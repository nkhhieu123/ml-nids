import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.label_report import _key, compare_with_cic, parse_cic_timestamp, report

CSV_HEADER = ("Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, "
              "Timestamp, Flow Duration, Label\n")


def utc(text):
    return datetime.strptime(text, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc).timestamp()


class TimestampTest(unittest.TestCase):
    def test_morning_and_afternoon(self):
        self.assertEqual(parse_cic_timestamp("5/7/2017 9:47"), utc("2017-07-05 12:47"))
        self.assertEqual(parse_cic_timestamp("5/7/2017 2:43"), utc("2017-07-05 17:43"))   # 14:43 địa phương
        self.assertEqual(parse_cic_timestamp("7/7/2017 12:05"), utc("2017-07-07 15:05"))

    def test_key_ignores_direction(self):
        self.assertEqual(_key("10.0.0.1", 80, "10.0.0.2", 4000, 6), _key("10.0.0.2", 4000, "10.0.0.1", 80, 6))


class CompareTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        t = utc("2017-07-05 13:00")
        self.flows = pd.DataFrame({
            "first_index": [0, 1, 2, 3], "first_ts": [t, t + 5, t + 30, t], "last_ts": [t + 1, t + 6, t + 31, t],
            "fwd_ip": ["172.16.0.1", "172.16.0.1", "172.16.0.1", "192.168.10.3"],
            "fwd_port": [40000, 40000, 40001, 5353.0], "bwd_ip": ["192.168.10.50"] * 3 + ["8.8.8.8"],
            "bwd_port": [80, 80, 80, 53.0], "protocol": [6, 6, 6, 17], "packets": [3, 2, 4, 1]})
        self.labels = pd.DataFrame({
            "first_index": [0, 1, 2, 3], "label_attack": ["dos", "dos", "dos", "benign"],
            "label_anomaly": ["anomaly"] * 3 + ["normal"], "label_status": ["khop"] * 3 + ["khong_khop"],
            "rule_id": ["r"] * 3 + [None]})
        self.csv = self.dir / "cic.csv"
        self.csv.write_text(CSV_HEADER
                            + "x,192.168.10.50,80,172.16.0.1,40000,6,5/7/2017 10:00,1,DoS Hulk\n"
                            + "x,172.16.0.1,40001,192.168.10.50,80,6,5/7/2017 10:00,1,BENIGN\n"
                            + "x,192.168.10.3,5353,8.8.8.8,53,17,5/7/2017 10:00,1,BENIGN\n"
                            + "x,10.9.9.9,1,10.9.9.8,2,6,5/7/2017 10:00,1,BENIGN\n", encoding="utf-8")

    def test_cross_table(self):
        r = compare_with_cic(self.flows, self.labels, self.csv)
        self.assertEqual(r["bang_cheo_csv_x_du_an"], {"dos": {"dos": 1}, "benign": {"dos": 1, "benign": 1}})
        self.assertEqual(r["so_flow_csv_khong_ghep_duoc"], {"benign": 1})
        self.assertEqual(r["so_flow_csv_ghep_duoc"], 3)
        self.assertAlmostEqual(r["ty_le_dong_y"], 2 / 3, places=5)

    def test_report_from_files(self):
        path = self.dir / "s.flows.csv"
        self.flows.to_csv(path, index=False)
        self.labels.to_csv(self.dir / "s.flows.labels.csv", index=False)
        r = report(path, [self.csv])
        self.assertEqual(r["theo_trang_thai"]["khop"], {"so_flow": 3, "so_goi": 9})
        self.assertEqual(r["nhom_mo_ho"], [])
        self.assertEqual(len(r["doi_chieu_cic"]), 1)


if __name__ == "__main__":
    unittest.main()

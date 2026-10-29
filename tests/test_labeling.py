import io
import sys
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.labeling import (
    STATUS_AMBIGUOUS, STATUS_EXCLUDED, STATUS_MATCHED, STATUS_UNMATCHED, label_flows, label_windows,
    labels_path, load_schedule, main,
)

HEADER = ("id,nguon,ngay,bat_dau,ket_thuc,utc_offset_h,nhan_goc,nhan_attack,ben_tan_cong,nan_nhan,"
          "cong_nan_nhan,khoi,ghi_chu\n")
RULES = (HEADER
         + "dos1,Lab,2017-07-05,09:47,10:10,-3,DoS,dos,10.0.0.1,10.0.0.50,,b1,\n"
         + "scan1,Lab,2017-07-05,10:15,10:20,-3,Scan,port_scan,10.0.0.1,10.0.0.50,,b2,\n"
         + "hb,Lab,2017-07-05,15:12,15:32,-3,Heartbleed,loai,10.0.0.1,10.0.0.51,444,,\n")
A, V, V2, OTHER = "10.0.0.1", "10.0.0.50", "10.0.0.51", "10.0.0.9"


def utc(day, hhmm_ss):
    return datetime.strptime(f"{day} {hhmm_ss}", "%Y-%m-%d %H:%M:%S").replace(
        tzinfo=timezone.utc).timestamp()


class ScheduleTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "s.csv"
        self.path.write_text(RULES, encoding="utf-8")
        self.rules = load_schedule(self.path)

    def test_local_time_converted_to_utc(self):
        dos = self.rules[0]
        self.assertEqual(dos.start_s, utc("2017-07-05", "12:47:00"))   # 09:47 giờ UTC−3
        self.assertEqual(dos.end_s, utc("2017-07-05", "13:11:00"))     # hết phút 10:10
        self.assertEqual(dos.day_start_s, utc("2017-07-05", "03:00:00"))

    def test_rejects_unknown_label(self):
        self.path.write_text(HEADER + "x,Lab,2017-07-05,09:00,09:10,-3,X,ddos,1.1.1.1,2.2.2.2,,,\n",
                             encoding="utf-8")
        with self.assertRaises(ValueError):
            load_schedule(self.path)

    def test_project_schedule_loads(self):
        rules = {r.id: r for r in load_schedule()}
        self.assertEqual(len(rules), 9)
        self.assertEqual(len(rules["cic17-fri-bot-ares"].victims), 5)
        self.assertEqual({r.label for r in rules.values()}, {"dos", "port_scan", "loai"})


class LabelTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "s.csv"
        path.write_text(RULES, encoding="utf-8")
        self.rules = load_schedule(path)

    def label(self, rows, tolerance=60):
        cols = ["fwd_ip", "bwd_ip", "first_ts", "last_ts", "fwd_port", "bwd_port"][:len(rows[0])]
        df = pd.DataFrame(rows, columns=cols)
        df.insert(0, "first_index", range(len(df)))
        return label_flows(df, self.rules, tolerance)

    def test_victim_port(self):
        # Heartbleed chỉ nhắm cổng 444 của V2; V2 gọi HTTPS tới A cả ngày là bình thường.
        t = lambda hms: utc("2017-07-05", hms)
        out = self.label([
            (A, V2, t("18:20:00"), t("18:21:00"), 50000, 444),
            (V2, A, t("18:20:00"), t("18:20:01"), 41000, 443),
            (V2, A, t("13:00:00"), t("13:00:01"), 41000, 443),
            (A, V2, t("13:00:00"), t("13:00:01"), 50001, 444),     # đúng cổng nhưng ngoài khung
        ])
        self.assertEqual(list(out["label_status"]),
                         [STATUS_EXCLUDED, STATUS_UNMATCHED, STATUS_UNMATCHED, STATUS_AMBIGUOUS])

    def test_statuses(self):
        t = lambda hms: utc("2017-07-05", hms)
        out = self.label([
            (A, V, t("13:00:00"), t("13:00:05")),       # trong khung DoS
            (V, A, t("13:00:00"), t("13:00:01")),       # chiều ngược vẫn là cặp tấn công
            (A, V, t("13:16:00"), t("13:16:00")),       # trong khung scan
            (A, V2, t("18:20:00"), t("18:21:00")),      # Heartbleed: loại
            (A, V, t("17:00:00"), t("17:00:01")),       # cặp tấn công, cùng ngày, ngoài khung
            (OTHER, V, t("13:00:00"), t("13:00:01")),   # IP khác: bình thường
        ])
        self.assertEqual(list(out["label_status"]), [
            STATUS_MATCHED, STATUS_MATCHED, STATUS_MATCHED, STATUS_EXCLUDED, STATUS_AMBIGUOUS,
            STATUS_UNMATCHED])
        self.assertEqual(list(out["label_attack"]), ["dos", "dos", "port_scan", None, None, "benign"])
        self.assertEqual(list(out["label_anomaly"]),
                         ["anomaly", "anomaly", "anomaly", "anomaly", None, "normal"])
        self.assertEqual(list(out["rule_id"][:4]), ["dos1", "dos1", "scan1", "hb"])

    def test_tolerance(self):
        just_before = utc("2017-07-05", "12:46:30")      # 30 giây trước 09:47
        out = self.label([(A, V, just_before, just_before)], tolerance=60)
        self.assertEqual(out["label_status"][0], STATUS_MATCHED)
        out = self.label([(A, V, just_before, just_before)], tolerance=0)
        self.assertEqual(out["label_status"][0], STATUS_AMBIGUOUS)

    def test_long_flow_touching_two_labels_is_ambiguous(self):
        out = self.label([(A, V, utc("2017-07-05", "13:05:00"), utc("2017-07-05", "13:17:00"))])
        self.assertEqual((out["label_status"][0], out["rule_id"][0]), (STATUS_AMBIGUOUS, "nhieu_quy_tac"))
        self.assertIsNone(out["label_attack"][0])

    def test_other_day_is_normal(self):
        monday = utc("2017-07-03", "13:00:00")
        out = self.label([(A, V, monday, monday)])
        self.assertEqual(out["label_status"][0], STATUS_UNMATCHED)

    def test_cli_writes_labels(self):
        with TemporaryDirectory() as tmp:
            flows = Path(tmp) / "x.flows.csv"
            t = utc("2017-07-05", "13:00:00")
            pd.DataFrame({"first_index": [0, 1], "first_ts": [t, t], "last_ts": [t, t],
                          "fwd_ip": ["172.16.0.1", "192.168.10.3"],
                          "bwd_ip": ["192.168.10.50", "8.8.8.8"],
                          "fwd_port": [40000, 40001], "bwd_port": [80, 53]}).to_csv(flows, index=False)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(flows)]), 0)
            out = pd.read_csv(labels_path(flows))
        self.assertEqual(list(out["label_attack"]), ["dos", "benign"])
        self.assertEqual(list(out.columns), ["first_index", "label_attack", "label_anomaly",
                                             "label_status", "rule_id"])

class WindowLabelTest(unittest.TestCase):
    """Nhãn cửa sổ chứa nhiều hành vi (C05-T03)."""

    def run_case(self, flow_rows, min_share=0.2):
        # flow_rows: (fwd_ip, bwd_ip, first, last, status, label_attack)
        flows = pd.DataFrame([r[:4] for r in flow_rows], columns=["fwd_ip", "bwd_ip", "first_ts", "last_ts"])
        flows.insert(0, "first_index", range(len(flows)))
        labels = pd.DataFrame({"first_index": range(len(flows)),
                               "label_status": [r[4] for r in flow_rows],
                               "label_attack": [r[5] for r in flow_rows]})
        windows = pd.DataFrame({"host": [V, V], "window_start": [0.0, 100.0], "window_end": [10.0, 110.0]})
        return label_windows(windows, flows, labels, min_share).iloc[0]

    def benign(self, n, t=5):
        return [(OTHER, V, t, t + 1, STATUS_UNMATCHED, "benign")] * n

    def test_pure_attack(self):
        w = self.run_case([(A, V, 1, 2, STATUS_MATCHED, "dos")] * 4)
        self.assertEqual((w["label_status"], w["label_attack"], w["label_anomaly"], w["attack_share"]),
                         (STATUS_MATCHED, "dos", "anomaly", 1.0))

    def test_mixed_window_above_share(self):
        w = self.run_case([(A, V, 1, 2, STATUS_MATCHED, "dos")] * 2 + self.benign(6))
        self.assertEqual((w["label_status"], w["label_attack"], w["attack_share"]), (STATUS_MATCHED, "dos", 0.25))

    def test_few_attack_flows_is_ambiguous_but_anomaly(self):
        w = self.run_case([(A, V, 1, 2, STATUS_MATCHED, "dos")] + self.benign(9))
        self.assertEqual((w["label_status"], w["label_attack"], w["label_anomaly"], w["rule_id"]),
                         (STATUS_AMBIGUOUS, None, "anomaly", "it_flow_tan_cong"))
        w = self.run_case([(A, V, 1, 2, STATUS_MATCHED, "dos")] + self.benign(9), min_share=0.1)
        self.assertEqual(w["label_attack"], "dos")

    def test_two_classes_is_ambiguous(self):
        w = self.run_case([(A, V, 1, 2, STATUS_MATCHED, "dos"), (A, V, 3, 4, STATUS_MATCHED, "port_scan")])
        self.assertEqual((w["label_status"], w["rule_id"]), (STATUS_AMBIGUOUS, "nhieu_lop"))

    def test_excluded_attack_wins(self):
        w = self.run_case([(A, V, 1, 2, STATUS_MATCHED, "dos"), (A, V, 1, 2, STATUS_EXCLUDED, None)])
        self.assertEqual((w["label_status"], w["label_attack"], w["label_anomaly"]),
                         (STATUS_EXCLUDED, None, "anomaly"))

    def test_ambiguous_flows_only(self):
        w = self.run_case([(A, V, 1, 2, STATUS_AMBIGUOUS, None)] + self.benign(3))
        self.assertEqual((w["label_status"], w["label_attack"], w["label_anomaly"]),
                         (STATUS_AMBIGUOUS, None, None))

    def test_flow_overlap_boundaries(self):
        # Flow kết thúc đúng lúc cửa sổ bắt đầu vẫn chồng; flow bắt đầu đúng lúc end thì không.
        w = self.run_case([(A, V, -5, 0, STATUS_MATCHED, "dos"), (A, V, 10, 12, STATUS_MATCHED, "dos")]
                          + self.benign(1))
        self.assertEqual((w["n_flows"], w["n_attack_flows"]), (2, 1))

    def test_benign_and_counts(self):
        w = self.run_case(self.benign(3) + [(OTHER, V, 50, 60, STATUS_UNMATCHED, "benign")])
        self.assertEqual((w["label_status"], w["label_attack"], w["label_anomaly"], w["n_flows"]),
                         (STATUS_UNMATCHED, "benign", "normal", 3))


if __name__ == "__main__":
    unittest.main()

"""Kiểm thử bộ đo Chặng 11 (độ trễ, bỏ sót, báo động giả) bằng dữ liệu tổng hợp."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.alerts import Alert
from nids.labeling import Rule
from nids.thuc_nghiem import (Attack, attacks_from_rules, attacks_from_runlog, detect, false_alarms,
                              latency_summary, load_runlog)

NET = ["192.168.10.0/24", "172.16.0.0/24"]


def alert(module, label, host, ws, we):
    return Alert(module, label, float(ws), float(we), src_ip=host)


class GroundTruthTest(unittest.TestCase):
    def _rule(self, label, original="", a="172.16.0.1", v="192.168.10.50", s=100, e=500):
        return Rule("r-" + label, s, e, 0, 10**6, frozenset({a}), frozenset({v}), label, original, "blk")

    def test_maps_and_filters_hosts(self):
        rules = [self._rule("dos"), self._rule("port_scan"),
                 self._rule("loai", "Bot", a="205.174.165.73", v="192.168.10.5"),   # botnet
                 self._rule("loai", "DDoS")]                                          # bỏ (chỉ anomaly)
        atks = attacks_from_rules(rules, 0, 1000, NET)
        self.assertEqual(sorted(a.loai for a in atks), ["botnet", "dos", "port_scan"])
        bot = [a for a in atks if a.loai == "botnet"][0]
        self.assertEqual(set(bot.hosts), {"192.168.10.5"})          # host ngoài mạng bị loại
        self.assertEqual([a for a in atks if a.loai == "dos"][0].t0, 100)

    def test_time_overlap_required(self):
        self.assertEqual(attacks_from_rules([self._rule("dos", s=2000, e=3000)], 0, 1000, NET), [])

    def test_from_runlog(self):
        logs = [{"ma_lan_chay": "k3-dos", "kieu": "tai-ket-noi", "nhan": "dos", "ip_nguon": "192.168.50.20",
                 "ip_dich": "192.168.50.30", "bat_dau": "2026-11-06T13:00:00+00:00",
                 "ket_thuc": "2026-11-06T13:01:00+00:00"}]
        a = attacks_from_runlog(logs, ["192.168.50.0/24"])
        self.assertEqual((a[0].loai, set(a[0].hosts)), ("dos", {"192.168.50.20", "192.168.50.30"}))  # nguồn ∪ nạn nhân

    def test_lab_run_log(self):
        import json
        import tempfile
        log = {"ma_lan_chay": "k4-co-dinh-test-01", "hanh_vi": [
            {"kieu": "tap-trung", "nhan": "botnet", "ip_nguon": ["192.168.50.41", "192.168.50.42"],
             "ip_dich": ["192.168.50.50"], "bat_dau": "x", "ket_thuc": "x",
             "bat_dau_epoch": 1000.5, "ket_thuc_epoch": 1600.5},
            {"kieu": "doi-chung-tap-trung", "nhan": "benign", "ip_nguon": ["192.168.50.43"],
             "ip_dich": ["192.168.50.30"], "bat_dau_epoch": 1000.0, "ket_thuc_epoch": 1600.0}]}
        with tempfile.TemporaryDirectory() as d:
            Path(d, "k4-co-dinh-test-01.json").write_text(json.dumps(log), encoding="utf-8")
            entries = load_runlog(d, "data/pcap/lab/k4-co-dinh-test-01.pcap")       # thư mục -> file theo tên PCAP
        atks = attacks_from_runlog(entries, ["192.168.50.0/24"])
        self.assertEqual(len(atks), 1)                                              # đối chứng benign không thành đợt
        a = atks[0]
        self.assertEqual((a.kich_ban, a.loai, a.t0), ("k4-co-dinh-test-01", "botnet", 1000.5))   # dùng epoch
        self.assertEqual(set(a.hosts), {"192.168.50.41", "192.168.50.42"})          # chỉ bot
        self.assertEqual(set(a.lien_quan), {"192.168.50.50"})                       # máy điều khiển
        self.assertEqual(attacks_from_runlog(entries, ["192.168.50.0/24"], 0, 500), [])   # ngoài khoảng PCAP

    def test_controller_alert_explained_not_detection(self):
        a = Attack("r", "botnet", frozenset({"192.168.50.41"}), 100.0, 700.0, frozenset({"192.168.50.50"}))
        cc = alert("botnet_topology", "suspect_host", "192.168.50.50", 200, 320)
        self.assertEqual(detect([a], [cc])["phat_hien"], 0)                         # cảnh báo trên máy điều khiển không tính
        ev = [{"module": cc.module, "label": cc.label, "src_ip": cc.src_ip, "bat_dau": 200.0, "ket_thuc": 320.0}]
        self.assertEqual(false_alarms(ev, [a], 1.0)["so_su_kien_bao_gia"], 0)       # nhưng không phải báo giả

    def test_anomaly_recorded_separately(self):
        a = Attack("r", "dos", frozenset({"192.168.50.20"}), 100.0, 160.0)
        r = detect([a], [alert("anomaly", "anomaly", "192.168.50.20", 104, 114)])["theo_dot"][0]
        self.assertEqual((r["phat_hien"], r["anomaly_do_tre_s"]), (False, 14.0))


class DetectTest(unittest.TestCase):
    def test_detection_latency_and_miss(self):
        attacks = [Attack("s", "dos", frozenset({"172.16.0.1"}), 100.0, 200.0),
                   Attack("s", "port_scan", frozenset({"192.168.10.50"}), 100.0, 200.0)]
        alerts = [alert("attack_classification", "dos", "172.16.0.1", 110, 120),   # trễ 20s
                  alert("attack_classification", "dos", "172.16.0.1", 150, 160)]   # muộn hơn, không tính
        r = detect(attacks, alerts)
        self.assertEqual((r["phat_hien"], r["bo_sot"]), (1, 1))
        dos = [x for x in r["theo_dot"] if x["loai"] == "dos"][0]
        self.assertEqual((dos["phat_hien"], dos["do_tre_s"]), (True, 20.0))         # 120 − 100
        ps = [x for x in r["theo_dot"] if x["loai"] == "port_scan"][0]
        self.assertFalse(ps["phat_hien"])                                           # không có cảnh báo -> bỏ sót

    def test_wrong_host_or_label_not_detected(self):
        attacks = [Attack("s", "dos", frozenset({"172.16.0.1"}), 100.0, 200.0)]
        alerts = [alert("attack_classification", "dos", "10.0.0.9", 110, 120),       # sai host
                  alert("attack_classification", "port_scan", "172.16.0.1", 110, 120)]  # sai nhãn
        self.assertEqual(detect(attacks, alerts)["phat_hien"], 0)

    def test_latency_summary(self):
        rows = [{"phat_hien": True, "do_tre_s": 10.0}, {"phat_hien": True, "do_tre_s": 30.0},
                {"phat_hien": False, "do_tre_s": None}]
        s = latency_summary(rows)
        self.assertEqual((s["so_mau"], s["nho_nhat"], s["lon_nhat"]), (2, 10.0, 30.0))


class FalseAlarmTest(unittest.TestCase):
    def test_uncovered_events_are_false(self):
        attacks = [Attack("s", "dos", frozenset({"172.16.0.1"}), 100.0, 200.0)]
        events = [{"module": "attack_classification", "label": "dos", "src_ip": "172.16.0.1",
                   "bat_dau": 110.0, "ket_thuc": 120.0, "thoi_luong_s": 10.0},        # được giải thích
                  {"module": "botnet_topology", "label": "suspect_host", "src_ip": "192.168.10.9",
                   "bat_dau": 110.0, "ket_thuc": 120.0, "thoi_luong_s": 10.0}]        # báo giả
        fa = false_alarms(events, attacks, hours=1.0)
        self.assertEqual(fa["so_su_kien_bao_gia"], 1)
        self.assertEqual(fa["theo_module"], {"botnet_topology": 1})
        self.assertEqual(fa["moi_gio"], 1.0)


if __name__ == "__main__":
    unittest.main()

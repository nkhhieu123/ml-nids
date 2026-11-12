"""Kiểm thử phần tổng hợp kết quả lab và độ trễ realtime của Chặng 11 bằng dữ liệu tổng hợp."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.alerts import Alert
from nids.do_tre_realtime import realtime_latency
from nids.thuc_nghiem import Attack
from nids.thuc_nghiem_lab import per_variant, totals, variant_of


def scenario(pcap, dots, fa, hours=0.1):
    return {"pcap": pcap, "gio": hours, "khoang_giay": hours * 3600,
            "phat_hien": {"theo_dot": [{"phat_hien": ok, "do_tre_s": lat, "anomaly_do_tre_s": None} for ok, lat in dots]},
            "bao_gia": {"so_su_kien_bao_gia": sum(fa.values()), "theo_module": fa},
            "hieu_nang": {"flow": 10, "cua_so": 20, "thoi_gian_s": {"trich_xuat": 1.0, "anomaly": 0.5}}}


class AggregateTest(unittest.TestCase):
    def test_variant_name(self):
        self.assertEqual(variant_of("k3-dos-muc2-test-01.pcap"), "k3-dos-muc2")
        self.assertEqual(variant_of("k1-binh-thuong-val-12"), "k1-binh-thuong")

    def test_groups_runs_and_counts_misses(self):
        runs = [scenario("k2-quet-cham-test-01.pcap", [(True, 2.0)], {"anomaly": 1}),
                scenario("k2-quet-cham-test-02.pcap", [(True, 4.0)], {}),
                scenario("k4-co-dinh-test-01.pcap", [(False, None)], {"attack_classification": 2})]
        logs = {"k2-quet-cham-test-01": {"ban_thu": {"goi_bat_duoc": 100, "goi_nhan_bo": 0}},
                "k2-quet-cham-test-02": {"ban_thu": {"goi_bat_duoc": 50, "goi_nhan_bo": 1}}}
        rows = {r["bien_the"]: r for r in per_variant(runs, logs)}
        scan = rows["k2-quet-cham"]
        self.assertEqual((scan["so_lan_chay"], scan["phat_hien"], scan["bo_sot"]), (2, 2, 0))
        self.assertEqual((scan["do_tre_s"], scan["do_tre_trung_vi_s"]), ([2.0, 4.0], 3.0))
        self.assertEqual((scan["bao_gia"], scan["bao_gia_moi_gio"], scan["bao_gia_tung_lan"]), (1, 5.0, [1, 0]))
        self.assertEqual((scan["goi_bat_duoc"], scan["goi_nhan_bo"]), (150, 1))
        self.assertEqual((rows["k4-co-dinh"]["phat_hien"], rows["k4-co-dinh"]["bo_sot"]), (0, 1))   # không báo = bỏ sót
        t = totals(list(rows.values()))
        self.assertEqual((t["so_dot"], t["phat_hien"], t["bo_sot"], t["bao_gia"]), (3, 2, 1, 3))
        self.assertEqual(t["ty_le_phat_hien"], 0.667)


class RealtimeLatencyTest(unittest.TestCase):
    def test_maps_emit_time_to_capture_clock(self):
        a = Attack("r", "dos", frozenset({"192.168.50.20"}), 1100.0, 1160.0)
        # bản thu bắt đầu ở 1000; phát lại bắt đầu lúc giờ thật 5000; cảnh báo phát lúc 5105 -> 1105 theo bản thu
        early = Alert("attack_classification", "dos", 1092.0, 1102.0, src_ip="192.168.50.20", created_at=5105.0)
        late = Alert("attack_classification", "dos", 1094.0, 1104.0, src_ip="192.168.50.20", created_at=5107.0)
        other = Alert("anomaly", "anomaly", 1092.0, 1102.0, src_ip="192.168.50.20", created_at=5103.0)   # sai module
        row = realtime_latency([a], [late, other, early], 1000.0, 5000.0)[0]
        self.assertEqual((row["phat_hien"], row["do_tre_realtime_s"]), (True, 5.0))       # 1105 − 1100
        self.assertEqual((row["do_tre_cuoi_cua_so_s"], row["cho_sau_cua_so_s"]), (2.0, 3.0))

    def test_live_alert_csv_uses_real_clock(self):
        import io
        import tempfile

        from nids.alerts import AlertSink
        from nids.do_tre_realtime import live_latency
        log = [{"ma_lan_chay": "r", "kieu": "tai-ket-noi", "nhan": "dos", "ip_nguon": ["192.168.50.20"],
                "ip_dich": ["192.168.50.30"], "bat_dau_epoch": 1100.0, "ket_thuc_epoch": 1160.0}]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "a.csv"
            with AlertSink(path, stream=io.StringIO()) as sink:
                sink.emit(Alert("attack_classification", "dos", 1092.0, 1102.0, src_ip="192.168.50.20", created_at=1105.25))
            row = live_latency(path, log, ["192.168.50.0/24"])[0]
        self.assertEqual((row["phat_hien"], row["do_tre_realtime_s"], row["cho_sau_cua_so_s"]), (True, 5.2, 3.2))

    def test_no_alert_is_miss(self):
        a = Attack("r", "botnet", frozenset({"192.168.50.41"}), 1100.0, 1700.0)
        self.assertEqual(realtime_latency([a], [], 1000.0, 5000.0)[0]["phat_hien"], False)


if __name__ == "__main__":
    unittest.main()

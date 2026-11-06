"""Kiểm thử script sinh traffic lab (kịch bản 1–3) và bộ đổi nhật ký sang lịch gán nhãn.

Không chạm mạng lab: dùng chế độ --thu (chỉ in kế hoạch) và một máy chủ loopback 127.0.0.1 với mạng
cho phép mở rộng thành 127.0.0.0/8, nên mọi kết nối thật chỉ ở trong máy.
"""

import importlib.util
import ipaddress
import json
import socket
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


traffic = _load("sinh_traffic")
convert = _load("nhat_ky_sang_lich")


class LoopbackServer:
    """Máy chủ TCP nhỏ trên 127.0.0.1 để kiểm tra đường gửi thật mà không ra mạng."""

    def __init__(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(16)
        self.port = self.srv.getsockname()[1]
        self.stop = False
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self):
        self.srv.settimeout(0.3)
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                continue
            with c:
                try:
                    c.recv(4096)
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass

    def close(self):
        self.stop = True
        self.srv.close()


class TargetGuardTest(unittest.TestCase):
    def test_refuses_outside_lab(self):
        with self.assertRaises(SystemExit):
            traffic.check_target("8.8.8.8")
        with self.assertRaises(SystemExit):
            traffic.check_target("192.168.51.5")
        self.assertEqual(traffic.check_target("192.168.50.30"), "192.168.50.30")

    def test_dos_capped_at_60s(self):
        plan = traffic.run_conn_load("192.168.50.30", 80, 3, duration=600, rng=None, dry=True)
        self.assertEqual(plan["thoi_gian_s"], traffic.DOS_MAX_S)
        self.assertEqual(plan["ket_noi_moi_giay"], traffic.DOS_LEVELS[3])


class DryPlanTest(unittest.TestCase):
    def test_benign_plan(self):
        import random
        r = traffic.run_benign("192.168.50.30", 80, 120, random.Random(1), dry=True)
        self.assertGreater(r["so_yeu_cau"], 0)

    def test_scan_plan(self):
        r = traffic.run_scan("192.168.50.30", 1, 100, traffic.SCAN_RATES["cham"], dry=True)
        self.assertEqual(r["so_cong"], 100)

    def test_main_dry_writes_no_log(self):
        with TemporaryDirectory() as d:
            log = Path(d) / "nhat_ky.jsonl"
            traffic.LOG = log
            rc = traffic.main(["quet", "--may-chu", "192.168.50.30", "--cong-dau", "1",
                               "--cong-cuoi", "10", "--toc-do", "nhanh", "--vai-tro", "train", "--lan", "01", "--thu"])
            self.assertEqual(rc, 0)
            self.assertFalse(log.exists())


class RealSendTest(unittest.TestCase):
    """Chạy thật nhưng chỉ trên loopback, với mạng cho phép là 127.0.0.0/8."""

    def setUp(self):
        self.orig = traffic.LAB_NET
        traffic.LAB_NET = ipaddress.ip_network("127.0.0.0/8")
        self.srv = LoopbackServer()
        self.addCleanup(self.srv.close)
        self.addCleanup(lambda: setattr(traffic, "LAB_NET", self.orig))

    def test_benign_real(self):
        import random
        r = traffic.run_benign("127.0.0.1", self.srv.port, 2, random.Random(3), dry=False)
        self.assertGreater(r["so_lan_thanh_cong"], 0)

    def test_conn_load_real(self):
        r = traffic.run_conn_load("127.0.0.1", self.srv.port, 1, duration=0.3, rng=None, dry=False)
        self.assertGreaterEqual(r["so_lan_thu"], 1)
        self.assertLessEqual(r["thoi_gian_s"], 1.0)


class ConvertTest(unittest.TestCase):
    def test_rows_from_logs(self):
        logs = [
            {"ma_lan_chay": "k1-binh-thuong-train-01", "bien_the": "k1-binh-thuong", "vai_tro": "train",
             "kieu": "binh-thuong", "nhan": "benign", "bat_dau": "2026-11-06T13:00:00+07:00",
             "ket_thuc": "2026-11-06T13:10:00+07:00", "ip_nguon": "192.168.50.41", "ip_dich": "192.168.50.30",
             "tham_so": {"cong": 80}},
            {"ma_lan_chay": "k3-dos-muc2-train-01", "bien_the": "k3-dos-muc2", "vai_tro": "train",
             "kieu": "tai-ket-noi", "nhan": "dos", "bat_dau": "2026-11-06T13:20:05+07:00",
             "ket_thuc": "2026-11-06T13:21:05+07:00", "ip_nguon": "192.168.50.20", "ip_dich": "192.168.50.30",
             "tham_so": {"cong": 80, "muc": 2}},
        ]
        rows = convert.rows_from_logs(logs)
        self.assertEqual(len(rows), 1)                       # benign không tạo luật
        r = rows[0]
        self.assertEqual((r["nhan_attack"], r["ben_tan_cong"], r["nan_nhan"]), ("dos", "192.168.50.20", "192.168.50.30"))
        self.assertEqual((r["bat_dau"], r["ket_thuc"], r["utc_offset_h"]), ("13:20", "13:21", "7"))
        self.assertEqual(r["cong_nan_nhan"], "80")

    def test_columns_match_labeling(self):
        # Lịch sinh ra phải đúng cột mà nids.labeling đòi.
        import sys
        sys.path.insert(0, str(ROOT / "src"))
        from nids.labeling import SCHEDULE_COLUMNS
        self.assertEqual(convert.COLUMNS, SCHEDULE_COLUMNS)

    def test_main_writes_csv(self):
        with TemporaryDirectory() as d:
            nk = Path(d) / "nhat_ky.jsonl"
            nk.write_text(json.dumps({"ma_lan_chay": "k2-quet-nhanh-train-01", "bien_the": "k2-quet-nhanh",
                                      "vai_tro": "train", "kieu": "quet", "nhan": "port_scan",
                                      "bat_dau": "2026-11-06T14:00:00+07:00", "ket_thuc": "2026-11-06T14:02:00+07:00",
                                      "ip_nguon": "192.168.50.20", "ip_dich": "192.168.50.30", "tham_so": {}}) + "\n",
                          encoding="utf-8")
            out = Path(d) / "lich.csv"
            convert.main([str(nk), "--out", str(out)])
            text = out.read_text(encoding="utf-8").splitlines()
            self.assertEqual(text[0], ",".join(convert.COLUMNS))
            self.assertIn("port_scan", text[1])


if __name__ == "__main__":
    unittest.main()

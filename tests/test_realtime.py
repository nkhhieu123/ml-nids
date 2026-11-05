import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.moi_truong import (FAIL, OK, WARN, capabilities, check_capture_permission, check_interface, check_ntp,
                             check_packages, check_python)


class EnvironmentTest(unittest.TestCase):
    """C10-T01: kiểm tra môi trường trước khi chạy cảm biến."""

    def test_python_and_packages(self):
        self.assertEqual(check_python((3, 12, 1))[0], OK)
        self.assertEqual(check_python((3, 9, 0))[0], FAIL)
        res = dict((msg.split()[0] if lv == OK else msg, lv) for lv, msg in
                   check_packages(required=("json",), optional=("khong_co_thu_vien_nay",)))
        self.assertEqual(res["json"], OK)
        self.assertEqual(res["thiếu thư viện khong_co_thu_vien_nay (tùy chọn)"], WARN)
        self.assertEqual(check_packages(required=("khong_co_x",), optional=())[0][0], FAIL)

    def test_capture_permission(self):
        status = "Name:\tpython\nCapEff:\t0000000000003000\n"                      # bit 12, 13
        self.assertEqual(capabilities(status), 0x3000)
        self.assertIsNone(capabilities("Name: x\n"))
        self.assertEqual(check_capture_permission("Linux", euid=0)[0], OK)
        self.assertEqual(check_capture_permission("Linux", euid=1000, status_text=status)[0], OK)
        self.assertEqual(check_capture_permission("Linux", euid=1000, status_text="CapEff:\t0\n")[0], FAIL)
        self.assertEqual(check_capture_permission("Windows")[0], WARN)

    def test_interface(self):
        with TemporaryDirectory() as d:
            (Path(d) / "eth1").mkdir()
            (Path(d) / "eth1" / "operstate").write_text("up\n")
            (Path(d) / "lo").mkdir()
            self.assertEqual(check_interface("eth1", "Linux", d)[0], OK)
            lv, msg = check_interface("eth0", "Linux", d)
            self.assertEqual(lv, FAIL)
            self.assertIn("eth1", msg)                                              # gợi ý card có thật
        self.assertEqual(check_interface(None, "Linux")[0], WARN)

    def test_ntp(self):
        yes = lambda *a, **k: SimpleNamespace(stdout="yes\n")
        no = lambda *a, **k: SimpleNamespace(stdout="no\n")
        def broken(*a, **k):
            raise OSError("không có")
        self.assertEqual(check_ntp("Linux", yes)[0], OK)
        self.assertEqual(check_ntp("Linux", no)[0], WARN)
        self.assertEqual(check_ntp("Linux", broken)[0], WARN)


def handshake_packets(n=30, t0=1_500_000_000.0, server="192.168.50.30"):
    """n kết nối TCP đủ bắt tay từ 192.168.50.41 tới ``server``:80; mỗi gói (giây, khung)."""
    from test_pipeline import frame
    pk = []
    for k in range(n):
        t = t0 + k
        c = ("192.168.50.41", server, 50000 + k, 80)
        s = (server, "192.168.50.41", 80, 50000 + k)
        pk += [(t, frame(*c, 0x02)), (t + 0.01, frame(*s, 0x12)), (t + 0.02, frame(*c, 0x10)),
               (t + 0.5, frame(*c, 0x11)), (t + 0.51, frame(*s, 0x11)), (t + 0.52, frame(*c, 0x10))]
    return pk


class SensorTest(unittest.TestCase):
    """C10-T02: cảm biến thấy traffic hai chiều."""

    def run_on(self, packets, lab_hosts=None):
        from nids.cam_bien import analyze, read_with_digest
        from test_pipeline import write_pcap
        with TemporaryDirectory() as d:
            path = write_pcap(Path(d) / "x.pcap", sorted(packets, key=lambda x: x[0]))
            return analyze(read_with_digest(path), ["192.168.50.0/24"], lab_hosts)

    def test_two_way(self):
        r = self.run_on(handshake_packets(), ["192.168.50.41", "192.168.50.30", "192.168.50.42"])
        self.assertEqual((r["ty_le_flow_tcp_hai_chieu"], r["ty_le_co_phan_hoi_trong_mang"]), (1.0, 1.0))
        self.assertEqual(r["ty_le_nhan_doi"], 0.0)
        self.assertEqual(r["ket_luan"], "dat")
        self.assertFalse(r["may_lab"]["192.168.50.42"])
        self.assertTrue(any("192.168.50.42" in x for x in r["ly_do"]))               # máy lab chưa thấy

    def test_one_way(self):
        only_client = [p for p in handshake_packets() if p[1][26:30] == bytes([192, 168, 50, 41])]
        r = self.run_on(only_client)
        self.assertEqual(r["ty_le_flow_tcp_hai_chieu"], 0.0)
        self.assertEqual(r["ket_luan"], "loi")
        self.assertEqual(r["so_cap_mot_chieu"], 1)
        self.assertEqual(r["cap_mot_chieu"][0]["goi_b_sang_a"] + r["cap_mot_chieu"][0]["goi_a_sang_b"], 120)

    def test_duplicates(self):
        pk = handshake_packets()
        r = self.run_on(pk + [(t + 2e-6, f) for t, f in pk])                      # mỗi gói có một bản sao sau 2 µs
        self.assertAlmostEqual(r["ty_le_nhan_doi"], 0.5)
        self.assertEqual(r["ty_le_flow_tcp_hai_chieu"], 1.0)                        # bản sao không làm hỏng flow
        self.assertEqual(r["ket_luan"], "canh_bao")

    def test_too_few_flows(self):
        r = self.run_on(handshake_packets(n=5))
        self.assertEqual(r["ket_luan"], "canh_bao")
        self.assertIn("flow TCP", r["ly_do"][0])

    def test_digest_ignores_ttl(self):
        from nids.cam_bien import ip_digest
        from nids.pcap_reader import RawPacket
        from test_pipeline import frame
        f = bytearray(frame("192.168.50.41", "192.168.50.30", 1, 80, 0x02))
        g = bytearray(f)
        g[14 + 8] = 1                                                               # TTL khác
        h = bytearray(f)
        h[14 + 4] = 9                                                               # IP ID khác: gói khác
        dg = lambda b: ip_digest(RawPacket(0, 0, len(b), len(b), 1, bytes(b)))
        self.assertEqual(dg(f), dg(g))
        self.assertNotEqual(dg(f), dg(h))


if __name__ == "__main__":
    unittest.main()

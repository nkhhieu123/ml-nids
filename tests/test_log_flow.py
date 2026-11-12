"""Kiểm thử ghép dòng access log với flow (dung sai thời gian, cổng nguồn dùng lại)."""

import sys
import unittest
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.log_flow import ambiguous, flow_index, match, summarize
from nids.service_log import parse_line


def log(ts, port, server_port=80, ip="192.168.50.41"):
    return parse_line(f'{ts:.3f} {ip} {port} {server_port} "GET / HTTP/1.1" 200 10 80 0.000 1 1 "nids-lab"', 1)


FLOWS = pd.DataFrame([
    # client 41:5000 -> server 30:80, hai lần dùng lại cùng cổng nguồn
    {"first_index": 1, "first_ts": 100.0, "last_ts": 100.5, "protocol": 6, "fwd_ip": "192.168.50.41", "fwd_port": 5000,
     "bwd_ip": "192.168.50.30", "bwd_port": 80},
    {"first_index": 2, "first_ts": 130.0, "last_ts": 130.4, "protocol": 6, "fwd_ip": "192.168.50.41", "fwd_port": 5000,
     "bwd_ip": "192.168.50.30", "bwd_port": 80},
    # flow ghi theo chiều ngược (máy chủ ở phía fwd)
    {"first_index": 3, "first_ts": 200.0, "last_ts": 200.2, "protocol": 6, "fwd_ip": "192.168.50.30", "fwd_port": 80,
     "bwd_ip": "192.168.50.42", "bwd_port": 6000},
    # UDP cùng cổng: không được ghép
    {"first_index": 4, "first_ts": 300.0, "last_ts": 300.1, "protocol": 17, "fwd_ip": "192.168.50.43", "fwd_port": 7000,
     "bwd_ip": "192.168.50.30", "bwd_port": 80},
])


class LogFlowTest(unittest.TestCase):
    def setUp(self):
        self.index = flow_index(FLOWS)

    def test_inside_flow_and_nearest_on_port_reuse(self):
        rows = match([log(100.3, 5000), log(130.401, 5000)], self.index)
        self.assertEqual([r["first_index"] for r in rows], [1, 2])          # lấy flow gần thời điểm ghi log nhất
        self.assertEqual(rows[0]["khoang_cach_s"], 0.0)                     # nằm trong flow
        self.assertAlmostEqual(rows[1]["khoang_cach_s"], 0.001, places=6)   # ghi log sau gói cuối 1 mili giây

    def test_reverse_direction_and_protocol(self):
        rows = match([log(200.1, 6000, ip="192.168.50.42"), log(300.05, 7000, ip="192.168.50.43")], self.index)
        self.assertEqual(rows[0]["first_index"], 3)                         # máy chủ ở phía fwd vẫn ghép được
        self.assertIsNone(rows[1]["first_index"])                           # flow UDP không tính

    def test_tolerance_summary_and_ambiguity(self):
        rows = match([log(100.3, 5000), log(130.401, 5000), log(999.0, 5555)], self.index)
        s = {t["dung_sai_s"]: t for t in summarize(rows, (0.0, 1.0, 60.0))["theo_dung_sai"]}
        self.assertEqual((s[0.0]["ghep_duoc"], s[1.0]["ghep_duoc"]), (1, 2))   # dòng thứ ba không có flow cùng cổng
        self.assertEqual((s[1.0]["khong_duy_nhat"], s[60.0]["khong_duy_nhat"]), (0, 2))
        self.assertTrue(ambiguous(rows[0], 60.0))                           # nới quá rộng thì hai flow cùng cổng đều khớp


if __name__ == "__main__":
    unittest.main()

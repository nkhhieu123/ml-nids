"""Kiểm thử dashboard HTML tĩnh (QĐ-090)."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.dashboard import render

CSV = """module,label,window_start,window_end,src_ip,dst_ip,score,threshold,run_id,detail,created_at
attack_classification,port_scan,2026-11-14T06:59:26.000Z,2026-11-14T06:59:36.000Z,192.168.50.20,,0.95,,t,,2026-11-14T06:59:37.000Z
attack_classification,dos,2026-11-14T07:00:26.000Z,2026-11-14T07:00:36.000Z,192.168.50.30,,0.99,,t,,2026-11-14T07:00:37.000Z
botnet_topology,suspect_host,2026-11-14T07:00:00.000Z,2026-11-14T07:02:00.000Z,192.168.50.41,,0.9,0.8,t,,2026-11-14T07:02:10.000Z
botnet_topology,p2p,2026-11-14T07:00:00.000Z,2026-11-14T07:02:00.000Z,192.168.50.41,,,,t,,2026-11-14T07:02:10.000Z
"""


class DashboardTest(unittest.TestCase):
    def test_render_self_contained(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.alerts.csv"
            p.write_text(CSV, encoding="utf-8")
            page = render(p)
        self.assertIn("<!doctype html>", page)
        self.assertEqual(page.count("data:image/png;base64,"), 2)      # dòng thời gian và đồ thị botnet
        self.assertIn("192.168.50.20", page)
        self.assertNotIn("http://", page)                               # không tải gì từ mạng


if __name__ == "__main__":
    unittest.main()

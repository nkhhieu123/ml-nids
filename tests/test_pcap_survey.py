import hashlib
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.flows import FlowSettings
from nids.packets import TCP_ACK, TCP_SYN
from nids.pcap_survey import main, survey
from test_packets import IP_A, IP_B, ether, ipv4, pcap_file, tcp, udp


class SurveyTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        # Ba SYN từ .20 tới ba cổng của .30, một SYN+ACK trả lời, một UDP, một ARP.
        frames = [ether(ipv4(payload=tcp(40000, port))) for port in (22, 80, 443)]
        frames.append(ether(ipv4(payload=tcp(80, 40000, TCP_SYN | TCP_ACK), src=IP_B, dst=IP_A)))
        frames.append(ether(ipv4(17, udp())))
        frames.append(ether(bytes(28), ethertype=0x0806))
        self.pcap = pcap_file(self.dir / "t.pcap", frames)

    def test_counts_hash_and_time(self):
        r = survey(self.pcap, FlowSettings(), [("192.168.50.20", "192.168.50.30")])
        self.assertEqual(r["sha256"], hashlib.sha256(self.pcap.read_bytes()).hexdigest())
        self.assertEqual(r["kich_thuoc_byte"], self.pcap.stat().st_size)
        self.assertEqual((r["dinh_dang"], r["giao_dien"]), ("pcap", [{"linktype": 1, "snaplen": 262144}]))
        self.assertEqual((r["packet"]["giu_lai"], r["packet"]["bo_qua"]), (5, 1))
        # pcap_file đặt thời điểm gói thứ i là 100 + i giây
        self.assertEqual(r["goi_dau_utc"], "1970-01-01T00:01:40.000005+00:00")
        self.assertEqual(r["thoi_luong_s"], 5.0 - 1.0)
        self.assertEqual(r["flow"]["so_flow"], 4)
        self.assertEqual(r["nguon_nhieu_goi_nhat"][0], ("192.168.50.20", 4))

    def test_pair_activity_per_minute(self):
        r = survey(self.pcap, FlowSettings(), [("192.168.50.20", "192.168.50.30")], with_hash=False)
        (pair,) = r["cap_theo_doi"]
        self.assertEqual(pair["tong_goi"], 4)
        self.assertEqual(pair["theo_phut"], [{"phut_utc": "1970-01-01T00:01", "goi": 4, "syn": 3,
                                              "so_cong_dich": 4}])
        self.assertNotIn("sha256", r)

    def test_cli_writes_report(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main([str(self.pcap), "--pair", "192.168.50.20:192.168.50.30",
                         "--report", str(self.dir / "r.json")])
        self.assertEqual(code, 0)
        report = json.loads((self.dir / "r.json").read_text(encoding="utf-8"))
        self.assertEqual(report["flow"]["so_packet"], 5)
        self.assertIn("6 packet, giữ 5, bỏ qua 1", out.getvalue())

    def test_bad_pair_rejected(self):
        with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
            main([str(self.pcap), "--pair", "192.168.50.20"])


if __name__ == "__main__":
    unittest.main()

import csv
import io
import math
import sys
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.flows import FlowSettings
from nids.packets import TCP_ACK, TCP_RST, TCP_SYN, PacketRecord
from nids.window_features import (
    CSV_COLUMNS, WINDOW_FEATURES, WindowPipeline, main, shannon_entropy,
)
from test_packets import ether, ipv4, pcap_file, tcp

SCANNER, VICTIM, CLIENT2 = "192.168.10.66", "192.168.10.50", "192.168.10.70"
S = 10**9


def pkt(src, dst, sport, dport, flags=TCP_SYN, ts=1.0, proto=6, index=0):
    has_ports = proto in (6, 17)
    return PacketRecord(index, round(ts * S), src, dst, 4, proto, 54, 40, 54, 34, False,
                        sport if has_ports else None, dport if has_ports else None,
                        flags if proto == 6 else None)


def windows(packets, size=10, step=10, settings=None):
    pipe = WindowPipeline(settings or FlowSettings(), size, step)
    out = []
    for i, p in enumerate(packets):
        out += pipe.add(replace(p, index=i))
    out += pipe.finish()
    return {(w.host, w.start_ns // S): w.features() for w in out}


class EntropyTest(unittest.TestCase):
    def test_values(self):
        self.assertEqual(shannon_entropy([5, 5, 5, 5]), 2.0)        # 4 cổng đều nhau: 2 bit
        self.assertEqual(shannon_entropy([7]), 0.0)                 # một cổng: 0
        self.assertIsNone(shannon_entropy([]))
        self.assertAlmostEqual(shannon_entropy([3, 1]),
                               -(0.75 * math.log2(0.75) + 0.25 * math.log2(0.25)))


class WindowFeatureTest(unittest.TestCase):
    def test_vertical_scan(self):
        # Quét 20 cổng của một máy; máy nạn nhân trả RST.
        packets = []
        for i, port in enumerate(range(1000, 1020)):
            packets.append(pkt(SCANNER, VICTIM, 50000, port, TCP_SYN, ts=1 + i * 0.1))
            packets.append(pkt(VICTIM, SCANNER, port, 50000, TCP_RST | TCP_ACK, ts=1.01 + i * 0.1))
        f = windows(packets)
        scan, victim = f[(SCANNER, 0)], f[(VICTIM, 0)]
        self.assertEqual((scan["dst_hosts"], scan["dst_ports"], scan["dst_host_ports"]), (1, 20, 20))
        self.assertEqual(scan["new_conn_out"], 20)
        self.assertEqual(scan["dst_port_entropy"], round(math.log2(20), 6))
        # Máy nạn nhân chỉ trả lời: không có đích, cổng nào trong vai client
        self.assertEqual((victim["dst_hosts"], victim["dst_ports"], victim["dst_port_entropy"]),
                         (0, 0, None))
        self.assertEqual((victim["src_hosts"], victim["new_conn_in"]), (1, 20))

    def test_horizontal_scan(self):
        packets = [pkt(SCANNER, f"192.168.10.{i}", 50000 + i, 22, ts=1 + i * 0.01) for i in range(1, 31)]
        f = windows(packets)[(SCANNER, 0)]
        self.assertEqual((f["dst_hosts"], f["dst_ports"], f["dst_host_ports"]), (30, 1, 30))
        self.assertEqual(f["dst_port_entropy"], 0.0)

    def test_server_replies_do_not_count_as_destinations(self):
        # Server web trả lời hai client: không được trông giống máy quét.
        packets = [
            pkt(SCANNER, VICTIM, 40001, 80, TCP_SYN, ts=1),
            pkt(VICTIM, SCANNER, 80, 40001, TCP_SYN | TCP_ACK, ts=1.1),
            pkt(CLIENT2, VICTIM, 40002, 80, TCP_SYN, ts=2),
            pkt(VICTIM, CLIENT2, 80, 40002, TCP_SYN | TCP_ACK, ts=2.1),
            pkt(VICTIM, CLIENT2, 80, 40002, TCP_ACK, ts=2.2),
        ]
        server = windows(packets)[(VICTIM, 0)]
        self.assertEqual((server["dst_hosts"], server["dst_ports"]), (0, 0))
        self.assertEqual((server["src_hosts"], server["new_conn_in"]), (2, 2))

    def test_packets_weight_entropy(self):
        # 3 gói tới cổng 443, 1 gói tới cổng 53
        packets = [pkt(SCANNER, VICTIM, 40001, 443, TCP_SYN, ts=1)]
        packets += [pkt(SCANNER, VICTIM, 40001, 443, TCP_ACK, ts=1 + i * 0.1) for i in (1, 2)]
        packets.append(pkt(SCANNER, VICTIM, 40002, 53, None, ts=2, proto=17))
        f = windows(packets)[(SCANNER, 0)]
        self.assertEqual(f["dst_port_entropy"], round(shannon_entropy([3, 1]), 6))
        self.assertEqual(f["new_conn_out"], 2)

    def test_icmp_counts_destination_without_port(self):
        f = windows([pkt(SCANNER, VICTIM, None, None, ts=1, proto=1),
                     pkt(SCANNER, CLIENT2, None, None, ts=1.1, proto=1)])[(SCANNER, 0)]
        self.assertEqual((f["dst_hosts"], f["dst_ports"], f["dst_port_entropy"]), (2, 0, None))

    def test_continuation_is_not_new_connection(self):
        # Kết nối dài bị active timeout cắt: phần sau không phải kết nối mới.
        settings = FlowSettings(active_timeout_s=5)
        packets = [pkt(SCANNER, VICTIM, 40001, 80, TCP_SYN, ts=1)]
        packets += [pkt(SCANNER, VICTIM, 40001, 80, TCP_ACK, ts=t) for t in (3, 5, 7, 9)]
        f = windows(packets, settings=settings)[(SCANNER, 0)]
        self.assertEqual(f["new_conn_out"], 1)

    def test_new_connection_counted_in_window_of_first_packet(self):
        packets = [pkt(SCANNER, VICTIM, 40001, 80, TCP_SYN, ts=1),
                   pkt(SCANNER, VICTIM, 40001, 80, TCP_ACK, ts=12)]
        f = windows(packets)
        self.assertEqual((f[(SCANNER, 0)]["new_conn_out"], f[(SCANNER, 10)]["new_conn_out"]), (1, 0))

    def test_schema(self):
        f = windows([pkt(SCANNER, VICTIM, 1, 2)])[(SCANNER, 0)]
        self.assertEqual(list(f), list(WINDOW_FEATURES))
        for name, (unit, text) in WINDOW_FEATURES.items():
            self.assertTrue(unit and text, name)
            self.assertIn(name, CSV_COLUMNS)


class CliTest(unittest.TestCase):
    def test_cli(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp)
            frames = [ether(ipv4(payload=tcp(40000 + i, 1000 + i))) for i in range(4)]
            pcap = pcap_file(d / "t.pcap", frames)
            with redirect_stdout(io.StringIO()):
                code = main([str(pcap), "--net", "192.168.50.20/32", "--csv", str(d / "w.csv")])
            with open(d / "w.csv", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        self.assertEqual(code, 0)
        self.assertEqual(tuple(rows[0]), CSV_COLUMNS)
        best = max(rows, key=lambda r: int(r["dst_ports"]))
        self.assertEqual((best["dst_ports"], best["new_conn_out"], best["dst_port_entropy"]),
                         ("4", "4", "2.0"))


if __name__ == "__main__":
    unittest.main()

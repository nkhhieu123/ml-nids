import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.flow_features import BASIC_FEATURES, basic_features
from nids.flows import CSV_COLUMNS, FlowAssigner, csv_row
from nids.packets import TCP_ACK, TCP_PSH, TCP_SYN, PacketRecord, parse_packet
from test_packets import ether, ipv4, raw, tcp, udp

CLIENT = "192.168.50.41"
SERVER = "192.168.50.30"
MS = 10**6


def pkt(src=CLIENT, dst=SERVER, sport=40000, dport=80, flags=TCP_ACK, proto=6,
        ts_ms=0, index=0, ip_len=40, payload=0):
    """Bản ghi packet tối giản; ``ts_ms`` tính bằng mili giây."""
    if proto not in (6, 17):
        sport = dport = None
    return PacketRecord(index, None if ts_ms is None else ts_ms * MS, src, dst, 4, proto,
                        ip_len + 14, ip_len, ip_len + 14, 34, False, sport, dport,
                        flags if proto == 6 else None, None, None,
                        payload if proto in (6, 17) else None)


def reply(**kw):
    return pkt(SERVER, CLIENT, 80, 40000, **kw)


def features(*records):
    assigner = FlowAssigner()
    for r in records:
        assigner.add(r)
    assigner.finish_all()
    return [basic_features(f) for f in assigner.flows()]


class BasicFeatureTest(unittest.TestCase):
    def test_http_like_exchange(self):
        (f,) = features(
            pkt(flags=TCP_SYN, ts_ms=0, ip_len=60),
            reply(flags=TCP_SYN | TCP_ACK, ts_ms=10, index=1, ip_len=60),
            pkt(ts_ms=20, index=2, ip_len=52),
            pkt(flags=TCP_ACK | TCP_PSH, ts_ms=21, index=3, ip_len=152, payload=100),
            reply(flags=TCP_ACK | TCP_PSH, ts_ms=1520, index=4, ip_len=1052, payload=1000),
        )
        self.assertEqual((f["packets"], f["fwd_packets"], f["bwd_packets"]), (5, 3, 2))
        self.assertEqual((f["bytes"], f["fwd_bytes"], f["bwd_bytes"]), (1376, 264, 1112))
        self.assertEqual((f["payload_bytes"], f["fwd_payload_bytes"], f["bwd_payload_bytes"]),
                         (1100, 100, 1000))
        self.assertEqual(f["duration_s"], "1.520000000")
        self.assertEqual(f["fwd_packet_share"], 0.6)
        self.assertEqual(f["fwd_byte_share"], round(264 / 1376, 6))

    def test_single_unanswered_syn(self):
        # Quét cổng: một SYN không được trả lời; tỷ lệ vẫn xác định, không chia cho 0.
        (f,) = features(pkt(flags=TCP_SYN))
        self.assertEqual((f["duration_s"], f["bwd_packets"]), ("0.000000000", 0))
        self.assertEqual((f["fwd_packet_share"], f["fwd_byte_share"]), (1.0, 1.0))

    def test_first_packet_from_server(self):
        # Flow bắt giữa chừng mở bằng gói server: fwd vẫn là client nên fwd có thể bằng 0.
        (f,) = features(reply(flags=TCP_ACK | TCP_PSH, payload=10, ip_len=50))
        self.assertEqual((f["fwd_packets"], f["fwd_packet_share"], f["fwd_byte_share"]),
                         (0, 0.0, 0.0))

    def test_icmp_has_no_payload_columns(self):
        (f,) = features(pkt(proto=1, ip_len=84), reply(proto=1, ts_ms=5, index=1, ip_len=84))
        self.assertIsNone(f["payload_bytes"])
        self.assertEqual((f["bytes"], f["fwd_byte_share"]), (168, 0.5))

    def test_unknown_payload_counted(self):
        # Gói TCP bị cắt trước Data Offset: không biết payload, đếm riêng.
        assigner = FlowAssigner()
        assigner.add(pkt(payload=None))
        assigner.finish_all()
        (flow,) = assigner.flows()
        self.assertEqual(flow.payload_unknown, 1)
        self.assertEqual(basic_features(flow)["payload_bytes"], 0)

    def test_out_of_order_time_gives_non_negative_duration(self):
        (f,) = features(pkt(ts_ms=100), pkt(ts_ms=40, index=1), pkt(ts_ms=90, index=2))
        self.assertEqual(f["duration_s"], "0.060000000")

    def test_missing_time(self):
        (f,) = features(pkt(ts_ms=None))
        self.assertIsNone(f["duration_s"])

    def test_fragment_bytes_counted(self):
        first = parse_packet(raw(ether(ipv4(17, udp(data=bytes(16)), flags_frag=0x2000)),
                                 index=0))
        later = parse_packet(raw(ether(ipv4(17, bytes(24), flags_frag=3)), index=1))
        (f,) = features(first, later)
        self.assertEqual((f["packets"], f["bytes"], f["payload_bytes"]), (2, 44 + 44, 40))

    def test_parsed_packets(self):
        a = parse_packet(raw(ether(ipv4(payload=tcp(data=b"hello")))))
        (f,) = features(a)
        self.assertEqual((f["bytes"], f["payload_bytes"]), (45, 5))


class SchemaTest(unittest.TestCase):
    def test_every_feature_has_unit_and_is_exported(self):
        (f,) = features(pkt())
        self.assertEqual(list(f), list(BASIC_FEATURES))
        for name, (unit, text) in BASIC_FEATURES.items():
            self.assertTrue(unit and text, name)
            self.assertIn(name, CSV_COLUMNS)

    def test_csv_row_has_all_columns(self):
        assigner = FlowAssigner()
        assigner.add(pkt())
        assigner.finish_all()
        row = csv_row(assigner.flows()[0])
        self.assertEqual(set(row), set(CSV_COLUMNS))
        self.assertEqual(row["payload_bytes"], 0)


if __name__ == "__main__":
    unittest.main()

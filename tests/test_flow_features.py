import random
import statistics
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.flow_features import (
    BASIC_FEATURES, FLAG_COLUMNS, STAT_FEATURES, RunningStats, basic_features, stat_features,
)
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

def stats_of(*records):
    assigner = FlowAssigner()
    for r in records:
        assigner.add(r)
    assigner.finish_all()
    return [stat_features(f) for f in assigner.flows()]


class RunningStatsTest(unittest.TestCase):
    def test_matches_statistics_module(self):
        rng = random.Random(42)
        values = [rng.randint(40, 1500) for _ in range(500)]
        rs = RunningStats()
        for v in values:
            rs.add(v)
        self.assertEqual((rs.n, rs.min, rs.max), (500, min(values), max(values)))
        self.assertAlmostEqual(rs.mean, statistics.fmean(values), places=9)
        self.assertAlmostEqual(rs.std, statistics.pstdev(values), places=9)

    def test_single_value_has_zero_std(self):
        rs = RunningStats()
        rs.add(60)
        self.assertEqual((rs.mean, rs.std), (60, 0.0))

    def test_empty(self):
        self.assertIsNone(RunningStats().std)


class StatFeatureTest(unittest.TestCase):
    def exchange(self):
        return (
            pkt(flags=TCP_SYN, ts_ms=0, ip_len=60),
            reply(flags=TCP_SYN | TCP_ACK, ts_ms=10, index=1, ip_len=60),
            pkt(ts_ms=30, index=2, ip_len=52),
            pkt(flags=TCP_ACK | TCP_PSH, ts_ms=40, index=3, ip_len=152, payload=100),
            reply(flags=TCP_ACK | TCP_PSH, ts_ms=100, index=4, ip_len=1052, payload=1000),
        )

    def test_sizes_per_direction(self):
        (f,) = stats_of(*self.exchange())
        self.assertEqual((f["pkt_len_min"], f["pkt_len_max"]), (52, 1052))
        self.assertEqual(f["pkt_len_mean"], round(statistics.fmean([60, 60, 52, 152, 1052]), 6))
        self.assertEqual(f["pkt_len_std"], round(statistics.pstdev([60, 60, 52, 152, 1052]), 6))
        self.assertEqual((f["fwd_pkt_len_min"], f["fwd_pkt_len_max"], f["fwd_pkt_len_mean"]),
                         (52, 152, round(264 / 3, 6)))
        self.assertEqual((f["bwd_pkt_len_mean"], f["bwd_pkt_len_std"]), (556.0, 496.0))

    def test_inter_arrival_per_direction(self):
        (f,) = stats_of(*self.exchange())
        # Mọi gói: 10, 20, 10, 60 ms; forward: 30, 10 ms; backward: 90 ms.
        self.assertEqual((f["iat_min"], f["iat_max"], f["iat_mean"]), (0.01, 0.06, 0.025))
        self.assertEqual(f["iat_std"], round(statistics.pstdev([0.01, 0.02, 0.01, 0.06]), 9))
        self.assertEqual((f["fwd_iat_min"], f["fwd_iat_max"], f["fwd_iat_mean"]), (0.01, 0.03, 0.02))
        self.assertEqual((f["bwd_iat_mean"], f["bwd_iat_std"]), (0.09, 0.0))

    def test_flag_counts(self):
        (f,) = stats_of(*self.exchange())
        self.assertEqual((f["syn_count"], f["ack_count"], f["psh_count"], f["fin_count"],
                          f["rst_count"], f["urg_count"]), (2, 4, 2, 0, 0, 0))

    def test_single_packet_flow(self):
        # SYN quét không được trả lời: chưa có khoảng cách nào, chiều backward trống.
        (f,) = stats_of(pkt(flags=TCP_SYN, ip_len=44))
        self.assertEqual((f["pkt_len_mean"], f["pkt_len_std"]), (44, 0.0))
        self.assertIsNone(f["iat_mean"])
        self.assertIsNone(f["bwd_pkt_len_min"])
        self.assertEqual(f["syn_count"], 1)

    def test_out_of_order_time_gives_zero_gap(self):
        (f,) = stats_of(pkt(ts_ms=100), pkt(ts_ms=40, index=1), pkt(ts_ms=90, index=2))
        self.assertEqual((f["iat_min"], f["iat_max"]), (0.0, 0.05))

    def test_udp_has_zero_flags(self):
        (f,) = stats_of(pkt(proto=17), reply(proto=17, ts_ms=5, index=1))
        self.assertEqual(sum(f[name] for name, _ in FLAG_COLUMNS), 0)

    def test_missing_time_skipped(self):
        (f,) = stats_of(pkt(ts_ms=None), pkt(ts_ms=None, index=1))
        self.assertIsNone(f["iat_min"])
        self.assertEqual(f["pkt_len_min"], 40)

    def test_schema(self):
        (f,) = stats_of(pkt())
        self.assertEqual(list(f), list(STAT_FEATURES))
        for name, (unit, text) in STAT_FEATURES.items():
            self.assertTrue(unit and text, name)
            self.assertIn(name, CSV_COLUMNS)


if __name__ == "__main__":
    unittest.main()

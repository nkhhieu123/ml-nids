import csv
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.flows import (
    BASIS_FIRST_PACKET, BASIS_SAME_ENDPOINT, BASIS_SERVICE_PORT, BASIS_SYN, BASIS_SYN_ACK,
    CSV_COLUMNS, FRAGMENT_TIMEOUT_S, FlowAssigner, main, make_key,
)
from nids.packets import (
    TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, PacketRecord, parse_packet,
)
from test_packets import ether, ipv4, pcap_file, raw, tcp, udp

CLIENT = "192.168.50.41"
SERVER = "192.168.50.30"
SEC = 10**9


def rec(src=CLIENT, dst=SERVER, sport=40000, dport=80, flags=TCP_SYN, proto=6,
        ts=1, index=0, version=4, fragment=False, frag_id=None, has_l4=True):
    """Bản ghi packet tối giản; ``ts`` tính bằng giây."""
    if proto not in (6, 17, 132) or not has_l4:
        sport = dport = None
    if proto != 6 or not has_l4:
        flags = None
    return PacketRecord(index, None if ts is None else ts * SEC, src, dst, version, proto,
                        60, 40, 60, 34 if has_l4 else None, fragment,
                        sport, dport, flags, frag_id)


def feed(*records):
    assigner = FlowAssigner()
    results = [assigner.add(r) for r in records]
    return assigner, results


class KeyTest(unittest.TestCase):
    def test_both_directions_give_same_key(self):
        a = make_key(4, 6, (CLIENT, 40000), (SERVER, 80))
        b = make_key(4, 6, (SERVER, 80), (CLIENT, 40000))
        self.assertEqual(a, b)
        self.assertEqual((a.a, a.b), ((SERVER, 80), (CLIENT, 40000)))

    def test_ip_compared_as_number_not_text(self):
        # Theo chuỗi thì "10.0.0.10" < "10.0.0.9"; theo số thì ngược lại.
        key = make_key(4, 17, ("10.0.0.10", 53), ("10.0.0.9", 53))
        self.assertEqual(key.a_ip, "10.0.0.9")

    def test_same_ip_ordered_by_port(self):
        key = make_key(4, 6, (CLIENT, 5000), (CLIENT, 22))
        self.assertEqual((key.a_port, key.b_port), (22, 5000))

    def test_ipv6_key(self):
        key = make_key(6, 17, ("fe80::2", 546), ("fe80::1", 547))
        self.assertEqual(key.a, ("fe80::1", 547))


class DirectionTest(unittest.TestCase):
    def test_syn_sender_is_forward(self):
        assigner, res = feed(
            rec(flags=TCP_SYN, index=0),
            rec(SERVER, CLIENT, 80, 40000, TCP_SYN | TCP_ACK, index=1),
            rec(flags=TCP_ACK, index=2),
            rec(flags=TCP_ACK | TCP_PSH, index=3),
        )
        self.assertEqual([fwd for _, fwd in res], [True, False, True, True])
        (flow,) = assigner.flows()
        self.assertEqual(flow.direction_basis, BASIS_SYN)
        self.assertEqual((flow.fwd_endpoint, flow.bwd_endpoint),
                         ((CLIENT, 40000), (SERVER, 80)))
        self.assertEqual((flow.fwd_packets, flow.bwd_packets), (3, 1))

    def test_missed_syn_uses_syn_ack(self):
        assigner, res = feed(rec(SERVER, CLIENT, 80, 40000, TCP_SYN | TCP_ACK),
                             rec(flags=TCP_ACK, index=1))
        flow = assigner.flows()[0]
        self.assertEqual(flow.direction_basis, BASIS_SYN_ACK)
        self.assertEqual(flow.fwd_endpoint, (CLIENT, 40000))
        self.assertEqual([fwd for _, fwd in res], [False, True])

    def test_mid_connection_uses_service_port(self):
        # Bắt giữa chừng, gói đầu là dữ liệu server gửi về: client vẫn là cổng 40000.
        assigner, res = feed(rec(SERVER, CLIENT, 80, 40000, TCP_ACK | TCP_PSH))
        flow = assigner.flows()[0]
        self.assertEqual(flow.direction_basis, BASIS_SERVICE_PORT)
        self.assertEqual(flow.fwd_endpoint, (CLIENT, 40000))
        self.assertFalse(res[0][1])

    def test_mid_connection_both_ports_high_or_low(self):
        for sport, dport in ((50000, 6881), (22, 80)):
            assigner, _ = feed(rec(SERVER, CLIENT, sport, dport, TCP_ACK))
            flow = assigner.flows()[0]
            self.assertEqual(flow.direction_basis, BASIS_FIRST_PACKET)
            self.assertEqual(flow.fwd_endpoint, (SERVER, sport))

    def test_rst_or_fin_first_falls_back_to_ports(self):
        for flags in (TCP_RST, TCP_FIN | TCP_ACK):
            assigner, _ = feed(rec(flags=flags))
            flow = assigner.flows()[0]
            self.assertEqual(flow.direction_basis, BASIS_SERVICE_PORT)
            self.assertEqual(flow.fwd_endpoint, (CLIENT, 40000))

    def test_udp_uses_first_packet_even_from_service_port(self):
        assigner, res = feed(rec(SERVER, CLIENT, 53, 5353, proto=17),
                             rec(CLIENT, SERVER, 5353, 53, proto=17, index=1))
        flow = assigner.flows()[0]
        self.assertEqual(flow.direction_basis, BASIS_FIRST_PACKET)
        self.assertEqual(flow.fwd_endpoint, (SERVER, 53))
        self.assertEqual([fwd for _, fwd in res], [True, False])

    def test_icmp_flow_has_no_ports(self):
        assigner, res = feed(rec(proto=1), rec(SERVER, CLIENT, proto=1, index=1))
        (flow,) = assigner.flows()
        self.assertEqual((flow.key.a_port, flow.key.b_port), (None, None))
        self.assertEqual(flow.fwd_endpoint, (CLIENT, None))
        self.assertEqual([fwd for _, fwd in res], [True, False])

    def test_same_endpoint_all_forward(self):
        assigner, res = feed(rec(CLIENT, CLIENT, 5000, 5000, proto=17),
                             rec(CLIENT, CLIENT, 5000, 5000, proto=17, index=1))
        flow = assigner.flows()[0]
        self.assertEqual(flow.direction_basis, BASIS_SAME_ENDPOINT)
        self.assertEqual((flow.fwd_packets, flow.bwd_packets), (2, 0))

    def test_direction_fixed_by_first_packet_only(self):
        # Gói SYN đến sau không đổi chiều đã chọn; tách flow mới là việc của C04-T02.
        assigner, res = feed(rec(SERVER, CLIENT, 80, 40000, TCP_ACK),
                             rec(flags=TCP_SYN, index=1))
        flow = assigner.flows()[0]
        self.assertEqual(flow.fwd_endpoint, (CLIENT, 40000))
        self.assertEqual(len(assigner.flows()), 1)


class SeparationTest(unittest.TestCase):
    def test_protocol_and_ports_separate_flows(self):
        assigner, _ = feed(
            rec(proto=6), rec(proto=17, index=1),
            rec(sport=40001, index=2), rec(SERVER, "192.168.50.42", index=3),
        )
        self.assertEqual(len(assigner.flows()), 4)

    def test_truncated_ports_go_to_portless_flow(self):
        assigner, _ = feed(rec(), rec(has_l4=False, index=1))
        self.assertEqual(len(assigner.flows()), 2)
        self.assertEqual(assigner.summary()["flow_khong_co_cong"], 1)

    def test_flows_in_order_of_first_packet_with_times(self):
        assigner, _ = feed(rec(ts=5), rec(proto=17, ts=6, index=1),
                           rec(SERVER, CLIENT, 80, 40000, TCP_ACK, ts=9, index=2))
        tcp_flow, udp_flow = assigner.flows()
        self.assertEqual((tcp_flow.first_index, udp_flow.first_index), (0, 1))
        self.assertEqual((tcp_flow.first_ts_ns, tcp_flow.last_ts_ns), (5 * SEC, 9 * SEC))

    def test_out_of_order_time_counted(self):
        assigner, _ = feed(rec(ts=5), rec(ts=4, index=1), rec(ts=None, index=2),
                           rec(ts=6, index=3))
        self.assertEqual(assigner.out_of_order, 1)


class FragmentTest(unittest.TestCase):
    def first(self, **kw):
        return rec(proto=17, sport=5353, dport=53, fragment=True, frag_id=77, **kw)

    def later(self, **kw):
        kw.setdefault("frag_id", 77)
        return rec(proto=17, fragment=True, has_l4=False, **kw)

    def test_later_fragments_join_flow_of_first(self):
        assigner, res = feed(self.first(), self.later(index=1), self.later(index=2))
        (flow,) = assigner.flows()
        self.assertEqual((flow.fwd_packets, flow.fragments_attached), (3, 2))
        self.assertTrue(all(fwd for _, fwd in res))

    def test_reply_fragments_are_backward(self):
        assigner, res = feed(
            rec(proto=17, sport=5353, dport=53),
            rec(SERVER, CLIENT, proto=17, sport=53, dport=5353, fragment=True,
                frag_id=9, index=1),
            self.later(src=SERVER, dst=CLIENT, frag_id=9, index=2),
        )
        (flow,) = assigner.flows()
        self.assertEqual([fwd for _, fwd in res], [True, False, False])
        self.assertEqual(flow.bwd_packets, 2)

    def test_orphan_fragment(self):
        # Không thấy mảnh đầu (khác Identification): vào flow không cổng của cặp IP.
        assigner, _ = feed(self.first(), self.later(frag_id=78, index=1))
        self.assertEqual(len(assigner.flows()), 2)
        self.assertEqual(assigner.orphan_fragments, 1)
        self.assertEqual(assigner.summary()["manh_mo_coi"], 1)

    def test_fragment_after_timeout_is_orphan(self):
        late = 1 + FRAGMENT_TIMEOUT_S + 1
        assigner, _ = feed(self.first(ts=1), self.later(ts=late, index=1))
        self.assertEqual(assigner.orphan_fragments, 1)
        # Thời hạn lấy từ cấu hình: đặt dài hơn thì mảnh vẫn được gắn.
        assigner = FlowAssigner(fragment_timeout_s=60)
        for r in (self.first(ts=1), self.later(ts=late, index=1)):
            assigner.add(r)
        self.assertEqual(assigner.orphan_fragments, 0)

    def test_identification_is_per_source(self):
        assigner, _ = feed(self.first(), self.later(src="192.168.50.42", index=1))
        self.assertEqual(assigner.orphan_fragments, 1)

    def test_real_parsed_fragments(self):
        payload = udp(5353, 53) + bytes(16)
        first = parse_packet(raw(ether(ipv4(17, payload, flags_frag=0x2000)), index=0))
        later = parse_packet(raw(ether(ipv4(17, bytes(24), flags_frag=3)), index=1))
        assigner, res = feed(first, later)
        (flow,) = assigner.flows()
        self.assertEqual(flow.fwd_endpoint[1], 5353)
        self.assertEqual(flow.fragments_attached, 1)


class CliTest(unittest.TestCase):
    def test_csv_and_stats(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp)
            pcap = pcap_file(d / "t.pcap", [
                ether(ipv4(payload=tcp(flags=TCP_SYN))),
                ether(ipv4(payload=tcp(80, 40000, TCP_SYN | TCP_ACK),
                           src=bytes([192, 168, 50, 30]), dst=bytes([192, 168, 50, 20]))),
                ether(ipv4(17, udp())),
            ])
            out = io.StringIO()
            with redirect_stdout(out):
                code = main([str(pcap), "--csv", str(d / "f.csv"), "--stats", str(d / "s.json")])
            self.assertEqual(code, 0)
            self.assertIn("3 packet IP, 2 flow", out.getvalue())
            with open(d / "f.csv", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(tuple(rows[0]), CSV_COLUMNS)
            self.assertEqual((rows[0]["fwd_ip"], rows[0]["fwd_port"], rows[0]["direction_basis"],
                              rows[0]["fwd_packets"], rows[0]["bwd_packets"]),
                             ("192.168.50.20", "40000", "syn", "1", "1"))
            stats = json.loads((d / "s.json").read_text(encoding="utf-8"))
            self.assertEqual(stats["flow"]["so_flow"], 2)
            self.assertEqual(stats["packet"]["giu_lai"], 3)


if __name__ == "__main__":
    unittest.main()

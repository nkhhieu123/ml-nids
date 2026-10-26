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
    CSV_COLUMNS, END_ACTIVE, END_FIN, END_IDLE, END_OF_INPUT, END_REUSE, END_RST,
    FlowAssigner, FlowSettings, main, make_key,
)
from nids.packets import (
    TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, PacketRecord, parse_packet,
)
from test_packets import ether, ipv4, pcap_file, raw, tcp, udp

CLIENT = "192.168.50.41"
SERVER = "192.168.50.30"
SEC = 10**9


def rec(src=CLIENT, dst=SERVER, sport=40000, dport=80, flags=TCP_SYN, proto=6,
        ts=1, index=0, version=4, fragment=False, frag_id=None, has_l4=True, seq=None):
    """Bản ghi packet tối giản; ``ts`` tính bằng giây."""
    if proto not in (6, 17, 132) or not has_l4:
        sport = dport = None
    if proto != 6 or not has_l4:
        flags = None
    return PacketRecord(index, None if ts is None else ts * SEC, src, dst, version, proto,
                        60, 40, 60, 34 if has_l4 else None, fragment,
                        sport, dport, flags, frag_id, seq if proto == 6 and has_l4 else None)


def feed(*records, **settings):
    assigner = FlowAssigner(FlowSettings(**settings))
    results = [assigner.add(r) for r in records]
    assigner.finish_all()
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
        # Gói tới sau không đổi chiều của flow đã có.
        assigner, res = feed(rec(SERVER, CLIENT, 50000, 6881, TCP_ACK),
                             rec(CLIENT, SERVER, 6881, 50000, TCP_ACK | TCP_PSH, index=1))
        (flow,) = assigner.flows()
        self.assertEqual(flow.fwd_endpoint, (SERVER, 50000))
        self.assertEqual([fwd for _, fwd in res], [True, False])


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
        late = 1 + FlowSettings().fragment_timeout_s + 1
        assigner, _ = feed(self.first(ts=1), self.later(ts=late, index=1))
        self.assertEqual(assigner.orphan_fragments, 1)
        # Thời hạn lấy từ cấu hình: đặt dài hơn thì mảnh vẫn được gắn.
        assigner, _ = feed(self.first(ts=1), self.later(ts=late, index=1),
                           fragment_timeout_s=60)
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

def srv(flags=TCP_ACK, **kw):
    """Gói TCP từ server 192.168.50.30:80 về client :40000."""
    return rec(SERVER, CLIENT, 80, 40000, flags, **kw)


class EndTest(unittest.TestCase):
    """Kết thúc flow: FIN/RST, timeout, 5-tuple dùng lại (C04-T02)."""

    def handshake(self, t=0):
        return [rec(flags=TCP_SYN, ts=t), srv(TCP_SYN | TCP_ACK, ts=t, index=1),
                rec(flags=TCP_ACK, ts=t, index=2)]

    def close(self, t=1, start=3):
        return [rec(flags=TCP_FIN | TCP_ACK, ts=t, index=start),
                srv(TCP_FIN | TCP_ACK, ts=t, index=start + 1)]

    def test_fin_both_sides_keeps_final_ack(self):
        assigner, _ = feed(*self.handshake(), *self.close(),
                           rec(flags=TCP_ACK, ts=1, index=5))
        (flow,) = assigner.flows()
        self.assertEqual((flow.end_reason, flow.packets), (END_FIN, 6))

    def test_half_close_keeps_flow_open(self):
        assigner, _ = feed(*self.handshake(), rec(flags=TCP_FIN | TCP_ACK, ts=1, index=3),
                           srv(TCP_ACK | TCP_PSH, ts=2, index=4))
        (flow,) = assigner.flows()
        self.assertEqual((flow.end_reason, flow.packets), (END_OF_INPUT, 5))

    def test_new_syn_after_fin_is_new_flow(self):
        assigner, _ = feed(*self.handshake(), *self.close(),
                           rec(flags=TCP_SYN, ts=1, index=5))
        first, second = assigner.flows()
        self.assertEqual(first.end_reason, END_FIN)
        self.assertEqual((second.direction_basis, second.continuation), ("syn", False))

    def test_packet_after_grace_is_continuation(self):
        late = 1 + FlowSettings().close_grace_s + 1
        assigner, res = feed(*self.handshake(), *self.close(),
                             srv(TCP_ACK, ts=late, index=5))
        first, second = assigner.flows()
        self.assertEqual((first.packets, second.packets), (5, 1))
        # Gói lẻ từ server: chiều lấy từ flow trước, không đoán lại.
        self.assertTrue(second.continuation)
        self.assertEqual(second.fwd_endpoint, (CLIENT, 40000))
        self.assertFalse(res[-1][1])

    def test_rst_keeps_in_flight_packets_then_syn_starts_new(self):
        assigner, _ = feed(*self.handshake(), rec(flags=TCP_RST, ts=1, index=3),
                           srv(TCP_ACK | TCP_PSH, ts=1, index=4),
                           rec(flags=TCP_SYN, ts=2, index=5))
        first, second = assigner.flows()
        self.assertEqual((first.end_reason, first.packets), (END_RST, 5))
        self.assertEqual(second.direction_basis, "syn")

    def test_scan_syn_rst_each_probe_is_a_flow(self):
        packets = []
        for i in range(3):
            packets += [rec(flags=TCP_SYN, ts=i, index=2 * i),
                        srv(TCP_RST | TCP_ACK, ts=i, index=2 * i + 1)]
        assigner, _ = feed(*packets)
        self.assertEqual([f.end_reason for f in assigner.flows()], [END_RST] * 3)

    def test_syn_on_open_flow_is_reuse(self):
        assigner, _ = feed(*self.handshake(), rec(flags=TCP_ACK | TCP_PSH, ts=1, index=3),
                           rec(flags=TCP_SYN, ts=2, index=4))
        first, second = assigner.flows()
        self.assertEqual(first.end_reason, END_REUSE)
        self.assertEqual(second.first_index, 4)

    def test_syn_retransmission_stays_in_flow(self):
        assigner, _ = feed(rec(flags=TCP_SYN, ts=0), rec(flags=TCP_SYN, ts=1, index=1),
                           srv(TCP_SYN | TCP_ACK, ts=1, index=2),
                           rec(flags=TCP_SYN, ts=2, index=3))
        (flow,) = assigner.flows()
        self.assertEqual(flow.packets, 4)

    def test_syn_with_new_sequence_number_is_new_attempt(self):
        # Như bản thu CTU-13: gửi lại SYN cùng số thứ tự, rồi thử lại với số mới.
        assigner, _ = feed(rec(flags=TCP_SYN, ts=0, seq=100), rec(flags=TCP_SYN, ts=3, index=1, seq=100),
                           rec(flags=TCP_SYN, ts=21, index=2, seq=900),
                           rec(flags=TCP_SYN, ts=24, index=3, seq=900))
        first, second = assigner.flows()
        self.assertEqual((first.packets, first.end_reason, second.packets), (2, END_REUSE, 2))

    def test_syn_ack_with_new_sequence_number(self):
        # Chỉ thấy SYN+ACK của server (chiều đi không được bắt): mỗi số thứ tự mới
        # là một lần server nhận kết nối; cùng số là gửi lại.
        assigner, _ = feed(srv(TCP_SYN | TCP_ACK, ts=0, seq=7), srv(TCP_SYN | TCP_ACK, ts=3, index=1, seq=7),
                           srv(TCP_SYN | TCP_ACK, ts=30, index=2, seq=8))
        first, second = assigner.flows()
        self.assertEqual((first.packets, first.end_reason), (2, END_REUSE))
        self.assertEqual((second.direction_basis, second.fwd_endpoint), ("syn_ack", (CLIENT, 40000)))

    def test_syn_ack_resent_after_server_ack_stays(self):
        # Như donbot của CTU-13: server đã gửi ACK rồi gửi lại SYN+ACK cùng số thứ tự.
        assigner, _ = feed(rec(flags=TCP_SYN, ts=0, seq=5), srv(TCP_SYN | TCP_ACK, ts=0, index=1, seq=7),
                           rec(flags=TCP_SYN, ts=3, index=2, seq=5), srv(TCP_ACK, ts=3, index=3, seq=8),
                           srv(TCP_SYN | TCP_ACK, ts=3, index=4, seq=7),
                           rec(flags=TCP_ACK, ts=3, index=5, seq=6))
        (flow,) = assigner.flows()
        self.assertEqual(flow.packets, 6)

    def test_first_syn_ack_of_new_attempt_is_a_reply(self):
        # Như bản thu CTU-13: client thử lại với số thứ tự mới; server đã gửi ACK
        # rồi mới gửi SYN+ACK đầu tiên của lần thử này.
        assigner, _ = feed(rec(flags=TCP_SYN, ts=0, seq=5), rec(flags=TCP_SYN, ts=9, index=1, seq=50),
                           srv(TCP_ACK, ts=9, index=2, seq=8),
                           srv(TCP_SYN | TCP_ACK, ts=10, index=3, seq=7))
        self.assertEqual([f.packets for f in assigner.flows()], [1, 3])

    def test_late_syn_after_syn_ack_stays(self):
        # SYN tới sau SYN+ACK (gửi lại hoặc bắt lệch thứ tự): cùng lần bắt tay.
        assigner, _ = feed(srv(TCP_SYN | TCP_ACK, ts=0, seq=7), rec(flags=TCP_SYN, ts=1, index=1, seq=5),
                           rec(flags=TCP_ACK, ts=1, index=2, seq=6))
        (flow,) = assigner.flows()
        self.assertEqual((flow.packets, flow.direction_basis), (3, "syn_ack"))

    def test_handshake_packet_after_rst_is_new_flow(self):
        # SYN+ACK gửi lại sau khi client đã RST: kết nối cũ đã bị hủy.
        assigner, _ = feed(srv(TCP_SYN | TCP_ACK, ts=0, seq=7), rec(flags=TCP_RST, ts=0, index=1),
                           srv(TCP_SYN | TCP_ACK, ts=5, index=2, seq=7),
                           rec(flags=TCP_RST, ts=5, index=3))
        self.assertEqual([(f.packets, f.end_reason) for f in assigner.flows()],
                         [(2, END_RST), (2, END_RST)])

    def test_reverse_syn_on_mid_stream_flow(self):
        # Trường hợp BitTorrent của bản thu CTU-13 (docs/18, mục 7).
        assigner, res = feed(rec(SERVER, CLIENT, 6881, 50000, TCP_ACK | TCP_PSH, ts=0),
                             rec(CLIENT, SERVER, 50000, 6881, TCP_SYN, ts=1, index=1),
                             rec(SERVER, CLIENT, 6881, 50000, TCP_SYN | TCP_ACK, ts=1,
                                 index=2))
        first, second = assigner.flows()
        self.assertEqual(first.end_reason, END_REUSE)
        self.assertEqual(second.fwd_endpoint, (CLIENT, 50000))
        self.assertEqual([fwd for _, fwd in res], [True, True, False])

    def test_idle_timeout(self):
        idle = FlowSettings().idle_timeout_s
        assigner, res = feed(rec(proto=17, ts=0),
                             rec(proto=17, ts=idle, index=1),          # đúng bằng: vẫn chung
                             rec(SERVER, CLIENT, 80, 40000, proto=17, ts=2 * idle + 1, index=2))
        first, second = assigner.flows()
        self.assertEqual((first.packets, first.end_reason), (2, END_IDLE))
        # Gói trả lời tới trước sau khoảng nghỉ: chiều vẫn theo flow trước.
        self.assertTrue(second.continuation)
        self.assertEqual(second.fwd_endpoint, (CLIENT, 40000))
        self.assertFalse(res[2][1])

    def test_active_timeout_splits_long_flow(self):
        packets = [rec(flags=TCP_SYN, ts=0)] + [
            rec(flags=TCP_ACK, ts=t, index=i) for i, t in enumerate(range(10, 131, 10), 1)]
        assigner, _ = feed(*packets)
        first, second = assigner.flows()
        self.assertEqual((first.end_reason, first.packets), (END_ACTIVE, 13))
        self.assertEqual((second.first_ts_ns, second.continuation), (130 * SEC, True))
        self.assertEqual(second.direction_basis, "syn")

    def test_direction_memory_expires(self):
        assigner, _ = feed(rec(proto=17, ts=0),
                           rec(SERVER, CLIENT, 80, 40000, proto=17, ts=500, index=1),
                           direction_memory_s=100)
        second = assigner.flows()[1]
        self.assertFalse(second.continuation)
        self.assertEqual(second.fwd_endpoint, (SERVER, 80))

    def test_settings_from_config(self):
        from nids.config import load_config
        s = FlowSettings.from_config(load_config())
        self.assertEqual((s.idle_timeout_s, s.active_timeout_s, s.close_grace_s),
                         (60, 120, 10))

    def test_missing_timestamps_do_not_split(self):
        assigner, _ = feed(rec(ts=None), srv(ts=None, index=1))
        self.assertEqual(len(assigner.flows()), 1)


class StreamingTest(unittest.TestCase):
    def test_idle_flow_returned_before_end(self):
        assigner = FlowAssigner()
        assigner.add(rec(proto=17, ts=0))
        for t in range(1, 70, 5):        # flow khác làm thời gian trôi
            assigner.add(rec("192.168.50.42", SERVER, proto=17, ts=t, index=t))
        done = assigner.pop_finished()
        self.assertEqual([(f.fwd_endpoint[0], f.end_reason) for f in done],
                         [(CLIENT, END_IDLE)])
        self.assertEqual(assigner.pop_finished(), [])

    def test_closed_flow_returned_after_grace(self):
        assigner = FlowAssigner()
        for r in (rec(flags=TCP_SYN, ts=0), rec(flags=TCP_RST, ts=0, index=1)):
            assigner.add(r)
        assigner.add(rec(proto=17, ts=5, index=2))
        self.assertEqual(assigner.pop_finished(), [])
        assigner.add(rec(proto=17, ts=12, index=3))
        self.assertEqual([f.end_reason for f in assigner.pop_finished()], [END_RST])

    def test_streaming_matches_batch(self):
        # Cùng chuỗi gói, dọn thường xuyên hay không cũng cho cùng kết quả.
        packets = []
        for i in range(40):
            t = i * 7
            packets.append(rec(sport=40000 + i % 3, flags=TCP_SYN if i % 5 == 0 else TCP_ACK,
                               ts=t, index=i))
            if i % 4 == 0:
                packets.append(rec(SERVER, CLIENT, 80, 40000 + i % 3, TCP_RST, ts=t,
                                   index=1000 + i))
        batch, _ = feed(*packets)
        streaming = FlowAssigner()
        for r in packets:
            streaming.add(r)
            streaming.expire()
        streaming.finish_all()
        shape = lambda a: [(f.first_index, f.packets, f.end_reason, f.continuation)
                           for f in a.flows()]
        self.assertEqual(shape(batch), shape(streaming))

    def test_fragment_of_returned_flow_is_orphan(self):
        assigner = FlowAssigner()
        assigner.add(rec(proto=17, sport=5353, dport=53, fragment=True, frag_id=5, ts=0))
        assigner.add(rec("192.168.50.42", SERVER, proto=17, ts=61, index=1))
        assigner.add(rec("192.168.50.42", SERVER, proto=17, ts=62, index=2))
        assigner.pop_finished()
        assigner.add(rec(proto=17, fragment=True, has_l4=False, frag_id=5, ts=62, index=3))
        self.assertEqual(assigner.orphan_fragments, 1)


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

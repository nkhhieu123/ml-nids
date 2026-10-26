import shutil
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.packets import inspect_packet
from nids.wireshark_compare import (
    KNOWN_ICMP_QUOTE, KNOWN_IP_CUT, KNOWN_TSO, TSHARK_FIELDS, WINDOWS_TSHARK, compare_file, compare_packet,
    expected_from_tshark,
)
from test_packets import ether, ipv4, ipv6, pcap_file, raw, tcp, udp


def tshark_line(**values):
    """Một dòng đầu ra tshark giả, chỉ điền các trường được truyền vào."""
    defaults = {"frame.number": "1", "frame.time_epoch": "1.000000000", "frame.len": "54",
                "frame.cap_len": "54"}
    defaults.update({k.replace("__", "."): v for k, v in values.items()})
    return "\t".join(defaults.get(f, "") for f in TSHARK_FIELDS) + "\n"


IPV4_TCP = dict(_ws__col__protocol="TCP", ip__src="192.168.50.20", ip__dst="192.168.50.30",
                ip__proto="6", ip__len="40", ip__flags__mf="False", ip__frag_offset="0",
                tcp__srcport="40000", tcp__dstport="80", tcp__flags="0x0002",
                tcp__seq_raw="1", tcp__len="0")


class ParseLineTest(unittest.TestCase):
    def test_ipv4_tcp(self):
        exp = expected_from_tshark(tshark_line(**IPV4_TCP))
        self.assertEqual((exp["ip_version"], exp["src_ip"], exp["protocols"]),
                         (4, "192.168.50.20", {6}))
        self.assertEqual((exp["ts"], exp["ports"], exp["tcp_flags"], exp["tcp_seq"]),
                         (10**9, (40000, 80), 2, 1))
        self.assertFalse(exp["is_fragment"])

    def test_non_ip(self):
        exp = expected_from_tshark(tshark_line(_ws__col__protocol="ARP"))
        self.assertIsNone(exp["ip_version"])
        self.assertEqual(exp["column_protocol"], "ARP")

    def test_outer_header_of_icmp_error_is_first_value(self):
        exp = expected_from_tshark(tshark_line(
            ip__src="10.0.0.2,10.0.0.1", ip__dst="10.0.0.1,10.0.0.2", ip__proto="1,17",
            ip__len="56,28", udp__srcport="5000", udp__dstport="7"))
        self.assertEqual((exp["src_ip"], exp["protocols"], exp["ip_len"]), ("10.0.0.2", {1}, 56))
        self.assertEqual((exp["ports"], exp["ip_layers"]), ((5000, 7), 2))

    def test_ipv6_extension_header_protocols(self):
        exp = expected_from_tshark(tshark_line(
            ipv6__src="fe80::1", ipv6__dst="ff02::1", ipv6__nxt="0", ipv6__plen="8",
            ipv6__hopopts__nxt="58"))
        self.assertEqual((exp["ip_version"], exp["protocols"], exp["ip_len"]), (6, {0, 58}, 48))


class ComparePacketTest(unittest.TestCase):
    def test_known_ip_header_cut_before_destination(self):
        frame = ether(ipv6(17, udp()), ethertype=0x86DD)[:42]     # như PCAP cắt của CTU-13
        exp = expected_from_tshark(tshark_line(ipv6__src="fe80::a00:27ff:feaa:bb01",
                                               frame__len="70", frame__cap_len="42"))
        self.assertEqual(compare_packet(inspect_packet(raw(frame)), exp), ([], KNOWN_IP_CUT))

    def frame(self):
        return raw(ether(ipv4(payload=tcp(40000, 80))))

    def test_match(self):
        exp = expected_from_tshark(tshark_line(**IPV4_TCP))
        self.assertEqual(compare_packet(inspect_packet(self.frame()), exp), ([], None))

    def test_detects_wrong_fields(self):
        exp = expected_from_tshark(tshark_line(**dict(IPV4_TCP, tcp__dstport="81", ip__len="41",
                                                     tcp__flags="0x0012", tcp__seq_raw="2", tcp__len="1")))
        diffs, _ = compare_packet(inspect_packet(self.frame()), exp)
        self.assertEqual(diffs, ["ip_len", "ports", "tcp_flags", "tcp_seq", "payload_len"])

    def test_skip_must_agree(self):
        arp = inspect_packet(raw(ether(bytes(28), ethertype=0x0806)))
        self.assertEqual(compare_packet(arp, expected_from_tshark(tshark_line()))[0], [])
        diffs, _ = compare_packet(arp, expected_from_tshark(tshark_line(**IPV4_TCP)))
        self.assertTrue(diffs[0].startswith("bộ trích xuất bỏ qua"))

    def test_known_icmp_quote(self):
        pkt = raw(ether(ipv4(proto=1, payload=bytes(8) + ipv4(proto=17, payload=udp(5000, 7)))))
        exp = expected_from_tshark(tshark_line(
            ip__src="192.168.50.20,192.168.50.20", ip__dst="192.168.50.30,192.168.50.30",
            ip__proto="1,17", ip__len="56,28", ip__flags__mf="False,False",
            ip__frag_offset="0,0", udp__srcport="5000", udp__dstport="7", frame__len="70",
            frame__cap_len="70"))
        self.assertEqual(compare_packet(inspect_packet(pkt), exp), ([], KNOWN_ICMP_QUOTE))

    def test_known_tso_zero_length(self):
        frame = bytearray(ether(ipv4(payload=tcp(40000, 80))))
        frame[16:18] = b"\0\0"
        exp = expected_from_tshark(tshark_line(**dict(IPV4_TCP, ip__len="0")))
        self.assertEqual(compare_packet(inspect_packet(raw(bytes(frame))), exp), ([], KNOWN_TSO))


def _tshark():
    return shutil.which("tshark") or (str(WINDOWS_TSHARK) if WINDOWS_TSHARK.exists() else None)


@unittest.skipUnless(_tshark(), "cần cài Wireshark (tshark)")
class TsharkFileTest(unittest.TestCase):
    def test_synthetic_file_matches(self):
        with TemporaryDirectory() as tmp:
            hop = bytes([6, 0]) + bytes(6)
            frames = [
                ether(ipv4(payload=tcp(51234, 443, 0x012))),
                ether(ipv4(proto=17, payload=udp(5353, 53, b"x" * 10))),
                ether(ipv4(flags_frag=0x2000, payload=tcp())),
                ether(ipv4(proto=17, payload=udp(), flags_frag=0x2000), vlans=[(0x8100, 10)]),
                ether(ipv6(0, hop + tcp(1234, 22)), ethertype=0x86DD),
                ether(bytes(28), ethertype=0x0806),
            ]
            report = compare_file(pcap_file(Path(tmp) / "t.pcap", frames), _tshark())
        self.assertEqual(report.mismatch_count, 0, report.examples)
        self.assertEqual(report.total, 6)
        self.assertEqual(sum(report.matched.values()), 5)
        self.assertEqual(dict(report.skipped_agree), {"ARP": 1})


if __name__ == "__main__":
    unittest.main()

import csv
import io
import json
import struct
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.packets import (
    CSV_COLUMNS, LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2,
    LINKTYPE_NULL, LINKTYPE_RAW, NOTE_FRAGMENT, NOTE_IP_LEN_OVER, NOTE_IP_LEN_ZERO,
    NOTE_L4_TRUNCATED, NOTE_NO_TS, NOTE_SNAPLEN, SKIP_IP_INVALID, SKIP_IP_TRUNCATED,
    SKIP_LINK_TRUNCATED, SKIP_LINKTYPE, SKIP_NON_IP, TCP_ACK, TCP_AE, TCP_SYN, ParseStats,
    extract_packets, inspect_packet, main, parse_packet, tcp_flag_names,
)
from nids.pcap_reader import PcapFormatError, RawPacket

MAC_A = bytes.fromhex("080027aabb01")
MAC_B = bytes.fromhex("080027aabb02")
IP_A = bytes([192, 168, 50, 20])
IP_B = bytes([192, 168, 50, 30])
IP6_A = bytes.fromhex("fe800000000000000a0027fffeaabb01")
IP6_B = bytes.fromhex("ff020000000000000000000000000001")


def ipv4(proto=6, payload=b"\0" * 20, flags_frag=0, ihl=5, src=IP_A, dst=IP_B):
    options = b"\0" * ((ihl - 5) * 4)
    total = ihl * 4 + len(payload)
    return struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, total, 1, flags_frag, 64, proto, 0,
                       src, dst) + options + payload


def ipv6(next_header=17, payload=b"\0" * 8):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), next_header, 64,
                       IP6_A, IP6_B) + payload


def tcp(sport=40000, dport=80, flags=TCP_SYN, data=b""):
    off_flags = (5 << 12) | flags
    return struct.pack("!HHIIHHHH", sport, dport, 1, 0, off_flags, 64240, 0, 0) + data


def udp(sport=5353, dport=53, data=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data


def ether(payload, ethertype=0x0800, vlans=()):
    tags = b"".join(struct.pack("!HH", tpid, vid) for tpid, vid in vlans)
    return MAC_B + MAC_A + tags + struct.pack("!H", ethertype) + payload


def raw(data, linktype=LINKTYPE_ETHERNET, origlen=None, index=0, ts_ns=1_000_000_000):
    return RawPacket(index, ts_ns, len(data),
                     len(data) if origlen is None else origlen, linktype, data)


class Ipv4Test(unittest.TestCase):
    def test_tcp_over_ethernet(self):
        rec = parse_packet(raw(ether(ipv4())))
        self.assertEqual((rec.src_ip, rec.dst_ip), ("192.168.50.20", "192.168.50.30"))
        self.assertEqual((rec.ip_version, rec.protocol, rec.protocol_name), (4, 6, "TCP"))
        self.assertEqual((rec.frame_len, rec.ip_len), (54, 40))
        self.assertEqual(rec.l4_offset, 34)
        self.assertFalse(rec.is_fragment)
        self.assertEqual(rec.ts_ns, 1_000_000_000)

    def test_ethernet_padding_does_not_change_ip_len(self):
        frame = ether(ipv4(proto=1, payload=b"\0" * 8)) + b"\0" * 18  # khung tối thiểu 60 byte
        rec = parse_packet(raw(frame))
        self.assertEqual((rec.frame_len, rec.ip_len, rec.protocol_name), (60, 28, "ICMP"))

    def test_options_shift_l4_offset(self):
        rec = parse_packet(raw(ether(ipv4(ihl=6))))
        self.assertEqual(rec.l4_offset, 14 + 24)

    def test_vlan_and_qinq(self):
        rec = parse_packet(raw(ether(ipv4(proto=17), vlans=[(0x88A8, 10), (0x8100, 20)])))
        self.assertEqual(rec.protocol_name, "UDP")
        self.assertEqual(rec.l4_offset, 22 + 20)

    def test_fragments(self):
        first = parse_packet(raw(ether(ipv4(flags_frag=0x2000))))
        later = parse_packet(raw(ether(ipv4(flags_frag=185))))
        self.assertTrue(first.is_fragment)
        self.assertEqual(first.l4_offset, 34)
        self.assertTrue(later.is_fragment)
        self.assertIsNone(later.l4_offset)
        # Identification của IPv4 (bằng 1 trong ipv4()) dùng để gắn các mảnh vào flow
        self.assertEqual((first.frag_id, later.frag_id), (1, 1))
        self.assertIsNone(parse_packet(raw(ether(ipv4()))).frag_id)

    def test_snaplen_cut_keeps_frame_len(self):
        frame = ether(ipv4(payload=b"\0" * 1000))
        rec = parse_packet(raw(frame[:96], origlen=len(frame)))
        self.assertEqual((rec.caplen, rec.frame_len, rec.ip_len), (96, 1034, 1020))

    def test_invalid_or_truncated_header(self):
        self.assertIsNone(parse_packet(raw(ether(ipv4())[:30])))
        bad_ihl = bytearray(ether(ipv4()))
        bad_ihl[14] = 0x43
        self.assertIsNone(parse_packet(raw(bytes(bad_ihl))))

    def test_non_ip_is_skipped(self):
        arp = ether(bytes(28), ethertype=0x0806)
        self.assertIsNone(parse_packet(raw(arp)))
        self.assertIsNone(parse_packet(raw(b"\x01\x02")))
        self.assertIsNone(parse_packet(raw(ether(ipv4()), linktype=105)))  # 802.11


class Ipv6Test(unittest.TestCase):
    def test_udp(self):
        rec = parse_packet(raw(ether(ipv6(), ethertype=0x86DD)))
        self.assertEqual((rec.src_ip, rec.dst_ip), ("fe80::a00:27ff:feaa:bb01", "ff02::1"))
        self.assertEqual((rec.ip_version, rec.protocol_name), (6, "UDP"))
        self.assertEqual((rec.ip_len, rec.l4_offset), (48, 54))

    def test_extension_headers(self):
        hop_by_hop = bytes([58, 0]) + bytes(6)            # next = ICMPv6
        rec = parse_packet(raw(ether(ipv6(0, hop_by_hop + bytes(8)), ethertype=0x86DD)))
        self.assertEqual(rec.protocol_name, "ICMPv6")
        self.assertEqual(rec.l4_offset, 14 + 40 + 8)

    def test_fragment_header(self):
        first = bytes([6, 0]) + struct.pack("!HI", 1, 7)              # offset 0, M=1
        later = bytes([6, 0]) + struct.pack("!HI", (100 << 3), 7)     # offset 100
        a = parse_packet(raw(ether(ipv6(44, first + bytes(20)), ethertype=0x86DD)))
        b = parse_packet(raw(ether(ipv6(44, later + bytes(20)), ethertype=0x86DD)))
        self.assertEqual((a.protocol_name, a.is_fragment, a.l4_offset), ("TCP", True, 62))
        self.assertEqual((b.protocol_name, b.is_fragment, b.l4_offset), ("TCP", True, None))
        self.assertEqual((a.frag_id, b.frag_id), (7, 7))


class PortFlagTest(unittest.TestCase):
    def test_tcp_ports_and_flags(self):
        rec = parse_packet(raw(ether(ipv4(payload=tcp(51234, 443, TCP_SYN | TCP_ACK)))))
        self.assertEqual((rec.src_port, rec.dst_port), (51234, 443))
        self.assertEqual(rec.tcp_flags, 0x012)
        self.assertEqual(rec.tcp_flag_names, "SYN,ACK")
        self.assertEqual(rec.tcp_seq, 1)          # tcp() đặt sequence number bằng 1

    def test_ae_bit_kept_reserved_bits_dropped(self):
        segment = bytearray(tcp(flags=TCP_ACK))
        segment[12] |= 0x0F                       # 3 bit dự trữ + AE
        rec = parse_packet(raw(ether(ipv4(payload=bytes(segment)))))
        self.assertEqual(rec.tcp_flags, TCP_AE | TCP_ACK)
        self.assertEqual(tcp_flag_names(0), "")

    def test_udp_ports_no_flags(self):
        rec = parse_packet(raw(ether(ipv4(proto=17, payload=udp()))))
        self.assertEqual((rec.src_port, rec.dst_port, rec.tcp_flags, rec.tcp_seq),
                         (5353, 53, None, None))
        self.assertEqual(rec.tcp_flag_names, "")

    def test_icmp_has_no_ports(self):
        rec = parse_packet(raw(ether(ipv4(proto=1, payload=bytes(8)))))
        self.assertEqual((rec.src_port, rec.dst_port, rec.tcp_flags), (None, None, None))

    def test_ipv6_tcp_after_extension_header(self):
        hop_by_hop = bytes([6, 0]) + bytes(6)
        rec = parse_packet(raw(ether(ipv6(0, hop_by_hop + tcp(1234, 22)), ethertype=0x86DD)))
        self.assertEqual((rec.src_port, rec.dst_port, rec.tcp_flag_names), (1234, 22, "SYN"))

    def test_snaplen_cut(self):
        frame = ether(ipv4(payload=tcp()))
        ports_only = parse_packet(raw(frame[:34 + 8], origlen=len(frame)))
        self.assertEqual((ports_only.src_port, ports_only.tcp_flags), (40000, None))
        # Bị cắt trước byte cờ: như Wireshark, không lấy số thứ tự dù còn đủ byte
        self.assertIsNone(ports_only.tcp_seq)
        nothing = parse_packet(raw(frame[:34 + 2], origlen=len(frame)))
        self.assertEqual((nothing.src_port, nothing.dst_port), (None, None))

    def test_ethernet_padding_is_not_read_as_ports(self):
        frame = ether(ipv4(payload=b"")) + bytes([0x12, 0x34, 0x56, 0x78]) + bytes(22)
        rec = parse_packet(raw(frame))
        self.assertEqual(rec.ip_len, 20)
        self.assertIsNone(rec.src_port)

    def test_later_fragment_has_no_ports(self):
        rec = parse_packet(raw(ether(ipv4(flags_frag=185, payload=tcp()))))
        self.assertEqual((rec.src_port, rec.tcp_flags), (None, None))


class SkipReasonTest(unittest.TestCase):
    def skip(self, pkt):
        result = inspect_packet(pkt)
        self.assertIsNone(result.record)
        return result.reason, result.detail

    def test_non_ip(self):
        self.assertEqual(self.skip(raw(ether(bytes(28), ethertype=0x0806))),
                         (SKIP_NON_IP, "ARP (0x0806)"))
        self.assertEqual(self.skip(raw(ether(bytes(28), ethertype=0x1234))),
                         (SKIP_NON_IP, "0x1234"))
        self.assertEqual(self.skip(raw(ether(bytes(40), ethertype=46))),   # khung 802.3
                         (SKIP_NON_IP, "802.3/LLC"))
        self.assertEqual(self.skip(raw(struct.pack("<I", 7) + ipv4(), LINKTYPE_NULL)),
                         (SKIP_NON_IP, "họ địa chỉ 7"))

    def test_unsupported_linktype(self):
        self.assertEqual(self.skip(raw(ether(ipv4()), linktype=105)),
                         (SKIP_LINKTYPE, "LINKTYPE 105"))

    def test_truncated_link_header(self):
        self.assertEqual(self.skip(raw(b"\x01\x02"))[0], SKIP_LINK_TRUNCATED)
        vlan_cut = ether(ipv4(), vlans=[(0x8100, 1)])[:16]
        self.assertEqual(self.skip(raw(vlan_cut)), (SKIP_LINK_TRUNCATED, "VLAN"))

    def test_truncated_ip_header(self):
        self.assertEqual(self.skip(raw(ether(ipv4())[:30])), (SKIP_IP_TRUNCATED, "IPv4"))
        self.assertEqual(self.skip(raw(ether(ipv6(), ethertype=0x86DD)[:50])),
                         (SKIP_IP_TRUNCATED, "IPv6"))

    def test_invalid_ip_header(self):
        frame = bytearray(ether(ipv4()))
        frame[14] = 0x43                                   # IHL = 3
        self.assertEqual(self.skip(raw(bytes(frame)))[0], SKIP_IP_INVALID)
        frame[14] = 0x65                                   # phiên bản 6 trong EtherType IPv4
        self.assertEqual(self.skip(raw(bytes(frame))), (SKIP_IP_INVALID, "IPv4: phiên bản 6"))
        frame = bytearray(ether(ipv4()))
        frame[16:18] = struct.pack("!H", 10)                # Total Length < 20
        self.assertEqual(self.skip(raw(bytes(frame)))[0], SKIP_IP_INVALID)
        self.assertEqual(self.skip(raw(bytes([0x50]) + bytes(30), LINKTYPE_RAW))[0],
                         SKIP_IP_INVALID)


class NoteTest(unittest.TestCase):
    def notes(self, pkt):
        result = inspect_packet(pkt)
        self.assertIsNotNone(result.record)
        return set(result.notes)

    def test_clean_packet_has_no_notes(self):
        self.assertEqual(self.notes(raw(ether(ipv4(payload=tcp())))), set())

    def test_snaplen_and_missing_l4(self):
        frame = ether(ipv4(payload=tcp()))
        self.assertEqual(self.notes(raw(frame[:40], origlen=len(frame))),
                         {NOTE_SNAPLEN, NOTE_L4_TRUNCATED})

    def test_fragment_and_no_timestamp(self):
        pkt = raw(ether(ipv4(flags_frag=185)), ts_ns=None)
        self.assertEqual(self.notes(pkt), {NOTE_FRAGMENT, NOTE_NO_TS})

    def test_total_length_zero_uses_captured_bytes(self):
        frame = bytearray(ether(ipv4(payload=tcp())))
        frame[16:18] = b"\0\0"
        result = inspect_packet(raw(bytes(frame)))
        self.assertEqual(result.record.ip_len, 40)
        self.assertEqual(result.record.dst_port, 80)
        self.assertEqual(set(result.notes), {NOTE_IP_LEN_ZERO})

    def test_ip_length_larger_than_frame(self):
        frame = bytearray(ether(ipv4(payload=tcp())))
        frame[16:18] = struct.pack("!H", 1500)
        self.assertEqual(self.notes(raw(bytes(frame))), {NOTE_IP_LEN_OVER})


class LinkTypeTest(unittest.TestCase):
    def test_linux_cooked(self):
        sll = struct.pack("!HHH8sH", 0, 1, 6, MAC_A + b"\0\0", 0x0800)
        sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 2, 1, 0, 6, MAC_A + b"\0\0")
        self.assertEqual(parse_packet(raw(sll + ipv4(), LINKTYPE_LINUX_SLL)).l4_offset, 36)
        self.assertEqual(parse_packet(raw(sll2 + ipv4(), LINKTYPE_LINUX_SLL2)).l4_offset, 40)

    def test_loopback_and_raw(self):
        self.assertEqual(parse_packet(raw(struct.pack("<I", 2) + ipv4(), LINKTYPE_NULL)).ip_version, 4)
        self.assertEqual(parse_packet(raw(struct.pack(">I", 30) + ipv6(), LINKTYPE_NULL)).ip_version, 6)
        self.assertEqual(parse_packet(raw(ipv6(), LINKTYPE_RAW)).ip_version, 6)


def pcap_file(path, frames, tail=b""):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", 100 + i, 5, len(frame), len(frame)) + frame
    path.write_bytes(out + tail)
    return path


class FileTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        arp = ether(bytes(28), ethertype=0x0806)
        self.pcap = pcap_file(self.dir / "t.pcap",
                              [ether(ipv4(payload=tcp())), arp,
                               ether(ipv6(payload=udp()), ethertype=0x86DD)])

    def test_extract_skips_non_ip(self):
        recs = list(extract_packets(self.pcap))
        self.assertEqual([r.index for r in recs], [0, 2])
        self.assertEqual([r.protocol_name for r in recs], ["TCP", "UDP"])

    def test_cli_writes_csv(self):
        out_csv = self.dir / "packets.csv"
        with redirect_stdout(io.StringIO()) as out:
            main([str(self.pcap), "--csv", str(out_csv)])
        self.assertIn("Tổng packet: 3; gói IP: 2", out.getvalue())
        with out_csv.open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(tuple(rows[0]), CSV_COLUMNS)
        self.assertEqual(rows[0]["ts"], "100.000005000")
        self.assertEqual(rows[1]["dst_ip"], "ff02::1")
        self.assertEqual((rows[0]["dst_port"], rows[0]["tcp_flags"], rows[0]["tcp_flag_names"]),
                         ("80", "2", "SYN"))
        self.assertEqual((rows[1]["dst_port"], rows[1]["tcp_flags"]), ("53", ""))

    def test_stats_count_skipped(self):
        stats = ParseStats()
        recs = list(extract_packets(self.pcap, stats))
        self.assertEqual(len(recs), 2)
        self.assertEqual((stats.total, stats.kept, stats.skipped_total), (3, 2, 1))
        self.assertEqual(dict(stats.skipped), {SKIP_NON_IP: 1})
        self.assertEqual(stats.first_skipped, {SKIP_NON_IP: 1})
        d = stats.as_dict()
        self.assertEqual(d["chi_tiet_bo_qua"], {SKIP_NON_IP: {"ARP (0x0806)": 1}})
        self.assertIsNone(d["loi_file"])

    def test_cut_file_keeps_earlier_packets(self):
        cut = pcap_file(self.dir / "cut.pcap", [ether(ipv4())], tail=b"\x01\x02\x03")
        stats = ParseStats()
        self.assertEqual(len(list(extract_packets(cut, stats))), 1)
        self.assertTrue(stats.truncated_file)
        self.assertIn("CẢNH BÁO: file kết thúc giữa chừng", "\n".join(stats.summary_lines()))

    def test_corrupt_record_stops_with_error(self):
        bad_header = struct.pack("<IIII", 0, 0, 10**7, 10**7)   # incl_len quá lớn
        bad = pcap_file(self.dir / "bad.pcap", [ether(ipv4())], tail=bad_header)
        with self.assertRaises(PcapFormatError):
            list(extract_packets(bad))
        stats = ParseStats()
        self.assertEqual(len(list(extract_packets(bad, stats))), 1)
        self.assertIn("incl_len", stats.file_error)
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main([str(bad)]), 1)
        self.assertIn("LỖI: dừng đọc vì file hỏng", out.getvalue())

    def test_cli_writes_stats_json(self):
        out_json = self.dir / "stats.json"
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main([str(self.pcap), "--stats", str(out_json)]), 0)
        self.assertIn("khong_phai_ip: 1 [ARP (0x0806)=1] (khung đầu tiên trong Wireshark: 2)",
                      out.getvalue())
        data = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertEqual((data["tong_packet"], data["bo_qua"]), (3, 1))
        self.assertEqual(data["bo_qua_theo_ly_do"], {SKIP_NON_IP: 1})


if __name__ == "__main__":
    unittest.main()

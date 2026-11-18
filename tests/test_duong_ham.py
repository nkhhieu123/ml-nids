"""Kiểm thử bóc lớp đường hầm: IP trong IP, GRE, VXLAN (QĐ-086)."""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.duong_ham import decapsulate, enabled
from nids.packets import parse_packet
from nids.pcap_reader import RawPacket

MAC = b"\x02\x00\x00\x00\x00\x01" * 2


def ip4(proto, payload, src="192.168.50.41", dst="192.168.50.42", frag=0):
    a = lambda s: bytes(int(x) for x in s.split("."))
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, frag, 64, proto, 0, a(src), a(dst)) + payload


def tcp(sport=40000, dport=8081):
    return struct.pack("!HHIIHHHH", sport, dport, 1, 0, (5 << 12) | 0x02, 64240, 0, 0)


def eth(payload, ethertype=0x0800):
    return MAC + struct.pack("!H", ethertype) + payload


def raw(data):
    return RawPacket(0, 10**9, len(data), len(data), 1, data)


INNER = ip4(6, tcp(), src="10.99.0.1", dst="10.99.0.2")


class DecapTest(unittest.TestCase):
    def check_inner(self, frame):
        rec = parse_packet(decapsulate(raw(frame)))
        self.assertEqual((rec.src_ip, rec.dst_ip, rec.protocol, rec.dst_port), ("10.99.0.1", "10.99.0.2", 6, 8081))

    def test_ipip(self):
        self.check_inner(eth(ip4(4, INNER)))

    def test_gre(self):
        self.check_inner(eth(ip4(47, struct.pack("!HH", 0, 0x0800) + INNER)))
        self.check_inner(eth(ip4(47, struct.pack("!HHI", 0x2000, 0x0800, 7) + INNER)))   # có trường khóa

    def test_vxlan(self):
        udp = struct.pack("!HHHH", 50000, 4789, 0, 0) + struct.pack("!BBHI", 0x08, 0, 0, 42 << 8)
        self.check_inner(eth(ip4(17, udp + eth(INNER))))

    def test_not_tunnel_unchanged(self):
        r = raw(eth(ip4(6, tcp())))
        self.assertIs(decapsulate(r), r)
        frag = raw(eth(ip4(4, INNER, frag=0x2000)))                 # gói đường hầm bị phân mảnh: giữ nguyên
        self.assertIs(decapsulate(frag), frag)
        udp = raw(eth(ip4(17, struct.pack("!HHHH", 50000, 53, 8, 0))))
        self.assertIs(decapsulate(udp), udp)

    def test_config(self):
        self.assertFalse(enabled({"capture": {}}))
        self.assertTrue(enabled({"capture": {"giai_duong_ham": True}}))


if __name__ == "__main__":
    unittest.main()

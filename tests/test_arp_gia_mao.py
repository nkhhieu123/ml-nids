"""Kiểm thử phát hiện dấu hiệu giả mạo ARP (gói ARP dựng tay, không phát lên mạng)."""

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.arp_gia_mao import ArpWatch, parse_arp, scan_pcap

A = bytes.fromhex("020000000001")
B = bytes.fromhex("020000000002")
EVIL = bytes.fromhex("0200000000ee")
BCAST = b"\xff" * 6


def arp(op, smac, sip, tip, frame_src=None, vlan=False):
    ip = lambda s: bytes(int(x) for x in s.split("."))
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + smac + ip(sip) + b"\0" * 6 + ip(tip)
    tag = struct.pack("!HH", 0x8100, 5) if vlan else b""
    return BCAST + (frame_src or smac) + tag + struct.pack("!H", 0x0806) + body


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1000 + i, 0, len(fr), len(fr)) + fr)


class ArpTest(unittest.TestCase):
    def test_parse_with_vlan(self):
        got = parse_arp(1, arp(2, A, "192.168.50.30", "192.168.50.41", vlan=True))
        self.assertEqual(got[1:4], (2, "02:00:00:00:00:01", "192.168.50.30"))

    def test_non_arp_ignored(self):
        self.assertIsNone(parse_arp(1, BCAST + A + struct.pack("!H", 0x0800) + b"\0" * 40))

    def test_normal_traffic_no_alert(self):
        w = ArpWatch()
        for t in range(5):
            w.add(t, parse_arp(1, arp(1, A, "192.168.50.41", "192.168.50.30")))
            w.add(t, parse_arp(1, arp(2, B, "192.168.50.30", "192.168.50.41")))
            w.add(t, parse_arp(1, arp(1, A, "0.0.0.0", "192.168.50.41")))     # thăm dò không học
        self.assertEqual(w.canh_bao, [])
        self.assertEqual(len(w.bang), 2)

    def test_mac_change_and_one_mac_many_ips(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.pcap"
            write_pcap(p, [arp(2, B, "192.168.50.30", "192.168.50.41"),
                           arp(2, EVIL, "192.168.50.30", "192.168.50.41"),   # nhận là .30
                           arp(2, EVIL, "192.168.50.41", "192.168.50.30"),   # nhận là .41
                           arp(2, EVIL, "192.168.50.42", "192.168.50.30"),
                           arp(2, A, "192.168.50.43", "192.168.50.30", frame_src=EVIL)])
            w = scan_pcap(p)
        kinds = [c["loai"] for c in w.canh_bao]
        self.assertEqual(kinds, ["doi_mac", "mot_mac_nhieu_ip", "khung_khong_khop"])
        self.assertEqual((w.canh_bao[0]["mac_cu"], w.canh_bao[0]["mac_moi"]), ("02:00:00:00:00:02", "02:00:00:00:00:ee"))


if __name__ == "__main__":
    unittest.main()

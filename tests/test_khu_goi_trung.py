"""Kiểm thử bộ khử gói trùng do mirror (QĐ-079)."""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.cam_bien import DuplicateFilter
from nids.pcap_reader import RawPacket

MAC = b"\x02\x00\x00\x00\x00\x01" * 2


def frame(ident, ttl=64, src=b"\xc0\xa8\x32\x29"):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, ident, 0, ttl, 17, 0, src, b"\xc0\xa8\x32\x1e")
    return MAC + struct.pack("!H", 0x0800) + ip + struct.pack("!HHHH", 1000, 53, 8, 0)


def raw(i, ts_ns, data):
    return RawPacket(i, ts_ns, len(data), len(data), 1, data)


class DuplicateFilterTest(unittest.TestCase):
    def test_copy_within_window_dropped(self):
        f = DuplicateFilter(1_000_000)
        self.assertFalse(f.is_duplicate(raw(0, 0, frame(1))))
        self.assertTrue(f.is_duplicate(raw(1, 2_000, frame(1, ttl=63))))      # bản sao qua router: khác TTL
        self.assertFalse(f.is_duplicate(raw(2, 3_000, frame(2))))              # gói khác (IP ID khác)
        self.assertFalse(f.is_duplicate(raw(3, 5_000_000, frame(1))))         # cùng nội dung nhưng quá 1 ms
        self.assertEqual(f.dropped, 1)

    def test_config(self):
        self.assertIsNone(DuplicateFilter.from_config({"capture": {"khu_goi_trung_ms": 0}}))
        self.assertIsNone(DuplicateFilter.from_config({"capture": {}}))
        self.assertEqual(DuplicateFilter.from_config({"capture": {"khu_goi_trung_ms": 1}}).window_ns, 1_000_000)


if __name__ == "__main__":
    unittest.main()

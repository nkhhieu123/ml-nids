import io
import struct
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.pcap_reader import (
    LINKTYPE_ETHERNET, PcapFormatError, PcapReader, main, read_packets,
)

# File PCAP 82 byte trong docs/04_dinh_dang_pcap.md, mục 5: một gói ARP.
DOC_EXAMPLE = bytes.fromhex(
    "d4c3b2a1020004000000000000000000"
    "0000040001000000889acc6a40e20100"
    "2a0000002a000000ffffffffffff0800"
    "27aabb01080600010800060400010800"
    "27aabb01c0a83214000000000000c0a8"
    "321e"
)
ARP = DOC_EXAMPLE[40:]


def pcap_bytes(packets, endian="<", nano=False, snaplen=262144, linktype=1):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)
    for sec, frac, data, origlen in packets:
        out += struct.pack(endian + "IIII", sec, frac, len(data), origlen) + data
    return out


def block(btype, body, endian="<"):
    body += b"\0" * (-len(body) % 4)
    total = len(body) + 12
    return struct.pack(endian + "II", btype, total) + body + struct.pack(endian + "I", total)


def shb(endian="<"):
    return block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def idb(linktype, snaplen=0, tsresol=None, endian="<"):
    body = struct.pack(endian + "HHI", linktype, 0, snaplen)
    if tsresol is not None:
        body += struct.pack(endian + "HH", 9, 1) + bytes([tsresol, 0, 0, 0])
        body += struct.pack(endian + "HH", 0, 0)
    return block(1, body, endian)


def epb(iface, ticks, data, origlen=None, endian="<"):
    origlen = len(data) if origlen is None else origlen
    body = struct.pack(endian + "IIIII", iface, ticks >> 32, ticks & 0xFFFFFFFF,
                       len(data), origlen) + data
    return block(6, body, endian)


class ReaderTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def write(self, content, name="t.pcap"):
        path = Path(self._tmp.name) / name
        path.write_bytes(content)
        return path


class PcapTest(ReaderTestCase):
    def test_doc_example(self):
        with PcapReader(self.write(DOC_EXAMPLE)) as reader:
            packets = list(reader)
        self.assertEqual(reader.format, "pcap")
        self.assertEqual(reader.version, (2, 4))
        self.assertEqual(reader.interfaces[0].linktype, LINKTYPE_ETHERNET)
        self.assertEqual(reader.interfaces[0].snaplen, 262144)
        self.assertEqual(len(packets), 1)
        pkt = packets[0]
        self.assertEqual(pkt.ts_ns, 1791793800_123456000)  # 12/10/2026 08:30:00.123456 UTC
        self.assertEqual((pkt.caplen, pkt.origlen), (42, 42))
        self.assertFalse(pkt.truncated)
        self.assertEqual(pkt.data[12:14], b"\x08\x06")  # EtherType ARP
        self.assertFalse(reader.truncated_file)

    def test_big_endian_nanosecond(self):
        data = pcap_bytes([(100, 5, b"\x01\x02\x03", 3), (101, 999999999, b"\x04", 1500)],
                          endian=">", nano=True, snaplen=96)
        packets = list(read_packets(self.write(data)))
        self.assertEqual([p.ts_ns for p in packets], [100_000000005, 101_999999999])
        self.assertEqual([p.index for p in packets], [0, 1])
        self.assertTrue(packets[1].truncated)
        self.assertEqual(packets[1].origlen, 1500)

    def test_header_only_file_has_no_packets(self):
        with PcapReader(self.write(pcap_bytes([]))) as reader:
            self.assertEqual(list(reader), [])
            self.assertEqual(reader.packets_read, 0)

    def test_truncated_tail_is_reported(self):
        data = pcap_bytes([(1, 0, ARP, 42), (2, 0, ARP, 42)])
        with PcapReader(self.write(data[:-10])) as reader:
            packets = list(reader)
        self.assertEqual(len(packets), 1)
        self.assertTrue(reader.truncated_file)

    def test_rejects_unknown_magic(self):
        with self.assertRaises(PcapFormatError):
            PcapReader(self.write(b"GIF89a" + bytes(30))).open()

    def test_rejects_absurd_record_length(self):
        data = pcap_bytes([]) + struct.pack("<IIII", 0, 0, 10**7, 10**7)
        with self.assertRaises(PcapFormatError):
            list(read_packets(self.write(data)))


class PcapngTest(ReaderTestCase):
    def test_two_interfaces_and_resolution(self):
        data = (shb() + idb(1) + idb(101, tsresol=9)
                + epb(0, 1_000_000, ARP)          # micro giây mặc định -> 1 giây
                + block(5, bytes(16))             # Interface Statistics Block, bỏ qua
                + epb(1, 2_500_000_000, b"\x45" + bytes(19)))
        with PcapReader(self.write(data, "t.pcapng")) as reader:
            packets = list(reader)
        self.assertEqual(reader.format, "pcapng")
        self.assertEqual(reader.version, (1, 0))
        self.assertEqual([p.interface for p in packets], [0, 1])
        self.assertEqual([p.linktype for p in packets], [1, 101])
        self.assertEqual([p.ts_ns for p in packets], [1_000_000_000, 2_500_000_000])
        self.assertEqual(packets[0].data, ARP)
        self.assertEqual(reader.skipped_blocks, 1)

    def test_big_endian_section(self):
        data = shb(">") + idb(1, endian=">") + epb(0, 7, ARP, origlen=60, endian=">")
        (pkt,) = read_packets(self.write(data, "t.pcapng"))
        self.assertEqual(pkt.ts_ns, 7000)
        self.assertEqual((pkt.caplen, pkt.origlen), (42, 60))

    def test_simple_packet_block_has_no_timestamp(self):
        spb = block(3, struct.pack("<I", 42) + ARP)
        (pkt,) = read_packets(self.write(shb() + idb(1) + spb, "t.pcapng"))
        self.assertIsNone(pkt.ts_ns)
        self.assertIsNone(pkt.ts)
        self.assertEqual(pkt.data, ARP)

    def test_new_section_resets_interfaces(self):
        data = shb() + idb(1) + epb(0, 1, ARP) + shb() + idb(101) + epb(0, 2, ARP)
        packets = list(read_packets(self.write(data, "t.pcapng")))
        self.assertEqual([p.linktype for p in packets], [1, 101])
        self.assertEqual([p.index for p in packets], [0, 1])

    def test_rejects_undeclared_interface(self):
        with self.assertRaises(PcapFormatError):
            list(read_packets(self.write(shb() + epb(0, 1, ARP), "t.pcapng")))


class CompressedTest(ReaderTestCase):
    """Đọc thẳng file PCAP/PCAPNG nén gzip/bz2, không cần giải nén trước."""

    def _gz(self, data):
        import gzip
        return gzip.compress(data)

    def _bz2(self, data):
        import bz2
        return bz2.compress(data)

    def test_gzip_pcap(self):
        data = pcap_bytes([(1, 0, ARP, 42), (2, 500000, ARP, 42)])
        with PcapReader(self.write(self._gz(data), "t.pcap.gz")) as reader:
            packets = list(reader)
        self.assertEqual(reader.compression, "gzip")
        self.assertEqual(reader.format, "pcap")
        self.assertEqual([p.ts_ns for p in packets], [1_000_000_000, 2_500_000_000])
        self.assertEqual(packets[0].data, ARP)

    def test_bz2_pcap(self):
        data = pcap_bytes([(5, 0, ARP, 42)])
        with PcapReader(self.write(self._bz2(data), "t.pcap.bz2")) as reader:
            packets = list(reader)
        self.assertEqual(reader.compression, "bz2")
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].ts_ns, 5_000_000_000)

    def test_gzip_pcapng_two_sections(self):
        # Hai Section Header Block: buộc dùng đường unread trên luồng nén.
        data = shb() + idb(1) + epb(0, 1, ARP) + shb() + idb(101) + epb(0, 2, ARP)
        with PcapReader(self.write(self._gz(data), "t.pcapng.gz")) as reader:
            packets = list(reader)
        self.assertEqual(reader.compression, "gzip")
        self.assertEqual(reader.format, "pcapng")
        self.assertEqual([p.linktype for p in packets], [1, 101])
        self.assertEqual([p.index for p in packets], [0, 1])

    def test_compression_detected_by_magic_not_extension(self):
        # Nội dung gzip nhưng tên .pcap: vẫn nhận ra nhờ magic.
        data = pcap_bytes([(9, 0, ARP, 42)])
        with PcapReader(self.write(self._gz(data), "nham_ten.pcap")) as reader:
            packets = list(reader)
        self.assertEqual(reader.compression, "gzip")
        self.assertEqual(packets[0].ts_ns, 9_000_000_000)

    def test_plain_file_has_no_compression(self):
        with PcapReader(self.write(DOC_EXAMPLE)) as reader:
            list(reader)
        self.assertIsNone(reader.compression)


class CliTest(ReaderTestCase):
    def test_prints_summary(self):
        out = io.StringIO()
        with redirect_stdout(out):
            main([str(self.write(DOC_EXAMPLE))])
        text = out.getvalue()
        self.assertIn("2026-10-12T08:30:00.123456000Z", text)
        self.assertIn("Số packet: 1", text)


if __name__ == "__main__":
    unittest.main()

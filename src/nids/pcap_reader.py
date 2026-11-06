"""Đọc file PCAP và PCAPNG theo từng packet (C03-T01).

Bộ đọc chỉ tách bản ghi: thời điểm bắt, độ dài đã lưu, độ dài gốc, kiểu tầng
liên kết và byte thô của gói. Việc phân tích header Ethernet/IP/TCP làm ở bước
sau. Định dạng file được mô tả trong docs/04_dinh_dang_pcap.md.

File được đọc tuần tự theo luồng, không nạp cả file vào bộ nhớ, nên dùng được
cho bản thu nhiều GB.

    with PcapReader("data/pcap/k1-binh-thuong-train-01.pcap") as reader:
        for pkt in reader:
            ...
"""

import argparse
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# 4 byte đầu file đọc theo little-endian -> (thứ tự byte của file, đơn vị phần lẻ/giây)
PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 10**6),
    0xA1B23C4D: ("<", 10**9),
    0xD4C3B2A1: (">", 10**6),
    0x4D3CB2A1: (">", 10**9),
}
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D

# Kiểu block PCAPNG mang gói tin
BLOCK_IDB = 0x00000001
BLOCK_OBSOLETE_PACKET = 0x00000002
BLOCK_SPB = 0x00000003
BLOCK_EPB = 0x00000006

OPT_END = 0
OPT_IF_TSRESOL = 9
OPT_IF_TSOFFSET = 14

LINKTYPE_ETHERNET = 1

# Không gói nào trên mạng lab dài hơn mức này. Bản ghi vượt quá coi là file hỏng.
MAX_RECORD_LEN = 262144


class PcapFormatError(ValueError):
    """File không phải PCAP/PCAPNG hoặc cấu trúc bị hỏng."""


# Magic của file nén; dùng để nhận ra, không phụ thuộc phần mở rộng tên file.
GZIP_MAGIC = b"\x1f\x8b"
BZ2_MAGIC = b"BZh"


class _PushbackReader:
    """Bọc luồng đọc tuần tự để trả lại (``unread``) vài byte đã đọc.

    Dùng cho luồng nén (gzip/bz2) vì không tua lui được rẻ: thay cho ``seek(-n, 1)``.
    """

    def __init__(self, stream):
        self._s = stream
        self._buf = b""

    def read(self, n=-1):
        if n is None or n < 0:
            data = self._buf + self._s.read()
            self._buf = b""
            return data
        if not self._buf:
            return self._s.read(n)
        if len(self._buf) >= n:
            out, self._buf = self._buf[:n], self._buf[n:]
            return out
        out = self._buf + self._s.read(n - len(self._buf))
        self._buf = b""
        return out

    def unread(self, data):
        self._buf = data + self._buf

    def close(self):
        self._s.close()


@dataclass(frozen=True)
class RawPacket:
    index: int          # thứ tự trong file, bắt đầu từ 0
    ts_ns: int | None   # thời điểm bắt, nano giây từ epoch UTC; None với Simple Packet Block
    caplen: int         # số byte đã lưu (incl_len)
    origlen: int        # độ dài gói trên đường truyền (orig_len)
    linktype: int       # mã LINKTYPE, quyết định byte đầu của data thuộc header nào
    data: bytes
    interface: int = 0  # chỉ số giao diện; PCAP luôn là 0

    @property
    def ts(self) -> float | None:
        """Thời điểm bắt tính bằng giây (float, mất độ chính xác dưới micro giây)."""
        return None if self.ts_ns is None else self.ts_ns / 1e9

    @property
    def truncated(self) -> bool:
        """Gói bị cắt khi bắt (snaplen nhỏ hơn độ dài gốc)."""
        return self.caplen < self.origlen


@dataclass
class Interface:
    linktype: int
    snaplen: int
    units_per_s: int = 10**6  # độ phân giải timestamp
    offset_s: int = 0         # if_tsoffset


class PcapReader:
    """Đọc tuần tự một file PCAP hoặc PCAPNG, mỗi lần lặp trả về một RawPacket.

    Sau khi đọc, các thuộc tính sau mô tả file:

    - ``format``: ``"pcap"`` hoặc ``"pcapng"``
    - ``interfaces``: danh sách Interface (PCAP có đúng một)
    - ``packets_read``: số packet đã trả về
    - ``truncated_file``: True nếu file kết thúc giữa chừng một bản ghi
    - ``skipped_blocks``: số block PCAPNG không chứa packet đã bỏ qua
    """

    def __init__(self, path):
        self.path = Path(path)
        self._f = None
        self.format = None
        self.version = None
        self.interfaces = []
        self.packets_read = 0
        self.truncated_file = False
        self.skipped_blocks = 0
        self.compression = None   # None, "gzip" hoặc "bz2": nhận ra qua magic, không qua tên file
        self._endian = "<"

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    def open(self):
        self._f = self._open_maybe_compressed()
        try:
            self._read_file_header()
        except BaseException:
            self.close()
            raise
        return self

    def _open_maybe_compressed(self):
        """Mở file; nếu là gzip/bz2 thì giải nén trong luồng (đọc thẳng .gz/.bz2, không cần giải nén trước)."""
        with self.path.open("rb") as probe:
            head = probe.read(3)
        if head[:2] == GZIP_MAGIC:
            import gzip
            self.compression = "gzip"
            return _PushbackReader(gzip.open(self.path, "rb"))
        if head[:3] == BZ2_MAGIC:
            import bz2
            self.compression = "bz2"
            return _PushbackReader(bz2.open(self.path, "rb"))
        return self.path.open("rb")   # file thường: giữ seek() nhanh, không bọc

    def _rewind4(self, four):
        """Tua lui 4 byte vừa đọc; luồng nén dùng unread, file thường dùng seek."""
        if self.compression:
            self._f.unread(four)
        else:
            self._f.seek(-4, 1)

    def _read_file_header(self):
        head = self._f.read(4)
        if len(head) < 4:
            raise PcapFormatError(f"{self.path}: file quá ngắn, không có header")
        magic = struct.unpack("<I", head)[0]
        if magic in PCAP_MAGICS:
            self.format = "pcap"
            self._read_pcap_header(magic)
        elif magic == PCAPNG_SHB:
            self.format = "pcapng"
            self._read_shb(head)
        else:
            raise PcapFormatError(
                f"{self.path}: 4 byte đầu {head.hex(' ')} không phải PCAP hay PCAPNG"
            )

    def close(self):
        if self._f is not None:
            self._f.close()
            self._f = None

    def __iter__(self):
        if self._f is None:
            self.open()
        if self.format == "pcap":
            return self._iter_pcap()
        return self._iter_pcapng()

    # ---- PCAP ----

    def _read_pcap_header(self, magic):
        self._endian, units = PCAP_MAGICS[magic]
        rest = self._f.read(20)
        if len(rest) < 20:
            raise PcapFormatError(f"{self.path}: Global Header thiếu byte")
        major, minor, _zone, _sigfigs, snaplen, network = struct.unpack(
            self._endian + "HHiIII", rest
        )
        self.version = (major, minor)
        # 16 bit thấp là LINKTYPE; các bit cao có thể mang thông tin FCS.
        self.interfaces = [Interface(network & 0xFFFF, snaplen, units)]

    def _iter_pcap(self):
        iface = self.interfaces[0]
        limit = max(iface.snaplen, MAX_RECORD_LEN)
        header = struct.Struct(self._endian + "IIII")
        while True:
            raw = self._f.read(16)
            if not raw:
                return
            if len(raw) < 16:
                self.truncated_file = True
                return
            ts_sec, ts_frac, caplen, origlen = header.unpack(raw)
            if caplen > limit:
                raise PcapFormatError(
                    f"{self.path}: packet {self.packets_read} có incl_len={caplen},"
                    f" vượt giới hạn {limit}; file hỏng"
                )
            data = self._f.read(caplen)
            if len(data) < caplen:
                self.truncated_file = True
                return
            ts_ns = ts_sec * 10**9 + ts_frac * 10**9 // iface.units_per_s
            yield self._packet(ts_ns, caplen, origlen, iface.linktype, data, 0)

    # ---- PCAPNG ----

    def _read_shb(self, type_bytes):
        """Đọc Section Header Block; 4 byte kiểu block đã được đọc."""
        raw = self._f.read(8)
        if len(raw) < 8:
            raise PcapFormatError(f"{self.path}: Section Header Block thiếu byte")
        if struct.unpack("<I", raw[4:])[0] == PCAPNG_BYTE_ORDER_MAGIC:
            self._endian = "<"
        elif struct.unpack(">I", raw[4:])[0] == PCAPNG_BYTE_ORDER_MAGIC:
            self._endian = ">"
        else:
            raise PcapFormatError(f"{self.path}: Byte-Order Magic không hợp lệ")
        total = struct.unpack(self._endian + "I", raw[:4])[0]
        if total < 28 or total % 4:
            raise PcapFormatError(f"{self.path}: Section Header Block có độ dài {total}")
        body = self._f.read(total - 12)
        if len(body) < total - 12:
            raise PcapFormatError(f"{self.path}: Section Header Block thiếu byte")
        self.version = struct.unpack(self._endian + "HH", body[:4])
        # Section mới: chỉ số giao diện đánh lại từ 0.
        self.interfaces = []

    def _iter_pcapng(self):
        e = self._endian
        while True:
            raw = self._f.read(8)
            if not raw:
                return
            if len(raw) < 8:
                self.truncated_file = True
                return
            if struct.unpack("<I", raw[:4])[0] == PCAPNG_SHB:
                self._rewind4(raw[4:8])
                self._read_shb(raw[:4])
                e = self._endian
                continue
            btype, total = struct.unpack(e + "II", raw)
            if total < 12 or total % 4:
                raise PcapFormatError(
                    f"{self.path}: block kiểu 0x{btype:08x} có độ dài {total} không hợp lệ"
                )
            rest = self._f.read(total - 8)
            if len(rest) < total - 8:
                self.truncated_file = True
                return
            body = rest[:-4]
            if btype == BLOCK_IDB:
                self.interfaces.append(self._parse_idb(body))
            elif btype == BLOCK_EPB:
                yield self._parse_epb(body)
            elif btype == BLOCK_SPB:
                yield self._parse_spb(body)
            elif btype == BLOCK_OBSOLETE_PACKET:
                yield self._parse_obsolete(body)
            else:
                self.skipped_blocks += 1

    def _parse_idb(self, body):
        linktype, _reserved, snaplen = struct.unpack(self._endian + "HHI", body[:8])
        iface = Interface(linktype, snaplen)
        for code, value in self._options(body[8:]):
            if code == OPT_IF_TSRESOL and value:
                v = value[0]
                iface.units_per_s = 2 ** (v & 0x7F) if v & 0x80 else 10**v
            elif code == OPT_IF_TSOFFSET and len(value) == 8:
                iface.offset_s = struct.unpack(self._endian + "q", value)[0]
        return iface

    def _options(self, raw):
        pos = 0
        while pos + 4 <= len(raw):
            code, length = struct.unpack(self._endian + "HH", raw[pos:pos + 4])
            if code == OPT_END:
                return
            yield code, raw[pos + 4:pos + 4 + length]
            pos += 4 + (length + 3) // 4 * 4

    def _interface(self, idx):
        if idx >= len(self.interfaces):
            raise PcapFormatError(
                f"{self.path}: packet {self.packets_read} tham chiếu giao diện {idx}"
                f" chưa được khai báo"
            )
        return self.interfaces[idx]

    def _ts_ns(self, iface, high, low):
        ticks = (high << 32) | low
        return iface.offset_s * 10**9 + ticks * 10**9 // iface.units_per_s

    def _parse_epb(self, body):
        idx, high, low, caplen, origlen = struct.unpack(self._endian + "IIIII", body[:20])
        iface = self._interface(idx)
        return self._packet(self._ts_ns(iface, high, low), caplen, origlen,
                            iface.linktype, body[20:20 + caplen], idx)

    def _parse_spb(self, body):
        (origlen,) = struct.unpack(self._endian + "I", body[:4])
        iface = self._interface(0)
        caplen = min(origlen, len(body) - 4)
        if iface.snaplen:
            caplen = min(caplen, iface.snaplen)
        return self._packet(None, caplen, origlen, iface.linktype, body[4:4 + caplen], 0)

    def _parse_obsolete(self, body):
        idx, _drops, high, low, caplen, origlen = struct.unpack(
            self._endian + "HHIIII", body[:20]
        )
        iface = self._interface(idx)
        return self._packet(self._ts_ns(iface, high, low), caplen, origlen,
                            iface.linktype, body[20:20 + caplen], idx)

    def _packet(self, ts_ns, caplen, origlen, linktype, data, interface):
        if len(data) < caplen:
            raise PcapFormatError(
                f"{self.path}: packet {self.packets_read} khai báo {caplen} byte"
                f" nhưng block chỉ chứa {len(data)} byte"
            )
        pkt = RawPacket(self.packets_read, ts_ns, caplen, origlen, linktype, data, interface)
        self.packets_read += 1
        return pkt


def read_packets(path):
    """Duyệt các packet của một file; đóng file khi duyệt xong."""
    with PcapReader(path) as reader:
        yield from reader


def _format_ts(ts_ns):
    if ts_ns is None:
        return "-"
    sec, ns = divmod(ts_ns, 10**9)
    base = datetime.fromtimestamp(sec, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{ns:09d}Z"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Đọc file PCAP/PCAPNG theo từng packet và in tóm tắt."
    )
    parser.add_argument("file", help="đường dẫn file .pcap hoặc .pcapng")
    parser.add_argument("-n", "--count", type=int, default=10,
                        help="số packet đầu tiên được in (mặc định: %(default)s)")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    first = last = None
    total_bytes = 0
    with PcapReader(args.file) as reader:
        for pkt in reader:
            if pkt.index < args.count:
                print(f"{pkt.index:>6}  {_format_ts(pkt.ts_ns)}  if={pkt.interface}"
                      f"  linktype={pkt.linktype}  {pkt.caplen}/{pkt.origlen} byte"
                      f"  {pkt.data[:16].hex(' ')}")
            if pkt.ts_ns is not None:
                first = pkt.ts_ns if first is None else first
                last = pkt.ts_ns
            total_bytes += pkt.origlen
        print()
        print(f"Định dạng: {reader.format} {reader.version[0]}.{reader.version[1]}")
        for i, iface in enumerate(reader.interfaces):
            print(f"Giao diện {i}: linktype={iface.linktype} snaplen={iface.snaplen}"
                  f" độ phân giải=1/{iface.units_per_s} giây")
        print(f"Số packet: {reader.packets_read}, tổng độ dài gốc: {total_bytes} byte")
        print(f"Thời gian: {_format_ts(first)} -> {_format_ts(last)}")
        if reader.skipped_blocks:
            print(f"Block không chứa packet đã bỏ qua: {reader.skipped_blocks}")
        if reader.truncated_file:
            print("CẢNH BÁO: file kết thúc giữa chừng một bản ghi; bản ghi cuối bị bỏ")


if __name__ == "__main__":
    main()

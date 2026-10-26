"""Trích xuất timestamp, IP, giao thức, độ dài, cổng và cờ TCP từ từng packet.

Nhận RawPacket của pcap_reader, bóc header tầng liên kết rồi đọc header IPv4
hoặc IPv6 (C03-T02), sau đó đọc cổng của TCP/UDP/SCTP và cờ TCP khi các trường
này có trong gói (C03-T03). Packet không phải IP, hoặc header bị cắt/không hợp
lệ, bị bỏ qua kèm lý do; ParseStats đếm số gói bỏ qua theo lý do và các điểm
bất thường của gói vẫn được giữ (C03-T04).

    stats = ParseStats()
    for rec in extract_packets("data/pcap/k1-binh-thuong-train-01.pcap", stats):
        print(rec.ts_ns, rec.src_ip, rec.dst_ip, rec.protocol_name, rec.ip_len)
    print("\n".join(stats.summary_lines()))
"""

import argparse
import csv
import socket
import json
import struct
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from ipaddress import IPv6Address

from .pcap_reader import PcapFormatError, PcapReader, RawPacket

# Mã LINKTYPE được hỗ trợ (xem docs/04_dinh_dang_pcap.md, mục 2)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = (0x8100, 0x88A8, 0x9100)  # 802.1Q, 802.1ad (QinQ)
# Các EtherType không phải IP hay gặp, chỉ dùng để ghi tên trong thống kê bỏ qua
ETHERTYPE_NAMES = {
    0x0806: "ARP", 0x8035: "RARP", 0x88CC: "LLDP", 0x888E: "EAPOL",
    0x8863: "PPPoE Discovery", 0x8864: "PPPoE Session", 0x8847: "MPLS",
    0x8848: "MPLS", 0x88E5: "MACsec", 0x88F7: "PTP", 0x9000: "Loopback",
    0x8899: "Realtek", 0x893A: "IEEE 1905",
}

# Giá trị họ địa chỉ trong header loopback BSD (LINKTYPE_NULL)
NULL_AF_INET = 2
NULL_AF_INET6 = (10, 24, 28, 30)  # Linux, NetBSD/OpenBSD, FreeBSD, macOS

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58
PROTO_SCTP = 132
PROTOCOL_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP",
    51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

# Header mở rộng của IPv6 có dạng (next header, độ dài) ở 2 byte đầu
IPV6_EXT_HOP_BY_HOP = 0
IPV6_EXT_ROUTING = 43
IPV6_EXT_FRAGMENT = 44
IPV6_EXT_AH = 51
IPV6_EXT_DEST_OPTS = 60
IPV6_NO_NEXT = 59

# Giao thức có cổng nguồn/đích ở 4 byte đầu header
PORT_PROTOCOLS = (PROTO_TCP, PROTO_UDP, PROTO_SCTP)

# Cờ TCP: 8 bit ở byte 13 và bit thấp nhất của byte 12 (AE, trước đây là NS).
# Ba bit dự trữ còn lại không phải cờ nên bị bỏ qua.
TCP_FIN = 0x001
TCP_SYN = 0x002
TCP_RST = 0x004
TCP_PSH = 0x008
TCP_ACK = 0x010
TCP_URG = 0x020
TCP_ECE = 0x040
TCP_CWR = 0x080
TCP_AE = 0x100
TCP_FLAG_MASK = 0x1FF
TCP_FLAG_NAMES = (
    (TCP_SYN, "SYN"), (TCP_ACK, "ACK"), (TCP_FIN, "FIN"), (TCP_RST, "RST"),
    (TCP_PSH, "PSH"), (TCP_URG, "URG"), (TCP_ECE, "ECE"), (TCP_CWR, "CWR"),
    (TCP_AE, "AE"),
)


# Lý do bỏ qua một packet
SKIP_LINKTYPE = "linktype_khong_ho_tro"       # kiểu tầng liên kết chưa hỗ trợ, ví dụ 802.11
SKIP_NON_IP = "khong_phai_ip"                 # tầng liên kết đọc được nhưng không chở IP, ví dụ ARP
SKIP_LINK_TRUNCATED = "header_lien_ket_bi_cat"
SKIP_IP_TRUNCATED = "header_ip_bi_cat"
SKIP_IP_INVALID = "header_ip_sai"             # sai phiên bản, IHL hoặc Total Length
SKIP_REASONS = (SKIP_NON_IP, SKIP_LINKTYPE, SKIP_LINK_TRUNCATED, SKIP_IP_TRUNCATED,
                SKIP_IP_INVALID)

# Điểm bất thường của gói vẫn được giữ lại
NOTE_SNAPLEN = "bi_cat_snaplen"               # caplen < orig_len
NOTE_L4_TRUNCATED = "thieu_header_tang_tren"  # không đọc được cổng/cờ TCP vì gói bị cắt
NOTE_FRAGMENT = "phan_manh_ip"
NOTE_IP_LEN_ZERO = "ip_len_bang_0"            # IPv4 Total Length 0 (TSO), lấy theo byte đã bắt
NOTE_IP_LEN_OVER = "ip_len_vuot_khung"        # header IP khai báo dài hơn khung, gói không bị cắt
NOTE_NO_TS = "khong_co_timestamp"             # Simple Packet Block của PCAPNG
NOTES = (NOTE_SNAPLEN, NOTE_L4_TRUNCATED, NOTE_FRAGMENT, NOTE_IP_LEN_ZERO,
         NOTE_IP_LEN_OVER, NOTE_NO_TS)


@dataclass(frozen=True)
class PacketRecord:
    index: int            # thứ tự packet trong file
    ts_ns: int | None     # thời điểm bắt, nano giây từ epoch UTC
    src_ip: str
    dst_ip: str
    ip_version: int       # 4 hoặc 6
    protocol: int         # số hiệu giao thức tầng trên (6 = TCP, 17 = UDP, ...)
    frame_len: int        # độ dài gói trên đường truyền (orig_len), gồm cả header liên kết
    ip_len: int           # độ dài gói IP theo header IP (IPv4 total length; IPv6 40 + payload length)
    caplen: int           # số byte đã lưu trong file
    l4_offset: int | None  # vị trí header tầng trên trong data; None với mảnh IP không phải mảnh đầu
    is_fragment: bool     # gói thuộc một datagram IP bị phân mảnh
    src_port: int | None = None   # cổng TCP/UDP/SCTP; None nếu không có hoặc bị cắt
    dst_port: int | None = None
    tcp_flags: int | None = None  # 9 bit cờ TCP (TCP_*); None nếu không phải TCP hoặc bị cắt
    frag_id: int | None = None    # Identification của datagram bị phân mảnh; None nếu không phân mảnh
    tcp_seq: int | None = None    # số thứ tự TCP (sequence number); None nếu không phải TCP hoặc bị cắt
    payload_len: int | None = None  # số byte dữ liệu TCP/UDP theo ip_len (không tính header); xem docs/20

    @property
    def protocol_name(self) -> str:
        return PROTOCOL_NAMES.get(self.protocol, str(self.protocol))

    @property
    def tcp_flag_names(self) -> str:
        """Tên các cờ đang bật, ví dụ "SYN,ACK"; chuỗi rỗng nếu không có cờ TCP."""
        return tcp_flag_names(self.tcp_flags)

    @property
    def ts(self) -> float | None:
        return None if self.ts_ns is None else self.ts_ns / 1e9


@dataclass(frozen=True)
class ParseResult:
    record: PacketRecord | None   # None khi gói bị bỏ qua
    reason: str | None = None     # lý do bỏ qua (SKIP_*)
    detail: str = ""              # chi tiết lý do, ví dụ "ARP (0x0806)", "LINKTYPE 105"
    notes: tuple[str, ...] = ()   # điểm bất thường của gói được giữ (NOTE_*)


class ParseStats:
    """Đếm số gói giữ lại, gói bỏ qua theo lý do, và lỗi ở mức file.

    ``first_skipped`` ghi chỉ số packet đầu tiên của mỗi lý do; trong Wireshark
    đó là khung số ``index + 1``.
    """

    def __init__(self):
        self.total = 0
        self.kept = 0
        self.skipped = Counter()
        self.skipped_detail = Counter()   # (lý do, chi tiết) -> số gói
        self.first_skipped = {}
        self.notes = Counter()
        self.truncated_file = False
        self.skipped_blocks = 0
        self.file_error = None

    @property
    def skipped_total(self) -> int:
        return self.total - self.kept

    def add(self, pkt: RawPacket, result: ParseResult):
        self.total += 1
        if result.record is None:
            self.skipped[result.reason] += 1
            self.skipped_detail[(result.reason, result.detail)] += 1
            self.first_skipped.setdefault(result.reason, pkt.index)
            return
        self.kept += 1
        self.notes.update(result.notes)

    def read_file_state(self, reader: PcapReader):
        self.truncated_file = self.truncated_file or reader.truncated_file
        self.skipped_blocks += reader.skipped_blocks

    def as_dict(self) -> dict:
        details = {}
        for (reason, detail), n in self.skipped_detail.most_common():
            details.setdefault(reason, {})[detail or "-"] = n
        return {
            "tong_packet": self.total,
            "giu_lai": self.kept,
            "bo_qua": self.skipped_total,
            "bo_qua_theo_ly_do": dict(self.skipped.most_common()),
            "chi_tiet_bo_qua": details,
            "packet_dau_tien_bo_qua": self.first_skipped,
            "ghi_chu_goi_giu_lai": dict(self.notes.most_common()),
            "file_bi_cut": self.truncated_file,
            "block_pcapng_bo_qua": self.skipped_blocks,
            "loi_file": self.file_error,
        }

    def summary_lines(self) -> list[str]:
        pct = 100 * self.skipped_total / self.total if self.total else 0
        lines = [f"Tổng packet: {self.total}; gói IP: {self.kept}; bỏ qua: "
                 f"{self.skipped_total} ({pct:.2f}%)"]
        if self.skipped:
            lines.append("Bỏ qua theo lý do:")
            for reason, n in self.skipped.most_common():
                parts = [f"{d or '-'}={c}" for (r, d), c in self.skipped_detail.most_common()
                         if r == reason]
                lines.append(f"  {reason}: {n} [{', '.join(parts[:5])}]"
                             f" (khung đầu tiên trong Wireshark: {self.first_skipped[reason] + 1})")
        if self.notes:
            lines.append("Ghi chú trên gói giữ lại: " + ", ".join(
                f"{note}={n}" for note, n in self.notes.most_common()))
        if self.skipped_blocks:
            lines.append(f"Block PCAPNG không chứa packet đã bỏ qua: {self.skipped_blocks}")
        if self.truncated_file:
            lines.append("CẢNH BÁO: file kết thúc giữa chừng một bản ghi; bản ghi cuối bị bỏ")
        if self.file_error:
            lines.append(f"LỖI: dừng đọc vì file hỏng: {self.file_error}")
        if self.total and not self.kept:
            lines.append("CẢNH BÁO: không có gói IP nào; kiểm tra kiểu tầng liên kết của file")
        return lines


class _Skip(Exception):
    """Gói bị bỏ qua: lý do (SKIP_*) và chi tiết để thống kê."""

    def __init__(self, reason, detail=""):
        super().__init__(reason, detail)
        self.reason = reason
        self.detail = detail


def network_offset(linktype: int, data: bytes) -> tuple[int, int] | None:
    """Tìm header tầng mạng: trả về (vị trí bắt đầu, phiên bản IP) hoặc None."""
    try:
        return _network_offset(linktype, data)
    except _Skip:
        return None


def _network_offset(linktype, data):
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            raise _Skip(SKIP_LINK_TRUNCATED, "Ethernet")
        pos = 12
        ethertype = struct.unpack_from("!H", data, pos)[0]
        while ethertype in ETHERTYPE_VLAN:
            pos += 4
            if len(data) < pos + 2:
                raise _Skip(SKIP_LINK_TRUNCATED, "VLAN")
            ethertype = struct.unpack_from("!H", data, pos)[0]
        return _from_ethertype(ethertype, pos + 2)
    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            raise _Skip(SKIP_LINK_TRUNCATED, "Linux cooked")
        return _from_ethertype(struct.unpack_from("!H", data, 14)[0], 16)
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            raise _Skip(SKIP_LINK_TRUNCATED, "Linux cooked v2")
        return _from_ethertype(struct.unpack_from("!H", data, 0)[0], 20)
    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            raise _Skip(SKIP_LINK_TRUNCATED, "loopback")
        # Họ địa chỉ ghi theo thứ tự byte của máy bắt gói; thử cả hai chiều.
        for fmt in ("<I", ">I"):
            family = struct.unpack_from(fmt, data, 0)[0]
            if family == NULL_AF_INET:
                return 4, 4
            if family in NULL_AF_INET6:
                return 4, 6
        raise _Skip(SKIP_NON_IP, f"họ địa chỉ {struct.unpack_from('<I', data, 0)[0]}")
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not data:
            raise _Skip(SKIP_IP_TRUNCATED, "IP thô rỗng")
        version = data[0] >> 4
        if version not in (4, 6):
            raise _Skip(SKIP_IP_INVALID, f"phiên bản {version}")
        return 0, version
    raise _Skip(SKIP_LINKTYPE, f"LINKTYPE {linktype}")


def _from_ethertype(ethertype, pos):
    if ethertype == ETHERTYPE_IPV4:
        return pos, 4
    if ethertype == ETHERTYPE_IPV6:
        return pos, 6
    raise _Skip(SKIP_NON_IP, ethertype_name(ethertype))


def ethertype_name(ethertype: int) -> str:
    """Tên EtherType dùng trong thống kê, ví dụ "ARP (0x0806)"."""
    if ethertype < 0x0600:
        # Giá trị nhỏ hơn 0x0600 là trường độ dài của khung 802.3, theo sau là LLC.
        return "802.3/LLC"
    name = ETHERTYPE_NAMES.get(ethertype)
    return f"{name} (0x{ethertype:04x})" if name else f"0x{ethertype:04x}"


def inspect_packet(pkt: RawPacket) -> ParseResult:
    """Phân tích một packet; nếu bỏ qua thì ghi lý do, nếu giữ thì ghi các điểm bất thường."""
    try:
        record, notes = _parse(pkt)
    except _Skip as skip:
        return ParseResult(None, skip.reason, skip.detail)
    return ParseResult(record, notes=notes)


def parse_packet(pkt: RawPacket) -> PacketRecord | None:
    """Trích xuất các trường IP của một packet; None nếu không phải gói IP đọc được."""
    return inspect_packet(pkt).record


def _parse(pkt):
    pos, version = _network_offset(pkt.linktype, pkt.data)
    notes = []
    if version == 4:
        src, dst, proto, ip_len, l4_offset, frag_id, hdr_end = _parse_ipv4(pkt.data, pos, notes)
    else:
        src, dst, proto, ip_len, l4_offset, frag_id, hdr_end = _parse_ipv6(pkt.data, pos, notes)
    is_fragment = frag_id is not None
    src_port = dst_port = tcp_flags = tcp_seq = tcp_hdr_len = None
    if l4_offset is not None and proto in PORT_PROTOCOLS:
        # Chỉ đọc trong phạm vi gói IP để không lấy nhầm byte đệm của khung Ethernet.
        end = min(len(pkt.data), pos + ip_len)
        src_port, dst_port, tcp_flags, tcp_seq, tcp_hdr_len = _parse_l4(
            pkt.data, l4_offset, end, proto)
        if src_port is None or (proto == PROTO_TCP and tcp_flags is None):
            notes.append(NOTE_L4_TRUNCATED)
    payload_len = _payload_len(proto, ip_len, None if hdr_end is None else hdr_end - pos,
                               l4_offset is not None, tcp_hdr_len)
    if pkt.truncated:
        notes.append(NOTE_SNAPLEN)
    elif pos + ip_len > len(pkt.data):
        notes.append(NOTE_IP_LEN_OVER)
    if is_fragment:
        notes.append(NOTE_FRAGMENT)
    if pkt.ts_ns is None:
        notes.append(NOTE_NO_TS)
    record = PacketRecord(pkt.index, pkt.ts_ns, src, dst, version, proto,
                          pkt.origlen, ip_len, pkt.caplen, l4_offset, is_fragment,
                          src_port, dst_port, tcp_flags, frag_id, tcp_seq, payload_len)
    return record, tuple(notes)


def _payload_len(proto, ip_len, ip_hdr_len, has_l4_header, tcp_hdr_len):
    """Số byte dữ liệu TCP/UDP của gói, tính từ ip_len nên đúng cả khi gói bị cắt.

    Mảnh IP không phải mảnh đầu chỉ chứa dữ liệu. TCP cần độ dài header (Data
    Offset) nên trả None nếu header bị cắt trước byte đó; giao thức khác trả None.
    """
    if proto not in (PROTO_TCP, PROTO_UDP) or ip_hdr_len is None:
        return None
    if not has_l4_header:
        l4_hdr_len = 0
    elif proto == PROTO_UDP:
        l4_hdr_len = 8
    elif tcp_hdr_len is not None and tcp_hdr_len >= 20:
        l4_hdr_len = tcp_hdr_len
    else:
        return None
    payload = ip_len - ip_hdr_len - l4_hdr_len
    return payload if payload >= 0 else None


def _parse_ipv4(data, pos, notes):
    if len(data) < pos + 20:
        raise _Skip(SKIP_IP_TRUNCATED, "IPv4")
    ver_ihl, _tos, total_len, ident, flags_frag, _ttl, proto = struct.unpack_from(
        "!BBHHHBB", data, pos
    )
    ihl = (ver_ihl & 0x0F) * 4
    if ver_ihl >> 4 != 4:
        raise _Skip(SKIP_IP_INVALID, f"IPv4: phiên bản {ver_ihl >> 4}")
    if ihl < 20:
        raise _Skip(SKIP_IP_INVALID, "IPv4: IHL nhỏ hơn 20 byte")
    if total_len == 0 and len(data) >= pos + ihl:
        # Gói gửi đi được bắt trước khi card mạng chia đoạn (TSO) có Total Length 0;
        # Wireshark khi đó lấy độ dài theo số byte đã bắt, ở đây làm giống vậy.
        total_len = len(data) - pos
        notes.append(NOTE_IP_LEN_ZERO)
    elif total_len < ihl:
        raise _Skip(SKIP_IP_INVALID, "IPv4: Total Length nhỏ hơn header")
    frag_offset = flags_frag & 0x1FFF
    more_fragments = bool(flags_frag & 0x2000)
    src = socket.inet_ntoa(data[pos + 12:pos + 16])
    dst = socket.inet_ntoa(data[pos + 16:pos + 20])
    l4_offset = pos + ihl if frag_offset == 0 else None
    frag_id = ident if more_fragments or frag_offset > 0 else None
    return src, dst, proto, total_len, l4_offset, frag_id, pos + ihl


def _parse_ipv6(data, pos, notes):
    if len(data) < pos + 40:
        raise _Skip(SKIP_IP_TRUNCATED, "IPv6")
    if data[pos] >> 4 != 6:
        raise _Skip(SKIP_IP_INVALID, f"IPv6: phiên bản {data[pos] >> 4}")
    payload_len, next_header = struct.unpack_from("!HB", data, pos + 4)
    src = IPv6Address(data[pos + 8:pos + 24]).compressed
    dst = IPv6Address(data[pos + 24:pos + 40]).compressed
    offset = pos + 40
    frag_id = None
    first_fragment = True
    # Đi qua các header mở rộng để tới giao thức tầng trên.
    while next_header in (IPV6_EXT_HOP_BY_HOP, IPV6_EXT_ROUTING, IPV6_EXT_FRAGMENT,
                          IPV6_EXT_AH, IPV6_EXT_DEST_OPTS):
        if len(data) < offset + 8:
            # Header mở rộng bị cắt: vẫn biết địa chỉ nhưng không biết giao thức.
            notes.append(NOTE_L4_TRUNCATED)
            return src, dst, next_header, 40 + payload_len, None, frag_id, None
        nxt, hdr_len = data[offset], data[offset + 1]
        if next_header == IPV6_EXT_FRAGMENT:
            frag_offset, frag_id = struct.unpack_from("!HI", data, offset + 2)
            frag_offset >>= 3
            first_fragment = frag_offset == 0
            size = 8
        elif next_header == IPV6_EXT_AH:
            size = (hdr_len + 2) * 4
        else:
            size = (hdr_len + 1) * 8
        next_header = nxt
        offset += size
        if not first_fragment:
            break
    l4_offset = offset if first_fragment and next_header != IPV6_NO_NEXT else None
    return src, dst, next_header, 40 + payload_len, l4_offset, frag_id, offset


def _parse_l4(data, pos, end, proto):
    """Đọc cổng, cờ TCP, số thứ tự và độ dài header TCP; trường nằm ngoài phần đã bắt là None."""
    if end < pos + 4:
        return None, None, None, None, None
    src_port, dst_port = struct.unpack_from("!HH", data, pos)
    tcp_flags = tcp_seq = tcp_hdr_len = None
    if proto == PROTO_TCP and end >= pos + 14:
        # Như Wireshark: header TCP bị cắt trước byte cờ thì không lấy cả số thứ tự.
        tcp_seq = struct.unpack_from("!I", data, pos + 4)[0]
        off_flags = struct.unpack_from("!H", data, pos + 12)[0]
        tcp_flags = off_flags & TCP_FLAG_MASK
        tcp_hdr_len = (off_flags >> 12) * 4
    return src_port, dst_port, tcp_flags, tcp_seq, tcp_hdr_len


def tcp_flag_names(flags: int | None) -> str:
    """Đổi giá trị cờ TCP thành chuỗi tên, ví dụ 0x012 -> "SYN,ACK"."""
    if not flags:
        return ""
    return ",".join(name for bit, name in TCP_FLAG_NAMES if flags & bit)


def extract_packets(path, stats: ParseStats | None = None):
    """Duyệt các gói IP của một file PCAP/PCAPNG; bỏ qua gói không đọc được.

    Khi truyền ``stats``, số gói bỏ qua được đếm vào đó, và nếu file hỏng giữa
    chừng thì dừng đọc, ghi lỗi vào ``stats.file_error`` thay vì ném ngoại lệ;
    các gói trước chỗ hỏng vẫn được trả về. Không truyền ``stats`` thì
    PcapFormatError được ném ra như bình thường. File không mở được hoặc sai
    header luôn ném ngoại lệ.
    """
    with PcapReader(path) as reader:
        try:
            for pkt in reader:
                result = inspect_packet(pkt)
                if stats is not None:
                    stats.add(pkt, result)
                if result.record is not None:
                    yield result.record
        except PcapFormatError as exc:
            if stats is None:
                raise
            stats.file_error = str(exc)
        finally:
            if stats is not None:
                stats.read_file_state(reader)


CSV_COLUMNS = ("index", "ts", "src_ip", "dst_ip", "ip_version", "protocol",
               "protocol_name", "frame_len", "ip_len", "caplen", "is_fragment",
               "src_port", "dst_port", "tcp_flags", "tcp_flag_names")


def _csv_row(rec):
    row = asdict(rec)
    row["ts"] = "" if rec.ts_ns is None else f"{rec.ts_ns // 10**9}.{rec.ts_ns % 10**9:09d}"
    row["protocol_name"] = rec.protocol_name
    row["is_fragment"] = int(rec.is_fragment)
    row["tcp_flag_names"] = rec.tcp_flag_names
    return {col: "" if row[col] is None else row[col] for col in CSV_COLUMNS}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Trích xuất timestamp, IP, giao thức, độ dài, cổng, cờ TCP từ file PCAP/PCAPNG."
    )
    parser.add_argument("file", help="đường dẫn file .pcap hoặc .pcapng")
    parser.add_argument("--csv", help="ghi bảng packet ra file CSV")
    parser.add_argument("--stats", help="ghi thống kê gói bỏ qua ra file JSON")
    parser.add_argument("-n", "--count", type=int, default=10,
                        help="số gói IP đầu tiên được in (mặc định: %(default)s)")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    stats = ParseStats()
    by_proto = Counter()
    out = writer = None
    try:
        if args.csv:
            out = open(args.csv, "w", encoding="utf-8", newline="")
            writer = csv.DictWriter(out, fieldnames=CSV_COLUMNS)
            writer.writeheader()
        for rec in extract_packets(args.file, stats):
            if stats.kept <= args.count:
                row = _csv_row(rec)
                src = _endpoint(rec.src_ip, rec.src_port)
                dst = _endpoint(rec.dst_ip, rec.dst_port)
                flags = f" [{rec.tcp_flag_names}]" if rec.tcp_flags is not None else ""
                print(f"{rec.index:>6}  {row['ts']}  {src} -> {dst}"
                      f"  {rec.protocol_name}{flags}  frame={rec.frame_len} ip={rec.ip_len}")
            by_proto[rec.protocol_name] += 1
            if writer:
                writer.writerow(_csv_row(rec))
    finally:
        if out:
            out.close()
    print()
    print("\n".join(stats.summary_lines()))
    print("Theo giao thức: " + ", ".join(f"{name}={n}" for name, n in by_proto.most_common()))
    if args.csv:
        print(f"Đã ghi CSV: {args.csv}")
    if args.stats:
        with open(args.stats, "w", encoding="utf-8") as f:
            json.dump(stats.as_dict(), f, ensure_ascii=False, indent=2)
        print(f"Đã ghi thống kê: {args.stats}")
    return 1 if stats.file_error else 0


def _endpoint(ip, port):
    if port is None:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


if __name__ == "__main__":
    sys.exit(main())

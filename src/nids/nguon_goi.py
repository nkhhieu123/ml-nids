"""Nguồn gói cho chế độ realtime (C10-T03): card mạng (Linux, AF_PACKET) hoặc phát lại PCAP.

Mọi nguồn trả ``RawPacket`` giống bộ đọc PCAP (``nids.pcap_reader``), nên phần sau (phân tích gói, ghép
flow, cửa sổ, đặc trưng) dùng đúng mã của pipeline offline (B12).

- ``AfPacketSource``: socket ``AF_PACKET`` của Linux, nhận mọi gói trên card (chế độ promiscuous), dấu
  thời gian do kernel gắn (``SO_TIMESTAMPNS``), số gói kernel bỏ đọc bằng ``PACKET_STATISTICS``. Cần root
  hoặc CAP_NET_RAW (docs/59). Không cần thư viện ngoài.
- ``PcapReplaySource``: phát lại file PCAP/PCAPNG, nhanh nhất có thể hoặc theo nhịp thời gian thật
  (``speed``), để thử chế độ realtime khi không có card mạng và để kiểm tra nhất quán (C10-T08).

Nguồn dừng khi ``stop()`` được gọi (từ luồng khác hoặc trình xử lý tín hiệu).
"""

import socket
import struct
import threading
import time

from .pcap_reader import PcapReader, RawPacket

LINKTYPE_ETHERNET = 1
ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_STATISTICS = 6
SO_TIMESTAMPNS = 35
SCM_TIMESTAMPNS = SO_TIMESTAMPNS
MSG_TRUNC = getattr(socket, "MSG_TRUNC", 0x20)
# Chỗ cho dữ liệu phụ chứa struct timespec (16 byte); CMSG_SPACE chỉ có trên Unix
ANC_BUFSIZE = socket.CMSG_SPACE(16) if hasattr(socket, "CMSG_SPACE") else 64


class PacketSource:
    """Lớp chung: lặp qua gói, dừng được, đếm gói nhận và gói kernel bỏ."""

    name = "nguon"

    def __init__(self):
        self._stop = threading.Event()
        self.received = 0

    def stop(self):
        self._stop.set()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def kernel_drops(self) -> int:
        """Số gói kernel bỏ kể từ lần gọi trước (0 nếu nguồn không có khái niệm này)."""
        return 0

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class PcapReplaySource(PacketSource):
    """Phát lại một file PCAP. ``speed``: None là nhanh nhất có thể; 1.0 là đúng nhịp lúc bắt; 10 là nhanh gấp 10."""

    name = "pcap"

    def __init__(self, path, speed=None):
        super().__init__()
        self.path = path
        self.speed = speed

    def __iter__(self):
        start_wall = first_ts = None
        with PcapReader(self.path) as reader:
            for pkt in reader:
                if self.stopped:
                    return
                if self.speed and pkt.ts_ns is not None:
                    if first_ts is None:
                        first_ts, start_wall = pkt.ts_ns, time.monotonic()
                    due = start_wall + (pkt.ts_ns - first_ts) / 1e9 / self.speed
                    delay = due - time.monotonic()
                    if delay > 0 and self._stop.wait(delay):
                        return
                self.received += 1
                yield pkt


def promisc_mreq(ifindex: int) -> bytes:
    """struct packet_mreq {int ifindex; unsigned short type; unsigned short alen; unsigned char address[8];}"""
    return struct.pack("iHH8s", ifindex, PACKET_MR_PROMISC, 0, b"")


def parse_timestamp(ancdata) -> int | None:
    """Thời điểm nano giây từ dữ liệu phụ ``SCM_TIMESTAMPNS`` (struct timespec) của recvmsg."""
    for level, kind, data in ancdata:
        if level == socket.SOL_SOCKET and kind == SCM_TIMESTAMPNS and len(data) >= 16:
            sec, nsec = struct.unpack("qq", data[:16])
            return sec * 10**9 + nsec
    return None


class AfPacketSource(PacketSource):
    """Bắt gói trực tiếp trên card mạng Linux bằng AF_PACKET."""

    name = "card"

    def __init__(self, iface, snaplen=65535, promisc=True, timeout_s=0.5, sock=None):
        super().__init__()
        self.iface = iface
        self.snaplen = snaplen
        self._dropped_total = 0
        if sock is not None:                        # dùng trong kiểm thử
            self.sock = sock
            return
        if not hasattr(socket, "AF_PACKET"):
            raise OSError("AF_PACKET chỉ có trên Linux; dùng --pcap để phát lại file")
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((iface, 0))
        self.sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024 * 1024)
        if promisc:
            self.sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, promisc_mreq(socket.if_nametoindex(iface)))
        self.sock.settimeout(timeout_s)
        self.kernel_drops()                         # đặt lại bộ đếm của kernel

    def __iter__(self):
        index = 0
        while not self.stopped:
            try:
                data, anc, flags, _ = self.sock.recvmsg(self.snaplen, ANC_BUFSIZE, MSG_TRUNC)
            except socket.timeout:
                continue
            except OSError:
                if self.stopped:
                    return
                raise
            ts = parse_timestamp(anc) or time.time_ns()
            origlen = len(data)
            if flags & MSG_TRUNC:                  # gói dài hơn snaplen: kernel cho biết đã cắt
                origlen = max(origlen, self.snaplen + 1)
            self.received += 1
            yield RawPacket(index, ts, len(data), origlen, LINKTYPE_ETHERNET, data)
            index += 1

    def kernel_drops(self) -> int:
        """PACKET_STATISTICS trả struct tpacket_stats {unsigned tp_packets; unsigned tp_drops;}, đặt lại khi đọc."""
        try:
            raw = self.sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
        except (OSError, AttributeError):
            return 0
        _, drops = struct.unpack("II", raw[:8])
        self._dropped_total += drops
        return drops

    @property
    def dropped_total(self) -> int:
        return self._dropped_total

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def open_source(iface=None, pcap=None, speed=None) -> PacketSource:
    if bool(iface) == bool(pcap):
        raise ValueError("chọn đúng một nguồn: --iface hoặc --pcap")
    return AfPacketSource(iface) if iface else PcapReplaySource(pcap, speed)

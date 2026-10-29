"""Đặc trưng của flow.

- Cơ bản (C04-T03): số gói, số byte, thời lượng, tỷ lệ gửi/nhận; docs/20, QĐ-018.
- Thống kê (C04-T04): kích thước gói, khoảng cách giữa hai gói (inter-arrival
  time), số gói mang từng cờ TCP; docs/21, QĐ-020.

Mọi giá trị chỉ dựa vào các gói của chính flow đó và được cộng dồn từng gói
(không giữ danh sách gói), nên tính được ngay khi flow kết thúc, kể cả realtime.

    for flow in assign_flows(extract_packets(path)).flows():
        print(basic_features(flow), stat_features(flow))
"""

import math

from .packets import (
    PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_CWR, TCP_ECE, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN,
    TCP_URG,
)

# Tên đặc trưng -> (đơn vị, mô tả). Thứ tự này là thứ tự cột khi xuất bảng.
BASIC_FEATURES = {
    "packets": ("gói", "Tổng số gói của flow"),
    "fwd_packets": ("gói", "Số gói chiều forward (client → server)"),
    "bwd_packets": ("gói", "Số gói chiều backward (server → client)"),
    "bytes": ("byte", "Tổng độ dài gói theo header IP (ip_len)"),
    "fwd_bytes": ("byte", "Tổng ip_len chiều forward"),
    "bwd_bytes": ("byte", "Tổng ip_len chiều backward"),
    "payload_bytes": ("byte", "Tổng dữ liệu TCP/UDP, không tính header; trống nếu không phải TCP/UDP"),
    "fwd_payload_bytes": ("byte", "Dữ liệu TCP/UDP chiều forward"),
    "bwd_payload_bytes": ("byte", "Dữ liệu TCP/UDP chiều backward"),
    "duration_s": ("giây", "Thời điểm gói cuối trừ gói đầu; 0 nếu flow có một gói"),
    "fwd_packet_share": ("tỷ lệ 0–1", "fwd_packets / packets"),
    "fwd_byte_share": ("tỷ lệ 0–1", "fwd_bytes / bytes"),
}

SHARE_DIGITS = 6


def _duration_s(flow):
    if flow.first_ts_ns is None or flow.last_ts_ns is None:
        return None
    ns = flow.last_ts_ns - flow.first_ts_ns
    return f"{ns // 10**9}.{ns % 10**9:09d}"


def basic_features(flow) -> dict:
    """Đặc trưng cơ bản của một flow (đối tượng Flow của flows.py).

    ``duration_s`` là chuỗi số thập phân đủ 9 chữ số (nano giây) để không mất độ
    chính xác khi ghi CSV. Hai tỷ lệ luôn xác định vì mọi flow có ít nhất một gói
    và mỗi gói IP dài ít nhất 20 byte.
    """
    packets = flow.fwd_packets + flow.bwd_packets
    total_bytes = flow.fwd_bytes + flow.bwd_bytes
    has_payload = flow.key.protocol in (PROTO_TCP, PROTO_UDP)
    return {
        "packets": packets,
        "fwd_packets": flow.fwd_packets,
        "bwd_packets": flow.bwd_packets,
        "bytes": total_bytes,
        "fwd_bytes": flow.fwd_bytes,
        "bwd_bytes": flow.bwd_bytes,
        "payload_bytes": flow.fwd_payload_bytes + flow.bwd_payload_bytes if has_payload else None,
        "fwd_payload_bytes": flow.fwd_payload_bytes if has_payload else None,
        "bwd_payload_bytes": flow.bwd_payload_bytes if has_payload else None,
        "duration_s": _duration_s(flow),
        "fwd_packet_share": round(flow.fwd_packets / packets, SHARE_DIGITS),
        "fwd_byte_share": round(flow.fwd_bytes / total_bytes, SHARE_DIGITS) if total_bytes else None,
    }


# ---- C04-T04: thống kê kích thước, inter-arrival time, cờ TCP ----

STAT_DIGITS = 6        # kích thước (byte): 6 chữ số thập phân
IAT_DIGITS = 9         # inter-arrival time (giây): tới nano giây

# Cờ được đếm, theo thứ tự cột
FLAG_COLUMNS = (
    ("syn_count", TCP_SYN), ("fin_count", TCP_FIN), ("rst_count", TCP_RST),
    ("psh_count", TCP_PSH), ("ack_count", TCP_ACK), ("urg_count", TCP_URG),
    ("ece_count", TCP_ECE), ("cwr_count", TCP_CWR),
)


class RunningStats:
    """Số lượng, nhỏ nhất, lớn nhất, trung bình, độ lệch chuẩn tính dần (Welford).

    Không giữ các giá trị, nên bộ nhớ không đổi dù flow dài bao nhiêu. Độ lệch
    chuẩn là của tổng thể (chia n), bằng 0 khi chỉ có một giá trị.
    """
    __slots__ = ("n", "min", "max", "mean", "_m2")

    def __init__(self):
        self.n = 0
        self.min = self.max = None
        self.mean = 0.0
        self._m2 = 0.0

    def add(self, x):
        self.n += 1
        if self.n == 1:
            self.min = self.max = x
        else:
            self.min = min(self.min, x)
            self.max = max(self.max, x)
        delta = x - self.mean
        self.mean += delta / self.n
        self._m2 += delta * (x - self.mean)

    @property
    def std(self):
        return math.sqrt(max(self._m2, 0.0) / self.n) if self.n else None


class PacketStats:
    """Thống kê theo gói của một flow, cập nhật mỗi khi có gói mới."""
    __slots__ = ("size", "fwd_size", "bwd_size", "iat", "fwd_iat", "bwd_iat",
                 "_last", "_last_fwd", "_last_bwd", "flags")

    def __init__(self):
        self.size, self.fwd_size, self.bwd_size = RunningStats(), RunningStats(), RunningStats()
        self.iat, self.fwd_iat, self.bwd_iat = RunningStats(), RunningStats(), RunningStats()
        self._last = self._last_fwd = self._last_bwd = None
        self.flags = [0] * len(FLAG_COLUMNS)

    def add(self, ip_len, ts_ns, forward, tcp_flags):
        self.size.add(ip_len)
        (self.fwd_size if forward else self.bwd_size).add(ip_len)
        if ts_ns is not None:
            # Khoảng cách tính theo thứ tự gói tới; file sai thứ tự thời gian cho
            # khoảng âm, được tính là 0 (docs/21, mục 3).
            if self._last is not None:
                self.iat.add(max(0, ts_ns - self._last))
            self._last = ts_ns
            if forward:
                if self._last_fwd is not None:
                    self.fwd_iat.add(max(0, ts_ns - self._last_fwd))
                self._last_fwd = ts_ns
            else:
                if self._last_bwd is not None:
                    self.bwd_iat.add(max(0, ts_ns - self._last_bwd))
                self._last_bwd = ts_ns
        if tcp_flags:
            for i, (_, bit) in enumerate(FLAG_COLUMNS):
                if tcp_flags & bit:
                    self.flags[i] += 1


def _stat_columns(prefix, unit, what):
    return {
        f"{prefix}_min": (unit, f"Nhỏ nhất của {what}"),
        f"{prefix}_max": (unit, f"Lớn nhất của {what}"),
        f"{prefix}_mean": (unit, f"Trung bình của {what}"),
        f"{prefix}_std": (unit, f"Độ lệch chuẩn (chia n) của {what}"),
    }


STAT_FEATURES = {
    **_stat_columns("pkt_len", "byte", "ip_len mọi gói"),
    **_stat_columns("fwd_pkt_len", "byte", "ip_len gói forward; trống nếu chiều này không có gói"),
    **_stat_columns("bwd_pkt_len", "byte", "ip_len gói backward; trống nếu chiều này không có gói"),
    **_stat_columns("iat", "giây", "khoảng cách giữa hai gói liên tiếp; trống nếu flow có dưới 2 gói"),
    **_stat_columns("fwd_iat", "giây", "khoảng cách giữa hai gói forward liên tiếp; trống nếu dưới 2 gói forward"),
    **_stat_columns("bwd_iat", "giây", "khoảng cách giữa hai gói backward liên tiếp; trống nếu dưới 2 gói backward"),
    **{name: ("gói", f"Số gói TCP có cờ {name[:3].upper()}; 0 với flow không phải TCP")
       for name, _ in FLAG_COLUMNS},
}


def _summary(stats, scale, digits):
    """(min, max, mean, std) chia cho ``scale``; None cả bốn nếu chưa có giá trị nào."""
    if not stats.n:
        return None, None, None, None
    if scale == 1:
        return stats.min, stats.max, round(stats.mean, digits), round(stats.std, digits)
    return tuple(round(v / scale, digits) for v in (stats.min, stats.max, stats.mean, stats.std))


def stat_features(flow) -> dict:
    """Đặc trưng thống kê của một flow (C04-T04). Kích thước: byte; IAT: giây."""
    ps = flow.pkt_stats
    row = {}
    for prefix, stats, scale, digits in (
            ("pkt_len", ps.size, 1, STAT_DIGITS),
            ("fwd_pkt_len", ps.fwd_size, 1, STAT_DIGITS),
            ("bwd_pkt_len", ps.bwd_size, 1, STAT_DIGITS),
            ("iat", ps.iat, 1e9, IAT_DIGITS),
            ("fwd_iat", ps.fwd_iat, 1e9, IAT_DIGITS),
            ("bwd_iat", ps.bwd_iat, 1e9, IAT_DIGITS)):
        for name, value in zip(("min", "max", "mean", "std"), _summary(stats, scale, digits)):
            row[f"{prefix}_{name}"] = value
    for (name, _), count in zip(FLAG_COLUMNS, ps.flags):
        row[name] = count
    return row

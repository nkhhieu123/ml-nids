"""Ghép packet thành flow hai chiều, xác định chiều và kết thúc flow (C04-T01, C04-T02).

Một flow hai chiều gồm các packet có cùng giao thức và cùng cặp đầu mút
(IP, cổng), bất kể gói đi theo chiều nào. Chiều forward là chiều của bên mở
kết nối (client); chiều backward là chiều ngược lại (docs/18_flow_hai_chieu.md,
QĐ-016).

Một flow kết thúc khi (docs/19_ket_thuc_flow.md, QĐ-017):
- TCP đã đóng bằng FIN hai chiều hoặc RST, rồi có SYN mới hoặc hết thời gian chờ;
- không có gói mới trong ``idle_timeout_s``;
- có SYN mở kết nối mới trên cùng 5-tuple khi flow cũ chưa đóng;
- flow kéo dài quá ``active_timeout_s``; phần sau là flow tiếp nối cùng chiều.

    assigner = FlowAssigner(FlowSettings.from_config(load_config()))
    for rec in extract_packets("data/pcap/<file>.pcap"):
        flow, forward = assigner.add(rec)
        for done in assigner.pop_finished():
            print(done.fwd_endpoint, done.end_reason)
    assigner.finish_all()
"""

import argparse
import csv
import json
import sys
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from ipaddress import ip_address

from .config import load_config
from .flow_features import (
    BASIC_FEATURES, STAT_FEATURES, PacketStats, basic_features, stat_features,
)
from .packets import (
    PORT_PROTOCOLS, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, ParseStats,
    PacketRecord, extract_packets,
)

# Cách xác định bên mở kết nối, theo thứ tự ưu tiên (docs/18, mục 3)
BASIS_SYN = "syn"                    # gói đầu là SYN không có ACK: bên gửi là client
BASIS_SYN_ACK = "syn_ack"            # gói đầu là SYN+ACK: bên nhận là client
BASIS_SERVICE_PORT = "cong_dich_vu"  # TCP giữa chừng: bên dùng cổng >= 1024 là client
BASIS_FIRST_PACKET = "goi_dau"       # còn lại: bên gửi gói đầu tiên là client
BASIS_SAME_ENDPOINT = "cung_dau_mut"  # hai đầu trùng nhau: mọi gói là forward
BASES = (BASIS_SYN, BASIS_SYN_ACK, BASIS_SERVICE_PORT, BASIS_FIRST_PACKET,
         BASIS_SAME_ENDPOINT)

# Lý do kết thúc flow (docs/19, mục 2)
END_FIN = "fin"                      # cả hai bên đã gửi FIN
END_RST = "rst"                      # một bên đã gửi RST
END_IDLE = "idle_timeout"            # không có gói mới trong idle_timeout_s
END_ACTIVE = "active_timeout"        # flow dài quá active_timeout_s
END_REUSE = "tai_su_dung"            # SYN mới trên cùng 5-tuple khi flow chưa đóng
END_OF_INPUT = "het_du_lieu"         # hết file khi flow còn mở
END_REASONS = (END_FIN, END_RST, END_IDLE, END_ACTIVE, END_REUSE, END_OF_INPUT)

# Cổng dưới ngưỡng này coi là cổng dịch vụ (well-known ports, RFC 6335)
SERVICE_PORT_LIMIT = 1024

# Khoảng thời gian (theo thời điểm gói) giữa hai lần dọn flow đã hết hạn.
# Chỉ ảnh hưởng lúc flow được trả ra, không ảnh hưởng cách cắt flow.
SWEEP_INTERVAL_NS = 10**9


@dataclass(frozen=True)
class FlowSettings:
    """Tham số ghép flow; giá trị dùng thật nằm ở mục ``flow`` của config/default.yaml."""
    idle_timeout_s: float = 60        # QĐ-006
    active_timeout_s: float = 120     # QĐ-017, như CICFlowMeter của CIC-IDS2017
    close_grace_s: float = 10         # QĐ-017: nhận gói cuối sau FIN/RST
    direction_memory_s: float = 3600  # QĐ-017: nhớ chiều để flow sau tiếp nối
    fragment_timeout_s: float = 30    # QĐ-016

    @classmethod
    def from_config(cls, cfg: dict) -> "FlowSettings":
        return cls(**{name: cfg["flow"][name] for name in cls.__dataclass_fields__})


@dataclass(frozen=True, order=True)
class FlowKey:
    """Khóa của flow hai chiều: giao thức và hai đầu mút xếp theo thứ tự cố định.

    Đầu mút ``a`` luôn nhỏ hơn hoặc bằng ``b`` (so IP dạng số, rồi đến cổng) nên
    gói chiều đi và chiều về cho cùng một khóa. Cổng là None với giao thức
    không có cổng (ICMP, IGMP, ...) và với gói không đọc được cổng.
    """
    ip_version: int
    protocol: int
    a_ip: str
    a_port: int | None
    b_ip: str
    b_port: int | None

    @property
    def a(self) -> tuple[str, int | None]:
        return self.a_ip, self.a_port

    @property
    def b(self) -> tuple[str, int | None]:
        return self.b_ip, self.b_port


def _sort_key(ip, port):
    return int(ip_address(ip)), -1 if port is None else port


def make_key(ip_version, protocol, src, dst) -> FlowKey:
    """Tạo FlowKey từ hai đầu mút (ip, port) theo thứ tự bất kỳ."""
    if _sort_key(*dst) < _sort_key(*src):
        src, dst = dst, src
    return FlowKey(ip_version, protocol, src[0], src[1], dst[0], dst[1])


@dataclass
class Flow:
    """Một flow hai chiều cùng chiều forward đã xác định.

    Các bộ đếm được cộng dần theo từng gói (dùng được khi chạy realtime); đặc
    trưng suy ra từ chúng nằm ở flow_features.py (docs/20_dac_trung_flow_co_ban.md).
    """
    key: FlowKey
    fwd_endpoint: tuple[str, int | None]   # bên mở kết nối (client)
    bwd_endpoint: tuple[str, int | None]   # bên còn lại (server)
    direction_basis: str                   # một trong BASES
    first_index: int                       # chỉ số packet đầu tiên trong file
    first_ts_ns: int | None                # thời điểm nhỏ nhất của các gói trong flow
    last_ts_ns: int | None                 # thời điểm lớn nhất
    continuation: bool = False             # chiều lấy từ flow trước của cùng 5-tuple
    end_reason: str | None = None          # một trong END_REASONS khi flow đã kết thúc
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0                     # tổng ip_len các gói chiều forward
    bwd_bytes: int = 0
    fwd_payload_bytes: int = 0             # tổng payload_len (dữ liệu TCP/UDP) chiều forward
    bwd_payload_bytes: int = 0
    payload_unknown: int = 0               # gói TCP/UDP không tính được payload (header bị cắt)
    fragments_attached: int = 0            # mảnh IP không mang cổng được gắn vào flow này
    # Thống kê kích thước, inter-arrival time, cờ TCP (C04-T04)
    pkt_stats: PacketStats = field(default_factory=PacketStats, repr=False)
    # Trạng thái TCP dùng để kết thúc flow
    fin_from: set = field(default_factory=set, repr=False)  # đầu mút đã gửi FIN
    closed_ts_ns: int | None = field(default=None, repr=False)  # lúc đóng bằng FIN/RST
    sent_non_syn: set = field(default_factory=set, repr=False)  # đầu mút đã gửi gói không SYN
    # (đầu mút, "syn"/"syn_ack") -> số thứ tự TCP của gói bắt tay đầu tiên loại đó
    handshake_seq: dict = field(default_factory=dict, repr=False)
    finished: bool = field(default=False, repr=False)           # đã được trả ra

    @property
    def packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def closed(self) -> bool:
        """TCP đã đóng bằng FIN hai chiều hoặc RST (đang chờ gói cuối)."""
        return self.end_reason in (END_FIN, END_RST)

    def is_forward(self, rec: PacketRecord, src_port=None) -> bool:
        """Gói có đi từ phía client không. ``src_port`` dùng cho mảnh không mang cổng."""
        if self.direction_basis == BASIS_SAME_ENDPOINT:
            return True
        port = rec.src_port if src_port is None else src_port
        return (rec.src_ip, port) == self.fwd_endpoint


def initiator(rec: PacketRecord, src, dst) -> tuple[tuple, tuple, str]:
    """Từ gói đầu tiên của flow, trả về (đầu mút client, đầu mút server, cơ sở).

    Thứ tự ưu tiên: SYN, SYN+ACK, cổng dịch vụ (chỉ TCP), gói đầu.
    """
    if src == dst:
        return src, dst, BASIS_SAME_ENDPOINT
    if rec.protocol == PROTO_TCP and rec.tcp_flags is not None:
        if rec.tcp_flags & TCP_SYN:
            if rec.tcp_flags & TCP_ACK:
                return dst, src, BASIS_SYN_ACK
            return src, dst, BASIS_SYN
        sport, dport = src[1], dst[1]
        if sport is not None and dport is not None:
            src_service = sport < SERVICE_PORT_LIMIT
            dst_service = dport < SERVICE_PORT_LIMIT
            if src_service and not dst_service:
                return dst, src, BASIS_SERVICE_PORT
            if dst_service and not src_service:
                return src, dst, BASIS_SERVICE_PORT
    return src, dst, BASIS_FIRST_PACKET


def _is_syn(rec):
    """SYN không có ACK: gói mở kết nối của client."""
    return (rec.protocol == PROTO_TCP and rec.tcp_flags is not None
            and rec.tcp_flags & TCP_SYN and not rec.tcp_flags & TCP_ACK)


def _is_handshake(rec):
    return rec.protocol == PROTO_TCP and rec.tcp_flags is not None and rec.tcp_flags & TCP_SYN


class FlowAssigner:
    """Gắn từng packet vào flow hai chiều theo thứ tự trong file và kết thúc flow.

    Flow đã kết thúc được đưa vào hàng chờ, lấy ra bằng ``pop_finished()``; khi
    hết dữ liệu gọi ``finish_all()``. Quyết định cắt flow chỉ dựa vào gói hiện
    tại và các gói trước nó, nên đọc file hay bắt realtime cho cùng kết quả.

    Mảnh IP không phải mảnh đầu không có cổng. Nó được gắn vào flow của mảnh
    đầu cùng datagram (cùng IP nguồn, IP đích, giao thức, Identification) nếu
    mảnh đầu đã thấy trong vòng ``fragment_timeout_s`` giây và flow đó chưa được
    trả ra; nếu không thì vào flow không cổng của cặp IP đó và được đếm trong
    ``orphan_fragments``.

    ``keep_finished=False`` không giữ lại flow đã trả ra bằng ``pop_finished()``,
    để bộ nhớ không tăng theo độ dài bản thu (file rất lớn, chạy realtime); khi
    đó ``flows()`` chỉ còn các flow chưa lấy ra, còn ``summary()`` vẫn đủ.
    """

    def __init__(self, settings: FlowSettings | None = None, keep_finished: bool = True):
        s = settings or FlowSettings()
        self.settings = s
        self.keep_finished = keep_finished
        self._counts = Counter()          # thống kê cộng dồn của flow đã kết thúc
        self.idle_ns = int(s.idle_timeout_s * 10**9)
        self.active_ns = int(s.active_timeout_s * 10**9)
        self.grace_ns = int(s.close_grace_s * 10**9)
        self.memory_ns = int(s.direction_memory_s * 10**9)
        self.fragment_timeout_ns = int(s.fragment_timeout_s * 10**9)
        # Các bảng dưới đây xếp theo thời gian để expire() chỉ cần xem đầu bảng.
        # Flow đang mở; flow vừa có gói nằm cuối bảng
        self._active: OrderedDict[FlowKey, Flow] = OrderedDict()
        # Flow đã đóng bằng FIN/RST, đang chờ gói cuối, theo lúc đóng
        self._closing: OrderedDict[FlowKey, Flow] = OrderedDict()
        self._finished: list[Flow] = []        # chờ pop_finished()
        self._all_finished: list[Flow] = []    # giữ lại để flows() trả về đủ
        # Chiều của flow trước trên cùng khóa: key -> (fwd, bwd, basis, ts kết thúc)
        self._recent: OrderedDict[FlowKey, tuple] = OrderedDict()
        # (ip_version, src, dst, proto, frag_id) -> (flow, cổng nguồn, ts của mảnh đầu)
        self._fragments: OrderedDict[tuple, tuple] = OrderedDict()
        self.orphan_fragments = 0
        self.out_of_order = 0   # số gói có thời điểm nhỏ hơn gói đứng trước trong file
        self._now = None        # thời điểm lớn nhất đã thấy
        self._last_ts = None
        self._next_sweep = None

    # ---- nhận gói ----

    def add(self, rec: PacketRecord) -> tuple[Flow, bool]:
        """Gắn một packet vào flow; trả về (flow, gói có thuộc chiều forward không)."""
        ts = rec.ts_ns
        if ts is not None:
            if self._last_ts is not None and ts < self._last_ts:
                self.out_of_order += 1
            self._last_ts = ts
            if self._now is None or ts > self._now:
                self._now = ts
            if self._next_sweep is None:
                self._next_sweep = ts + SWEEP_INTERVAL_NS
            elif ts >= self._next_sweep:
                self.expire(ts)
                self._next_sweep = ts + SWEEP_INTERVAL_NS

        attached = self._attach_fragment(rec)
        if attached is not None:
            flow, src_port = attached
            forward = flow.is_forward(rec, src_port)
            flow.fragments_attached += 1
        else:
            flow = self._flow_for(rec)
            forward = flow.is_forward(rec)
            if rec.is_fragment and rec.l4_offset is not None:
                frag = (rec.ip_version, rec.src_ip, rec.dst_ip, rec.protocol, rec.frag_id)
                self._fragments[frag] = (flow, rec.src_port, ts)

        payload = rec.payload_len
        if payload is None and rec.protocol in (PROTO_TCP, PROTO_UDP):
            flow.payload_unknown += 1
            payload = 0
        elif payload is None:
            payload = 0
        if forward:
            flow.fwd_packets += 1
            flow.fwd_bytes += rec.ip_len
            flow.fwd_payload_bytes += payload
        else:
            flow.bwd_packets += 1
            flow.bwd_bytes += rec.ip_len
            flow.bwd_payload_bytes += payload
        if ts is not None:
            # Lấy nhỏ nhất/lớn nhất để thời lượng không âm khi file sai thứ tự thời gian.
            if flow.first_ts_ns is None or ts < flow.first_ts_ns:
                flow.first_ts_ns = ts
            if flow.last_ts_ns is None or ts > flow.last_ts_ns:
                flow.last_ts_ns = ts
        flow.pkt_stats.add(rec.ip_len, ts, forward, rec.tcp_flags)
        if not flow.finished:
            self._active.move_to_end(flow.key)
        self._track_tcp(flow, rec, forward)
        return flow, forward

    def _flow_for(self, rec):
        """Flow đang mở của khóa này, sau khi đã kết thúc flow cũ nếu gói này mở flow mới."""
        src = (rec.src_ip, rec.src_port)
        dst = (rec.dst_ip, rec.dst_port)
        key = make_key(rec.ip_version, rec.protocol, src, dst)
        flow = self._active.get(key)
        if flow is not None:
            reason = self._end_reason_on_arrival(flow, rec)
            if reason is not None:
                self._finish(flow, reason)
                flow = None
        if flow is None:
            flow = self._create(key, rec, src, dst)
            self._active[key] = flow
        return flow

    def _end_reason_on_arrival(self, flow, rec):
        """Lý do kết thúc flow khi gói ``rec`` tới; None nếu gói thuộc flow này.

        Thứ tự kiểm tra (docs/19, mục 2): đã đóng, nhàn rỗi, SYN mới, quá dài.
        """
        ts = rec.ts_ns
        gap = None if ts is None or flow.last_ts_ns is None else ts - flow.last_ts_ns
        if flow.closed:
            if _is_handshake(rec):
                return flow.end_reason
            if ts is not None and flow.closed_ts_ns is not None \
                    and ts - flow.closed_ts_ns > self.grace_ns:
                return flow.end_reason
            if gap is not None and gap > self.idle_ns:
                return flow.end_reason
            return None
        if gap is not None and gap > self.idle_ns:
            return END_IDLE
        if self._opens_new_connection(flow, rec):
            return END_REUSE
        if ts is not None and flow.first_ts_ns is not None \
                and ts - flow.first_ts_ns > self.active_ns:
            return END_ACTIVE
        return None

    @staticmethod
    def _opens_new_connection(flow, rec):
        """Gói SYN hoặc SYN+ACK này có mở kết nối mới trên flow chưa đóng không.

        SYN từ phía server của flow luôn là kết nối mới (mở ngược chiều). Còn lại,
        nếu bên gửi đã gửi gói cùng loại trước đó trong flow thì so số thứ tự TCP:
        cùng số là gửi lại, khác số là kết nối mới. Không so được thì (docs/19,
        mục 2):
        - SYN+ACK đầu tiên của bên đó là trả lời bình thường; chỉ khi gói không
          có số thứ tự mà bên đó đã gửi gói khác (đã qua bắt tay) thì là kết nối mới;
        - SYN của client là kết nối mới nếu client đã gửi gói khác, hoặc flow
          không mở bằng bắt tay (bắt giữa chừng).
        """
        if not _is_handshake(rec):
            return False
        sender = (rec.src_ip, rec.src_port)
        kind = "syn" if _is_syn(rec) else "syn_ack"
        if kind == "syn" and sender != flow.fwd_endpoint:
            return True
        previous = flow.handshake_seq.get((sender, kind))
        if previous is not None and rec.tcp_seq is not None:
            return rec.tcp_seq != previous
        if kind == "syn_ack":
            return rec.tcp_seq is None and sender in flow.sent_non_syn
        return (sender in flow.sent_non_syn
                or flow.direction_basis not in (BASIS_SYN, BASIS_SYN_ACK))

    def _create(self, key, rec, src, dst):
        recent = self._recent.pop(key, None)
        if recent is not None and rec.ts_ns is not None \
                and rec.ts_ns - recent[3] > self.memory_ns:
            recent = None
        if recent is not None and not _is_handshake(rec):
            # Phần tiếp của cùng kết nối (sau timeout hoặc gói cuối sau khi đóng):
            # giữ chiều của flow trước thay vì đoán lại từ gói giữa chừng.
            fwd, bwd, basis = recent[0], recent[1], recent[2]
            continuation = True
        else:
            fwd, bwd, basis = initiator(rec, src, dst)
            continuation = False
        return Flow(key, fwd, bwd, basis, rec.index, rec.ts_ns, rec.ts_ns,
                    continuation=continuation)

    def _track_tcp(self, flow, rec, forward):
        if rec.protocol != PROTO_TCP or rec.tcp_flags is None:
            return
        flags = rec.tcp_flags
        sender = (rec.src_ip, rec.src_port)
        if flags & TCP_SYN:
            kind = "syn_ack" if flags & TCP_ACK else "syn"
            if rec.tcp_seq is not None:
                flow.handshake_seq.setdefault((sender, kind), rec.tcp_seq)
        else:
            flow.sent_non_syn.add(sender)
        if flow.closed:
            return
        if flags & TCP_RST:
            flow.end_reason = END_RST
        elif flags & TCP_FIN:
            flow.fin_from.add((rec.src_ip, rec.src_port))
            if len(flow.fin_from) == 2:
                flow.end_reason = END_FIN
        if flow.closed:
            flow.closed_ts_ns = rec.ts_ns
            self._closing[flow.key] = flow

    def _attach_fragment(self, rec):
        """Với mảnh không phải mảnh đầu, tìm flow của mảnh đầu; None nếu không áp dụng."""
        if not rec.is_fragment or rec.l4_offset is not None:
            return None
        frag = (rec.ip_version, rec.src_ip, rec.dst_ip, rec.protocol, rec.frag_id)
        entry = self._fragments.get(frag)
        if entry is not None:
            flow, src_port, first_ts = entry
            if not flow.finished and (
                    first_ts is None or rec.ts_ns is None
                    or 0 <= rec.ts_ns - first_ts <= self.fragment_timeout_ns):
                return flow, src_port
            del self._fragments[frag]
        if rec.protocol in PORT_PROTOCOLS:
            self.orphan_fragments += 1
        return None

    # ---- kết thúc flow ----

    def _finish(self, flow, reason):
        if not flow.closed:
            flow.end_reason = reason
        flow.finished = True
        del self._active[flow.key]
        self._closing.pop(flow.key, None)
        self._finished.append(flow)
        if self.keep_finished:
            self._all_finished.append(flow)
        self._count(flow, self._counts)
        end_ts = flow.last_ts_ns if flow.last_ts_ns is not None else self._now
        if end_ts is not None:
            self._recent.pop(flow.key, None)
            self._recent[flow.key] = (flow.fwd_endpoint, flow.bwd_endpoint,
                                      flow.direction_basis, end_ts)

    def expire(self, now_ns: int | None = None) -> None:
        """Kết thúc các flow mà gói tới sau thời điểm ``now_ns`` chắc chắn không thuộc về.

        Chỉ dùng nhàn rỗi và thời gian chờ sau khi đóng, là hai điều kiện không
        phụ thuộc vào gói tới sau, nên kết quả giống như kiểm tra lúc gói tới.
        Đồng thời dọn bộ nhớ mảnh IP và bộ nhớ chiều đã quá hạn.
        """
        now = self._now if now_ns is None else now_ns
        if now is None:
            return
        while self._closing:
            flow = next(iter(self._closing.values()))
            if flow.closed_ts_ns is not None and now - flow.closed_ts_ns <= self.grace_ns:
                break
            self._finish(flow, flow.end_reason)
        while self._active:
            flow = next(iter(self._active.values()))
            if flow.last_ts_ns is not None and now - flow.last_ts_ns <= self.idle_ns:
                break
            self._finish(flow, END_IDLE)
        # Hai bảng nhớ chỉ cần dọn gần đúng: lúc dùng vẫn kiểm tra hạn lại.
        while self._fragments:
            first_ts = next(iter(self._fragments.values()))[2]
            if first_ts is not None and now - first_ts <= self.fragment_timeout_ns:
                break
            self._fragments.popitem(last=False)
        while self._recent:
            if now - next(iter(self._recent.values()))[3] <= self.memory_ns:
                break
            self._recent.popitem(last=False)

    def finish_all(self) -> None:
        """Hết dữ liệu: flow còn mở kết thúc với lý do ``het_du_lieu``."""
        for flow in list(self._active.values()):
            self._finish(flow, END_OF_INPUT)

    def pop_finished(self) -> list[Flow]:
        """Lấy các flow đã kết thúc kể từ lần gọi trước."""
        done, self._finished = self._finished, []
        return done

    # ---- kết quả ----

    def flows(self) -> list[Flow]:
        """Mọi flow (đã kết thúc và còn mở) theo thứ tự gói đầu tiên trong file.

        Với ``keep_finished=False`` chỉ gồm các flow chưa được ``pop_finished()``.
        """
        kept = self._all_finished if self.keep_finished else self._finished
        return sorted(kept + list(self._active.values()), key=lambda f: f.first_index)

    @staticmethod
    def _count(flow, counts):
        counts["so_flow"] += 1
        counts["so_packet"] += flow.packets
        counts["co_so:" + flow.direction_basis] += 1
        counts[f"giao_thuc:{flow.key.protocol}"] += 1
        counts["ket_thuc:" + (flow.end_reason or "dang_mo")] += 1
        counts["flow_tiep_noi"] += flow.continuation
        counts["flow_khong_co_cong"] += (flow.key.protocol in PORT_PROTOCOLS
                                         and flow.key.a_port is None)
        counts["manh_da_gan"] += flow.fragments_attached

    def summary(self) -> dict:
        counts = Counter(self._counts)
        for flow in self._active.values():
            self._count(flow, counts)
        return {
            "so_flow": counts["so_flow"],
            "so_packet": counts["so_packet"],
            "flow_theo_co_so": _group(counts, "co_so:"),
            "flow_theo_giao_thuc": _group(counts, "giao_thuc:", int),
            "flow_theo_ly_do_ket_thuc": _group(counts, "ket_thuc:"),
            "flow_tiep_noi": counts["flow_tiep_noi"],
            "flow_khong_co_cong": counts["flow_khong_co_cong"],
            "manh_da_gan": counts["manh_da_gan"],
            "manh_mo_coi": self.orphan_fragments,
            "goi_sai_thu_tu_thoi_gian": self.out_of_order,
            "tham_so": self.settings.__dict__,
        }


def _group(counts, prefix, cast=str):
    """Lấy các mục có tiền tố ``prefix`` của Counter thành dict, bỏ tiền tố."""
    return {cast(k[len(prefix):]): v for k, v in counts.items() if k.startswith(prefix)}


def assign_flows(records, settings: FlowSettings | None = None) -> FlowAssigner:
    """Ghép mọi packet của một nguồn bản ghi rồi kết thúc mọi flow còn mở."""
    assigner = FlowAssigner(settings)
    for rec in records:
        assigner.add(rec)
    assigner.finish_all()
    return assigner


CSV_COLUMNS = ("first_index", "first_ts", "last_ts", "ip_version", "protocol",
               "fwd_ip", "fwd_port", "bwd_ip", "bwd_port", "direction_basis",
               "continuation", "end_reason", "fragments_attached",
               "payload_unknown") + tuple(BASIC_FEATURES) + tuple(STAT_FEATURES)


def _ts(ts_ns):
    return "" if ts_ns is None else f"{ts_ns // 10**9}.{ts_ns % 10**9:09d}"


def csv_row(flow: Flow) -> dict:
    row = {
        "first_index": flow.first_index,
        "first_ts": _ts(flow.first_ts_ns),
        "last_ts": _ts(flow.last_ts_ns),
        "ip_version": flow.key.ip_version,
        "protocol": flow.key.protocol,
        "fwd_ip": flow.fwd_endpoint[0],
        "fwd_port": flow.fwd_endpoint[1],
        "bwd_ip": flow.bwd_endpoint[0],
        "bwd_port": flow.bwd_endpoint[1],
        "direction_basis": flow.direction_basis,
        "continuation": int(flow.continuation),
        "end_reason": flow.end_reason,
        "fragments_attached": flow.fragments_attached,
        "payload_unknown": flow.payload_unknown,
    }
    row.update(basic_features(flow))
    row.update(stat_features(flow))
    return {k: "" if v is None else v for k, v in row.items()}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Ghép packet thành flow hai chiều, xác định chiều và kết thúc flow."
    )
    parser.add_argument("file", help="đường dẫn file .pcap hoặc .pcapng")
    parser.add_argument("--csv", help="ghi bảng flow ra file CSV")
    parser.add_argument("--stats", help="ghi thống kê ra file JSON")
    parser.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    args = parser.parse_args(argv)

    settings = FlowSettings.from_config(load_config(args.config))
    stats = ParseStats()
    assigner = assign_flows(extract_packets(args.file, stats), settings)
    summary = assigner.summary()
    print(f"{args.file}: {summary['so_packet']} packet IP, {summary['so_flow']} flow")
    print("  Cơ sở xác định chiều: " + ", ".join(
        f"{k}={v}" for k, v in sorted(summary["flow_theo_co_so"].items()))
        + f"; flow tiếp nối: {summary['flow_tiep_noi']}")
    print("  Lý do kết thúc: " + ", ".join(
        f"{k}={v}" for k, v in sorted(summary["flow_theo_ly_do_ket_thuc"].items())))
    print(f"  Mảnh IP đã gắn vào flow: {summary['manh_da_gan']}; "
          f"mảnh mồ côi: {summary['manh_mo_coi']}; "
          f"flow TCP/UDP/SCTP không có cổng: {summary['flow_khong_co_cong']}")
    if summary["goi_sai_thu_tu_thoi_gian"]:
        print(f"  Cảnh báo: {summary['goi_sai_thu_tu_thoi_gian']} gói có thời điểm "
              "nhỏ hơn gói trước; flow được ghép theo thứ tự trong file")
    if stats.file_error:
        print(f"  Lỗi file: {stats.file_error}")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            for flow in assigner.flows():
                writer.writerow(csv_row(flow))
        print(f"Đã ghi bảng flow: {args.csv}")
    if args.stats:
        with open(args.stats, "w", encoding="utf-8") as f:
            json.dump({"flow": summary, "packet": stats.as_dict()}, f,
                      ensure_ascii=False, indent=2)
        print(f"Đã ghi thống kê: {args.stats}")
    return 1 if stats.file_error else 0


if __name__ == "__main__":
    sys.exit(main())

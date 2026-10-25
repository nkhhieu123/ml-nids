"""Ghép packet thành flow hai chiều và xác định chiều forward/backward (C04-T01).

Một flow hai chiều gồm mọi packet có cùng giao thức và cùng cặp đầu mút
(IP, cổng), bất kể gói đi theo chiều nào. Chiều forward là chiều của bên mở
kết nối (client); chiều backward là chiều ngược lại. Quy tắc chi tiết ở
docs/18_flow_hai_chieu.md và QĐ-016.

Module này chưa cắt flow theo timeout, FIN/RST hay tái sử dụng 5-tuple; phần
đó thuộc C04-T02. Ở đây mỗi khóa flow ứng một flow trong cả file.

    assigner = FlowAssigner()
    for rec in extract_packets("data/pcap/<file>.pcap"):
        flow, forward = assigner.add(rec)
    for flow in assigner.flows():
        print(flow.fwd_endpoint, flow.bwd_endpoint, flow.direction_basis)
"""

import argparse
import csv
import json
import sys
from collections import Counter
from dataclasses import dataclass
from ipaddress import ip_address

from .config import load_config
from .packets import (
    PORT_PROTOCOLS, PROTO_TCP, TCP_ACK, TCP_SYN, ParseStats, PacketRecord,
    extract_packets,
)

# Cách xác định bên mở kết nối, theo thứ tự ưu tiên (docs/18, mục 3)
BASIS_SYN = "syn"                    # gói đầu là SYN không có ACK: bên gửi là client
BASIS_SYN_ACK = "syn_ack"            # gói đầu là SYN+ACK: bên nhận là client
BASIS_SERVICE_PORT = "cong_dich_vu"  # TCP giữa chừng: bên dùng cổng >= 1024 là client
BASIS_FIRST_PACKET = "goi_dau"       # còn lại: bên gửi gói đầu tiên là client
BASIS_SAME_ENDPOINT = "cung_dau_mut"  # hai đầu trùng nhau: mọi gói là forward
BASES = (BASIS_SYN, BASIS_SYN_ACK, BASIS_SERVICE_PORT, BASIS_FIRST_PACKET,
         BASIS_SAME_ENDPOINT)

# Cổng dưới ngưỡng này coi là cổng dịch vụ (well-known ports, RFC 6335)
SERVICE_PORT_LIMIT = 1024

# Mảnh IP đầu tiên được nhớ trong khoảng này để gắn các mảnh sau vào cùng flow;
# mặc định bằng thời gian chờ ghép mảnh của Linux (net.ipv4.ipfrag_time).
# Giá trị dùng thật lấy từ flow.fragment_timeout_s trong config/default.yaml.
FRAGMENT_TIMEOUT_S = 30


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

    Các bộ đếm ở đây chỉ để kiểm tra việc ghép và phân chiều; đặc trưng thật
    (byte, thời lượng, thống kê) tính ở C04-T03 và C04-T04.
    """
    key: FlowKey
    fwd_endpoint: tuple[str, int | None]   # bên mở kết nối (client)
    bwd_endpoint: tuple[str, int | None]   # bên còn lại (server)
    direction_basis: str                   # một trong BASES
    first_index: int                       # chỉ số packet đầu tiên trong file
    first_ts_ns: int | None
    last_ts_ns: int | None
    fwd_packets: int = 0
    bwd_packets: int = 0
    fragments_attached: int = 0            # mảnh IP không mang cổng được gắn vào flow này

    @property
    def packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

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


class FlowAssigner:
    """Gắn từng packet vào flow hai chiều theo thứ tự trong file.

    Mảnh IP không phải mảnh đầu không có cổng. Nó được gắn vào flow của mảnh
    đầu cùng datagram (cùng IP nguồn, IP đích, giao thức, Identification) nếu
    mảnh đầu đã thấy trong vòng ``fragment_timeout_s`` giây; nếu không thì vào
    flow không cổng của cặp IP đó và được đếm trong ``orphan_fragments``.
    """

    def __init__(self, fragment_timeout_s: float = FRAGMENT_TIMEOUT_S):
        self.fragment_timeout_ns = int(fragment_timeout_s * 10**9)
        self._flows: dict[FlowKey, Flow] = {}
        # (ip_version, src, dst, proto, frag_id) -> (flow, cổng nguồn, ts của mảnh đầu)
        self._fragments: dict[tuple, tuple[Flow, int | None, int | None]] = {}
        self.orphan_fragments = 0
        self.out_of_order = 0   # số gói có thời điểm nhỏ hơn gói đứng trước trong file
        self._last_ts = None

    def add(self, rec: PacketRecord) -> tuple[Flow, bool]:
        """Gắn một packet vào flow; trả về (flow, gói có thuộc chiều forward không)."""
        if rec.ts_ns is not None:
            if self._last_ts is not None and rec.ts_ns < self._last_ts:
                self.out_of_order += 1
            self._last_ts = rec.ts_ns

        attached = self._attach_fragment(rec)
        if attached is not None:
            flow, src_port = attached
            forward = flow.is_forward(rec, src_port)
            flow.fragments_attached += 1
        else:
            flow = self._get_or_create(rec)
            forward = flow.is_forward(rec)
            if rec.is_fragment and rec.l4_offset is not None:
                frag = (rec.ip_version, rec.src_ip, rec.dst_ip, rec.protocol, rec.frag_id)
                self._fragments[frag] = (flow, rec.src_port, rec.ts_ns)

        if forward:
            flow.fwd_packets += 1
        else:
            flow.bwd_packets += 1
        if rec.ts_ns is not None:
            if flow.first_ts_ns is None:
                flow.first_ts_ns = rec.ts_ns
            flow.last_ts_ns = rec.ts_ns
        return flow, forward

    def _attach_fragment(self, rec):
        """Với mảnh không phải mảnh đầu, tìm flow của mảnh đầu; None nếu không áp dụng."""
        if not rec.is_fragment or rec.l4_offset is not None:
            return None
        frag = (rec.ip_version, rec.src_ip, rec.dst_ip, rec.protocol, rec.frag_id)
        entry = self._fragments.get(frag)
        if entry is not None:
            flow, src_port, first_ts = entry
            if (first_ts is None or rec.ts_ns is None
                    or 0 <= rec.ts_ns - first_ts <= self.fragment_timeout_ns):
                return flow, src_port
            del self._fragments[frag]
        if rec.protocol in PORT_PROTOCOLS:
            self.orphan_fragments += 1
        return None

    def _get_or_create(self, rec):
        src = (rec.src_ip, rec.src_port)
        dst = (rec.dst_ip, rec.dst_port)
        key = make_key(rec.ip_version, rec.protocol, src, dst)
        flow = self._flows.get(key)
        if flow is None:
            fwd, bwd, basis = initiator(rec, src, dst)
            flow = Flow(key, fwd, bwd, basis, rec.index, rec.ts_ns, rec.ts_ns)
            self._flows[key] = flow
        return flow

    def flows(self) -> list[Flow]:
        """Các flow theo thứ tự xuất hiện của gói đầu tiên."""
        return list(self._flows.values())

    def summary(self) -> dict:
        flows = self._flows.values()
        return {
            "so_flow": len(self._flows),
            "so_packet": sum(f.packets for f in flows),
            "flow_theo_co_so": dict(Counter(f.direction_basis for f in flows)),
            "flow_theo_giao_thuc": dict(Counter(f.key.protocol for f in flows)),
            "flow_khong_co_cong": sum(1 for f in flows
                                      if f.key.protocol in PORT_PROTOCOLS
                                      and f.key.a_port is None),
            "manh_da_gan": sum(f.fragments_attached for f in flows),
            "manh_mo_coi": self.orphan_fragments,
            "goi_sai_thu_tu_thoi_gian": self.out_of_order,
        }


def assign_flows(records, fragment_timeout_s: float = FRAGMENT_TIMEOUT_S) -> FlowAssigner:
    """Ghép mọi packet của một nguồn bản ghi; trả về FlowAssigner đã đầy."""
    assigner = FlowAssigner(fragment_timeout_s)
    for rec in records:
        assigner.add(rec)
    return assigner


CSV_COLUMNS = ("first_index", "first_ts", "last_ts", "ip_version", "protocol",
               "fwd_ip", "fwd_port", "bwd_ip", "bwd_port", "direction_basis",
               "fwd_packets", "bwd_packets", "fragments_attached")


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
        "fwd_packets": flow.fwd_packets,
        "bwd_packets": flow.bwd_packets,
        "fragments_attached": flow.fragments_attached,
    }
    return {k: "" if v is None else v for k, v in row.items()}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Ghép packet thành flow hai chiều và xác định chiều forward/backward."
    )
    parser.add_argument("file", help="đường dẫn file .pcap hoặc .pcapng")
    parser.add_argument("--csv", help="ghi bảng flow ra file CSV")
    parser.add_argument("--stats", help="ghi thống kê ra file JSON")
    parser.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    stats = ParseStats()
    assigner = assign_flows(extract_packets(args.file, stats),
                            cfg["flow"]["fragment_timeout_s"])
    summary = assigner.summary()
    print(f"{args.file}: {summary['so_packet']} packet IP, {summary['so_flow']} flow")
    print("  Cơ sở xác định chiều: " + ", ".join(
        f"{k}={v}" for k, v in sorted(summary["flow_theo_co_so"].items())))
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

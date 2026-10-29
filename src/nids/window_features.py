"""Đặc trưng trên cửa sổ host.

- C04-T06: số đích, cổng đích, kết nối mới, entropy cổng; docs/23, QĐ-022.
- C04-T07: tỷ lệ kết nối TCP không hoàn tất sau thời gian quan sát; docs/24, QĐ-023.

Dùng cơ chế cửa sổ của host_windows.py (C04-T05) và flow của flows.py để biết gói
nào host gửi trong vai client.

    python -m nids.window_features data/pcap/<file>.pcap --net 192.168.10.0/24 --csv output/windows.csv
"""

import argparse
import csv
import json
import math
import sys
from collections import Counter

from .config import load_config
from .flows import FlowAssigner, FlowSettings
from .host_windows import CSV_COLUMNS as BASE_COLUMNS, HostWindow, HostWindower, csv_row as base_row
from .flows import BASIS_SYN
from .packets import PORT_PROTOCOLS, PROTO_TCP, ParseStats, extract_packets

ENTROPY_DIGITS = 6

# Tên đặc trưng -> (đơn vị, mô tả). Thứ tự là thứ tự cột.
WINDOW_FEATURES = {
    "dst_hosts": ("host", "Số IP đích khác nhau host gửi tới trong vai client"),
    "dst_ports": ("cổng", "Số cổng đích TCP/UDP khác nhau host gửi tới trong vai client"),
    "dst_host_ports": ("cặp", "Số cặp (IP đích, cổng đích) khác nhau, vai client"),
    "new_conn_out": ("kết nối", "Số flow mới do host mở (host là client), gói đầu nằm trong cửa sổ"),
    "src_hosts": ("host", "Số IP nguồn khác nhau gửi tới host trong vai client (host là server)"),
    "new_conn_in": ("kết nối", "Số flow mới mở tới host (host là server), gói đầu nằm trong cửa sổ"),
    "dst_port_entropy": ("bit", "Entropy Shannon của cổng đích trên các gói host gửi trong vai client; "
                                "trống nếu không có gói TCP/UDP nào"),
    "tcp_attempts_out": ("lần thử", "Số lần thử kết nối TCP (flow mới mở bằng SYN) host mở"),
    "incomplete_out": ("lần thử", "Số lần thử host mở không hoàn tất bắt tay trong thời gian quan sát"),
    "no_reply_out": ("lần thử", "Số lần thử host mở không có trả lời"),
    "rejected_out": ("lần thử", "Số lần thử host mở bị server trả RST"),
    "half_open_out": ("lần thử", "Số lần thử có SYN+ACK nhưng host không gửi ACK hoàn tất"),
    "incomplete_ratio_out": ("tỷ lệ 0–1", "incomplete_out / tcp_attempts_out; trống nếu không có lần thử"),
    "tcp_attempts_in": ("lần thử", "Số lần thử kết nối TCP tới host"),
    "incomplete_in": ("lần thử", "Số lần thử tới host không hoàn tất trong thời gian quan sát"),
    "incomplete_ratio_in": ("tỷ lệ 0–1", "incomplete_in / tcp_attempts_in; trống nếu không có lần thử"),
}

RATIO_DIGITS = 6

# Kết quả của một lần thử kết nối TCP sau thời gian quan sát
OUTCOME_COMPLETE = "hoan_tat"        # SYN+ACK rồi ACK của client
OUTCOME_HALF_OPEN = "do_dang"        # có SYN+ACK, client không ACK (ví dụ nmap -sS gửi RST)
OUTCOME_REJECTED = "bi_tu_choi"      # server trả RST
OUTCOME_NO_REPLY = "khong_phan_hoi"  # không có trả lời


def is_tcp_attempt(flow) -> bool:
    """Flow TCP mở bằng SYN của client và không phải phần tiếp nối."""
    return flow.key.protocol == PROTO_TCP and flow.direction_basis == BASIS_SYN \
        and not flow.continuation


def attempt_outcome(flow, observe_ns: int) -> str:
    """Kết quả bắt tay chỉ xét các bước xảy ra trong ``observe_ns`` kể từ gói đầu.

    Không phụ thuộc gói tới sau thời hạn, nên giống nhau khi đọc file và realtime.
    """
    deadline = flow.first_ts_ns + observe_ns
    within = lambda ts: ts is not None and ts <= deadline
    if within(flow.synack_ts_ns):
        return OUTCOME_COMPLETE if within(flow.client_ack_ts_ns) else OUTCOME_HALF_OPEN
    if within(flow.server_rst_ts_ns):
        return OUTCOME_REJECTED
    return OUTCOME_NO_REPLY


def shannon_entropy(counts) -> float | None:
    """H = −Σ p·log2(p) với p là tỷ lệ của từng giá trị; None nếu không có giá trị nào."""
    total = sum(counts)
    if not total:
        return None
    h = -sum(c / total * math.log2(c / total) for c in counts if c)
    return h + 0.0          # đổi −0.0 thành 0.0


class HostWindowFeatures(HostWindow):
    """Cửa sổ host có thêm các tập đích, cổng và bộ đếm kết nối mới."""

    def __init__(self, host, start_ns, end_ns, observe_ns=3 * 10**9):
        super().__init__(host, start_ns, end_ns)
        self.observe_ns = observe_ns
        self.attempts_out = []                # flow của các lần thử TCP host mở
        self.attempts_in = []
        self.dst_ips = set()
        self.dst_port_counts = Counter()      # cổng đích -> số gói (vai client)
        self.dst_pairs = set()
        self.src_ips = set()
        self.new_conn_out = 0
        self.new_conn_in = 0

    def add(self, rec, outgoing, flow=None, forward=None, new_conn=False):
        super().add(rec, outgoing)
        if flow is None:
            return
        if outgoing and forward:
            # Host gửi gói forward: host là client của flow này.
            self.dst_ips.add(rec.dst_ip)
            if rec.protocol in PORT_PROTOCOLS and rec.dst_port is not None:
                self.dst_port_counts[rec.dst_port] += 1
                self.dst_pairs.add((rec.dst_ip, rec.dst_port))
        elif not outgoing and forward:
            # Host nhận gói forward: host là server của flow này.
            self.src_ips.add(rec.src_ip)
        if new_conn:
            attempt = is_tcp_attempt(flow)
            if flow.fwd_endpoint[0] == self.host:
                self.new_conn_out += 1
                if attempt:
                    self.attempts_out.append(flow)
            if flow.bwd_endpoint[0] == self.host:
                self.new_conn_in += 1
                if attempt:
                    self.attempts_in.append(flow)

    def features(self) -> dict:
        h = shannon_entropy(self.dst_port_counts.values())
        return {
            "dst_hosts": len(self.dst_ips),
            "dst_ports": len(self.dst_port_counts),
            "dst_host_ports": len(self.dst_pairs),
            "new_conn_out": self.new_conn_out,
            "src_hosts": len(self.src_ips),
            "new_conn_in": self.new_conn_in,
            "dst_port_entropy": None if h is None else round(h, ENTROPY_DIGITS),
            **self._attempt_features(),
        }

    def _attempt_features(self):
        out = [attempt_outcome(f, self.observe_ns) for f in self.attempts_out]
        inc_out = sum(o != OUTCOME_COMPLETE for o in out)
        inc_in = sum(attempt_outcome(f, self.observe_ns) != OUTCOME_COMPLETE
                     for f in self.attempts_in)
        ratio = lambda part, total: round(part / total, RATIO_DIGITS) if total else None
        return {
            "tcp_attempts_out": len(out),
            "incomplete_out": inc_out,
            "no_reply_out": out.count(OUTCOME_NO_REPLY),
            "rejected_out": out.count(OUTCOME_REJECTED),
            "half_open_out": out.count(OUTCOME_HALF_OPEN),
            "incomplete_ratio_out": ratio(inc_out, len(out)),
            "tcp_attempts_in": len(self.attempts_in),
            "incomplete_in": inc_in,
            "incomplete_ratio_in": ratio(inc_in, len(self.attempts_in)),
        }


def is_new_connection(flow, rec) -> bool:
    """Gói ``rec`` mở một kết nối mới: gói đầu của flow không phải phần tiếp nối."""
    return flow.first_index == rec.index and not flow.continuation


class WindowPipeline:
    """Ghép flow và lập cửa sổ host trong cùng một lượt đọc gói.

    ``flow_sink``: hàm nhận từng flow đã kết thúc (ví dụ để ghi bảng flow, C04-T08);
    None thì bỏ flow đi sau khi dùng.
    """

    def __init__(self, settings: FlowSettings, size_s, step_s, networks=None,
                 observe_s: float = 3, flow_sink=None):
        observe_ns = round(observe_s * 10**9)
        self.flow_sink = flow_sink
        self.flows = FlowAssigner(settings, keep_finished=False)
        # Cửa sổ chờ thêm observe_s sau khi kết thúc: lần thử ở cuối cửa sổ cần
        # đủ thời gian quan sát trước khi tính tỷ lệ không hoàn tất.
        self.windows = HostWindower(
            size_s, step_s, networks,
            lambda host, start, end: HostWindowFeatures(host, start, end, observe_ns),
            emit_delay_s=observe_s)

    def _drain_flows(self):
        for flow in self.flows.pop_finished():
            if self.flow_sink is not None:
                self.flow_sink(flow)

    def add(self, rec):
        flow, forward = self.flows.add(rec)
        self._drain_flows()
        self.windows.add(rec, flow=flow, forward=forward, new_conn=is_new_connection(flow, rec))
        return self.windows.pop_finished()

    def finish(self):
        self.flows.finish_all()
        self._drain_flows()
        self.windows.finish_all()
        return self.windows.pop_finished()


CSV_COLUMNS = BASE_COLUMNS + tuple(WINDOW_FEATURES)


def csv_row(w: HostWindowFeatures) -> dict:
    row = base_row(w)
    row.update(w.features())
    return {k: "" if v is None else v for k, v in row.items()}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Đặc trưng cửa sổ host từ file PCAP.")
    parser.add_argument("file")
    parser.add_argument("--net", action="append",
                        help="chỉ lập cửa sổ cho host trong dải mạng này (CIDR); lặp lại được")
    parser.add_argument("--csv", help="ghi bảng cửa sổ ra file CSV")
    parser.add_argument("--stats", help="ghi thống kê ra file JSON")
    parser.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    win = cfg["windows"]["flow"]
    pipe = WindowPipeline(FlowSettings.from_config(cfg), win["size_s"], win["step_s"], args.net,
                          cfg["flow"]["handshake_observe_s"])
    stats = ParseStats()
    out = open(args.csv, "w", newline="", encoding="utf-8") if args.csv else None
    writer = csv.DictWriter(out, fieldnames=CSV_COLUMNS) if out else None
    if writer:
        writer.writeheader()
    try:
        for rec in extract_packets(args.file, stats):
            for w in pipe.add(rec):
                if writer:
                    writer.writerow(csv_row(w))
        for w in pipe.finish():
            if writer:
                writer.writerow(csv_row(w))
    finally:
        if out:
            out.close()
    summary = pipe.windows.summary()
    print(f"{args.file}: {summary['so_goi']} gói IP, {summary['so_cua_so_host']} cửa sổ host")
    if args.csv:
        print(f"Đã ghi bảng cửa sổ: {args.csv}")
    if args.stats:
        with open(args.stats, "w", encoding="utf-8") as f:
            json.dump({"cua_so": summary, "flow": pipe.flows.summary(), "packet": stats.as_dict()},
                      f, ensure_ascii=False, indent=2)
        print(f"Đã ghi thống kê: {args.stats}")
    return 1 if stats.file_error else 0


if __name__ == "__main__":
    sys.exit(main())

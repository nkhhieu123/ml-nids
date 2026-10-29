"""Đặc trưng trên cửa sổ host: số đích, cổng đích, kết nối mới, entropy cổng (C04-T06).

Dùng cơ chế cửa sổ của host_windows.py (C04-T05) và flow của flows.py để biết gói
nào host gửi trong vai client. Công thức ở docs/23_dac_trung_cua_so.md (QĐ-022).

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
from .packets import PORT_PROTOCOLS, ParseStats, extract_packets

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
}


def shannon_entropy(counts) -> float | None:
    """H = −Σ p·log2(p) với p là tỷ lệ của từng giá trị; None nếu không có giá trị nào."""
    total = sum(counts)
    if not total:
        return None
    h = -sum(c / total * math.log2(c / total) for c in counts if c)
    return h + 0.0          # đổi −0.0 thành 0.0


class HostWindowFeatures(HostWindow):
    """Cửa sổ host có thêm các tập đích, cổng và bộ đếm kết nối mới."""

    def __init__(self, host, start_ns, end_ns):
        super().__init__(host, start_ns, end_ns)
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
            if flow.fwd_endpoint[0] == self.host:
                self.new_conn_out += 1
            if flow.bwd_endpoint[0] == self.host:
                self.new_conn_in += 1

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
        }


def is_new_connection(flow, rec) -> bool:
    """Gói ``rec`` mở một kết nối mới: gói đầu của flow không phải phần tiếp nối."""
    return flow.first_index == rec.index and not flow.continuation


class WindowPipeline:
    """Ghép flow và lập cửa sổ host trong cùng một lượt đọc gói."""

    def __init__(self, settings: FlowSettings, size_s, step_s, networks=None,
                 window_factory=HostWindowFeatures):
        self.flows = FlowAssigner(settings, keep_finished=False)
        self.windows = HostWindower(size_s, step_s, networks, window_factory)

    def add(self, rec):
        flow, forward = self.flows.add(rec)
        self.flows.pop_finished()
        self.windows.add(rec, flow=flow, forward=forward, new_conn=is_new_connection(flow, rec))
        return self.windows.pop_finished()

    def finish(self):
        self.flows.finish_all()
        self.flows.pop_finished()
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
    pipe = WindowPipeline(FlowSettings.from_config(cfg), win["size_s"], win["step_s"], args.net)
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

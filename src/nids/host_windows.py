"""Cửa sổ thời gian theo host, chạy theo thời điểm của gói (C04-T05).

Mỗi host (một địa chỉ IP) có một chuỗi cửa sổ trượt dài ``size_s`` giây, bước
``step_s`` giây (QĐ-006: 10 giây, bước 2 giây). Cửa sổ bắt đầu tại các bội số của
``step_s`` tính từ epoch, nên đọc file hay bắt realtime đều cắt cửa sổ ở cùng chỗ.
Thời gian trôi theo thời điểm ghi trong gói, không theo đồng hồ máy: cửa sổ
[start, end) đóng khi đã thấy gói có thời điểm >= end. Chi tiết ở
docs/22_cua_so_host.md (QĐ-021).

    windower = HostWindower(size_s=10, step_s=2, networks=["192.168.10.0/24"])
    for rec in extract_packets(path):
        windower.add(rec)
        for w in windower.pop_finished():
            print(w.host, w.start_ns, w.packets_out)
    windower.finish_all()
"""

import argparse
import csv
import json
import sys
from collections import OrderedDict
from dataclasses import dataclass
from ipaddress import ip_address, ip_network

from .config import load_config
from .packets import ParseStats, PacketRecord, extract_packets

NS = 10**9


@dataclass
class HostWindow:
    """Các gói của một host trong một cửa sổ [start_ns, end_ns)."""
    host: str
    start_ns: int
    end_ns: int
    packets_out: int = 0     # gói host gửi đi (host là IP nguồn)
    packets_in: int = 0      # gói host nhận (host là IP đích)
    bytes_out: int = 0       # tổng ip_len gói gửi đi
    bytes_in: int = 0
    first_ts_ns: int | None = None   # thời điểm gói đầu và cuối của host trong cửa sổ
    last_ts_ns: int | None = None

    def add(self, rec: PacketRecord, outgoing: bool):
        if outgoing:
            self.packets_out += 1
            self.bytes_out += rec.ip_len
        else:
            self.packets_in += 1
            self.bytes_in += rec.ip_len
        ts = rec.ts_ns
        if self.first_ts_ns is None or ts < self.first_ts_ns:
            self.first_ts_ns = ts
        if self.last_ts_ns is None or ts > self.last_ts_ns:
            self.last_ts_ns = ts


class HostWindower:
    """Gom gói vào cửa sổ trượt theo host, trả cửa sổ ra khi đã đóng.

    ``networks``: chỉ lập cửa sổ cho host thuộc các dải mạng này (ví dụ mạng nội
    bộ); None là mọi host. Gói vẫn được tính cho host trong dải dù đầu bên kia ở
    ngoài. ``window_factory`` cho phép task sau dùng lớp cửa sổ có thêm đặc trưng.
    ``emit_delay_s``: chờ thêm sau ``end`` rồi mới trả cửa sổ, để đặc trưng cần
    quan sát tiếp sau cửa sổ (C04-T07) có đủ dữ liệu.
    """

    def __init__(self, size_s: float = 10, step_s: float = 2, networks=None,
                 window_factory=HostWindow, emit_delay_s: float = 0):
        self.size_ns = round(size_s * NS)
        self.step_ns = round(step_s * NS)
        self.delay_ns = round(emit_delay_s * NS)
        if not 0 < self.step_ns <= self.size_ns:
            raise ValueError(f"cần 0 < step <= size, nhận size={size_s}, step={step_s}")
        self.networks = None if networks is None else [ip_network(n) for n in networks]
        self.window_factory = window_factory
        # start_ns -> {host: cửa sổ}; khóa tăng dần theo start
        self._open: OrderedDict[int, dict[str, HostWindow]] = OrderedDict()
        self._finished: list[HostWindow] = []
        self._closed_before = None   # mọi cửa sổ có start < giá trị này đã trả ra
        self._now = None
        self._host_cache: dict[str, bool] = {}
        self.packets = 0
        self.late_packets = 0        # gói tới sau khi một số cửa sổ chứa nó đã đóng
        self.no_time_packets = 0     # gói không có thời điểm, không vào cửa sổ nào
        self.windows_emitted = 0

    def _tracked(self, ip):
        if self.networks is None:
            return True
        hit = self._host_cache.get(ip)
        if hit is None:
            addr = ip_address(ip)
            hit = any(addr.version == n.version and addr in n for n in self.networks)
            self._host_cache[ip] = hit
        return hit

    def window_starts(self, ts_ns: int) -> range:
        """Thời điểm bắt đầu của mọi cửa sổ chứa ``ts_ns`` (start <= ts < start + size)."""
        last = ts_ns // self.step_ns * self.step_ns
        first = (ts_ns - self.size_ns) // self.step_ns * self.step_ns + self.step_ns
        return range(first, last + 1, self.step_ns)

    def add(self, rec: PacketRecord, **extra):
        """Thêm một gói. ``extra`` được chuyển cho ``add`` của cửa sổ (dùng ở task sau)."""
        self.packets += 1
        ts = rec.ts_ns
        if ts is None:
            self.no_time_packets += 1
            return
        if self._now is None or ts > self._now:
            self._now = ts
            self._close_until(ts)
        sides = [(h, out) for h, out in ((rec.src_ip, True), (rec.dst_ip, False))
                 if self._tracked(h)]
        late = False
        for start in self.window_starts(ts):
            if self._closed_before is not None and start < self._closed_before:
                late = True
                continue
            hosts = self._open.get(start)
            if hosts is None:
                # Gói sai thứ tự sau một khoảng lặng có thể tạo cửa sổ nằm trước cửa
                # sổ đang mở (khi có emit_delay_s); sắp lại để khóa luôn tăng dần.
                out_of_order = bool(self._open) and start < next(reversed(self._open))
                hosts = self._open[start] = {}
                if out_of_order:
                    self._open = OrderedDict(sorted(self._open.items()))
            for host, outgoing in sides:
                w = hosts.get(host)
                if w is None:
                    w = hosts[host] = self.window_factory(host, start, start + self.size_ns)
                w.add(rec, outgoing, **extra)
        if late:
            self.late_packets += 1

    def _close_until(self, now_ns):
        """Đóng mọi cửa sổ có end + emit_delay <= now_ns."""
        limit = now_ns - self.delay_ns
        while self._open:
            start = next(iter(self._open))
            if start + self.size_ns > limit:
                break
            self._emit(start)
        closed = limit - self.size_ns + 1      # cửa sổ có start < closed đã trả ra
        closed = -(-closed // self.step_ns) * self.step_ns
        if self._closed_before is None or closed > self._closed_before:
            self._closed_before = closed

    def _emit(self, start):
        hosts = self._open.pop(start)
        for host in sorted(hosts):
            self._finished.append(hosts[host])
            self.windows_emitted += 1

    def finish_all(self):
        """Hết dữ liệu: trả ra mọi cửa sổ còn mở (cửa sổ cuối có thể chưa đủ dữ liệu)."""
        while self._open:
            self._emit(next(iter(self._open)))

    def pop_finished(self) -> list[HostWindow]:
        done, self._finished = self._finished, []
        return done

    def summary(self) -> dict:
        return {
            "kich_thuoc_cua_so_s": self.size_ns / NS,
            "buoc_s": self.step_ns / NS,
            "cho_truoc_khi_tra_s": self.delay_ns / NS,
            "dai_mang": None if self.networks is None else [str(n) for n in self.networks],
            "so_goi": self.packets,
            "goi_tre": self.late_packets,
            "goi_khong_co_thoi_diem": self.no_time_packets,
            "so_cua_so_host": self.windows_emitted,
        }


def _ts(ns):
    return None if ns is None else f"{ns // NS}.{ns % NS:09d}"


CSV_COLUMNS = ("host", "window_start", "window_end", "packets_out", "packets_in",
               "bytes_out", "bytes_in", "first_ts", "last_ts")


def csv_row(w: HostWindow) -> dict:
    return {
        "host": w.host,
        "window_start": _ts(w.start_ns),
        "window_end": _ts(w.end_ns),
        "packets_out": w.packets_out,
        "packets_in": w.packets_in,
        "bytes_out": w.bytes_out,
        "bytes_in": w.bytes_in,
        "first_ts": _ts(w.first_ts_ns),
        "last_ts": _ts(w.last_ts_ns),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Lập cửa sổ thời gian theo host từ file PCAP.")
    parser.add_argument("file")
    parser.add_argument("--net", action="append",
                        help="chỉ lập cửa sổ cho host trong dải mạng này (CIDR); lặp lại được")
    parser.add_argument("--csv", help="ghi bảng cửa sổ ra file CSV")
    parser.add_argument("--stats", help="ghi thống kê ra file JSON")
    parser.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    args = parser.parse_args(argv)

    win = load_config(args.config)["windows"]["flow"]
    windower = HostWindower(win["size_s"], win["step_s"], args.net)
    stats = ParseStats()
    out = open(args.csv, "w", newline="", encoding="utf-8") if args.csv else None
    writer = csv.DictWriter(out, fieldnames=CSV_COLUMNS) if out else None
    if writer:
        writer.writeheader()
    try:
        for rec in extract_packets(args.file, stats):
            windower.add(rec)
            for w in windower.pop_finished():
                if writer:
                    writer.writerow(csv_row(w))
        windower.finish_all()
        for w in windower.pop_finished():
            if writer:
                writer.writerow(csv_row(w))
    finally:
        if out:
            out.close()
    summary = windower.summary()
    print(f"{args.file}: {summary['so_goi']} gói IP, {summary['so_cua_so_host']} cửa sổ host "
          f"({summary['kich_thuoc_cua_so_s']:g} giây, bước {summary['buoc_s']:g} giây)")
    if summary["goi_tre"]:
        print(f"  {summary['goi_tre']} gói tới sau khi cửa sổ chứa nó đã đóng")
    if args.csv:
        print(f"Đã ghi bảng cửa sổ: {args.csv}")
    if args.stats:
        with open(args.stats, "w", encoding="utf-8") as f:
            json.dump({"cua_so": summary, "packet": stats.as_dict()}, f, ensure_ascii=False, indent=2)
        print(f"Đã ghi thống kê: {args.stats}")
    return 1 if stats.file_error else 0


if __name__ == "__main__":
    sys.exit(main())

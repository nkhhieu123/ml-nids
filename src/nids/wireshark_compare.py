"""Đối chiếu kết quả đọc packet với Wireshark (C03-T07).

Chạy `tshark` trên cùng file, lấy các trường tương ứng của từng packet rồi so
với `inspect_packet()` của packets.py: timestamp, độ dài khung, độ dài đã lưu,
IP nguồn/đích, giao thức, độ dài IP, phân mảnh, cổng và cờ TCP. Gói mà bộ
trích xuất bỏ qua phải là gói mà tshark cũng không thấy IP.

Đọc song song hai luồng (bộ đọc PCAP và đầu ra của tshark) nên dùng được cho
file nhiều GB mà không nạp hết vào bộ nhớ.

    python -m nids.wireshark_compare data/pcap/<file>.pcap --report output/ws_compare.json

Một số khác biệt là có chủ ý và được đếm riêng, không tính là lệch (xem
docs/17_doi_chieu_wireshark.md):

- Gói lỗi ICMP chép lại header của gói gốc; tshark báo cổng của header được
  chép, bộ trích xuất không gán cổng cho gói ICMP.
- IPv4 Total Length bằng 0 (TSO): tshark giữ 0, bộ trích xuất lấy theo số byte
  đã bắt.
- Đường hầm IP trong IP: bộ trích xuất chỉ đọc header IP ngoài cùng nên không
  có cổng; tshark báo cổng của gói bên trong.
- Header IP bị cắt khi bắt, mất địa chỉ đích: tshark vẫn hiện phần đọc được,
  bộ trích xuất bỏ gói (header_ip_bi_cat) vì không dùng được cho flow.
"""

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from decimal import Decimal
from pathlib import Path

from .packets import (
    NOTE_IP_LEN_ZERO, PORT_PROTOCOLS, PROTO_ICMP, PROTO_ICMPV6, PROTO_UDP, SKIP_IP_TRUNCATED,
    TCP_FLAG_MASK,
    inspect_packet,
)
from .pcap_reader import PcapReader

# Trường lấy từ tshark; thứ tự này là thứ tự cột của đầu ra.
TSHARK_FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "_ws.col.protocol",
    "ip.src", "ip.dst", "ip.proto", "ip.len", "ip.flags.mf", "ip.frag_offset",
    "ipv6.src", "ipv6.dst", "ipv6.nxt", "ipv6.plen",
    "ipv6.hopopts.nxt", "ipv6.routing.nxt", "ipv6.fraghdr.nxt", "ipv6.dstopts.nxt",
    "ipv6.fraghdr.offset", "ipv6.fraghdr.more",
    "tcp.srcport", "tcp.dstport", "tcp.flags",
    "udp.srcport", "udp.dstport", "sctp.srcport", "sctp.dstport",
    "tcp.seq_raw", "tcp.len", "udp.length",
)
# Tắt ghép mảnh và ghép đoạn TCP để mỗi dòng ứng đúng một gói như trong file.
TSHARK_PREFS = (
    "ip.defragment:FALSE", "ipv6.defragment:FALSE", "tcp.desegment_tcp_streams:FALSE",
)
WINDOWS_TSHARK = Path("C:/Program Files/Wireshark/tshark.exe")
COMPARED = ("ts", "frame_len", "caplen", "src_ip", "dst_ip", "protocol", "ip_len",
            "is_fragment", "src_port", "dst_port", "tcp_flags", "tcp_seq",
            "payload_len")

# Khác biệt có chủ ý
KNOWN_ICMP_QUOTE = "icmp_chep_header_goc"
KNOWN_TSO = "ip_len_bang_0_tso"
KNOWN_TUNNEL = "duong_ham_ip"
KNOWN_IP_CUT = "header_ip_bi_cat_mat_dia_chi"
KNOWN_UDP_LEN = "udp_length_khac_ip"


def find_tshark(path=None) -> str:
    """Đường dẫn tshark: tham số, PATH, hoặc thư mục cài mặc định trên Windows."""
    if path:
        return str(path)
    found = shutil.which("tshark")
    if found:
        return found
    if WINDOWS_TSHARK.exists():
        return str(WINDOWS_TSHARK)
    raise FileNotFoundError("không tìm thấy tshark; cài Wireshark hoặc truyền --tshark")


def tshark_command(tshark, path):
    cmd = [tshark, "-r", str(path), "-n", "-T", "fields", "-E", "separator=\t",
           "-E", "occurrence=a", "-E", "aggregator=,"]
    for pref in TSHARK_PREFS:
        cmd += ["-o", pref]
    for field in TSHARK_FIELDS:
        cmd += ["-e", field]
    return cmd


def _first(value):
    return value.split(",")[0] if value else ""


def _all(value):
    return value.split(",") if value else []


def _int(value, base=10):
    return int(value, base) if value else None


def expected_from_tshark(line: str) -> dict:
    """Giá trị mong đợi của một packet theo tshark; `ip_version` là None nếu không phải IP."""
    v = dict(zip(TSHARK_FIELDS, (line.rstrip("\r\n").split("\t") + [""] * len(TSHARK_FIELDS))))
    exp = {
        "number": int(v["frame.number"]),
        "ts": int(Decimal(v["frame.time_epoch"]) * 10**9) if v["frame.time_epoch"] else None,
        "frame_len": int(v["frame.len"]),
        "caplen": int(v["frame.cap_len"]),
        "column_protocol": v["_ws.col.protocol"],
        "ip_version": None,
    }
    # Gói ICMP lỗi hay đường hầm có nhiều header IP; header ngoài cùng là giá trị đầu.
    if v["ip.src"]:
        mf = _first(v["ip.flags.mf"]) in ("1", "True")
        offset = _int(_first(v["ip.frag_offset"])) or 0
        exp.update(ip_version=4, src_ip=_first(v["ip.src"]), dst_ip=_first(v["ip.dst"]),
                   protocols={_int(_first(v["ip.proto"]))}, ip_len=_int(_first(v["ip.len"])),
                   is_fragment=mf or offset > 0, ip_layers=len(_all(v["ip.src"])))
    elif v["ipv6.src"]:
        # Giao thức tầng trên của IPv6 là "next header" của header mở rộng cuối cùng;
        # chấp nhận mọi giá trị next header xuất hiện trong chuỗi.
        nxt = [v["ipv6.nxt"], v["ipv6.hopopts.nxt"], v["ipv6.routing.nxt"],
               v["ipv6.fraghdr.nxt"], v["ipv6.dstopts.nxt"]]
        protocols = {int(x) for field in nxt for x in _all(field)}
        frag = bool(v["ipv6.fraghdr.offset"] or v["ipv6.fraghdr.more"])
        plen = _int(_first(v["ipv6.plen"]))
        exp.update(ip_version=6, src_ip=_first(v["ipv6.src"]), dst_ip=_first(v["ipv6.dst"]),
                   protocols=protocols, ip_len=None if plen is None else 40 + plen,
                   is_fragment=frag, ip_layers=len(_all(v["ipv6.src"])))
    else:
        return exp
    ports = None
    for proto in ("tcp", "udp", "sctp"):
        if v[f"{proto}.srcport"]:
            ports = (_int(_first(v[f"{proto}.srcport"])), _int(_first(v[f"{proto}.dstport"])))
            break
    exp["ports"] = ports
    exp["tcp_flags"] = _int(_first(v["tcp.flags"]), 16)
    exp["tcp_seq"] = _int(_first(v["tcp.seq_raw"]))
    exp["payload_len"] = _int(_first(v["tcp.len"]))
    udp_length = _int(_first(v["udp.length"]))
    exp["udp_payload_len"] = None if udp_length is None else udp_length - 8
    return exp


def compare_packet(result, exp) -> tuple[list[str], str | None]:
    """So một packet; trả về (danh sách trường lệch, khác biệt có chủ ý nếu có)."""
    rec = result.record
    if exp["ip_version"] is None:
        return ([] if rec is None else ["tshark không thấy IP nhưng bộ trích xuất giữ gói"]), None
    if rec is None:
        if result.reason == SKIP_IP_TRUNCATED and not exp["dst_ip"]:
            return [], KNOWN_IP_CUT
        return [f"bộ trích xuất bỏ qua ({result.reason}: {result.detail})"], None
    diffs = []
    known = None
    if rec.ts_ns != exp["ts"]:
        diffs.append("ts")
    if rec.frame_len != exp["frame_len"]:
        diffs.append("frame_len")
    if rec.caplen != exp["caplen"]:
        diffs.append("caplen")
    if (rec.ip_version, rec.src_ip, rec.dst_ip) != (exp["ip_version"], exp["src_ip"], exp["dst_ip"]):
        diffs.append("ip")
    if rec.protocol not in exp["protocols"]:
        diffs.append("protocol")
    if rec.ip_len != exp["ip_len"]:
        if NOTE_IP_LEN_ZERO in result.notes and exp["ip_len"] == 0:
            known = KNOWN_TSO
        else:
            diffs.append("ip_len")
    if rec.is_fragment != exp["is_fragment"]:
        diffs.append("is_fragment")
    got_ports = None if rec.src_port is None else (rec.src_port, rec.dst_port)
    if got_ports != exp["ports"]:
        if got_ports is None and rec.protocol in (PROTO_ICMP, PROTO_ICMPV6):
            known = KNOWN_ICMP_QUOTE
        elif got_ports is None and exp["ip_layers"] > 1 and rec.protocol not in PORT_PROTOCOLS:
            known = KNOWN_TUNNEL
        else:
            diffs.append("ports")
    exp_flags = None if exp["tcp_flags"] is None else exp["tcp_flags"] & TCP_FLAG_MASK
    if rec.tcp_flags != exp_flags and known is None:
        diffs.append("tcp_flags")
    if rec.tcp_seq != exp["tcp_seq"] and known is None:
        diffs.append("tcp_seq")
    # Mảnh IP không so: Wireshark (tắt ghép mảnh) báo độ dài UDP của cả datagram ở
    # mảnh đầu và không có TCP/UDP ở các mảnh sau, còn dự án tính theo từng mảnh.
    if known is None and not rec.is_fragment:
        if rec.protocol == PROTO_UDP:
            # Dự án lấy độ dài dữ liệu UDP theo header IP; trường Length của UDP
            # khác đi là gói sai định dạng, đếm riêng. Header UDP bị cắt thì không so.
            if exp["udp_payload_len"] is not None and rec.payload_len != exp["udp_payload_len"]:
                known = KNOWN_UDP_LEN
        elif rec.payload_len != exp["payload_len"]:
            diffs.append("payload_len")
    return diffs, known


class CompareReport:
    def __init__(self, path):
        self.path = str(path)
        self.total = 0
        self.matched = Counter()          # "IPv4 TCP" -> số gói
        self.skipped_agree = Counter()    # giao thức theo tshark của gói cả hai bên không coi là IP
        self.known = Counter()
        self.field_diffs = Counter()
        self.mismatch_count = 0
        self.examples = []

    def add(self, pkt, result, exp):
        self.total += 1
        diffs, known = compare_packet(result, exp)
        if diffs:
            self.mismatch_count += 1
            self.field_diffs.update(diffs)
            if len(self.examples) < 20:
                self.examples.append({"frame": exp["number"], "lech": diffs})
            return
        if known:
            self.known[known] += 1
            if result.record is None:
                return
        if result.record is None:
            self.skipped_agree[exp["column_protocol"] or "?"] += 1
        else:
            rec = result.record
            self.matched[f"IPv{rec.ip_version} {rec.protocol_name}"] += 1

    def as_dict(self):
        return {
            "file": self.path,
            "tong_packet": self.total,
            "goi_ip_khop": sum(self.matched.values()),
            "khop_theo_giao_thuc": dict(self.matched.most_common()),
            "khong_phai_ip_ca_hai_dong_y": dict(self.skipped_agree.most_common()),
            "khac_biet_co_chu_y": dict(self.known.most_common()),
            "lech": self.mismatch_count,
            "lech_theo_truong": dict(self.field_diffs.most_common()),
            "vi_du_lech": self.examples,
        }

    def summary_lines(self):
        d = self.as_dict()
        lines = [f"{Path(self.path).name}: {self.total} packet; gói IP khớp {d['goi_ip_khop']};"
                 f" không phải IP (hai bên đồng ý) {sum(self.skipped_agree.values())};"
                 f" lệch {self.mismatch_count}"]
        if self.matched:
            lines.append("  Khớp theo giao thức: " + ", ".join(
                f"{k}={n}" for k, n in self.matched.most_common()))
        if self.skipped_agree:
            lines.append("  Không phải IP theo tshark: " + ", ".join(
                f"{k}={n}" for k, n in self.skipped_agree.most_common()))
        if self.known:
            lines.append("  Khác biệt có chủ ý: " + ", ".join(
                f"{k}={n}" for k, n in self.known.most_common()))
        if self.mismatch_count:
            lines.append("  LỆCH theo trường: " + ", ".join(
                f"{k}={n}" for k, n in self.field_diffs.most_common()))
            for e in self.examples[:10]:
                lines.append(f"    khung {e['frame']}: {', '.join(e['lech'])}")
        return lines


def compare_file(path, tshark=None, limit=None) -> CompareReport:
    """Đối chiếu từng packet của một file với tshark."""
    report = CompareReport(path)
    cmd = tshark_command(find_tshark(tshark), path)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace")
    try:
        with PcapReader(path) as reader:
            for pkt in reader:
                line = proc.stdout.readline()
                if not line:
                    raise RuntimeError(f"tshark dừng sớm ở packet {pkt.index + 1}")
                report.add(pkt, inspect_packet(pkt), expected_from_tshark(line))
                if limit and report.total >= limit:
                    break
            else:
                if proc.stdout.readline():
                    raise RuntimeError("tshark có nhiều packet hơn bộ đọc PCAP")
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stderr.close()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Đối chiếu kết quả đọc packet với Wireshark (tshark).")
    parser.add_argument("files", nargs="+", help="file .pcap hoặc .pcapng")
    parser.add_argument("--tshark", help="đường dẫn tshark (mặc định: tìm trong PATH)")
    parser.add_argument("--limit", type=int, help="chỉ so N packet đầu của mỗi file")
    parser.add_argument("--report", help="ghi kết quả ra file JSON")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    reports = [compare_file(f, args.tshark, args.limit) for f in args.files]
    for r in reports:
        print("\n".join(r.summary_lines()))
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump([r.as_dict() for r in reports], f, ensure_ascii=False, indent=2)
        print(f"Đã ghi kết quả: {args.report}")
    return 1 if any(r.mismatch_count for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())

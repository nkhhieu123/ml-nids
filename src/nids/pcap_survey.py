"""Khảo sát một file PCAP/PCAPNG lớn: mã băm, thời gian, gói bỏ qua, flow, host.

Dùng khi nhận một bản thu mới (CIC-IDS2017, lab) để ghi vào manifest và kiểm
tra các giả định về dữ liệu, ví dụ địa chỉ bên tấn công và khung giờ tấn công.
Đọc tuần tự, không giữ gói hay flow trong bộ nhớ nên chạy được với file nhiều GB.

    python -m nids.pcap_survey data/pcap/cic-ids2017/Friday-WorkingHours.pcap \\
        --pair 172.16.0.1:192.168.10.50 --report output/survey_friday.json
"""

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .config import load_config
from .flows import FlowAssigner, FlowSettings
from .packets import PROTO_TCP, TCP_ACK, TCP_SYN, ParseStats, extract_packets
from .pcap_reader import PcapReader

HASH_CHUNK = 8 * 1024 * 1024
TOP_HOSTS = 15


def file_hashes(path) -> dict:
    """SHA-256 và MD5 của cả file (MD5 để so với mã băm nhà cung cấp nếu có)."""
    sha, md5 = hashlib.sha256(), hashlib.md5()
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(HASH_CHUNK):
            sha.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return {"kich_thuoc_byte": size, "sha256": sha.hexdigest(), "md5": md5.hexdigest()}


def _utc(ts_ns):
    if ts_ns is None:
        return None
    return datetime.fromtimestamp(ts_ns / 1e9, timezone.utc).isoformat(timespec="microseconds")


def _parse_pair(text):
    src, sep, dst = text.partition(":")
    if not sep or not src or not dst:
        raise argparse.ArgumentTypeError(f"cặp phải có dạng IP_NGUON:IP_DICH, nhận {text!r}")
    return src, dst


class PairActivity:
    """Theo dõi gói từ ``src`` tới ``dst`` theo từng phút (UTC)."""

    def __init__(self, src, dst):
        self.src, self.dst = src, dst
        self.packets = Counter()            # phút -> số gói
        self.syn = Counter()                # phút -> số SYN không ACK
        self.ports = defaultdict(set)       # phút -> các cổng đích khác nhau

    def add(self, rec):
        if rec.src_ip != self.src or rec.dst_ip != self.dst or rec.ts_ns is None:
            return
        minute = rec.ts_ns // (60 * 10**9)
        self.packets[minute] += 1
        if rec.protocol == PROTO_TCP and rec.tcp_flags is not None \
                and rec.tcp_flags & TCP_SYN and not rec.tcp_flags & TCP_ACK:
            self.syn[minute] += 1
        if rec.dst_port is not None:
            self.ports[minute].add(rec.dst_port)

    def as_dict(self) -> dict:
        rows = []
        for minute in sorted(self.packets):
            rows.append({
                "phut_utc": _utc(minute * 60 * 10**9)[:16],
                "goi": self.packets[minute],
                "syn": self.syn[minute],
                "so_cong_dich": len(self.ports[minute]),
            })
        return {"nguon": self.src, "dich": self.dst, "tong_goi": sum(self.packets.values()),
                "theo_phut": rows}


def survey(path, settings: FlowSettings, pairs=(), with_hash=True) -> dict:
    """Khảo sát một file; trả về dict có thể ghi ra JSON."""
    result = {"file": str(path)}
    if with_hash:
        result.update(file_hashes(path))
    with PcapReader(path) as reader:
        # Giao diện của PCAPNG chỉ biết sau khi đọc block mô tả, nên đọc thử một gói.
        next(iter(reader), None)
        result.update({
            "dinh_dang": reader.format,
            "phien_ban": list(reader.version or ()),
            "giao_dien": [{"linktype": i.linktype, "snaplen": i.snaplen}
                          for i in reader.interfaces],
        })
    stats = ParseStats()
    assigner = FlowAssigner(settings, keep_finished=False)
    watch = [PairActivity(src, dst) for src, dst in pairs]
    src_packets, dst_packets = Counter(), Counter()
    per_hour = Counter()
    first_ts = last_ts = None
    for rec in extract_packets(path, stats):
        assigner.add(rec)
        assigner.pop_finished()
        src_packets[rec.src_ip] += 1
        dst_packets[rec.dst_ip] += 1
        if rec.ts_ns is not None:
            first_ts = rec.ts_ns if first_ts is None else min(first_ts, rec.ts_ns)
            last_ts = rec.ts_ns if last_ts is None else max(last_ts, rec.ts_ns)
            per_hour[_utc(rec.ts_ns)[:13]] += 1
        for w in watch:
            w.add(rec)
    assigner.finish_all()
    assigner.pop_finished()
    result.update({
        "goi_dau_utc": _utc(first_ts),
        "goi_cuoi_utc": _utc(last_ts),
        "thoi_luong_s": None if first_ts is None else round((last_ts - first_ts) / 1e9, 3),
        "goi_theo_gio_utc": dict(sorted(per_hour.items())),
        "nguon_nhieu_goi_nhat": src_packets.most_common(TOP_HOSTS),
        "dich_nhieu_goi_nhat": dst_packets.most_common(TOP_HOSTS),
        "packet": stats.as_dict(),
        "flow": assigner.summary(),
        "cap_theo_doi": [w.as_dict() for w in watch],
    })
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Khảo sát một file PCAP/PCAPNG lớn.")
    parser.add_argument("file")
    parser.add_argument("--pair", action="append", type=_parse_pair, default=[],
                        help="theo dõi gói IP_NGUON:IP_DICH theo từng phút; lặp lại được")
    parser.add_argument("--no-hash", action="store_true", help="không tính mã băm")
    parser.add_argument("--report", help="ghi kết quả ra file JSON")
    parser.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    args = parser.parse_args(argv)

    settings = FlowSettings.from_config(load_config(args.config))
    result = survey(args.file, settings, args.pair, with_hash=not args.no_hash)
    p, f = result["packet"], result["flow"]
    print(f"{args.file}: {p['tong_packet']} packet, giữ {p['giu_lai']}, bỏ qua {p['bo_qua']}")
    if "sha256" in result:
        print(f"  {result['kich_thuoc_byte']} byte; SHA-256 {result['sha256']}")
    print(f"  {result['goi_dau_utc']} → {result['goi_cuoi_utc']} UTC ({result['thoi_luong_s']} giây)")
    print(f"  {f['so_flow']} flow; kết thúc: {f['flow_theo_ly_do_ket_thuc']}")
    if p["loi_file"]:
        print(f"  Lỗi file: {p['loi_file']}")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as out:
            json.dump(result, out, ensure_ascii=False, indent=2)
        print(f"Đã ghi kết quả: {args.report}")
    return 1 if p["loi_file"] else 0


if __name__ == "__main__":
    sys.exit(main())

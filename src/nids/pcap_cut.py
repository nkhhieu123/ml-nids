"""Cắt một đoạn thời gian của PCAP/PCAPNG ra file PCAP nhỏ (C09-T02).

Dùng bộ đọc của dự án (``nids.pcap_reader``), giữ gói có thời điểm trong ``[bat_dau, ket_thuc)``
(giây UTC) và ghi ra PCAP thường với dấu thời gian nano giây (magic 0xA1B23C4D), giữ nguyên byte
gói và kiểu liên kết. Đọc dừng khi gặp gói muộn hơn ``ket_thuc`` quá ``--du`` giây (file bắt theo
thời gian, cho phép vài gói lệch thứ tự).

    python -m nids.pcap_cut data/pcap/cic-ids2017/Friday-WorkingHours.pcap output/pcap/fri_scan.pcap \\
        --bat-dau "2017-07-07 14:45" --ket-thuc "2017-07-07 15:05" --utc-offset -3
"""

import argparse
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .pcap_reader import read_packets

MAGIC_NS = 0xA1B23C4D


def parse_time(text, utc_offset_h=0.0) -> float:
    """Chuỗi ``YYYY-MM-DD HH:MM[:SS]`` theo giờ địa phương (lệch ``utc_offset_h`` giờ so với UTC) → giây UTC."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            local = datetime.strptime(text, fmt)
            break
        except ValueError:
            continue
    else:
        raise ValueError(f"không đọc được thời điểm: {text!r}")
    tz = timezone(timedelta(hours=utc_offset_h))
    return local.replace(tzinfo=tz).timestamp()


def cut(src, dst, start_s, end_s, slack_s=60.0) -> dict:
    """Ghi gói trong ``[start_s, end_s)`` ra ``dst``; trả về số gói đọc, ghi và khoảng thời gian thật."""
    start_ns, end_ns, slack_ns = int(start_s * 1e9), int(end_s * 1e9), int(slack_s * 1e9)
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    read = written = 0
    first = last = None
    linktype = None
    with open(dst, "wb") as out:
        for p in read_packets(src):
            read += 1
            if p.ts_ns is None:
                continue
            if p.ts_ns >= end_ns + slack_ns:
                break
            if not start_ns <= p.ts_ns < end_ns:
                continue
            if linktype is None:
                linktype = p.linktype
                out.write(struct.pack("<IHHiIII", MAGIC_NS, 2, 4, 0, 0, 262144, linktype))
            elif p.linktype != linktype:
                continue                                  # PCAP thường chỉ có một kiểu liên kết
            sec, ns = divmod(p.ts_ns, 10**9)
            out.write(struct.pack("<IIII", sec, ns, p.caplen, p.origlen))
            out.write(p.data)
            written += 1
            first = p.ts_ns if first is None else min(first, p.ts_ns)
            last = p.ts_ns if last is None else max(last, p.ts_ns)
        if linktype is None:                              # không có gói nào: vẫn ghi header hợp lệ
            out.write(struct.pack("<IHHiIII", MAGIC_NS, 2, 4, 0, 0, 262144, 1))
    return {"goi_doc": read, "goi_ghi": written, "dau": None if first is None else first / 1e9,
            "cuoi": None if last is None else last / 1e9, "file": str(dst)}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Cắt một đoạn thời gian của PCAP.")
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--bat-dau", required=True, help='"YYYY-MM-DD HH:MM[:SS]" giờ địa phương')
    ap.add_argument("--ket-thuc", required=True)
    ap.add_argument("--utc-offset", type=float, default=0.0, help="giờ địa phương lệch UTC (CIC: -3)")
    ap.add_argument("--du", type=float, default=60.0, help="giây đọc thêm sau ket-thuc rồi dừng")
    a = ap.parse_args(argv)
    r = cut(a.src, a.dst, parse_time(a.bat_dau, a.utc_offset), parse_time(a.ket_thuc, a.utc_offset), a.du)
    print(f"Đọc {r['goi_doc']} gói, ghi {r['goi_ghi']} gói vào {r['file']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

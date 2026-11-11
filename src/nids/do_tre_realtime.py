"""Chặng 11 — độ trễ phát hiện của cảm biến realtime, đo bằng phát lại PCAP đúng nhịp lúc bắt (C11-T08).

``nids.thuc_nghiem`` tính độ trễ từ cuối cửa sổ của cảnh báo đầu tiên (đã gồm thời gian tích lũy cửa sổ).
Cảm biến realtime còn phát cảnh báo muộn hơn cuối cửa sổ: chờ quan sát bắt tay, chờ cửa sổ đóng, thời gian
chấm. Ở đây phát lại PCAP với tốc độ 1× qua đúng bộ máy realtime (``RealtimeEngine`` + ``ThreadedRunner``),
ghi giờ thật lúc từng cảnh báo được phát (``created_at``) rồi quy về trục thời gian của bản thu:

    thời điểm phát (theo bản thu) = giờ gói đầu + (created_at − giờ thật lúc phát lại gói đầu) × tốc độ
    độ trễ realtime               = thời điểm phát − thời điểm bắt đầu đợt tấn công (nhật ký lần chạy)

    cd src
    python -m nids.do_tre_realtime ../data/pcap/lab/k3-dos-muc2-test-01.pcap --nhat-ky ../data/run_logs \
        --out ../docs/hinh/thuc_nghiem/lab/realtime
"""

import argparse
import json
import sys
import time
from pathlib import Path

from .nguon_goi import PcapReplaySource
from .thuc_nghiem import DETECT, attacks_from_runlog, load_runlog


class TimedReplay(PcapReplaySource):
    """Phát lại theo nhịp, nhớ giờ của gói đầu trong bản thu và giờ thật lúc gói đó được phát."""

    first = None

    def __iter__(self):
        for pkt in super().__iter__():
            if self.first is None and pkt.ts_ns is not None:
                self.first = (pkt.ts_ns / 1e9, time.time())
            yield pkt


class Collect:
    def __init__(self):
        self.alerts = []

    def emit(self, alert):
        self.alerts.append(alert)
        return True


def realtime_latency(attacks, alerts, first_ts, wall0, speed=1.0) -> list:
    """Với mỗi đợt: cảnh báo đúng loại được phát sớm nhất, quy về trục thời gian bản thu."""
    emitted = lambda al: first_ts + (al.created_at - wall0) * speed
    rows = []
    for a in attacks:
        mod, labels = DETECT[a.loai]
        hits = [al for al in alerts if al.is_alert and al.module == mod and al.label in labels
                and al.src_ip in a.hosts and al.window_end > a.t0 and al.window_start < a.t1]
        row = {"kich_ban": a.kich_ban, "loai": a.loai, "phat_hien": bool(hits), "so_canh_bao": len(hits)}
        if hits:
            first = min(hits, key=emitted)
            row.update(do_tre_realtime_s=round(emitted(first) - a.t0, 1),
                       do_tre_cuoi_cua_so_s=round(first.window_end - a.t0, 1),
                       cho_sau_cua_so_s=round(emitted(first) - first.window_end, 1), host=first.src_ip)
        rows.append(row)
    return rows


def measure(pcap, networks, runlog, cfg, mode="ket_hop", speed=1.0) -> dict:
    from .realtime import RealtimeEngine, ThreadedRunner, realtime_config

    rt = realtime_config(cfg)
    sink = Collect()
    source = TimedReplay(str(pcap), speed)
    engine = RealtimeEngine(cfg, networks, mode=mode, run_id=Path(pcap).stem, alert_sink=sink)
    runner = ThreadedRunner(source, engine, rt["queue_size"], rt["tick_s"], speed)
    t = time.perf_counter()
    n = runner.run()
    first_ts, wall0 = source.first
    rows = realtime_latency(attacks_from_runlog(runlog, networks), sink.alerts, first_ts, wall0, speed)
    return {"pcap": Path(pcap).name, "che_do": mode, "toc_do": speed, "goi": n, "goi_hang_doi_bo": runner.dropped,
            "thoi_gian_phat_lai_s": round(time.perf_counter() - t, 1), "so_canh_bao": len(sink.alerts),
            "theo_dot": rows}


def main(argv=None):
    from .config import load_config

    ap = argparse.ArgumentParser(description="Chặng 11: độ trễ phát hiện realtime bằng phát lại PCAP đúng nhịp.")
    ap.add_argument("pcap")
    ap.add_argument("--net", action="append", help="mạng giám sát; mặc định lab.subnet")
    ap.add_argument("--nhat-ky", required=True, help="thư mục nhật ký lần chạy, hoặc file .json/.jsonl")
    ap.add_argument("--che-do", default="ket_hop", choices=("doc_lap", "tuan_tu", "ket_hop"))
    ap.add_argument("--toc-do", type=float, default=1.0, help="1 là đúng nhịp lúc bắt")
    ap.add_argument("--out", help="thư mục ghi <tên PCAP>.json")
    ap.add_argument("--config")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    res = measure(a.pcap, a.net or [cfg["lab"]["subnet"]], load_runlog(a.nhat_ky, a.pcap), cfg, a.che_do, a.toc_do)
    print(json.dumps(res, ensure_ascii=False))
    if a.out:
        od = Path(a.out)
        od.mkdir(parents=True, exist_ok=True)
        (od / f"{Path(a.pcap).stem}.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

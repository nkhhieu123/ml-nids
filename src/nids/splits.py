"""Chia train/validation/test theo thời gian trong từng phiên và khối tấn công (C05-T04).

Mỗi phiên (một file PCAP, ví dụ một ngày CIC) được cắt thành các đoạn liền nhau:
- mỗi khối tấn công (cột ``khoi`` của lịch nhãn) cắt thành train, validation, test
  sao cho mỗi phần có 60/20/20 số flow bắt đầu trong khối (ranh giới ở phân vị của
  thời điểm bắt đầu flow), theo đúng thứ tự thời gian;
- mỗi khoảng không có khối tấn công cũng cắt như vậy.
Mẫu (flow hoặc cửa sổ) phải nằm trọn trong một đoạn, cách ranh giới ít nhất
``embargo_s``; mẫu vắt qua ranh giới hoặc nằm trong vùng đệm bị bỏ (``bo``).
Chi tiết ở docs/29_chia_du_lieu.md (QĐ-027).

    python -m nids.splits output/features/cic17_wednesday.flows.csv
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from .config import load_config
from .labeling import labels_path, load_schedule

SPLITS = ("train", "validation", "test")
DROPPED = "bo"
MIN_SAMPLES_FOR_QUANTILE = 20   # khoảng có ít flow hơn thì cắt theo thời gian


def build_segments(t_min, t_max, rules, ratios, sample_times=None) -> list[tuple[float, float, str]]:
    """Các đoạn (đầu, cuối, tập) phủ [t_min, t_max] của một phiên, theo thứ tự thời gian.

    ``sample_times``: thời điểm bắt đầu các mẫu (đã sắp xếp). Có thì ranh giới trong mỗi
    khoảng đặt ở phân vị của chúng để số mẫu theo đúng tỷ lệ; không có (hoặc khoảng có
    quá ít mẫu) thì chia theo thời gian.
    """
    blocks = {}
    for r in rules:
        if r.block and r.end_s > t_min and r.start_s < t_max:
            s, e = blocks.get(r.block, (r.start_s, r.end_s))
            blocks[r.block] = (min(s, r.start_s), max(e, r.end_s))
    spans = []
    cursor = t_min
    for s, e in sorted(blocks.values()):
        s, e = max(s, t_min), min(e, t_max)
        if s > cursor:
            spans.append((cursor, s))
        spans.append((max(s, cursor), e))
        cursor = max(cursor, e)
    if cursor < t_max:
        spans.append((cursor, t_max))
    bounds = np.cumsum([0.0] + list(ratios))
    segments = []
    for s, e in spans:
        if e <= s:
            continue
        cuts = [s + a * (e - s) for a in bounds]
        if sample_times is not None:
            lo, hi = np.searchsorted(sample_times, [s, e], "left")
            inside = sample_times[lo:hi]
            if len(inside) >= MIN_SAMPLES_FOR_QUANTILE:
                cuts = [s] + [float(np.quantile(inside, a)) for a in bounds[1:-1]] + [e]
        for name, a, b in zip(SPLITS, cuts[:-1], cuts[1:]):
            segments.append((a, b, name))
    return segments


def assign(first, last, segments, embargo_s) -> np.ndarray:
    """Tập của từng mẫu [first, last]; ``bo`` nếu vắt qua ranh giới hoặc trong vùng đệm."""
    out = np.full(len(first), DROPPED, dtype=object)
    first = np.asarray(first, dtype=float)
    last = np.asarray(last, dtype=float)
    n = len(segments)
    for i, (s, e, name) in enumerate(segments):
        # Vùng đệm chỉ đặt ở ranh giới giữa hai đoạn khác tập.
        lo = s + (embargo_s if i > 0 and segments[i - 1][2] != name else 0)
        hi = e - (embargo_s if i < n - 1 and segments[i + 1][2] != name else 0)
        inside = (first >= lo) & (last < hi) if i < n - 1 else (first >= lo) & (last <= hi)
        out[inside] = name
    return out


def split_tables(flows_path, rules, ratios, embargo_s) -> dict:
    """Ghi ``<tên>.flows.split.csv`` và ``<tên>.windows.split.csv``; trả về tóm tắt."""
    flows = pd.read_csv(flows_path, usecols=["first_index", "first_ts", "last_ts"])
    win_path = Path(str(flows_path)[:-len(".flows.csv")] + ".windows.csv")
    windows = pd.read_csv(win_path, usecols=["host", "window_start", "window_end"],
                          dtype={"host": str}) if win_path.exists() else None
    t_min = flows["first_ts"].min()
    t_max = flows["last_ts"].max()
    if windows is not None:
        t_min = min(t_min, windows["window_start"].min())
        t_max = max(t_max, windows["window_end"].max())
    segments = build_segments(t_min, t_max, rules, ratios, np.sort(flows["first_ts"].to_numpy()))
    summary = {"doan": [{"tu": s, "den": e, "tap": n} for s, e, n in segments]}

    flows["split"] = assign(flows["first_ts"], flows["last_ts"], segments, embargo_s)
    flows[["first_index", "split"]].to_csv(labels_path(flows_path, "split"), index=False)
    summary["flows"] = flows["split"].value_counts().to_dict()
    if windows is not None:
        # Cửa sổ là [start, end): coi end là điểm cuối, nên cửa sổ kết thúc đúng ranh giới vẫn ở trong.
        end = windows["window_end"] - 1e-9
        windows["split"] = assign(windows["window_start"], end, segments, embargo_s)
        windows[["host", "window_start", "split"]].to_csv(labels_path(win_path, "split"), index=False)
        summary["windows"] = windows["split"].value_counts().to_dict()
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description="Chia train/validation/test theo thời gian.")
    parser.add_argument("flows", nargs="+", help="file <tên>.flows.csv")
    parser.add_argument("--schedule", help="lịch tấn công, mặc định config/label_schedule.csv")
    parser.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    args = parser.parse_args(argv)
    cfg = load_config(args.config)["split"]
    ratios = (cfg["train"], cfg["validation"], cfg["test"])
    rules = load_schedule(args.schedule)
    for path in args.flows:
        s = split_tables(path, rules, ratios, cfg["embargo_s"])
        print(f"{path}: {len(s['doan'])} đoạn; flow {s['flows']}; cửa sổ {s.get('windows')}")
        out = labels_path(path, "split").with_suffix(".json")
        out.write_text(json.dumps(s, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Ghép dòng access log với flow, và đo dung sai thời gian cần cho việc ghép (docs/05 mục 2, QĐ-067).

Một dòng log khớp một flow TCP khi:

- một đầu của flow là (IP client, cổng client) của dòng log, đầu kia dùng cổng máy chủ của dòng log;
- thời điểm ghi log (`$msec`, lúc yêu cầu kết thúc) nằm trong khoảng sống của flow, nới thêm mỗi đầu một
  **dung sai** để bù làm tròn mili giây và độ lệch đồng hồ giữa máy chủ dịch vụ và máy giám sát.

Cùng (IP, cổng client) có thể xuất hiện ở nhiều flow (hệ điều hành dùng lại cổng nguồn); khi đó lấy flow gần
thời điểm ghi log nhất. ``khoang_cach_s`` của một dòng là khoảng thời điểm ghi log nằm ngoài flow gần nhất (0
khi nằm trong): dung sai nhỏ nhất để dòng đó ghép được.

    cd src
    python -m nids.log_flow ../data/pcap/lab/k*.pcap --log-dir ../data/service_logs --out ../docs/hinh
"""

import argparse
import json
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

import pandas as pd

from .config import load_config
from .service_log import read_log

TOLERANCES = (0.0, 0.001, 0.01, 0.1, 1.0, 5.0, 60.0)
PROTO_TCP = 6


def load_flow_table(path) -> pd.DataFrame:
    return pd.read_csv(path, usecols=["first_index", "first_ts", "last_ts", "protocol", "fwd_ip", "fwd_port",
                                      "bwd_ip", "bwd_port"], dtype={"fwd_ip": str, "bwd_ip": str})


def flow_index(flows: pd.DataFrame) -> dict:
    """(ip client, cổng client, cổng máy chủ) -> danh sách (first_ts, last_ts, first_index); cả hai chiều của flow."""
    index = defaultdict(list)
    tcp = flows[flows["protocol"] == PROTO_TCP]
    cols = ["first_ts", "last_ts", "first_index", "fwd_ip", "fwd_port", "bwd_ip", "bwd_port"]
    for first, last, key, a_ip, a_port, b_ip, b_port in tcp[cols].itertuples(index=False, name=None):
        if pd.isna(a_port) or pd.isna(b_port):
            continue
        index[(a_ip, int(a_port), int(b_port))].append((first, last, int(key)))
        index[(b_ip, int(b_port), int(a_port))].append((first, last, int(key)))
    return index


def match(records, index) -> list:
    """Mỗi dòng log: flow gần nhất cùng (IP, cổng client, cổng máy chủ) và khoảng cách thời gian tới nó."""
    rows = []
    for r in records:
        cands = index.get((r.client_ip, r.client_port, r.server_port), [])
        best = None
        for first, last, key in cands:
            gap = max(first - r.ts, r.ts - last, 0.0)
            if best is None or gap < best[0]:
                best = (gap, key, r.ts - first, last - r.ts)
        rows.append({"line_no": r.line_no, "ts": r.ts, "so_ung_vien": len(cands),
                     "khoang_cach_s": None if best is None else best[0],
                     "first_index": None if best is None else best[1],
                     "sau_dau_flow_s": None if best is None else best[2],
                     "truoc_cuoi_flow_s": None if best is None else best[3],
                     "_cands": cands})
    return rows


def ambiguous(row, tol) -> bool:
    """Có hơn một flow chứa thời điểm ghi log khi nới ``tol``: ghép không còn duy nhất."""
    return sum(max(f - row["ts"], row["ts"] - l, 0.0) <= tol for f, l, _ in row["_cands"]) > 1


def summarize(rows, tolerances=TOLERANCES) -> dict:
    n = len(rows)
    gaps = sorted(r["khoang_cach_s"] for r in rows if r["khoang_cach_s"] is not None)
    out = {"so_dong": n, "khong_co_flow_cung_cong": sum(r["so_ung_vien"] == 0 for r in rows),
           "khoang_cach_lon_nhat_s": round(gaps[-1], 6) if gaps else None,
           "khoang_cach_p99_s": round(gaps[min(len(gaps) - 1, int(0.99 * len(gaps)))], 6) if gaps else None,
           "theo_dung_sai": []}
    inside = [r for r in rows if r["khoang_cach_s"] == 0]
    if inside:
        after = sorted(r["sau_dau_flow_s"] for r in inside)
        before = sorted(r["truoc_cuoi_flow_s"] for r in inside)
        mid = lambda v: round(v[len(v) // 2], 6)
        out["trong_flow"] = {"so_dong": len(inside), "sau_dau_flow_trung_vi_s": mid(after),
                             "truoc_cuoi_flow_trung_vi_s": mid(before), "truoc_cuoi_flow_nho_nhat_s": round(before[0], 6)}
    for tol in tolerances:
        ok = sum(r["khoang_cach_s"] is not None and r["khoang_cach_s"] <= tol for r in rows)
        amb = sum(ambiguous(r, tol) for r in rows)
        out["theo_dung_sai"].append({"dung_sai_s": tol, "ghep_duoc": ok, "ty_le": round(ok / n, 6) if n else None,
                                     "khong_duy_nhat": amb})
    return out


def join(log_path, flows: pd.DataFrame) -> list:
    return match(list(read_log(log_path)), flow_index(flows))


def main(argv=None):
    from .pipeline import extract

    ap = argparse.ArgumentParser(description="Ghép access log với flow và đo dung sai thời gian cần thiết.")
    ap.add_argument("pcap", nargs="+", help="PCAP của lần chạy; log lấy ở <log-dir>/<tên PCAP>/access_nids.log")
    ap.add_argument("--log-dir", required=True)
    ap.add_argument("--net", action="append", help="mạng giám sát; mặc định lab.subnet")
    ap.add_argument("--out", required=True, help="thư mục ghi log_flow.json")
    a = ap.parse_args(argv)
    cfg = load_config()
    nets = a.net or [cfg["lab"]["subnet"]]
    all_rows, per_run = [], {}
    for p in a.pcap:
        log = Path(a.log_dir) / Path(p).stem / "access_nids.log"
        if not log.exists():
            continue
        with tempfile.TemporaryDirectory() as d:
            flows = load_flow_table(f"{extract(p, d, nets)}.flows.csv")
        rows = join(log, flows)
        s = summarize(rows, (cfg["service_log"]["match_tolerance_s"],))
        port80 = flows[(flows["protocol"] == PROTO_TCP) & ((flows["bwd_port"] == 80) | (flows["fwd_port"] == 80))]
        matched = {r["first_index"] for r in rows if r["khoang_cach_s"] is not None}
        per_run[Path(p).stem] = {"dong_log": len(rows), "ghep_duoc": s["theo_dung_sai"][0]["ghep_duoc"],
                                 "khoang_cach_lon_nhat_s": s["khoang_cach_lon_nhat_s"],
                                 "flow_cong_80": len(port80),
                                 "flow_cong_80_khong_co_dong_log": int((~port80["first_index"].isin(matched)).sum())}
        all_rows += rows
    out = {"dung_sai_da_chot_s": cfg["service_log"]["match_tolerance_s"], "so_lan_chay": len(per_run),
           "tong": summarize(all_rows), "theo_lan_chay": per_run}
    od = Path(a.out)
    od.mkdir(parents=True, exist_ok=True)
    (od / "log_flow.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(out["tong"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

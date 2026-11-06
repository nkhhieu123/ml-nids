"""Kiểm tra tính nhất quán offline/realtime trên cùng một PCAP (C10-T08).

Chạy PCAP qua pipeline offline (``nids.pipeline``, Chặng 9) và qua bộ máy realtime (``nids.realtime``,
phát lại nhanh nhất có thể, một luồng để kết quả xác định), cùng mô hình, cùng chế độ; rồi so:

- cửa sổ 10 giây: cùng tập (host, window_start) và cùng giá trị từng đặc trưng;
- anomaly: d² và nhãn; phân loại: nhãn và xác suất;
- botnet: host–cửa sổ 120 giây được chấm, điểm, nhãn, topology;
- cảnh báo theo module và nhãn; số sự kiện.

    python -m nids.nhat_quan output/pcap/wed_slowloris.pcap --net 192.168.10.0/24 --net 172.16.0.0/24 \\
        --bang output/nhat_quan --out docs/hinh/nhat_quan.json

Chi tiết ở docs/66_nhat_quan_offline_realtime.md (QĐ-056).
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from .scope import MODULE_ANOMALY, MODULE_ATTACK, MODULE_BOTNET

KEY = ["host", "window_start"]


def _key(df) -> pd.DataFrame:
    out = df.copy()
    out["host"] = out["host"].astype(str)
    out["window_start"] = out["window_start"].astype(float).round(6)
    return out


def compare_windows(off, rt, features) -> dict:
    """Cùng tập cửa sổ? Lệch lớn nhất của từng đặc trưng trên các cửa sổ chung (NaN coi như bằng nhau)."""
    a, b = _key(off), _key(rt)
    m = a.merge(b, on=KEY, how="outer", suffixes=("_off", "_rt"), indicator=True)
    both = m[m["_merge"] == "both"]
    diffs = {}
    for f in features:
        x, y = both[f + "_off"].astype(float), both[f + "_rt"].astype(float)
        same_nan = x.isna() & y.isna()
        d = (x - y).abs().where(~same_nan, 0.0)
        diffs[f] = float(d.fillna(np.inf).max()) if len(d) else 0.0
    return {"offline": len(a), "realtime": len(b), "chung": int(len(both)),
            "chi_offline": int((m["_merge"] == "left_only").sum()), "chi_realtime": int((m["_merge"] == "right_only").sum()),
            "dac_trung_lech_lon_nhat": max(diffs.values()) if diffs else 0.0,
            "dac_trung_lech": {k: v for k, v in diffs.items() if v > 1e-9}}


def compare_predictions(off, rt, label_col="du_doan", score_col=None) -> dict:
    a, b = _key(off), _key(rt)
    m = a.merge(b, on=KEY, how="outer", suffixes=("_off", "_rt"), indicator=True)
    both = m[m["_merge"] == "both"]
    out = {"offline": len(a), "realtime": len(b), "chung": int(len(both)),
           "chi_offline": int((m["_merge"] == "left_only").sum()), "chi_realtime": int((m["_merge"] == "right_only").sum()),
           "nhan_khop": round(float((both[label_col + "_off"] == both[label_col + "_rt"]).mean()), 6) if len(both) else None,
           "nhan_khac": int((both[label_col + "_off"] != both[label_col + "_rt"]).sum())}
    if score_col and len(both):
        d = (both[score_col + "_off"].astype(float) - both[score_col + "_rt"].astype(float)).abs()
        out["diem_lech_lon_nhat"] = float(d.max())
        out["diem_lech_trung_binh"] = float(d.mean())
    return out


def realtime_frames(pcap, networks, cfg, mode, arts):
    """Chạy bộ máy realtime một luồng trên PCAP; trả bảng cửa sổ, dự đoán từng module, cảnh báo, sự kiện."""
    from .nguon_goi import PcapReplaySource
    from .realtime import RealtimeEngine, run

    windows, scores, events = [], [], []
    from types import SimpleNamespace
    eng = RealtimeEngine(cfg, networks, arts=arts, mode=mode, run_id="nhat_quan",
                         score_sink=SimpleNamespace(emit=scores.append), event_sink=events.append,
                         window_sink=windows.append)
    run(PcapReplaySource(pcap), eng)
    return (pd.concat(windows, ignore_index=True) if windows else pd.DataFrame()), scores, events, eng


def alerts_to_frames(alerts) -> dict:
    """Danh sách Alert (log_all) → bảng dự đoán từng module, dạng gần giống bảng của pipeline offline."""
    rows = {MODULE_ANOMALY: [], MODULE_ATTACK: [], MODULE_BOTNET: []}
    topo = {}
    for a in alerts:
        r = {"host": a.src_ip, "window_start": a.window_start, "du_doan": a.label, "diem": a.score}
        if a.module == MODULE_BOTNET and a.label in ("centralized", "p2p"):
            topo[(a.src_ip, round(a.window_start, 6))] = a.label
            continue
        rows[a.module].append(r)
    out = {m: pd.DataFrame(v, columns=["host", "window_start", "du_doan", "diem"]) for m, v in rows.items()}
    bo = out[MODULE_BOTNET]
    bo["topology"] = [topo.get((h, round(w, 6)), "none") for h, w in zip(bo["host"], bo["window_start"])]
    return out


def check(pcap, networks, out_dir, cfg, mode=None) -> dict:
    from .dataset import feature_columns
    from .pipeline import (load_artifacts, merge_events, pipeline_config, run_alerts, run_pcap)
    from .realtime import single_thread

    mode = mode or pipeline_config(cfg)["mode"]
    arts = load_artifacts(cfg)
    for art in arts.values():
        single_thread(art.model)                      # cùng mô hình, cùng cách chạy cho cả hai bên
    off = run_pcap(pcap, out_dir, networks, cfg, None, mode, Path(pcap).stem + "_offline")
    from .pipeline import load_windows
    off_windows = load_windows(off["prefix"])
    rt_windows, scores, rt_events, eng = realtime_frames(pcap, networks, cfg, mode, arts)
    rt = alerts_to_frames(scores)
    off_res = off["ket_qua"]
    an_off = off_res[MODULE_ANOMALY].rename(columns={"d2": "diem"})
    at_off = off_res[MODULE_ATTACK].assign(diem=lambda d: d[[c for c in d.columns if c.startswith("p_")]].max(axis=1))
    bo_off = off_res[MODULE_BOTNET]
    feats = feature_columns("windows")
    res = {"pcap": str(pcap), "che_do": mode,
           "cua_so_10s": compare_windows(off_windows[KEY + feats], rt_windows[KEY + feats], feats),
           MODULE_ANOMALY: compare_predictions(an_off, rt[MODULE_ANOMALY], score_col="diem"),
           MODULE_ATTACK: compare_predictions(at_off, rt[MODULE_ATTACK], score_col="diem"),
           MODULE_BOTNET: compare_predictions(bo_off, rt[MODULE_BOTNET], score_col="diem"),
           "topology": compare_predictions(bo_off.assign(t=bo_off["topology"]).drop(columns="du_doan")
                                           .rename(columns={"t": "du_doan"}),
                                           rt[MODULE_BOTNET].drop(columns="du_doan").rename(columns={"topology": "du_doan"}))}
    off_alerts = run_alerts(off, arts, "x")
    res["canh_bao"] = {"offline": dict(Counter(f"{a.module}:{a.label}" for a in off_alerts)),
                       "realtime": dict(Counter(f"{a.module}:{a.label}" for a in scores if a.is_alert))}
    res["su_kien"] = {"offline": len(merge_events(off_alerts, pipeline_config(cfg)["merge_gap_s"])),
                      "realtime": len(rt_events)}
    return res


def main(argv=None):
    from .config import load_config

    ap = argparse.ArgumentParser(description="Kiểm tra nhất quán offline/realtime trên cùng PCAP.")
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--net", action="append", required=True)
    ap.add_argument("--bang", default="output/nhat_quan", help="thư mục ghi bảng của lượt offline")
    ap.add_argument("--che-do", choices=("doc_lap", "tuan_tu", "ket_hop"))
    ap.add_argument("--out", help="file JSON kết quả")
    ap.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    res = {}
    for p in a.pcap:
        r = check(p, a.net, a.bang, cfg, a.che_do)
        res[Path(p).stem] = r
        w = r["cua_so_10s"]
        print(f"{Path(p).stem}: cửa sổ 10 s {w['chung']}/{w['offline']} chung (chỉ offline {w['chi_offline']}, chỉ "
              f"realtime {w['chi_realtime']}), đặc trưng lệch tối đa {w['dac_trung_lech_lon_nhat']}")
        for m in (MODULE_ANOMALY, MODULE_ATTACK, MODULE_BOTNET, "topology"):
            print(f"   {m}: {r[m]}")
        print("   cảnh báo:", r["canh_bao"], "sự kiện:", r["su_kien"])
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

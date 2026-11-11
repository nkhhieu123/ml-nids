"""Độ nhạy của bộ phân loại với hai tham số gán nhãn: nới lịch (giây) và ngưỡng phần flow tấn công của cửa sổ.

QĐ-025 và QĐ-026 đặt tạm ``labeling.tolerance_s`` = 60 và ``labeling.window_min_attack_share`` = 0,2, hẹn chỉnh
trên validation. Ở đây mỗi lần đổi một tham số, gán nhãn lại trong bộ nhớ (không ghi đè file nhãn), giữ nguyên
cách chia train/validation/test và tham số Random Forest đã chọn ở C07-T04, fit lại trên train rồi đo trên
**validation**. Không đọc test.

Vì đổi tham số gán nhãn cũng đổi nhãn của validation, mỗi cấu hình được đo hai cách:

- ``rieng``: trên validation gán nhãn theo chính cấu hình đó;
- ``chuan``: trên validation gán nhãn theo cấu hình hiện tại (60 giây; 0,2), cố định cho mọi cấu hình.

    cd src
    python -m nids.do_nhay_nhan ../output/features/cic17_wednesday ../output/features/cic17_friday \
        --chon ../docs/hinh/phan_loai_chon.json --out ../docs/hinh
"""

import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd

from .classifier import LABEL_COL, AttackClassifier, classifier_config, load_data, multiclass_metrics, prepare_data
from .config import load_config
from .labeling import (WINDOW_KEY, WINDOW_LABEL_COLUMNS, label_flows, label_windows, load_flows_for_labels,
                       load_schedule, load_windows_for_labels)

TOLERANCES = (0, 30, 60, 120, 300)
SHARES = (0.05, 0.1, 0.2, 0.3, 0.5)


def relabel(df, sources, rules, tolerance_s, share) -> pd.DataFrame:
    """Bảng cửa sổ với nhãn gán lại theo (tolerance_s, share); giữ nguyên đặc trưng và cột chia tập."""
    parts = []
    for session, (flows, windows) in sources.items():
        wl = label_windows(windows, flows, label_flows(flows, rules, tolerance_s), share)
        part = df[df["session"] == session].drop(columns=[c for c in WINDOW_LABEL_COLUMNS if c in df.columns])
        parts.append(part.merge(wl, on=list(WINDOW_KEY), how="left", validate="one_to_one"))
    return pd.concat(parts, ignore_index=True)


def score(model, frame) -> dict:
    m = multiclass_metrics(frame[LABEL_COL], model.predict(frame))
    return {"macro_f1": round(m["macro_f1"], 4),
            **{f"{k}_{c}": round(m["theo_lop"][c][k], 4) for c in ("port_scan", "dos") for k in ("precision", "recall")}}


def run_one(df, sources, rules, tolerance_s, share, best, cfg, reference=None) -> dict:
    t = time.perf_counter()
    data = prepare_data(relabel(df, sources, rules, tolerance_s, share), best["ty_le_can_bang"],
                        cfg["random_seed"], cfg["drop_train_duplicates"])
    model = AttackClassifier("random_forest", best["tham_so"], cfg["random_seed"]).fit(data["train"], data["train_full"])
    row = {"tolerance_s": tolerance_s, "window_min_attack_share": share,
           "lop_train": data["info"]["lop_train"], "lop_validation": data["info"]["lop_validation"],
           "rieng": score(model, data["validation"])}
    ref = data["validation"] if reference is None else reference
    row["chuan"] = score(model, ref)
    row["giay"] = round(time.perf_counter() - t, 1)
    return row, data["validation"]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Độ nhạy của bộ phân loại với tham số gán nhãn, đo trên validation.")
    ap.add_argument("prefixes", nargs="+", help="tiền tố bảng đặc trưng, ví dụ ../output/features/cic17_wednesday")
    ap.add_argument("--chon", required=True, help="JSON của classifier chon (tham số Random Forest đã chọn)")
    ap.add_argument("--out", required=True, help="thư mục ghi nhan_do_nhay.json")
    ap.add_argument("--config")
    a = ap.parse_args(argv)
    cfg_all = load_config(a.config)
    cfg = classifier_config(cfg_all)
    lab = cfg_all["labeling"]
    base = (lab["tolerance_s"], lab["window_min_attack_share"])
    best = json.loads(Path(a.chon).read_text(encoding="utf-8"))["mo_hinh"]["random_forest"]["tot_nhat"]
    rules = load_schedule()
    df = load_data(a.prefixes, cfg["sessions"])
    sources = {}
    for p in a.prefixes:
        session = Path(p).name
        if session in set(df["session"]):
            sources[session] = (load_flows_for_labels(f"{p}.flows.csv"), load_windows_for_labels(f"{p}.windows.csv"))
    first, reference = run_one(df, sources, rules, *base, best, cfg)
    rows = [first]
    print(json.dumps(first, ensure_ascii=False))
    for tol in TOLERANCES:
        if tol != base[0]:
            rows.append(run_one(df, sources, rules, tol, base[1], best, cfg, reference)[0])
            print(json.dumps(rows[-1], ensure_ascii=False))
    for share in SHARES:
        if share != base[1]:
            rows.append(run_one(df, sources, rules, base[0], share, best, cfg, reference)[0])
            print(json.dumps(rows[-1], ensure_ascii=False))
    out = {"hien_tai": {"tolerance_s": base[0], "window_min_attack_share": base[1]},
           "mo_hinh": {"loai": "random_forest", "tham_so": best["tham_so"], "ty_le_can_bang": best["ty_le_can_bang"]},
           "macro_f1_validation_luc_chon": best["macro_f1_validation"], "cac_lan_thu": rows}
    od = Path(a.out)
    od.mkdir(parents=True, exist_ok=True)
    (od / "nhan_do_nhay.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Đã ghi: {od / 'nhan_do_nhay.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Phân loại tấn công đa lớp trên cửa sổ host: Benign, PortScan, DoS (Chặng 7).

- C07-T01: chốt nhãn thực tế: lớp nào, mẫu nào, đợt tấn công nào bị loại và vì sao
  (docs/39_phan_loai_nhan.md, QĐ-033).

    python -m nids.classifier nhan <tiền tố phiên>... --out docs/hinh

Mọi bước học chỉ dùng tập train; validation để chọn tham số và mô hình; test chỉ để đánh giá.
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from .dataset import load_table
from .gaussian import attack_groups
from .labeling import STATUS_AMBIGUOUS, STATUS_EXCLUDED, load_schedule
from .preprocessing import select_samples
from .scope import ATTACK_LABELS, MODULE_ATTACK

TABLE = "windows"
SPLITS = ("train", "validation", "test")
LABEL_COL = "label_attack"
# Lớp có ít hơn số mẫu này ở một tập thì kết quả của lớp đó ở tập ấy dao động lớn
MIN_CLASS_SAMPLES = 100
# Đợt tấn công có trong dữ liệu nhưng chưa thành lớp (QĐ-033): chỉ thêm khi có dữ liệu và kiểm thử
EXCLUDED_REASONS = {
    "DDoS": "Một đợt 20 phút, LOIT nhiều nguồn sau NAT; không đủ đợt độc lập để train và test riêng",
    "Heartbleed": "Một kết nối khai thác TLS kéo dài; lưu lượng trông bình thường, quá ít mẫu",
    "Bot": "Thuộc module botnet (Chặng 8); không phải PortScan hay DoS",
}


def load_data(prefixes, sessions=None) -> pd.DataFrame:
    df = load_table(prefixes, TABLE)
    if sessions:
        df = df[df["session"].isin(sessions)].reset_index(drop=True)
    return df


def classifier_config(cfg) -> dict:
    c = dict((cfg or {}).get("classifier") or {})
    p = (cfg or {}).get("preprocess") or {}
    c.setdefault("sessions", (p.get("sessions") or {}).get(MODULE_ATTACK))
    c.setdefault("drop_train_duplicates", p.get("drop_train_duplicates", True))
    c.setdefault("balance_max_ratio", p.get("balance_max_ratio", 10))
    c.setdefault("random_seed", (cfg or {}).get("random_seed", 42))
    return c


# ---- C07-T01: nhãn thực tế ----

def host_roles(df, rules) -> np.ndarray:
    """Vai trò của host trong lịch tấn công: ``ben_tan_cong``, ``nan_nhan`` hoặc ``khac``.

    Theo IP, không theo giờ: ở CIC mọi tấn công đi qua NAT 172.16.0.1, nên một IP có thể là bên
    tấn công cả ngày dù chỉ tấn công trong vài khung giờ.
    """
    attackers = set().union(*(r.attackers for r in rules)) if rules else set()
    victims = set().union(*(r.victims for r in rules)) if rules else set()
    host = df["host"].astype(str).to_numpy()
    out = np.full(len(df), "khac", dtype=object)
    out[np.isin(host, list(victims))] = "nan_nhan"
    out[np.isin(host, list(attackers))] = "ben_tan_cong"
    return out


def _counts(series) -> dict:
    return {str(k): int(v) for k, v in series.value_counts().sort_index().items()}


def class_report(df, rules) -> dict:
    """Số mẫu từng lớp theo tập, theo đợt tấn công và vai trò host; mẫu bị loại và lý do."""
    data, label_col = select_samples(df, MODULE_ATTACK)
    data = data[data["split"].isin(SPLITS)]
    groups = attack_groups(data, rules)
    roles = host_roles(data, rules)
    out = {"lop": list(ATTACK_LABELS), "phien": sorted(df["session"].unique()),
           "theo_tap": {}, "theo_dot": {}, "theo_vai_tro": {}, "canh_bao": []}
    for s in SPLITS:
        m = (data["split"] == s).to_numpy()
        out["theo_tap"][s] = {c: int((data[label_col].to_numpy()[m] == c).sum()) for c in ATTACK_LABELS}
        attack = m & (data[label_col] != "benign").to_numpy()
        out["theo_dot"][s] = _counts(pd.Series(groups[attack]))
        out["theo_vai_tro"][s] = {
            c: _counts(pd.Series(roles[m & (data[label_col] == c).to_numpy()])) for c in ATTACK_LABELS}
        for c, n in out["theo_tap"][s].items():
            if n < MIN_CLASS_SAMPLES:
                out["canh_bao"].append(f"{c} ở {s} chỉ có {n} mẫu: chỉ số của lớp này dao động lớn")
    excluded = df[df["label_status"] == STATUS_EXCLUDED]
    excluded = excluded[excluded["split"].isin(SPLITS)]
    exg = attack_groups(excluded.assign(label_anomaly="anomaly"), rules)
    out["bi_loai"] = {
        g: {"so_mau": {s: int(((exg == g) & (excluded["split"] == s).to_numpy()).sum()) for s in SPLITS},
            "ly_do": EXCLUDED_REASONS.get(g, "")}
        for g in sorted(set(exg))}
    amb = df[df["label_status"] == STATUS_AMBIGUOUS]
    out["mo_ho"] = {s: int((amb["split"] == s).sum()) for s in SPLITS}
    out["tong"] = {s: int(sum(out["theo_tap"][s].values())) for s in SPLITS}
    return out


def cmd_labels(args):
    from .config import load_config

    cfg = classifier_config(load_config(args.config))
    df = load_data(args.prefixes, cfg["sessions"])
    rep = class_report(df, load_schedule())
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "phan_loai_nhan.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
    print(pd.DataFrame(rep["theo_tap"]).to_string())
    for s in SPLITS:
        print(s, rep["theo_dot"][s])
    print("Bị loại:", {g: v["so_mau"] for g, v in rep["bi_loai"].items()})
    for w in rep["canh_bao"]:
        print("Cảnh báo:", w)
    print(f"Đã ghi: {out / 'phan_loai_nhan.json'}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Phân loại tấn công đa lớp trên cửa sổ host.")
    sub = parser.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("nhan", help="số mẫu từng lớp theo tập, đợt tấn công; mẫu bị loại (C07-T01)")
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--out", required=True, help="thư mục ghi JSON")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_labels)
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    # Chạy bản của module đã import để đối tượng lưu bằng joblib nạp lại được (docs/32 mục 4).
    from nids.classifier import main as module_main
    sys.exit(module_main())

"""Kiểm tra dữ liệu trước khi huấn luyện: thiếu, vô hạn, trùng, phân bố lớp (C05-T05).

    python -m nids.data_quality output/features/cic17_monday output/features/cic17_wednesday \\
        output/features/cic17_friday --out output/quality.json

Chi tiết và kết quả ở docs/30_kiem_tra_du_lieu.md.
"""

import argparse
import json
import sys

import numpy as np
import pandas as pd

from .dataset import TABLES, feature_columns, load_table
from .splits import DROPPED, SPLITS


def missing_report(df, feats) -> dict:
    """Số ô trống theo cột (chỉ cột có ô trống), tính trên các mẫu được dùng."""
    n = df[feats].isna().sum()
    n = n[n > 0].sort_values(ascending=False)
    return {c: {"so_o": int(v), "ty_le": round(v / len(df), 6)} for c, v in n.items()}


def infinite_report(df, feats) -> dict:
    vals = df[feats].to_numpy(dtype=float)
    inf = np.isinf(vals).sum(axis=0)
    return {c: int(v) for c, v in zip(feats, inf) if v}


def duplicate_report(df, feats) -> dict:
    """Mẫu có vector đặc trưng giống hệt nhau: trong cùng tập và giữa các tập.

    Mẫu giống hệt nằm ở cả train và test làm kết quả test đẹp hơn thật (rò rỉ do trùng).
    """
    key = pd.util.hash_pandas_object(df[feats].fillna(-1.2345e300), index=False)
    out = {"trong_cung_tap": {}}
    for s in SPLITS:
        k = key[df["split"] == s]
        out["trong_cung_tap"][s] = {"so_mau": int(len(k)), "so_mau_trung": int(k.duplicated().sum())}
    train = set(key[df["split"] == "train"])
    for s in ("validation", "test"):
        k = key[df["split"] == s]
        out[f"{s}_trung_train"] = {"so_mau": int(k.isin(train).sum()),
                                   "ty_le": round(float(k.isin(train).mean()), 6) if len(k) else None}
    return out


def class_report(df, label_col) -> dict:
    t = pd.crosstab(df[label_col].fillna("trong"), df["split"].fillna(DROPPED))
    return {lab: {s: int(v) for s, v in row.items()} for lab, row in t.iterrows()}


def check(prefixes, table) -> dict:
    df = load_table(prefixes, table)
    feats = feature_columns(table)
    used = df[df["split"].isin(SPLITS)]
    return {
        "bang": table,
        "phien": sorted(df["session"].unique()),
        "so_mau": len(df),
        "so_mau_dung": len(used),
        "so_mau_bo_vi_ranh_gioi": int((df["split"] == DROPPED).sum()),
        "so_dac_trung": len(feats),
        "o_trong": missing_report(used, feats),
        "vo_han": infinite_report(used, feats),
        "trung": duplicate_report(used, feats),
        "phan_bo_label_attack": class_report(df, "label_attack"),
        "phan_bo_label_anomaly": class_report(df, "label_anomaly"),
        "phan_bo_trang_thai": class_report(df, "label_status"),
        "theo_phien_va_tap": {f"{sess}/{s}": int(n) for (sess, s), n in
                              df.groupby(["session", "split"]).size().items()},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Kiểm tra dữ liệu trước khi huấn luyện.")
    parser.add_argument("prefixes", nargs="+", help="tiền tố phiên, ví dụ output/features/cic17_friday")
    parser.add_argument("--out", required=True, help="file JSON kết quả")
    args = parser.parse_args(argv)
    result = {t: check(args.prefixes, t) for t in TABLES}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    for t, r in result.items():
        print(f"{t}: {r['so_mau']} mẫu, dùng {r['so_mau_dung']}, bỏ {r['so_mau_bo_vi_ranh_gioi']}; "
              f"cột có ô trống {len(r['o_trong'])}, cột vô hạn {len(r['vo_han'])}")
        print(f"  label_attack theo tập: {r['phan_bo_label_attack']}")
    print(f"Đã ghi: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

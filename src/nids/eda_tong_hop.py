"""EDA tổng hợp cho ba bộ dữ liệu của đề tài: CIC-IDS2017, CTU-13 và lab ảo (docs/81).

Bổ sung cho ``nids.eda`` (docs/31, chỉ CIC): tổng quan kích thước, chất lượng dữ liệu (ô trống, trùng, cột hằng),
thống kê mô tả và độ lệch, mức mất cân bằng lớp, khả năng phân biệt từng đặc trưng (AUC một biến, thông tin tương
hỗ), đặc trưng đồ thị của bot CTU-13, và độ lệch phân bố giữa traffic bình thường của CIC và của lab.

Mọi thống kê theo nhãn chỉ dùng **tập train** (validation, test chỉ được đếm số mẫu), như docs/31.

    cd src
    python -m nids.eda_tong_hop --cic ../output/features --ctu13 ../output/ctu13 \\
        --lab ../output/lab_features_h1 --nhat-ky ../data/run_logs --out ../docs/hinh/eda_tong_hop
"""

import argparse
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from .dataset import feature_columns, load_table  # noqa: E402

CIC_SESSIONS = ("cic17_monday", "cic17_wednesday", "cic17_friday")


def _r(x, n=4):
    return None if x is None or (isinstance(x, float) and np.isnan(x)) else round(float(x), n)


def describe(df, feats) -> dict:
    out = {}
    for f in feats:
        v = pd.to_numeric(df[f], errors="coerce")
        nn = v.dropna()
        out[f] = {"trong": _r(v.isna().mean()), "bang_0": _r((nn == 0).mean()), "trung_binh": _r(nn.mean()),
                  "do_lech_chuan": _r(nn.std()), "trung_vi": _r(nn.median()), "p99": _r(nn.quantile(0.99)),
                  "lon_nhat": _r(nn.max()), "do_lech_skew": _r(nn.skew(), 2), "so_gia_tri_khac": int(nn.nunique())}
    return out


def separability(df, feats, label_col, positive) -> dict:
    """AUC một biến (lớp ``positive`` so với phần còn lại) và thông tin tương hỗ của từng đặc trưng."""
    from sklearn.feature_selection import mutual_info_classif
    from sklearn.metrics import roc_auc_score

    y = (df[label_col] == positive).to_numpy()
    X = df[feats].apply(pd.to_numeric, errors="coerce").fillna(0).to_numpy(float)
    rng = np.random.default_rng(42)
    sub = rng.choice(len(df), min(len(df), 60000), replace=False)
    mi = mutual_info_classif(X[sub], y[sub], random_state=42)
    out = {}
    for i, f in enumerate(feats):
        auc = roc_auc_score(y, X[:, i]) if 0 < y.sum() < len(y) else float("nan")
        out[f] = {"auc": _r(auc), "auc_tach": _r(max(auc, 1 - auc)), "thong_tin_tuong_ho": _r(mi[i])}
    return dict(sorted(out.items(), key=lambda kv: -(kv[1]["auc_tach"] or 0)))


def plot_bars(sep_by_class, out, title):
    classes = list(sep_by_class)
    feats = list(next(iter(sep_by_class.values())))
    order = sorted(feats, key=lambda f: -max(sep_by_class[c][f]["auc_tach"] or 0 for c in classes))
    fig, ax = plt.subplots(figsize=(9, 0.32 * len(order) + 1.5))
    yy = np.arange(len(order))
    for j, c in enumerate(classes):
        ax.barh(yy + (j - (len(classes) - 1) / 2) * 0.38, [sep_by_class[c][f]["auc_tach"] for f in order], 0.38, label=c)
    ax.set_yticks(yy, order)
    ax.invert_yaxis()
    ax.axvline(0.5, color="grey", lw=0.8, ls="--")
    ax.set_xlim(0.45, 1.0)
    ax.set_xlabel("AUC một biến (0,5 = không phân biệt; 1 = tách hoàn toàn)")
    ax.set_title(title, fontsize=10)
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(out, dpi=110)
    plt.close(fig)


def plot_skew(desc, out):
    feats = sorted(desc, key=lambda f: -(desc[f]["do_lech_skew"] or 0))
    fig, ax = plt.subplots(figsize=(9, 5.5))
    ax.barh(feats, [desc[f]["do_lech_skew"] or 0 for f in feats], color="#4C72B0")
    ax.invert_yaxis()
    ax.set_xscale("symlog")
    ax.set_xlabel("độ lệch (skewness), thang log; 0 = đối xứng")
    ax.set_title("Độ lệch của 20 đặc trưng cửa sổ host (train CIC)", fontsize=10)
    fig.tight_layout()
    fig.savefig(out, dpi=110)
    plt.close(fig)


def plot_shift(cic, lab, feats, out):
    fig, axes = plt.subplots(2, 4, figsize=(15, 7))
    for ax, f in zip(axes.flat, feats):
        for name, df, c in (("CIC (train, benign)", cic, "#4C72B0"), ("Lab (k1 train)", lab, "#DD8452")):
            v = np.log1p(pd.to_numeric(df[f], errors="coerce").dropna().clip(lower=0))
            ax.hist(v, bins=40, density=True, alpha=0.55, label=name, color=c)
        ax.set_title(f, fontsize=9)
        ax.set_xlabel("log(1 + x)")
    axes.flat[0].legend(fontsize=8)
    fig.suptitle("Traffic bình thường của CIC và của lab có phân bố khác nhau", fontsize=11)
    fig.tight_layout()
    fig.savefig(out, dpi=110)
    plt.close(fig)


def cic_part(prefix_dir, out) -> dict:
    prefixes = [str(Path(prefix_dir) / s) for s in CIC_SESSIONS]
    win = load_table(prefixes, "windows")
    feats = feature_columns("windows")
    res = {"tong_quan": {}}
    for s in CIC_SESSIONS:
        meta = json.loads((Path(prefix_dir) / f"{s}.meta.json").read_text(encoding="utf-8"))
        res["tong_quan"][s] = {"goi": meta["thong_ke"]["packet"]["giu_lai"], "flow": meta["bang"]["flows"]["so_dong"],
                               "cua_so": meta["bang"]["windows"]["so_dong"]}
    lab = win[win["split"].isin(["train", "validation", "test"])]
    res["lop_theo_tap"] = {s: {k: int(v) for k, v in g["label_attack"].value_counts().items()}
                           for s, g in lab.groupby("split")}
    tr = win[win["split"] == "train"]
    sure = tr[tr["label_attack"].isin(["benign", "port_scan", "dos"]) & tr["label_status"].isin(["khop", "khong_khop"])]
    dup = sure.duplicated(subset=feats + ["label_attack"]).mean()
    conflict = sure.groupby(feats, dropna=False)["label_attack"].nunique()
    res["chat_luong_train"] = {"so_cua_so": len(sure), "ty_le_trung_ca_dac_trung_lan_nhan": _r(dup),
                               "nhom_dac_trung_trung_mang_nhieu_nhan": int((conflict > 1).sum()),
                               "cot_hang": [f for f in feats if sure[f].nunique(dropna=False) <= 1]}
    res["mo_ta_train"] = describe(sure, feats)
    n = sure["label_attack"].value_counts()
    res["mat_can_bang_train"] = {"benign_tren_dos": _r(n["benign"] / n["dos"], 1),
                                 "benign_tren_port_scan": _r(n["benign"] / n["port_scan"], 1)}
    res["phan_biet_train"] = {c: separability(sure, feats, "label_attack", c) for c in ("port_scan", "dos")}
    plot_bars(res["phan_biet_train"], Path(out) / "cic_auc_dac_trung.png",
              "Mỗi đặc trưng một mình tách lớp tấn công khỏi phần còn lại tốt tới đâu (train CIC)")
    plot_skew(res["mo_ta_train"], Path(out) / "cic_do_lech.png")
    return res, sure[sure["label_attack"] == "benign"]


def ctu_part(flows_dir, out) -> dict:
    from . import botnet as bn

    df = bn.load_labeled(flows_dir, sorted(bn.SCENARIOS))
    feats = [f for f in bn.feature_names() if f in df.columns]
    res = {"so_host_cua_so": len(df), "theo_tap_nhan": {s: {k: int(v) for k, v in g[bn.LABEL_COL].value_counts(dropna=False).items()}
                                                         for s, g in df.groupby("split")}}
    tr = df[(df["split"] == "train") & df[bn.LABEL_COL].isin([bn.SUSPECT, bn.NORMAL])]
    res["trung_vi_train"] = {lab: {f: _r(g[f].median()) for f in feats} for lab, g in tr.groupby(bn.LABEL_COL)}
    res["phan_biet_train"] = {"suspect_host": separability(tr, feats, bn.LABEL_COL, bn.SUSPECT)}
    res["o_trong_train"] = {f: _r(tr[f].isna().mean()) for f in feats if tr[f].isna().any()}
    top = dict(list(res["phan_biet_train"]["suspect_host"].items())[:20])
    plot_bars({"bot": top}, Path(out) / "ctu13_auc_dac_trung.png",
              "20 đặc trưng đồ thị tách host bot khỏi host bình thường tốt nhất (train CTU-13)")
    return res


def lab_part(cache, logs, out, cic_benign) -> dict:
    runs = sorted(Path(logs).glob("*.json"))
    count = {}
    for p in runs:
        parts = p.stem.rsplit("-", 2)
        if len(parts) == 3 and parts[1] in ("train", "val", "test"):
            count.setdefault(parts[0], {}).setdefault(parts[1], 0)
            count[parts[0]][parts[1]] += 1
    k1 = [pd.read_csv(f) for f in sorted(Path(cache).glob("k1-binh-thuong-train-0*.windows.csv"))]
    res = {"lan_chay_theo_bien_the": count}
    if k1:
        lab = pd.concat(k1, ignore_index=True)
        feats = ["packets_in", "packets_out", "new_conn_in", "new_conn_out", "dst_ports", "src_hosts",
                 "dst_hosts", "bytes_in"]
        res["trung_vi_binh_thuong"] = {f: {"cic": _r(cic_benign[f].median()), "lab": _r(lab[f].median())} for f in feats}
        plot_shift(cic_benign, lab, feats, Path(out) / "lech_cic_lab.png")
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description="EDA tổng hợp ba bộ dữ liệu.")
    ap.add_argument("--cic", required=True)
    ap.add_argument("--ctu13", required=True)
    ap.add_argument("--lab", required=True, help="thư mục bảng đặc trưng các lần chạy lab")
    ap.add_argument("--nhat-ky", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    Path(a.out).mkdir(parents=True, exist_ok=True)
    cic, cic_benign = cic_part(a.cic, a.out)
    res = {"cic": cic, "ctu13": ctu_part(a.ctu13, a.out), "lab": lab_part(a.lab, a.nhat_ky, a.out, cic_benign)}
    (Path(a.out) / "eda_tong_hop.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: list(v) for k, v in res.items()}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

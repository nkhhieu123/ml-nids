"""Vẽ EDA cho các đặc trưng chính, chỉ trên tập train (C05-T06).

    python -m nids.eda output/features/cic17_monday output/features/cic17_wednesday \\
        output/features/cic17_friday --out docs/hinh

Chỉ dùng mẫu train để không nhìn trước phân bố của validation/test (tránh rò rỉ
khi chọn đặc trưng, ngưỡng). Ngoại lệ là hình phân bố lớp theo tập, chỉ đếm nhãn.
Chi tiết ở docs/31_eda.md.
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
from .splits import SPLITS  # noqa: E402

CLASS_ORDER = ("benign", "port_scan", "dos")
COLORS = {"benign": "#4C72B0", "port_scan": "#DD8452", "dos": "#C44E52",
          "normal": "#4C72B0", "anomaly": "#C44E52"}
FLOW_MAIN = ("duration_s", "packets", "bytes", "pkt_len_mean", "iat_mean", "fwd_byte_share",
             "syn_count", "rst_count")
WINDOW_MAIN = ("packets_in", "new_conn_out", "new_conn_in", "dst_ports", "dst_port_entropy",
               "src_hosts", "incomplete_ratio_out", "incomplete_ratio_in")
# Đặc trưng là tỷ lệ hoặc entropy: vẽ thang thường; còn lại thang log(1 + x)
LINEAR = {"fwd_byte_share", "fwd_packet_share", "dst_port_entropy", "incomplete_ratio_out",
          "incomplete_ratio_in"}


def _classes(df):
    return [c for c in CLASS_ORDER if (df["label_attack"] == c).any()]


def plot_class_counts(flows, windows, out):
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    for ax, (name, df) in zip(axes, (("flow", flows), ("cửa sổ host", windows))):
        t = pd.crosstab(df["label_attack"], df["split"]).reindex(index=_classes(df), columns=SPLITS)
        t.plot.bar(ax=ax, logy=True, rot=0, color=["#55A868", "#8172B2", "#937860"])
        ax.set_title(f"Số {name} theo lớp và tập (thang log)")
        ax.set_xlabel("")
        ax.set_ylabel("số mẫu")
    fig.tight_layout()
    fig.savefig(out, dpi=110)
    plt.close(fig)


def plot_by_class(df, feats, title, out, label_col="label_attack", order=CLASS_ORDER):
    order = [c for c in order if (df[label_col] == c).any()]
    fig, axes = plt.subplots(2, 4, figsize=(15, 7))
    for ax, f in zip(axes.flat, feats):
        data = []
        for c in order:
            v = df.loc[df[label_col] == c, f].dropna().to_numpy(dtype=float)
            data.append(v if f in LINEAR else np.log1p(v))
        ax.boxplot(data, showfliers=False, patch_artist=True,
                   boxprops={"alpha": 0.7}, medianprops={"color": "black"})
        for patch, c in zip(ax.patches, order):
            patch.set_facecolor(COLORS[c])
        ax.set_xticks(range(1, len(order) + 1), order, fontsize=8)
        ax.set_title(f if f in LINEAR else f"log(1 + {f})", fontsize=9)
    fig.suptitle(title)
    fig.tight_layout()
    fig.savefig(out, dpi=110)
    plt.close(fig)


def plot_correlation(df, feats, out):
    corr = df[feats].astype(float).corr(method="spearman")
    fig, ax = plt.subplots(figsize=(9, 8))
    im = ax.imshow(corr.to_numpy(), cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_xticks(range(len(feats)), feats, rotation=90, fontsize=7)
    ax.set_yticks(range(len(feats)), feats, fontsize=7)
    fig.colorbar(im, ax=ax, shrink=0.8)
    ax.set_title("Tương quan Spearman giữa các đặc trưng cửa sổ (train)")
    fig.tight_layout()
    fig.savefig(out, dpi=110)
    plt.close(fig)
    pairs = []
    for i, a in enumerate(feats):
        for b in feats[i + 1:]:
            r = corr.loc[a, b]
            if pd.notna(r) and abs(r) >= 0.95:
                pairs.append((a, b, round(float(r), 3)))
    return pairs


def plot_timeline(windows, session, host, out):
    w = windows[(windows["session"] == session) & (windows["host"] == host)].sort_values("window_start")
    t = pd.to_datetime(w["window_start"], unit="s", utc=True).dt.tz_convert("Etc/GMT+3")
    fig, ax = plt.subplots(figsize=(13, 3.5))
    ax.plot(t, w["new_conn_in"], color="#999999", lw=0.6)
    for c in _classes(w):
        m = w["label_attack"] == c
        ax.scatter(t[m], w.loc[m, "new_conn_in"], s=4, color=COLORS[c], label=c)
    ax.set_yscale("symlog")
    ax.set_ylabel("new_conn_in")
    ax.set_title(f"{host} trong {session}: kết nối mới tới host theo cửa sổ (giờ địa phương UTC−3; chỉ train)")
    ax.legend(markerscale=4)
    fig.tight_layout()
    fig.savefig(out, dpi=110)
    plt.close(fig)


def class_medians(df, feats, label_col="label_attack") -> dict:
    g = df.groupby(label_col)[list(feats)].median()
    return {c: {f: (None if pd.isna(v) else round(float(v), 6)) for f, v in row.items()}
            for c, row in g.iterrows()}


def run(prefixes, out_dir) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    flows = load_table(prefixes, "flows")
    windows = load_table(prefixes, "windows")
    files = {}
    files["phan_bo_lop"] = out_dir / "eda_phan_bo_lop.png"
    plot_class_counts(flows, windows, files["phan_bo_lop"])
    ft = flows[flows["split"] == "train"]
    wt = windows[windows["split"] == "train"]
    files["flow_theo_lop"] = out_dir / "eda_flow_theo_lop.png"
    plot_by_class(ft, FLOW_MAIN, "Đặc trưng flow chính theo lớp (train)", files["flow_theo_lop"])
    files["cua_so_theo_lop"] = out_dir / "eda_cua_so_theo_lop.png"
    plot_by_class(wt, WINDOW_MAIN, "Đặc trưng cửa sổ host chính theo lớp (train)", files["cua_so_theo_lop"])
    files["cua_so_anomaly"] = out_dir / "eda_cua_so_anomaly.png"
    plot_by_class(wt, WINDOW_MAIN, "Đặc trưng cửa sổ host: normal và anomaly (train)",
                  files["cua_so_anomaly"], "label_anomaly", ("normal", "anomaly"))
    files["tuong_quan"] = out_dir / "eda_tuong_quan_cua_so.png"
    high_corr = plot_correlation(wt, feature_columns("windows"), files["tuong_quan"])
    sessions = set(windows["session"])
    if "cic17_wednesday" in sessions:
        files["dong_thoi_gian"] = out_dir / "eda_dong_thoi_gian_thu_tu.png"
        plot_timeline(wt, "cic17_wednesday", "192.168.10.50", files["dong_thoi_gian"])
    summary = {
        "hinh": {k: str(v) for k, v in files.items()},
        "trung_vi_flow_train": class_medians(ft, FLOW_MAIN),
        "trung_vi_cua_so_train": class_medians(wt, WINDOW_MAIN),
        "cap_tuong_quan_cao_cua_so": high_corr,
    }
    (out_dir / "eda_tom_tat.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                                              encoding="utf-8")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description="Vẽ EDA trên tập train.")
    parser.add_argument("prefixes", nargs="+")
    parser.add_argument("--out", required=True, help="thư mục ghi hình")
    args = parser.parse_args(argv)
    s = run(args.prefixes, args.out)
    for k, v in s["hinh"].items():
        print(f"  {k}: {v}")
    print(f"Cặp đặc trưng cửa sổ tương quan |r| >= 0,95: {len(s['cap_tuong_quan_cao_cua_so'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

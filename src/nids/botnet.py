"""Phát hiện botnet và nhận diện topology trên host–cửa sổ (Chặng 8).

- C08-T04: gán nhãn host–cửa sổ, quy định cách xử lý Background, chia tập theo scenario
  (docs/48_botnet_nhan.md, QĐ-039).

    python -m nids.botnet nhan output/ctu13 --out docs/hinh

Nhãn host lấy từ nhãn flow của CTU-13 (docs/07 mục 5), độc lập với đặc trưng.
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from .ctu13 import FLOW_BOT, FLOW_NORMAL, SCENARIOS, flow_group, load_flows, load_info, session_name
from .graph_features import HOST_KEYS, graph_window

LABEL_COL = "label_host"
SUSPECT, NORMAL = "suspect_host", "normal_host"
BACKGROUND, DROP = "background", "bo"
SPLITS = ("train", "validation", "test")
TOPOLOGY_COL = "label_topology"


def botnet_config(cfg=None) -> dict:
    b = dict((cfg or {}).get("botnet") or {})
    b.setdefault("flows_dir", "output/ctu13")
    b.setdefault("splits", {"train": [3, 5, 7, 10, 11, 12], "validation": [4, 13], "test": [1, 2, 6, 8, 9]})
    b.setdefault("topology", {"p2p": [12]})
    return b


def scenario_split(scenario, splits) -> str:
    for name, members in splits.items():
        if int(scenario) in [int(m) for m in members]:
            return name
    return DROP


def scenario_topology(scenario, topology) -> str:
    """Topology của botnet trong scenario: ``p2p`` nếu nằm trong danh sách, còn lại ``centralized`` (docs/07)."""
    return "p2p" if int(scenario) in [int(s) for s in topology.get("p2p", [])] else "centralized"


def flow_counts(flows, hosts, group, size, step) -> pd.DataFrame:
    """Số flow nhóm ``group`` (ví dụ tu_bot) mỗi host khởi tạo trong từng cửa sổ."""
    f = flows[flows["src"].isin(set(hosts))]
    f = f[flow_group(f["label"]) == group]
    if f.empty:
        return pd.DataFrame(columns=HOST_KEYS + ["n"])
    o = np.floor(f["ts"].to_numpy(float) / step).astype("int64")
    cell = pd.DataFrame({"session": f["session"].to_numpy(), "host": f["src"].to_numpy(), "o": o}) \
        .groupby(["session", "host", "o"]).size().rename("n").reset_index()
    k = int(round(size / step))
    rep = cell.loc[cell.index.repeat(k)].reset_index(drop=True)
    rep["window_start"] = (rep["o"] - np.tile(np.arange(k), len(cell))) * step
    return rep.groupby(HOST_KEYS)["n"].sum().reset_index()


def label_host_windows(features, flows, info, cfg=None) -> pd.DataFrame:
    """Thêm nhãn host, nhãn topology, tập và số flow có nhãn của host trong cửa sổ.

    - ``suspect_host``: host là bot và khởi tạo ít nhất một flow From-Botnet trong cửa sổ.
    - ``normal_host``: host là máy bình thường đã xác nhận và khởi tạo flow From-Normal trong cửa sổ.
    - ``background``: host Background lấy mẫu; không học, không tính chỉ số, chỉ ước lượng báo động.
    - ``bo``: còn lại (bot chưa hoạt động hoặc đang im lặng; máy bình thường không có flow From-Normal).
    """
    size, step = graph_window(cfg)
    b = botnet_config(cfg)
    hosts = info["host"]
    bots, normals, bg = set(hosts["bot"]), set(hosts["binh_thuong"]), set(hosts["background_mau"])
    out = features.copy()
    nb = flow_counts(flows, bots, FLOW_BOT, size, step).rename(columns={"n": "so_flow_bot"})
    nn = flow_counts(flows, normals, FLOW_NORMAL, size, step).rename(columns={"n": "so_flow_normal"})
    out = out.merge(nb, on=HOST_KEYS, how="left").merge(nn, on=HOST_KEYS, how="left")
    out[["so_flow_bot", "so_flow_normal"]] = out[["so_flow_bot", "so_flow_normal"]].fillna(0).astype(int)
    lab = np.full(len(out), DROP, dtype=object)
    lab[out["host"].isin(bg).to_numpy()] = BACKGROUND
    lab[(out["host"].isin(normals) & (out["so_flow_normal"] > 0)).to_numpy()] = NORMAL
    lab[(out["host"].isin(bots) & (out["so_flow_bot"] > 0)).to_numpy()] = SUSPECT
    out[LABEL_COL] = lab
    s = int(info["scenario"])
    out[TOPOLOGY_COL] = np.where(lab == SUSPECT, scenario_topology(s, b["topology"]),
                                 np.where(lab == NORMAL, "none", ""))
    out["scenario"] = s
    out["split"] = scenario_split(s, b["splits"])
    return out


def load_labeled(flows_dir, scenarios, cfg=None) -> pd.DataFrame:
    """Đặc trưng (nids.graph_features dac-trung) kèm nhãn của các scenario."""
    parts = []
    for s in scenarios:
        info = load_info(flows_dir, s)
        feats = pd.read_csv(Path(flows_dir) / f"{session_name(s)}.host_windows.csv.gz", dtype={"host": str})
        parts.append(label_host_windows(feats, load_flows(flows_dir, [s]), info, cfg))
    return pd.concat(parts, ignore_index=True)


def label_report(df, infos) -> dict:
    """Số host–cửa sổ theo scenario × nhãn, số host độc lập, flow, tập."""
    rows = {}
    for s, g in df.groupby("scenario"):
        info = infos[s]
        rows[int(s)] = {
            "tap": g["split"].iloc[0], "gio": info["gio"], "so_flow": info["so_flow"],
            "nhom_nhan_flow": info["nhom_nhan"], "so_flow_cc": info["so_flow_cc"],
            "bot": info["host"]["bot"], "peer_bot_ben_ngoai": info.get("peer_bot_ben_ngoai", []),
            "may_binh_thuong": info["host"]["binh_thuong"],
            "flow_bot_dau_tien_sau_bat_dau_giay": (round(float(info["flow_bot_dau_tien"]) - float(info["bat_dau"]), 1)
                                                  if info.get("flow_bot_dau_tien") is not None else None),
            "host_cua_so": {k: int(v) for k, v in g[LABEL_COL].value_counts().items()},
            "topology": g.loc[g[LABEL_COL] == SUSPECT, TOPOLOGY_COL].iloc[0] if (g[LABEL_COL] == SUSPECT).any() else None,
        }
    tot = df[df[LABEL_COL].isin([SUSPECT, NORMAL])]
    return {"theo_scenario": rows,
            "theo_tap": {sp: {k: int(v) for k, v in tot[tot["split"] == sp][LABEL_COL].value_counts().items()}
                         for sp in SPLITS},
            "host_doc_lap_theo_tap": {sp: {k: int(v) for k, v in tot[tot["split"] == sp].groupby(LABEL_COL)["host"]
                                           .nunique().items()} for sp in SPLITS},
            "background_theo_tap": {sp: int(((df[LABEL_COL] == BACKGROUND) & (df["split"] == sp)).sum()) for sp in SPLITS}}


def cmd_labels(args):
    from .config import load_config

    cfg = load_config(args.config)
    scen = args.scenario or sorted(SCENARIOS)
    df = load_labeled(args.flows_dir, scen, cfg)
    rep = label_report(df, {s: load_info(args.flows_dir, s) for s in scen})
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "botnet_nhan.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    for s, r in rep["theo_scenario"].items():
        print(s, r["tap"], r["topology"], r["host_cua_so"], "bot", len(r["bot"]))
    print("Theo tập:", rep["theo_tap"])
    print("Host độc lập:", rep["host_doc_lap_theo_tap"])
    print("Background:", rep["background_theo_tap"])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Phát hiện botnet và nhận diện topology.")
    sub = parser.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("nhan", help="gán nhãn host–cửa sổ, chia tập theo scenario (C08-T04)")
    p.add_argument("flows_dir")
    p.add_argument("--scenario", type=int, action="append")
    p.add_argument("--out", required=True)
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_labels)
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    # Chạy bản của module đã import để đối tượng lưu bằng joblib nạp lại được (docs/32 mục 4).
    from nids.botnet import main as module_main
    sys.exit(module_main())

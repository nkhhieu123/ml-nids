"""Đọc file ``.binetflow`` của CTU-13 thành bảng flow chung của module botnet (Chặng 8).

Bảng flow chung (``FLOW_COLUMNS``) là đầu vào của đồ thị và đặc trưng ở ``nids.graph_features``;
flow do dự án tự ghép từ PCAP (CIC, lab) đổi sang cùng dạng bằng ``from_project_flows``.

File CTU-13 lớn (tới 610 MB), nên đọc theo từng khúc và chỉ giữ flow có một đầu là **host cần xét**:
các bot, ba máy bình thường đã xác nhận và một mẫu host Background (docs/45, QĐ-036).

    python -m nids.ctu13 chuan-bi data/ctu13 --out output/ctu13
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# Cột của bảng flow chung. src là bên khởi tạo (Argus: SrcAddr; dự án: fwd_ip).
FLOW_COLUMNS = ["session", "ts", "end_ts", "proto", "src", "sport", "dst", "dport",
                "packets", "bytes", "src_bytes", "dst_bytes", "state", "label"]

# Nhãn flow của CTU-13 quy về năm nhóm (docs/07 mục 4)
FLOW_BOT, FLOW_NORMAL, FLOW_TO_BOT, FLOW_TO_NORMAL, FLOW_BACKGROUND = (
    "tu_bot", "tu_normal", "toi_bot", "toi_normal", "background")

# 13 scenario: số thư mục trên máy chủ và tên file (docs/07 mục 2)
SCENARIOS = {
    1: (42, "capture20110810.binetflow"), 2: (43, "capture20110811.binetflow"),
    3: (44, "capture20110812.binetflow"), 4: (45, "capture20110815.binetflow"),
    5: (46, "capture20110815-2.binetflow"), 6: (47, "capture20110816.binetflow"),
    7: (48, "capture20110816-2.binetflow"), 8: (49, "capture20110816-3.binetflow"),
    9: (50, "capture20110817.binetflow"), 10: (51, "capture20110818.binetflow"),
    11: (52, "capture20110818-2.binetflow"), 12: (53, "capture20110819.binetflow"),
    13: (54, "capture20110815-3.binetflow"),
}
# Máy chủ trong mạng trường mà README ghi là "kém tin cậy": không dùng làm normal_host
UNRELIABLE_NORMAL = {"147.32.87.36", "147.32.80.9", "147.32.87.11"}
LOCAL_NET = "147.32."
CHUNK = 400_000


def session_name(scenario) -> str:
    return f"ctu13_s{int(scenario):02d}"


def flow_group(labels) -> np.ndarray:
    """Nhóm của nhãn flow: tu_bot, tu_normal, toi_bot, toi_normal, background."""
    s = pd.Series(labels, dtype=str).str.replace("flow=", "", regex=False)
    out = np.full(len(s), FLOW_BACKGROUND, dtype=object)
    out[s.str.startswith("From-Botnet").to_numpy()] = FLOW_BOT
    out[s.str.startswith("From-Normal").to_numpy()] = FLOW_NORMAL
    out[s.str.startswith("To-Botnet").to_numpy()] = FLOW_TO_BOT
    out[s.str.startswith("To-Normal").to_numpy()] = FLOW_TO_NORMAL
    return out


def is_cc(labels) -> np.ndarray:
    """Flow của kênh điều khiển: nhãn From-Botnet có đoạn ``CC`` (docs/07 mục 4)."""
    s = pd.Series(labels, dtype=str)
    return (s.str.contains("From-Botnet", regex=False) & s.str.contains(r"-CC\d*", regex=True)).to_numpy()


def _port(s) -> pd.Series:
    """Cổng của Argus: số thập phân, hoặc ``0x...`` (loại/mã ICMP); còn lại để trống."""
    s = s.astype(str).str.strip()
    hexa = s.str.startswith("0x")
    out = pd.to_numeric(s.where(~hexa), errors="coerce")
    out[hexa] = s[hexa].map(lambda v: int(v, 16) if all(c in "0123456789abcdefABCDEF" for c in v[2:]) and len(v) > 2 else np.nan)
    return out


def normalize(chunk, session) -> pd.DataFrame:
    """Một khúc ``.binetflow`` thành bảng flow chung. StartTime là giờ địa phương, đọc như UTC."""
    ts = pd.to_datetime(chunk["StartTime"], format="%Y/%m/%d %H:%M:%S.%f").astype("int64") / 1e9
    dur = pd.to_numeric(chunk["Dur"], errors="coerce").fillna(0.0)
    tot = pd.to_numeric(chunk["TotBytes"], errors="coerce")
    srcb = pd.to_numeric(chunk["SrcBytes"], errors="coerce")
    return pd.DataFrame({
        "session": session, "ts": ts.to_numpy(), "end_ts": (ts + dur).to_numpy(),
        "proto": chunk["Proto"].astype(str).str.lower().to_numpy(),
        "src": chunk["SrcAddr"].astype(str).to_numpy(), "sport": _port(chunk["Sport"]).to_numpy(),
        "dst": chunk["DstAddr"].astype(str).to_numpy(), "dport": _port(chunk["Dport"]).to_numpy(),
        "packets": pd.to_numeric(chunk["TotPkts"], errors="coerce").to_numpy(),
        "bytes": tot.to_numpy(), "src_bytes": srcb.to_numpy(), "dst_bytes": (tot - srcb).to_numpy(),
        "state": chunk["State"].astype(str).to_numpy(), "label": chunk["Label"].astype(str).to_numpy(),
    })


def read_chunks(path, session, chunksize=CHUNK):
    for chunk in pd.read_csv(path, chunksize=chunksize, dtype=str, keep_default_na=False):
        yield normalize(chunk, session)


def scan(path, session) -> dict:
    """Lượt đọc thứ nhất: đếm nhãn, tìm bot và máy bình thường từ nhãn, đếm flow Background của host nội bộ."""
    groups, cc, bots, normals = {}, 0, {}, {}
    background_src = {}
    t0, t1, n = np.inf, -np.inf, 0
    first_bot = np.inf
    for f in read_chunks(path, session):
        g = flow_group(f["label"])
        n += len(f)
        t0, t1 = min(t0, f["ts"].min()), max(t1, f["end_ts"].max())
        for k, v in pd.Series(g).value_counts().items():
            groups[k] = groups.get(k, 0) + int(v)
        cc += int(is_cc(f["label"]).sum())
        for k, v in f.loc[g == FLOW_BOT, "src"].value_counts().items():
            bots[k] = bots.get(k, 0) + int(v)
        if (g == FLOW_BOT).any():
            first_bot = min(first_bot, float(f.loc[g == FLOW_BOT, "ts"].min()))
        for k, v in f.loc[g == FLOW_NORMAL, "src"].value_counts().items():
            normals[k] = normals.get(k, 0) + int(v)
        bg = f[(g == FLOW_BACKGROUND) & f["src"].str.startswith(LOCAL_NET)]
        for k, v in bg["src"].value_counts().items():
            background_src[k] = background_src.get(k, 0) + int(v)
    return {"session": session, "so_flow": n, "bat_dau": t0, "ket_thuc": t1, "gio": round((t1 - t0) / 3600, 2),
            "nhom_nhan": groups, "so_flow_cc": cc, "bot": bots, "may_binh_thuong": normals,
            "flow_bot_dau_tien": None if not np.isfinite(first_bot) else first_bot,
            "_background_src": background_src}


def pick_background(background_src, exclude, n, min_flows=20, seed=42) -> list:
    """Mẫu ngẫu nhiên host nội bộ chỉ có nhãn Background, khởi tạo ít nhất ``min_flows`` flow."""
    cand = sorted(h for h, c in background_src.items() if c >= min_flows and h not in exclude)
    if len(cand) <= n:
        return cand
    rng = np.random.default_rng(seed)
    return sorted(rng.choice(cand, n, replace=False).tolist())


def extract(path, session, hosts) -> pd.DataFrame:
    """Lượt đọc thứ hai: chỉ flow có một đầu thuộc ``hosts``."""
    hosts = set(hosts)
    parts = [f[f["src"].isin(hosts) | f["dst"].isin(hosts)] for f in read_chunks(path, session)]
    return pd.concat(parts, ignore_index=True).sort_values("ts", kind="stable").reset_index(drop=True)


def prepare_scenario(path, scenario, out_dir, n_background=20, seed=42) -> dict:
    session = session_name(scenario)
    info = scan(path, session)
    # Máy bị nhiễm là host trong mạng trường; nguồn From-Botnet bên ngoài (scenario 12) là peer P2P ở xa
    bots = sorted(h for h in info["bot"] if h.startswith(LOCAL_NET))
    info["peer_bot_ben_ngoai"] = sorted(h for h in info["bot"] if not h.startswith(LOCAL_NET))
    normals = sorted(h for h in info["may_binh_thuong"] if h not in UNRELIABLE_NORMAL and h not in info["bot"])
    background = pick_background(info.pop("_background_src"), set(bots) | set(normals) | UNRELIABLE_NORMAL,
                                 n_background, seed=seed + int(scenario))
    hosts = {"bot": bots, "binh_thuong": normals, "background_mau": background}
    flows = extract(path, session, bots + normals + background)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    flows.to_csv(out_dir / f"{session}.flows.csv.gz", index=False, compression="gzip")
    info.update({"scenario": int(scenario), "file": Path(path).name, "host": hosts,
                 "so_flow_giu_lai": len(flows)})
    (out_dir / f"{session}.json").write_text(json.dumps(info, ensure_ascii=False, indent=2, default=str),
                                             encoding="utf-8")
    return info


def load_flows(out_dir, scenarios) -> pd.DataFrame:
    parts = [pd.read_csv(Path(out_dir) / f"{session_name(s)}.flows.csv.gz",
                         dtype={"src": str, "dst": str, "proto": str, "state": str, "label": str, "session": str},
                         keep_default_na=False, na_values=[""])
             for s in scenarios]
    return pd.concat(parts, ignore_index=True)


def load_info(out_dir, scenario) -> dict:
    return json.loads((Path(out_dir) / f"{session_name(scenario)}.json").read_text(encoding="utf-8"))


PROTO_NAMES = {"6": "tcp", "17": "udp", "1": "icmp", "58": "ipv6-icmp", "132": "sctp"}


def from_project_flows(df, session) -> pd.DataFrame:
    """Bảng flow của nids.flows (CIC, lab) sang bảng flow chung."""
    proto = df["protocol"].astype(str)
    return pd.DataFrame({
        "session": session, "ts": df["first_ts"].astype(float), "end_ts": df["last_ts"].astype(float),
        "proto": proto.map(PROTO_NAMES).fillna(proto).to_numpy(),
        "src": df["fwd_ip"].astype(str), "sport": df["fwd_port"], "dst": df["bwd_ip"].astype(str),
        "dport": df["bwd_port"], "packets": df["packets"], "bytes": df["bytes"],
        "src_bytes": df["fwd_bytes"], "dst_bytes": df["bwd_bytes"], "state": "",
        "label": df["label"] if "label" in df else "",
    })[FLOW_COLUMNS]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Chuẩn bị flow CTU-13 cho module botnet.")
    sub = parser.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("chuan-bi", help="đếm nhãn và giữ flow của host cần xét, mỗi scenario một file")
    p.add_argument("data_dir", help="thư mục chứa các file .binetflow")
    p.add_argument("--out", required=True)
    p.add_argument("--scenario", type=int, action="append", help="mặc định: mọi scenario có file")
    p.add_argument("--background", type=int, default=20, help="số host Background lấy mẫu mỗi scenario")
    args = parser.parse_args(argv)
    for s in args.scenario or sorted(SCENARIOS):
        path = Path(args.data_dir) / SCENARIOS[s][1]
        if not path.exists():
            print(f"scenario {s}: chưa có {path.name}, bỏ qua")
            continue
        info = prepare_scenario(path, s, args.out, args.background)
        print(f"scenario {s}: {info['so_flow']} flow, {info['gio']} giờ, nhãn {info['nhom_nhan']}, "
              f"CC {info['so_flow_cc']}, bot {list(info['bot'])}, giữ {info['so_flow_giu_lai']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

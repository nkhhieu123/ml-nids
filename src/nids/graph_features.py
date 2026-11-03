"""Đồ thị giao tiếp theo cửa sổ và đặc trưng của module botnet/topology (Chặng 8).

- C08-T01: đồ thị theo cửa sổ 120 giây, bước 10 giây (B02): node là IP, cạnh có hướng từ bên
  khởi tạo, trọng số là số flow, gói, byte, cổng (docs/45_do_thi_cua_so.md, QĐ-036).

Đầu vào là bảng flow chung của ``nids.ctu13`` (CTU-13 hoặc flow của dự án đã đổi dạng).

    python -m nids.graph_features do-thi output/ctu13 --scenario 11 --out docs/hinh
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

OUT, IN = "ra", "vao"
EDGE_KEYS = ["session", "window_start", "host", "peer", "huong"]


def graph_window(cfg=None) -> tuple:
    w = ((cfg or {}).get("windows") or {}).get("graph") or {}
    return float(w.get("size_s", 120)), float(w.get("step_s", 10))


def incident(flows, hosts) -> pd.DataFrame:
    """Mỗi flow thành một dòng cho mỗi đầu thuộc ``hosts``: host, peer, hướng (ra: host khởi tạo)."""
    hosts = set(hosts)
    cols = ["session", "ts", "proto", "packets", "bytes", "src_bytes", "dst_bytes"]
    out_side = flows[flows["src"].isin(hosts)]
    in_side = flows[flows["dst"].isin(hosts)]
    a = out_side[cols].assign(host=out_side["src"].to_numpy(), peer=out_side["dst"].to_numpy(), huong=OUT,
                              port=out_side["dport"].to_numpy(),
                              tra_loi=(out_side["dst_bytes"].fillna(0) > 0).to_numpy())
    b = in_side[cols].assign(host=in_side["dst"].to_numpy(), peer=in_side["src"].to_numpy(), huong=IN,
                             port=in_side["dport"].to_numpy(),
                             tra_loi=(in_side["dst_bytes"].fillna(0) > 0).to_numpy())
    return pd.concat([a, b], ignore_index=True)


def window_edges(flows, hosts, size=120.0, step=10.0) -> pd.DataFrame:
    """Cạnh của đồ thị từng cửa sổ, nhìn từ mỗi host cần xét (đồ thị một bước quanh host).

    Flow thuộc mọi cửa sổ ``[ws, ws + size)`` chứa thời điểm bắt đầu của nó; ``ws`` là bội của
    ``step``. Gộp theo ô ``step`` giây trước rồi mới trải ra ``size / step`` cửa sổ để tiết kiệm bộ nhớ.
    """
    if int(round(size / step)) * step != size:
        raise ValueError("size phải là bội của step")
    inc = incident(flows, hosts)
    if inc.empty:
        return pd.DataFrame(columns=EDGE_KEYS + ["so_flow", "so_goi", "so_byte", "so_cong", "so_flow_udp",
                                                 "so_flow_khong_tra_loi", "cong"])
    inc["o"] = np.floor(inc["ts"] / step).astype("int64")
    inc["udp"] = (inc["proto"] == "udp").astype(int)
    inc["khong_tra_loi"] = (~inc["tra_loi"]).astype(int)
    inc["port"] = inc["port"].fillna(-1).astype("int64")
    cell = inc.groupby(["session", "o", "host", "peer", "huong", "port"], sort=False).agg(
        so_flow=("ts", "size"), so_goi=("packets", "sum"), so_byte=("bytes", "sum"), so_flow_udp=("udp", "sum"),
        so_flow_khong_tra_loi=("khong_tra_loi", "sum")).reset_index()
    k = int(round(size / step))
    rep = cell.loc[cell.index.repeat(k)].reset_index(drop=True)
    rep["window_start"] = (rep["o"] - np.tile(np.arange(k), len(cell))) * step
    edges = rep.groupby(EDGE_KEYS, sort=False).agg(
        so_flow=("so_flow", "sum"), so_goi=("so_goi", "sum"), so_byte=("so_byte", "sum"),
        so_cong=("port", "nunique"), so_flow_udp=("so_flow_udp", "sum"),
        so_flow_khong_tra_loi=("so_flow_khong_tra_loi", "sum")).reset_index()
    return edges.sort_values(["session", "host", "window_start", "huong", "peer"]).reset_index(drop=True)


def host_ports(flows, hosts, size=120.0, step=10.0) -> pd.DataFrame:
    """Số cổng đích khác nhau mỗi host dùng khi khởi tạo flow, theo cửa sổ (không cộng được qua peer)."""
    inc = incident(flows, hosts)
    inc = inc[inc["huong"] == OUT]
    if inc.empty:
        return pd.DataFrame(columns=["session", "window_start", "host", "so_cong_ra"])
    inc = inc.assign(o=np.floor(inc["ts"] / step).astype("int64"), port=inc["port"].fillna(-1).astype("int64"))
    cell = inc[["session", "o", "host", "port"]].drop_duplicates()
    k = int(round(size / step))
    rep = cell.loc[cell.index.repeat(k)].reset_index(drop=True)
    rep["window_start"] = (rep["o"] - np.tile(np.arange(k), len(cell))) * step
    return rep.groupby(["session", "window_start", "host"])["port"].nunique().rename("so_cong_ra").reset_index()


def to_graph(edges):
    """Đồ thị có hướng (networkx) của các cạnh một cửa sổ; cạnh luôn đi từ bên khởi tạo."""
    import networkx as nx

    g = nx.DiGraph()
    for r in edges.itertuples(index=False):
        u, v = (r.host, r.peer) if r.huong == OUT else (r.peer, r.host)
        if g.has_edge(u, v):
            continue                                   # cùng cạnh nhìn từ hai host cần xét: chỉ tính một lần
        g.add_edge(u, v, so_flow=int(r.so_flow), so_goi=int(r.so_goi), so_byte=int(r.so_byte),
                   so_cong=int(r.so_cong))
    return g


def edge_summary(edges) -> dict:
    per = edges.groupby(["session", "window_start", "host"]).agg(so_peer=("peer", "nunique"), so_canh=("peer", "size"))
    return {"so_canh": int(len(edges)), "so_host_cua_so": int(len(per)),
            "peer_moi_host_cua_so": {q: float(per["so_peer"].quantile(q)) for q in (0.5, 0.9, 0.99)},
            "so_cua_so_moi_phien": {s: int(v) for s, v in edges.groupby("session")["window_start"].nunique().items()}}


def plot_ego(edges, hosts_titles, path):
    """Vẽ đồ thị quanh vài host ở một cửa sổ: cỡ cạnh theo số flow, màu theo hướng."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import networkx as nx

    fig, axes = plt.subplots(1, len(hosts_titles), figsize=(5.2 * len(hosts_titles), 5))
    axes = np.atleast_1d(axes)
    for ax, (session, ws, host, title) in zip(axes, hosts_titles):
        e = edges[(edges["session"] == session) & (edges["window_start"] == ws) & (edges["host"] == host)]
        g = to_graph(e)
        pos = nx.spring_layout(g, seed=1, k=1.2 / max(np.sqrt(len(g)), 1))
        w = np.array([d["so_flow"] for *_, d in g.edges(data=True)], float)
        colors = ["#C44E52" if u == host else "#4C72B0" for u, _ in g.edges()]
        nx.draw_networkx_edges(g, pos, ax=ax, width=0.5 + 2.5 * w / max(w.max(), 1), edge_color=colors,
                               arrowsize=6, alpha=0.7)
        nx.draw_networkx_nodes(g, pos, ax=ax, node_size=[160 if n == host else 25 for n in g.nodes()],
                               node_color=["#C44E52" if n == host else "#999999" for n in g.nodes()])
        ax.set_title(f"{title}\n{host}: {len(g) - 1} peer, {int(e['so_flow'].sum())} flow", fontsize=9)
        ax.axis("off")
    fig.suptitle("Đồ thị một cửa sổ 120 giây quanh host (đỏ: host khởi tạo, xanh: peer khởi tạo)", fontsize=10)
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)


def cmd_graph(args):
    from .config import load_config
    from .ctu13 import load_flows, load_info

    size, step = graph_window(load_config(args.config))
    res, picks = {}, []
    for s in args.scenario:
        info = load_info(args.flows_dir, s)
        flows = load_flows(args.flows_dir, [s])
        hosts = info["host"]["bot"] + info["host"]["binh_thuong"]
        edges = window_edges(flows, hosts, size, step)
        res[info["session"]] = edge_summary(edges)
        busiest = edges.groupby(["window_start", "host"])["so_flow"].sum()
        for role, members in (("bot", info["host"]["bot"]), ("máy bình thường", info["host"]["binh_thuong"])):
            sub = busiest[busiest.index.get_level_values("host").isin(members)]
            if len(sub):
                ws, h = sub.sort_values().index[len(sub) // 2]       # cửa sổ có lưu lượng trung vị
                picks.append((info["session"], ws, h, f"{info['session']} — {role}"))
        print(info["session"], res[info["session"]])
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "botnet_do_thi.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    if picks:
        plot_ego(edges if len(args.scenario) == 1 else window_edges(
            load_flows(args.flows_dir, args.scenario),
            sum((load_info(args.flows_dir, s)["host"]["bot"] + load_info(args.flows_dir, s)["host"]["binh_thuong"]
                 for s in args.scenario), []), size, step), picks[:4], out / "botnet_do_thi.png")
    print(f"Đã ghi: {out / 'botnet_do_thi.json'}, {out / 'botnet_do_thi.png'}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Đồ thị giao tiếp và đặc trưng botnet theo cửa sổ.")
    sub = parser.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("do-thi", help="dựng đồ thị theo cửa sổ, thống kê và vẽ ví dụ (C08-T01)")
    p.add_argument("flows_dir", help="thư mục ra của nids.ctu13 chuan-bi")
    p.add_argument("--scenario", type=int, action="append", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_graph)
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Dashboard HTML tĩnh từ file cảnh báo (tùy chọn nâng cao của Giai đoạn 4, QĐ-090).

Đọc ``<tên>.alerts.csv`` (và ``<tên>.su_kien.csv`` nếu có) do pipeline offline hoặc cảm biến realtime ghi, rồi
sinh **một file HTML tự chứa** (hình nhúng sẵn, không cần mạng, không cần máy chủ): số cảnh báo theo module và nhãn,
dòng thời gian cảnh báo theo máy, máy bị báo nhiều nhất, bảng sự kiện, và đồ thị liên lạc giữa các máy bị nghi
botnet (từ trường ``dst_ip`` hoặc nhãn topology). Mở bằng trình duyệt.

    cd src
    python -m nids.dashboard ../output/demo/k2-quet-nhanh-test-99/k2-quet-nhanh-test-99.alerts.csv \\
        --out ../output/dashboard.html
"""

import argparse
import base64
import html
import io
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

COLORS = {"anomaly": "#8c8c8c", "port_scan": "#e45756", "dos": "#f58518", "suspect_host": "#4c78a8",
          "centralized": "#54a24b", "p2p": "#b279a2"}


def _png(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=100, bbox_inches="tight")
    plt.close(fig)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def load(path) -> pd.DataFrame:
    df = pd.read_csv(path, dtype={"src_ip": str, "dst_ip": str})
    for c in ("window_start", "window_end", "created_at"):
        df[c] = pd.to_datetime(df[c], utc=True, errors="coerce")
    return df


def timeline(df):
    hosts = df["src_ip"].value_counts().index.tolist()[:25]
    d = df[df["src_ip"].isin(hosts)]
    fig, ax = plt.subplots(figsize=(10, 0.35 * len(hosts) + 1.6))
    pos = {h: i for i, h in enumerate(hosts)}
    for lab, g in d.groupby("label"):
        ax.scatter(g["window_end"], g["src_ip"].map(pos), s=14, label=lab, color=COLORS.get(lab, "#333333"))
    ax.set_yticks(range(len(hosts)), hosts)
    ax.invert_yaxis()
    ax.set_xlabel("cuối cửa sổ (UTC)")
    ax.legend(loc="upper left", bbox_to_anchor=(1, 1), fontsize=8)
    ax.set_title("Dòng thời gian cảnh báo theo máy", fontsize=10)
    return _png(fig)


def comm_graph(df):
    """Đồ thị máy bị nghi botnet: nối máy với đích (``dst_ip``) nếu có; tô màu theo topology."""
    import networkx as nx

    bot = df[df["module"] == "botnet_topology"]
    if bot.empty:
        return None
    topo = bot[bot["label"].isin(["centralized", "p2p"])].groupby("src_ip")["label"].agg(lambda s: s.mode().iat[0])
    g = nx.Graph()
    for ip in bot.loc[bot["label"] == "suspect_host", "src_ip"].unique():
        g.add_node(ip)
    for _, r in bot.dropna(subset=["dst_ip"]).iterrows():
        if r["dst_ip"]:
            g.add_edge(r["src_ip"], r["dst_ip"])
    p2p = [h for h, t in topo.items() if t == "p2p"]
    for i, a in enumerate(p2p):                       # bot ngang hàng: nối với nhau để thấy dạng lưới
        for b in p2p[i + 1:]:
            g.add_edge(a, b)
    if not g.number_of_nodes():
        return None
    fig, ax = plt.subplots(figsize=(5.5, 4.2))
    pos = nx.spring_layout(g, seed=1)
    nx.draw_networkx(g, pos, ax=ax, font_size=8, node_size=600,
                     node_color=[COLORS.get(topo.get(n, ""), "#cccccc") for n in g.nodes])
    ax.set_title("Máy bị nghi botnet (xanh lá: tập trung, tím: ngang hàng)", fontsize=9)
    ax.axis("off")
    return _png(fig)


def table(df: pd.DataFrame) -> str:
    return df.to_html(index=False, border=0, classes="t", escape=True)


def render(alerts_path, events_path=None, title=None) -> str:
    df = load(alerts_path)
    title = title or Path(alerts_path).name.replace(".alerts.csv", "")
    counts = df.groupby(["module", "label"]).size().reset_index(name="so_canh_bao")
    attack = df[df["label"].isin(["port_scan", "dos", "suspect_host"])]
    top = (attack.groupby(["src_ip", "label"]).size().reset_index(name="so_canh_bao")
           .sort_values("so_canh_bao", ascending=False).head(15))
    t0, t1 = df["window_start"].min(), df["window_end"].max()
    parts = [f"<h1>Dashboard cảnh báo: {html.escape(title)}</h1>",
             f"<p>{len(df)} cảnh báo, {df['src_ip'].nunique()} máy, từ {t0} tới {t1} (UTC).</p>",
             "<h2>Số cảnh báo theo module và nhãn</h2>", table(counts),
             "<h2>Dòng thời gian</h2>", f'<img src="{timeline(df)}">' if len(df) else "<p>Không có cảnh báo.</p>",
             "<h2>Máy bị báo nhiều nhất (quét, DoS, bot)</h2>", table(top) if len(top) else "<p>Không có.</p>"]
    g = comm_graph(df)
    if g:
        parts += ["<h2>Đồ thị máy bị nghi botnet</h2>", f'<img src="{g}">',
                  "<p>Cảnh báo botnet chỉ thể hiện mức nghi vấn, không khẳng định có mã độc. Cạnh giữa các bot ngang hàng chỉ để "
                  "minh họa chúng thuộc cùng nhóm, không phải flow đã đo; cạnh tới máy khác lấy từ trường dst_ip.</p>"]
    if events_path and Path(events_path).exists():
        ev = pd.read_csv(events_path)
        parts += [f"<h2>Sự kiện ({len(ev)})</h2>", table(ev.head(200))]
    style = ("body{font-family:Segoe UI,Arial,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#222}"
             "table.t{border-collapse:collapse;font-size:13px}table.t td,table.t th{border-bottom:1px solid #ddd;"
             "padding:4px 10px;text-align:left}img{max-width:100%}h2{margin-top:28px;font-size:18px}")
    return (f"<!doctype html><html lang=vi><head><meta charset=utf-8><title>{html.escape(title)}</title>"
            f"<style>{style}</style></head><body>{''.join(parts)}</body></html>")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Dashboard HTML tĩnh từ file cảnh báo.")
    ap.add_argument("alerts")
    ap.add_argument("--su-kien", help="file sự kiện; mặc định cùng tên với .su_kien.csv nếu có")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    ev = a.su_kien or str(a.alerts).replace(".alerts.csv", ".su_kien.csv")
    Path(a.out).write_text(render(a.alerts, ev), encoding="utf-8")
    print(f"Đã ghi {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

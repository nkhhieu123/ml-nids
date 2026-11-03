"""Dữ liệu topology giả lập ở mức flow: tập trung, ngang hàng và đối chứng lành tính (C08-T06).

Chỉ sinh **bản ghi flow** (bảng flow chung của ``nids.ctu13``), không gửi gói nào. Dùng để kiểm tra bộ
nhận diện topology khi chưa có lab, và vì CTU-13 chỉ có một scenario P2P. Traffic thật trong lab do
``scripts/sinh_topology.py`` tạo (thông điệp vô hại, chỉ trong mạng lab).

    python -m nids.topology_sim --out output/topology_sim

Mỗi lần chạy giả lập có nhật ký (mã lần chạy, thời gian, IP, hành vi) như lần chạy lab (B10); nhãn lấy
từ nhật ký, không từ đặc trưng. Xem docs/50_du_lieu_topology.md, QĐ-041.
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from .ctu13 import FLOW_COLUMNS

LAB = "192.168.50."
BOTS = [f"{LAB}{i}" for i in (41, 42, 43)]
CC_SERVER = f"{LAB}50"
SERVICE = f"{LAB}30"
KINDS = ("centralized", "p2p", "benign_centralized", "benign_p2p")
TOPOLOGY_OF = {"centralized": "centralized", "p2p": "p2p", "benign_centralized": "none", "benign_p2p": "none"}


def _flow(session, ts, src, dst, dport, proto, pk, src_b, dst_b, label, sport=None, rng=None):
    sport = sport if sport is not None else int(rng.integers(1024, 65535))
    return (session, ts, ts + 0.05 + 0.01 * pk, proto, src, sport, dst, dport, pk, src_b + dst_b, src_b, dst_b, "",
            label)


def _browsing(rng, session, hosts, t0, duration, rate_per_min=6.0):
    """Nền bình thường: mỗi host mở kết nối web tới máy chủ ngoài ngẫu nhiên, theo phân bố Poisson."""
    rows = []
    servers = [f"203.0.113.{i}" for i in range(1, 60)] + [SERVICE]
    for h in hosts:
        n = rng.poisson(rate_per_min * duration / 60)
        for ts in np.sort(rng.uniform(t0, t0 + duration, n)):
            dst = servers[rng.integers(len(servers))]
            rows.append(_flow(session, ts, h, dst, int(rng.choice([80, 443])), "tcp", int(rng.integers(6, 40)),
                              int(rng.integers(300, 2000)), int(rng.integers(2000, 60000)), "nen", rng=rng))
        if rng.random() < 0.9:                                  # DNS
            for ts in np.sort(rng.uniform(t0, t0 + duration, max(n // 3, 1))):
                rows.append(_flow(session, ts, h, f"{LAB}1", 53, "udp", 2, 70, 120, "nen", rng=rng))
    return rows


def _periodic(rng, t0, duration, period, jitter):
    """Các thời điểm gọi đều: chu kỳ ``period``, lệch ngẫu nhiên đều trong ±``jitter`` × chu kỳ."""
    ts, t = [], t0 + rng.uniform(0, period)
    while t < t0 + duration:
        ts.append(t)
        t += period * (1 + rng.uniform(-jitter, jitter))
    return ts


def simulate(kind, run_id, t0=0.0, duration=900.0, period=30.0, jitter=0.0, n_peers=12, seed=42) -> tuple:
    """Một lần chạy giả lập; trả về (flow, nhật ký). Ba host 192.168.50.41–43 là đối tượng của lần chạy.

    - ``centralized``: mỗi bot gọi máy điều khiển 192.168.50.50:8080 theo chu kỳ (jitter tùy chọn).
    - ``p2p``: mỗi bot gọi UDP tới các peer khác (bot kia và ``n_peers`` peer ngoài), danh sách peer
      đổi dần; peer gọi lại bot; một phần không được trả lời.
    - ``benign_centralized``: đối chứng: ba máy hỏi máy chủ cập nhật 192.168.50.30:443 theo chu kỳ
      (dịch vụ hợp lệ, cùng hình dạng với botnet tập trung).
    - ``benign_p2p``: đối chứng: ba máy chia sẻ file với nhau và vài peer ngoài theo từng đợt, TCP,
      lượng byte lớn, không đều.
    """
    if kind not in KINDS:
        raise ValueError(f"kiểu chưa hỗ trợ: {kind}")
    rng = np.random.default_rng(seed)
    session = f"sim_{run_id}"
    rows = _browsing(rng, session, BOTS + [f"{LAB}20"], t0, duration)
    if kind in ("centralized", "benign_centralized"):
        server, port, label = (CC_SERVER, 8080, "hanh_vi") if kind == "centralized" else (SERVICE, 443, "hanh_vi")
        for h in BOTS:
            for ts in _periodic(rng, t0, duration, period, jitter):
                rows.append(_flow(session, ts, h, server, port, "tcp", int(rng.integers(6, 10)),
                                  int(rng.integers(150, 260)), int(rng.integers(150, 400)), label, rng=rng))
    elif kind == "p2p":
        outside = [f"198.51.100.{i}" for i in range(1, 200)]
        peers = list(rng.choice(outside, n_peers, replace=False))
        for h in BOTS:
            port = int(rng.integers(20000, 60000))
            for ts in _periodic(rng, t0, duration, period / 4, max(jitter, 0.5)):
                if rng.random() < 0.15:                         # danh sách peer đổi dần
                    peers[rng.integers(len(peers))] = outside[rng.integers(len(outside))]
                cand = [b for b in BOTS if b != h] + peers
                dst = cand[rng.integers(len(cand))]
                answered = rng.random() > 0.35
                rows.append(_flow(session, ts, h, dst, port, "udp", 1 + int(answered), int(rng.integers(40, 120)),
                                  int(rng.integers(40, 120)) if answered else 0, "hanh_vi", rng=rng))
                if rng.random() < 0.6:                          # peer gọi lại
                    src = peers[rng.integers(len(peers))]
                    rows.append(_flow(session, ts + rng.uniform(0, 3), src, h, port, "udp", 2,
                                      int(rng.integers(40, 120)), int(rng.integers(40, 120)), "hanh_vi", rng=rng))
    else:                                                       # benign_p2p
        outside = [f"198.51.100.{i}" for i in range(200, 210)]
        for h in BOTS:
            n_bursts = max(int(duration / 300), 1)
            for start in rng.uniform(t0, t0 + duration, n_bursts):
                for _ in range(int(rng.integers(3, 10))):
                    dst = ([b for b in BOTS if b != h] + outside)[rng.integers(len(BOTS) - 1 + len(outside))]
                    ts = start + rng.exponential(20)
                    rows.append(_flow(session, ts, h, dst, 6881, "tcp", int(rng.integers(200, 2000)),
                                      int(rng.integers(10_000, 50_000)), int(rng.integers(200_000, 2_000_000)),
                                      "hanh_vi", rng=rng))
                    if rng.random() < 0.5:
                        rows.append(_flow(session, ts + rng.uniform(1, 10), dst, h, 6881, "tcp",
                                          int(rng.integers(200, 2000)), int(rng.integers(200_000, 2_000_000)),
                                          int(rng.integers(10_000, 50_000)), "hanh_vi", rng=rng))
    flows = pd.DataFrame(rows, columns=FLOW_COLUMNS).sort_values("ts", kind="stable").reset_index(drop=True)
    flows = flows[(flows["ts"] >= t0) & (flows["ts"] < t0 + duration)].reset_index(drop=True)
    log = {"ma_lan_chay": run_id, "kieu": kind, "topology": TOPOLOGY_OF[kind], "bat_dau": t0,
           "ket_thuc": t0 + duration, "ip_tham_gia": BOTS, "may_dieu_khien": CC_SERVER if kind == "centralized" else None,
           "hanh_vi": kind, "chu_ky_s": period, "jitter": jitter, "so_peer_ngoai": n_peers if kind == "p2p" else 0,
           "seed": seed, "gia_lap": True}
    return flows, log


def default_runs(seed=42) -> list:
    """Bộ lần chạy mặc định: mỗi kiểu 3 lần với lịch khác nhau (B19), chu kỳ và jitter thay đổi (B17, B18)."""
    runs = []
    plans = {"centralized": [(30, 0.0), (60, 0.2), (45, 0.4)], "p2p": [(30, 0.3), (60, 0.5), (20, 0.4)],
             "benign_centralized": [(30, 0.0), (60, 0.1), (45, 0.3)], "benign_p2p": [(0, 0), (0, 0), (0, 0)]}
    i = 0
    for kind, plan in plans.items():
        for k, (period, jitter) in enumerate(plan):
            runs.append({"kind": kind, "run_id": f"{kind}_{k + 1}", "t0": 10_000.0 * i, "duration": 900.0,
                         "period": float(period or 30), "jitter": float(jitter), "seed": seed + i})
            i += 1
    return runs


def label_runs(out_dir, cfg=None) -> pd.DataFrame:
    """Đặc trưng (T02, T03) và nhãn host–cửa sổ của các lần chạy giả lập, nhãn lấy từ nhật ký.

    Host tham gia có ít nhất một flow hành vi trong cửa sổ: ``suspect_host`` nếu lần chạy là botnet
    (topology theo nhật ký), ``normal_host`` (topology ``none``) nếu là đối chứng lành tính. Host
    192.168.50.20 chỉ duyệt web: ``normal_host``. Cửa sổ host tham gia không có flow hành vi: ``bo``.
    """
    from .graph_features import HOST_KEYS, build_features, graph_window

    size, step = graph_window(cfg)
    out_dir = Path(out_dir)
    logs = [json.loads(l) for l in (out_dir / "nhat_ky.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    parts = []
    for log in logs:
        flows = pd.read_csv(out_dir / f"sim_{log['ma_lan_chay']}.flows.csv.gz", dtype={"src": str, "dst": str})
        hosts = log["ip_tham_gia"] + [f"{LAB}20"]
        feats = build_features(flows, hosts, cfg)
        act = flows[(flows["label"] == "hanh_vi") & flows["src"].isin(log["ip_tham_gia"])]
        o = np.floor(act["ts"].to_numpy(float) / step).astype("int64")
        k = int(round(size / step))
        ws = pd.DataFrame({"host": np.repeat(act["src"].to_numpy(), k),
                           "window_start": (np.repeat(o, k) - np.tile(np.arange(k), len(o))) * step}).drop_duplicates()
        feats = feats.merge(ws.assign(_co=1), on=["host", "window_start"], how="left")
        bot_run = log["topology"] != "none"
        part_of_run = feats["host"].isin(log["ip_tham_gia"]) & feats["_co"].eq(1)
        lab = np.where(part_of_run, "suspect_host" if bot_run else "normal_host", "bo")
        lab = np.where(feats["host"] == f"{LAB}20", "normal_host", lab)
        feats["label_host"] = lab
        feats["label_topology"] = np.where(lab == "suspect_host", log["topology"],
                                           np.where(lab == "normal_host", "none", ""))
        feats["lan_chay"] = log["ma_lan_chay"]
        feats["kieu"] = log["kieu"]
        # bỏ cửa sổ chỉ chạm một phần lần chạy (đầu và cuối) để mọi cửa sổ có đủ 120 giây dữ liệu
        inside = (feats["window_start"] >= log["bat_dau"]) & (feats["window_start"] + size <= log["ket_thuc"])
        parts.append(feats[inside].drop(columns="_co"))
    return pd.concat(parts, ignore_index=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sinh flow giả lập cho nhận diện topology (không gửi gói).")
    parser.add_argument("--out", required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    logs = []
    for r in default_runs(args.seed):
        flows, log = simulate(r["kind"], r["run_id"], r["t0"], r["duration"], r["period"], r["jitter"], seed=r["seed"])
        flows.to_csv(out / f"sim_{r['run_id']}.flows.csv.gz", index=False, compression="gzip")
        logs.append(log)
        print(f"{r['run_id']}: {len(flows)} flow")
    (out / "nhat_ky.jsonl").write_text("\n".join(json.dumps(l, ensure_ascii=False) for l in logs) + "\n",
                                       encoding="utf-8")
    print(f"Đã ghi {len(logs)} lần chạy vào {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

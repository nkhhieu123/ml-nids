"""Học lại ba module trên dữ liệu lab (lần chạy ``train``), chọn ngưỡng trên ``val``, lưu bộ mô hình lab.

Chặng 11 cho thấy mô hình học từ CIC-IDS2017 và CTU-13 có ba lỗi trên lab: Gaussian báo máy chủ dịch vụ suốt
bản thu, bộ phân loại báo nhầm ``dos`` khi chia sẻ dữ liệu lớn, module botnet bỏ sót mọi bot. Module này:

- **Gaussian**: fit lại trên cửa sổ bình thường của các lần ``train`` (cùng đặc trưng, cùng cách co hiệp phương
  sai), chọn ngưỡng trên ``val`` bằng đúng cách của Chặng 6.
- **Bộ phân loại**: giữ tham số Random Forest đã chọn ở C07-T04; train = train CIC + train lab; đo trên
  validation CIC, ``val`` lab và test CIC để chắc không làm hỏng kết quả cũ.
- **Botnet**: cùng loại mô hình và tham số như Chặng 8; train trên host–cửa sổ 120 giây của ``train`` lab, chọn
  ngưỡng trên ``val``; chọn lại quy tắc topology trên ``val``.

Không đọc lần chạy ``test`` nào của lab. Mô hình lưu ở ``models/lab/``; cấu hình dùng chúng là ``config/lab.yaml``.

    cd src
    python -m nids.hoc_lai_lab ../data/pcap/lab/*-train-01.pcap ../data/pcap/lab/*-val-01.pcap \
        --nhat-ky ../data/run_logs --cic ../output/features/cic17_wednesday ../output/features/cic17_friday \
        --chon ../docs/hinh/phan_loai_chon.json --out ../docs/hinh
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

from . import botnet as bn
from . import classifier as clf
from . import gaussian as gs
from .config import DEFAULT_CONFIG, PROJECT_ROOT, load_config
from .graph_features import build_features, graph_window
from .lab_cua_so import rules_from_runlog
from .labeling import (STATUS_MATCHED, STATUS_UNMATCHED, label_flows, label_windows, load_flows_for_labels,
                       load_windows_for_labels)
from .thuc_nghiem import _epoch, _ips, load_runlog

MIN_OVERLAP_S = 60.0          # host–cửa sổ 120 giây là của bot khi chồng lên hành vi ít nhất một nửa cửa sổ
TOPOLOGY_GRID = {"min_peer_vao": (1, 2, 3, 5), "min_udp": (0.05, 0.1, 0.2, 0.3, 0.5), "min_entropy_vao": (0.0, 0.5, 0.8)}


def prepare_run(pcap, entries, networks, cfg, cache) -> dict:
    """Bảng cửa sổ 10 giây (đặc trưng + nhãn) và bảng host–cửa sổ 120 giây (đặc trưng + nhãn bot) của một lần chạy."""
    from .pipeline import extract, load_flows, load_windows, monitored_hosts

    run_id = Path(pcap).stem
    prefix = Path(cache) / run_id
    if not Path(f"{prefix}.windows.csv").exists():
        extract(pcap, cache, networks)
    windows = load_windows(prefix)
    raw = load_flows_for_labels(f"{prefix}.flows.csv")
    labels = label_windows(load_windows_for_labels(f"{prefix}.windows.csv"), raw,
                           label_flows(raw, rules_from_runlog(entries), 1.0), cfg["labeling"]["window_min_attack_share"])
    windows = windows.merge(labels, on=["host", "window_start"], how="left", validate="one_to_one")

    flows = load_flows(prefix)
    bcfg = dict(cfg)
    bcfg["botnet"] = {**(cfg.get("botnet") or {}), "local_nets": list(networks)}
    feats = build_features(flows, monitored_hosts(flows, networks), bcfg)
    size, _ = graph_window(bcfg)
    bots, others, t0, t1, topo = set(), set(), None, None, "none"
    for g in entries:
        if g.get("nhan") == "botnet":
            bots, others = set(_ips(g["ip_nguon"])), set(_ips(g["ip_dich"])) - set(_ips(g["ip_nguon"]))
            t0, t1, topo = _epoch(g, "bat_dau"), _epoch(g, "ket_thuc"), (g.get("tham_so") or {}).get("topology", "none")
    label = np.full(len(feats), bn.NORMAL, dtype=object)
    if bots:
        ws = feats["window_start"].to_numpy(float)
        overlap = np.clip(np.minimum(ws + size, t1) - np.maximum(ws, t0), 0, None)
        is_bot = feats["host"].isin(bots).to_numpy()
        label[is_bot & (overlap >= MIN_OVERLAP_S)] = bn.SUSPECT
        label[is_bot & (overlap > 0) & (overlap < MIN_OVERLAP_S)] = None       # mơ hồ: bỏ
        label[feats["host"].isin(others).to_numpy()] = None                    # máy điều khiển: không học, không chấm
    feats = feats.assign(**{bn.LABEL_COL: label, bn.TOPOLOGY_COL: np.where(label == bn.SUSPECT, topo, "none")})
    role, variant = run_id.rsplit("-", 2)[1], run_id.rsplit("-", 2)[0]
    return {"run_id": run_id, "role": role, "variant": variant,
            "windows": windows.assign(run_id=run_id, variant=variant),
            "graph": feats[feats[bn.LABEL_COL].notna()].assign(run_id=run_id, variant=variant)}


def binary(y, pred) -> dict:
    y, pred = np.asarray(y, bool), np.asarray(pred, bool)
    tp, fp, fn = int((y & pred).sum()), int((~y & pred).sum()), int((y & ~pred).sum())
    p, r = (tp / (tp + fp) if tp + fp else 0.0), (tp / (tp + fn) if tp + fn else 0.0)
    return {"so_mau": len(y), "duong": int(y.sum()), "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
            "ty_le_am_bi_bao": round(fp / max(int((~y).sum()), 1), 4)}


def retrain_gaussian(train, val, cfg, out_dir) -> dict:
    old = gs.load_model(PROJECT_ROOT / cfg["pipeline"]["models"]["anomaly"])
    sure = lambda d: gs.fill_empty(d[d["label_anomaly"].isin(["normal", "anomaly"])])
    tr, va = sure(train), sure(val)
    new = gs.GaussianDetector(old.features, old.covariance).fit(tr[tr["label_anomaly"] == "normal"])
    y = (va["label_anomaly"] == "anomaly").to_numpy()
    g = cfg["gaussian"]
    new.threshold = gs.choose_threshold(new.score(va), y, g["threshold"], g["target_fpr"], g["threshold_band"])
    new.info["du_lieu"] = "lab: cửa sổ bình thường của các lần chạy train; ngưỡng chọn trên val"
    gs.save_model(new, Path(out_dir) / "gaussian_windows.joblib", {"gaussian": g})
    res = {"dac_trung": new.features, "so_mau_fit": int((tr["label_anomaly"] == "normal").sum()), "nguong": new.threshold}
    server = (va["host"] == cfg["lab"]["may_chu_dich"]).to_numpy() & ~y
    for name, m in (("cu", old), ("moi", new)):
        pred = m.score(va) > m.threshold
        res[name] = {"val": binary(y, pred), "nguong": m.threshold,
                     "may_chu_binh_thuong_bi_bao": round(float(pred[server].mean()), 4)}
    return res


def lab_class_metrics(model, frame) -> dict:
    m = clf.multiclass_metrics(frame[clf.LABEL_COL], model.predict(frame))
    return {"macro_f1": m["macro_f1"], **{c: {k: v[k] for k in ("precision", "recall", "so_mau")}
                                           for c, v in m["theo_lop"].items()}}


def retrain_classifier(train, val, cic_prefixes, chon, cfg, out_dir) -> dict:
    ccfg = clf.classifier_config(cfg)
    best = json.loads(Path(chon).read_text(encoding="utf-8"))["mo_hinh"]["random_forest"]["tot_nhat"]
    cic = clf.load_data(cic_prefixes, ccfg["sessions"])
    lab = pd.concat([train.assign(split="train"), val.assign(split="validation")], ignore_index=True)
    df = pd.concat([cic, lab[[c for c in cic.columns if c in lab.columns]]], ignore_index=True)
    data = clf.prepare_data(df, best["ty_le_can_bang"], ccfg["random_seed"], ccfg["drop_train_duplicates"])
    new = clf.AttackClassifier("random_forest", best["tham_so"], ccfg["random_seed"]).fit(data["train"], data["train_full"])
    new.info.update({"ty_le_can_bang": best["ty_le_can_bang"], "du_lieu": data["info"],
                     "ghi_chu": "train = train CIC-IDS2017 + train lab"})
    clf.save_model(new, Path(out_dir) / "phan_loai_rf_windows.joblib", cfg)
    old = clf.load_model(PROJECT_ROOT / cfg["pipeline"]["models"]["attack_classification"])
    is_cic = lambda d: d["session"].str.startswith("cic17")
    parts = {"validation_cic": data["validation"][is_cic(data["validation"])],
             "val_lab": data["validation"][~is_cic(data["validation"])], "test_cic": data["test"]}
    res = {"tham_so": best["tham_so"], "lop_train": data["info"]["lop_train"]}
    for name, m in (("cu", old), ("moi", new)):
        res[name] = {k: lab_class_metrics(m, v) for k, v in parts.items()}
    v = parts["val_lab"]
    for name, m in (("cu", old), ("moi", new)):
        wrong = v[(v[clf.LABEL_COL] == "benign") & (m.predict(v) != "benign")]
        res[name]["val_lab_benign_bi_bao"] = {k: int(n) for k, n in wrong["session"].str.rsplit("-", n=2).str[0].value_counts().items()}
    return res


def retrain_botnet(train, val, cfg, out_dir) -> dict:
    old = bn.load_model(PROJECT_ROOT / cfg["pipeline"]["models"]["botnet_topology"])
    new = bn.BotnetDetector(old.kind, old.params, cfg["random_seed"]).fit(train)
    y = (val[bn.LABEL_COL] == bn.SUSPECT).to_numpy()
    score = new.score(val)
    new.threshold = float(round(gs.choose_threshold(score, y, "f1"), 4))
    res = {"loai": old.kind, "tham_so": old.params, "lop_train": new.info["lop_train"], "nguong": new.threshold}
    for name, m in (("cu", old), ("moi", new)):
        pred = m.score(val) >= m.threshold
        res[name] = {"val": binary(y, pred), "nguong": m.threshold,
                     "theo_bien_the": {k: binary(y[(val["variant"] == k).to_numpy()], pred[(val["variant"] == k).to_numpy()])
                                       for k in sorted(val["variant"].unique())}}
    # Quy tắc topology: chọn trên cửa sổ bot của val (k4 -> centralized, k5 -> p2p)
    bots = val[y]
    truth = bots[bn.TOPOLOGY_COL].to_numpy()
    rows = []
    for a in TOPOLOGY_GRID["min_peer_vao"]:
        for b in TOPOLOGY_GRID["min_udp"]:
            for c in TOPOLOGY_GRID["min_entropy_vao"]:
                rule = {"min_peer_vao": a, "min_udp": b, "min_entropy_vao": c}
                got = bn.recognize_topology(bots, np.ones(len(bots), bool), rule)
                rows.append({**rule, "dung": round(float((got == truth).mean()), 4),
                             "dung_p2p": round(float((got == truth)[truth == "p2p"].mean()), 4),
                             "dung_centralized": round(float((got == truth)[truth == "centralized"].mean()), 4)})
    # tốt nhất; bằng nhau thì lấy quy tắc chặt nhất (gần mặc định nhất)
    best = max(rows, key=lambda r: (r["dung"], r["min_peer_vao"], r["min_udp"], r["min_entropy_vao"]))
    default = next(r for r in rows if (r["min_peer_vao"], r["min_udp"], r["min_entropy_vao"]) == (5, 0.5, 0.8))
    res["topology"] = {"mac_dinh": default, "chon": best, "so_cua_so_bot_val": len(bots),
                       "trung_vi_bot_p2p": {c: round(float(bots[truth == "p2p"][c].median()), 3)
                                            for c in ("so_peer_vao", "ty_le_udp", "entropy_peer_vao")}}
    new.info["du_lieu"] = "lab: host–cửa sổ 120 giây của các lần chạy train; ngưỡng chọn trên val"
    bn.save_model(new, Path(out_dir) / "botnet_rf.joblib", {"nguong": new.threshold})
    res["quan_trong"] = bn.importance(new, top=8)
    return res


def write_lab_config(model_dir, topology_rule, mode, path) -> None:
    """config/lab.yaml = config/default.yaml với mô hình lab, quy tắc topology và chế độ chọn trên val."""
    raw = yaml.safe_load(Path(DEFAULT_CONFIG).read_text(encoding="utf-8"))
    rel = Path(model_dir).resolve().relative_to(PROJECT_ROOT).as_posix()
    raw["pipeline"]["models"] = {"anomaly": f"{rel}/gaussian_windows.joblib",
                                 "attack_classification": f"{rel}/phan_loai_rf_windows.joblib",
                                 "botnet_topology": f"{rel}/botnet_rf.joblib"}
    raw["pipeline"]["mode"] = mode
    raw["botnet"]["topology_rule"] = {k: topology_rule[k] for k in ("min_peer_vao", "min_udp", "min_entropy_vao")}
    head = ("# Cấu hình cho mạng lab: sinh bởi `python -m nids.hoc_lai_lab` từ config/default.yaml (QĐ-068).\n"
            "# Khác default.yaml ở: pipeline.models (mô hình học lại trên lab), pipeline.mode, botnet.topology_rule.\n"
            "# Không sửa tay; sửa default.yaml rồi chạy lại.\n")
    Path(path).write_text(head + yaml.safe_dump(raw, allow_unicode=True, sort_keys=False), encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Học lại ba module trên lần chạy train của lab, chọn ngưỡng trên val.")
    ap.add_argument("pcap", nargs="+", help="PCAP của các lần chạy train và val")
    ap.add_argument("--nhat-ky", required=True)
    ap.add_argument("--cic", nargs="+", required=True, help="tiền tố bảng đặc trưng CIC của bộ phân loại")
    ap.add_argument("--chon", required=True, help="JSON của classifier chon")
    ap.add_argument("--models", default=str(PROJECT_ROOT / "models" / "lab"))
    ap.add_argument("--cache", default=str(PROJECT_ROOT / "output" / "lab_features"))
    ap.add_argument("--che-do", default="doc_lap", help="pipeline.mode ghi vào config/lab.yaml")
    ap.add_argument("--out", required=True, help="thư mục ghi lab_hoc_lai.json")
    a = ap.parse_args(argv)
    cfg = load_config()
    nets = [cfg["lab"]["subnet"]]
    runs = [prepare_run(p, load_runlog(a.nhat_ky, p), nets, cfg, a.cache) for p in a.pcap]
    if any(r["role"] == "test" for r in runs):
        raise SystemExit("Không đưa lần chạy test vào bước học lại.")
    part = lambda role, key: pd.concat([r[key] for r in runs if r["role"] == role], ignore_index=True)
    out = {"lan_chay": {role: sorted(r["run_id"] for r in runs if r["role"] == role) for role in ("train", "val")},
           "gaussian": retrain_gaussian(part("train", "windows"), part("val", "windows"), cfg, a.models),
           "phan_loai": retrain_classifier(part("train", "windows"), part("val", "windows"), a.cic, a.chon, cfg, a.models),
           "botnet": retrain_botnet(part("train", "graph"), part("val", "graph"), cfg, a.models)}
    write_lab_config(a.models, out["botnet"]["topology"]["chon"], a.che_do, PROJECT_ROOT / "config" / "lab.yaml")
    od = Path(a.out)
    od.mkdir(parents=True, exist_ok=True)
    (od / "lab_hoc_lai.json").write_text(json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(json.dumps({k: {n: v.get(n) for n in ("cu", "moi", "nguong", "topology") if n in v} for k, v in out.items()
                      if k != "lan_chay"}, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())

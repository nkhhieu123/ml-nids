"""Pipeline offline: PCAP → flow, cửa sổ → ba module → cảnh báo (Chặng 9).

- C09-T01: nạp artifact (mô hình, biến đổi, ngưỡng) và kiểm tra schema trước khi chạy
  (docs/53_nap_artifact.md, QĐ-043).
- C09-T02: chạy PCAP qua toàn bộ pipeline: trích flow và cửa sổ, ba module, thời gian từng bước
  (docs/54_chay_pcap.md, QĐ-044).
- C09-T03: mỗi module tạo đầu ra độc lập theo schema cảnh báo chung; hợp nhất vào một file, tổng hợp
  theo host (docs/55_hop_nhat_canh_bao.md, QĐ-045).

    python -m nids.pipeline kiem-tra
    python -m nids.pipeline chay output/pcap/fri_quet.pcap --net 192.168.10.0/24 --net 172.16.0.0/24 --out output/pipeline

Ba module dùng mô hình đã lưu ở Chặng 6–8; pipeline không học gì.
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .config import PROJECT_ROOT, load_config
from .scope import MODULE_ANOMALY, MODULE_ATTACK, MODULE_BOTNET, MODULES

# File mô hình mặc định của từng module, trong paths.model_dir
DEFAULT_MODELS = {MODULE_ANOMALY: "gaussian_windows.joblib", MODULE_ATTACK: "phan_loai_rf_windows.joblib",
                  MODULE_BOTNET: "botnet_rf.joblib"}
# Bảng đầu vào của từng module
INPUT_TABLE = {MODULE_ANOMALY: "windows", MODULE_ATTACK: "windows", MODULE_BOTNET: "host_windows_120s"}
ERROR, WARNING = "loi", "canh_bao"


@dataclass
class Artifact:
    module: str
    path: Path
    model: object
    meta: dict = field(default_factory=dict)

    @property
    def features(self) -> list:
        return list(self.model.features)

    @property
    def threshold(self):
        return getattr(self.model, "threshold", None)


def pipeline_config(cfg=None) -> dict:
    p = dict((cfg or {}).get("pipeline") or {})
    model_dir = Path((cfg or {}).get("paths", {}).get("model_dir", "models"))
    if not model_dir.is_absolute():
        model_dir = PROJECT_ROOT / model_dir
    models = {m: str(model_dir / f) for m, f in DEFAULT_MODELS.items()}
    models.update({k: v if Path(v).is_absolute() else str(PROJECT_ROOT / v) for k, v in (p.get("models") or {}).items()})
    p["models"] = models
    p.setdefault("mode", "doc_lap")
    p.setdefault("merge_gap_s", 30.0)
    return p


def _loader(module):
    if module == MODULE_ANOMALY:
        from .gaussian import load_model
    elif module == MODULE_ATTACK:
        from .classifier import load_model
    else:
        from .botnet import load_model
    return load_model


def load_artifacts(cfg=None, modules=MODULES) -> dict:
    """Nạp mô hình của từng module kèm file .json metadata. Lỗi nạp (thiếu file, sai loại) báo ngay."""
    pc = pipeline_config(cfg)
    out = {}
    for m in modules:
        path = Path(pc["models"][m])
        if not path.exists():
            raise FileNotFoundError(f"{m}: không có file mô hình {path}")
        model = _loader(m)(path)
        meta_path = path.with_suffix(".json")
        meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
        out[m] = Artifact(m, path, model, meta)
    return out


def expected_inputs(module) -> list:
    """Cột đầu vào hợp lệ của module: đặc trưng cửa sổ 10 giây theo schema, hoặc đặc trưng host–cửa sổ 120 giây."""
    if module in (MODULE_ANOMALY, MODULE_ATTACK):
        from .dataset import feature_columns
        return feature_columns("windows")
    from .graph_features import BEACON_FEATURES, GRAPH_FEATURES
    return GRAPH_FEATURES + BEACON_FEATURES


def check_artifact(a: Artifact) -> list:
    """Danh sách vấn đề (mức, nội dung) của một artifact: đặc trưng, metadata, ngưỡng, phiên bản mã."""
    problems = []
    allowed = set(expected_inputs(a.module))
    missing = [f for f in a.features if f not in allowed]
    if missing:
        problems.append((ERROR, f"đặc trưng không có trong schema đầu vào ({INPUT_TABLE[a.module]}): {missing}"))
    if not a.meta:
        problems.append((ERROR, "thiếu file .json metadata"))
    elif a.meta.get("dac_trung") and list(a.meta["dac_trung"]) != a.features:
        problems.append((ERROR, "danh sách đặc trưng trong .json khác mô hình"))
    if a.module in (MODULE_ANOMALY, MODULE_BOTNET) and a.threshold is None:
        problems.append((ERROR, "mô hình chưa có ngưỡng"))
    if a.module == MODULE_ATTACK:
        from .scope import ATTACK_LABELS
        classes = set(a.model.classes)
        if not classes <= set(ATTACK_LABELS):
            problems.append((ERROR, f"lớp ngoài tập nhãn đã chốt: {sorted(classes - set(ATTACK_LABELS))}"))
    src = a.meta.get("ma_nguon") or {}
    if src.get("co_sua_chua_commit"):
        problems.append((WARNING, f"tạo khi mã nguồn có sửa chưa commit (commit {str(src.get('commit'))[:8]}); "
                                  "nên huấn luyện lại từ mã đã commit"))
    if not src.get("commit"):
        problems.append((WARNING, "metadata không ghi commit mã nguồn"))
    return problems


def check_table(df, artifact) -> None:
    """Báo lỗi nếu bảng đầu vào thiếu cột đặc trưng mà mô hình cần."""
    missing = [f for f in artifact.features if f not in df.columns]
    if missing:
        raise ValueError(f"{artifact.module}: bảng đầu vào thiếu cột {missing}")


def check_all(cfg=None) -> dict:
    """Nạp và kiểm tra mọi artifact; trả về báo cáo (không dừng ở cảnh báo, dừng ở lỗi nạp)."""
    arts = load_artifacts(cfg)
    report = {}
    for m, a in arts.items():
        report[m] = {"file": str(a.path), "loai": type(a.model).__name__, "so_dac_trung": len(a.features),
                     "nguong": a.threshold, "commit": (a.meta.get("ma_nguon") or {}).get("commit"),
                     "van_de": [{"muc": lv, "noi_dung": msg} for lv, msg in check_artifact(a)]}
    report["hop_le"] = all(p["muc"] != ERROR for m in MODULES for p in report[m]["van_de"])
    return report


# ---- C09-T02: chạy PCAP qua toàn bộ pipeline ----

class Timer:
    """Đo thời gian từng bước (giây, đồng hồ thật)."""

    def __init__(self):
        self.steps = {}

    def __call__(self, name):
        import time
        timer = self

        class _Step:
            def __enter__(self):
                self.t = time.perf_counter()

            def __exit__(self, *exc):
                timer.steps[name] = round(timer.steps.get(name, 0.0) + time.perf_counter() - self.t, 3)
        return _Step()


def extract(pcap, out_dir, networks, config_path=None, name=None) -> Path:
    """PCAP → bảng flow và cửa sổ 10 giây (cùng mã ``nids.feature_export`` như lúc huấn luyện, B12)."""
    from .feature_export import export

    name = name or Path(pcap).stem
    export(pcap, out_dir, name, networks, config_path)
    return Path(out_dir) / name


def load_windows(prefix) -> "pd.DataFrame":
    import pandas as pd
    df = pd.read_csv(f"{prefix}.windows.csv", dtype={"host": str})
    df.insert(0, "session", Path(prefix).name)
    return df


def load_flows(prefix) -> "pd.DataFrame":
    """Bảng flow của dự án đổi sang bảng flow chung của module botnet."""
    import pandas as pd

    from .ctu13 import from_project_flows
    cols = ["first_ts", "last_ts", "protocol", "fwd_ip", "fwd_port", "bwd_ip", "bwd_port", "packets", "bytes",
            "fwd_bytes", "bwd_bytes"]
    f = pd.read_csv(f"{prefix}.flows.csv", usecols=cols, dtype={"fwd_ip": str, "bwd_ip": str, "protocol": str})
    return from_project_flows(f.dropna(subset=["first_ts"]), Path(prefix).name)


def monitored_hosts(flows, networks) -> list:
    """Host trong các mạng giám sát xuất hiện ở một đầu của flow."""
    import pandas as pd

    from .graph_features import in_networks
    ips = pd.unique(pd.concat([flows["src"], flows["dst"]], ignore_index=True).astype(str))
    return sorted(ip for ip, ok in zip(ips, in_networks(ips, networks)) if ok)


def score_anomaly(art, windows):
    check_table(windows, art)
    return art.model.predict_frame(windows)                     # host, window_start, window_end, d2, du_doan


def score_attack(art, windows):
    from .classifier import predict_frame
    check_table(windows, art)
    out = predict_frame(art.model, windows)
    out["window_end"] = windows["window_end"].to_numpy()
    return out


def score_botnet(art, flows, hosts, networks, cfg=None, topology_rule=None):
    """Đặc trưng đồ thị và beaconing 120 giây của ``hosts``, điểm botnet và topology theo quy tắc."""
    import numpy as np

    from .botnet import SUSPECT, recognize_topology
    from .graph_features import build_features, graph_window
    cfg = dict(cfg or {})
    cfg["botnet"] = {**(cfg.get("botnet") or {}), "local_nets": list(networks)}
    feats = build_features(flows, hosts, cfg)
    if feats.empty:
        return feats.assign(diem=[], du_doan=[], topology=[])
    check_table(feats, art)
    size, _ = graph_window(cfg)
    score = art.model.score(feats)
    out = feats[["session", "host", "window_start"]].copy()
    out["window_end"] = out["window_start"] + size
    out["diem"] = score
    out["du_doan"] = np.where(score >= art.threshold, SUSPECT, "normal_host")
    from .botnet import topology_rule as default_rule
    out["topology"] = recognize_topology(feats, out["du_doan"] == SUSPECT, topology_rule or default_rule(cfg))
    return out


def run_independent(arts, windows, flows, networks, cfg=None, timer=None) -> dict:
    """Ba module chạy độc lập trên cùng dữ liệu (docs/02 mục 1: anomaly không là cổng lọc)."""
    timer = timer or Timer()
    out = {}
    with timer(MODULE_ANOMALY):
        out[MODULE_ANOMALY] = score_anomaly(arts[MODULE_ANOMALY], windows)
    with timer(MODULE_ATTACK):
        out[MODULE_ATTACK] = score_attack(arts[MODULE_ATTACK], windows)
    with timer(MODULE_BOTNET):
        out[MODULE_BOTNET] = score_botnet(arts[MODULE_BOTNET], flows, monitored_hosts(flows, networks),
                                          networks, cfg)
    return out


def run_pcap(pcap, out_dir, networks, cfg=None, config_path=None, mode="doc_lap", name=None) -> dict:
    """PCAP → bảng đặc trưng → ba module. Trả về kết quả từng module, thời gian từng bước, số liệu."""
    timer = Timer()
    arts = load_artifacts(cfg)
    bad = {m: [p for p in check_artifact(a) if p[0] == ERROR] for m, a in arts.items()}
    if any(bad.values()):
        raise ValueError(f"artifact không hợp lệ: {bad}")
    with timer("trich_xuat"):
        prefix = extract(pcap, out_dir, networks, config_path, name)
    with timer("doc_bang"):
        windows, flows = load_windows(prefix), load_flows(prefix)
    res = run_independent(arts, windows, flows, networks, cfg, timer)
    return {"prefix": prefix, "ket_qua": res, "thoi_gian_s": timer.steps, "artifact": arts,
            "so_luong": {"flow": len(flows), "cua_so": len(windows), "host_giam_sat": len(monitored_hosts(flows, networks))},
            "che_do": mode}


# ---- C09-T03: đầu ra độc lập của từng module, hợp nhất cảnh báo ----

ALERT_LABELS = {"anomaly", "port_scan", "dos", "suspect_host", "centralized", "p2p"}


def module_alerts(module, df, art, run_id="", log_all=False) -> list:
    """Bảng dự đoán của một module thành danh sách ``Alert`` theo schema chung (docs/02 mục 3).

    Module botnet có hai nhóm đầu ra riêng: nhãn host (``suspect_host``) và topology (``centralized``,
    ``p2p``); chỉ cửa sổ bị nghi mới có dòng topology.
    """
    from .alerts import Alert

    out = []
    if df is None or df.empty:
        return out
    rows = df if log_all else df[df["du_doan"].isin(ALERT_LABELS)]
    for r in rows.itertuples(index=False):
        ws, we = float(r.window_start), float(r.window_end)
        if module == MODULE_ANOMALY:
            out.append(Alert(module, r.du_doan, ws, we, src_ip=r.host, score=float(r.d2),
                             threshold=float(art.threshold), run_id=run_id))
        elif module == MODULE_ATTACK:
            probs = {c: getattr(r, f"p_{c}") for c in art.model.classes}
            out.append(Alert(module, r.du_doan, ws, we, src_ip=r.host, score=float(probs[r.du_doan]), run_id=run_id,
                             detail=" ".join(f"p_{c}={v:.3f}" for c, v in probs.items())))
        else:
            out.append(Alert(module, "suspect_host" if r.du_doan == "suspect_host" else "normal_host", ws, we,
                             src_ip=r.host, score=float(r.diem), threshold=float(art.threshold), run_id=run_id,
                             detail="mức nghi vấn, không khẳng định có mã độc"))
            if r.du_doan == "suspect_host":
                out.append(Alert(module, r.topology, ws, we, src_ip=r.host, run_id=run_id,
                                 detail="topology theo quy tắc (QĐ-042)"))
    return out


def merge_alerts(alert_lists) -> list:
    """Hợp nhất cảnh báo của các module: một danh sách, sắp theo thời gian, rồi host, rồi module."""
    from .scope import MODULES as ORDER
    merged = [a for lst in alert_lists for a in lst]
    return sorted(merged, key=lambda a: (a.window_start, a.src_ip, ORDER.index(a.module), a.label))


def host_overview(alerts) -> dict:
    """Theo host: module nào báo, nhãn gì, bao nhiêu cửa sổ, lần đầu và lần cuối; host có ≥ 2 module báo."""
    hosts = {}
    for a in alerts:
        if not a.is_alert:
            continue
        h = hosts.setdefault(a.src_ip, {"module": {}, "dau": a.window_start, "cuoi": a.window_end})
        h["module"].setdefault(a.module, {})
        h["module"][a.module][a.label] = h["module"][a.module].get(a.label, 0) + 1
        h["dau"], h["cuoi"] = min(h["dau"], a.window_start), max(h["cuoi"], a.window_end)
    for h in hosts.values():
        h["so_module_bao"] = len(h["module"])
    return {"theo_host": dict(sorted(hosts.items(), key=lambda kv: -kv[1]["so_module_bao"])),
            "host_nhieu_module": sorted(k for k, v in hosts.items() if v["so_module_bao"] >= 2)}


def write_alerts(alerts, path, log_all=False, stream=None) -> int:
    """Ghi cảnh báo ra CSV qua ``AlertSink`` (ghi đè file cũ); trả về số dòng ghi."""
    import io

    from .alerts import AlertSink
    path = Path(path)
    if path.exists():
        path.unlink()
    n = 0
    with AlertSink(path, stream=stream if stream is not None else io.StringIO(), log_all=log_all) as sink:
        for a in alerts:
            n += sink.emit(a)
    return n


def run_alerts(run, arts, run_id="", log_all=False) -> list:
    return merge_alerts(module_alerts(m, df, arts[m], run_id, log_all) for m, df in run["ket_qua"].items())


def write_predictions(run) -> dict:
    """Ghi bảng dự đoán của từng module cạnh bảng đặc trưng; trả về đường dẫn."""
    paths = {}
    for m, df in run["ket_qua"].items():
        p = Path(f"{run['prefix']}.{m}.csv")
        df.to_csv(p, index=False)
        paths[m] = str(p)
    return paths


def cmd_run(args):
    cfg = load_config(args.config)
    run = run_pcap(args.pcap, args.out, args.net, cfg, args.config, args.che_do, args.ten)
    paths = write_predictions(run)
    run_id = args.ma_lan_chay or Path(run["prefix"]).name
    alerts = run_alerts(run, run["artifact"], run_id)
    paths["canh_bao"] = str(Path(f"{run['prefix']}.alerts.csv"))
    n_alerts = write_alerts(alerts, paths["canh_bao"])
    overview = host_overview(alerts)
    summary = {"pcap": args.pcap, "che_do": run["che_do"], "thoi_gian_s": run["thoi_gian_s"], "so_luong": run["so_luong"],
               "bao_dong": {m: int((df["du_doan"].isin(["anomaly", "port_scan", "dos", "suspect_host"])).sum())
                            for m, df in run["ket_qua"].items()},
               "so_canh_bao_hop_nhat": n_alerts, "host_nhieu_module": overview["host_nhieu_module"],
               "theo_host": overview["theo_host"], "file": paths}
    Path(f"{run['prefix']}.pipeline.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))


def cmd_check(args):
    rep = check_all(load_config(args.config))
    for m in MODULES:
        r = rep[m]
        print(f"{m}: {r['loai']}, {r['so_dac_trung']} đặc trưng, ngưỡng {r['nguong']}, commit {str(r['commit'])[:8]}")
        for p in r["van_de"]:
            print(f"   [{p['muc']}] {p['noi_dung']}")
    print("Hợp lệ:", rep["hop_le"])
    if args.out:
        Path(args.out).write_text(json.dumps(rep, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return 0 if rep["hop_le"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Pipeline offline: PCAP qua ba module, cảnh báo hợp nhất.")
    sub = parser.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("kiem-tra", help="nạp và kiểm tra artifact của ba module (C09-T01)")
    p.add_argument("--out", help="ghi báo cáo JSON")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_check)
    p = sub.add_parser("chay", help="chạy một PCAP qua toàn bộ pipeline (C09-T02)")
    p.add_argument("pcap")
    p.add_argument("--net", action="append", required=True, help="mạng giám sát, ví dụ 192.168.10.0/24")
    p.add_argument("--out", required=True, help="thư mục ghi bảng đặc trưng và dự đoán")
    p.add_argument("--ten", help="tên tiền tố, mặc định tên file PCAP")
    p.add_argument("--che-do", choices=("doc_lap",), default="doc_lap")
    p.add_argument("--ma-lan-chay", help="run_id ghi vào cảnh báo, khớp nhật ký kịch bản; mặc định tên tiền tố")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_run)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

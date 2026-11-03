"""Pipeline offline: PCAP → flow, cửa sổ → ba module → cảnh báo (Chặng 9).

- C09-T01: nạp artifact (mô hình, biến đổi, ngưỡng) và kiểm tra schema trước khi chạy
  (docs/53_nap_artifact.md, QĐ-043).
- C09-T02: chạy PCAP qua toàn bộ pipeline: trích flow và cửa sổ, ba module, thời gian từng bước
  (docs/54_chay_pcap.md, QĐ-044).
- C09-T03: mỗi module tạo đầu ra độc lập theo schema cảnh báo chung; hợp nhất vào một file, tổng hợp
  theo host (docs/55_hop_nhat_canh_bao.md, QĐ-045).
- C09-T04: chế độ tuần tự Gaussian → phân loại → kiểm tra botnet (docs/56_che_do_tuan_tu.md, QĐ-046).
- C09-T05: so sánh hai chế độ về bỏ sót (theo nhãn của lịch tấn công) và thời gian (docs/57_so_sanh_che_do.md).
- C09-T06: ghi cảnh báo, điểm mô hình của mọi dự đoán, gộp cảnh báo lặp thành sự kiện
  (docs/58_ghi_canh_bao_su_kien.md, QĐ-048).

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
    p.setdefault("mode", "ket_hop")
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


# ---- C09-T04: chế độ tuần tự Gaussian → phân loại → kiểm tra botnet ----

def run_sequential(arts, windows, flows, networks, cfg=None, timer=None, classify_all=False) -> dict:
    """Gaussian chấm mọi cửa sổ; phân loại chỉ cửa sổ bất thường; botnet chỉ kiểm tra host có bất thường
    mà bộ phân loại cho là ``benign`` (bất thường chưa giải thích được).

    Kết quả cùng dạng chế độ độc lập, nhưng bảng phân loại chỉ gồm cửa sổ đã xét, bảng botnet chỉ gồm
    host–cửa sổ 120 giây của host được kiểm tra **chồng lên** một cửa sổ bất thường chưa giải thích.

    ``classify_all=True`` (chế độ ``ket_hop``, C09-T05): bộ phân loại chạy trên mọi cửa sổ như chế độ độc
    lập; chỉ bước kiểm tra botnet là tuần tự.
    """
    import numpy as np
    timer = timer or Timer()
    out = {}
    with timer(MODULE_ANOMALY):
        an = score_anomaly(arts[MODULE_ANOMALY], windows)
        out[MODULE_ANOMALY] = an
    flagged = (an["du_doan"] == "anomaly").to_numpy()
    with timer(MODULE_ATTACK):
        sub = windows if classify_all else windows[flagged].reset_index(drop=True)
        at = score_attack(arts[MODULE_ATTACK], sub) if len(sub) else score_attack(arts[MODULE_ATTACK], windows.iloc[:0])
        out[MODULE_ATTACK] = at
    with timer(MODULE_BOTNET):
        if classify_all:                                  # chỉ cửa sổ Gaussian báo mới là bất thường
            at_flag = at[flagged]
        else:
            at_flag = at
        unexplained = at_flag[at_flag["du_doan"] == "benign"]
        hosts = sorted(set(unexplained["host"].astype(str)))
        if hosts:
            bo = score_botnet(arts[MODULE_BOTNET], flows, hosts, networks, cfg)
            # chỉ giữ cửa sổ 120 giây chồng lên ít nhất một cửa sổ bất thường chưa giải thích của cùng host
            keep = np.zeros(len(bo), bool)
            for h, g in unexplained.groupby("host"):
                m = (bo["host"] == h).to_numpy()
                s, e = g["window_start"].to_numpy(float), g["window_end"].to_numpy(float)
                ws, we = bo.loc[m, "window_start"].to_numpy(float), bo.loc[m, "window_end"].to_numpy(float)
                hit = ((ws[:, None] < e[None, :]) & (we[:, None] > s[None, :])).any(1)
                keep[np.flatnonzero(m)[hit]] = True
            bo = bo[keep].reset_index(drop=True)
        else:
            bo = score_botnet(arts[MODULE_BOTNET], flows.iloc[:0], [], networks, cfg)
        out[MODULE_BOTNET] = bo
    out["_tuan_tu"] = {"cua_so_bat_thuong": int(flagged.sum()), "cua_so_phan_loai": int(len(at)),
                       "phan_loai_moi_cua_so": classify_all,
                       "cua_so_chua_giai_thich": int(len(unexplained)), "host_kiem_tra_botnet": hosts}
    return out


# ---- C09-T05: so sánh chế độ độc lập và tuần tự ----

def label_tables(prefix, cfg=None) -> "pd.DataFrame":
    """Nhãn cửa sổ 10 giây của một đoạn PCAP theo lịch tấn công (cùng mã gán nhãn Chặng 5)."""
    from .labeling import (label_flows, label_windows, load_flows_for_labels, load_schedule,
                           load_windows_for_labels)
    lc = (cfg or load_config()).get("labeling", {})
    flows = load_flows_for_labels(f"{prefix}.flows.csv")
    fl = label_flows(flows, load_schedule(), lc.get("tolerance_s", 60))
    return label_windows(load_windows_for_labels(f"{prefix}.windows.csv"), flows, fl,
                         lc.get("window_min_attack_share", 0.2))


def coverage(windows, res) -> "pd.DataFrame":
    """Với mỗi cửa sổ 10 giây: module nào báo nó (cùng host; botnet: cửa sổ 120 giây chồng lên)."""
    import numpy as np
    import pandas as pd

    key = windows[["host", "window_start", "window_end"]].copy()
    key["host"] = key["host"].astype(str)
    out = key.copy()
    for m, labels in ((MODULE_ANOMALY, {"anomaly"}), (MODULE_ATTACK, {"port_scan", "dos"})):
        df = res[m]
        hit = df[df["du_doan"].isin(labels)][["host", "window_start", "du_doan"]].astype({"host": str})
        merged = key.merge(hit, on=["host", "window_start"], how="left")
        out[m] = merged["du_doan"].fillna("").to_numpy()
    bo = res[MODULE_BOTNET]
    bo = bo[bo["du_doan"] == "suspect_host"] if len(bo) else bo
    flag = np.zeros(len(key), bool)
    for h, g in bo.groupby(bo["host"].astype(str)) if len(bo) else []:
        m = (key["host"] == h).to_numpy()
        ws, we = key.loc[m, "window_start"].to_numpy(float), key.loc[m, "window_end"].to_numpy(float)
        s, e = g["window_start"].to_numpy(float), g["window_end"].to_numpy(float)
        flag[np.flatnonzero(m)[((ws[:, None] < e[None, :]) & (we[:, None] > s[None, :])).any(1)]] = True
    out[MODULE_BOTNET] = np.where(flag, "suspect_host", "")
    out["bao"] = (out[MODULE_ANOMALY] != "") | (out[MODULE_ATTACK] != "") | flag
    return out


def miss_report(labels, cov, rules) -> dict:
    """Bỏ sót theo đợt tấn công, gọi đúng tên, và báo nhầm trên cửa sổ bình thường."""
    import numpy as np

    from .gaussian import attack_groups
    lab = labels.astype({"host": str}).merge(cov, on=["host", "window_start"], how="inner")
    lab = lab[lab["label_anomaly"].isin(["normal", "anomaly"])].reset_index(drop=True)
    groups = attack_groups(lab, rules)
    out = {"theo_dot": {}}
    for g in sorted(set(groups) - {"normal"}):
        m = groups == g
        attack = lab.loc[m, "label_attack"].fillna("").to_numpy()
        named = np.where(np.isin(attack, ["port_scan", "dos"]), lab.loc[m, MODULE_ATTACK].to_numpy() == attack,
                         lab.loc[m, MODULE_BOTNET].to_numpy() == "suspect_host")
        out["theo_dot"][g] = {"so_cua_so": int(m.sum()), "bo_sot": int((~lab.loc[m, "bao"]).sum()),
                              "ty_le_bo_sot": round(float((~lab.loc[m, "bao"]).mean()), 4),
                              "goi_dung_ten": round(float(named.mean()), 4)}
    normal = (groups == "normal")
    out["binh_thuong"] = {"so_cua_so": int(normal.sum()),
                          "ty_le_bi_bao": round(float(lab.loc[normal, "bao"].mean()), 4) if normal.any() else None,
                          "theo_module": {mm: round(float((lab.loc[normal, mm] != "").mean()), 4) if normal.any() else None
                                          for mm in MODULES}}
    att = groups != "normal"
    out["tong_tan_cong"] = {"so_cua_so": int(att.sum()), "bo_sot": int((~lab.loc[att, "bao"]).sum()),
                            "ty_le_bo_sot": round(float((~lab.loc[att, "bao"]).mean()), 4) if att.any() else None}
    return out


def compare_modes(prefix, networks, cfg=None, repeats=3) -> dict:
    """Chạy cả hai chế độ trên cùng bảng đặc trưng của một đoạn PCAP; đo bỏ sót và thời gian mô hình."""
    from .labeling import load_schedule

    arts = load_artifacts(cfg)
    windows, flows = load_windows(prefix), load_flows(prefix)
    labels = label_tables(prefix, cfg)
    rules = load_schedule()
    out = {}
    from functools import partial
    for mode, fn in (("doc_lap", run_independent), ("tuan_tu", run_sequential),
                     ("ket_hop", partial(run_sequential, classify_all=True))):
        times = []
        for _ in range(repeats):
            timer = Timer()
            res = fn(arts, windows, flows, networks, cfg, timer)
            times.append(timer.steps)
        info = res.pop("_tuan_tu", None)
        cov = coverage(windows, res)
        out[mode] = {"thoi_gian_mo_hinh_s": {k: round(sorted(t[k] for t in times)[len(times) // 2], 3) for k in times[0]},
                     "tong_thoi_gian_mo_hinh_s": round(sorted(sum(t.values()) for t in times)[len(times) // 2], 3),
                     **miss_report(labels, cov, rules), "tuan_tu": info}
    return out


def cmd_compare(args):
    cfg = load_config(args.config)
    res = {}
    for pcap in args.pcap:
        name = Path(pcap).stem
        timer = Timer()
        with timer("trich_xuat"):
            prefix = extract(pcap, args.bang, args.net, args.config, name)
        r = compare_modes(prefix, args.net, cfg, args.lap)
        r["trich_xuat_s"] = timer.steps["trich_xuat"]
        res[name] = r
        for mode in ("doc_lap", "tuan_tu", "ket_hop"):
            x = r[mode]
            print(f"{name} {mode}: mô hình {x['tong_thoi_gian_mo_hinh_s']} s (trích xuất {r['trich_xuat_s']} s), "
                  f"bỏ sót {x['tong_tan_cong']}, bình thường bị báo {x['binh_thuong']['ty_le_bi_bao']}")
            for g, v in x["theo_dot"].items():
                print(f"    {g}: {v}")
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(res, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"Đã ghi: {args.out}")


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
    if mode == "doc_lap":
        res = run_independent(arts, windows, flows, networks, cfg, timer)
    elif mode in ("tuan_tu", "ket_hop"):
        res = run_sequential(arts, windows, flows, networks, cfg, timer, classify_all=mode == "ket_hop")
    else:
        raise ValueError(f"chế độ chưa hỗ trợ: {mode}")
    info = res.pop("_tuan_tu", None)
    return {"prefix": prefix, "ket_qua": res, "thoi_gian_s": timer.steps, "artifact": arts,
            "so_luong": {"flow": len(flows), "cua_so": len(windows), "host_giam_sat": len(monitored_hosts(flows, networks))},
            "che_do": mode, "tuan_tu": info}


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


# ---- C09-T06: ghi cảnh báo, điểm mô hình, gộp sự kiện lặp ----

EVENT_COLUMNS = ["module", "label", "src_ip", "bat_dau", "ket_thuc", "thoi_luong_s", "so_canh_bao", "diem_lon_nhat",
                 "diem_trung_binh", "nguong", "run_id", "canh_bao_dau_tao_luc"]


def merge_events(alerts, gap_s=30.0) -> list:
    """Gộp cảnh báo lặp thành sự kiện.

    Hai cảnh báo cùng module, cùng nhãn, cùng host thuộc một sự kiện nếu cảnh báo sau bắt đầu không quá
    ``gap_s`` giây sau khi cảnh báo trước kết thúc (cửa sổ trượt chồng nhau nên liên tiếp luôn gộp).
    Chỉ gộp cảnh báo thật (bỏ dự đoán bình thường).
    """
    groups = {}
    for a in alerts:
        if a.is_alert:
            groups.setdefault((a.module, a.label, a.src_ip), []).append(a)
    events = []
    for (module, label, host), lst in groups.items():
        lst.sort(key=lambda a: a.window_start)
        cur = None
        for a in lst:
            if cur is not None and a.window_start <= cur["ket_thuc"] + gap_s:
                cur["ket_thuc"] = max(cur["ket_thuc"], a.window_end)
                cur["_diem"].append(a.score)
                continue
            if cur is not None:
                events.append(cur)
            cur = {"module": module, "label": label, "src_ip": host, "bat_dau": a.window_start, "ket_thuc": a.window_end,
                   "_diem": [a.score], "nguong": a.threshold, "run_id": a.run_id, "canh_bao_dau_tao_luc": a.created_at}
        events.append(cur)
    out = []
    for e in events:
        scores = [s for s in e.pop("_diem") if s is not None]
        e["so_canh_bao"] = len(scores) if scores else None
        e["diem_lon_nhat"] = round(max(scores), 6) if scores else None
        e["diem_trung_binh"] = round(sum(scores) / len(scores), 6) if scores else None
        e["thoi_luong_s"] = round(e["ket_thuc"] - e["bat_dau"], 3)
        out.append(e)
    # nhãn topology không có điểm: đếm theo số dòng của sự kiện
    for e in out:
        if e["so_canh_bao"] is None:
            e["so_canh_bao"] = sum(1 for a in groups[(e["module"], e["label"], e["src_ip"])]
                                   if e["bat_dau"] <= a.window_start and a.window_end <= e["ket_thuc"])
    return sorted(out, key=lambda e: (e["bat_dau"], e["src_ip"], e["module"]))


def write_events(events, path) -> int:
    import csv

    from .alerts import _iso
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=EVENT_COLUMNS)
        w.writeheader()
        for e in events:
            row = dict(e)
            for k in ("bat_dau", "ket_thuc", "canh_bao_dau_tao_luc"):
                row[k] = _iso(row[k])
            w.writerow({k: ("" if row.get(k) is None else row[k]) for k in EVENT_COLUMNS})
    return len(events)


def format_event(e) -> str:
    from .alerts import _iso
    s = f"{_iso(e['bat_dau'])} → {_iso(e['ket_thuc'])} | [{e['module']}] {e['label'].upper()} | {e['src_ip']} | " \
        f"{e['so_canh_bao']} cảnh báo"
    if e["diem_lon_nhat"] is not None:
        s += f" | điểm lớn nhất {e['diem_lon_nhat']:.4g}"
    return s


def write_outputs(run, run_id="", gap_s=30.0, stream=None) -> dict:
    """Ghi bảng dự đoán, cảnh báo, điểm mô hình (mọi dự đoán) và sự kiện; in sự kiện ra terminal."""
    prefix = run["prefix"]
    paths = write_predictions(run)
    alerts = run_alerts(run, run["artifact"], run_id)
    scores = run_alerts(run, run["artifact"], run_id, log_all=True)
    paths["canh_bao"] = f"{prefix}.alerts.csv"
    paths["diem"] = f"{prefix}.diem.csv"
    paths["su_kien"] = f"{prefix}.su_kien.csv"
    n_alerts = write_alerts(alerts, paths["canh_bao"])
    n_scores = write_alerts(scores, paths["diem"], log_all=True)
    events = merge_events(alerts, gap_s)
    write_events(events, paths["su_kien"])
    if stream is not None:
        for e in events:
            print(format_event(e), file=stream)
    return {"file": paths, "so_canh_bao_hop_nhat": n_alerts, "so_dong_diem": n_scores, "so_su_kien": len(events),
            "su_kien_theo_module": {m: sum(e["module"] == m for e in events) for m in MODULES},
            **{k: v for k, v in host_overview(alerts).items()}}


def write_predictions(run) -> dict:
    """Ghi bảng dự đoán của từng module cạnh bảng đặc trưng; trả về đường dẫn."""
    paths = {}
    for m, df in run["ket_qua"].items():
        p = Path(f"{run['prefix']}.{m}.csv")
        df.to_csv(p, index=False)
        paths[m] = str(p)
    return paths


def cmd_run(args):
    import sys as _sys
    cfg = load_config(args.config)
    pc = pipeline_config(cfg)
    mode = args.che_do or pc["mode"]
    name = args.ten or (Path(args.pcap).stem + ("" if mode == pc["mode"] else f"_{mode}"))
    run = run_pcap(args.pcap, args.out, args.net, cfg, args.config, mode, name)
    run_id = args.ma_lan_chay or Path(run["prefix"]).name
    out = write_outputs(run, run_id, pc["merge_gap_s"], _sys.stdout if args.in_su_kien else None)
    summary = {"pcap": args.pcap, "che_do": run["che_do"], "tuan_tu": run["tuan_tu"], "thoi_gian_s": run["thoi_gian_s"],
               "so_luong": run["so_luong"],
               "bao_dong": {m: int((df["du_doan"].isin(["anomaly", "port_scan", "dos", "suspect_host"])).sum())
                            for m, df in run["ket_qua"].items()},
               "gop_su_kien_cach_s": pc["merge_gap_s"], **out}
    Path(f"{run['prefix']}.pipeline.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{run['prefix']}: chế độ {mode}, {out['so_canh_bao_hop_nhat']} cảnh báo -> {out['so_su_kien']} sự kiện "
          f"{out['su_kien_theo_module']}; thời gian {run['thoi_gian_s']}")
    print(f"Đã ghi: {', '.join(out['file'].values())}, {run['prefix']}.pipeline.json")


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
    p.add_argument("--che-do", choices=("doc_lap", "tuan_tu", "ket_hop"), default=None,
                   help="doc_lap: ba module độc lập; tuan_tu: Gaussian → phân loại → kiểm tra botnet; "
                        "ket_hop: phân loại mọi cửa sổ, botnet chỉ kiểm tra bất thường chưa giải thích; mặc định pipeline.mode")
    p.add_argument("--ma-lan-chay", help="run_id ghi vào cảnh báo, khớp nhật ký kịch bản; mặc định tên tiền tố")
    p.add_argument("--in-su-kien", action="store_true", help="in từng sự kiện ra terminal")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("so-sanh", help="so sánh chế độ độc lập và tuần tự: bỏ sót, thời gian (C09-T05)")
    p.add_argument("pcap", nargs="+")
    p.add_argument("--net", action="append", required=True)
    p.add_argument("--bang", required=True, help="thư mục ghi bảng đặc trưng trích từ PCAP")
    p.add_argument("--out", required=True, help="file JSON kết quả")
    p.add_argument("--lap", type=int, default=3, help="số lần chạy mỗi chế độ để lấy trung vị thời gian")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_compare)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

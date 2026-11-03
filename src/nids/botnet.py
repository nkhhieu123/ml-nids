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


# ---- C08-T05: mô hình phát hiện botnet ----

def feature_names() -> list:
    from .graph_features import BEACON_FEATURES, GRAPH_FEATURES
    return GRAPH_FEATURES + BEACON_FEATURES


# Đặc trưng là tỷ lệ, entropy, CV: không log; còn lại là đếm, byte, giây: lệch phải mạnh
LINEAR = {"ty_le_tuong_ho", "tap_trung_ra", "entropy_peer_ra", "tap_trung_vao", "entropy_peer_vao",
          "ty_le_khong_tra_loi_ra", "ty_le_udp", "ty_le_peer_noi_bo", "ty_le_peer_moi", "beacon_cv_nho_nhat"}


class BotnetDetector:
    """Tiền xử lý (log, điền trung vị train + cột đánh dấu, chuẩn hóa) và một mô hình; dự đoán từ đặc trưng thô."""

    def __init__(self, kind, params=None, seed=42):
        self.kind, self.params, self.seed = kind, dict(params or {}), seed
        self.features = feature_names()
        self.pipeline = None
        self.info = {}
        self.threshold = 0.5

    def _x(self, df):
        X = df[self.features].astype(float).copy()
        logc = [c for c in self.features if c not in LINEAR]
        X[logc] = np.log1p(X[logc].clip(lower=0))
        return X.to_numpy()

    def fit(self, train):
        from sklearn.impute import SimpleImputer
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        from .classifier import make_estimator

        self.pipeline = Pipeline([("dien_o_trong", SimpleImputer(strategy="median", add_indicator=True,
                                                                  keep_empty_features=True)),
                                  ("chuan_hoa", StandardScaler()),
                                  ("mo_hinh", make_estimator(self.kind, self.params, self.seed))])
        self.pipeline.fit(self._x(train), train[LABEL_COL].to_numpy())
        self.info.update({"so_mau_train": len(train), "lop_train": {k: int(v) for k, v in
                                                                    train[LABEL_COL].value_counts().items()}})
        return self

    def score(self, df) -> np.ndarray:
        """Xác suất là ``suspect_host``."""
        p = self.pipeline.predict_proba(self._x(df))
        return p[:, list(self.pipeline.classes_).index(SUSPECT)]

    def predict(self, df, threshold=None) -> np.ndarray:
        th = self.threshold if threshold is None else threshold
        return np.where(self.score(df) >= th, SUSPECT, NORMAL)


def binary_report(y, pred) -> dict:
    from .gaussian import binary_metrics
    m = binary_metrics(np.asarray(y) == SUSPECT, np.asarray(pred) == SUSPECT)
    return {"precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
            "ty_le_bao_nham": m["fpr"], "tp": m["tp"], "fp": m["fp"], "fn": m["fn"], "tn": m["tn"]}


def labeled_part(df, split) -> pd.DataFrame:
    return df[(df["split"] == split) & df[LABEL_COL].isin([SUSPECT, NORMAL])].reset_index(drop=True)


def training_set(df, background_fraction=0.0, seed=42) -> pd.DataFrame:
    """Train có nhãn, cộng thêm một phần cửa sổ Background của train làm mẫu âm yếu (QĐ-040).

    Background chưa kiểm chứng nên không bao giờ là lớp dương; phần thêm vào mang nhãn ``normal_host``
    chỉ khi học. Validation và test không đổi.
    """
    train = labeled_part(df, "train")
    if not background_fraction:
        return train
    bg = df[(df["split"] == "train") & (df[LABEL_COL] == BACKGROUND)]
    extra = bg.sample(frac=float(background_fraction), random_state=seed).assign(**{LABEL_COL: NORMAL})
    return pd.concat([train, extra], ignore_index=True)


def model_search(df, cfg=None, log=print) -> dict:
    """Mỗi loại mô hình thử lưới (tỷ lệ Background làm mẫu âm × tham số × ngưỡng), chọn trên validation.

    Tiêu chí: F1 của ``suspect_host`` lớn nhất trong các cấu hình có tỷ lệ cửa sổ Background validation
    bị báo không quá ``max_background_alarm`` (QĐ-040).
    """
    from .classifier import _grid

    b = botnet_config(cfg)
    grid = b.get("search") or {"logistic_regression": {"C": [0.1, 1.0, 10.0], "class_weight": ["balanced", None]},
                               "random_forest": {"n_estimators": [300], "max_depth": [None, 10],
                                                 "min_samples_leaf": [5], "class_weight": [None]}}
    fractions = b.get("background_negative_fractions", [0.0, 0.1, 0.3, 1.0])
    seed = (cfg or {}).get("random_seed", 42)
    val = labeled_part(df, "validation")
    trains = {f: training_set(df, f, seed) for f in fractions}
    thresholds = b.get("thresholds") or [round(x, 2) for x in np.arange(0.05, 0.96, 0.05)]
    max_bg = float(b.get("max_background_alarm", 0.05))
    bg_val = df[(df["split"] == "validation") & (df[LABEL_COL] == BACKGROUND)]
    out = {}
    for kind, space in grid.items():
        rows = []
        for frac, params in ((f, p) for f in fractions for p in _grid(space)):
            m = BotnetDetector(kind, params, seed).fit(trains[frac])
            sc, sb = m.score(val), m.score(bg_val) if len(bg_val) else np.array([])
            best_th, r, best_bg = None, None, None
            # Ngưỡng cũng chọn trên validation: F1 lớn nhất trong các ngưỡng có tỷ lệ cửa sổ Background
            # bị báo <= max_bg; không ngưỡng nào đạt thì lấy ngưỡng báo Background ít nhất (QĐ-040).
            for th in thresholds:
                cand = binary_report(val[LABEL_COL], np.where(sc >= th, SUSPECT, NORMAL))
                bg_rate = float((sb >= th).mean()) if len(sb) else 0.0
                key = (bg_rate <= max_bg, cand["f1"] if bg_rate <= max_bg else -bg_rate)
                if r is None or key > best_key:
                    best_th, r, best_bg, best_key = th, cand, bg_rate, key
            rows.append({"tham_so": params, "ty_le_background_lam_mau_am": frac, "nguong": best_th, "background_bi_bao_validation": round(best_bg, 4),
                         **{f"{k}_validation": v for k, v in r.items()}})
            log(f"  {kind} Background {frac} {params}: ngưỡng {best_th}, F1 validation {r['f1']} (P {r['precision']}, "
                f"R {r['recall']}), Background bị báo {best_bg:.3f}")
        best = max(rows, key=lambda r: (r["background_bi_bao_validation"] <= max_bg, r["f1_validation"]))
        out[kind] = {"tot_nhat": best, "cac_lan_thu": rows}
    out["chon"] = max((k for k in grid), key=lambda k: (out[k]["tot_nhat"]["background_bi_bao_validation"] <= max_bg,
                                                         out[k]["tot_nhat"]["f1_validation"]))
    out["gioi_han_background"] = max_bg
    return out


def evaluate(model, df, split="test") -> dict:
    """Chỉ số mức host–cửa sổ: tổng, theo scenario; tỷ lệ cửa sổ Background bị báo (không phải FPR)."""
    part = labeled_part(df, split)
    pred = model.predict(part)
    res = {"tong": binary_report(part[LABEL_COL], pred), "theo_scenario": {}}
    bg = df[(df["split"] == split) & (df[LABEL_COL] == BACKGROUND)]
    bg_pred = model.predict(bg) if len(bg) else np.array([])
    for s in sorted(set(part["scenario"]) | set(bg["scenario"])):
        m = (part["scenario"] == s).to_numpy()
        mb = (bg["scenario"] == s).to_numpy()
        res["theo_scenario"][int(s)] = {
            "so_cua_so_bot": int((part.loc[m, LABEL_COL] == SUSPECT).sum()),
            "so_cua_so_binh_thuong": int((part.loc[m, LABEL_COL] == NORMAL).sum()),
            **binary_report(part.loc[m, LABEL_COL], pred[m]),
            "background_bi_bao": round(float((bg_pred[mb] == SUSPECT).mean()), 4) if mb.any() else None,
            "host_bot_bi_bat": int(part.loc[m & (pred == SUSPECT) & (part[LABEL_COL] == SUSPECT).to_numpy(), "host"].nunique()),
            "so_host_bot": int(part.loc[m & (part[LABEL_COL] == SUSPECT).to_numpy(), "host"].nunique()),
        }
    res["background_bi_bao"] = round(float((bg_pred == SUSPECT).mean()), 4) if len(bg) else None
    return res


MODEL_FILES = {"logistic_regression": "botnet_lr.joblib", "random_forest": "botnet_rf.joblib"}


def save_model(model, path, extra=None) -> Path:
    import datetime
    import joblib

    from .feature_export import _git_version

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path, compress=3)
    meta = {"mo_hinh": f"{model.kind} phát hiện host bot trên host–cửa sổ 120 giây (Chặng 8)", "loai": model.kind,
            "tham_so": model.params, "dac_trung": model.features, "cot_khong_log": sorted(LINEAR),
            **model.info, **(extra or {}), "ma_nguon": _git_version(),
            "thoi_diem_tao": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}
    path.with_suffix(".json").write_text(json.dumps(meta, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return path


def load_model(path) -> BotnetDetector:
    import joblib

    model = joblib.load(path)
    if not isinstance(model, BotnetDetector):
        raise TypeError(f"{path} không phải mô hình botnet của dự án")
    return model


def importance(model, top=10) -> dict:
    est = model.pipeline.named_steps["mo_hinh"]
    imp = model.pipeline.named_steps["dien_o_trong"]
    names = model.features + [f"{model.features[i]}__trong" for i in imp.indicator_.features_]
    vals = est.feature_importances_ if hasattr(est, "feature_importances_") else np.abs(est.coef_[0])
    order = np.argsort(-vals)[:top]
    return {names[i]: round(float(vals[i]), 4) for i in order}


def cmd_train(args):
    from .config import PROJECT_ROOT, load_config

    cfg = load_config(args.config)
    df = load_labeled(args.flows_dir, sorted(SCENARIOS), cfg)
    res = model_search(df, cfg)
    seed = cfg.get("random_seed", 42)
    out_dir = Path(args.models or PROJECT_ROOT / cfg.get("paths", {}).get("model_dir", "models"))
    for kind in MODEL_FILES:
        best = res[kind]["tot_nhat"]
        train = training_set(df, best["ty_le_background_lam_mau_am"], seed)
        model = BotnetDetector(kind, best["tham_so"], seed).fit(train)
        model.info["ty_le_background_lam_mau_am"] = best["ty_le_background_lam_mau_am"]
        model.threshold = best["nguong"]
        model.info["f1_validation"] = best["f1_validation"]
        model.info["nguong"] = best["nguong"]
        model.info["chon_tren_validation"] = kind == res["chon"]
        res[kind]["validation_theo_scenario"] = evaluate(model, df, "validation")["theo_scenario"]
        res[kind]["do_quan_trong"] = importance(model)
        save_model(model, out_dir / MODEL_FILES[kind], {"chia_tap": botnet_config(cfg)["splits"]})
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "botnet_mo_hinh.json").write_text(json.dumps(res, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    for kind in MODEL_FILES:
        b = res[kind]["tot_nhat"]
        print(f"{kind}: Background {b['ty_le_background_lam_mau_am']} {b['tham_so']} ngưỡng {b['nguong']} F1 {b['f1_validation']} P {b['precision_validation']} R {b['recall_validation']}")
        print("   ", res[kind]["validation_theo_scenario"])
        print("   ", res[kind]["do_quan_trong"])
    print("Chọn:", res["chon"])


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
    p = sub.add_parser("huan-luyen", help="thử tham số, chọn trên validation, lưu LR và RF (C08-T05)")
    p.add_argument("flows_dir")
    p.add_argument("--out", required=True, help="thư mục ghi JSON")
    p.add_argument("--models", help="thư mục lưu mô hình, mặc định models/")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_train)
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    # Chạy bản của module đã import để đối tượng lưu bằng joblib nạp lại được (docs/32 mục 4).
    from nids.botnet import main as module_main
    sys.exit(module_main())

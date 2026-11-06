"""Phát hiện botnet và nhận diện topology trên host–cửa sổ (Chặng 8).

- C08-T04: gán nhãn host–cửa sổ, quy định cách xử lý Background, chia tập theo scenario
  (docs/48_botnet_nhan.md, QĐ-039).
- C08-T05: Logistic Regression và Random Forest phát hiện host bot; chọn trên validation với giới hạn
  báo động Background (docs/49_botnet_mo_hinh.md, QĐ-040).
- C08-T07: nhận diện topology bằng quy tắc, không ML (docs/51_nhan_dien_topology.md, QĐ-042).
- C08-T08: đánh giá bằng hai bảng riêng: phát hiện botnet và topology (docs/52_botnet_danh_gia.md).

    python -m nids.botnet nhan output/ctu13 --out docs/hinh
    python -m nids.botnet huan-luyen output/ctu13 --out docs/hinh
    python -m nids.botnet danh-gia output/ctu13 --sim-dir output/topology_sim --model models/botnet_rf.joblib         --model models/botnet_lr.joblib --chon botnet_rf --out docs/hinh

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


def host_aggregation_config(cfg=None) -> dict:
    """Tham số gộp theo host (C09); chọn trên validation (docs/69). ``min_strong`` 0 nghĩa là tắt."""
    r = dict((botnet_config(cfg).get("host_aggregation")) or {})
    r.setdefault("min_strong", 500)
    r.setdefault("min_frac", 0.13)
    return r


def confirmed_bot_hosts(df, scores, threshold, min_strong, min_frac) -> set:
    """Tập (session, host) được xác nhận là bot trong run: đủ nhiều cửa sổ điểm ≥ ngưỡng.

    Gộp theo (session, host) = một lần thu. Host được xác nhận nếu số cửa sổ có điểm ≥ ``threshold``
    đạt ít nhất ``min_strong`` VÀ chiếm ít nhất ``min_frac`` tổng số cửa sổ của host (C09, docs/69).
    """
    strong = np.asarray(scores) >= threshold
    t = pd.DataFrame({"session": df["session"].to_numpy(), "host": df["host"].to_numpy(), "s": strong})
    agg = t.groupby(["session", "host"])["s"].agg(["sum", "size"])
    ok = agg[(agg["sum"] >= min_strong) & (agg["sum"] >= min_frac * agg["size"])]
    return set(ok.index)


def aggregate_host(df, pred, confirmed):
    """Nâng dự đoán lên ``suspect_host`` cho mọi cửa sổ thuộc host đã được xác nhận (C09)."""
    keys = zip(df["session"].to_numpy(), df["host"].to_numpy())
    return np.array([SUSPECT if k in confirmed else p for k, p in zip(keys, pred)], dtype=object)


def evaluate(model, df, split="test", host_agg=None) -> dict:
    """Chỉ số mức host–cửa sổ: tổng, theo scenario; tỷ lệ cửa sổ Background bị báo (không phải FPR).

    ``host_agg`` (dict ``min_strong``/``min_frac``) bật lớp gộp theo host của C09 (docs/69): xác nhận host
    là bot trong run rồi nâng mọi cửa sổ của host lên suspect. Mặc định None: giữ nguyên hành vi C08.
    """
    part = labeled_part(df, split)
    pred = model.predict(part)
    bg = df[(df["split"] == split) & (df[LABEL_COL] == BACKGROUND)]
    bg_pred = model.predict(bg) if len(bg) else np.array([])
    if host_agg:
        full = df[df["split"] == split]
        confirmed = confirmed_bot_hosts(full, model.score(full), model.threshold,
                                        host_agg["min_strong"], host_agg["min_frac"])
        pred = aggregate_host(part, pred, confirmed)
        if len(bg):
            bg_pred = aggregate_host(bg, bg_pred, confirmed)
    res = {"tong": binary_report(part[LABEL_COL], pred), "theo_scenario": {}}
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


# ---- C08-T07: nhận diện topology bằng QUY TẮC (không ML) ----

TOPOLOGY_LABELS = ("centralized", "p2p", "none")


def topology_rule(cfg=None) -> dict:
    r = dict((botnet_config(cfg).get("topology_rule")) or {})
    r.setdefault("min_peer_vao", 5)
    r.setdefault("min_udp", 0.5)
    r.setdefault("min_entropy_vao", 0.8)
    return r


def recognize_topology(df, suspect, rule=None) -> np.ndarray:
    """Topology của từng host–cửa sổ, bằng quy tắc (QĐ-042).

    - ``none`` nếu host–cửa sổ không bị nghi là bot (``suspect`` False).
    - ``p2p`` nếu đồng thời: ≥ ``min_peer_vao`` peer gọi vào host, ≥ ``min_udp`` phần flow là UDP và entropy
      của flow vào theo peer ≥ ``min_entropy_vao`` (nhiều peer ngang hàng chủ động gọi tới, chia đều).
    - ``centralized`` cho các cửa sổ bị nghi còn lại (bot chủ yếu gọi ra tới ít máy điều khiển hoặc nạn nhân).

    Dùng quy tắc vì CTU-13 chỉ có một scenario P2P: không đủ dữ liệu để học và kiểm thử riêng một mô hình.
    """
    r = rule or topology_rule()
    suspect = np.asarray(suspect, bool)
    p2p = ((df["so_peer_vao"].fillna(0) >= r["min_peer_vao"]) & (df["ty_le_udp"].fillna(0) >= r["min_udp"])
           & (df["entropy_peer_vao"].fillna(0) >= r["min_entropy_vao"])).to_numpy()
    return np.where(~suspect, "none", np.where(p2p, "p2p", "centralized"))


def run_topology(windows_topology, groups) -> pd.Series:
    """Topology của cả lần chạy hoặc scenario: nhãn chiếm đa số trong các cửa sổ bị nghi; không có thì ``none``."""
    s = pd.Series(windows_topology)
    out = {}
    for g, idx in pd.Series(groups).groupby(groups).groups.items():
        vals = s.loc[idx]
        vals = vals[vals != "none"]
        out[g] = vals.value_counts().idxmax() if len(vals) else "none"
    return pd.Series(out)


def topology_confusion(y, pred) -> dict:
    from sklearn.metrics import confusion_matrix

    labels = list(TOPOLOGY_LABELS)
    cm = confusion_matrix(y, pred, labels=labels)
    acc = float(np.trace(cm) / cm.sum()) if cm.sum() else 0.0
    return {"nhan": labels, "ma_tran": cm.tolist(), "do_chinh_xac": round(acc, 4),
            "recall_theo_lop": {c: round(float(cm[i, i] / cm[i].sum()), 4) if cm[i].sum() else None
                                for i, c in enumerate(labels)}}


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


# ---- C08-T08: đánh giá, hai bảng riêng ----

def topology_tables(df, detector, rule, group_col) -> dict:
    """Bảng topology: (a) quy tắc trên cửa sổ bot thật; (b) nối tiếp sau bộ phát hiện. Mức cửa sổ và mức nhóm."""
    part = df[df[LABEL_COL].isin([SUSPECT, NORMAL])].reset_index(drop=True)
    y = np.where(part[LABEL_COL] == SUSPECT, part[TOPOLOGY_COL], "none")
    true_suspect = (part[LABEL_COL] == SUSPECT).to_numpy()
    alone = recognize_topology(part, true_suspect, rule)
    chain = recognize_topology(part, detector.predict(part) == SUSPECT, rule)
    groups = part[group_col].astype(str).to_numpy()
    truth_run = pd.Series(y).groupby(groups).agg(lambda v: next((x for x in v if x != "none"), "none"))
    out = {"so_cua_so": int(len(part))}
    for name, pred in (("chi_bo_nhan_dien", alone), ("noi_tiep_bo_phat_hien", chain)):
        m = true_suspect if name == "chi_bo_nhan_dien" else np.ones(len(part), bool)
        runs = run_topology(pred, groups)
        out[name] = {"cua_so": topology_confusion(y[m], pred[m]),
                     "nhom": topology_confusion(truth_run.loc[runs.index].to_numpy(), runs.to_numpy()),
                     "nhom_chi_tiet": {g: {"that": truth_run[g], "doan": runs[g]} for g in runs.index}}
    return out


def plot_tables(res, path):
    """Hình: F1 theo scenario test (hai mô hình) và hai confusion matrix topology (chỉ bộ nhận diện)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.4))
    ax = axes[0]
    names = list(res["phat_hien_botnet"])
    scen = sorted({int(s) for r in res["phat_hien_botnet"].values() for s in r["theo_scenario"]})
    w = 0.8 / max(len(names), 1)
    for i, n in enumerate(names):
        vals = [res["phat_hien_botnet"][n]["theo_scenario"].get(s, res["phat_hien_botnet"][n]["theo_scenario"].get(str(s), {})).get("f1", 0)
                for s in scen]
        ax.bar(np.arange(len(scen)) + i * w, vals, w, label=n)
    ax.set_xticks(np.arange(len(scen)) + w * (len(names) - 1) / 2, [f"s{s}" for s in scen])
    ax.set_ylim(0, 1.25)
    ax.set_yticks(np.arange(0, 1.01, 0.2))
    ax.set_ylabel("F1 suspect_host")
    ax.set_title("Bảng 1 — phát hiện botnet, test CTU-13", fontsize=10)
    ax.legend(fontsize=8, loc="upper center", ncol=len(names))
    for ax, key, title in ((axes[1], "ctu13_test", "Bảng 2 — topology, test CTU-13"),
                           (axes[2], "mo_phong", "Bảng 2 — topology, giả lập")):
        cm = np.array(res["topology"][key]["chi_bo_nhan_dien"]["cua_so"]["ma_tran"], float)
        labels = res["topology"][key]["chi_bo_nhan_dien"]["cua_so"]["nhan"]
        keep = [i for i in range(len(labels)) if cm[i].sum() > 0 or cm[:, i].sum() > 0]
        cm = cm[np.ix_(keep, keep)]
        lab = [labels[i] for i in keep]
        norm = cm / np.maximum(cm.sum(1, keepdims=True), 1)
        ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
        ax.set_xticks(range(len(lab)), lab)
        ax.set_yticks(range(len(lab)), lab)
        for i in range(len(lab)):
            for j in range(len(lab)):
                ax.text(j, i, f"{int(cm[i, j])}\n{norm[i, j]:.0%}", ha="center", va="center", fontsize=8,
                        color="white" if norm[i, j] > 0.6 else "black")
        ax.set_xlabel("Đoán")
        ax.set_ylabel("Thật (cửa sổ bot)")
        ax.set_title(title + " (chỉ bộ nhận diện)", fontsize=10)
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)


def cmd_evaluate(args):
    from .config import load_config
    from .topology_sim import label_runs

    cfg = load_config(args.config)
    rule = topology_rule(cfg)
    df = load_labeled(args.flows_dir, sorted(SCENARIOS), cfg)
    sim = label_runs(args.sim_dir, cfg).assign(split="mo_phong", scenario=0)
    res = {"phat_hien_botnet": {}, "topology": {}, "quy_tac_topology": rule}
    models = {Path(p).stem: load_model(p) for p in args.model}
    for name, m in models.items():
        r = evaluate(m, df, "test")
        r["validation"] = evaluate(m, df, "validation")["tong"]
        simp = sim[sim[LABEL_COL].isin([SUSPECT, NORMAL])]
        pred = m.predict(simp)
        r["mo_phong"] = {"tong": binary_report(simp[LABEL_COL], pred),
                         "theo_kieu": {k: {"so_cua_so": int(g.shape[0]),
                                           "ty_le_bi_bao": round(float((pred[g.index.map(simp.index.get_loc)] == SUSPECT).mean()), 4)}
                                       for k, g in simp.groupby("kieu")}}
        res["phat_hien_botnet"][name] = {"nguong": m.threshold, "tham_so": m.params, **r}
    chosen = models[args.chon] if args.chon else next(iter(models.values()))
    res["topology"]["mo_hinh_phat_hien"] = args.chon or next(iter(models))
    for split in ("train", "validation", "test"):
        res["topology"][f"ctu13_{split}"] = topology_tables(df[df["split"] == split], chosen, rule, "scenario")
    res["topology"]["mo_phong"] = topology_tables(sim, chosen, rule, "lan_chay")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "botnet_danh_gia.json").write_text(json.dumps(res, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    plot_tables(res, out / "botnet_danh_gia.png")
    for name, r in res["phat_hien_botnet"].items():
        print(name, "test:", r["tong"], "| Background bị báo:", r["background_bi_bao"])
        for s, v in r["theo_scenario"].items():
            print(f"   s{s}: P {v['precision']} R {v['recall']} F1 {v['f1']} báo nhầm {v['ty_le_bao_nham']} "
                  f"Background {v['background_bi_bao']} host bắt được {v['host_bot_bi_bat']}/{v['so_host_bot']}")
        print("   mô phỏng:", r["mo_phong"])
    for k, v in res["topology"].items():
        if isinstance(v, dict):
            print(k, "chỉ bộ nhận diện:", v["chi_bo_nhan_dien"]["cua_so"]["ma_tran"], v["chi_bo_nhan_dien"]["nhom"]["ma_tran"])
            print("   nối tiếp:", v["noi_tiep_bo_phat_hien"]["cua_so"]["ma_tran"], v["noi_tiep_bo_phat_hien"]["nhom"]["ma_tran"])
    print(f"Đã ghi: {out / 'botnet_danh_gia.json'}")


def cmd_host_agg(args):
    """C09: đo tác dụng của lớp gộp theo host (vớt bot chậm), so với baseline C08."""
    from .config import load_config

    cfg = load_config(args.config)
    ha = host_aggregation_config(cfg)
    df = load_labeled(args.flows_dir, sorted(SCENARIOS), cfg)
    model = load_model(args.model)
    res = {"tham_so": ha, "nguong": model.threshold}
    for split in ("validation", "test"):
        res[split] = {"baseline": evaluate(model, df, split), "gop_host": evaluate(model, df, split, host_agg=ha)}
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "botnet_gop_host.json"
    path.write_text(json.dumps(res, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    for split in ("validation", "test"):
        b0, b1 = res[split]["baseline"]["tong"], res[split]["gop_host"]["tong"]
        print(f"[{split}] baseline: R {b0['recall']} P {b0['precision']} F1 {b0['f1']} "
              f"bg {res[split]['baseline']['background_bi_bao']}")
        print(f"[{split}] gộp host: R {b1['recall']} P {b1['precision']} F1 {b1['f1']} "
              f"bg {res[split]['gop_host']['background_bi_bao']}")
        for s, v in res[split]["gop_host"]["theo_scenario"].items():
            v0 = res[split]["baseline"]["theo_scenario"][s]
            print(f"   s{s}: R {v0['recall']}→{v['recall']} P {v0['precision']}→{v['precision']}")
    print(f"Đã ghi: {path}")


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
    p = sub.add_parser("danh-gia", help="hai bảng: phát hiện botnet và topology (C08-T08)")
    p.add_argument("flows_dir")
    p.add_argument("--sim-dir", required=True, help="thư mục của nids.topology_sim")
    p.add_argument("--model", action="append", required=True, help="file joblib; lặp lại cho nhiều mô hình")
    p.add_argument("--chon", help="tên mô hình (tên file không đuôi) dùng trước bộ nhận diện topology")
    p.add_argument("--out", required=True)
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_evaluate)
    p = sub.add_parser("gop-host", help="C09: đo lớp gộp theo host (vớt bot chậm), so baseline (docs/69)")
    p.add_argument("flows_dir")
    p.add_argument("--model", required=True, help="file joblib của bộ phát hiện (thường botnet_rf.joblib)")
    p.add_argument("--out", required=True)
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_host_agg)
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    # Chạy bản của module đã import để đối tượng lưu bằng joblib nạp lại được (docs/32 mục 4).
    from nids.botnet import main as module_main
    sys.exit(module_main())

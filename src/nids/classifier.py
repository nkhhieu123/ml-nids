"""Phân loại tấn công đa lớp trên cửa sổ host: Benign, PortScan, DoS (Chặng 7).

- C07-T01: chốt nhãn thực tế: lớp nào, mẫu nào, đợt tấn công nào bị loại và vì sao
  (docs/39_phan_loai_nhan.md, QĐ-033).
- C07-T02: Logistic Regression làm mô hình đối chiếu (docs/40_phan_loai_lr.md, QĐ-034).
- C07-T03: Random Forest (docs/41_phan_loai_rf.md).
- C07-T04: chọn tham số và mô hình theo macro-F1 validation (docs/42_phan_loai_chon.md, QĐ-035).
- C07-T05: đánh giá trên test: macro-F1, từng lớp, confusion matrix, theo đợt (docs/43_phan_loai_danh_gia.md).
- C07-T06: phân tích nhầm lẫn, lưu và nạp lại mô hình, dự đoán (docs/44_phan_loai_phan_tich.md).

    python -m nids.classifier nhan <tiền tố phiên>... --out docs/hinh
    python -m nids.classifier thu logistic_regression <tiền tố phiên>... --out docs/hinh
    python -m nids.classifier thu random_forest <tiền tố phiên>... --out docs/hinh
    python -m nids.classifier chon <tiền tố phiên>... --out docs/hinh
    python -m nids.classifier danh-gia <tiền tố>... --chon docs/hinh/phan_loai_chon.json --out docs/hinh
    python -m nids.classifier huan-luyen <tiền tố>... --chon docs/hinh/phan_loai_chon.json
    python -m nids.classifier phan-tich <tiền tố>... --model models/phan_loai_rf_windows.joblib --out docs/hinh
    python -m nids.classifier du-doan <tiền tố>... --model models/phan_loai_rf_windows.joblib --out output/x.csv

Mọi bước học chỉ dùng tập train; validation để chọn tham số và mô hình; test chỉ để đánh giá.
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from .dataset import feature_columns, load_table
from .gaussian import attack_groups
from .labeling import STATUS_AMBIGUOUS, STATUS_EXCLUDED, load_schedule
from .preprocessing import Preprocessor, balance_indices, drop_duplicates, log_columns, select_samples
from .scope import ATTACK_LABELS, MODULE_ATTACK

TABLE = "windows"
SPLITS = ("train", "validation", "test")
LABEL_COL = "label_attack"
# Lớp có ít hơn số mẫu này ở một tập thì kết quả của lớp đó ở tập ấy dao động lớn
MIN_CLASS_SAMPLES = 100
# Đợt tấn công có trong dữ liệu nhưng chưa thành lớp (QĐ-033): chỉ thêm khi có dữ liệu và kiểm thử
EXCLUDED_REASONS = {
    "DDoS": "Một đợt 20 phút, LOIT nhiều nguồn sau NAT; không đủ đợt độc lập để train và test riêng",
    "Heartbleed": "Một kết nối khai thác TLS kéo dài; lưu lượng trông bình thường, quá ít mẫu",
    "Bot": "Thuộc module botnet (Chặng 8); không phải PortScan hay DoS",
}


def load_data(prefixes, sessions=None) -> pd.DataFrame:
    df = load_table(prefixes, TABLE)
    if sessions:
        df = df[df["session"].isin(sessions)].reset_index(drop=True)
    return df


def classifier_config(cfg) -> dict:
    c = dict((cfg or {}).get("classifier") or {})
    p = (cfg or {}).get("preprocess") or {}
    c.setdefault("sessions", (p.get("sessions") or {}).get(MODULE_ATTACK))
    c.setdefault("drop_train_duplicates", p.get("drop_train_duplicates", True))
    c.setdefault("balance_max_ratio", p.get("balance_max_ratio", 10))
    c.setdefault("random_seed", (cfg or {}).get("random_seed", 42))
    c.setdefault("logistic_regression", {"C": 1.0, "class_weight": "balanced"})
    c.setdefault("random_forest", {"n_estimators": 300, "max_features": "sqrt",
                                   "class_weight": "balanced_subsample"})
    c.setdefault("search", {})
    return c


# ---- C07-T01: nhãn thực tế ----

def host_roles(df, rules) -> np.ndarray:
    """Vai trò của host trong lịch tấn công: ``ben_tan_cong``, ``nan_nhan`` hoặc ``khac``.

    Theo IP, không theo giờ: ở CIC mọi tấn công đi qua NAT 172.16.0.1, nên một IP có thể là bên
    tấn công cả ngày dù chỉ tấn công trong vài khung giờ.
    """
    attackers = set().union(*(r.attackers for r in rules)) if rules else set()
    victims = set().union(*(r.victims for r in rules)) if rules else set()
    host = df["host"].astype(str).to_numpy()
    out = np.full(len(df), "khac", dtype=object)
    out[np.isin(host, list(victims))] = "nan_nhan"
    out[np.isin(host, list(attackers))] = "ben_tan_cong"
    return out


def class_groups(df, rules) -> np.ndarray:
    """Đợt tấn công (``nhan_goc``) của từng mẫu tấn công, chỉ xét các đợt cùng lớp với nhãn của mẫu.

    ``benign`` cho mẫu benign; ``khác`` nếu không khớp đợt nào của lớp đó (sát ranh giới).
    """
    y = df[LABEL_COL].to_numpy()
    out = np.where(y == "benign", "benign", "khác").astype(object)
    for c in set(y) - {"benign"}:
        m = y == c
        same = [r for r in rules if r.label == c]
        g = attack_groups(df[m].assign(label_anomaly="anomaly"), same)
        out[m] = g
    return out


def _counts(series) -> dict:
    return {str(k): int(v) for k, v in series.value_counts().sort_index().items()}


def class_report(df, rules) -> dict:
    """Số mẫu từng lớp theo tập, theo đợt tấn công và vai trò host; mẫu bị loại và lý do."""
    data, label_col = select_samples(df, MODULE_ATTACK)
    data = data[data["split"].isin(SPLITS)]
    groups = class_groups(data, rules)
    roles = host_roles(data, rules)
    out = {"lop": list(ATTACK_LABELS), "phien": sorted(df["session"].unique()),
           "theo_tap": {}, "theo_dot": {}, "theo_vai_tro": {}, "canh_bao": []}
    for s in SPLITS:
        m = (data["split"] == s).to_numpy()
        out["theo_tap"][s] = {c: int((data[label_col].to_numpy()[m] == c).sum()) for c in ATTACK_LABELS}
        attack = m & (data[label_col] != "benign").to_numpy()
        out["theo_dot"][s] = _counts(pd.Series(groups[attack]))
        out["theo_vai_tro"][s] = {
            c: _counts(pd.Series(roles[m & (data[label_col] == c).to_numpy()])) for c in ATTACK_LABELS}
        for c, n in out["theo_tap"][s].items():
            if n < MIN_CLASS_SAMPLES:
                out["canh_bao"].append(f"{c} ở {s} chỉ có {n} mẫu: chỉ số của lớp này dao động lớn")
    excluded = df[df["label_status"] == STATUS_EXCLUDED]
    excluded = excluded[excluded["split"].isin(SPLITS)]
    exg = attack_groups(excluded.assign(label_anomaly="anomaly"), rules)
    out["bi_loai"] = {
        g: {"so_mau": {s: int(((exg == g) & (excluded["split"] == s).to_numpy()).sum()) for s in SPLITS},
            "ly_do": EXCLUDED_REASONS.get(g, "")}
        for g in sorted(set(exg))}
    amb = df[df["label_status"] == STATUS_AMBIGUOUS]
    out["mo_ho"] = {s: int((amb["split"] == s).sum()) for s in SPLITS}
    out["tong"] = {s: int(sum(out["theo_tap"][s].values())) for s in SPLITS}
    return out


# ---- C07-T02, T03: dữ liệu, mô hình, chỉ số ----

SHORT = {"logistic_regression": "lr", "random_forest": "rf"}


def prepare_data(df, max_ratio=10, seed=42, dedup=True) -> dict:
    """Ba tập dạng bảng gốc. Train: bỏ trùng rồi giảm mẫu (chỉ train); validation, test giữ nguyên.

    Trả thêm ``train_full`` (train sau bỏ trùng, trước giảm mẫu): bộ tiền xử lý fit trên bảng này
    để trung vị và chuẩn hóa phản ánh đủ dữ liệu train (như C05-T07).
    """
    data, label_col = select_samples(df, MODULE_ATTACK)
    feats = feature_columns(TABLE)
    parts = {s: data[data["split"] == s].reset_index(drop=True) for s in SPLITS}
    train = parts["train"]
    n0 = len(train)
    if dedup:
        train = drop_duplicates(train, feats, label_col).reset_index(drop=True)
    full = train
    if max_ratio:
        keep = balance_indices(train[label_col].to_numpy(), max_ratio, seed)
        train = train.iloc[keep].reset_index(drop=True)
    return {"train": train, "train_full": full, "validation": parts["validation"], "test": parts["test"],
            "info": {"so_mau_train_truoc_bo_trung": n0, "so_mau_train_sau_bo_trung": len(full),
                     "ty_le_can_bang": max_ratio, "seed": seed,
                     "lop_train": _counts(train[label_col]),
                     "lop_validation": _counts(parts["validation"][label_col]),
                     "lop_test": _counts(parts["test"][label_col])}}


def make_estimator(kind, params, seed=42):
    params = dict(params or {})
    if kind == "logistic_regression":
        from sklearn.linear_model import LogisticRegression
        params.setdefault("max_iter", 3000)
        return LogisticRegression(random_state=seed, **params)
    if kind == "random_forest":
        from sklearn.ensemble import RandomForestClassifier
        params.setdefault("n_jobs", 4)
        return RandomForestClassifier(random_state=seed, **params)
    raise ValueError(f"mô hình chưa hỗ trợ: {kind}")


class AttackClassifier:
    """Bộ tiền xử lý (fit trên train) và một mô hình phân loại; dự đoán từ bảng cửa sổ thô."""

    def __init__(self, kind, params=None, seed=42):
        self.kind = kind
        self.params = dict(params or {})
        self.seed = seed
        self.preprocessor = None
        self.estimator = None
        self.info = {}

    def fit(self, train, fit_frame=None):
        feats = feature_columns(TABLE)
        fit_frame = train if fit_frame is None else fit_frame
        self.preprocessor = Preprocessor(TABLE, feats, log_columns(TABLE, feats)).fit(fit_frame)
        self.estimator = make_estimator(self.kind, self.params, self.seed)
        self.estimator.fit(self.preprocessor.transform(train), train[LABEL_COL].to_numpy())
        self.info.update({"so_mau_train": len(train), "lop_train": _counts(train[LABEL_COL])})
        return self

    @property
    def classes(self):
        return list(self.estimator.classes_)

    @property
    def features(self):
        return self.preprocessor.features

    def predict(self, df) -> np.ndarray:
        return self.estimator.predict(self.preprocessor.transform(df))

    def predict_proba(self, df) -> np.ndarray:
        return self.estimator.predict_proba(self.preprocessor.transform(df))


def multiclass_metrics(y_true, y_pred, labels=ATTACK_LABELS) -> dict:
    """Macro-F1, accuracy, chỉ số từng lớp và confusion matrix (hàng: nhãn thật, cột: dự đoán)."""
    from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    p, r, f, n = precision_recall_fscore_support(y_true, y_pred, labels=list(labels), zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=list(labels))
    return {
        "macro_f1": round(float(np.mean(f)), 4),
        "accuracy": round(float((y_true == y_pred).mean()), 4) if len(y_true) else 0.0,
        "theo_lop": {c: {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4),
                         "f1": round(float(f[i]), 4), "so_mau": int(n[i])} for i, c in enumerate(labels)},
        "confusion": {"nhan": list(labels), "ma_tran": cm.tolist()},
    }


def fit_and_score(kind, params, data, seed=42) -> tuple:
    """Fit trên train, đo trên train và validation (không đọc test)."""
    model = AttackClassifier(kind, params, seed).fit(data["train"], data["train_full"])
    res = {s: multiclass_metrics(data[s][LABEL_COL], model.predict(data[s])) for s in ("train", "validation")}
    return model, res


def lr_coefficients(model, top=6) -> dict:
    """Hệ số lớn nhất theo trị tuyệt đối của từng lớp (đặc trưng đã log và chuẩn hóa)."""
    names = model.preprocessor.output_names
    coef = model.estimator.coef_
    out = {}
    for i, c in enumerate(model.classes):
        order = np.argsort(-np.abs(coef[i]))[:top]
        out[c] = {names[j]: round(float(coef[i][j]), 3) for j in order}
    return out


def _print_metrics(name, m):
    print(f"{name}: macro-F1 {m['macro_f1']}, accuracy {m['accuracy']}")
    for c, v in m["theo_lop"].items():
        print(f"   {c:10s} P {v['precision']:.4f} R {v['recall']:.4f} F1 {v['f1']:.4f} n {v['so_mau']}")
    print("   confusion", m["confusion"]["ma_tran"])


def cmd_try(args):
    from .config import load_config

    cfg = classifier_config(load_config(args.config))
    df = load_data(args.prefixes, cfg["sessions"])
    data = prepare_data(df, cfg["balance_max_ratio"], cfg["random_seed"], cfg["drop_train_duplicates"])
    model, res = fit_and_score(args.kind, cfg.get(args.kind), data, cfg["random_seed"])
    rep = {"mo_hinh": args.kind, "tham_so": model.estimator.get_params(), "du_lieu": data["info"], **res}
    if args.kind == "logistic_regression":
        rep["he_so"] = lr_coefficients(model)
    else:
        rep["do_quan_trong"] = dict(sorted(
            zip(model.preprocessor.output_names, np.round(model.estimator.feature_importances_, 4).tolist()),
            key=lambda kv: -kv[1]))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"phan_loai_{SHORT[args.kind]}_validation.json"
    path.write_text(json.dumps(rep, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print("Dữ liệu:", data["info"])
    for s in ("train", "validation"):
        _print_metrics(s, res[s])
    print(f"Đã ghi: {path}")


# ---- C07-T04: chọn tham số và mô hình trên validation ----

def _grid(space) -> list[dict]:
    import itertools

    keys = list(space)
    return [dict(zip(keys, vals)) for vals in itertools.product(*(space[k] for k in keys))]


def _row(kind, ratio, params, res, seconds) -> dict:
    v = res["validation"]
    return {"mo_hinh": kind, "ty_le_can_bang": ratio, "tham_so": params,
            "macro_f1_validation": v["macro_f1"], "macro_f1_train": res["train"]["macro_f1"],
            **{f"f1_{c}": v["theo_lop"][c]["f1"] for c in ATTACK_LABELS},
            **{f"precision_{c}": v["theo_lop"][c]["precision"] for c in ATTACK_LABELS if c != "benign"},
            **{f"recall_{c}": v["theo_lop"][c]["recall"] for c in ATTACK_LABELS if c != "benign"},
            "giay": round(seconds, 1)}


def search(kind, df, cfg, log=print) -> dict:
    """Hai bước, đều theo macro-F1 validation (không đọc test).

    1. Tỷ lệ giảm mẫu train × ``class_weight``, các tham số khác để mặc định của cấu hình.
    2. Các tham số còn lại của lưới, giữ tỷ lệ và ``class_weight`` tốt nhất ở bước 1.
    """
    import time

    space = dict((cfg["search"].get(kind) or {}))
    ratios = cfg["search"].get("balance_max_ratio", [cfg["balance_max_ratio"]])
    base = dict(cfg.get(kind) or {})
    weights = space.pop("class_weight", [base.get("class_weight")])
    datasets = {}

    def run(ratio, params):
        key = ratio if ratio is not None else "none"
        if key not in datasets:
            datasets[key] = prepare_data(df, ratio, cfg["random_seed"], cfg["drop_train_duplicates"])
        t = time.perf_counter()
        _, res = fit_and_score(kind, params, datasets[key], cfg["random_seed"])
        row = _row(kind, ratio, params, res, time.perf_counter() - t)
        log(f"  {kind} tỷ lệ {ratio} {params}: macro-F1 validation {row['macro_f1_validation']}")
        return row

    rows = []
    for ratio in ratios:
        for w in weights:
            rows.append(dict(run(ratio, {**base, "class_weight": w}), buoc=1))
    best1 = max(rows, key=lambda r: r["macro_f1_validation"])
    for extra in _grid(space):
        params = {**best1["tham_so"], **extra}
        if params == best1["tham_so"] or any(r["tham_so"] == params and r["ty_le_can_bang"] == best1["ty_le_can_bang"]
                                             for r in rows):
            continue
        rows.append(dict(run(best1["ty_le_can_bang"], params), buoc=2))
    best = max(rows, key=lambda r: r["macro_f1_validation"])
    return {"tot_nhat": best, "cac_lan_thu": rows}


def _macro_f1_fast(t, p, k) -> float:
    cm = np.bincount(t * k + p, minlength=k * k).reshape(k, k)
    tp = np.diag(cm).astype(float)
    denom = cm.sum(0) + cm.sum(1)
    return float(np.mean(np.divide(2 * tp, denom, out=np.zeros(k), where=denom > 0)))


def paired_bootstrap(y, pred_a, pred_b, n=1000, seed=42) -> dict:
    """Lấy lại mẫu validation có hoàn lại; tỷ lệ lần B hơn A và khoảng 95% của hiệu macro-F1 (B − A).

    Mẫu cửa sổ liền nhau không độc lập, nên khoảng này hẹp hơn thực tế; chỉ để thấy chênh lệch có
    vượt nhiễu lấy mẫu hay không.
    """
    labels = list(ATTACK_LABELS)
    idx = {c: i for i, c in enumerate(labels)}
    t = np.array([idx[v] for v in y])
    a = np.array([idx[v] for v in pred_a])
    b = np.array([idx[v] for v in pred_b])
    rng = np.random.default_rng(seed)
    diffs = np.empty(n)
    for i in range(n):
        s = rng.integers(0, len(t), len(t))
        diffs[i] = _macro_f1_fast(t[s], b[s], 3) - _macro_f1_fast(t[s], a[s], 3)
    return {"so_lan": n, "ty_le_b_hon_a": round(float((diffs > 0).mean()), 4),
            "hieu_trung_binh": round(float(diffs.mean()), 4),
            "khoang_95": [round(float(np.percentile(diffs, 2.5)), 4), round(float(np.percentile(diffs, 97.5)), 4)]}


def select_models(df, cfg, kinds=("logistic_regression", "random_forest"), log=print) -> dict:
    """Mỗi loại mô hình chọn tham số trên validation; mô hình cuối là loại có macro-F1 validation cao hơn."""
    out = {"mo_hinh": {}, "chi_so": "macro-F1 trên validation"}
    preds = {}
    for kind in kinds:
        log(f"{kind}:")
        res = search(kind, df, cfg, log)
        best = res["tot_nhat"]
        data = prepare_data(df, best["ty_le_can_bang"], cfg["random_seed"], cfg["drop_train_duplicates"])
        model, scores = fit_and_score(kind, best["tham_so"], data, cfg["random_seed"])
        preds[kind] = model.predict(data["validation"])
        out["mo_hinh"][kind] = {**res, "validation": scores["validation"]}
        y_val = data["validation"][LABEL_COL].to_numpy()        # như nhau với mọi tỷ lệ giảm mẫu
    chosen = max(kinds, key=lambda k: out["mo_hinh"][k]["tot_nhat"]["macro_f1_validation"])
    out["chon"] = chosen
    if len(kinds) == 2:
        out["bootstrap"] = {"a": kinds[0], "b": kinds[1], **paired_bootstrap(y_val, preds[kinds[0]], preds[kinds[1]])}
    return out


def cmd_select(args):
    from .config import load_config

    cfg = classifier_config(load_config(args.config))
    df = load_data(args.prefixes, cfg["sessions"])
    res = select_models(df, cfg)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "phan_loai_chon.json"
    path.write_text(json.dumps(res, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    for kind, r in res["mo_hinh"].items():
        b = r["tot_nhat"]
        print(f"{kind}: tỷ lệ {b['ty_le_can_bang']}, {b['tham_so']}, macro-F1 validation {b['macro_f1_validation']}")
    print("Chọn:", res["chon"], "| bootstrap:", res.get("bootstrap"))
    print(f"Đã ghi: {path}")


# ---- C07-T05: đánh giá trên test ----

def duplicate_mask(test, train, feats=None) -> np.ndarray:
    """Mẫu test có vector đặc trưng trùng hệt một mẫu train (ô trống coi như bằng nhau)."""
    feats = feats or feature_columns(TABLE)
    key = lambda d: pd.util.hash_pandas_object(d[feats].fillna(-1.2345e300), index=False).to_numpy()
    return np.isin(key(test), key(train))


def bootstrap_ci(y, pred, n=1000, seed=42) -> list:
    """Khoảng 95% của macro-F1 khi lấy lại mẫu có hoàn lại (mẫu liền nhau không độc lập: khoảng hẹp hơn thực)."""
    idx = {c: i for i, c in enumerate(ATTACK_LABELS)}
    t = np.array([idx[v] for v in y])
    p = np.array([idx[v] for v in pred])
    rng = np.random.default_rng(seed)
    vals = [_macro_f1_fast(t[s], p[s], 3) for s in (rng.integers(0, len(t), len(t)) for _ in range(n))]
    return [round(float(np.percentile(vals, 2.5)), 4), round(float(np.percentile(vals, 97.5)), 4)]


def evaluate(model, test, rules=None, train=None) -> dict:
    """Kết quả trên test: tổng, khoảng tin cậy, theo phiên, theo đợt, theo vai trò host, báo động giả."""
    from .gaussian import alert_episodes

    y = test[LABEL_COL].to_numpy()
    pred = model.predict(test)
    out = {"so_mau": len(test), **multiclass_metrics(y, pred), "khoang_95_macro_f1": bootstrap_ci(y, pred),
           "theo_phien": {}}
    for sess, idx in test.groupby("session").indices.items():
        part = test.iloc[idx]
        hours = (part["window_end"].max() - part["window_start"].min()) / 3600
        fa = (part[LABEL_COL] == "benign").to_numpy() & (pred[idx] != "benign")
        out["theo_phien"][sess] = {
            # Mỗi phiên chỉ có một lớp tấn công: tính macro-F1 trên các lớp có mặt, nếu không lớp vắng có F1 = 0
            "so_mau": len(idx), **{k: v for k, v in multiclass_metrics(
                y[idx], pred[idx], [c for c in ATTACK_LABELS if (y[idx] == c).any()]).items() if k != "confusion"},
            "gio": round(float(hours), 2), "cua_so_benign_bi_bao": int(fa.sum()),
            "dot_bao_dong_gia_moi_gio": round(alert_episodes(part.reset_index(drop=True), fa) / hours, 1) if hours else None}
    benign = y == "benign"
    out["ty_le_benign_bi_bao"] = round(float((pred[benign] != "benign").mean()), 5) if benign.any() else None
    if rules is not None:
        groups = class_groups(test, rules)
        out["theo_dot"] = {g: {"so_mau": int((groups == g).sum()), "recall": round(float((pred[groups == g] == y[groups == g]).mean()), 4),
                               "du_doan": _counts(pd.Series(pred[groups == g]))}
                           for g in sorted(set(groups) - {"benign"})}
        roles = host_roles(test, rules)
        out["theo_vai_tro"] = {r: {"so_mau_tan_cong": int(((roles == r) & ~benign).sum()),
                                   "recall_tan_cong": round(float((pred[(roles == r) & ~benign] == y[(roles == r) & ~benign]).mean()), 4)
                                   if ((roles == r) & ~benign).any() else None}
                               for r in ("ben_tan_cong", "nan_nhan")}
    if train is not None:
        dup = duplicate_mask(test, train)
        out["trung_train"] = {"so_mau": int(dup.sum()), "theo_lop": _counts(pd.Series(y[dup])),
                              "bo_mau_trung": {k: v for k, v in multiclass_metrics(y[~dup], pred[~dup]).items()
                                               if k in ("macro_f1", "theo_lop")}}
    return out


def refit_chosen(df, choice, cfg, kind) -> tuple:
    """Fit lại cấu hình tốt nhất của ``kind`` (đã chọn ở C07-T04) trên train; trả mô hình và dữ liệu."""
    best = choice["mo_hinh"][kind]["tot_nhat"]
    data = prepare_data(df, best["ty_le_can_bang"], cfg["random_seed"], cfg["drop_train_duplicates"])
    model = AttackClassifier(kind, best["tham_so"], cfg["random_seed"]).fit(data["train"], data["train_full"])
    model.info.update({"ty_le_can_bang": best["ty_le_can_bang"], "macro_f1_validation": best["macro_f1_validation"],
                       "du_lieu": data["info"]})
    return model, data


def plot_confusions(results, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, len(results), figsize=(5.2 * len(results), 4.4))
    axes = np.atleast_1d(axes)
    for ax, (name, r) in zip(axes, results.items()):
        cm = np.array(r["confusion"]["ma_tran"], float)
        norm = cm / np.maximum(cm.sum(1, keepdims=True), 1)
        ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
        labels = r["confusion"]["nhan"]
        ax.set_xticks(range(len(labels)), labels)
        ax.set_yticks(range(len(labels)), labels)
        for i in range(len(labels)):
            for j in range(len(labels)):
                ax.text(j, i, f"{int(cm[i, j])}\n{norm[i, j]:.1%}", ha="center", va="center", fontsize=8,
                        color="white" if norm[i, j] > 0.6 else "black")
        ax.set_xlabel("Dự đoán")
        ax.set_ylabel("Nhãn thật")
        ax.set_title(f"{name}: macro-F1 {r['macro_f1']}", fontsize=10)
    fig.suptitle("Test: confusion matrix (số mẫu và tỷ lệ theo hàng)", fontsize=10)
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)


def cmd_evaluate(args):
    from .config import load_config

    cfg = classifier_config(load_config(args.config))
    choice = json.loads(Path(args.chon).read_text(encoding="utf-8"))
    df = load_data(args.prefixes, cfg["sessions"])
    rules = load_schedule()
    res = {"chon_tren_validation": choice["chon"], "mo_hinh": {}}
    preds = {}
    for kind in choice["mo_hinh"]:
        model, data = refit_chosen(df, choice, cfg, kind)
        r = evaluate(model, data["test"], rules, data["train_full"])
        res["mo_hinh"][kind] = {"ty_le_can_bang": model.info["ty_le_can_bang"], "tham_so": model.params,
                                "macro_f1_validation": model.info["macro_f1_validation"], **r}
        preds[kind] = model.predict(data["test"])
        y_test = data["test"][LABEL_COL].to_numpy()
    kinds = list(preds)
    if len(kinds) == 2:
        res["bootstrap_test"] = {"a": kinds[0], "b": kinds[1], **paired_bootstrap(y_test, preds[kinds[0]], preds[kinds[1]])}
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "phan_loai_test.json").write_text(json.dumps(res, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    plot_confusions({SHORT[k].upper(): v for k, v in res["mo_hinh"].items()}, out / "phan_loai_confusion.png")
    for kind, r in res["mo_hinh"].items():
        _print_metrics(f"{kind} (test)", r)
        print("   khoảng 95%:", r["khoang_95_macro_f1"], "| benign bị báo:", r["ty_le_benign_bi_bao"])
        print("   theo đợt:", {g: v["recall"] for g, v in r.get("theo_dot", {}).items()})
    print("bootstrap:", res.get("bootstrap_test"))
    print(f"Đã ghi: {out / 'phan_loai_test.json'}, {out / 'phan_loai_confusion.png'}")


# ---- C07-T06: phân tích nhầm lẫn, lưu artifact ----

def error_table(model, test, rules) -> list:
    """Các cặp (nhãn thật, dự đoán) sai, tách theo đợt tấn công và vai trò host."""
    y = test[LABEL_COL].to_numpy()
    pred = model.predict(test)
    wrong = y != pred
    d = pd.DataFrame({"nhan": y[wrong], "du_doan": pred[wrong], "dot": class_groups(test, rules)[wrong],
                      "vai_tro": host_roles(test, rules)[wrong]})
    g = d.groupby(list(d.columns)).size().sort_values(ascending=False)
    return [{**dict(zip(d.columns, k)), "so_mau": int(v)} for k, v in g.items()]


def compare_profiles(model, df, label, features=None) -> dict:
    """Trung vị đặc trưng của mẫu lớp ``label`` đoán đúng, đoán sai, và của benign (để thấy vì sao sai)."""
    features = features or model.features
    y = df[LABEL_COL].to_numpy()
    pred = model.predict(df)
    groups = {"dung": (y == label) & (pred == label), "sai": (y == label) & (pred != label), "benign": y == "benign"}
    return {name: {"so_mau": int(m.sum()),
                   **{f: (None if not m.any() or pd.isna(df.loc[m, f].median()) else round(float(df.loc[m, f].median()), 3))
                      for f in features}}
            for name, m in groups.items()}


FLOW_COLS = ["first_index", "first_ts", "last_ts", "protocol", "fwd_ip", "bwd_ip", "bwd_port", "continuation",
             "packets", "syn_count", "fin_count", "rst_count", "ack_count", "psh_count", "urg_count"]
# Cửa sổ port_scan có ít hơn số lần thử TCP này (cả vào lẫn ra) coi là "ít hoạt động quét"
WEAK_SCAN_ATTEMPTS = 20


def load_attack_flows(prefixes, label) -> pd.DataFrame:
    """Flow mang nhãn ``label`` của các phiên (chỉ cột cần cho phân tích, để tiết kiệm bộ nhớ)."""
    parts = []
    for prefix in prefixes:
        lab = pd.read_csv(f"{prefix}.flows.labels.csv", usecols=["first_index", "label_attack"])
        keep = set(lab.loc[lab["label_attack"] == label, "first_index"])
        if not keep:
            continue
        chunks = [c[c["first_index"].isin(keep)] for c in
                  pd.read_csv(f"{prefix}.flows.csv", usecols=FLOW_COLS, chunksize=200_000,
                              dtype={"fwd_ip": str, "bwd_ip": str, "protocol": str})]
        parts.append(pd.concat(chunks).assign(session=Path(prefix).name))
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=FLOW_COLS + ["session"])


def flow_kind(f) -> np.ndarray:
    """Kiểu flow: ICMP, UDP, SCTP, TCP có SYN, TCP không SYN (FIN/NULL/Xmas/ACK...), TCP tiếp nối flow trước."""
    proto = f["protocol"].astype(str).str.lower().to_numpy()
    out = np.full(len(f), "khac", dtype=object)
    out[np.isin(proto, ["1", "icmp", "58", "icmpv6"])] = "icmp"
    out[np.isin(proto, ["17", "udp"])] = "udp"
    out[np.isin(proto, ["132", "sctp"])] = "sctp"
    tcp = np.isin(proto, ["6", "tcp"])
    cont = f["continuation"].fillna(0).astype(float).to_numpy() > 0
    syn = f["syn_count"].fillna(0).to_numpy() > 0
    out[tcp & syn] = "tcp_co_syn"
    out[tcp & ~syn] = "tcp_khong_syn"
    out[tcp & ~syn & cont] = "tcp_tiep_noi"
    return out


def scan_window_traffic(windows, flows, max_attempts=WEAK_SCAN_ATTEMPTS, pred=None) -> dict:
    """Flow tấn công trong các cửa sổ port_scan có ít lần thử TCP: kiểu flow, cổng, số gói.

    Flow thuộc cửa sổ khi host là một đầu của flow và flow chạm khoảng [window_start, window_end).
    """
    if pred is not None:
        windows = windows.assign(_pred=np.asarray(pred))
    w = windows[(windows[LABEL_COL] == "port_scan")]
    is_weak = (w["tcp_attempts_out"].fillna(0) < max_attempts) & (w["tcp_attempts_in"].fillna(0) < max_attempts)
    weak = w[is_weak]
    if weak.empty or flows.empty:
        return {"so_cua_so_it_hoat_dong": int(len(weak)), "so_cua_so_port_scan": int(len(w))}
    f = flows.sort_values("first_ts").reset_index(drop=True)
    f["kieu"] = flow_kind(f)
    starts = f["first_ts"].to_numpy(float)
    span = float((f["last_ts"] - f["first_ts"]).max())
    hits = []
    for h, ws, we, sess in weak[["host", "window_start", "window_end", "session"]].itertuples(index=False):
        lo, hi = np.searchsorted(starts, [ws - span, we])
        c = f.iloc[lo:hi]
        c = c[(c["last_ts"] >= ws) & (c["session"] == sess) & ((c["fwd_ip"] == h) | (c["bwd_ip"] == h))]
        hits.append(c.assign(cua_so=f"{h}@{ws}"))
    hit = pd.concat(hits, ignore_index=True) if hits else f.iloc[:0]
    per_window = hit.groupby("cua_so")["kieu"].agg(lambda s: s.value_counts().idxmax())
    extra = {}
    if pred is not None:
        ok = (w["_pred"] == "port_scan").to_numpy()
        keys = (w["host"].astype(str) + "@" + w["window_start"].astype(str)).to_numpy()
        kind = pd.Series(keys).map(per_window).fillna("khong_co_flow").to_numpy()
        extra = {"recall_cua_so_nhieu_hoat_dong": round(float(ok[~is_weak.to_numpy()].mean()), 4) if (~is_weak).any() else None,
                 "recall_cua_so_it_hoat_dong": round(float(ok[is_weak.to_numpy()].mean()), 4),
                 "recall_theo_kieu_chu_dao": {k: {"so_cua_so": int((kind[is_weak.to_numpy()] == k).sum()),
                                                  "recall": round(float(ok[is_weak.to_numpy() & (kind == k)].mean()), 4)}
                                              for k in sorted(set(kind[is_weak.to_numpy()]))}}
    return {**extra,
        "so_cua_so_port_scan": int(len(w)), "so_cua_so_it_hoat_dong": int(len(weak)),
        "flow_moi_cua_so_trung_vi": float(hit.groupby("cua_so").size().median()) if len(hit) else 0.0,
        "kieu_flow": _counts(hit["kieu"]),
        "kieu_chu_dao_cua_cua_so": _counts(per_window),
        "cong_dich_pho_bien": {str(int(k)): int(v) for k, v in hit["bwd_port"].dropna().value_counts().head(10).items()},
        "goi_moi_flow_trung_vi": float(hit["packets"].median()) if len(hit) else 0.0,
    }


def unseen_attacks(model, df, rules) -> dict:
    """Mô hình đoán gì với cửa sổ của đợt tấn công bị loại (DDoS, Heartbleed, Bot) trong test."""
    ex = df[(df["label_status"] == STATUS_EXCLUDED) & (df["split"] == "test")]
    if ex.empty:
        return {}
    groups = attack_groups(ex.assign(label_anomaly="anomaly"), rules)
    pred = model.predict(ex)
    return {g: {"so_mau": int((groups == g).sum()), "du_doan": _counts(pd.Series(pred[groups == g]))}
            for g in sorted(set(groups))}


def permutation_importance(model, df, n_repeats=3, seed=42) -> dict:
    """Macro-F1 giảm bao nhiêu khi xáo trộn từng đặc trưng gốc (trước tiền xử lý) trên ``df``."""
    rng = np.random.default_rng(seed)
    y = df[LABEL_COL].to_numpy()
    base = multiclass_metrics(y, model.predict(df))["macro_f1"]
    out = {}
    for f in model.features:
        drops = []
        for _ in range(n_repeats):
            shuffled = df.copy()
            shuffled[f] = rng.permutation(shuffled[f].to_numpy())
            drops.append(base - multiclass_metrics(y, model.predict(shuffled))["macro_f1"])
        out[f] = round(float(np.mean(drops)), 4)
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def model_metadata(model, cfg=None) -> dict:
    import datetime
    import platform

    import sklearn

    from .feature_export import _git_version

    return {
        "mo_hinh": f"{model.kind} phân loại {', '.join(model.classes)} trên cửa sổ host (Chặng 7)",
        "bang": TABLE, "loai": model.kind, "lop": model.classes, "tham_so": model.params, "seed": model.seed,
        "dac_trung": model.features, "cot_sau_tien_xu_ly": model.preprocessor.output_names,
        "tien_xu_ly": {"cot_log": model.preprocessor.log_features, **model.preprocessor.info},
        "cau_hinh": cfg, **{k: v for k, v in model.info.items()},
        "ma_nguon": _git_version(),
        "phien_ban": {"python": platform.python_version(), "numpy": np.__version__, "pandas": pd.__version__,
                      "scikit-learn": sklearn.__version__},
        "thoi_diem_tao": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    }


def save_model(model, path, cfg=None) -> Path:
    """Lưu bộ tiền xử lý và mô hình ra joblib, kèm file .json đọc được không cần Python."""
    import joblib

    if model.estimator is None:
        raise ValueError("mô hình chưa fit; không lưu")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path, compress=3)
    path.with_suffix(".json").write_text(
        json.dumps(model_metadata(model, cfg), ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return path


def load_model(path) -> AttackClassifier:
    import joblib

    model = joblib.load(path)
    if not isinstance(model, AttackClassifier):
        raise TypeError(f"{path} không phải mô hình phân loại của dự án")
    return model


def predict_frame(model, df) -> pd.DataFrame:
    """Nhãn dự đoán và xác suất từng lớp cho bảng cửa sổ thô (cần đủ cột đặc trưng)."""
    missing = [f for f in model.features if f not in df.columns]
    if missing:
        raise ValueError(f"bảng thiếu cột đặc trưng: {missing}")
    proba = model.predict_proba(df)
    out = df[["session", "host", "window_start"]].copy() if "session" in df else df[["host", "window_start"]].copy()
    out["du_doan"] = np.asarray(model.classes)[proba.argmax(1)]
    for i, c in enumerate(model.classes):
        out[f"p_{c}"] = np.round(proba[:, i], 4)
    return out.reset_index(drop=True)


MODEL_FILES = {"logistic_regression": "phan_loai_lr_windows.joblib", "random_forest": "phan_loai_rf_windows.joblib"}


def cmd_train(args):
    from .config import PROJECT_ROOT, load_config

    full = load_config(args.config)
    cfg = classifier_config(full)
    choice = json.loads(Path(args.chon).read_text(encoding="utf-8"))
    df = load_data(args.prefixes, cfg["sessions"])
    out_dir = Path(args.out or PROJECT_ROOT / full.get("paths", {}).get("model_dir", "models"))
    for kind in choice["mo_hinh"]:
        model, _ = refit_chosen(df, choice, cfg, kind)
        model.info["chon_tren_validation"] = kind == choice["chon"]
        path = save_model(model, out_dir / MODEL_FILES[kind], cfg)
        print(f"{kind}: {model.params}, macro-F1 validation {model.info['macro_f1_validation']} -> {path}")
    print("Mô hình chọn trên validation:", choice["chon"])


def cmd_analyze(args):
    from .config import load_config

    cfg = classifier_config(load_config(args.config))
    df = load_data(args.prefixes, cfg["sessions"])
    rules = load_schedule()
    data = prepare_data(df, None, cfg["random_seed"], cfg["drop_train_duplicates"])
    scan_flows = load_attack_flows(args.prefixes, "port_scan")
    res = {"quet_it_hoat_dong_train": scan_window_traffic(data["train_full"], scan_flows)}
    for path in args.model:
        model = load_model(path)
        r = {"loi_test": error_table(model, data["test"], rules)[:25],
             "port_scan_validation": compare_profiles(model, data["validation"], "port_scan"),
             "port_scan_test": compare_profiles(model, data["test"], "port_scan"),
             "dos_test": compare_profiles(model, data["test"], "dos"),
             "tan_cong_chua_hoc": unseen_attacks(model, df, rules),
             **{f"quet_it_hoat_dong_{sp}": scan_window_traffic(data[sp], scan_flows, pred=model.predict(data[sp]))
                for sp in ("validation", "test")}}
        if args.hoan_vi:
            r["hoan_vi_validation"] = permutation_importance(model, data["validation"], seed=cfg["random_seed"])
        res[model.kind] = r
        print(model.kind, "| sai nhiều nhất:", r["loi_test"][:6])
        print("   chưa học:", r["tan_cong_chua_hoc"])
        print("   quét ít hoạt động (test):", r["quet_it_hoat_dong_test"])
        if "hoan_vi_validation" in r:
            print("   hoán vị:", dict(list(r["hoan_vi_validation"].items())[:8]))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "phan_loai_phan_tich.json").write_text(json.dumps(res, ensure_ascii=False, indent=2, default=str),
                                                  encoding="utf-8")
    print(f"Đã ghi: {out / 'phan_loai_phan_tich.json'}")


def cmd_predict(args):
    from .gaussian import _load_features_only

    model = load_model(args.model)
    df = _load_features_only(args.prefixes) if args.khong_nhan else load_table(args.prefixes, TABLE)
    pred = predict_frame(model, df)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    pred.to_csv(out, index=False)
    print(f"{len(pred)} cửa sổ: {_counts(pred['du_doan'])}. Đã ghi: {out}")


def cmd_labels(args):
    from .config import load_config

    cfg = classifier_config(load_config(args.config))
    df = load_data(args.prefixes, cfg["sessions"])
    rep = class_report(df, load_schedule())
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "phan_loai_nhan.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
    print(pd.DataFrame(rep["theo_tap"]).to_string())
    for s in SPLITS:
        print(s, rep["theo_dot"][s])
    print("Bị loại:", {g: v["so_mau"] for g, v in rep["bi_loai"].items()})
    for w in rep["canh_bao"]:
        print("Cảnh báo:", w)
    print(f"Đã ghi: {out / 'phan_loai_nhan.json'}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Phân loại tấn công đa lớp trên cửa sổ host.")
    sub = parser.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("nhan", help="số mẫu từng lớp theo tập, đợt tấn công; mẫu bị loại (C07-T01)")
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--out", required=True, help="thư mục ghi JSON")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_labels)
    p = sub.add_parser("thu", help="fit một mô hình với tham số trong cấu hình, đo trên validation (C07-T02, T03)")
    p.add_argument("kind", choices=("logistic_regression", "random_forest"))
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--out", required=True, help="thư mục ghi JSON")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_try)
    p = sub.add_parser("chon", help="chọn tham số và mô hình theo macro-F1 validation (C07-T04)")
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--out", required=True, help="thư mục ghi JSON")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_select)
    p = sub.add_parser("danh-gia", help="fit lại cấu hình đã chọn, đánh giá trên test (C07-T05)")
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--chon", required=True, help="JSON của lệnh chon (docs/hinh/phan_loai_chon.json)")
    p.add_argument("--out", required=True, help="thư mục ghi JSON và hình")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_evaluate)
    p = sub.add_parser("huan-luyen", help="fit lại cấu hình đã chọn và lưu cả hai mô hình (C07-T06)")
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--chon", required=True, help="JSON của lệnh chon")
    p.add_argument("--out", help="thư mục lưu, mặc định models/")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_train)
    p = sub.add_parser("phan-tich", help="phân tích nhầm lẫn bằng mô hình đã lưu (C07-T06)")
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--model", action="append", required=True, help="file joblib; lặp lại cho nhiều mô hình")
    p.add_argument("--out", required=True, help="thư mục ghi JSON")
    p.add_argument("--hoan-vi", action="store_true", help="thêm độ quan trọng hoán vị trên validation (chậm)")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_analyze)
    p = sub.add_parser("du-doan", help="nạp mô hình đã lưu và dự đoán bảng cửa sổ (C07-T06)")
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--model", required=True)
    p.add_argument("--out", required=True, help="file CSV kết quả")
    p.add_argument("--khong-nhan", action="store_true", help="bảng chưa gán nhãn, chưa chia tập")
    p.set_defaults(func=cmd_predict)
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    # Chạy bản của module đã import để đối tượng lưu bằng joblib nạp lại được (docs/32 mục 4).
    from nids.classifier import main as module_main
    sys.exit(module_main())

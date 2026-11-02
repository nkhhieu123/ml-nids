"""Phân loại tấn công đa lớp trên cửa sổ host: Benign, PortScan, DoS (Chặng 7).

- C07-T01: chốt nhãn thực tế: lớp nào, mẫu nào, đợt tấn công nào bị loại và vì sao
  (docs/39_phan_loai_nhan.md, QĐ-033).
- C07-T02: Logistic Regression làm mô hình đối chiếu (docs/40_phan_loai_lr.md, QĐ-034).
- C07-T03: Random Forest (docs/41_phan_loai_rf.md).
- C07-T04: chọn tham số và mô hình theo macro-F1 validation (docs/42_phan_loai_chon.md, QĐ-035).

    python -m nids.classifier nhan <tiền tố phiên>... --out docs/hinh
    python -m nids.classifier thu logistic_regression <tiền tố phiên>... --out docs/hinh
    python -m nids.classifier thu random_forest <tiền tố phiên>... --out docs/hinh
    python -m nids.classifier chon <tiền tố phiên>... --out docs/hinh

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
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    # Chạy bản của module đã import để đối tượng lưu bằng joblib nạp lại được (docs/32 mục 4).
    from nids.classifier import main as module_main
    sys.exit(module_main())

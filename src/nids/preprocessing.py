"""Tiền xử lý: chọn mẫu theo module, biến đổi, điền ô trống, chuẩn hóa, cân bằng lớp (C05-T07).

Mọi tham số (trung vị để điền, trung bình và độ lệch chuẩn để chuẩn hóa, số mẫu khi
cân bằng) chỉ học từ tập **train**; validation và test chỉ được biến đổi bằng tham
số đó và giữ nguyên phân bố lớp thật. Chi tiết ở docs/32_tien_xu_ly.md (QĐ-028).

    python -m nids.preprocessing --table windows --module attack_classification \\
        output/features/cic17_wednesday output/features/cic17_friday
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.utils.class_weight import compute_class_weight

from .config import PROJECT_ROOT, load_config
from .dataset import feature_columns, load_table
from .feature_export import table_schemas
from .labeling import STATUS_MATCHED, STATUS_UNMATCHED
from .scope import ANOMALY_LABELS, ATTACK_LABELS, MODULE_ANOMALY, MODULE_ATTACK

# Đơn vị của đặc trưng không cần log (tỷ lệ, entropy); còn lại là đếm, byte, giây: lệch phải mạnh
LINEAR_UNITS = {"tỷ lệ 0–1", "bit"}


def log_columns(table, feats) -> list[str]:
    unit = {c["ten"]: c["don_vi"] for c in table_schemas()[table]}
    return [f for f in feats if unit[f] not in LINEAR_UNITS]


def _signed_log1p(x):
    return np.sign(x) * np.log1p(np.abs(x))


@dataclass
class Preprocessor:
    """Biến đổi đã fit trên train; dùng lại nguyên vẹn cho validation, test và realtime."""
    table: str
    features: list
    log_features: list
    pipeline: Pipeline = None
    info: dict = field(default_factory=dict)

    def _log(self, df):
        X = df[self.features].astype(float).copy()
        X[self.log_features] = _signed_log1p(X[self.log_features])
        return X.to_numpy()

    def fit(self, df):
        self.pipeline = Pipeline([
            ("dien_o_trong", SimpleImputer(strategy="median", add_indicator=True,
                                           keep_empty_features=True)),
            ("chuan_hoa", StandardScaler()),
        ])
        self.pipeline.fit(self._log(df))
        imputer = self.pipeline.named_steps["dien_o_trong"]
        missing = [self.features[i] for i in imputer.indicator_.features_]
        self.info.update({"so_mau_fit": len(df), "cot_co_danh_dau_trong": missing})
        return self

    def transform(self, df):
        return self.pipeline.transform(self._log(df))

    @property
    def output_names(self):
        imputer = self.pipeline.named_steps["dien_o_trong"]
        return self.features + [f"{self.features[i]}__trong" for i in imputer.indicator_.features_]


def select_samples(df, module) -> tuple[pd.DataFrame, str]:
    """Mẫu dùng cho từng module và cột nhãn tương ứng.

    - attack_classification: nhãn chắc chắn (``khop`` hoặc ``khong_khop``) trong ba lớp.
    - anomaly: mẫu có nhãn normal/anomaly (bỏ ``mo_ho`` không xác định).
    """
    if module == MODULE_ATTACK:
        keep = df["label_status"].isin([STATUS_MATCHED, STATUS_UNMATCHED]) & \
            df["label_attack"].isin(ATTACK_LABELS)
        return df[keep], "label_attack"
    if module == MODULE_ANOMALY:
        return df[df["label_anomaly"].isin(ANOMALY_LABELS)], "label_anomaly"
    raise ValueError(f"module chưa hỗ trợ: {module}")


def balance(X, y, max_ratio, seed) -> tuple[np.ndarray, np.ndarray]:
    """Giảm mẫu ngẫu nhiên mỗi lớp xuống tối đa ``max_ratio`` lần lớp ít nhất. Chỉ gọi trên train."""
    rng = np.random.default_rng(seed)
    labels, counts = np.unique(y, return_counts=True)
    cap = int(counts.min() * max_ratio)
    keep = []
    for lab in labels:
        idx = np.flatnonzero(y == lab)
        if len(idx) > cap:
            idx = rng.choice(idx, cap, replace=False)
        keep.append(idx)
    keep = np.sort(np.concatenate(keep))
    return X[keep], y[keep]


def drop_duplicates(df, feats, label_col) -> pd.DataFrame:
    """Bỏ mẫu trùng hệt cả vector đặc trưng lẫn nhãn; giữ mẫu đầu tiên. Chỉ gọi trên train."""
    return df.drop_duplicates(subset=list(feats) + [label_col], keep="first")


def prepare(prefixes, table, module, max_ratio=None, seed=42, sessions=None,
            fit_sessions=None, dedup_train=False) -> dict:
    """Trả về X/y của ba tập, bộ tiền xử lý đã fit trên train và thông tin để ghi metadata.

    ``sessions``: chỉ dùng các phiên này (mặc định mọi phiên của ``prefixes``).
    ``fit_sessions``: với anomaly, chỉ fit trên train của các phiên này (phiên bình thường).
    ``dedup_train``: bỏ mẫu train trùng hệt trước khi fit và cân bằng.
    """
    df = load_table(prefixes, table)
    if sessions:
        df = df[df["session"].isin(sessions)]
    data, label_col = select_samples(df, module)
    feats = feature_columns(table)
    parts = {s: data[data["split"] == s] for s in ("train", "validation", "test")}
    train = parts["train"]
    if module == MODULE_ANOMALY:
        # Gaussian học phân bố bình thường: chỉ fit trên mẫu normal của train (C06-T01).
        train = train[train[label_col] == "normal"]
        if fit_sessions:
            train = train[train["session"].isin(fit_sessions)]
    n_before_dedup = len(train)
    if dedup_train:
        train = drop_duplicates(train, feats, label_col)
    pre = Preprocessor(table, feats, log_columns(table, feats)).fit(train)
    out = {"preprocessor": pre, "label_col": label_col}
    for s, part in parts.items():
        src = train if s == "train" else part
        out[f"X_{s}"] = pre.transform(src)
        out[f"y_{s}"] = src[label_col].to_numpy()
    before = dict(zip(*np.unique(out["y_train"], return_counts=True)))
    if max_ratio and module == MODULE_ATTACK:
        out["X_train"], out["y_train"] = balance(out["X_train"], out["y_train"], max_ratio, seed)
    classes = np.unique(out["y_train"])
    weights = compute_class_weight("balanced", classes=classes, y=out["y_train"])
    pre.info.update({
        "bang": table, "module": module, "phien": sorted(df["session"].unique()),
        "phien_fit": sorted(train["session"].unique()),
        "so_mau_train_truoc_bo_trung": n_before_dedup, "so_mau_train_sau_bo_trung": len(train),
        "so_dac_trung_vao": len(feats), "so_cot_ra": len(pre.output_names),
        "cot_log": pre.log_features,
        "lop_train_truoc_can_bang": {k: int(v) for k, v in before.items()},
        "lop_train_sau_can_bang": {k: int(v) for k, v in zip(*np.unique(out["y_train"], return_counts=True))},
        "trong_so_lop": {k: round(float(w), 6) for k, w in zip(classes, weights)},
        "lop_validation": {k: int(v) for k, v in zip(*np.unique(out["y_validation"], return_counts=True))},
        "lop_test": {k: int(v) for k, v in zip(*np.unique(out["y_test"], return_counts=True))},
        "can_bang": {"ty_le_toi_da": max_ratio, "seed": seed} if max_ratio and module == MODULE_ATTACK else None,
    })
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fit tiền xử lý trên train và lưu lại.")
    parser.add_argument("prefixes", nargs="+")
    parser.add_argument("--table", choices=("flows", "windows"), required=True)
    parser.add_argument("--module", choices=(MODULE_ATTACK, MODULE_ANOMALY), required=True)
    parser.add_argument("--out", help="file joblib, mặc định models/preprocess_<bảng>_<module>.joblib")
    parser.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    p = cfg["preprocess"]
    res = prepare(args.prefixes, args.table, args.module, p["balance_max_ratio"], cfg["random_seed"],
                  p["sessions"][args.module],
                  p["anomaly_fit_sessions"] if args.module == MODULE_ANOMALY else None,
                  # Gaussian ước lượng phân bố: tần suất mẫu lặp là thông tin, không bỏ trùng.
                  p["drop_train_duplicates"] and args.module == MODULE_ATTACK)
    pre = res["preprocessor"]
    out = Path(args.out or PROJECT_ROOT / "models" / f"preprocess_{args.table}_{args.module}.joblib")
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pre, out)
    out.with_suffix(".json").write_text(json.dumps(pre.info, ensure_ascii=False, indent=2), encoding="utf-8")
    for s in ("train", "validation", "test"):
        print(f"  {s}: X {res[f'X_{s}'].shape}")
    print(f"  phiên: {pre.info['phien']}; fit trên {pre.info['phien_fit']}")
    print(f"  mẫu train trước/sau bỏ trùng: {pre.info['so_mau_train_truoc_bo_trung']} -> "
          f"{pre.info['so_mau_train_sau_bo_trung']}")
    print(f"  lớp train trước/sau cân bằng: {pre.info['lop_train_truoc_can_bang']} -> "
          f"{pre.info['lop_train_sau_can_bang']}")
    print(f"Đã lưu: {out}")
    return 0


if __name__ == "__main__":
    # Chạy bản của module đã import: nếu dùng trực tiếp bản trong __main__, joblib ghi lớp là
    # __main__.Preprocessor và chương trình khác không nạp lại được.
    from nids.preprocessing import main as module_main
    sys.exit(module_main())

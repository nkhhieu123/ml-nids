"""Đọc bảng đặc trưng kèm nhãn và tập (train/validation/test) vào pandas (C05).

Mỗi phiên là một tiền tố, ví dụ ``output/features/cic17_wednesday``, có các file
của nids.feature_export, nids.labeling và nids.splits:

    <tiền tố>.flows.csv  .flows.labels.csv  .flows.split.csv  .schema.json
    <tiền tố>.windows.csv  .windows.labels.csv  .windows.split.csv

    from nids.dataset import load_table, feature_columns
    df = load_table(["output/features/cic17_wednesday", "output/features/cic17_friday"], "windows")
    X = df[feature_columns("windows")]
"""

import json
from pathlib import Path

import pandas as pd

from .feature_export import ROLE_FEATURE, SCHEMA_VERSION, TYPE_FLOAT, TYPE_INT, TYPE_STR, TYPE_TIME

TABLES = ("flows", "windows")
KEYS = {"flows": ["first_index"], "windows": ["host", "window_start"]}


def _schema(prefix) -> dict:
    schema = json.loads(Path(f"{prefix}.schema.json").read_text(encoding="utf-8"))
    if schema["phien_ban_schema"] != SCHEMA_VERSION:
        raise ValueError(f"{prefix}.schema.json: schema {schema['phien_ban_schema']}, cần {SCHEMA_VERSION}")
    return schema


def columns(table, prefix=None, role=None) -> list[str]:
    """Tên cột của bảng theo schema; lọc theo vai trò nếu có ``role``."""
    from .feature_export import table_schemas
    cols = _schema(prefix)["bang"][table] if prefix else table_schemas()[table]
    return [c["ten"] for c in cols if role is None or c["vai_tro"] == role]


def feature_columns(table, prefix=None) -> list[str]:
    """Cột có vai trò ``dac_trung``: đầu vào duy nhất của mô hình (QĐ-024)."""
    return columns(table, prefix, ROLE_FEATURE)


def _dtypes(prefix, table):
    out = {}
    for c in _schema(prefix)["bang"][table]:
        # Thời điểm đọc dạng số thực (giây) để so sánh, nối khóa; số nguyên đọc dạng
        # số thực vì có thể có ô trống.
        out[c["ten"]] = {TYPE_STR: str, TYPE_INT: "float64", TYPE_FLOAT: "float64",
                         TYPE_TIME: "float64"}[c["kieu"]]
    return out


def load_one(prefix, table) -> pd.DataFrame:
    """Bảng của một phiên, nối nhãn và tập theo khóa; thêm cột ``session``."""
    if table not in TABLES:
        raise ValueError(f"bảng phải là một trong {TABLES}")
    prefix = str(prefix)
    df = pd.read_csv(f"{prefix}.{table}.csv", dtype=_dtypes(prefix, table))
    key = KEYS[table]
    key_types = {"first_index": "float64", "host": str, "window_start": "float64"}
    for extra in ("labels", "split"):
        path = Path(f"{prefix}.{table}.{extra}.csv")
        if path.exists():
            part = pd.read_csv(path, dtype={**{k: key_types[k] for k in key},
                                            "label_attack": str, "label_anomaly": str,
                                            "label_status": str, "rule_id": str, "split": str})
            df = df.merge(part, on=key, how="left", validate="one_to_one")
    df.insert(0, "session", Path(prefix).name)
    return df


def load_table(prefixes, table) -> pd.DataFrame:
    """Gộp bảng của nhiều phiên."""
    if isinstance(prefixes, (str, Path)):
        prefixes = [prefixes]
    return pd.concat([load_one(p, table) for p in prefixes], ignore_index=True)

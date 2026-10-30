"""Phiên giả lập cho kiểm thử C05-T05 đến T07: bảng đúng cột theo schema, nhãn và tập."""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from nids.dataset import feature_columns
from nids.feature_export import schema_document, table_schemas

SPLIT_CYCLE = ["train"] * 6 + ["validation"] * 2 + ["test"] * 2


def make_session(d: Path, name: str, n: int, seed: int, attack="port_scan") -> str:
    """Phiên giả lập: bảng đúng cột theo schema, nhãn và tập ghép theo khóa."""
    rng = np.random.default_rng(seed)
    prefix = d / name
    (d / f"{name}.schema.json").write_text(json.dumps(schema_document()), encoding="utf-8")
    for table in ("flows", "windows"):
        cols = table_schemas()[table]
        data = {}
        for c in cols:
            if c["kieu"] == "str":
                data[c["ten"]] = [f"10.0.0.{i % 7}" for i in range(n)]
            elif c["kieu"] == "thoi_diem":
                data[c["ten"]] = 1000.0 + np.arange(n) * 3
            else:
                data[c["ten"]] = rng.integers(0, 50, n).astype(float)
        df = pd.DataFrame(data)
        if table == "flows":
            df["first_index"] = np.arange(n)
            key = df[["first_index"]]
        else:
            key = df[["host", "window_start"]]
        is_attack = np.arange(n) % 3 == 0           # có ở cả ba tập
        df.loc[is_attack, feature_columns(table)[0]] += 1000          # lớp tấn công tách biệt
        df.loc[np.arange(n) % 4 == 0, "iat_mean" if table == "flows" else "dst_port_entropy"] = np.nan
        df.to_csv(d / f"{name}.{table}.csv", index=False)
        labels = key.copy()
        labels["label_attack"] = np.where(is_attack, attack, "benign")
        labels["label_anomaly"] = np.where(is_attack, "anomaly", "normal")
        labels["label_status"] = np.where(is_attack, "khop", "khong_khop")
        labels["rule_id"] = np.where(is_attack, "r", "")
        labels.to_csv(d / f"{name}.{table}.labels.csv", index=False)
        split = key.copy()
        split["split"] = [SPLIT_CYCLE[i % 10] for i in range(n)]
        split.loc[n - 1, "split"] = "bo"
        split.to_csv(d / f"{name}.{table}.split.csv", index=False)
    return str(prefix)

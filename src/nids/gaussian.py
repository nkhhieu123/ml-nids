"""Phát hiện bất thường bằng Gaussian đa biến trên cửa sổ host (Chặng 6).

- C06-T01: chọn đặc trưng theo quy tắc chạy trên train, lấy mẫu normal của train
  (docs/33_gaussian_dac_trung.md, QĐ-029).

Mọi bước học (chọn đặc trưng, biến đổi, trung bình, hiệp phương sai) chỉ dùng mẫu
``normal`` của tập train; validation dùng để chọn ngưỡng, test chỉ để đánh giá.
"""

import numpy as np
import pandas as pd

from .dataset import feature_columns, load_table
from .preprocessing import select_samples
from .scope import MODULE_ANOMALY

TABLE = "windows"
# Bỏ cột trống quá tỷ lệ này trong train: Gaussian cần giá trị ở mọi cột
MAX_EMPTY_SHARE = 0.5
# Bỏ một cột trong mỗi cặp có |Spearman| từ mức này trở lên trên train
MAX_ABS_CORR = 0.95
# Cột bằng đúng tổng các cột khác: giữ cả hai làm hiệp phương sai suy biến chắc chắn
DERIVED = {"incomplete_out": ("no_reply_out", "rejected_out", "half_open_out")}
# Cột có thể trống mà trống mang nghĩa "không có gì": điền 0 thay vì bỏ
EMPTY_MEANS_ZERO = {"dst_port_entropy": "Không gửi gói TCP/UDP nào trong vai client: không có độ đa dạng cổng"}


def normal_train(df: pd.DataFrame, fit_sessions=None) -> pd.DataFrame:
    """Mẫu normal của tập train (chỉ các phiên ``fit_sessions`` nếu có)."""
    data, label_col = select_samples(df, MODULE_ANOMALY)
    train = data[(data["split"] == "train") & (data[label_col] == "normal")]
    if fit_sessions:
        train = train[train["session"].isin(fit_sessions)]
    return train


def select_features(train: pd.DataFrame, candidates=None) -> tuple[list, dict]:
    """Chọn đặc trưng cho Gaussian từ mẫu train; trả về (danh sách, lý do bỏ từng cột).

    Quy tắc, theo thứ tự: bỏ cột trống quá ``MAX_EMPTY_SHARE`` (trừ cột trống nghĩa là 0);
    bỏ cột là tổng của các cột khác; bỏ cột hằng số; với mỗi cặp tương quan Spearman
    |r| >= ``MAX_ABS_CORR`` bỏ cột đứng sau theo thứ tự schema.
    """
    candidates = list(candidates or feature_columns(TABLE))
    dropped = {}
    kept = []
    for f in candidates:
        share = train[f].isna().mean()
        if share > MAX_EMPTY_SHARE and f not in EMPTY_MEANS_ZERO:
            dropped[f] = f"trống {share:.1%} trong train"
        elif f in DERIVED and all(p in candidates for p in DERIVED[f]):
            dropped[f] = "bằng tổng " + " + ".join(DERIVED[f])
        else:
            kept.append(f)
    values = fill_empty(train[kept])
    for f in list(kept):
        if values[f].nunique() <= 1:
            dropped[f] = "hằng số trong train"
            kept.remove(f)
    corr = values[kept].rank().corr()          # Spearman = Pearson trên thứ hạng
    for i, a in enumerate(list(kept)):
        if a not in kept:
            continue
        for b in kept[kept.index(a) + 1:]:
            r = corr.loc[a, b]
            if abs(r) >= MAX_ABS_CORR:
                dropped[b] = f"tương quan Spearman {r:.3f} với {a}"
                kept.remove(b)
    return kept, dropped


def fill_empty(df: pd.DataFrame) -> pd.DataFrame:
    """Điền 0 cho các cột trống nghĩa là "không có gì" (``EMPTY_MEANS_ZERO``)."""
    out = df.copy()
    for f in EMPTY_MEANS_ZERO:
        if f in out:
            out[f] = out[f].fillna(0.0)
    return out


def load_windows(prefixes) -> pd.DataFrame:
    return load_table(prefixes, TABLE)

"""Phát hiện bất thường bằng Gaussian đa biến trên cửa sổ host (Chặng 6).

- C06-T01: chọn đặc trưng theo quy tắc chạy trên train, lấy mẫu normal của train
  (docs/33_gaussian_dac_trung.md, QĐ-029).
- C06-T02: biến đổi để phân bố gần dạng chuông: Yeo-Johnson cho cột liên tục, log(1 + x)
  cho cột gần như toàn 0 (docs/34_gaussian_phan_bo.md, QĐ-030).

Mọi bước học (chọn đặc trưng, biến đổi, trung bình, hiệp phương sai) chỉ dùng mẫu
``normal`` của tập train; validation dùng để chọn ngưỡng, test chỉ để đánh giá.
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.preprocessing import PowerTransformer, StandardScaler

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


# ---- C06-T02: biến đổi ----

# Cột có từ tỷ lệ này giá trị 0 trở lên trong train dùng log(1 + x): λ của Yeo-Johnson học từ
# vài chục mẫu khác 0 không đáng tin, và không phép lũy thừa nào biến khối dồn tại 0 thành chuông.
ZERO_HEAVY_SHARE = 0.9


class GaussianTransform:
    """Biến đổi đặc trưng trước Gaussian; mọi tham số học từ mẫu train.

    Cột liên tục: Yeo-Johnson (λ học trên train). Cột gần như toàn 0: log(1 + x). Sau đó
    chuẩn hóa về trung bình 0, độ lệch chuẩn 1 theo train.
    """

    def __init__(self, features):
        self.features = list(features)
        self.yj_features = []
        self.log_features = []
        self.power = None
        self.scaler = None

    def fit(self, df):
        X = fill_empty(df[self.features]).astype(float)
        zero = (X == 0).mean()
        self.yj_features = [f for f in self.features if zero[f] < ZERO_HEAVY_SHARE]
        self.log_features = [f for f in self.features if zero[f] >= ZERO_HEAVY_SHARE]
        if self.yj_features:
            self.power = PowerTransformer(method="yeo-johnson", standardize=False)
            self.power.fit(X[self.yj_features])
        self.scaler = StandardScaler().fit(self._raw(X))
        return self

    def _raw(self, X):
        parts = []
        if self.yj_features:
            parts.append(pd.DataFrame(self.power.transform(X[self.yj_features]),
                                      columns=self.yj_features, index=X.index))
        if self.log_features:
            parts.append(np.log1p(X[self.log_features].clip(lower=0)))
        return pd.concat(parts, axis=1)[self.features].to_numpy()

    def transform(self, df) -> np.ndarray:
        X = fill_empty(df[self.features]).astype(float)
        return self.scaler.transform(self._raw(X))

    @property
    def lambdas(self) -> dict:
        if not self.yj_features:
            return {}
        return {f: round(float(v), 4) for f, v in zip(self.yj_features, self.power.lambdas_)}


def normality_report(Z, features) -> dict:
    """Độ lệch, độ nhọn dư của từng cột và so phân vị d² với χ²(số cột)."""
    sk = stats.skew(Z, axis=0)
    ku = stats.kurtosis(Z, axis=0)
    cov = np.cov(Z, rowvar=False)
    ev = np.linalg.eigvalsh(cov)
    d2 = np.einsum("ij,jk,ik->i", Z, np.linalg.pinv(cov), Z)
    qs = [0.5, 0.9, 0.99, 0.999]
    return {
        "theo_cot": {f: {"skew": round(float(a), 3), "kurtosis_du": round(float(b), 3)}
                     for f, a, b in zip(features, sk, ku)},
        "skew_tri_tuyet_doi_trung_vi": round(float(np.median(np.abs(sk))), 3),
        "tri_rieng_nho_nhat": float(ev.min()),
        "chi_so_dieu_kien": float(ev.max() / ev.min()) if ev.min() > 0 else None,
        "d2_phan_vi": {str(q): round(float(v), 2) for q, v in zip(qs, np.quantile(d2, qs))},
        "chi2_phan_vi": {str(q): round(float(v), 2) for q, v in zip(qs, stats.chi2.ppf(qs, len(features)))},
    }


def compare_transforms(train, features) -> dict:
    """So giữ nguyên, log(1 + x) và cách kết hợp của GaussianTransform trên train."""
    X = fill_empty(train[features]).astype(float).to_numpy()
    t = GaussianTransform(features).fit(train)
    return {
        "giu_nguyen": normality_report(StandardScaler().fit_transform(X), features),
        "log1p": normality_report(StandardScaler().fit_transform(np.log1p(X)), features),
        "yeo_johnson_va_log": normality_report(t.transform(train), features),
        "cot_yeo_johnson": t.yj_features, "cot_log": t.log_features, "lambda": t.lambdas,
    }


def plot_distribution(train, features, out_dir) -> list:
    """Hình trước/sau biến đổi của vài cột, và QQ của d² so với χ²."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    t = GaussianTransform(features).fit(train)
    Z = t.transform(train)
    X = fill_empty(train[features]).astype(float)
    show = [f for f in ("packets_in", "new_conn_out", "dst_port_entropy", "no_reply_out") if f in features]
    fig, axes = plt.subplots(2, len(show), figsize=(4 * len(show), 6))
    for j, f in enumerate(show):
        axes[0, j].hist(X[f], bins=60, color="#8C8C8C", log=True)
        axes[0, j].set_title(f"{f}: gốc", fontsize=9)
        axes[1, j].hist(Z[:, features.index(f)], bins=60, color="#4C72B0", log=True)
        kind = "Yeo-Johnson" if f in t.yj_features else "log(1+x)"
        axes[1, j].set_title(f"{f}: sau {kind}, chuẩn hóa", fontsize=9)
    fig.suptitle("Phân bố trước và sau biến đổi (normal, train; trục dọc thang log)")
    fig.tight_layout()
    f1 = out_dir / "gauss_phan_bo.png"
    fig.savefig(f1, dpi=110)
    plt.close(fig)

    cov = np.cov(Z, rowvar=False)
    d2 = np.sort(np.einsum("ij,jk,ik->i", Z, np.linalg.inv(cov), Z))
    theo = stats.chi2.ppf((np.arange(1, len(d2) + 1) - 0.5) / len(d2), len(features))
    step = max(1, len(d2) // 4000)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.loglog(theo[::step], d2[::step], ".", ms=2, color="#4C72B0")
    lim = [theo.min(), max(theo.max(), d2.max())]
    ax.loglog(lim, lim, "--", color="black", lw=1, label="y = x (nếu đúng Gaussian)")
    ax.set_xlabel(f"Phân vị lý thuyết χ²({len(features)})")
    ax.set_ylabel("Phân vị d² thực tế")
    ax.set_title("QQ: khoảng cách Mahalanobis² của mẫu normal (train)")
    ax.legend()
    fig.tight_layout()
    f2 = out_dir / "gauss_qq_chi2.png"
    fig.savefig(f2, dpi=110)
    plt.close(fig)
    return [f1, f2]


# ---- C06-T03: mô hình Gaussian ----

# Trị riêng nhỏ hơn mức này lần trị riêng lớn nhất bị nâng lên mức đó (chỉ số điều kiện ≤ 1e6)
EIG_FLOOR_REL = 1e-6


def fit_covariance(Z, method="empirical", floor_rel=EIG_FLOOR_REL) -> tuple[np.ndarray, dict]:
    """Ma trận hiệp phương sai của Z (đã chuẩn hóa) và thông tin xử lý suy biến.

    ``empirical``: hiệp phương sai mẫu. ``ledoit_wolf``: co về ma trận đường chéo, hệ số co
    chọn tự động (Ledoit-Wolf 2004). Sau đó mọi trị riêng < ``floor_rel`` × trị riêng lớn nhất
    được nâng lên mức đó, nên ma trận luôn nghịch đảo được.
    """
    info = {"phuong_phap": method}
    if method == "ledoit_wolf":
        from sklearn.covariance import LedoitWolf
        lw = LedoitWolf(assume_centered=False).fit(Z)
        cov = lw.covariance_
        info["he_so_co"] = round(float(lw.shrinkage_), 6)
    elif method == "empirical":
        cov = np.cov(Z, rowvar=False)
    else:
        raise ValueError(f"phương pháp hiệp phương sai chưa hỗ trợ: {method}")
    cov = np.atleast_2d((cov + cov.T) / 2)
    ev, vec = np.linalg.eigh(cov)
    floor = max(float(ev.max()), 1e-12) * floor_rel
    raised = int((ev < floor).sum())
    info.update({"tri_rieng_nho_nhat_truoc": float(ev.min()), "so_tri_rieng_nang": raised,
                 "nguong_tri_rieng": floor})
    if raised:
        ev = np.maximum(ev, floor)
        cov = (vec * ev) @ vec.T
    info["chi_so_dieu_kien"] = float(ev.max() / ev.min())
    return cov, info


class GaussianDetector:
    """Gaussian đa biến trên cửa sổ host; điểm bất thường là khoảng cách Mahalanobis² (d²).

    Học (biến đổi, trung bình, hiệp phương sai) chỉ trên mẫu normal của train. ``threshold``
    đặt sau, trên validation (C06-T04). Dự đoán ``anomaly`` khi d² > ngưỡng.
    """

    def __init__(self, features, covariance="empirical"):
        self.features = list(features)
        self.covariance = covariance
        self.transform_ = None
        self.mean_ = None
        self.cov_ = None
        self.precision_ = None
        self.logdet_ = None
        self.threshold = None
        self.info = {}

    def fit(self, train):
        self.transform_ = GaussianTransform(self.features).fit(train)
        Z = self.transform_.transform(train)
        self.mean_ = Z.mean(axis=0)
        self.cov_, cov_info = fit_covariance(Z, self.covariance)
        self.precision_ = np.linalg.inv(self.cov_)
        self.logdet_ = float(np.linalg.slogdet(self.cov_)[1])
        self.info.update({"so_mau_fit": len(train), "so_dac_trung": len(self.features),
                          "hiep_phuong_sai": cov_info,
                          "cot_yeo_johnson": self.transform_.yj_features,
                          "cot_log": self.transform_.log_features})
        return self

    def score(self, df) -> np.ndarray:
        """d² của từng mẫu; càng lớn càng bất thường."""
        D = self.transform_.transform(df) - self.mean_
        return np.einsum("ij,jk,ik->i", D, self.precision_, D)

    def log_density(self, df) -> np.ndarray:
        """log mật độ Gaussian; xếp hạng ngược hẳn với d² (cùng một mô hình)."""
        k = len(self.features)
        return -0.5 * (self.score(df) + self.logdet_ + k * np.log(2 * np.pi))

    def predict(self, df) -> np.ndarray:
        if self.threshold is None:
            raise ValueError("chưa đặt ngưỡng: chạy chọn ngưỡng trên validation trước (C06-T04)")
        return np.where(self.score(df) > self.threshold, "anomaly", "normal")


def cmd_distribution(args):
    train = normal_train(load_windows(args.prefixes), args.fit_session)
    feats, dropped = select_features(train)
    report = {"so_mau": len(train), "dac_trung": feats, "cot_bo": dropped,
              **compare_transforms(train, feats)}
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "gauss_phan_bo.json").write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                            encoding="utf-8")
    for f in plot_distribution(train, feats, out):
        print(f"Đã ghi: {f}")
    for k in ("giu_nguyen", "log1p", "yeo_johnson_va_log"):
        r = report[k]
        print(f"{k}: |skew| trung vị {r['skew_tri_tuyet_doi_trung_vi']}, d² phân vị 99% "
              f"{r['d2_phan_vi']['0.99']} (χ² {r['chi2_phan_vi']['0.99']})")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Gaussian phát hiện bất thường trên cửa sổ host.")
    sub = parser.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("phan-bo", help="kiểm tra phân bố và các phép biến đổi (C06-T02)")
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--fit-session", action="append", help="chỉ dùng train của phiên này")
    p.add_argument("--out", required=True, help="thư mục ghi hình và JSON")
    p.set_defaults(func=cmd_distribution)
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    # Chạy bản của module đã import để đối tượng lưu bằng joblib nạp lại được (docs/32 mục 4).
    from nids.gaussian import main as module_main
    sys.exit(module_main())

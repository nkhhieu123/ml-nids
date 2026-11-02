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


# ---- C06-T04: điểm bất thường và ngưỡng ----

def attack_groups(df, rules, tolerance_s=60.0) -> np.ndarray:
    """Tên đợt tấn công (cột ``nhan_goc`` của lịch) của từng cửa sổ ``anomaly``; ``normal`` nếu không.

    Cửa sổ khớp đợt khi host là bên tấn công hoặc nạn nhân và cửa sổ chạm khung giờ (nới
    ``tolerance_s``). Nhiều đợt khớp thì lấy đợt ngắn nhất (bot kéo dài cả ngày bị ưu tiên sau).
    Chỉ dùng để báo cáo Recall theo loại tấn công, không dùng khi học hay chọn ngưỡng.
    """
    out = np.full(len(df), "normal", dtype=object)
    anomaly = (df["label_anomaly"] == "anomaly").to_numpy()
    out[anomaly] = "khác"
    host = df["host"].astype(str).to_numpy()
    start = df["window_start"].to_numpy(float)
    end = df["window_end"].to_numpy(float)
    for r in sorted(rules, key=lambda r: r.end_s - r.start_s, reverse=True):
        hit = anomaly & np.isin(host, list(r.attackers | r.victims)) & \
            (end > r.start_s - tolerance_s) & (start < r.end_s + tolerance_s)
        out[hit] = r.original
    return out


def binary_metrics(y_true, y_pred) -> dict:
    """Precision, Recall, F1, tỷ lệ báo động giả cho lớp ``anomaly`` (y là mảng bool)."""
    y_true = np.asarray(y_true, bool)
    y_pred = np.asarray(y_pred, bool)
    tp = int((y_pred & y_true).sum())
    fp = int((y_pred & ~y_true).sum())
    fn = int((~y_pred & y_true).sum())
    tn = int((~y_pred & ~y_true).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "fpr": round(fp / (fp + tn), 5) if fp + tn else 0.0,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def choose_threshold(scores, y, method="f1", target_fpr=0.01, band=1.2) -> float:
    """Ngưỡng d² chọn trên validation; dự đoán ``anomaly`` khi d² > ngưỡng.

    ``f1``: ngưỡng cho F1 lớn nhất (bằng nhau thì lấy ngưỡng cao hơn, ít báo động giả hơn).
    ``f1_on_dinh``: ngưỡng có F1 *xấu nhất* trong khoảng [t / band, t × band] lớn nhất, để
    ngưỡng không nằm sát một "vách" mà lệch nhẹ là F1 sụp (docs/36 mục 3).
    ``fpr``: ngưỡng để tỷ lệ báo động giả trên mẫu normal không vượt ``target_fpr``.
    """
    scores = np.asarray(scores, float)
    y = np.asarray(y, bool)
    if method == "fpr":
        return float(np.quantile(scores[~y], 1 - target_fpr, method="higher"))
    if method == "f1_on_dinh":
        curve = threshold_curve(scores, y, n=400)
        t, f1 = curve["nguong"].to_numpy(), curve["f1"].to_numpy()
        worst = np.array([f1[(t >= v / band) & (t <= v * band)].min() for v in t])
        return float(t[np.flatnonzero(worst == worst.max())[-1]])
    if method != "f1":
        raise ValueError(f"cách chọn ngưỡng chưa hỗ trợ: {method}")
    order = np.argsort(-scores, kind="stable")
    s, t = scores[order], y[order]
    tp = np.cumsum(t)
    fp = np.cumsum(~t)
    last = np.r_[s[1:] != s[:-1], True]          # chỉ xét điểm cắt giữa hai giá trị khác nhau
    tp, fp, s_cut = tp[last], fp[last], s[last]
    f1 = 2 * tp / (tp + fp + t.sum())
    best = np.flatnonzero(f1 == f1.max())[0]      # điểm cắt sớm nhất = ngưỡng cao nhất
    nxt = scores[scores < s_cut[best]]
    # đặt ngưỡng giữa giá trị cuối được báo và giá trị kế tiếp
    return float((s_cut[best] + nxt.max()) / 2) if len(nxt) else float(s_cut[best] - 1e-9)


def threshold_curve(scores, y, n=200) -> pd.DataFrame:
    """Precision, Recall, F1, FPR theo ngưỡng (lưới log) để vẽ và báo cáo độ nhạy."""
    scores = np.asarray(scores, float)
    lo = max(np.quantile(scores, 0.5), 1e-3)
    hi = np.quantile(scores, 0.9999)
    rows = []
    for t in np.geomspace(lo, hi, n):
        rows.append({"nguong": t, **binary_metrics(y, scores > t)})
    return pd.DataFrame(rows)


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


def labeled(df) -> pd.DataFrame:
    """Mẫu có nhãn normal/anomaly (bỏ ``mo_ho`` không xác định)."""
    data, _ = select_samples(df, MODULE_ANOMALY)
    return data


def plot_threshold(curve, threshold, path, title):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(7, 4.5))
    for col, name, color in (("precision", "Precision", "#4C72B0"), ("recall", "Recall", "#DD8452"),
                             ("f1", "F1", "#55A868")):
        ax.semilogx(curve["nguong"], curve[col], label=name, color=color)
    ax2 = ax.twinx()
    ax2.semilogx(curve["nguong"], curve["fpr"] * 100, "--", color="#8C8C8C", label="FPR (%)")
    ax2.set_ylabel("Tỷ lệ báo động giả (%)")
    ax.axvline(threshold, color="black", lw=1)
    ax.text(threshold, 0.02, f" ngưỡng {threshold:.1f}", fontsize=8)
    ax.set_xlabel("Ngưỡng d²")
    ax.set_ylim(0, 1)
    ax.set_title(title, fontsize=10)
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, loc="center left", fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)


def group_recall(groups, pred) -> dict:
    out = {}
    for g in sorted(set(groups) - {"normal"}):
        m = groups == g
        out[g] = {"so_mau": int(m.sum()), "recall": round(float(pred[m].mean()), 4)}
    return out


def gaussian_config(cfg) -> dict:
    g = dict(cfg.get("gaussian") or {})
    g.setdefault("covariance", "ledoit_wolf")
    g.setdefault("threshold", "f1_on_dinh")
    g.setdefault("threshold_band", 1.2)
    g.setdefault("target_fpr", 0.01)
    g.setdefault("fit_sessions", None)
    g.setdefault("fit_session_candidates", [["cic17_monday"], None])
    return g


def select_model(windows, cfg, rules=None):
    """Fit từng cách lấy mẫu normal, chọn ngưỡng trên validation, giữ cách có F1 validation cao nhất.

    Trả về (mô hình đã đặt ngưỡng, báo cáo, điểm validation, nhãn validation). Không đọc test.
    """
    val = labeled(windows)
    val = val[val["split"] == "validation"]
    y = (val["label_anomaly"] == "anomaly").to_numpy()
    groups = attack_groups(val, rules) if rules is not None else None
    report = {"so_mau_validation": len(val), "so_anomaly_validation": int(y.sum()),
              "cach_chon_nguong": cfg["threshold"], "ung_vien": []}
    best = None
    for fs in cfg["fit_session_candidates"]:
        train = normal_train(windows, fs)
        feats, dropped = select_features(train)
        model = GaussianDetector(feats, cfg["covariance"]).fit(train)
        sc = model.score(val)
        t = choose_threshold(sc, y, cfg["threshold"], cfg["target_fpr"], cfg["threshold_band"])
        t_max = choose_threshold(sc, y, "f1")
        res = {"phien_fit": fs or "tất cả", "so_mau_fit": len(train), "nguong": round(t, 3),
               **binary_metrics(y, sc > t),
               "so_sanh_f1_lon_nhat": {"nguong": round(t_max, 3), **binary_metrics(y, sc > t_max)}}
        if groups is not None:
            res["recall_theo_dot"] = group_recall(groups, sc > t)
        report["ung_vien"].append(res)
        if best is None or res["f1"] > best[1]["f1"]:  # so theo F1 validation tại ngưỡng đã chọn
            model.threshold = float(t)
            model.info.update({"phien_fit": sorted(train["session"].unique()), "cot_bo": dropped,
                               "cach_chon_nguong": cfg["threshold"], "nguong": float(t),
                               "validation": binary_metrics(y, sc > t)})
            best = (model, res, sc)
    model, res, sc = best
    report["chon"] = res["phien_fit"]
    report["nguong"] = res["nguong"]
    return model, report, sc, y


def cmd_threshold(args):
    from .config import load_config
    from .labeling import load_schedule

    cfg = gaussian_config(load_config(args.config))
    model, report, s, y = select_model(load_windows(args.prefixes), cfg, load_schedule())
    for r in report["ung_vien"]:
        print(f"fit {r['phien_fit']}: ngưỡng {r['nguong']:.1f}, P {r['precision']}, R {r['recall']}, "
              f"F1 {r['f1']}, FPR {r['fpr']}")
    res = next(r for r in report["ung_vien"] if r["phien_fit"] == report["chon"])
    curve = threshold_curve(s, y)
    near = curve[(curve["f1"] >= res["f1"] - 0.02)]
    report["khoang_nguong_f1_trong_0_02"] = [round(float(near["nguong"].min()), 1),
                                            round(float(near["nguong"].max()), 1)]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    plot_threshold(curve, model.threshold, out / "gauss_nguong.png",
                   f"Validation: chọn ngưỡng (fit trên {res['phien_fit']})")
    (out / "gauss_nguong.json").write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                           encoding="utf-8")
    print(f"Chọn fit trên {res['phien_fit']}, ngưỡng {model.threshold:.2f}. "
          f"Đã ghi: {out / 'gauss_nguong.json'}")
    for g, v in res["recall_theo_dot"].items():
        print(f"  {g}: {v['so_mau']} cửa sổ, recall {v['recall']}")


# ---- C06-T05: đánh giá trên test ----

def alert_episodes(df, flagged, gap_s=10.0) -> int:
    """Số đợt báo động: các cửa sổ bị báo liên tiếp của cùng host (cách nhau ≤ gap_s) gộp làm một."""
    d = df.loc[flagged, ["host", "window_start", "window_end"]].sort_values(["host", "window_start"])
    if d.empty:
        return 0
    new_host = d["host"].ne(d["host"].shift())
    gap = d["window_start"] - d["window_end"].shift()
    return int((new_host | (gap > gap_s)).sum())


def evaluate(model, test, rules=None) -> dict:
    """Kết quả trên test với ngưỡng đã chọn: tổng, theo phiên, theo đợt tấn công, báo động giả."""
    y = (test["label_anomaly"] == "anomaly").to_numpy()
    sc = model.score(test)
    pred = sc > model.threshold
    from sklearn.metrics import average_precision_score, roc_auc_score
    out = {"nguong": model.threshold, "so_mau": len(test), "so_anomaly": int(y.sum()),
           "tong": binary_metrics(y, pred),
           "auc": round(float(roc_auc_score(y, sc)), 4) if 0 < y.sum() < len(y) else None,
           "ap": round(float(average_precision_score(y, sc)), 4) if y.any() else None,
           "theo_phien": {}}
    for sess, idx in test.groupby("session").indices.items():
        m = np.zeros(len(test), bool)
        m[idx] = True
        normal = m & ~y
        part = test.iloc[idx]
        hours = (part["window_end"].max() - part["window_start"].min()) / 3600
        out["theo_phien"][sess] = {
            "so_mau": int(m.sum()), "so_anomaly": int(y[m].sum()), **binary_metrics(y[m], pred[m]),
            "gio": round(float(hours), 2),
            "dot_bao_dong_gia": alert_episodes(test, normal & pred),
            "dot_bao_dong_gia_moi_gio": round(alert_episodes(test, normal & pred) / hours, 1) if hours else None,
        }
    if rules is not None:
        out["recall_theo_dot"] = group_recall(attack_groups(test, rules), pred)
    for q in (0.99, 0.999):
        tc = float(stats.chi2.ppf(q, len(model.features)))
        out[f"neu_dung_nguong_chi2_{q}"] = {"nguong": round(tc, 2), **binary_metrics(y, sc > tc)}
    return out


def assumption_checks(model, train, val, test) -> dict:
    """So Gaussian đầy đủ với hai biến thể để đo giới hạn của giả định Gaussian.

    - Đường chéo: bỏ tương quan giữa các cột (giả định các cột độc lập).
    - Hỗn hợp 8 Gaussian: bỏ giả định "một đỉnh".
    Cùng biến đổi, cùng mẫu fit, ngưỡng chọn cùng cách trên validation.
    """
    from sklearn.metrics import average_precision_score, roc_auc_score
    from sklearn.mixture import GaussianMixture

    yv = (val["label_anomaly"] == "anomaly").to_numpy()
    yt = (test["label_anomaly"] == "anomaly").to_numpy()
    tf = model.transform_
    Z = tf.transform(train)
    mu, var = Z.mean(axis=0), Z.var(axis=0)
    gm = GaussianMixture(8, covariance_type="full", reg_covar=1e-4, random_state=42).fit(Z)
    variants = {
        "gaussian_day_du": lambda df: model.score(df),
        "gaussian_duong_cheo": lambda df: (((tf.transform(df) - mu) ** 2) / var).sum(axis=1),
        "hon_hop_8_gaussian": lambda df: -gm.score_samples(tf.transform(df)),
    }
    out = {}
    for name, f in variants.items():
        sv, st = f(val), f(test)
        t = choose_threshold(sv, yv, "f1_on_dinh")
        out[name] = {"f1_validation": binary_metrics(yv, sv > t)["f1"],
                     "test": binary_metrics(yt, st > t),
                     "auc_test": round(float(roc_auc_score(yt, st)), 4),
                     "ap_test": round(float(average_precision_score(yt, st)), 4)}
    return out


def plot_test_scores(model, test, rules, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    sc = model.score(test)
    groups = attack_groups(test, rules)
    names = ["normal"] + sorted(set(groups) - {"normal"})
    data = [np.log10(np.maximum(sc[groups == g], 1e-3)) for g in names]
    fig, ax = plt.subplots(figsize=(9, 4.8))
    ax.boxplot(data, vert=False, labels=[f"{g} ({len(d)})" for g, d in zip(names, data)],
               showfliers=False, whis=(5, 95))
    ax.axvline(np.log10(model.threshold), color="#C44E52", lw=1.2, label=f"ngưỡng d² = {model.threshold:.1f}")
    ax.set_xlabel("log10(d²)  (hộp: 25–75%, râu: 5–95%)")
    ax.set_title("Test: điểm bất thường theo đợt tấn công", fontsize=10)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)


def cmd_evaluate(args):
    import joblib

    from .config import load_config
    from .labeling import load_schedule

    cfg = gaussian_config(load_config(args.config))
    windows = load_windows(args.prefixes)
    rules = load_schedule()
    if args.model:
        model = joblib.load(args.model)
        print(f"Nạp mô hình: {args.model}")
    else:
        model = select_model(windows, cfg)[0]
    data = labeled(windows)
    test = data[data["split"] == "test"]
    report = evaluate(model, test, rules)
    if args.so_sanh:
        val = data[data["split"] == "validation"]
        train = normal_train(windows, cfg_fit_sessions(model))
        report["kiem_tra_gia_dinh"] = assumption_checks(model, train, val, test)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    plot_test_scores(model, test, rules, out / "gauss_test_theo_dot.png")
    (out / "gauss_test.json").write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                         encoding="utf-8")
    t = report["tong"]
    print(f"Test: P {t['precision']}, R {t['recall']}, F1 {t['f1']}, FPR {t['fpr']}, "
          f"AUC {report['auc']}, AP {report['ap']}")
    for g, v in report.get("recall_theo_dot", {}).items():
        print(f"  {g}: {v['so_mau']} cửa sổ, recall {v['recall']}")
    print(f"Đã ghi: {out / 'gauss_test.json'}")


def cfg_fit_sessions(model):
    """Phiên mà mô hình đã fit (để dựng lại đúng mẫu train khi so sánh)."""
    return model.info.get("phien_fit")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Gaussian phát hiện bất thường trên cửa sổ host.")
    sub = parser.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("phan-bo", help="kiểm tra phân bố và các phép biến đổi (C06-T02)")
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--fit-session", action="append", help="chỉ dùng train của phiên này")
    p.add_argument("--out", required=True, help="thư mục ghi hình và JSON")
    p.set_defaults(func=cmd_distribution)
    p = sub.add_parser("nguong", help="chọn phiên fit và ngưỡng trên validation (C06-T04)")
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--out", required=True, help="thư mục ghi hình và JSON")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_threshold)
    p = sub.add_parser("danh-gia", help="đánh giá trên test với ngưỡng chọn trên validation (C06-T05)")
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--out", required=True, help="thư mục ghi hình và JSON")
    p.add_argument("--model", help="file joblib đã lưu; không có thì fit lại theo cấu hình")
    p.add_argument("--so-sanh", action="store_true", help="so với Gaussian đường chéo và hỗn hợp 8 Gaussian")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_evaluate)
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    # Chạy bản của module đã import để đối tượng lưu bằng joblib nạp lại được (docs/32 mục 4).
    from nids.gaussian import main as module_main
    sys.exit(module_main())

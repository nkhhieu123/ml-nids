"""So sánh nhiều thuật toán phân loại trên cùng dữ liệu cửa sổ host (Benign, PortScan, DoS).

Mọi mô hình dùng chung: cùng tập train/validation/test (chia theo thời gian), cùng 20 đặc trưng, cùng bộ
tiền xử lý (điền trung vị, logarit, chuẩn hóa; fit trên train). Mỗi mô hình là một ``sklearn.pipeline.Pipeline``
gồm bước tiền xử lý và bước phân loại.

Logistic Regression và Random Forest dùng tham số đã chọn trên validation ở Chặng 7
(docs/hinh/phan_loai_chon.json). Các mô hình còn lại dùng tham số ghi trong ``MODELS`` bên dưới, **không dò
tham số**, nên bảng này cho biết thứ hạng tương đối chứ không phải giới hạn tốt nhất của từng thuật toán.

    python -m nids.so_sanh_mo_hinh ../output/features/cic17_wednesday ../output/features/cic17_friday \
        --chon ../docs/hinh/phan_loai_chon.json --out ../docs/hinh
"""

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline

from .classifier import LABEL_COL, TABLE, classifier_config, load_data, multiclass_metrics, prepare_data
from .dataset import feature_columns
from .preprocessing import Preprocessor, log_columns


class TienXuLy(BaseEstimator, TransformerMixin):
    """Bọc ``Preprocessor`` của đề tài thành một bước của Pipeline; ``fit_frame`` là train trước khi giảm mẫu."""

    def __init__(self, fit_frame=None):
        self.fit_frame = fit_frame

    def fit(self, X, y=None):
        feats = feature_columns(TABLE)
        self.pre_ = Preprocessor(TABLE, feats, log_columns(TABLE, feats)).fit(X if self.fit_frame is None else self.fit_frame)
        return self

    def transform(self, X):
        return self.pre_.transform(X)


def _models(choice, seed) -> dict:
    from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.naive_bayes import GaussianNB
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.svm import LinearSVC
    from sklearn.tree import DecisionTreeClassifier

    lr = choice["mo_hinh"]["logistic_regression"]["tot_nhat"]["tham_so"]
    rf = choice["mo_hinh"]["random_forest"]["tot_nhat"]["tham_so"]
    return {
        "Random Forest": RandomForestClassifier(random_state=seed, n_jobs=4, **rf),
        "Extra Trees": ExtraTreesClassifier(n_estimators=300, max_depth=20, random_state=seed, n_jobs=4),
        "Gradient Boosting (Hist)": HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, random_state=seed),
        "Decision Tree": DecisionTreeClassifier(max_depth=20, random_state=seed),
        "MLP (mạng nơ-ron)": MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=200, random_state=seed),
        "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=5, n_jobs=4),
        "Logistic Regression": LogisticRegression(random_state=seed, max_iter=3000, **lr),
        "Linear SVM": LinearSVC(C=1.0, random_state=seed),
        "Gaussian Naive Bayes": GaussianNB(),
    }


def compare(df, choice, cfg, log=print) -> dict:
    seed = cfg["random_seed"]
    ratio = choice["mo_hinh"]["random_forest"]["tot_nhat"]["ty_le_can_bang"]
    data = prepare_data(df, ratio, seed, cfg["drop_train_duplicates"])
    y = {s: data[s][LABEL_COL].to_numpy().astype(str) for s in ("train", "validation", "test")}
    out = {"du_lieu": data["info"], "so_dac_trung": len(feature_columns(TABLE)), "mo_hinh": {}}
    for name, est in _models(choice, seed).items():
        pipe = Pipeline([("tien_xu_ly", TienXuLy(data["train_full"])), ("phan_loai", est)])
        t0 = time.perf_counter()
        pipe.fit(data["train"], y["train"])
        t_fit = time.perf_counter() - t0
        res = {}
        for s in ("validation", "test"):
            t0 = time.perf_counter()
            pred = pipe.predict(data[s])
            dt = time.perf_counter() - t0
            m = multiclass_metrics(y[s], pred)
            benign = y[s] == "benign"
            res[s] = {**m, "ty_le_benign_bi_bao": round(float((pred[benign] != "benign").mean()), 5),
                      "giay_du_doan": round(dt, 2)}
        params = {k: v for k, v in est.get_params().items() if k in
                  ("n_estimators", "max_depth", "max_iter", "learning_rate", "hidden_layer_sizes", "n_neighbors", "C",
                   "class_weight", "max_features", "min_samples_leaf")}
        out["mo_hinh"][name] = {"tham_so": params, "giay_hoc": round(t_fit, 1), **res}
        log(f"{name:26s} val {res['validation']['macro_f1']:.4f}  test {res['test']['macro_f1']:.4f}  "
            f"học {t_fit:.1f}s  dự đoán test {res['test']['giay_du_doan']:.2f}s")
    out["xep_hang_theo_validation"] = sorted(out["mo_hinh"], key=lambda k: -out["mo_hinh"][k]["validation"]["macro_f1"])
    return out


def plot(res, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    names = res["xep_hang_theo_validation"][::-1]
    val = [res["mo_hinh"][n]["validation"]["macro_f1"] for n in names]
    test = [res["mo_hinh"][n]["test"]["macro_f1"] for n in names]
    yy = np.arange(len(names))
    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    b1 = ax.barh(yy + 0.2, val, 0.38, label="validation", color="#4c78a8")
    b2 = ax.barh(yy - 0.2, test, 0.38, label="test", color="#f58518")
    ax.bar_label(b1, fmt="%.3f", fontsize=8, padding=2)
    ax.bar_label(b2, fmt="%.3f", fontsize=8, padding=2)
    ax.set_yticks(yy, names)
    ax.set_xlim(0, 1.08)
    ax.set_xlabel("macro-F1")
    ax.set_title("So sánh các thuật toán phân loại trên CIC-IDS2017 (cùng dữ liệu, cùng tiền xử lý)", fontsize=10)
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)


def main(argv=None):
    from .config import load_config

    p = argparse.ArgumentParser(description="So sánh nhiều thuật toán phân loại trên cùng dữ liệu.")
    p.add_argument("prefixes", nargs="+")
    p.add_argument("--chon", required=True, help="JSON của lệnh nids.classifier chon")
    p.add_argument("--out", required=True, help="thư mục ghi JSON và hình")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    args = p.parse_args(argv)
    cfg = classifier_config(load_config(args.config))
    choice = json.loads(Path(args.chon).read_text(encoding="utf-8"))
    res = compare(load_data(args.prefixes, cfg["sessions"]), choice, cfg)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "so_sanh_mo_hinh.json").write_text(json.dumps(res, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    plot(res, out / "so_sanh_mo_hinh.png")
    print("Xếp hạng theo validation:", res["xep_hang_theo_validation"])
    print(f"Đã ghi: {out / 'so_sanh_mo_hinh.json'}, {out / 'so_sanh_mo_hinh.png'}")


if __name__ == "__main__":
    sys.exit(main())

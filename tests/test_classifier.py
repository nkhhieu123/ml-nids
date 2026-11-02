import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.classifier import (class_report, fit_and_score, host_roles, load_data, lr_coefficients,
                             make_estimator, multiclass_metrics, prepare_data)
from nids.dataset import feature_columns
from nids.labeling import Rule
from session_fixture import make_session


def rule(id_, label, original, attackers, victims, start=0, end=10 ** 6):
    return Rule(id_, start, end, 0, 10 ** 6, frozenset(attackers), frozenset(victims), label, original, "")


RULES = [rule("scan", "port_scan", "PortScan", ["10.0.0.0"], ["10.0.0.1"]),
         rule("dos", "dos", "DoS Hulk", ["10.0.0.0"], ["10.0.0.1"]),
         rule("ddos", "loai", "DDoS", ["10.0.0.2"], ["10.0.0.3"], 1300, 1600)]


def separable(df):
    """Trong phiên giả lập, port_scan và dos cùng dịch cột đầu; dịch thêm cột thứ hai cho dos."""
    df = df.copy()
    df.loc[df["label_attack"] == "dos", feature_columns("windows")[1]] += 1000
    return df


class SessionCase(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.prefixes = [make_session(self.dir, "s1", 300, 1), make_session(self.dir, "s2", 300, 2, "dos")]


class LabelReportTest(SessionCase):
    """C07-T01: số mẫu từng lớp theo tập, theo đợt; mẫu bị loại."""

    def test_counts_match_labels(self):
        df = load_data(self.prefixes)
        rep = class_report(df, RULES)
        for s in ("train", "validation", "test"):
            part = df[df["split"] == s]
            for c in ("benign", "port_scan", "dos"):
                self.assertEqual(rep["theo_tap"][s][c], int((part["label_attack"] == c).sum()))
        self.assertEqual(rep["tong"]["train"], int((df["split"] == "train").sum()))
        self.assertNotIn("bo", rep["theo_tap"])                     # mẫu vùng đệm không tính

    def test_excluded_and_ambiguous(self):
        df = load_data(self.prefixes)
        excl = (df["host"] == "10.0.0.2") & df["window_start"].between(1300, 1600)
        df.loc[excl, ["label_attack", "label_status"]] = [np.nan, "loai"]
        df.loc[df.index[:5], "label_status"] = "mo_ho"
        rep = class_report(df, RULES)
        n_ex = sum(rep["bi_loai"]["DDoS"]["so_mau"].values())
        self.assertEqual(n_ex, int((excl & df["split"].isin(["train", "validation", "test"])).sum()))
        self.assertIn("NAT", rep["bi_loai"]["DDoS"]["ly_do"])
        self.assertEqual(sum(rep["mo_ho"].values()), int(df.loc[df.index[:5], "split"].isin(
            ["train", "validation", "test"]).sum()))
        # mẫu loại và mơ hồ không nằm trong ba lớp
        self.assertEqual(sum(rep["tong"].values()), int(
            (~df["label_status"].isin(["loai", "mo_ho"]) & df["split"].isin(["train", "validation", "test"])).sum()))

    def test_small_class_warning(self):
        df = load_data(self.prefixes)
        rep = class_report(df, RULES)
        self.assertTrue(any("port_scan" in w for w in rep["canh_bao"]))   # lớp ít mẫu bị cảnh báo

    def test_sessions_and_roles(self):
        df = load_data(self.prefixes, ["s2"])
        self.assertEqual(set(df["session"]), {"s2"})
        roles = host_roles(pd.DataFrame({"host": ["10.0.0.0", "10.0.0.1", "10.0.0.5"]}), RULES)
        self.assertEqual(list(roles), ["ben_tan_cong", "nan_nhan", "khac"])


class PrepareTest(SessionCase):
    """C07-T02: bỏ trùng và giảm mẫu chỉ trên train; validation, test giữ nguyên."""

    def test_only_train_changes(self):
        df = load_data(self.prefixes)
        data = prepare_data(df, max_ratio=1, seed=0)
        y = data["train"]["label_attack"].value_counts()
        self.assertEqual(y.min(), y.max())                               # tỷ lệ 1: các lớp bằng nhau
        for s in ("validation", "test"):
            self.assertEqual(len(data[s]), int((df["split"] == s).sum()))
        self.assertGreaterEqual(len(data["train_full"]), len(data["train"]))
        none = prepare_data(df, max_ratio=None)
        self.assertEqual(len(none["train"]), len(none["train_full"]))

    def test_dedup_train(self):
        df = load_data(self.prefixes)
        dup = df[df["split"] == "train"].head(10)
        data = prepare_data(pd.concat([df, dup], ignore_index=True), max_ratio=None)
        self.assertEqual(len(data["train"]), int((df["split"] == "train").sum()))


class ModelTest(SessionCase):
    """C07-T02, T03: mô hình học được lớp tách biệt; chỉ số đúng định nghĩa."""

    def test_metrics(self):
        m = multiclass_metrics(["benign", "dos", "dos", "port_scan"], ["benign", "dos", "benign", "dos"])
        self.assertEqual(m["confusion"]["ma_tran"], [[1, 0, 0], [0, 0, 1], [1, 0, 1]])
        self.assertEqual(m["theo_lop"]["dos"]["recall"], 0.5)
        self.assertEqual(m["theo_lop"]["port_scan"]["f1"], 0.0)
        self.assertAlmostEqual(m["macro_f1"], round((2 / 3 + 0 + 0.5) / 3, 4))

    def test_fit_logistic_regression(self):
        data = prepare_data(separable(load_data(self.prefixes)), max_ratio=None)
        model, res = fit_and_score("logistic_regression", {"C": 1.0}, data)
        self.assertGreater(res["validation"]["macro_f1"], 0.9)
        self.assertEqual(set(model.classes), {"benign", "port_scan", "dos"})
        coef = lr_coefficients(model, top=2)
        self.assertEqual(len(coef["dos"]), 2)
        # bộ tiền xử lý fit trên train sau bỏ trùng, không phải validation
        self.assertEqual(model.preprocessor.info["so_mau_fit"], len(data["train_full"]))

    def test_fit_random_forest(self):
        data = prepare_data(separable(load_data(self.prefixes)), max_ratio=10)
        model, res = fit_and_score("random_forest", {"n_estimators": 20}, data)
        self.assertGreater(res["validation"]["macro_f1"], 0.9)
        self.assertEqual(len(model.estimator.feature_importances_), len(model.preprocessor.output_names))
        # cùng seed thì cùng kết quả
        again, _ = fit_and_score("random_forest", {"n_estimators": 20}, data)
        np.testing.assert_array_equal(model.predict_proba(data["validation"]),
                                      again.predict_proba(data["validation"]))

    def test_unknown_model(self):
        with self.assertRaises(ValueError):
            make_estimator("svm", {})


if __name__ == "__main__":
    unittest.main()

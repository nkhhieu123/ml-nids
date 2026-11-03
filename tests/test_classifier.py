import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import joblib
import numpy as np
import pandas as pd
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.classifier import (class_report, fit_and_score, host_roles, load_data, lr_coefficients,
                             make_estimator, multiclass_metrics, paired_bootstrap, prepare_data,
                             search, select_models, bootstrap_ci, duplicate_mask, evaluate, refit_chosen,
                             compare_profiles, error_table, load_model, permutation_importance, predict_frame,
                             save_model, unseen_attacks, flow_kind, scan_window_traffic)
from nids.config import DEFAULT_CONFIG
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


class SelectTest(SessionCase):
    """C07-T04: chọn trên validation, hai bước; so sánh bằng bootstrap."""

    CFG = {"random_seed": 0, "drop_train_duplicates": True, "balance_max_ratio": 10,
           "logistic_regression": {"C": 1.0}, "random_forest": {"n_estimators": 10},
           "search": {"balance_max_ratio": [1, None],
                      "logistic_regression": {"class_weight": ["balanced", None], "C": [0.1, 1.0]},
                      "random_forest": {"class_weight": [None], "max_depth": [None, 2]}}}

    def test_two_steps(self):
        df = separable(load_data(self.prefixes))
        res = search("logistic_regression", df, self.CFG, log=lambda *_: None)
        step1 = [r for r in res["cac_lan_thu"] if r["buoc"] == 1]
        step2 = [r for r in res["cac_lan_thu"] if r["buoc"] == 2]
        self.assertEqual(len(step1), 4)                       # 2 tỷ lệ × 2 trọng số
        best1 = max(step1, key=lambda r: r["macro_f1_validation"])
        self.assertTrue(all(r["ty_le_can_bang"] == best1["ty_le_can_bang"] for r in step2))
        self.assertEqual({r["tham_so"]["C"] for r in step2} | {1.0}, {0.1, 1.0})   # không thử lại C = 1
        self.assertEqual(res["tot_nhat"]["macro_f1_validation"],
                         max(r["macro_f1_validation"] for r in res["cac_lan_thu"]))

    def test_select_and_bootstrap(self):
        df = separable(load_data(self.prefixes))
        res = select_models(df, self.CFG, log=lambda *_: None)
        self.assertIn(res["chon"], ("logistic_regression", "random_forest"))
        self.assertEqual(set(res["mo_hinh"]), {"logistic_regression", "random_forest"})
        b = res["bootstrap"]
        self.assertLessEqual(b["khoang_95"][0], b["khoang_95"][1])

    def test_bootstrap_detects_difference(self):
        y = np.array(["benign"] * 80 + ["dos"] * 10 + ["port_scan"] * 10)
        good = y.copy()
        bad = y.copy()
        bad[80:] = "benign"
        b = paired_bootstrap(y, bad, good, n=200)
        self.assertEqual(b["ty_le_b_hon_a"], 1.0)
        self.assertGreater(b["khoang_95"][0], 0)
        same = paired_bootstrap(y, good, good, n=50)
        self.assertEqual(same["hieu_trung_binh"], 0.0)


class EvaluateTest(SessionCase):
    """C07-T05: chỉ số trên test, theo phiên, theo đợt, mẫu trùng train."""

    def test_evaluate(self):
        df = separable(load_data(self.prefixes))
        cfg = dict(SelectTest.CFG)
        choice = select_models(df, cfg, log=lambda *_: None)
        model, data = refit_chosen(df, choice, cfg, "random_forest")
        r = evaluate(model, data["test"], RULES, data["train_full"])
        self.assertEqual(r["so_mau"], int((df["split"] == "test").sum()))
        self.assertEqual(set(r["theo_phien"]), {"s1", "s2"})
        self.assertEqual(sum(v["so_mau"] for v in r["theo_phien"].values()), r["so_mau"])
        self.assertIn("PortScan", r["theo_dot"])
        lo, hi = r["khoang_95_macro_f1"]
        self.assertLessEqual(lo, hi)
        self.assertIn("bo_mau_trung", r["trung_train"])
        # cấu hình fit lại đúng là cấu hình đã chọn trên validation
        self.assertEqual(model.params, choice["mo_hinh"]["random_forest"]["tot_nhat"]["tham_so"])

    def test_duplicate_mask(self):
        a = pd.DataFrame({"x": [1.0, 2.0, np.nan], "y": [0.0, 0.0, 5.0]})
        b = pd.DataFrame({"x": [2.0, np.nan], "y": [0.0, 5.0]})
        self.assertEqual(list(duplicate_mask(a, b, ["x", "y"])), [False, True, True])

    def test_bootstrap_ci(self):
        y = np.array(["benign"] * 50 + ["dos"] * 25 + ["port_scan"] * 25)
        self.assertEqual(bootstrap_ci(y, y, n=50), [1.0, 1.0])


class ArtifactTest(SessionCase):
    """C07-T06: phân tích nhầm lẫn; lưu, nạp lại, dự đoán; dòng lệnh."""

    def fitted(self):
        df = separable(load_data(self.prefixes))
        data = prepare_data(df, max_ratio=None)
        model, _ = fit_and_score("random_forest", {"n_estimators": 15}, data)
        return df, data, model

    def test_analysis(self):
        df, data, model = self.fitted()
        errs = error_table(model, data["test"], RULES)
        self.assertTrue(all(e["nhan"] != e["du_doan"] for e in errs))
        prof = compare_profiles(model, data["test"], "dos")
        self.assertEqual(prof["dung"]["so_mau"] + prof["sai"]["so_mau"], int((data["test"]["label_attack"] == "dos").sum()))
        imp = permutation_importance(model, data["validation"], n_repeats=1)
        first = feature_columns("windows")[0]
        self.assertEqual(set(imp), set(model.features))
        self.assertGreater(imp[first], 0)                     # cột tách lớp tấn công là quan trọng nhất
        self.assertEqual(next(iter(imp)), first)

    def test_scan_window_traffic(self):
        flows = pd.DataFrame({
            "first_index": range(5), "first_ts": [100.0, 101, 102, 103, 500], "last_ts": [100.5, 101, 102, 103, 500],
            "protocol": ["17", "17", "132", "6", "6"], "fwd_ip": ["a"] * 5, "bwd_ip": ["b"] * 5,
            "bwd_port": [53, 161, 80, 22, 80], "continuation": [0, 0, 0, 0, 0], "packets": [1] * 5,
            "syn_count": [0, 0, 0, 1, 1], "fin_count": [0] * 5, "rst_count": [0] * 5, "ack_count": [0] * 5,
            "psh_count": [0] * 5, "urg_count": [0] * 5, "session": ["s"] * 5})
        self.assertEqual(list(flow_kind(flows)), ["udp", "udp", "sctp", "tcp_co_syn", "tcp_co_syn"])
        windows = pd.DataFrame({"host": ["a", "a"], "window_start": [98.0, 498.0], "window_end": [108.0, 508.0],
                                "session": ["s", "s"], "label_attack": ["port_scan"] * 2,
                                "tcp_attempts_out": [1.0, 500.0], "tcp_attempts_in": [0.0, 0.0]})
        r = scan_window_traffic(windows, flows, pred=["benign", "port_scan"])
        self.assertEqual(r["so_cua_so_it_hoat_dong"], 1)          # cửa sổ thứ hai có 500 lần thử TCP
        self.assertEqual(r["kieu_flow"], {"sctp": 1, "tcp_co_syn": 1, "udp": 2})
        self.assertEqual(r["kieu_chu_dao_cua_cua_so"], {"udp": 1})
        self.assertEqual(r["recall_cua_so_nhieu_hoat_dong"], 1.0)
        self.assertEqual(r["recall_theo_kieu_chu_dao"]["udp"], {"so_cua_so": 1, "recall": 0.0})

    def test_unseen_attacks(self):
        df, _, model = self.fitted()
        excl = (df["host"] == "10.0.0.2") & df["window_start"].between(1300, 1600) & (df["split"] == "test")
        df.loc[excl, ["label_attack", "label_status"]] = [np.nan, "loai"]
        res = unseen_attacks(model, df, RULES)
        self.assertEqual(res["DDoS"]["so_mau"], int(excl.sum()))
        self.assertEqual(sum(res["DDoS"]["du_doan"].values()), int(excl.sum()))

    def test_save_load_predict(self):
        _, data, model = self.fitted()
        path = save_model(model, self.dir / "m" / "rf.joblib", {"x": 1})
        meta = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertEqual(meta["lop"], model.classes)
        self.assertEqual(meta["dac_trung"], model.features)
        loaded = load_model(path)
        np.testing.assert_array_equal(loaded.predict_proba(data["test"]), model.predict_proba(data["test"]))
        pred = predict_frame(loaded, data["test"])
        self.assertEqual(len(pred), len(data["test"]))
        self.assertTrue(np.allclose(pred[["p_benign", "p_dos", "p_port_scan"]].sum(1), 1, atol=1e-3))
        with self.assertRaises(ValueError):
            predict_frame(loaded, data["test"].drop(columns=[model.features[0]]))
        joblib.dump({"khong": "phai"}, self.dir / "x.joblib")
        with self.assertRaises(TypeError):
            load_model(self.dir / "x.joblib")

    def test_cli(self):
        df = separable(load_data(self.prefixes))
        for prefix in self.prefixes:                          # ghi lại bảng đã làm tách biệt dos
            part = df[df["session"] == Path(prefix).name]
            orig = pd.read_csv(f"{prefix}.windows.csv")
            orig[feature_columns("windows")] = part[feature_columns("windows")].to_numpy()
            orig.to_csv(f"{prefix}.windows.csv", index=False)
        cfg = self.dir / "cfg.yaml"
        full = yaml.safe_load(DEFAULT_CONFIG.read_text(encoding="utf-8"))
        full["preprocess"]["sessions"]["attack_classification"] = ["s1", "s2"]
        full["classifier"]["search"] = SelectTest.CFG["search"]
        full["classifier"]["random_forest"] = {"n_estimators": 10}
        cfg.write_text(yaml.safe_dump(full, allow_unicode=True), encoding="utf-8")
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        src = str(Path(__file__).resolve().parents[1] / "src")
        run = lambda *a: subprocess.run([sys.executable, "-m", "nids.classifier", *a], cwd=src, env=env,
                                        capture_output=True, text=True, encoding="utf-8")
        out = self.dir / "out"
        r = run("chon", *self.prefixes, "--out", str(out), "--config", str(cfg))
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run("danh-gia", *self.prefixes, "--chon", str(out / "phan_loai_chon.json"), "--out", str(out),
                "--config", str(cfg))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((out / "phan_loai_confusion.png").exists())
        r = run("huan-luyen", *self.prefixes, "--chon", str(out / "phan_loai_chon.json"), "--out", str(out),
                "--config", str(cfg))
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run("phan-tich", *self.prefixes, "--model", str(out / "phan_loai_rf_windows.joblib"), "--out", str(out),
                "--config", str(cfg))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("random_forest", json.loads((out / "phan_loai_phan_tich.json").read_text(encoding="utf-8")))
        model = load_model(out / "phan_loai_rf_windows.joblib")      # nạp ở tiến trình khác
        self.assertEqual(type(model).__module__, "nids.classifier")
        r = run("du-doan", self.prefixes[0], "--khong-nhan", "--model", str(out / "phan_loai_rf_windows.joblib"),
                "--out", str(out / "du_doan.csv"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(pd.read_csv(out / "du_doan.csv")), 300)


if __name__ == "__main__":
    unittest.main()

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.gaussian import (GaussianDetector, GaussianTransform, alert_episodes, assumption_checks,
                           attack_groups, binary_metrics, choose_threshold, compare_transforms,
                           evaluate, fill_empty, fit_covariance, load_model, normal_train,
                           save_model, select_features)
from nids.labeling import Rule


class FeatureSelectionTest(unittest.TestCase):
    """C06-T01: chọn đặc trưng theo quy tắc trên train."""

    def frame(self, n=200, seed=0):
        rng = np.random.default_rng(seed)
        a = rng.poisson(5, n).astype(float)
        df = pd.DataFrame({
            "a": a,
            "a_copy": a * 2 + 1,                              # cùng thứ hạng với a
            "mostly_empty": np.where(np.arange(n) < n * 0.8, np.nan, 1.0),
            "const": np.zeros(n),
            "no_reply_out": rng.poisson(1, n).astype(float),
            "rejected_out": rng.poisson(1, n).astype(float),
            "half_open_out": rng.poisson(1, n).astype(float),
            "dst_port_entropy": np.where(np.arange(n) % 3 == 0, np.nan, rng.random(n)),
        })
        df["incomplete_out"] = df["no_reply_out"] + df["rejected_out"] + df["half_open_out"]
        return df

    def test_rules(self):
        df = self.frame()
        kept, dropped = select_features(df, list(df.columns))
        self.assertEqual(kept, ["a", "no_reply_out", "rejected_out", "half_open_out", "dst_port_entropy"])
        self.assertIn("trống", dropped["mostly_empty"])
        self.assertIn("hằng số", dropped["const"])
        self.assertIn("tương quan", dropped["a_copy"])
        self.assertIn("bằng tổng", dropped["incomplete_out"])

    def test_derived_kept_if_parts_missing(self):
        df = self.frame()[["a", "incomplete_out", "no_reply_out"]]
        kept, _ = select_features(df, list(df.columns))
        self.assertIn("incomplete_out", kept)

    def test_empty_means_zero(self):
        df = fill_empty(pd.DataFrame({"dst_port_entropy": [np.nan, 1.5], "x": [np.nan, 2.0]}))
        self.assertEqual(df["dst_port_entropy"].tolist(), [0.0, 1.5])
        self.assertTrue(np.isnan(df["x"][0]))                 # cột khác không bị điền

    def test_normal_train(self):
        df = pd.DataFrame({
            "session": ["mon", "mon", "mon", "wed", "mon"],
            "split": ["train", "train", "test", "train", "train"],
            "label_anomaly": ["normal", "anomaly", "normal", "normal", None],
            "label_status": ["khong_khop", "khop", "khong_khop", "khong_khop", "mo_ho"],
            "label_attack": ["benign", "dos", "benign", "benign", None],
        })
        self.assertEqual(normal_train(df).index.tolist(), [0, 3])
        self.assertEqual(normal_train(df, ["mon"]).index.tolist(), [0])


class TransformTest(unittest.TestCase):
    """C06-T02: biến đổi, tham số chỉ học từ train."""

    def frame(self, n=2000, seed=1):
        rng = np.random.default_rng(seed)
        return pd.DataFrame({
            "skewed": rng.lognormal(2, 1.2, n),
            "zero_heavy": np.where(rng.random(n) < 0.97, 0.0, rng.poisson(3, n) + 1.0),
            "dst_port_entropy": np.where(rng.random(n) < 0.2, np.nan, rng.random(n) * 3),
        })

    def test_split_columns_and_reduce_skew(self):
        df = self.frame()
        t = GaussianTransform(list(df.columns)).fit(df)
        self.assertEqual(t.log_features, ["zero_heavy"])
        self.assertEqual(t.yj_features, ["skewed", "dst_port_entropy"])
        Z = t.transform(df)
        self.assertFalse(np.isnan(Z).any())
        np.testing.assert_allclose(Z.mean(axis=0), 0, atol=1e-9)
        from scipy import stats
        self.assertLess(abs(stats.skew(Z[:, 0])), abs(stats.skew(df["skewed"])) / 5)

    def test_parameters_from_train_only(self):
        df = self.frame()
        a = GaussianTransform(list(df.columns)).fit(df)
        other = df * 100                                     # dữ liệu khác hẳn, chỉ transform
        a.transform(other)
        b = GaussianTransform(list(df.columns)).fit(df)
        self.assertEqual(a.lambdas, b.lambdas)
        np.testing.assert_allclose(a.scaler.mean_, b.scaler.mean_)

    def test_compare_transforms_report(self):
        df = self.frame()
        r = compare_transforms(df, list(df.columns))
        self.assertLess(r["yeo_johnson_va_log"]["skew_tri_tuyet_doi_trung_vi"],
                        r["giu_nguyen"]["skew_tri_tuyet_doi_trung_vi"])
        self.assertEqual(set(r["yeo_johnson_va_log"]["d2_phan_vi"]), {"0.5", "0.9", "0.99", "0.999"})


class DetectorTest(unittest.TestCase):
    """C06-T03: huấn luyện Gaussian, xử lý hiệp phương sai suy biến."""

    def normal(self, n=3000, seed=2):
        rng = np.random.default_rng(seed)
        a = rng.normal(0, 1, n)
        return pd.DataFrame({"x": np.exp(a + 3), "y": np.exp(0.6 * a + rng.normal(0, 0.8, n) + 2),
                             "z": rng.lognormal(1, 0.5, n)})

    def test_singular_covariance_is_invertible(self):
        rng = np.random.default_rng(3)
        Z = rng.normal(size=(500, 3))
        Z = np.column_stack([Z, Z[:, 0] + Z[:, 1]])          # cột 4 là tổng: suy biến
        self.assertLess(np.linalg.eigvalsh(np.cov(Z, rowvar=False)).min(), 1e-10)
        for method in ("empirical", "ledoit_wolf"):
            cov, info = fit_covariance(Z, method)
            self.assertTrue(np.isfinite(np.linalg.inv(cov)).all())
            self.assertLessEqual(info["chi_so_dieu_kien"], 1e6 * 1.0001)
        self.assertEqual(fit_covariance(Z, "empirical")[1]["so_tri_rieng_nang"], 1)
        self.assertGreater(fit_covariance(Z, "ledoit_wolf")[1]["he_so_co"], 0)

    def test_scores_outlier_higher(self):
        train = self.normal()
        m = GaussianDetector(["x", "y", "z"], "ledoit_wolf").fit(train)
        test = pd.DataFrame({"x": [np.exp(3), np.exp(3)], "y": [np.exp(2), np.exp(9)], "z": [np.e, np.e]})
        s = m.score(test)
        self.assertLess(s[0], 3)                               # gần trung tâm
        self.assertGreater(s[1], 25)                           # lệch xa quan hệ x-y
        # log mật độ xếp hạng ngược với d²
        self.assertGreater(m.log_density(test)[0], m.log_density(test)[1])
        # d² trung bình trên train xấp xỉ số chiều
        self.assertAlmostEqual(m.score(train).mean(), 3, delta=0.3)

    def test_predict_needs_threshold(self):
        m = GaussianDetector(["x", "y", "z"]).fit(self.normal())
        with self.assertRaises(ValueError):
            m.predict(self.normal(10))
        m.threshold = 10.0
        self.assertEqual(set(m.predict(self.normal(50))) <= {"normal", "anomaly"}, True)



class ThresholdTest(unittest.TestCase):
    """C06-T04: điểm, chỉ số và chọn ngưỡng trên validation."""

    def test_binary_metrics(self):
        y = np.array([1, 1, 1, 0, 0, 0, 0, 0], bool)
        p = np.array([1, 1, 0, 1, 0, 0, 0, 0], bool)
        m = binary_metrics(y, p)
        self.assertEqual((m["tp"], m["fp"], m["fn"], m["tn"]), (2, 1, 1, 4))
        self.assertAlmostEqual(m["precision"], 2 / 3, places=4)
        self.assertAlmostEqual(m["recall"], 2 / 3, places=4)
        self.assertAlmostEqual(m["fpr"], 0.2, places=4)

    def test_f1_threshold_separates(self):
        s = np.array([1, 2, 3, 4, 10, 11, 12], float)
        y = np.array([0, 0, 0, 0, 1, 1, 1], bool)
        t = choose_threshold(s, y, "f1")
        self.assertTrue(4 <= t < 10)
        self.assertEqual(binary_metrics(y, s > t)["f1"], 1.0)

    def test_fpr_threshold(self):
        rng = np.random.default_rng(0)
        s = np.r_[rng.normal(0, 1, 10000), rng.normal(5, 1, 100)]
        y = np.r_[np.zeros(10000, bool), np.ones(100, bool)]
        t = choose_threshold(s, y, "fpr", target_fpr=0.01)
        self.assertLessEqual(binary_metrics(y, s > t)["fpr"], 0.01)
        self.assertGreater(binary_metrics(y, s > t)["fpr"], 0.008)

    def test_stable_threshold_avoids_cliff(self):
        # 1000 normal quanh 10; 300 anomaly tụ sát ngay trên 100 (vách) và 300 ở xa (1000)
        rng = np.random.default_rng(1)
        normal = rng.lognormal(np.log(10), 0.6, 1000)
        cliff = rng.uniform(100, 103, 300)
        far = rng.uniform(900, 1100, 300)
        s = np.r_[normal, cliff, far]
        y = np.r_[np.zeros(1000, bool), np.ones(600, bool)]
        t_max = choose_threshold(s, y, "f1")
        t_stable = choose_threshold(s, y, "f1_on_dinh", band=1.2)
        self.assertLess(t_stable, 90)                        # lùi xa vách (lưới ngưỡng rời rạc)
        self.assertGreater(binary_metrics(y, s > t_stable)["f1"], 0.9)
        self.assertLessEqual(t_stable, t_max)

    def test_attack_groups(self):
        rule = lambda id_, s, e, att, vic, orig: Rule(id_, s, e, 0, 86400, frozenset(att), frozenset(vic),
                                                     "loai", orig, "")
        rules = [rule("bot", 0, 86400, ["10.0.0.5"], ["9.9.9.9"], "Bot"),
                 rule("hb", 1000, 2000, ["9.9.9.9"], ["10.0.0.51"], "Heartbleed")]
        df = pd.DataFrame({
            "host": ["10.0.0.5", "9.9.9.9", "10.0.0.51", "10.0.0.51", "10.0.0.7"],
            "window_start": [500, 1500, 1500, 5000, 1500],
            "window_end": [510, 1510, 1510, 5010, 1510],
            "label_anomaly": ["anomaly", "anomaly", "anomaly", "anomaly", "normal"],
        })
        g = attack_groups(df, rules)
        # 9.9.9.9 dính cả bot (cả ngày) và Heartbleed: lấy đợt ngắn hơn
        self.assertEqual(list(g), ["Bot", "Heartbleed", "Heartbleed", "khác", "normal"])



class EvaluateTest(unittest.TestCase):
    """C06-T05: đánh giá trên test."""

    def windows(self, n_normal=400, n_attack=40, seed=5, session="s"):
        rng = np.random.default_rng(seed)
        n = n_normal + n_attack
        x = np.r_[rng.lognormal(2, 0.5, n_normal), rng.lognormal(6, 0.3, n_attack)]
        y = np.r_[rng.lognormal(1, 0.5, n_normal), rng.lognormal(1, 0.5, n_attack)]
        return pd.DataFrame({
            "x": x, "y": y, "session": session,
            "host": np.where(np.arange(n) % 2 == 0, "10.0.0.1", "10.0.0.2"),
            "window_start": np.arange(n) * 2.0, "window_end": np.arange(n) * 2.0 + 10,
            "label_anomaly": ["normal"] * n_normal + ["anomaly"] * n_attack,
        })

    def test_alert_episodes(self):
        df = pd.DataFrame({"host": ["a", "a", "a", "b", "a"], "window_start": [0, 2, 100, 2, 4],
                           "window_end": [10, 12, 110, 12, 14]})
        flagged = np.array([True, True, True, True, False])
        # host a: 0 và 2 liền nhau là một đợt, 100 là đợt khác; host b một đợt
        self.assertEqual(alert_episodes(df, flagged), 3)
        self.assertEqual(alert_episodes(df, np.zeros(5, bool)), 0)

    def test_evaluate(self):
        train = self.windows(n_attack=0, seed=1)
        test = pd.concat([self.windows(seed=2, session="a"), self.windows(n_attack=0, seed=3, session="b")])
        m = GaussianDetector(["x", "y"]).fit(train)
        m.threshold = 15.0
        r = evaluate(m, test)
        self.assertEqual(r["so_anomaly"], 40)
        self.assertGreater(r["tong"]["recall"], 0.95)
        self.assertLess(r["tong"]["fpr"], 0.05)
        self.assertEqual(set(r["theo_phien"]), {"a", "b"})
        self.assertEqual(r["theo_phien"]["b"]["so_anomaly"], 0)
        self.assertIn("neu_dung_nguong_chi2_0.99", r)

    def test_assumption_checks(self):
        train = self.windows(n_attack=0, seed=1)
        m = GaussianDetector(["x", "y"]).fit(train)
        r = assumption_checks(m, train, self.windows(seed=2), self.windows(seed=3))
        self.assertEqual(set(r), {"gaussian_day_du", "gaussian_duong_cheo", "hon_hop_8_gaussian"})
        for v in r.values():
            self.assertGreater(v["auc_test"], 0.9)



class SaveLoadTest(unittest.TestCase):
    """C06-T06: lưu, nạp lại và dự đoán; file do dòng lệnh lưu nạp được ở tiến trình khác."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def model(self):
        rng = np.random.default_rng(7)
        train = pd.DataFrame({"x": rng.lognormal(2, 0.5, 500), "y": rng.lognormal(1, 0.5, 500)})
        m = GaussianDetector(["x", "y"]).fit(train)
        m.threshold = 12.5
        return m, train

    def test_round_trip(self):
        m, train = self.model()
        path = save_model(m, self.dir / "g.joblib")
        info = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertEqual(info["nguong"], 12.5)
        self.assertEqual(info["dac_trung"], ["x", "y"])
        self.assertIn("lambda", info["bien_doi"])
        m2 = load_model(path)
        np.testing.assert_allclose(m2.score(train), m.score(train))
        self.assertEqual(list(m2.predict(train)), list(m.predict(train)))
        frame = m2.predict_frame(train.assign(host="h", window_start=0.0))
        self.assertEqual(list(frame.columns), ["host", "window_start", "d2", "du_doan"])

    def test_refuse_without_threshold_or_columns(self):
        m, train = self.model()
        with self.assertRaises(ValueError):
            m.predict_frame(train[["x"]])
        m.threshold = None
        with self.assertRaises(ValueError):
            save_model(m, self.dir / "g.joblib")

    def test_command_line_saved_model_loads_elsewhere(self):
        import yaml
        from session_fixture import make_session
        from nids.config import DEFAULT_CONFIG

        prefixes = [make_session(self.dir, "s1", 300, 1), make_session(self.dir, "s2", 300, 2)]
        cfg = yaml.safe_load(DEFAULT_CONFIG.read_text(encoding="utf-8"))
        cfg["gaussian"]["fit_session_candidates"] = [["s1"], None]
        cfg_path = self.dir / "cfg.yaml"
        cfg_path.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
        src = str(Path(__file__).resolve().parents[1] / "src")
        env = {**os.environ, "PYTHONPATH": src, "PYTHONIOENCODING": "utf-8"}
        out = self.dir / "g.joblib"
        subprocess.run([sys.executable, "-m", "nids.gaussian", "huan-luyen", *prefixes, "--out", str(out),
                        "--config", str(cfg_path)], check=True, env=env, capture_output=True)
        code = (f"from nids.gaussian import load_model; m = load_model(r'{out}'); "
                f"print(type(m).__module__, m.threshold is not None)")
        res = subprocess.run([sys.executable, "-c", code], check=True, env=env, capture_output=True, text=True)
        self.assertEqual(res.stdout.strip(), "nids.gaussian True")
        pred = self.dir / "p.csv"
        subprocess.run([sys.executable, "-m", "nids.gaussian", "du-doan", prefixes[0], "--model", str(out),
                        "--out", str(pred)], check=True, env=env, capture_output=True)
        self.assertEqual(len(pd.read_csv(pred)), 300)


if __name__ == "__main__":
    unittest.main()

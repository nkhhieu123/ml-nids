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

from nids.config import DEFAULT_CONFIG
from nids.dataset import feature_columns
from nids.preprocessing import balance, log_columns, prepare
from session_fixture import make_session


class PreprocessTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.prefixes = [make_session(self.dir, "s1", 300, 1), make_session(self.dir, "s2", 200, 2, "dos")]

    def test_fit_only_on_train(self):
        res = prepare(self.prefixes, "windows", "attack_classification")
        pre = res["preprocessor"]
        # Trung bình của bộ chuẩn hóa = trung bình cột (đã log, đã điền) của train
        Xtr = res["X_train"]
        self.assertTrue(np.allclose(Xtr.mean(axis=0)[: len(pre.features)], 0, atol=1e-9))
        self.assertEqual(pre.info["so_mau_fit"], sum(pre.info["lop_train_truoc_can_bang"].values()))
        self.assertFalse(np.allclose(res["X_test"].mean(axis=0)[: len(pre.features)], 0, atol=1e-9))

    def test_validation_does_not_change_fit(self):
        a = prepare(self.prefixes, "windows", "attack_classification")["preprocessor"]
        df = pd.read_csv(f"{self.prefixes[0]}.windows.csv")
        df.loc[df.index % 10 >= 6, "packets_in"] = 10**9           # chỉ sửa validation/test
        df.to_csv(f"{self.prefixes[0]}.windows.csv", index=False)
        b = prepare(self.prefixes, "windows", "attack_classification")["preprocessor"]
        sa, sb = a.pipeline.named_steps["chuan_hoa"], b.pipeline.named_steps["chuan_hoa"]
        self.assertTrue(np.allclose(sa.mean_, sb.mean_) and np.allclose(sa.scale_, sb.scale_))

    def test_missing_indicator_and_log(self):
        res = prepare(self.prefixes, "windows", "attack_classification")
        pre = res["preprocessor"]
        self.assertIn("dst_port_entropy__trong", pre.output_names)
        self.assertNotIn("dst_port_entropy", pre.log_features)
        self.assertIn("packets_in", pre.log_features)
        self.assertFalse(np.isnan(res["X_validation"]).any())

    def test_anomaly_fits_on_normal_train_only(self):
        res = prepare(self.prefixes, "windows", "anomaly")
        self.assertEqual(set(res["y_train"]), {"normal"})
        self.assertIn("anomaly", set(res["y_test"]))

    def test_balance_train_only(self):
        res = prepare(self.prefixes, "flows", "attack_classification", max_ratio=2)
        counts = res["preprocessor"].info["lop_train_sau_can_bang"]
        self.assertLessEqual(max(counts.values()), 2 * min(counts.values()))
        self.assertEqual(res["preprocessor"].info["lop_test"],
                         {k: int(v) for k, v in zip(*np.unique(res["y_test"], return_counts=True))})

    def test_sessions_and_fit_sessions(self):
        res = prepare(self.prefixes, "windows", "anomaly", sessions=["s1", "s2"], fit_sessions=["s1"])
        info = res["preprocessor"].info
        self.assertEqual((info["phien"], info["phien_fit"]), (["s1", "s2"], ["s1"]))
        only = prepare(self.prefixes, "windows", "attack_classification", sessions=["s2"])
        self.assertEqual(only["preprocessor"].info["phien"], ["s2"])
        self.assertEqual(set(only["y_train"]), {"benign", "dos"})

    def test_dedup_only_train(self):
        df = pd.read_csv(f"{self.prefixes[0]}.windows.csv")
        cols = feature_columns("windows")
        df.loc[df.index < 100, cols] = 1.0          # 100 mẫu đầu có đặc trưng giống hệt
        df.to_csv(f"{self.prefixes[0]}.windows.csv", index=False)
        plain = prepare(self.prefixes, "windows", "attack_classification")
        dedup = prepare(self.prefixes, "windows", "attack_classification", dedup_train=True)
        a, b = plain["preprocessor"].info, dedup["preprocessor"].info
        self.assertLess(b["so_mau_train_sau_bo_trung"], a["so_mau_train_sau_bo_trung"])
        self.assertEqual(a["lop_test"], b["lop_test"])              # test không đổi

    def test_saved_preprocessor_gives_same_result(self):
        res = prepare(self.prefixes, "windows", "attack_classification")
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.joblib"
            joblib.dump(res["preprocessor"], path)
            loaded = joblib.load(path)
        df = pd.read_csv(f"{self.prefixes[0]}.windows.csv")
        self.assertTrue(np.array_equal(loaded.transform(df), res["preprocessor"].transform(df)))

    def test_file_saved_by_command_line_loads_elsewhere(self):
        # Chạy đúng như người dùng: python -m, rồi nạp trong một tiến trình khác.
        src = str(Path(__file__).resolve().parents[1] / "src")
        env = {**os.environ, "PYTHONPATH": src, "PYTHONIOENCODING": "utf-8"}
        cfg = self.dir / "cfg.yaml"
        data = yaml.safe_load(DEFAULT_CONFIG.read_text(encoding="utf-8"))
        data["preprocess"]["sessions"]["attack_classification"] = ["s1", "s2"]
        cfg.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
        out = self.dir / "p.joblib"
        subprocess.run([sys.executable, "-m", "nids.preprocessing", *self.prefixes, "--table", "windows",
                        "--module", "attack_classification", "--out", str(out), "--config", str(cfg)],
                       check=True, env=env, capture_output=True)
        code = f"import joblib; p = joblib.load(r'{out}'); print(type(p).__module__)"
        res = subprocess.run([sys.executable, "-c", code], check=True, env=env, capture_output=True, text=True)
        self.assertEqual(res.stdout.strip(), "nids.preprocessing")

    def test_balance_function(self):
        X = np.arange(20).reshape(-1, 1)
        y = np.array(["a"] * 16 + ["b"] * 4)
        Xb, yb = balance(X, y, 2, seed=0)
        self.assertEqual((sum(yb == "a"), sum(yb == "b")), (8, 4))
        self.assertTrue(set(Xb[yb == "b"].ravel()) == {16, 17, 18, 19})

    def test_log_columns_follow_units(self):
        cols = log_columns("windows", feature_columns("windows"))
        self.assertIn("new_conn_in", cols)
        self.assertNotIn("incomplete_ratio_in", cols)


if __name__ == "__main__":
    unittest.main()

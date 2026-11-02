import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.gaussian import fill_empty, normal_train, select_features


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


if __name__ == "__main__":
    unittest.main()

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.dataset import feature_columns
from nids.pipeline import (ERROR, WARNING, Artifact, check_artifact, check_table, expected_inputs, load_artifacts,
                           pipeline_config)


def fake(module, features, threshold=1.0, meta=None, classes=None):
    model = SimpleNamespace(features=features, threshold=threshold, classes=classes or ["benign", "dos"])
    meta = {"dac_trung": features, "ma_nguon": {"commit": "abc", "co_sua_chua_commit": False}} if meta is None else meta
    return Artifact(module, Path("x.joblib"), model, meta)


class ArtifactTest(unittest.TestCase):
    """C09-T01: nạp artifact và kiểm tra schema."""

    def test_valid(self):
        feats = feature_columns("windows")[:5]
        self.assertEqual(check_artifact(fake("anomaly", feats)), [])

    def test_problems(self):
        bad = fake("anomaly", ["khong_co_cot"], threshold=None)
        levels = [lv for lv, _ in check_artifact(bad)]
        self.assertEqual(levels.count(ERROR), 2)                                   # cột lạ, thiếu ngưỡng
        dirty = fake("botnet_topology", expected_inputs("botnet_topology")[:3],
                     meta={"dac_trung": expected_inputs("botnet_topology")[:3],
                           "ma_nguon": {"commit": "abc", "co_sua_chua_commit": True}})
        self.assertEqual([lv for lv, _ in check_artifact(dirty)], [WARNING])       # mã chưa commit: chỉ cảnh báo
        mismatch = fake("attack_classification", feature_columns("windows")[:3],
                        meta={"dac_trung": ["a"], "ma_nguon": {"commit": "abc"}}, classes=["benign", "ddos"])
        msgs = " ".join(m for _, m in check_artifact(mismatch))
        self.assertIn("khác mô hình", msgs)
        self.assertIn("ddos", msgs)
        self.assertIn("thiếu file .json", " ".join(m for _, m in check_artifact(fake("anomaly", [], meta={}))))

    def test_check_table(self):
        a = fake("anomaly", ["x", "y"])
        check_table(pd.DataFrame({"x": [1], "y": [2], "z": [3]}), a)
        with self.assertRaises(ValueError):
            check_table(pd.DataFrame({"x": [1]}), a)

    def test_load(self):
        from nids.botnet import BotnetDetector, feature_names, save_model
        rng = np.random.default_rng(0)
        df = pd.DataFrame(rng.random((60, len(feature_names()))), columns=feature_names())
        df["label_host"] = ["suspect_host", "normal_host"] * 30
        with TemporaryDirectory() as d:
            save_model(BotnetDetector("logistic_regression", {}).fit(df), Path(d) / "b.joblib")
            cfg = {"pipeline": {"models": {"botnet_topology": str(Path(d) / "b.joblib"),
                                           "anomaly": str(Path(d) / "khong_co.joblib")}}}
            arts = load_artifacts(cfg, modules=("botnet_topology",))
            self.assertEqual(arts["botnet_topology"].features, feature_names())
            self.assertTrue(arts["botnet_topology"].meta)
            with self.assertRaises(FileNotFoundError):
                load_artifacts(cfg, modules=("anomaly",))
        self.assertTrue(pipeline_config({})["models"]["anomaly"].endswith("gaussian_windows.joblib"))


if __name__ == "__main__":
    unittest.main()

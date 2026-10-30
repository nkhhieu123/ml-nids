import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.data_quality import check, duplicate_report
from nids.dataset import feature_columns, load_table
from session_fixture import make_session


class DatasetTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.p1 = make_session(self.dir, "s1", 200, 1)
        self.p2 = make_session(self.dir, "s2", 100, 2, attack="dos")

    def test_load_merges_labels_and_split(self):
        df = load_table([self.p1, self.p2], "windows")
        self.assertEqual(len(df), 300)
        self.assertEqual(set(df["session"]), {"s1", "s2"})
        self.assertEqual(df["label_attack"].isna().sum(), 0)
        self.assertEqual((df["split"] == "bo").sum(), 2)

    def test_feature_columns_exclude_identifiers(self):
        feats = feature_columns("flows")
        for c in ("fwd_ip", "bwd_port", "first_ts", "protocol", "end_reason"):
            self.assertNotIn(c, feats)
        self.assertIn("iat_mean", feats)

    def test_quality_report(self):
        r = check([self.p1, self.p2], "flows")
        self.assertEqual(r["so_mau_bo_vi_ranh_gioi"], 2)
        self.assertIn("iat_mean", r["o_trong"])
        self.assertEqual(r["vo_han"], {})
        self.assertEqual(sum(r["phan_bo_label_attack"]["dos"].values()), 34)     # 100 mẫu, mỗi 3 có 1

    def test_duplicates_across_splits(self):
        df = pd.DataFrame({"a": [1, 1, 2, 3], "b": [0, 0, 0, np.nan],
                           "split": ["train", "test", "test", "validation"]})
        r = duplicate_report(df, ["a", "b"])
        self.assertEqual(r["test_trung_train"]["so_mau"], 1)
        self.assertEqual(r["validation_trung_train"]["so_mau"], 0)


if __name__ == "__main__":
    unittest.main()

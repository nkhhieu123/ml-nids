import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.classifier import class_report, host_roles, load_data
from nids.labeling import Rule
from session_fixture import make_session


def rule(id_, label, original, attackers, victims, start=0, end=10 ** 6):
    return Rule(id_, start, end, 0, 10 ** 6, frozenset(attackers), frozenset(victims), label, original, "")


RULES = [rule("scan", "port_scan", "PortScan", ["10.0.0.0"], ["10.0.0.1"]),
         rule("dos", "dos", "DoS Hulk", ["10.0.0.0"], ["10.0.0.1"]),
         rule("ddos", "loai", "DDoS", ["10.0.0.2"], ["10.0.0.3"], 1300, 1600)]


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


if __name__ == "__main__":
    unittest.main()

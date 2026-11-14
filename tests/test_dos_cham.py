"""Kiểm thử lớp giữ nhãn dos theo host (vớt DoS HTTP chậm)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import numpy as np
import pandas as pd

from nids.dos_cham import DosHolder, hold_dos


class HoldDosTest(unittest.TestCase):
    def test_raises_benign_after_enough_recent_dos(self):
        t = [0, 2, 4, 6, 8, 60]
        pred = ["dos", "dos", "benign", "benign", "port_scan", "benign"]
        got = hold_dos(pred, ["h"] * 6, t, lookback_s=10, min_count=2)
        # cửa sổ 4 và 6 có hai cửa sổ dos trong 10 giây trước; port_scan giữ nguyên; cửa sổ 60 đã quá xa
        self.assertEqual(list(got), ["dos", "dos", "dos", "dos", "port_scan", "benign"])

    def test_only_original_predictions_count_and_hosts_are_separate(self):
        t = [0, 2, 4, 6, 0, 2]
        pred = ["dos", "benign", "benign", "benign", "benign", "benign"]
        got = hold_dos(pred, ["a", "a", "a", "a", "b", "b"], t, lookback_s=10, min_count=1)
        self.assertEqual(list(got), ["dos", "dos", "dos", "dos", "benign", "benign"])   # host b không bị kéo theo
        # cần 2 cửa sổ dos gốc: cửa sổ đã nâng không được tính nên không lan dây chuyền
        self.assertEqual(list(hold_dos(pred, ["a"] * 4 + ["b"] * 2, t, 10, 2)), pred)

    def test_looks_only_backwards_and_keeps_input_order(self):
        got = hold_dos(["benign", "dos", "dos"], ["h", "h", "h"], [4, 0, 2], lookback_s=10, min_count=2)
        self.assertEqual(list(got), ["dos", "dos", "dos"])                  # đầu vào không cần sắp theo thời gian
        self.assertEqual(list(hold_dos(["benign", "dos", "dos"], ["h"] * 3, [0, 2, 4], 10, 1)),
                         ["benign", "dos", "dos"])                           # dos đến sau không nâng cửa sổ trước


class DosHolderTest(unittest.TestCase):
    def _frame(self, n=400, seed=0):
        rng = np.random.default_rng(seed)
        hosts = rng.choice(["a", "b", "c"], n)
        df = pd.DataFrame({"session": "s", "host": hosts, "window_start": 0.0,
                           "du_doan": rng.choice(["benign", "dos", "port_scan"], n, p=[0.6, 0.3, 0.1])})
        for h in "abc":                                           # mỗi host: cửa sổ cách nhau 2 giây, có khoảng trống
            m = (df["host"] == h).to_numpy()
            df.loc[m, "window_start"] = np.cumsum(rng.choice([2.0, 2.0, 2.0, 40.0], m.sum()))
        return df.sort_values("window_start", kind="stable").reset_index(drop=True)

    def test_matches_hold_dos(self):
        df = self._frame()
        want = hold_dos(df["du_doan"], df["host"], df["window_start"], 20, 3)
        got = DosHolder(20, 3).apply(df.copy())
        self.assertEqual(list(got["du_doan"]), list(want))
        self.assertEqual(list(got["giu_dos"]), list(want != df["du_doan"].to_numpy()))
        self.assertTrue(got["giu_dos"].any())

    def test_chunked_like_realtime_equals_one_pass(self):
        df = self._frame(seed=1)
        whole = DosHolder(20, 3).apply(df.copy())
        holder, parts = DosHolder(20, 3), []
        for i in range(0, len(df), 7):                            # cảm biến chấm từng lô cửa sổ vừa đóng
            parts.append(holder.apply(df.iloc[i:i + 7].copy()))
        self.assertEqual(list(pd.concat(parts)["du_doan"]), list(whole["du_doan"]))

    def test_config_off_by_default(self):
        self.assertIsNone(DosHolder.from_config({"pipeline": {"mode": "doc_lap"}}))
        h = DosHolder.from_config({"pipeline": {"dos_hold": {"lookback_s": 20, "min_count": 5}}})
        self.assertEqual((h.lookback_s, h.min_count), (20.0, 5))


if __name__ == "__main__":
    unittest.main()

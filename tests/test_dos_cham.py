"""Kiểm thử lớp giữ nhãn dos theo host (vớt DoS HTTP chậm)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.dos_cham import hold_dos


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


if __name__ == "__main__":
    unittest.main()

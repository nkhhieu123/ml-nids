import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.labeling import Rule, labels_path
from nids.splits import DROPPED, assign, build_segments, main


def rule(start, end, block="b1", label="dos"):
    return Rule("r", start, end, 0, 10**6, frozenset({"a"}), frozenset({"v"}), label, "x", block)


class SegmentTest(unittest.TestCase):
    def test_block_and_gaps_split_in_time(self):
        segs = build_segments(0, 1000, [rule(200, 700)], (0.6, 0.2, 0.2))
        self.assertEqual(segs, [
            (0, 120, "train"), (120, 160, "validation"), (160, 200, "test"),       # trước khối
            (200, 500, "train"), (500, 600, "validation"), (600, 700, "test"),     # khối tấn công
            (700, 880, "train"), (880, 940, "validation"), (940, 1000, "test"),    # sau khối
        ])

    def test_session_without_attacks(self):
        segs = build_segments(0, 100, [], (0.6, 0.2, 0.2))
        self.assertEqual([(round(s), round(e), n) for s, e, n in segs],
                         [(0, 60, "train"), (60, 80, "validation"), (80, 100, "test")])

    def test_rules_of_same_block_merge_and_unblocked_rules_ignored(self):
        segs = build_segments(0, 1000, [rule(200, 300), rule(250, 400), rule(500, 600, block="")],
                              (0.6, 0.2, 0.2))
        self.assertIn((200, 320, "train"), segs)               # khối gộp thành 200–400
        self.assertEqual(sum(1 for s in segs if s[0] >= 400), 3)  # 400–1000 là một khoảng thường

    def test_cut_by_sample_quantiles(self):
        # 100 mẫu dồn vào đầu khoảng: chia theo số mẫu, không theo thời gian.
        times = np.sort(np.concatenate([np.linspace(0, 10, 90), np.linspace(50, 100, 10)]))
        segs = build_segments(0, 100, [], (0.6, 0.2, 0.2), times)
        counts = [((times >= a) & (times < b)).sum() for a, b, _ in segs]
        self.assertEqual([n for *_, n in segs], ["train", "validation", "test"])
        self.assertTrue(abs(counts[0] - 60) <= 1 and abs(counts[1] - 20) <= 1, counts)
        self.assertEqual(segs[-1][1], 100)

    def test_few_samples_fall_back_to_time(self):
        segs = build_segments(0, 100, [], (0.6, 0.2, 0.2), np.array([1.0, 2.0, 3.0]))
        self.assertEqual([round(a) for a, *_ in segs], [0, 60, 80])

    def test_block_outside_session_ignored(self):
        segs = build_segments(0, 100, [rule(500, 600)], (0.6, 0.2, 0.2))
        self.assertEqual(len(segs), 3)


class AssignTest(unittest.TestCase):
    segs = [(0, 60, "train"), (60, 80, "validation"), (80, 100, "test")]

    def test_inside_crossing_and_embargo(self):
        first = np.array([10, 55, 59, 65, 79, 85, 99])
        last = np.array([20, 58, 61, 70, 79.5, 90, 100])
        out = assign(first, last, self.segs, embargo_s=5)
        self.assertEqual(list(out), ["train", DROPPED, DROPPED, "validation", DROPPED, "test", "test"])

    def test_no_embargo(self):
        out = assign(np.array([55]), np.array([59.9]), self.segs, embargo_s=0)
        self.assertEqual(out[0], "train")


class CliTest(unittest.TestCase):
    def test_writes_split_files(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp)
            flows = d / "x.flows.csv"
            pd.DataFrame({"first_index": range(10), "first_ts": np.arange(10) * 100.0,
                          "last_ts": np.arange(10) * 100.0 + 1}).to_csv(flows, index=False)
            pd.DataFrame({"host": ["h"] * 3, "window_start": [0.0, 500.0, 890.0],
                          "window_end": [10.0, 510.0, 900.0]}).to_csv(d / "x.windows.csv", index=False)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(flows)]), 0)
            f = pd.read_csv(labels_path(flows, "split"))
            w = pd.read_csv(labels_path(d / "x.windows.csv", "split"))
        self.assertEqual(list(f["split"][:2]), ["train", "train"])
        self.assertEqual(f["split"].iloc[-1], "test")
        self.assertEqual(list(w["split"]), ["train", "train", "test"])


if __name__ == "__main__":
    unittest.main()

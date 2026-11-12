"""Kiểm thử các phần không cần dữ liệu của bước học lại trên lab."""

import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nids.config import load_config
from nids.hoc_lai_lab import binary, write_lab_config


class HocLaiLabTest(unittest.TestCase):
    def test_binary_metrics(self):
        m = binary([True, True, False, False, False], [True, False, True, False, False])
        self.assertEqual((m["so_mau"], m["duong"], m["precision"], m["recall"], m["f1"]), (5, 2, 0.5, 0.5, 0.5))
        self.assertEqual(m["ty_le_am_bi_bao"], 0.3333)
        self.assertEqual(binary([False, False], [False, False])["f1"], 0.0)      # không có mẫu dương

    def test_lab_config_only_changes_models_mode_and_topology(self):
        base = load_config()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "lab.yaml"
            write_lab_config(ROOT / "models" / "lab", {"min_peer_vao": 2, "min_udp": 0.1, "min_entropy_vao": 0.5,
                                                       "dung": 1.0}, "doc_lap", path)
            lab = load_config(path)                                  # vẫn là cấu hình hợp lệ
            self.assertTrue(path.read_text(encoding="utf-8").startswith("# Cấu hình cho mạng lab"))
        self.assertEqual(lab["pipeline"]["models"]["botnet_topology"], "models/lab/botnet_rf.joblib")
        self.assertEqual(lab["pipeline"]["mode"], "doc_lap")
        self.assertEqual(lab["botnet"]["topology_rule"], {"min_peer_vao": 2, "min_udp": 0.1, "min_entropy_vao": 0.5})
        for key in ("windows", "flow", "labeling", "lab", "gaussian", "classifier"):
            self.assertEqual(lab[key], base[key], key)               # mọi thứ khác giữ nguyên
        self.assertEqual({k: v for k, v in lab["botnet"].items() if k != "topology_rule"},
                         {k: v for k, v in base["botnet"].items() if k != "topology_rule"})


if __name__ == "__main__":
    unittest.main()

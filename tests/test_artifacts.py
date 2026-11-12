"""Mô hình đang có trên máy phải khớp mã nguồn hiện tại (tương đương ``python -m nids.pipeline kiem-tra``).

Chạy cùng bộ kiểm thử nên mỗi lần sửa ``src/`` hoặc ``config/`` đều kiểm tra lại, không cần nhớ chạy tay.
Thư mục ``models/`` không lên git; máy chưa có mô hình thì bỏ qua.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nids.config import load_config
from nids.pipeline import ERROR, check_all, pipeline_config
from nids.scope import MODULES


def have_models(cfg) -> bool:
    return all(Path(p).exists() for p in pipeline_config(cfg)["models"].values())


class ArtifactTest(unittest.TestCase):
    def _check(self, config_path):
        cfg = load_config(config_path)
        if not have_models(cfg):
            self.skipTest("chưa có mô hình trên máy này")
        report = check_all(cfg)
        errors = {m: [p["noi_dung"] for p in report[m]["van_de"] if p["muc"] == ERROR] for m in MODULES}
        self.assertTrue(report["hop_le"], errors)

    def test_default_models_match_code(self):
        self._check(None)

    def test_lab_models_match_code(self):
        path = ROOT / "config" / "lab.yaml"
        if not path.exists():
            self.skipTest("chưa có config/lab.yaml")
        self._check(path)


if __name__ == "__main__":
    unittest.main()

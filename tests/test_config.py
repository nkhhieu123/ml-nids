import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.config import DEFAULT_CONFIG, load_config


class ConfigTest(unittest.TestCase):
    def test_default_values(self):
        cfg = load_config()
        self.assertEqual(cfg["windows"]["flow"], {"size_s": 10, "step_s": 2})
        self.assertEqual(cfg["windows"]["graph"], {"size_s": 120, "step_s": 10})
        self.assertEqual(len(cfg["lab"]["hosts"]), 9)          # 7 máy + hai bot của kịch bản 6 (QĐ-076)
        self.assertIn("192.168.50.10", cfg["lab"]["hosts"])
        self.assertEqual(cfg["alerts"]["channels"], ["terminal", "csv"])

    def test_rejects_step_larger_than_window(self):
        text = DEFAULT_CONFIG.read_text(encoding="utf-8").replace("step_s: 2", "step_s: 20")
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()

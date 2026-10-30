import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from session_fixture import make_session

try:
    from nids.eda import run as run_eda
except ImportError:      # matplotlib là phần cài thêm (.[notebook])
    run_eda = None


@unittest.skipIf(run_eda is None, "chưa cài matplotlib")
class EdaTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.p1 = make_session(self.dir, "s1", 200, 1)
        self.p2 = make_session(self.dir, "s2", 100, 2, attack="dos")

    def test_eda_writes_figures(self):
        s = run_eda([self.p1, self.p2], self.dir / "hinh")
        for path in s["hinh"].values():
            self.assertTrue(Path(path).stat().st_size > 1000, path)


if __name__ == "__main__":
    unittest.main()

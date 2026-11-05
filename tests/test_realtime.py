import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.moi_truong import (FAIL, OK, WARN, capabilities, check_capture_permission, check_interface, check_ntp,
                             check_packages, check_python)


class EnvironmentTest(unittest.TestCase):
    """C10-T01: kiểm tra môi trường trước khi chạy cảm biến."""

    def test_python_and_packages(self):
        self.assertEqual(check_python((3, 12, 1))[0], OK)
        self.assertEqual(check_python((3, 9, 0))[0], FAIL)
        res = dict((msg.split()[0] if lv == OK else msg, lv) for lv, msg in
                   check_packages(required=("json",), optional=("khong_co_thu_vien_nay",)))
        self.assertEqual(res["json"], OK)
        self.assertEqual(res["thiếu thư viện khong_co_thu_vien_nay (tùy chọn)"], WARN)
        self.assertEqual(check_packages(required=("khong_co_x",), optional=())[0][0], FAIL)

    def test_capture_permission(self):
        status = "Name:\tpython\nCapEff:\t0000000000003000\n"                      # bit 12, 13
        self.assertEqual(capabilities(status), 0x3000)
        self.assertIsNone(capabilities("Name: x\n"))
        self.assertEqual(check_capture_permission("Linux", euid=0)[0], OK)
        self.assertEqual(check_capture_permission("Linux", euid=1000, status_text=status)[0], OK)
        self.assertEqual(check_capture_permission("Linux", euid=1000, status_text="CapEff:\t0\n")[0], FAIL)
        self.assertEqual(check_capture_permission("Windows")[0], WARN)

    def test_interface(self):
        with TemporaryDirectory() as d:
            (Path(d) / "eth1").mkdir()
            (Path(d) / "eth1" / "operstate").write_text("up\n")
            (Path(d) / "lo").mkdir()
            self.assertEqual(check_interface("eth1", "Linux", d)[0], OK)
            lv, msg = check_interface("eth0", "Linux", d)
            self.assertEqual(lv, FAIL)
            self.assertIn("eth1", msg)                                              # gợi ý card có thật
        self.assertEqual(check_interface(None, "Linux")[0], WARN)

    def test_ntp(self):
        yes = lambda *a, **k: SimpleNamespace(stdout="yes\n")
        no = lambda *a, **k: SimpleNamespace(stdout="no\n")
        def broken(*a, **k):
            raise OSError("không có")
        self.assertEqual(check_ntp("Linux", yes)[0], OK)
        self.assertEqual(check_ntp("Linux", no)[0], WARN)
        self.assertEqual(check_ntp("Linux", broken)[0], WARN)


if __name__ == "__main__":
    unittest.main()

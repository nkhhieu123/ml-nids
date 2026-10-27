import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.manifest import (
    DEFAULT_MANIFEST, VERIFY_MISMATCH, VERIFY_MISSING, VERIFY_OK, entries_for, load_manifest,
    sha256_file, verify,
)
from nids.scope import MODULES


class ManifestTest(unittest.TestCase):
    def test_every_module_has_data(self):
        rows = load_manifest()
        for module in MODULES:
            self.assertTrue(entries_for(module, rows), module)

    def test_ctu13_has_13_scenarios(self):
        rows = [r for r in load_manifest() if r["nguon"] == "CTU-13"]
        self.assertEqual(len(rows), 13)
        self.assertEqual([r["id"] for r in rows if "p2p" in r["nhan_do_an"]], ["ctu13-s12"])

    def test_reference_data_has_no_split(self):
        for row in entries_for("doi_chieu"):
            self.assertEqual(row["muc_dich"], ["doi_chieu"], row["id"])

    def _load_modified(self, old, new):
        text = DEFAULT_MANIFEST.read_text(encoding="utf-8")
        self.assertIn(old, text)
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.csv"
            path.write_text(text.replace(old, new, 1), encoding="utf-8")
            return load_manifest(path)

    def test_rejects_unknown_label(self):
        with self.assertRaises(ValueError):
            self._load_modified("benign;dos", "benign;ddos")

    def test_downloaded_rows_have_checksum(self):
        for row in load_manifest():
            if row["trang_thai"] == "da_tai":
                self.assertEqual(len(row["sha256"]), 64, row["id"])
        with self.assertRaises(ValueError):
            self._load_modified("chua_thu,", "da_tai,")

    def test_rejects_duplicate_id(self):
        with self.assertRaises(ValueError):
            self._load_modified("ctu13-s02", "ctu13-s01")


class VerifyTest(unittest.TestCase):
    def test_verify_downloaded_files(self):
        with TemporaryDirectory() as tmp:
            data = Path(tmp)
            (data / "pcap" / "cic").mkdir(parents=True)
            good = data / "pcap" / "cic" / "Monday.pcap"
            good.write_bytes(b"du lieu goc")
            bad = data / "Friday.pcap"
            bad.write_bytes(b"tai do dang")
            rows = [
                {"id": "a", "file": "Monday.pcap", "sha256": sha256_file(good)},
                {"id": "b", "file": "x/Friday.pcap", "sha256": "0" * 64},
                {"id": "c", "file": "Wednesday.pcap", "sha256": "1" * 64},
                {"id": "d", "file": "lab.pcap", "sha256": ""},       # chưa tải: bỏ qua
            ]
            results = {row_id: status for row_id, _, status in verify(rows, data)}
        self.assertEqual(results, {"a": VERIFY_OK, "b": VERIFY_MISMATCH, "c": VERIFY_MISSING})


if __name__ == "__main__":
    unittest.main()

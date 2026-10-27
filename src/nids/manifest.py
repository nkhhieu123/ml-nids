"""Đọc manifest dữ liệu từ config/data_manifest.csv (C02-T05) và kiểm tra file đã tải.

    python -m nids.manifest --verify      # so mã băm các file trong data/ với manifest
"""

import argparse
import csv
import hashlib
import re
import sys
from pathlib import Path

from .config import PROJECT_ROOT
from .scope import LABELS, MODULES

DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "data_manifest.csv"
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
HASH_CHUNK = 8 * 1024 * 1024

# Kết quả kiểm tra một file
VERIFY_OK = "khop"
VERIFY_MISSING = "thieu_file"
VERIFY_MISMATCH = "sai_ma_bam"

COLUMNS = (
    "id", "nguon", "bai_toan", "file", "dinh_dang", "thoi_gian",
    "nhan_goc", "nhan_do_an", "muc_dich", "dung_luong", "trang_thai", "ghi_chu", "sha256",
)
REQUIRED = ("id", "nguon", "bai_toan", "file", "dinh_dang", "muc_dich", "trang_thai")
# Cột chứa nhiều giá trị, ngăn cách bằng dấu chấm phẩy.
LIST_COLUMNS = ("bai_toan", "nhan_do_an", "muc_dich")

REFERENCE = "doi_chieu"  # dữ liệu chỉ để đối chiếu, không vào mô hình
PROBLEMS = MODULES + (REFERENCE,)
PURPOSES = ("train", "validation", "test", REFERENCE)
STATUSES = ("chua_tai", "da_kiem_tra_may_chu", "da_tai_thu", "da_tai", "chua_thu")
SHA256 = re.compile(r"[0-9a-f]{64}")
PROJECT_LABELS = frozenset(label for labels in LABELS.values() for label in labels)


def load_manifest(path=None) -> list:
    """Trả về danh sách dict, mỗi dict là một dòng của manifest."""
    path = Path(path) if path else DEFAULT_MANIFEST
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if tuple(reader.fieldnames or ()) != COLUMNS:
            raise ValueError(f"{path}: cột phải là {COLUMNS}, nhận {reader.fieldnames}")
        rows = list(reader)
    seen = set()
    for row in rows:
        _validate(row, path)
        if row["id"] in seen:
            raise ValueError(f"{path}: trùng id {row['id']}")
        seen.add(row["id"])
        for col in LIST_COLUMNS:
            row[col] = _split(row[col])
    return rows


def entries_for(problem, rows=None) -> list:
    """Các dòng manifest phục vụ một bài toán (tên module hoặc ``doi_chieu``)."""
    rows = load_manifest() if rows is None else rows
    return [row for row in rows if problem in row["bai_toan"]]


def _split(value):
    return [item.strip() for item in value.split(";") if item.strip()]


def _validate(row, path):
    where = f"{path}: dòng {row.get('id') or '?'}"
    for col in REQUIRED:
        if not row[col].strip():
            raise ValueError(f"{where}: thiếu {col}")
    _check(_split(row["bai_toan"]), PROBLEMS, "bai_toan", where)
    _check(_split(row["muc_dich"]), PURPOSES, "muc_dich", where)
    _check(_split(row["nhan_do_an"]), PROJECT_LABELS, "nhan_do_an", where)
    _check([row["trang_thai"]], STATUSES, "trang_thai", where)
    if row["sha256"] and not SHA256.fullmatch(row["sha256"]):
        raise ValueError(f"{where}: sha256 phải là 64 ký tự hex thường")
    if row["trang_thai"] == "da_tai" and not row["sha256"]:
        raise ValueError(f"{where}: dữ liệu đã tải (da_tai) phải có sha256")


def _check(values, allowed, col, where):
    unknown = [v for v in values if v not in allowed]
    if unknown:
        raise ValueError(f"{where}: {col} không hợp lệ: {unknown}")


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(HASH_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def verify(rows=None, data_dir=None) -> list:
    """So mã băm của các dòng có ``sha256`` với file cùng tên trong ``data_dir``.

    Tên file là phần cuối của cột ``file``; file được tìm ở mọi thư mục con của
    ``data_dir``. Trả về danh sách (id, đường dẫn hoặc None, kết quả).
    """
    rows = load_manifest() if rows is None else rows
    data_dir = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
    results = []
    for row in rows:
        if not row["sha256"]:
            continue
        name = row["file"].replace("\\", "/").split("/")[-1]
        found = sorted(data_dir.rglob(name)) if data_dir.exists() else []
        if not found:
            results.append((row["id"], None, VERIFY_MISSING))
            continue
        path = found[0]
        status = VERIFY_OK if sha256_file(path) == row["sha256"] else VERIFY_MISMATCH
        results.append((row["id"], path, status))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description="Kiểm tra manifest dữ liệu.")
    parser.add_argument("--manifest", help="file manifest, mặc định config/data_manifest.csv")
    parser.add_argument("--verify", action="store_true",
                        help="so mã băm SHA-256 của các file đã tải trong data/")
    parser.add_argument("--data-dir", help="thư mục dữ liệu, mặc định data/")
    args = parser.parse_args(argv)

    rows = load_manifest(args.manifest)
    print(f"Manifest hợp lệ: {len(rows)} dòng")
    if not args.verify:
        return 0
    results = verify(rows, args.data_dir)
    for row_id, path, status in results:
        print(f"  {row_id}: {status}" + (f" ({path})" if path else ""))
    bad = [r for r in results if r[2] != VERIFY_OK]
    if not results:
        print("  Không có dòng nào có sha256")
    elif bad:
        print(f"{len(bad)} file thiếu hoặc sai mã băm; tải lại từ nguồn chính thức")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

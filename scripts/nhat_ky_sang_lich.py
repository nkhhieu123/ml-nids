"""Đổi nhật ký lần chạy lab (data/run_logs/nhat_ky.jsonl) thành lịch gán nhãn cho nids.labeling (B10).

Nhật ký là căn cứ gán nhãn độc lập với dự đoán. Mỗi dòng nhật ký của sinh_traffic.py có nhãn tấn công
(benign/port_scan/dos), thời điểm bắt đầu/kết thúc, IP nguồn và đích; script này viết ra một CSV cùng định
dạng config/label_schedule.csv để nids.labeling gán nhãn cho PCAP lab y như với CIC-IDS2017.

Dòng ``benign`` không tạo luật (không có luật nào thì flow mặc định là bình thường). Dòng ``dos`` và
``port_scan`` thành một luật mỗi dòng: khung giờ là [bắt đầu, kết thúc] của hành vi, múi giờ lấy từ nhật ký.

    python scripts/nhat_ky_sang_lich.py data/run_logs/nhat_ky.jsonl --out config/label_schedule_lab.csv
"""

import argparse
import csv
import datetime
import json
import sys
from pathlib import Path

COLUMNS = ("id", "nguon", "ngay", "bat_dau", "ket_thuc", "utc_offset_h", "nhan_goc",
           "nhan_attack", "ben_tan_cong", "nan_nhan", "cong_nan_nhan", "khoi", "ghi_chu")
ATTACK_LABELS = {"port_scan", "dos"}


def _parts(iso):
    """'2026-11-06T13:40:05+07:00' -> (ngày, 'HH:MM', giờ_lệch). ket_thuc tính hết phút nên trừ lùi an toàn."""
    dt = datetime.datetime.fromisoformat(iso)
    off_h = dt.utcoffset().total_seconds() / 3600 if dt.utcoffset() is not None else 0.0
    return dt.strftime("%Y-%m-%d"), dt.strftime("%H:%M"), off_h


def rows_from_logs(logs):
    rows = []
    for log in logs:
        label = log.get("nhan")
        if label not in ATTACK_LABELS:
            continue                      # benign và các kiểu khác không cần luật
        day, start_hm, off = _parts(log["bat_dau"])
        _, end_hm, _ = _parts(log["ket_thuc"])
        port = log.get("tham_so", {}).get("cong", "")
        rows.append({
            "id": log["ma_lan_chay"], "nguon": "Lab", "ngay": day, "bat_dau": start_hm, "ket_thuc": end_hm,
            "utc_offset_h": f"{off:g}", "nhan_goc": log.get("kieu", label), "nhan_attack": label,
            "ben_tan_cong": log["ip_nguon"], "nan_nhan": log["ip_dich"],
            "cong_nan_nhan": str(port) if port else "", "khoi": log.get("bien_the", log["ma_lan_chay"]),
            "ghi_chu": f"Lab {log.get('vai_tro', '')}; sinh từ nhật ký lần chạy",
        })
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description="Đổi nhật ký lần chạy lab thành lịch gán nhãn.")
    parser.add_argument("nhat_ky", help="data/run_logs/nhat_ky.jsonl")
    parser.add_argument("--out", required=True, help="CSV lịch gán nhãn (dùng với nids.labeling --schedule)")
    a = parser.parse_args(argv)
    logs = [json.loads(l) for l in Path(a.nhat_ky).read_text(encoding="utf-8").splitlines() if l.strip()]
    rows = rows_from_logs(logs)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(f"{len(logs)} dòng nhật ký -> {len(rows)} luật tấn công; đã ghi {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

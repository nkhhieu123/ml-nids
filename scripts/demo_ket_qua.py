"""In bảng kết quả đã lưu của Chặng 11 để trình bày (gọi qua demo/4_ket_qua_da_luu.bat).

Đọc các file JSON trong docs/hinh/thuc_nghiem/lab; không chạy lại mô hình.
"""

import json
import statistics
from collections import defaultdict
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent / "docs" / "hinh" / "thuc_nghiem" / "lab"
NHOM = {"k2": "Quét cổng (Nmap)", "k3": "DoS tải kết nối", "k4": "Botnet tập trung", "k5": "Botnet ngang hàng",
        "x3": "SYN flood gói thô", "x4": "Botnet tập trung, đổi vai", "x5": "Botnet ngang hàng, đổi vai"}


def theo_nhom(ten):
    d = json.loads((LAB / f"{ten}.json").read_text(encoding="utf-8"))
    rows = defaultdict(lambda: {"dot": 0, "bat": 0, "tre": []})
    for k in d["kich_ban"]:
        for e in k["phat_hien"]["theo_dot"]:
            r = rows[e["kich_ban"][:2]]
            r["dot"] += 1
            r["bat"] += bool(e["phat_hien"])
            if e["phat_hien"]:
                r["tre"].append(e["do_tre_s"])
    return d["tong_hop"], rows


def bang(tieu_de, ten):
    tong, rows = theo_nhom(ten)
    print(f"\n{tieu_de}")
    print(f"  {'Loại tấn công':<28}{'Phát hiện':>10}  {'Độ trễ trung vị tới cuối cửa sổ':>32}")
    for k in sorted(rows):
        r = rows[k]
        tre = f"{statistics.median(r['tre']):.1f} giây" if r["tre"] else "-"
        print(f"  {NHOM.get(k, k):<28}{r['bat']:>5}/{r['dot']:<4}  {tre:>32}")
    print(f"  {'Tổng':<28}{tong['phat_hien']:>5}/{tong['so_dot']:<4}  báo động giả: {tong['bao_gia']} sự kiện")


def main():
    print("KẾT QUẢ CHẶNG 11 TRÊN LAB ẢO (33 lần chạy test mới, lần 9-11)")
    bang("1) Mô hình học từ CIC-IDS2017 và CTU-13, đem thẳng sang lab", "test3_cu")
    bang("2) Mô hình học lại trên dữ liệu lab (config/lab.yaml)", "test3_lab")
    bang("3) Mô hình lab trên biến thể đổi vai trò máy (không có trong dữ liệu học)", "doi_vai_lab")
    bang("4) Mô hình lab trên SYN flood gói thô bằng hping3 (không có trong dữ liệu học)", "syn_lab")
    print("\nHạn chế: mới đo trên lab ảo; mô hình botnet của lab cho recall 0 trên CTU-13 (docs/76).")


if __name__ == "__main__":
    main()

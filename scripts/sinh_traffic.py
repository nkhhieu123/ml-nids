"""Sinh traffic lab cho kịch bản 1–3: bình thường, quét cổng, và tải kết nối (DoS SYN) (B14–B16).

Dùng cùng khuôn an toàn với scripts/sinh_topology.py:

AN TOÀN (B24):
- Mọi địa chỉ đích phải nằm trong mạng lab (mặc định 192.168.50.0/24); địa chỉ khác bị từ chối ngay.
- Chỉ mở/đóng kết nối TCP thường và gửi yêu cầu HTTP GET vô hại tới máy chủ dịch vụ của lab; không chèn
  mã, không khai thác lỗ hổng, không gửi mã độc.
- Kịch bản 3 là bộ sinh *tải kết nối*: mở rồi đóng socket TCP thường thật nhanh để tạo nhiều kết nối dở
  dang (SYN gửi đi nhưng bắt tay chưa xong) — đúng mẫu đặc trưng mà module phân loại cần (cờ TCP, tỷ lệ
  kết nối không hoàn tất). Không tạo gói thô, không giả mạo IP nguồn. Thời gian bị chặn cứng ở tối đa 60
  giây (B16), và chỉ nhắm một máy chủ của lab.

Mỗi lần chạy ghi một dòng nhật ký (B10, B23) vào data/run_logs/nhat_ky.jsonl, cùng định dạng với
sinh_topology.py, làm căn cứ gán nhãn độc lập với dự đoán. Dùng scripts/nhat_ky_sang_lich.py để đổi
nhật ký thành lịch gán nhãn cho nids.labeling.

Ví dụ (mỗi lệnh chạy trên một máy của lab; đích luôn là máy chủ dịch vụ 192.168.50.30):

    # Kịch bản 1 — client sinh traffic bình thường 10 phút, có tác vụ kiểm tra trạng thái định kỳ
    python scripts/sinh_traffic.py binh-thuong --may-chu 192.168.50.30 --cong 80 --thoi-gian 600 \
        --vai-tro train --lan 01
    # Kịch bản 2 — quét cổng từ máy thử nghiệm 192.168.50.20 (gọi tcpdump/Nmap bên ngoài; đây chỉ ghi nhật ký)
    python scripts/sinh_traffic.py quet --may-chu 192.168.50.30 --cong-dau 1 --cong-cuoi 1024 \
        --toc-do cham --vai-tro train --lan 01
    # Kịch bản 3 — tải kết nối 60 giây, mức tải trung bình
    python scripts/sinh_traffic.py tai-ket-noi --may-chu 192.168.50.30 --cong 80 --muc 2 --thoi-gian 60 \
        --vai-tro train --lan 01

Thêm ``--thu`` để chỉ in kế hoạch, không gửi gì. ``--seed`` để lặp lại lịch.
"""

import argparse
import datetime
import ipaddress
import json
import os
import random
import socket
import sys
import time
import uuid
from pathlib import Path

LAB_NET = ipaddress.ip_network("192.168.50.0/24")
# NIDS_NHAT_KY: ghi nhật ký vào file khác (bộ chạy kịch bản lab_ao.py dùng một file cho mỗi lần chạy).
LOG = Path(os.environ.get("NIDS_NHAT_KY") or Path(__file__).resolve().parents[1] / "data" / "run_logs" / "nhat_ky.jsonl")
DOS_MAX_S = 60.0                 # B16: mỗi lần tải kết nối không quá 60 giây
HTTP_GET = "GET /{path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nids-lab\r\nConnection: close\r\n\r\n"
# Ba mức tải: số kết nối mỗi giây nhắm tới máy chủ dịch vụ của lab (chốt trước khi chạy, B16).
DOS_LEVELS = {1: 50, 2: 200, 3: 600}
# Hai tốc độ quét: giãn cách giây giữa hai lần thử cổng liên tiếp.
SCAN_RATES = {"cham": 0.5, "nhanh": 0.0}
BENIGN_PATHS = ("", "index.html", "about.html", "assets/app.css", "assets/app.js", "api/status")


def check_target(ip, allowed=LAB_NET):
    """Từ chối mọi đích ngoài mạng lab (B24)."""
    if ipaddress.ip_address(ip) not in allowed:
        raise SystemExit(f"Từ chối: {ip} không thuộc mạng lab {allowed}")
    return ip


def local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.168.50.1", 9))
            return s.getsockname()[0]
    except OSError:
        return "?"


def write_log(entry, path=LOG):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def http_get(host, port, path, timeout=3.0):
    """Mở kết nối, gửi một GET vô hại, đọc phản hồi, đóng. Trả về True nếu bắt tay xong."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(HTTP_GET.format(path=path, host=host).encode())
            s.recv(65536)
        return True
    except OSError:
        return False


def run_benign(host, port, duration, rng, dry):
    """Client bình thường: duyệt trang theo nhịp người dùng, xen tác vụ kiểm tra trạng thái mỗi ~30 giây."""
    plan, t, next_status = [], rng.uniform(0, 3), 30.0
    while t < duration:
        plan.append((t, "api/status" if t >= next_status else rng.choice(BENIGN_PATHS)))
        if t >= next_status:
            next_status += 30.0
        t += rng.uniform(1.0, 6.0)
    if dry:
        return {"so_yeu_cau": len(plan)}
    start, ok = time.time(), 0
    for t, path in plan:
        time.sleep(max(0.0, start + t - time.time()))
        ok += http_get(host, port, path)
    return {"so_yeu_cau": len(plan), "so_lan_thanh_cong": ok}


def run_scan(host, first_port, last_port, rate, dry):
    """Quét cổng: thử nối lần lượt từng cổng trong dải, giãn cách ``rate`` giây.

    Chỉ là nối TCP thường tới một máy của lab; mô phỏng hành vi của Nmap connect scan khi không chạy Nmap.
    Khi thu thật, dùng Nmap trên máy thử nghiệm và script này chỉ để ghi nhật ký (--thu)."""
    ports = list(range(first_port, last_port + 1))
    if dry:
        return {"so_cong": len(ports), "gian_cach_s": rate}
    mo, dong = 0, 0
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=1.0):
                mo += 1
        except OSError:
            dong += 1
        if rate:
            time.sleep(rate)
    return {"so_cong": len(ports), "cong_mo": mo, "cong_dong": dong}


def run_conn_load(host, port, level, duration, rng, dry):
    """Bộ sinh tải kết nối (DoS SYN mô phỏng): mở rồi đóng ngay socket TCP thường, nhiều kết nối mỗi giây.

    An toàn: socket hệ điều hành bình thường (không gói thô, không giả IP nguồn), chỉ nhắm một máy chủ của
    lab, thời gian bị chặn cứng ở DOS_MAX_S. Nhiều kết nối không kịp hoàn tất bắt tay -> đúng mẫu cần học."""
    duration = min(duration, DOS_MAX_S)
    per_s = DOS_LEVELS[level]
    if dry:
        return {"muc": level, "ket_noi_moi_giay": per_s, "thoi_gian_s": duration,
                "uoc_tinh_ket_noi": int(per_s * duration)}
    start, attempts, done = time.time(), 0, 0
    gap = 1.0 / per_s
    while time.time() - start < duration:
        attempts += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((host, port))        # mở kết nối thật tới máy chủ của lab
            done += 1
            s.close()                      # rồi đóng ngay: tạo kết nối ngắn, nhiều cái dở dang
        except OSError:
            pass
        time.sleep(max(0.0, start + attempts * gap - time.time()))
    return {"muc": level, "ket_noi_moi_giay": per_s, "thoi_gian_s": round(time.time() - start, 1),
            "so_lan_thu": attempts, "so_lan_noi_duoc": done}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sinh traffic lab vô hại cho kịch bản 1–3 (chỉ trong mạng lab).")
    sub = parser.add_subparsers(dest="kieu", required=True)

    p = sub.add_parser("binh-thuong", help="kịch bản 1: client duyệt web bình thường + kiểm tra trạng thái")
    p.add_argument("--may-chu", required=True)
    p.add_argument("--cong", type=int, default=80)
    p.add_argument("--thoi-gian", type=float, default=600.0)

    p = sub.add_parser("quet", help="kịch bản 2: quét cổng (connect scan) tới một máy chủ của lab")
    p.add_argument("--may-chu", required=True)
    p.add_argument("--cong-dau", type=int, default=1)
    p.add_argument("--cong-cuoi", type=int, default=1024)
    p.add_argument("--toc-do", choices=tuple(SCAN_RATES), default="cham")

    p = sub.add_parser("tai-ket-noi", help="kịch bản 3: tải kết nối (DoS SYN mô phỏng), tối đa 60 giây")
    p.add_argument("--may-chu", required=True)
    p.add_argument("--cong", type=int, default=80)
    p.add_argument("--muc", type=int, choices=tuple(DOS_LEVELS), required=True)
    p.add_argument("--thoi-gian", type=float, default=60.0)

    for p in sub.choices.values():
        p.add_argument("--vai-tro", choices=("train", "val", "test"), required=True,
                       help="vai trò lần chạy, phải ghi trước khi chạy (B11, B19)")
        p.add_argument("--lan", default="01", help="số thứ tự lần chạy trong vai trò")
        p.add_argument("--seed", type=int, default=None)
        p.add_argument("--thu", action="store_true", help="chỉ in kế hoạch, không gửi gì")

    a = parser.parse_args(argv)
    rng = random.Random(a.seed)
    host = check_target(a.may_chu)
    variant = {"binh-thuong": "k1-binh-thuong",
               "quet": None,            # điền bên dưới theo tốc độ
               "tai-ket-noi": None}[a.kieu]
    if a.kieu == "quet":
        variant = "k2-quet-cham" if a.toc_do == "cham" else "k2-quet-nhanh"
    elif a.kieu == "tai-ket-noi":
        variant = f"k3-dos-muc{a.muc}"
    run_id = f"{variant}-{a.vai_tro}-{a.lan}"
    began = datetime.datetime.now().astimezone()

    if a.kieu == "binh-thuong":
        result = run_benign(host, a.cong, a.thoi_gian, rng, a.thu)
        params = {"cong": a.cong, "thoi_gian": a.thoi_gian}
    elif a.kieu == "quet":
        result = run_scan(host, a.cong_dau, a.cong_cuoi, SCAN_RATES[a.toc_do], a.thu)
        params = {"cong_dau": a.cong_dau, "cong_cuoi": a.cong_cuoi, "toc_do": a.toc_do}
    else:
        result = run_conn_load(host, a.cong, a.muc, a.thoi_gian, rng, a.thu)
        params = {"cong": a.cong, "muc": a.muc, "thoi_gian": min(a.thoi_gian, DOS_MAX_S)}

    label = {"binh-thuong": "benign", "quet": "port_scan", "tai-ket-noi": "dos"}[a.kieu]
    entry = {"ma_lan_chay": run_id, "bien_the": variant, "vai_tro": a.vai_tro, "kieu": a.kieu,
             "nhan": label, "bat_dau": began.isoformat(timespec="seconds"),
             "ket_thuc": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
             "ip_nguon": local_ip(), "ip_dich": host, "tham_so": {**params, "seed": a.seed},
             "chi_thu": a.thu, **result}
    if a.thu:
        print(json.dumps(entry, ensure_ascii=False, indent=2))
    else:
        write_log(entry)
        print(f"Xong {run_id} ({label}); nhật ký: {LOG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Sinh traffic topology trong lab cô lập: botnet tập trung, ngang hàng và đối chứng lành tính (C08-T06).

AN TOÀN (B24): chỉ gửi thông điệp văn bản vô hại ("nids-lab ..."), không thực thi lệnh nhận được,
không dùng mã độc. Mọi địa chỉ đích phải nằm trong mạng lab (mặc định 192.168.50.0/24); địa chỉ khác bị
từ chối. Mỗi lần chạy ghi một dòng nhật ký (B10) vào data/run_logs/nhat_ky.jsonl: mã lần chạy, thời gian
bắt đầu và kết thúc, IP tham gia, hành vi, tham số. Nhật ký là căn cứ gán nhãn, độc lập với dự đoán.

Ví dụ (mỗi lệnh chạy trên một máy của lab):

    # Máy điều khiển 192.168.50.50
    python scripts/sinh_topology.py may-chu --cong 8080 --thoi-gian 900
    # Bot 192.168.50.41–43: gọi về máy điều khiển, chu kỳ 30 giây, jitter 20%
    python scripts/sinh_topology.py tap-trung --may-chu 192.168.50.50 --cong 8080 --chu-ky 30 --jitter 0.2 --thoi-gian 900
    # Ngang hàng: mỗi máy vừa nghe vừa gửi UDP tới danh sách peer
    python scripts/sinh_topology.py ngang-hang --peer 192.168.50.42 --peer 192.168.50.43 --cong 40000 --chu-ky 8 --thoi-gian 900
    # Đối chứng tập trung lành tính: hỏi máy chủ dịch vụ định kỳ (như kiểm tra cập nhật)
    python scripts/sinh_topology.py doi-chung-tap-trung --may-chu 192.168.50.30 --cong 80 --chu-ky 30 --thoi-gian 900
    # Đối chứng ngang hàng lành tính: chia sẻ khối dữ liệu theo đợt (máy nhận chạy may-chu --cong 6881)
    python scripts/sinh_topology.py doi-chung-ngang-hang --peer 192.168.50.42 --cong 6881 --thoi-gian 900

Thêm ``--thu`` để chỉ in kế hoạch, không gửi gì.
"""

import argparse
import datetime
import ipaddress
import json
import os
import random
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

LAB_NET = ipaddress.ip_network("192.168.50.0/24")
MESSAGE = b"nids-lab thong diep vo hai\n"
LOG = Path(__file__).resolve().parents[1] / "data" / "run_logs" / "nhat_ky.jsonl"


def check_target(ip, allowed=LAB_NET):
    """Từ chối mọi đích ngoài mạng lab."""
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


def schedule(period, jitter, duration, rng):
    """Các thời điểm gửi (giây kể từ lúc bắt đầu): chu kỳ ``period`` lệch đều trong ±jitter."""
    t, out = rng.uniform(0, period), []
    while t < duration:
        out.append(t)
        t += period * (1 + rng.uniform(-jitter, jitter))
    return out


def tcp_send(ip, port, payload=MESSAGE, timeout=3.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(payload)
            s.settimeout(timeout)
            try:
                s.recv(1024)
            except OSError:
                pass
        return True
    except OSError:
        return False


def run_server(port, duration, proto="tcp"):
    """Máy nhận: trả lời "ok" cho mỗi kết nối TCP hoặc gói UDP; không xử lý nội dung."""
    stop = time.time() + duration
    if proto == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("0.0.0.0", port))
            s.settimeout(1.0)
            while time.time() < stop:
                try:
                    _, addr = s.recvfrom(2048)
                    s.sendto(b"ok\n", addr)
                except OSError:
                    continue
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(64)
        srv.settimeout(1.0)
        while time.time() < stop:
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(2.0)
                try:
                    conn.recv(65536)
                    conn.sendall(b"ok\n")
                except OSError:
                    pass


def run_periodic(target, port, period, jitter, duration, rng, dry):
    times = schedule(period, jitter, duration, rng)
    if dry:
        return {"so_lan_gui": len(times)}
    start, ok = time.time(), 0
    for t in times:
        time.sleep(max(0.0, start + t - time.time()))
        ok += tcp_send(target, port)
    return {"so_lan_gui": len(times), "so_lan_thanh_cong": ok}


def run_p2p(peers, port, period, jitter, duration, rng, dry):
    times = schedule(period, max(jitter, 0.3), duration, rng)
    if dry:
        return {"so_lan_gui": len(times)}
    listener = threading.Thread(target=run_server, args=(port, duration + 5, "udp"), daemon=True)
    listener.start()
    start = time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.5)
        for t in times:
            time.sleep(max(0.0, start + t - time.time()))
            s.sendto(MESSAGE, (rng.choice(peers), port))
            try:
                s.recvfrom(64)
            except OSError:
                pass
    return {"so_lan_gui": len(times)}


def run_bulk(peers, port, duration, rng, dry):
    """Chia sẻ dữ liệu theo đợt: mỗi đợt vài kết nối gửi khối 200 KB–2 MB, khoảng nghỉ ngẫu nhiên."""
    bursts = max(int(duration / 300), 1)
    starts = sorted(rng.uniform(0, duration) for _ in range(bursts))
    if dry:
        return {"so_dot": bursts}
    start = time.time()
    for t in starts:
        time.sleep(max(0.0, start + t - time.time()))
        for _ in range(rng.randint(3, 9)):
            tcp_send(rng.choice(peers), port, os.urandom(rng.randint(200_000, 2_000_000)), timeout=10.0)
    return {"so_dot": bursts}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sinh traffic topology vô hại trong lab cô lập.")
    sub = parser.add_subparsers(dest="kieu", required=True)
    p = sub.add_parser("may-chu", help="máy nhận / máy điều khiển mô phỏng")
    p.add_argument("--cong", type=int, required=True)
    p.add_argument("--udp", action="store_true")
    for name in ("tap-trung", "doi-chung-tap-trung"):
        p = sub.add_parser(name, help="gọi định kỳ tới một máy chủ" + (" (botnet tập trung)" if name == "tap-trung"
                                                                        else " (dịch vụ hợp lệ)"))
        p.add_argument("--may-chu", required=True)
        p.add_argument("--cong", type=int, required=True)
        p.add_argument("--chu-ky", type=float, default=30.0)
        p.add_argument("--jitter", type=float, default=0.0)
    for name in ("ngang-hang", "doi-chung-ngang-hang"):
        p = sub.add_parser(name, help="ngang hàng" + (" (botnet P2P)" if name == "ngang-hang" else " (chia sẻ lành tính)"))
        p.add_argument("--peer", action="append", required=True)
        p.add_argument("--cong", type=int, required=True)
        p.add_argument("--chu-ky", type=float, default=8.0)
        p.add_argument("--jitter", type=float, default=0.3)
    for p in sub.choices.values():
        p.add_argument("--thoi-gian", type=float, default=600.0, help="giây; kịch bản botnet tối thiểu 600 (B17, B18)")
        p.add_argument("--seed", type=int, default=None)
        p.add_argument("--ma-lan-chay", default=None)
        p.add_argument("--thu", action="store_true", help="chỉ in kế hoạch, không gửi")
    a = parser.parse_args(argv)
    rng = random.Random(a.seed)
    targets = [check_target(x) for x in ([a.may_chu] if hasattr(a, "may_chu") else getattr(a, "peer", []))]
    run_id = a.ma_lan_chay or f"{a.kieu}-{datetime.datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4]}"
    began = datetime.datetime.now().astimezone()
    if a.kieu == "may-chu":
        result = {} if a.thu else (run_server(a.cong, a.thoi_gian, "udp" if a.udp else "tcp") or {})
    elif a.kieu in ("tap-trung", "doi-chung-tap-trung"):
        result = run_periodic(targets[0], a.cong, a.chu_ky, a.jitter, a.thoi_gian, rng, a.thu)
    elif a.kieu == "ngang-hang":
        result = run_p2p(targets, a.cong, a.chu_ky, a.jitter, a.thoi_gian, rng, a.thu)
    else:
        result = run_bulk(targets, a.cong, a.thoi_gian, rng, a.thu)
    entry = {"ma_lan_chay": run_id, "hanh_vi": a.kieu,
             "topology": {"tap-trung": "centralized", "ngang-hang": "p2p"}.get(a.kieu, "none"),
             "bat_dau": began.isoformat(timespec="seconds"),
             "ket_thuc": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
             "ip_may_nay": local_ip(), "ip_dich": targets, "cong": a.cong,
             "tham_so": {k: v for k, v in vars(a).items() if k in ("chu_ky", "jitter", "thoi_gian", "seed", "udp")},
             "chi_thu": a.thu, **result}
    if a.thu:
        print(json.dumps(entry, ensure_ascii=False, indent=2))
    else:
        write_log(entry)
        print(f"Xong {run_id}; nhật ký: {LOG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

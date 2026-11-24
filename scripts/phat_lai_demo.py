"""Phát lại một bản thu lab đã lưu qua cảm biến realtime, ngay trên Windows (C12-T07, không cần WSL).

Cảm biến đọc PCAP theo nhịp thời gian thật nhân ``--toc-do`` (mặc định 10 lần), in cảnh báo khi phát ra, rồi so
với nhật ký lần chạy (đáp án) và mở dashboard HTML. Dùng cho buổi bảo vệ khi không chạy được lab ảo, và để trình
diễn botnet (mỗi lần chạy lab thật mất 12 phút, phát lại ×10 còn khoảng 70 giây).

    python scripts/phat_lai_demo.py bot5-p2p          # botnet năm bot ngang hàng
    python scripts/phat_lai_demo.py --danh-sach       # các bản thu có sẵn

PCAP lab không có trong git (lớn); cần thư mục ``data/pcap/lab/`` của máy đã chạy lab.
"""

import argparse
import csv
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHOICES = {
    "binh-thuong": ("k1-binh-thuong-test-12", "Bình thường: không được có cảnh báo tấn công"),
    "quet": ("k2-quet-nhanh-test-12", "Quét cổng Nmap từ .20 vào .30"),
    "dos": ("k3-dos-muc2-test-12", "DoS tải kết nối 60 giây từ .20 vào .30"),
    "ddos": ("x3-ddos-test-21", "DDoS năm nguồn vào .30"),
    "bot5-tap-trung": ("k6-tap-trung-test-12", "Năm bot .41-.45 gọi máy điều khiển .50"),
    "bot5-p2p": ("k6-p2p-test-12", "Năm bot .41-.45 gửi tin cho nhau (ngang hàng)"),
}


def epoch(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def summary(run, alerts_path):
    log = json.loads((ROOT / "data" / "run_logs" / f"{run}.json").read_text(encoding="utf-8"))
    rows = list(csv.DictReader(open(alerts_path, encoding="utf-8")))
    print(f"\nTổng kết: {len(rows)} cảnh báo")
    used = set()
    for b in log["hanh_vi"]:
        t0, t1 = b["bat_dau_epoch"], b["ket_thuc_epoch"]
        want = {"botnet": {"suspect_host"}, "dos": {"dos"}, "port_scan": {"port_scan"}}.get(b["nhan"], set())
        ips = set(b["ip_nguon"]) | (set(b["ip_dich"]) if b["nhan"] != "botnet" else set())
        hit = [r for r in rows if r["label"] in want and r["src_ip"] in ips and epoch(r["window_end"]) > t0
               and epoch(r["window_start"]) < t1 + 130]
        used.update(id(r) for r in hit)
        print(f"  Hành vi thật: {b['nhan']} ({b['kieu']}), nguồn {', '.join(b['ip_nguon'])}, dài {t1 - t0:.0f} s")
        if b["nhan"] == "benign":
            continue
        if hit:
            first = min(epoch(r["window_end"]) for r in hit)
            hosts = sorted({r["src_ip"] for r in hit})
            print(f"  => PHÁT HIỆN: {len(hit)} cảnh báo; máy bị báo: {', '.join(hosts)}; "
                  f"cửa sổ đúng đầu tiên kết thúc sau {first - t0:.1f} s")
            topo = {r["label"] for r in rows if r["label"] in ("centralized", "p2p") and r["src_ip"] in ips}
            if topo:
                print(f"     topology: {', '.join(sorted(topo))}")
        else:
            print("  => BỎ SÓT")
    fa = [r for r in rows if r["label"] in ("port_scan", "dos", "suspect_host") and id(r) not in used]
    print(f"  Cảnh báo tấn công ngoài hành vi (báo động giả): {len(fa)}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Phát lại bản thu lab qua cảm biến realtime.")
    ap.add_argument("chon", nargs="?", choices=list(CHOICES))
    ap.add_argument("--toc-do", type=float, default=10.0)
    ap.add_argument("--danh-sach", action="store_true")
    a = ap.parse_args(argv)
    if a.danh_sach or not a.chon:
        for k, (run, d) in CHOICES.items():
            ok = (ROOT / "data" / "pcap" / "lab" / f"{run}.pcap").exists()
            print(f"  {k:15s} {d}{'' if ok else '  (thiếu PCAP)'}")
        return 0
    run, desc = CHOICES[a.chon]
    pcap = ROOT / "data" / "pcap" / "lab" / f"{run}.pcap"
    if not pcap.exists():
        raise SystemExit(f"Thiếu {pcap}. PCAP lab không có trong git; chép từ máy đã chạy lab.")
    out = ROOT / "output" / "phat_lai" / run
    out.mkdir(parents=True, exist_ok=True)
    for f in out.glob("*"):
        f.unlink()
    print(f"=== Phát lại {run} ×{a.toc_do}: {desc} ===", flush=True)
    print("Cảm biến realtime (mô hình lab, config/lab.yaml) in cảnh báo khi phát ra:\n", flush=True)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    subprocess.run([sys.executable, "-W", "ignore", "-m", "nids.realtime", "--pcap", str(pcap), "--toc-do", str(a.toc_do),
                    "--net", "192.168.50.0/24", "--config", str(ROOT / "config" / "lab.yaml"), "--out", str(out),
                    "--ten", run], cwd=ROOT / "src", env=env, check=True)
    alerts = out / f"{run}.alerts.csv"
    summary(run, alerts)
    sys.stdout.flush()
    page = out / "dashboard.html"
    subprocess.run([sys.executable, "-W", "ignore", "-m", "nids.dashboard", str(alerts), "--out", str(page)],
                   cwd=ROOT / "src", env=env, check=True)
    if sys.platform == "win32":
        os.startfile(page)
    return 0


if __name__ == "__main__":
    sys.exit(main())

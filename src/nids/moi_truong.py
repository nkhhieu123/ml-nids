"""Kiểm tra môi trường trước khi chạy cảm biến realtime (C10-T01).

    python -m nids.moi_truong [--iface eth0] [--out output/moi_truong.json]

Kiểm tra: phiên bản Python, thư viện, hệ điều hành, quyền bắt gói (root hoặc CAP_NET_RAW), card mạng,
artifact của ba module (``nids.pipeline``), đồng bộ giờ (NTP), dung lượng đĩa cho thư mục ra. Mã thoát 0
nếu không có lỗi; cảnh báo không làm thất bại. Chi tiết ở docs/59_cai_dat_kali.md.
"""

import argparse
import importlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

OK, WARN, FAIL = "dat", "canh_bao", "loi"
MIN_PYTHON = (3, 10)          # khớp requires-python trong pyproject.toml
REQUIRED = ("numpy", "pandas", "sklearn", "scipy", "yaml", "joblib", "networkx")
OPTIONAL = ("matplotlib", "psutil")
CAP_NET_RAW = 13          # bit trong CapEff của /proc/self/status


def check_python(version=None):
    v = version or sys.version_info[:3]
    ok = tuple(v[:2]) >= MIN_PYTHON
    return (OK if ok else FAIL, f"Python {'.'.join(map(str, v))}" + ("" if ok else f", cần ≥ {MIN_PYTHON[0]}.{MIN_PYTHON[1]}"))


def check_packages(required=REQUIRED, optional=OPTIONAL):
    out = []
    for name, need in [(n, True) for n in required] + [(n, False) for n in optional]:
        try:
            mod = importlib.import_module(name)
            out.append((OK, f"{name} {getattr(mod, '__version__', '?')}"))
        except ImportError:
            out.append((FAIL if need else WARN, f"thiếu thư viện {name}" + ("" if need else " (tùy chọn)")))
    return out


def capabilities(status_text) -> int | None:
    """Giá trị CapEff (hex) trong nội dung /proc/self/status; None nếu không có."""
    for line in status_text.splitlines():
        if line.startswith("CapEff:"):
            return int(line.split()[1], 16)
    return None


def check_capture_permission(system=None, euid=None, status_text=None):
    """Bắt gói thô trên Linux cần root hoặc CAP_NET_RAW."""
    system = system or platform.system()
    if system != "Linux":
        return (WARN, f"hệ điều hành {system}: bắt gói trực tiếp (AF_PACKET) chỉ hỗ trợ Linux; vẫn chạy được từ file PCAP")
    euid = os.geteuid() if euid is None else euid
    if euid == 0:
        return (OK, "chạy bằng root")
    if status_text is None:
        try:
            status_text = Path("/proc/self/status").read_text()
        except OSError:
            status_text = ""
    cap = capabilities(status_text)
    if cap is not None and cap >> CAP_NET_RAW & 1:
        return (OK, "có CAP_NET_RAW")
    return (FAIL, "không có quyền bắt gói: chạy bằng sudo, hoặc cấp CAP_NET_RAW cho python của môi trường ảo "
                  "(xem docs/59 mục 4)")


def check_interface(iface, system=None, sys_net=Path("/sys/class/net")):
    system = system or platform.system()
    if not iface:
        return (WARN, "chưa chỉ định card mạng (capture.interface hoặc --iface)")
    if system != "Linux":
        return (WARN, f"không kiểm tra được card {iface} trên {system}")
    d = Path(sys_net) / iface
    if not d.exists():
        names = sorted(p.name for p in Path(sys_net).iterdir()) if Path(sys_net).exists() else []
        return (FAIL, f"không có card {iface}; card hiện có: {', '.join(names) or 'không đọc được'}")
    state = (d / "operstate").read_text().strip() if (d / "operstate").exists() else "?"
    return (OK if state in ("up", "unknown") else WARN, f"card {iface}: trạng thái {state}")


def check_ntp(system=None, run=subprocess.run):
    system = system or platform.system()
    if system != "Linux":
        return (WARN, "không kiểm tra NTP ngoài Linux")
    try:
        r = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return (WARN, "không chạy được timedatectl; kiểm tra đồng bộ giờ thủ công")
    return (OK, "đồng hồ đã đồng bộ NTP") if r.stdout.strip() == "yes" else \
        (WARN, "đồng hồ chưa đồng bộ NTP: ghép log, PCAP và nhật ký kịch bản sẽ lệch giờ (docs/Viec_con_thieu mục 3)")


def check_disk(path, min_free_gb=5.0):
    path = Path(path)
    probe = path if path.exists() else path.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    free = shutil.disk_usage(probe).free / 1e9
    return (OK if free >= min_free_gb else WARN, f"còn trống {free:.1f} GB tại {probe}")


def check_artifacts(cfg):
    try:
        from .pipeline import check_all
        rep = check_all(cfg)
    except Exception as exc:                       # thiếu file, nạp lỗi
        return [(FAIL, f"artifact: {exc}")]
    out = []
    for m, r in rep.items():
        if m == "hop_le":
            continue
        problems = r["van_de"]
        if not problems:
            out.append((OK, f"{m}: {r['loai']}, {r['so_dac_trung']} đặc trưng"))
        for p in problems:
            out.append((FAIL if p["muc"] == "loi" else WARN, f"{m}: {p['noi_dung']}"))
    return out


def run_checks(cfg, iface=None) -> dict:
    iface = iface or (cfg.get("capture") or {}).get("interface")
    out_dir = (cfg.get("paths") or {}).get("output_dir", "output")
    items = {"python": [check_python()], "thu_vien": check_packages(),
             "he_dieu_hanh": [(OK, f"{platform.system()} {platform.release()}")],
             "quyen_bat_goi": [check_capture_permission()], "card_mang": [check_interface(iface)],
             "artifact": check_artifacts(cfg), "dong_bo_gio": [check_ntp()], "dia": [check_disk(out_dir)]}
    rep = {k: [{"muc": lv, "noi_dung": msg} for lv, msg in v] for k, v in items.items()}
    rep["hop_le"] = all(i["muc"] != FAIL for v in rep.values() if isinstance(v, list) for i in v)
    return rep


def main(argv=None):
    from .config import load_config

    ap = argparse.ArgumentParser(description="Kiểm tra môi trường trước khi chạy cảm biến.")
    ap.add_argument("--iface", help="card mạng giám sát, mặc định capture.interface")
    ap.add_argument("--out", help="ghi báo cáo JSON")
    ap.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    a = ap.parse_args(argv)
    rep = run_checks(load_config(a.config), a.iface)
    mark = {OK: "đạt ", WARN: "chú ý", FAIL: "LỖI "}
    for k, items in rep.items():
        if k == "hop_le":
            continue
        for i in items:
            print(f"[{mark[i['muc']]}] {k}: {i['noi_dung']}")
    print("Sẵn sàng chạy:" , "có" if rep["hop_le"] else "chưa")
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if rep["hop_le"] else 1


if __name__ == "__main__":
    sys.exit(main())

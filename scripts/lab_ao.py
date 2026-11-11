"""Lab ảo 7 node bằng network namespace của Linux, và bộ chạy kịch bản Chặng 11 (C11-T01..T07).

Mỗi "máy" của lab (docs/09) là một network namespace có ngăn xếp TCP/IP riêng của nhân Linux, nối vào một
bridge đóng vai switch. Máy giám sát 192.168.50.10 **không** cắm vào switch: nó chỉ nhận bản sao mọi khung đi
vào từng cổng switch (tc mirred), giống cổng mirror/SPAN (B13). Bridge không có địa chỉ IP và không có đường
ra ngoài, nên lab cô lập (B24). Chạy bằng root trên Linux (đã thử trên WSL2 Ubuntu).

    python3 scripts/lab_ao.py dung --lab 1            # dựng lab số 1
    python3 scripts/lab_ao.py kiem-tra --lab 1        # bắt thử, để nids.cam_bien xác nhận thấy hai chiều
    python3 scripts/lab_ao.py chay --lab 1 --bien-the k3-dos-muc2 --vai-tro test --lan 01
    python3 scripts/lab_ao.py go --lab 1              # gỡ lab

Nhiều lab (``--lab 1``, ``--lab 2``...) chạy song song được: mỗi lab có bridge và namespace riêng nên cùng dải
192.168.50.0/24 mà không thấy nhau.

Lệnh ``chay`` làm một lần chạy theo docs/09: bật máy chủ dịch vụ (Nginx, access log định dạng ``nids``), bắt
gói bằng tcpdump trên máy giám sát, sinh traffic bình thường làm nền, chạy hành vi của biến thể tại thời điểm
lấy ngẫu nhiên theo seed (lịch mỗi lần khác nhau, B19), rồi ghi **nhật ký lần chạy** — ground truth độc lập với
dự đoán (B10): script này không đọc bất kỳ kết quả nào của mô hình.

AN TOÀN (B24): mọi traffic do scripts/sinh_traffic.py, scripts/sinh_topology.py (vô hại, từ chối đích ngoài
lab) và Nmap connect scan tới máy chủ dịch vụ của lab sinh ra; tải kết nối bị chặn cứng ở 60 giây.
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import random
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
WORK = Path(os.environ.get("NIDS_LAB_WORK", "/root/nids_lab"))   # ghi PCAP trên đĩa Linux, xong mới chép về
NET = "192.168.50"
MONITOR, TESTER, SERVER, CC = 10, 20, 30, 50
CLIENTS = (41, 42, 43)
HOSTS = (MONITOR, TESTER, SERVER, *CLIENTS, CC)
VARIANTS = ("k1-binh-thuong", "k2-quet-cham", "k2-quet-nhanh", "k3-dos-muc1", "k3-dos-muc2", "k3-dos-muc3",
            "k4-co-dinh", "k4-bien-thien", "k4-doi-chung", "k5-p2p", "k5-doi-chung")
WEB_FILES = {"index.html": "<html><body><h1>nids-lab</h1><a href=about.html>about</a></body></html>\n" * 20,
             "about.html": "<html><body>May chu dich vu cua lab.</body></html>\n" * 40,
             "assets/app.css": "body{font-family:sans-serif}\n" * 300,
             "assets/app.js": "console.log('nids-lab');\n" * 600,
             "api/status": '{"status":"ok"}\n'}
NGINX_CONF = """user root;
worker_processes 2;
pid {work}/nginx.pid;
error_log {work}/nginx_error.log;
events {{ worker_connections 4096; }}
http {{
    default_type text/plain;
    log_format nids '$msec $remote_addr $remote_port $server_port '
                    '"$request" $status $body_bytes_sent $request_length '
                    '$request_time $connection $connection_requests '
                    '"$http_user_agent"';
    access_log {work}/access_nids.log nids;
    server {{ listen 80; root {work}/www; }}
}}
"""


def ip(h):
    return f"{NET}.{h}"


def ns(lab, h):
    return f"nl{lab}h{h}"


def port(lab, h):
    return f"nl{lab}v{h}"


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def in_ns(lab, h, *cmd):
    return ["ip", "netns", "exec", ns(lab, h), *cmd]


def iso(t):
    return datetime.datetime.fromtimestamp(t).astimezone().isoformat(timespec="milliseconds")


# ---------------------------------------------------------------- dựng và gỡ lab

def tear_down(lab):
    for h in HOSTS:
        sh("ip", "netns", "pids", ns(lab, h), check=False)
        pids = sh("ip", "netns", "pids", ns(lab, h), check=False).stdout.split()
        for p in pids:
            sh("kill", "-9", p, check=False)
        sh("ip", "link", "del", port(lab, h), check=False)
        sh("ip", "netns", "del", ns(lab, h), check=False)
    sh("ip", "link", "del", f"nlb{lab}", check=False)


def build(lab):
    tear_down(lab)
    for m in ("act_mirred", "sch_ingress", "cls_matchall"):
        sh("modprobe", m, check=False)
    br = f"nlb{lab}"
    sh("ip", "link", "add", br, "type", "bridge")
    sh("sysctl", "-qw", f"net.ipv6.conf.{br}.disable_ipv6=1", check=False)
    sh("ip", "link", "set", br, "up")
    for h in HOSTS:
        n, p = ns(lab, h), port(lab, h)
        sh("ip", "netns", "add", n)
        sh("ip", "link", "add", p, "type", "veth", "peer", "name", "eth0", "netns", n)
        sh("ip", "-n", n, "addr", "add", f"{ip(h)}/24", "dev", "eth0")
        sh("ip", "-n", n, "link", "set", "lo", "up")
        sh("ip", "-n", n, "link", "set", "eth0", "up")
        sh("ip", "link", "set", p, "up")
        # Tắt gộp/tách gói và tính checksum hộ của card ảo để gói bắt được giống gói trên dây thật.
        off = ("rx", "off", "tx", "off", "sg", "off", "tso", "off", "gso", "off", "gro", "off")
        sh("ethtool", "-K", p, *off, check=False)
        sh(*in_ns(lab, h, "ethtool", "-K", "eth0", *off), check=False)
        if h != MONITOR:
            sh("ip", "link", "set", p, "master", br)
    for h in HOSTS:
        if h != MONITOR:      # cổng mirror: sao mọi khung đi vào switch từ máy h sang máy giám sát, đúng một lần
            sh("tc", "qdisc", "add", "dev", port(lab, h), "clsact")
            sh("tc", "filter", "add", "dev", port(lab, h), "ingress", "matchall",
               "action", "mirred", "egress", "mirror", "dev", port(lab, MONITOR))
    print(f"Đã dựng lab {lab}: bridge {br}, {len(HOSTS)} máy {ip(HOSTS[0])}–{ip(HOSTS[-1])}, mirror -> {ip(MONITOR)}")


# ---------------------------------------------------------------- bắt gói và máy chủ dịch vụ

class Capture:
    """tcpdump trên máy giám sát; khi dừng đọc số gói bắt được và số gói nhân bỏ."""

    def __init__(self, lab, pcap):
        self.pcap = pcap
        self.err = open(str(pcap) + ".tcpdump.txt", "w+")
        self.proc = subprocess.Popen(in_ns(lab, MONITOR, "tcpdump", "-i", "eth0", "-n", "-s", "0", "-B", "65536",
                                           "-w", str(pcap)), stderr=self.err, stdout=subprocess.DEVNULL)
        for _ in range(100):                     # chờ tcpdump mở xong card rồi mới sinh traffic
            time.sleep(0.2)
            self.err.seek(0)
            if "listening on" in self.err.read():
                break
        else:
            raise SystemExit("tcpdump không khởi động được")
        time.sleep(1.0)
        self.start = time.time()

    def stop(self):
        time.sleep(2.0)
        self.end = time.time()
        self.proc.send_signal(signal.SIGINT)
        self.proc.wait(timeout=30)
        self.err.seek(0)
        text = self.err.read()
        self.err.close()
        num = lambda pat: int(m.group(1)) if (m := re.search(r"(\d+) packets? " + pat, text)) else None
        return {"goi_bat_duoc": num("captured"), "goi_qua_bo_loc": num("received by filter"),
                "goi_nhan_bo": num("dropped by kernel")}


def start_nginx(lab, work):
    www = work / "www"
    for name, body in WEB_FILES.items():
        (www / name).parent.mkdir(parents=True, exist_ok=True)
        (www / name).write_text(body)
    conf = work / "nginx.conf"
    conf.write_text(NGINX_CONF.format(work=work))
    sh(*in_ns(lab, SERVER, "nginx", "-c", str(conf)))


def stop_nginx(lab, work):
    sh(*in_ns(lab, SERVER, "nginx", "-c", str(work / "nginx.conf"), "-s", "quit"), check=False)


def py(script, *args):
    return [sys.executable, str(SCRIPTS / script), *map(str, args)]


def benign(duration, seed):
    return py("sinh_traffic.py", "binh-thuong", "--may-chu", ip(SERVER), "--cong", 80, "--thoi-gian", int(duration),
              "--vai-tro", "test", "--lan", "nen", "--seed", seed)


# ---------------------------------------------------------------- kế hoạch từng biến thể

def plan(variant, lan, rng):
    """Kế hoạch một lần chạy: thời lượng bản thu, máy nhận, nền, và các hành vi (đều chốt trước khi chạy).

    Mỗi hành vi: kiểu, nhãn, máy nguồn, máy đích, thời điểm bắt đầu (giây từ đầu bản thu), lệnh trên từng máy
    nguồn, tham số. ``lan`` (1, 2, 3...) đổi chu kỳ/danh sách peer; seed đổi thời điểm bắt đầu (B19).
    """
    k = (lan - 1) % 3
    p = {"thoi_luong_s": 600, "duoi_s": rng.uniform(60, 120), "may_nhan": [], "nen": list(CLIENTS), "hanh_vi": []}
    if variant == "k1-binh-thuong":
        pass                                    # chỉ có nền: ba client duyệt web + kiểm tra trạng thái định kỳ
    elif variant.startswith("k2-quet"):
        slow = variant.endswith("cham")
        cmd = ["nmap", "-sT", "-Pn", "-n", "-p", "1-1024", "--max-retries", "0",
               *(("--scan-delay", "500ms") if slow else ("-T4",)), ip(SERVER)]
        p["hanh_vi"].append({"kieu": "quet", "nhan": "port_scan", "nguon": [TESTER], "dich": [SERVER],
                             "bat_dau_sau_s": rng.uniform(90, 150) if slow else rng.uniform(120, 360),
                             "lenh": {TESTER: cmd},
                             "tham_so": {"cong_cu": "nmap -sT", "cong_dau": 1, "cong_cuoi": 1024,
                                         "gian_cach_s": 0.5 if slow else 0.0, "toc_do": "cham" if slow else "nhanh"}})
    elif variant.startswith("k3-dos-muc"):
        muc = int(variant[-1])
        p["thoi_luong_s"] = 300
        p["hanh_vi"].append({"kieu": "tai-ket-noi", "nhan": "dos", "nguon": [TESTER], "dich": [SERVER],
                             "bat_dau_sau_s": rng.uniform(90, 150),
                             "lenh": {TESTER: py("sinh_traffic.py", "tai-ket-noi", "--may-chu", ip(SERVER), "--cong", 80,
                                                 "--muc", muc, "--thoi-gian", 60, "--vai-tro", "test", "--lan", lan)},
                             "tham_so": {"cong": 80, "muc": muc, "thoi_gian_s": 60}})
    elif variant.startswith("k4-"):
        chu_ky = (30, 60, 45)[k]
        jitter = {"k4-co-dinh": (0, 0, 0), "k4-bien-thien": (0.2, 0.4, 0.3), "k4-doi-chung": (0, 0.1, 0.3)}[variant][k]
        bot = variant != "k4-doi-chung"
        dich, cong = (CC, 8080) if bot else (SERVER, 80)
        kieu = "tap-trung" if bot else "doi-chung-tap-trung"
        p["thoi_luong_s"], p["nen"] = 700, [TESTER, *CLIENTS]
        if bot:
            p["may_nhan"].append((CC, py("sinh_topology.py", "may-chu", "--cong", cong, "--thoi-gian", 3600)))
        p["hanh_vi"].append({"kieu": kieu, "nhan": "botnet" if bot else "benign", "nguon": list(CLIENTS), "dich": [dich],
                             "bat_dau_sau_s": rng.uniform(30, 60),
                             "lenh": {h: py("sinh_topology.py", kieu, "--may-chu", ip(dich), "--cong", cong,
                                            "--chu-ky", chu_ky, "--jitter", jitter, "--thoi-gian", 600,
                                            "--seed", rng.randrange(10**6)) for h in CLIENTS},
                             "tham_so": {"cong": cong, "chu_ky_s": chu_ky, "jitter": jitter, "thoi_gian_s": 600,
                                         "topology": "centralized" if bot else "none"}})
    elif variant.startswith("k5-"):
        bot = variant == "k5-p2p"
        p["thoi_luong_s"], p["nen"] = 700, [TESTER, *CLIENTS]
        # danh sách peer đổi giữa các lần: lưới đầy đủ / vòng / lưới đầy đủ
        peers = {h: [x for x in CLIENTS if x != h] if k != 1 else [CLIENTS[(CLIENTS.index(h) + 1) % 3]] for h in CLIENTS}
        if bot:
            chu_ky, jitter, cong = (8, 20, 30)[k], (0.3, 0.5, 0.4)[k], 40000
            lenh = {h: py("sinh_topology.py", "ngang-hang", *sum((["--peer", ip(x)] for x in peers[h]), []),
                          "--cong", cong, "--chu-ky", chu_ky, "--jitter", jitter, "--thoi-gian", 600,
                          "--seed", rng.randrange(10**6)) for h in CLIENTS}
            tham_so = {"cong": cong, "giao_thuc": "udp", "chu_ky_s": chu_ky, "jitter": jitter, "topology": "p2p"}
        else:
            cong = 6881
            p["may_nhan"] += [(h, py("sinh_topology.py", "may-chu", "--cong", cong, "--thoi-gian", 3600)) for h in CLIENTS]
            lenh = {h: py("sinh_topology.py", "doi-chung-ngang-hang", *sum((["--peer", ip(x)] for x in peers[h]), []),
                          "--cong", cong, "--thoi-gian", 600, "--seed", rng.randrange(10**6)) for h in CLIENTS}
            tham_so = {"cong": cong, "giao_thuc": "tcp", "topology": "none"}
        tham_so.update(thoi_gian_s=600, peer={ip(h): [ip(x) for x in v] for h, v in peers.items()})
        p["hanh_vi"].append({"kieu": "ngang-hang" if bot else "doi-chung-ngang-hang", "nhan": "botnet" if bot else "benign",
                             "nguon": list(CLIENTS), "dich": list(CLIENTS), "bat_dau_sau_s": rng.uniform(30, 60),
                             "lenh": lenh, "tham_so": tham_so})
    else:
        raise SystemExit(f"Biến thể lạ: {variant}")
    return p


# ---------------------------------------------------------------- một lần chạy

def run(lab, variant, role, lan, seed=None, out_root=ROOT, scale=1.0):
    run_id = f"{variant}-{role}-{lan:02d}"
    seed = zlib.crc32(run_id.encode()) if seed is None else seed
    rng = random.Random(seed)
    p = plan(variant, lan, rng)
    if scale != 1.0:                            # chỉ để thử nhanh script; lần chạy thật giữ scale = 1
        p["thoi_luong_s"] *= scale
        p["duoi_s"] *= scale
        for b in p["hanh_vi"]:
            b["bat_dau_sau_s"] *= scale
    work = WORK / run_id
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    env = {**os.environ, "NIDS_NHAT_KY": str(work / "may_sinh.jsonl")}
    spawn = lambda h, cmd: subprocess.Popen(in_ns(lab, h, *cmd), env=env, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL)
    start_nginx(lab, work)
    helpers = [spawn(h, cmd) for h, cmd in p["may_nhan"]]
    cap = Capture(lab, work / f"{run_id}.pcap")
    bg_start = time.time()
    helpers += [spawn(h, benign(86400, rng.randrange(10**6))) for h in p["nen"]]
    done = []

    def behave(b):
        time.sleep(max(0.0, cap.start + b["bat_dau_sau_s"] - time.time()))
        t0 = time.time()
        procs = [spawn(h, cmd) for h, cmd in b["lenh"].items()]
        codes = [q.wait() for q in procs]
        done.append({"kieu": b["kieu"], "nhan": b["nhan"], "bat_dau": iso(t0), "ket_thuc": iso(time.time()),
                     "bat_dau_epoch": round(t0, 3), "ket_thuc_epoch": round(time.time(), 3),
                     "ip_nguon": [ip(h) for h in b["nguon"]], "ip_dich": [ip(h) for h in b["dich"]],
                     "tham_so": b["tham_so"], "lenh": {ip(h): " ".join(map(str, c)) for h, c in b["lenh"].items()},
                     "ma_thoat": codes})

    threads = [threading.Thread(target=behave, args=(b,)) for b in p["hanh_vi"]]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Bản thu kéo dài tới hết thời lượng đã định, và luôn còn một đoạn bình thường sau hành vi.
    last = max((d["ket_thuc_epoch"] for d in done), default=cap.start)
    time.sleep(max(0.0, max(cap.start + p["thoi_luong_s"], last + (p["duoi_s"] if done else 0)) - time.time()))
    bg_end = time.time()
    for q in helpers:
        q.terminate()
    for q in helpers:
        q.wait()
    stats = cap.stop()
    stop_nginx(lab, work)
    if not stats["goi_bat_duoc"]:
        raise SystemExit(f"{run_id}: bản thu rỗng ({stats}); kiểm tra mirror bằng lệnh kiem-tra")

    pcap = work / f"{run_id}.pcap"
    gen = work / "may_sinh.jsonl"
    log = {
        "ma_lan_chay": run_id, "bien_the": variant, "vai_tro": role, "lan": lan, "seed": seed,
        "moi_truong": {"kieu": "lab ảo: network namespace + bridge + tc mirror", "lab": lab,
                       "nhan": platform.release(), "may": platform.node(),
                       "nmap": sh("nmap", "--version").stdout.splitlines()[0] if shutil.which("nmap") else None},
        "ban_thu": {"file": f"data/pcap/lab/{run_id}.pcap", "bat_dau": iso(cap.start), "ket_thuc": iso(cap.end),
                    "bat_dau_epoch": round(cap.start, 3), "ket_thuc_epoch": round(cap.end, 3),
                    "may_giam_sat": ip(MONITOR), "byte": pcap.stat().st_size,
                    "sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(), **stats},
        # Mọi máy của lab ảo dùng chung đồng hồ của một nhân Linux nên không lệch.
        "lech_dong_ho_s": 0.0,
        "nen": {"kieu": "binh-thuong", "nhan": "benign", "ip_nguon": [ip(h) for h in p["nen"]], "ip_dich": [ip(SERVER)],
                "bat_dau": iso(bg_start), "ket_thuc": iso(bg_end),
                "mo_ta": "duyệt web nghỉ 1–6 giây, kiểm tra trạng thái api/status mỗi ~30 giây"},
        "hanh_vi": sorted(done, key=lambda d: d["bat_dau_epoch"]),
        "nhat_ky_may_sinh": [json.loads(l) for l in gen.read_text(encoding="utf-8").splitlines()] if gen.exists() else [],
    }
    for sub in ("data/pcap/lab", "data/run_logs", f"data/service_logs/{run_id}"):
        (out_root / sub).mkdir(parents=True, exist_ok=True)
    shutil.copy(pcap, out_root / "data/pcap/lab" / pcap.name)
    shutil.copy(work / "access_nids.log", out_root / "data/service_logs" / run_id / "access_nids.log")
    (out_root / "data/run_logs" / f"{run_id}.json").write_text(json.dumps(log, ensure_ascii=False, indent=2),
                                                               encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)
    print(f"Xong {run_id}: {stats['goi_bat_duoc']} gói, nhân bỏ {stats['goi_nhan_bo']}, "
          f"{len(done)} hành vi; nhật ký data/run_logs/{run_id}.json", flush=True)
    return log


def mirror_check(lab, out_root=ROOT):
    """Bắt thử vài kết nối giữa các máy để nids.cam_bien xác nhận máy giám sát thấy cả hai chiều (B13)."""
    work = WORK / f"kiem-tra-mirror-{lab}"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    start_nginx(lab, work)
    cap = Capture(lab, work / "kiem_tra_mirror.pcap")
    env = {**os.environ, "NIDS_NHAT_KY": str(work / "may_sinh.jsonl")}
    for h in (TESTER, *CLIENTS, CC):
        sh(*in_ns(lab, h, "ping", "-c", "3", "-i", "0.2", ip(SERVER)), check=False)
        subprocess.run(in_ns(lab, h, *benign(15, h)), env=env, capture_output=True)
    stats = cap.stop()
    stop_nginx(lab, work)
    dst = out_root / "data/pcap/lab"
    dst.mkdir(parents=True, exist_ok=True)
    shutil.copy(work / "kiem_tra_mirror.pcap", dst / "kiem_tra_mirror.pcap")
    shutil.rmtree(work, ignore_errors=True)
    print(f"Đã bắt thử: {stats}; file data/pcap/lab/kiem_tra_mirror.pcap")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Lab ảo 7 node và bộ chạy kịch bản Chặng 11.")
    sub = ap.add_subparsers(dest="lenh", required=True)
    for name in ("dung", "go", "kiem-tra", "chay"):
        sub.add_parser(name).add_argument("--lab", type=int, default=1, help="số thứ tự lab (chạy song song nhiều lab)")
    c = sub.choices["chay"]
    c.add_argument("--bien-the", required=True, choices=VARIANTS)
    c.add_argument("--vai-tro", required=True, choices=("train", "val", "test"), help="ghi trước khi chạy (B11, B19)")
    c.add_argument("--lan", type=int, nargs="+", default=[1], help="số thứ tự lần chạy; nhiều số thì chạy lần lượt")
    c.add_argument("--seed", type=int, help="mặc định suy từ mã lần chạy")
    c.add_argument("--ti-le", type=float, default=1.0, help="co thời gian để thử nhanh script; lần thật để 1")
    a = ap.parse_args(argv)
    if a.lenh != "go" and (not sys.platform.startswith("linux") or os.geteuid() != 0):
        raise SystemExit("Cần chạy bằng root trên Linux (network namespace, tc, tcpdump).")
    if a.lenh == "dung":
        build(a.lab)
    elif a.lenh == "go":
        tear_down(a.lab)
    elif a.lenh == "kiem-tra":
        mirror_check(a.lab)
    else:
        for lan in a.lan:
            run(a.lab, a.bien_the, a.vai_tro, lan, a.seed, scale=a.ti_le)
    return 0


if __name__ == "__main__":
    sys.exit(main())

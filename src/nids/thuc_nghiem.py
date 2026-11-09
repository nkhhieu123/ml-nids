"""Chặng 11 — kiểm thử thực nghiệm: đo độ trễ phát hiện, bỏ sót, báo động giả và hiệu năng (C11-T08).

Chạy pipeline trên một PCAP kịch bản, lấy ground truth từ lịch nhãn (hoặc nhật ký lần chạy lab), rồi so:

- **Phát hiện / bỏ sót**: mỗi đợt tấn công (loại, host, khoảng thời gian) có ít nhất một cảnh báo đúng
  loại trên host của nó trong khoảng đó không. Không có = **bỏ sót** (nghiệm thu B20).
- **Độ trễ phát hiện**: cuối cửa sổ của cảnh báo đầu tiên − thời điểm bắt đầu đợt tấn công. Dùng cuối cửa
  sổ nên **đã gồm thời gian tích lũy cửa sổ** (nghiệm thu: độ trễ bao gồm thời gian tích lũy cửa sổ).
- **Báo động giả**: sự kiện cảnh báo không giải thích được bằng đợt tấn công nào (host/thời gian), quy ra
  số sự kiện mỗi giờ.
- **Hiệu năng**: thời gian trích xuất và chấm, số gói mỗi giây (từ pipeline).

Đây là **bộ đo** của Chặng 11; chạy trên các đoạn CIC (quét, DoS, bình thường) và dữ liệu mô phỏng để
kiểm chứng logic. Kết quả cuối phải đo trên **PCAP lab thật** (docs/09); khi có, chạy cùng lệnh này.

    cd src
    python -m nids.thuc_nghiem ../output/pcap/fri_quet.pcap --net 192.168.10.0/24 --net 172.16.0.0/24 \
        --out ../docs/hinh/thuc_nghiem
"""

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from .scope import MODULE_ATTACK, MODULE_BOTNET

# loại tấn công -> (module chịu trách nhiệm, các nhãn tính là phát hiện đúng loại)
DETECT = {
    "dos": (MODULE_ATTACK, {"dos"}),
    "port_scan": (MODULE_ATTACK, {"port_scan"}),
    "botnet": (MODULE_BOTNET, {"suspect_host"}),
}


@dataclass(frozen=True)
class Attack:
    kich_ban: str          # mã đợt (id rule hoặc mã lần chạy lab)
    loai: str              # dos / port_scan / botnet
    hosts: frozenset       # host nội bộ liên quan (bên tấn công và/hoặc nạn nhân được lập cửa sổ)
    t0: float              # thời điểm bắt đầu đợt (trong đoạn), giây
    t1: float              # thời điểm kết thúc


def _in_nets(ip, networks) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n) for n in networks)


def attacks_from_rules(rules, t0, t1, networks) -> list:
    """Ground truth từ lịch nhãn: các rule chồng [t0, t1], ánh xạ sang loại tấn công có thể phát hiện.

    dos/port_scan giữ nguyên; ``loai`` + nhãn gốc chứa ``Bot`` -> botnet; DDoS/Heartbleed bỏ (chỉ anomaly).
    Host của đợt = (bên tấn công ∪ nạn nhân) nằm trong mạng giám sát (host ngoài không được lập cửa sổ).
    """
    out = []
    for r in rules:
        if r.end_s <= t0 or r.start_s >= t1:
            continue
        if r.label in ("dos", "port_scan"):
            loai = r.label
        elif r.label == "loai" and "Bot" in (r.original or ""):
            loai = "botnet"
        else:
            continue
        hosts = frozenset(h for h in (set(r.attackers) | set(r.victims)) if _in_nets(h, networks))
        if hosts:
            out.append(Attack(r.id, loai, hosts, max(r.start_s, t0), min(r.end_s, t1)))
    return out


def attacks_from_runlog(logs, networks) -> list:
    """Ground truth từ nhật ký lần chạy lab (sinh_traffic.py / sinh_topology.py)."""
    out = []
    kind = {"tai-ket-noi": "dos", "quet": "port_scan", "tap-trung": "botnet", "ngang-hang": "botnet"}
    import datetime as _dt
    for g in logs:
        loai = kind.get(g.get("kieu")) or {"dos": "dos", "port_scan": "port_scan"}.get(g.get("nhan"))
        if loai is None:
            continue
        hosts = frozenset(h for h in ([g["ip_nguon"]] if "ip_nguon" in g else g.get("ip_tham_gia", []))
                          if _in_nets(h, networks))
        t0 = _dt.datetime.fromisoformat(g["bat_dau"]).timestamp()
        t1 = _dt.datetime.fromisoformat(g["ket_thuc"]).timestamp()
        if hosts:
            out.append(Attack(g["ma_lan_chay"], loai, hosts, t0, t1))
    return out


def detect(attacks, alerts) -> dict:
    """Phát hiện/bỏ sót và độ trễ cho mỗi đợt; tập cảnh báo đã giải thích (để tính báo động giả)."""
    rows = []
    for a in attacks:
        mod, labels = DETECT[a.loai]
        hits = [al for al in alerts if al.is_alert and al.module == mod and al.label in labels
                and al.src_ip in a.hosts and al.window_end > a.t0 and al.window_start < a.t1]
        row = {"kich_ban": a.kich_ban, "loai": a.loai, "host": sorted(a.hosts),
               "bat_dau": round(a.t0, 1), "so_canh_bao": len(hits)}
        if hits:
            row["phat_hien"] = True
            row["do_tre_s"] = round(min(al.window_end for al in hits) - a.t0, 1)
        else:
            row["phat_hien"] = False
            row["do_tre_s"] = None
        rows.append(row)
    return {"theo_dot": rows,
            "so_dot": len(attacks),
            "phat_hien": sum(r["phat_hien"] for r in rows),
            "bo_sot": sum(not r["phat_hien"] for r in rows)}


def false_alarms(events, attacks, hours) -> dict:
    """Sự kiện cảnh báo không giải thích được bằng đợt tấn công nào (cùng host, chồng thời gian)."""
    fa = []
    for e in events:
        host = e["src_ip"]
        covered = any(host in a.hosts and e["ket_thuc"] > a.t0 and e["bat_dau"] < a.t1 for a in attacks)
        if not covered:
            fa.append({"module": e["module"], "nhan": e["label"], "host": host,
                       "bat_dau": round(e["bat_dau"], 1), "thoi_luong_s": e.get("thoi_luong_s")})
    theo_module = {}
    for e in fa:
        theo_module[e["module"]] = theo_module.get(e["module"], 0) + 1
    return {"so_su_kien_bao_gia": len(fa), "moi_gio": round(len(fa) / hours, 2) if hours else None,
            "theo_module": theo_module, "chi_tiet": fa[:20]}


def latency_summary(rows) -> dict:
    vals = sorted(r["do_tre_s"] for r in rows if r["phat_hien"] and r["do_tre_s"] is not None)
    if not vals:
        return {"so_mau": 0}
    pct = lambda p: vals[min(len(vals) - 1, int(p * len(vals)))]
    return {"so_mau": len(vals), "nho_nhat": vals[0], "trung_vi": pct(0.5), "p95": pct(0.95), "lon_nhat": vals[-1]}


def run_scenario(pcap, networks, cfg=None, mode="ket_hop", name=None, rules=None, runlog=None) -> dict:
    """Chạy pipeline trên một PCAP, dựng ground truth, trả về chỉ số Chặng 11."""
    import tempfile

    import pandas as pd

    from .labeling import load_schedule
    from .pipeline import load_windows, merge_events, run_alerts, run_pcap

    with tempfile.TemporaryDirectory() as d:
        run = run_pcap(pcap, d, networks, cfg, mode=mode, name=name)
        alerts = run_alerts(run, run["artifact"])
        events = [_event_dict(e) for e in merge_events(alerts)]
        win = load_windows(run["prefix"])
    t0, t1 = float(win["window_start"].min()), float(win["window_end"].max())
    hours = (t1 - t0) / 3600
    if runlog is not None:
        attacks = attacks_from_runlog(runlog, networks)
    else:
        attacks = attacks_from_rules(rules if rules is not None else load_schedule(), t0, t1, networks)
    det = detect(attacks, alerts)
    perf = {"goi": run["so_luong"].get("flow"), "cua_so": run["so_luong"]["cua_so"],
            "thoi_gian_s": {k: round(v, 2) for k, v in run["thoi_gian_s"].items()}}
    return {"pcap": Path(pcap).name, "che_do": mode, "khoang_giay": round(t1 - t0, 1), "gio": round(hours, 3),
            "phat_hien": det, "do_tre": latency_summary(det["theo_dot"]),
            "bao_gia": false_alarms(events, attacks, hours), "hieu_nang": perf}


def _event_dict(e):
    return {"module": e["module"], "label": e["label"], "src_ip": e["src_ip"],
            "bat_dau": e["bat_dau"], "ket_thuc": e["ket_thuc"], "thoi_luong_s": e.get("thoi_luong_s")}


def summarize(scenarios) -> dict:
    tong = {"so_dot": 0, "phat_hien": 0, "bo_sot": 0, "bao_gia": 0}
    for s in scenarios:
        tong["so_dot"] += s["phat_hien"]["so_dot"]
        tong["phat_hien"] += s["phat_hien"]["phat_hien"]
        tong["bo_sot"] += s["phat_hien"]["bo_sot"]
        tong["bao_gia"] += s["bao_gia"]["so_su_kien_bao_gia"]
    tong["ty_le_phat_hien"] = round(tong["phat_hien"] / tong["so_dot"], 3) if tong["so_dot"] else None
    return tong


def main(argv=None):
    from .config import load_config

    parser = argparse.ArgumentParser(description="Chặng 11: đo độ trễ, bỏ sót, báo động giả, hiệu năng.")
    parser.add_argument("pcap", nargs="+", help="PCAP kịch bản (CIC hoặc lab)")
    parser.add_argument("--net", action="append", required=True, help="dải mạng giám sát; lặp lại được")
    parser.add_argument("--che-do", default="ket_hop", choices=("doc_lap", "tuan_tu", "ket_hop"))
    parser.add_argument("--nhat-ky", help="nhật ký lần chạy lab (JSONL) làm ground truth thay cho lịch nhãn")
    parser.add_argument("--config", help="file cấu hình")
    parser.add_argument("--out", help="thư mục ghi JSON kết quả")
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    runlog = None
    if args.nhat_ky:
        runlog = [json.loads(l) for l in Path(args.nhat_ky).read_text(encoding="utf-8").splitlines() if l.strip()]
    scenarios = [run_scenario(p, args.net, cfg, args.che_do, runlog=runlog) for p in args.pcap]
    out = {"kich_ban": scenarios, "tong_hop": summarize(scenarios)}
    for s in scenarios:
        d = s["phat_hien"]
        print(f"{s['pcap']}: {d['phat_hien']}/{d['so_dot']} đợt phát hiện, bỏ sót {d['bo_sot']}; "
              f"độ trễ trung vị {s['do_tre'].get('trung_vi')}s; báo giả {s['bao_gia']['so_su_kien_bao_gia']} "
              f"({s['bao_gia']['moi_gio']}/giờ)")
    print("Tổng:", out["tong_hop"])
    if args.out:
        od = Path(args.out)
        od.mkdir(parents=True, exist_ok=True)
        (od / "thuc_nghiem.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Đã ghi: {od / 'thuc_nghiem.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

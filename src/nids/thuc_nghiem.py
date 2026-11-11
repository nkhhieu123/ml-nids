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

from .scope import MODULE_ANOMALY, MODULE_ATTACK, MODULE_BOTNET

# loại tấn công -> (module chịu trách nhiệm, các nhãn tính là phát hiện đúng loại)
# Một sự kiện cảnh báo chỉ được coi là do đợt tấn công gây ra nếu nó bắt đầu không sớm hơn đầu đợt quá mức
# này: độ dài cửa sổ của module (10 giây; module botnet 120 giây) + khoảng gộp sự kiện 30 giây. Sự kiện bắt
# đầu từ lâu trước đợt (ví dụ cảnh báo kéo dài cả bản thu) là báo động giả dù có chồng lên đợt.
LEAD_S = {MODULE_BOTNET: 150.0}
LEAD_DEFAULT_S = 40.0

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
    lien_quan: frozenset = frozenset()   # host khác dính vào đợt (vd. máy điều khiển): chỉ để giải thích cảnh báo


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


def load_runlog(path, pcap=None) -> list:
    """Đọc nhật ký lần chạy lab thành danh sách hành vi.

    - Thư mục: lấy ``<thư mục>/<tên PCAP>.json`` (mỗi lần chạy một file, do scripts/lab_ao.py ghi).
    - File ``.json``: nhật ký một lần chạy; mỗi hành vi trong ``hanh_vi`` mang mã lần chạy của file.
    - File ``.jsonl``: mỗi dòng một hành vi (sinh_traffic.py / sinh_topology.py).
    """
    path = Path(path)
    if path.is_dir():
        path = path / f"{Path(pcap).stem}.json"
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        return [json.loads(l) for l in text.splitlines() if l.strip()]
    log = json.loads(text)
    return [{"ma_lan_chay": log["ma_lan_chay"], **b} for b in log.get("hanh_vi", [])]


def _ips(v) -> list:
    return [v] if isinstance(v, str) else list(v or [])


def _epoch(g, key) -> float:
    import datetime as _dt
    if g.get(key + "_epoch") is not None:
        return float(g[key + "_epoch"])
    return _dt.datetime.fromisoformat(g[key]).timestamp()


def attacks_from_runlog(logs, networks, t0=None, t1=None) -> list:
    """Ground truth từ nhật ký lần chạy lab (lab_ao.py, sinh_traffic.py, sinh_topology.py).

    Hành vi nhãn ``benign`` (nền, đối chứng) không thành đợt tấn công: mọi cảnh báo trên chúng là báo giả.
    dos/port_scan: host của đợt = (nguồn ∪ nạn nhân) trong mạng giám sát, như với lịch nhãn CIC.
    botnet: host của đợt = các bot (nguồn); máy điều khiển chỉ dùng để giải thích cảnh báo.
    Có ``t0``/``t1`` thì chỉ giữ hành vi chồng lên khoảng đó (nhật ký chung nhiều lần chạy).
    """
    out = []
    kind = {"tai-ket-noi": "dos", "quet": "port_scan", "tap-trung": "botnet", "ngang-hang": "botnet"}
    for g in logs:
        loai = kind.get(g.get("kieu")) or {"dos": "dos", "port_scan": "port_scan", "botnet": "botnet"}.get(g.get("nhan"))
        if loai is None:
            continue
        src = _ips(g["ip_nguon"]) if "ip_nguon" in g else _ips(g.get("ip_tham_gia"))
        dst = _ips(g.get("ip_dich"))
        inside = lambda ips: frozenset(h for h in ips if _in_nets(h, networks))
        hosts = inside(src) if loai == "botnet" else inside(src + dst)
        a0, a1 = _epoch(g, "bat_dau"), _epoch(g, "ket_thuc")
        if t0 is not None and (a1 <= t0 or a0 >= t1):
            continue
        if hosts:
            out.append(Attack(g["ma_lan_chay"], loai, hosts, a0, a1, inside(src + dst) - hosts))
    return out


def detect(attacks, alerts) -> dict:
    """Phát hiện/bỏ sót và độ trễ cho mỗi đợt; tập cảnh báo đã giải thích (để tính báo động giả)."""
    rows = []
    for a in attacks:
        mod, labels = DETECT[a.loai]
        hits = [al for al in alerts if al.is_alert and al.module == mod and al.label in labels
                and al.src_ip in a.hosts and al.window_end > a.t0 and al.window_start < a.t1]
        row = {"kich_ban": a.kich_ban, "loai": a.loai, "host": sorted(a.hosts),
               "bat_dau": round(a.t0, 1), "thoi_luong_s": round(a.t1 - a.t0, 1), "so_canh_bao": len(hits),
               "host_phat_hien": sorted({al.src_ip for al in hits})}
        # Module anomaly không nêu loại tấn công nên không tính là phát hiện; ghi riêng để phân tích bỏ sót.
        ano = [al for al in alerts if al.is_alert and al.module == MODULE_ANOMALY and al.src_ip in a.hosts
               and al.window_end > a.t0 and al.window_start < a.t1]
        row["anomaly_do_tre_s"] = round(min(al.window_end for al in ano) - a.t0, 1) if ano else None
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
    """Sự kiện cảnh báo không giải thích được bằng đợt tấn công nào.

    Được giải thích khi: cùng host với đợt, chồng thời gian, và không bắt đầu sớm hơn đầu đợt quá ``LEAD_S``."""
    fa = []
    for e in events:
        host = e["src_ip"]
        lead = LEAD_S.get(e["module"], LEAD_DEFAULT_S)
        covered = any(host in (a.hosts | a.lien_quan) and e["ket_thuc"] > a.t0 and a.t0 - lead <= e["bat_dau"] < a.t1
                      for a in attacks)
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


def run_scenario(pcap, networks, cfg=None, mode="ket_hop", name=None, rules=None, runlog=None, keep=None) -> dict:
    """Chạy pipeline trên một PCAP, dựng ground truth, trả về chỉ số Chặng 11.

    ``keep``: thư mục giữ lại file cảnh báo và sự kiện của lần chạy (bằng chứng); bỏ trống thì không giữ."""
    import tempfile

    import pandas as pd

    from .labeling import load_schedule
    from .pipeline import load_windows, merge_events, run_alerts, run_pcap, write_alerts, write_events

    with tempfile.TemporaryDirectory() as d:
        run = run_pcap(pcap, d, networks, cfg, mode=mode, name=name)
        alerts = run_alerts(run, run["artifact"])
        merged = merge_events(alerts)
        events = [_event_dict(e) for e in merged]
        if keep:
            Path(keep).mkdir(parents=True, exist_ok=True)
            stem = Path(keep) / (name or Path(pcap).stem)
            write_alerts(alerts, f"{stem}.alerts.csv")
            write_events(merged, f"{stem}.su_kien.csv")
        win = load_windows(run["prefix"])
    t0, t1 = float(win["window_start"].min()), float(win["window_end"].max())
    hours = (t1 - t0) / 3600
    if runlog is not None:
        attacks = attacks_from_runlog(runlog, networks, t0, t1)
    else:
        attacks = attacks_from_rules(rules if rules is not None else load_schedule(), t0, t1, networks)
    det = detect(attacks, alerts)
    perf = {"flow": run["so_luong"].get("flow"), "cua_so": run["so_luong"]["cua_so"],
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
    parser.add_argument("--nhat-ky", help="nhật ký lần chạy lab làm ground truth thay cho lịch nhãn: thư mục "
                                          "chứa <tên PCAP>.json, một file .json, hoặc .jsonl")
    parser.add_argument("--giu", help="thư mục giữ file cảnh báo và sự kiện của từng PCAP")
    parser.add_argument("--ten", default="thuc_nghiem", help="tên file JSON kết quả trong --out")
    parser.add_argument("--config", help="file cấu hình")
    parser.add_argument("--out", help="thư mục ghi JSON kết quả")
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    scenarios = [run_scenario(p, args.net, cfg, args.che_do, keep=args.giu,
                              runlog=load_runlog(args.nhat_ky, p) if args.nhat_ky else None) for p in args.pcap]
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
        (od / f"{args.ten}.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Đã ghi: {od / (args.ten + '.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

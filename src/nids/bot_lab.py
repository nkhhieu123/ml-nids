"""Chấm module botnet theo **từng bot** và theo **topology** trên các lần chạy lab (QĐ-076).

``nids.thuc_nghiem`` chấm theo đợt: một đợt botnet được tính là phát hiện khi có ít nhất một cảnh báo đúng. Với
kịch bản nhiều bot cần biết thêm: bao nhiêu bot trong đợt bị báo, nhãn topology gán cho bot có đúng không, và có
máy không phải bot nào bị báo không. Đầu vào là file cảnh báo do ``nids.thuc_nghiem --giu`` giữ lại và nhật ký
lần chạy (ground truth).

    cd src
    python -m nids.bot_lab ../output/bot5_canh_bao --nhat-ky ../data/run_logs --out ../docs/hinh/thuc_nghiem/lab --ten bot5_lab
"""

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path

SLACK_S = 130.0               # cửa sổ đồ thị 120 giây kết thúc sau hành vi tối đa chừng này vẫn tính là của đợt


def _epoch(s) -> float:
    try:
        return float(s)
    except ValueError:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def score_run(alerts, log) -> dict:
    """Một lần chạy: bot nào bị báo, topology gán cho bot, máy không phải bot bị báo."""
    bot_rows = [r for r in alerts if r["module"] == "botnet_topology"]
    suspects = [r for r in bot_rows if r["label"] == "suspect_host"]
    topo = [r for r in bot_rows if r["label"] in ("centralized", "p2p")]
    out = {"ma_lan_chay": log["ma_lan_chay"], "bien_the": log["bien_the"]}
    g = next((b for b in log["hanh_vi"] if b["nhan"] == "botnet"), None)
    if g is None:                                     # đối chứng: mọi cảnh báo suspect_host đều là báo nhầm
        out.update(so_bot=0, may_bi_bao_nham=sorted({r["src_ip"] for r in suspects}),
                   cua_so_bao_nham=len(suspects))
        return out
    bots = set(g["ip_nguon"])
    t0, t1 = g["bat_dau_epoch"], g["ket_thuc_epoch"] + SLACK_S
    in_time = lambda r: _epoch(r["window_end"]) > t0 and _epoch(r["window_start"]) < t1
    truth = (g.get("tham_so") or {}).get("topology", "none")
    hit = {ip: [r for r in suspects if r["src_ip"] == ip and in_time(r)] for ip in sorted(bots)}
    first = {ip: round(min(_epoch(r["window_end"]) for r in v) - g["bat_dau_epoch"], 1) for ip, v in hit.items() if v}
    tb = [r for r in topo if r["src_ip"] in bots and in_time(r)]
    others = sorted({r["src_ip"] for r in suspects if r["src_ip"] not in bots})
    out.update(so_bot=len(bots), topology_that=truth, bot_bi_bao=sum(bool(v) for v in hit.values()),
               bot_bo_sot=[ip for ip, v in hit.items() if not v],
               cua_so_bot_bi_bao={ip: len(v) for ip, v in hit.items()},
               giay_toi_canh_bao_dau={ip: first.get(ip) for ip in sorted(bots)},
               topology={"so_cua_so": len(tb), "dung": sum(r["label"] == truth for r in tb),
                         "theo_nhan": {k: sum(r["label"] == k for r in tb) for k in ("centralized", "p2p")}},
               may_bi_bao_nham=others,
               cua_so_bao_nham=sum(r["src_ip"] not in bots for r in suspects))
    return out


def summarize(rows) -> dict:
    out = {}
    for v in sorted({r["bien_the"] for r in rows}):
        rs = [r for r in rows if r["bien_the"] == v]
        s = {"so_lan_chay": len(rs), "cua_so_bao_nham": sum(r["cua_so_bao_nham"] for r in rs),
             "may_bi_bao_nham": sorted({ip for r in rs for ip in r["may_bi_bao_nham"]})}
        if any(r["so_bot"] for r in rs):
            n = sum(r["so_bot"] for r in rs)
            k = sum(r["bot_bi_bao"] for r in rs)
            tw = sum(r["topology"]["so_cua_so"] for r in rs)
            td = sum(r["topology"]["dung"] for r in rs)
            s.update(bot_bi_bao=k, tong_bot=n, ty_le_bot=round(k / n, 3),
                     dot_phat_hien=sum(r["bot_bi_bao"] > 0 for r in rs),
                     topology_dung=td, topology_cua_so=tw, ty_le_topology=round(td / tw, 3) if tw else None)
        out[v] = s
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Chấm module botnet theo từng bot và topology trên lần chạy lab.")
    ap.add_argument("thu_muc", help="thư mục file *.alerts.csv của nids.thuc_nghiem --giu")
    ap.add_argument("--nhat-ky", required=True, help="thư mục nhật ký lần chạy")
    ap.add_argument("--out", required=True)
    ap.add_argument("--ten", default="bot_lab")
    a = ap.parse_args(argv)
    rows = []
    for f in sorted(Path(a.thu_muc).glob("*.alerts.csv")):
        run_id = f.name[:-len(".alerts.csv")]
        log = json.loads((Path(a.nhat_ky) / f"{run_id}.json").read_text(encoding="utf-8"))
        rows.append(score_run(list(csv.DictReader(open(f, encoding="utf-8"))), log))
    res = {"tong_hop": summarize(rows), "lan_chay": rows}
    od = Path(a.out)
    od.mkdir(parents=True, exist_ok=True)
    (od / f"{a.ten}.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    for v, s in res["tong_hop"].items():
        print(v, json.dumps(s, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

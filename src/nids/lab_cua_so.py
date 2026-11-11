"""Đánh giá bộ phân loại theo từng cửa sổ host trên PCAP lab, nhãn lấy từ nhật ký lần chạy.

``nids.thuc_nghiem`` chấm theo đợt tấn công (có phát hiện hay không). Ở đây chấm theo **cửa sổ host**, đúng cách
đã chấm trên CIC-IDS2017 ở Chặng 7, để so được hai mạng và để xem riêng máy tấn công với máy nạn nhân:

- Mỗi hành vi `dos`/`port_scan` trong nhật ký thành một luật (IP nguồn, IP đích, cổng, thời điểm tới mili giây);
  flow và cửa sổ được gán nhãn bằng chính `nids.labeling` (cùng ngưỡng `window_min_attack_share`).
- Cửa sổ mơ hồ (có flow tấn công nhưng dưới ngưỡng) bị bỏ như ở CIC. Mọi cửa sổ khác là `benign`, kể cả cửa sổ
  của bot mô phỏng và của đối chứng: với bộ phân loại ba lớp, báo `dos`/`port_scan` trên chúng là báo nhầm.

    cd src
    python -m nids.lab_cua_so ../data/pcap/lab/k*.pcap --nhat-ky ../data/run_logs --out ../docs/hinh/thuc_nghiem/lab
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

import pandas as pd

from .classifier import multiclass_metrics
from .config import load_config
from .labeling import (STATUS_MATCHED, STATUS_UNMATCHED, Rule, label_flows, label_windows, load_flows_for_labels,
                       load_windows_for_labels)
from .scope import MODULE_ATTACK
from .thuc_nghiem import _epoch, _ips, load_runlog

DAY_S = 86400.0


def rules_from_runlog(entries) -> list:
    """Luật gán nhãn từ các hành vi tấn công của bộ phân loại trong nhật ký lần chạy."""
    rules = []
    for i, g in enumerate(entries):
        if g.get("nhan") not in ("dos", "port_scan"):
            continue
        t0, t1 = _epoch(g, "bat_dau"), _epoch(g, "ket_thuc")
        port = (g.get("tham_so") or {}).get("cong")
        rules.append(Rule(f"{g['ma_lan_chay']}#{i}", t0, t1, t0 - DAY_S, t1 + DAY_S, frozenset(_ips(g["ip_nguon"])),
                          frozenset(_ips(g["ip_dich"])), g["nhan"], g.get("kieu", g["nhan"]), g["ma_lan_chay"],
                          frozenset({float(port)}) if port else frozenset()))
    return rules


def role_of(host, rules) -> str:
    if any(host in r.attackers for r in rules):
        return "tan_cong"
    if any(host in r.victims for r in rules):
        return "nan_nhan"
    return "khac"


def window_table(pcap, entries, networks, cfg, tolerance_s=1.0) -> pd.DataFrame:
    """Một dòng mỗi cửa sổ host: nhãn theo nhật ký, dự đoán của bộ phân loại, vai trò của host."""
    from .pipeline import run_pcap

    rules = rules_from_runlog(entries)
    with tempfile.TemporaryDirectory() as d:
        run = run_pcap(pcap, d, networks, cfg, mode="ket_hop")
        flows = load_flows_for_labels(f"{run['prefix']}.flows.csv")
        windows = load_windows_for_labels(f"{run['prefix']}.windows.csv")
    labels = label_windows(windows, flows, label_flows(flows, rules, tolerance_s),
                           cfg["labeling"]["window_min_attack_share"])
    pred = run["ket_qua"][MODULE_ATTACK][["host", "window_start", "du_doan"]]
    out = labels.merge(pred, on=["host", "window_start"], how="left", validate="one_to_one")
    out["vai_tro_host"] = [role_of(h, rules) for h in out["host"]]
    out["run_id"] = Path(pcap).stem
    return out


def evaluate(table) -> dict:
    """Chỉ số theo cửa sổ: chung, và recall riêng cho máy tấn công, máy nạn nhân."""
    sure = table[table["label_status"].isin([STATUS_MATCHED, STATUS_UNMATCHED])]
    res = {"so_cua_so": len(table), "bo_vi_mo_ho": int(len(table) - len(sure)),
           "chung": multiclass_metrics(sure["label_attack"], sure["du_doan"])}
    by_role = {}
    for role, g in sure[sure["label_attack"] != "benign"].groupby("vai_tro_host"):
        by_role[role] = {lab: {"so_mau": len(x), "recall": round(float((x["du_doan"] == lab).mean()), 4)}
                         for lab, x in g.groupby("label_attack")}
    res["recall_theo_vai_tro"] = by_role
    benign = sure[sure["label_attack"] == "benign"]
    wrong = benign[benign["du_doan"] != "benign"]
    res["benign_bi_bao"] = {"so_mau": len(benign), "bi_bao": len(wrong),
                            "theo_bien_the": {k: int(v) for k, v in
                                              wrong["run_id"].str.rsplit("-", n=2).str[0].value_counts().items()}}
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description="Bộ phân loại theo cửa sổ host trên PCAP lab, nhãn từ nhật ký lần chạy.")
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--net", action="append", help="mạng giám sát; mặc định lab.subnet")
    ap.add_argument("--nhat-ky", required=True)
    ap.add_argument("--out", required=True, help="thư mục ghi cua_so.json")
    ap.add_argument("--ten", default="cua_so")
    a = ap.parse_args(argv)
    cfg = load_config()
    nets = a.net or [cfg["lab"]["subnet"]]
    tables = {}
    for p in a.pcap:
        role = Path(p).stem.rsplit("-", 2)[1]                      # train / val / test
        tables.setdefault(role, []).append(window_table(p, load_runlog(a.nhat_ky, p), nets, cfg))
    out = {role: {"so_lan_chay": len(ts), **evaluate(pd.concat(ts, ignore_index=True))} for role, ts in tables.items()}
    od = Path(a.out)
    od.mkdir(parents=True, exist_ok=True)
    (od / f"{a.ten}.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    for role, r in out.items():
        c = r["chung"]
        print(f"{role}: {r['so_lan_chay']} lần, {r['so_cua_so']} cửa sổ (bỏ {r['bo_vi_mo_ho']} mơ hồ); macro-F1 "
              f"{c['macro_f1']}; " + "; ".join(f"{k} P {v['precision']} R {v['recall']} n {v['so_mau']}"
                                               for k, v in c["theo_lop"].items()))
        print(f"  recall theo vai trò: {r['recall_theo_vai_tro']}; benign bị báo: {r['benign_bi_bao']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

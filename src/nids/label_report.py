"""Báo cáo nhãn: mẫu khớp, không khớp, mơ hồ, và đối chiếu với CSV có nhãn của CIC (C05-T02).

    python -m nids.label_report output/features/cic17_wednesday.flows.csv \\
        --cic-csv data/cic-ids2017/TrafficLabelling/Wednesday-workingHours.pcap_ISCX.csv

Đọc bảng flow và file nhãn của nids.labeling. Kết quả ghi ra
``<tên>.flows.label_report.json``. Chi tiết ở docs/27_bao_cao_nhan.md.
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from .labeling import STATUS_AMBIGUOUS, labels_path

# Nhãn CSV của CIC -> nhãn của đồ án (loai: tấn công bị loại khỏi phân loại)
CIC_LABEL_MAP = {
    "BENIGN": "benign", "DoS Hulk": "dos", "DoS GoldenEye": "dos", "DoS slowloris": "dos",
    "DoS Slowhttptest": "dos", "PortScan": "port_scan", "DDoS": "loai", "Heartbleed": "loai",
    "Bot": "loai",
}
CIC_UTC_OFFSET_H = -3
# Cột Timestamp của CSV CIC ghi giờ kiểu 12 giờ không có SA/CH; dữ liệu thu từ
# khoảng 08:40 tới 17:10, nên giờ 1–7 là buổi chiều (docs/06 mục 7.5).
CIC_AFTERNOON_HOURS = range(1, 8)
CSV_MATCH_SLACK_S = 120      # CSV chỉ ghi tới phút; nới 2 phút khi ghép với flow của dự án


def parse_cic_timestamp(text) -> float:
    """``5/7/2017 2:43`` (ngày/tháng, 12 giờ không SA/CH, giờ địa phương) -> giây UTC."""
    date_part, time_part = text.strip().split()
    day, month, year = (int(x) for x in date_part.split("/"))
    hh, mm = (int(x) for x in time_part.split(":")[:2])
    if hh in CIC_AFTERNOON_HOURS:
        hh += 12
    local = datetime(year, month, day, hh, mm)
    return (local - timedelta(hours=CIC_UTC_OFFSET_H)).replace(tzinfo=timezone.utc).timestamp()


def _key(ip1, port1, ip2, port2, proto):
    a, b = (ip1, port1), (ip2, port2)
    return (proto,) + (a + b if a <= b else b + a)


def compare_with_cic(flows: pd.DataFrame, labels: pd.DataFrame, csv_path) -> dict:
    """Ghép flow của CSV CIC với flow của dự án (cùng 5-tuple, thời gian chồng nhau).

    Trả về bảng chéo nhãn CSV (đã đổi sang nhãn đồ án) × nhãn của dự án, và số flow
    CSV không ghép được.
    """
    merged = flows.merge(labels, on="first_index")
    index = defaultdict(list)
    for r in merged.itertuples(index=False):
        port = lambda p: -1 if pd.isna(p) else int(p)
        k = _key(r.fwd_ip, port(r.fwd_port), r.bwd_ip, port(r.bwd_port), int(r.protocol))
        ours = r.label_attack if isinstance(r.label_attack, str) else (
            "loai" if r.label_status == "loai" else r.label_status)
        index[k].append((r.first_ts, r.last_ts, ours))
    cross = Counter()
    unmatched = Counter()
    with open(csv_path, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        header = [h.strip() for h in next(reader)]
        col = {h: i for i, h in enumerate(header)}
        for row in reader:
            if len(row) != len(header):
                continue
            cic = CIC_LABEL_MAP.get(row[col["Label"]].strip(), "khac")
            proto = int(row[col["Protocol"]])
            k = _key(row[col["Source IP"]], int(row[col["Source Port"]]),
                     row[col["Destination IP"]], int(row[col["Destination Port"]]), proto)
            t = parse_cic_timestamp(row[col["Timestamp"]])
            hits = [lab for first, last, lab in index.get(k, ())
                    if last >= t - CSV_MATCH_SLACK_S and first <= t + 60 + CSV_MATCH_SLACK_S]
            if not hits:
                unmatched[cic] += 1
                continue
            # Một flow CSV có thể ứng nhiều flow của dự án (cắt khác nhau): lấy nhãn chiếm đa số.
            cross[(cic, Counter(hits).most_common(1)[0][0])] += 1
    table = defaultdict(dict)
    for (cic, ours), n in cross.items():
        table[cic][ours] = n
    total = sum(cross.values())
    agree = sum(n for (cic, ours), n in cross.items() if cic == ours)
    return {
        "file_csv": str(csv_path),
        "so_flow_csv_ghep_duoc": total,
        "so_flow_csv_khong_ghep_duoc": dict(unmatched),
        "bang_cheo_csv_x_du_an": {k: dict(v) for k, v in table.items()},
        "ty_le_dong_y": round(agree / total, 6) if total else None,
    }


def ambiguous_groups(flows: pd.DataFrame, labels: pd.DataFrame, top=10) -> list:
    """Nhóm flow mơ hồ theo cặp IP và giờ UTC, để biết vì sao mơ hồ."""
    m = flows.merge(labels, on="first_index")
    m = m[m["label_status"] == STATUS_AMBIGUOUS]
    if m.empty:
        return []
    m = m.assign(hour=pd.to_datetime(m["first_ts"], unit="s", utc=True).dt.strftime("%Y-%m-%d %H"))
    g = (m.groupby(["fwd_ip", "bwd_ip", "hour", "rule_id"], dropna=False)
          .agg(so_flow=("first_index", "size"), so_goi=("packets", "sum"),
               dau=("first_ts", "min"), cuoi=("last_ts", "max"))
          .reset_index().sort_values("so_flow", ascending=False).head(top))
    out = []
    for r in g.itertuples(index=False):
        out.append({"client": r.fwd_ip, "server": r.bwd_ip, "gio_utc": r.hour,
                    "ly_do": "nhieu_quy_tac" if r.rule_id == "nhieu_quy_tac" else "cap_tan_cong_ngoai_khung_gio",
                    "so_flow": int(r.so_flow), "so_goi": int(r.so_goi),
                    "tu_utc": datetime.fromtimestamp(r.dau, timezone.utc).strftime("%H:%M:%S"),
                    "den_utc": datetime.fromtimestamp(r.cuoi, timezone.utc).strftime("%H:%M:%S")})
    return out


def report(flows_path, cic_csvs=()) -> dict:
    flows = pd.read_csv(flows_path, usecols=["first_index", "first_ts", "last_ts", "fwd_ip",
                                             "fwd_port", "bwd_ip", "bwd_port", "protocol", "packets"],
                        dtype={"fwd_ip": str, "bwd_ip": str})
    labels = pd.read_csv(labels_path(flows_path), dtype=str, keep_default_na=False,
                         na_values=[""]).astype({"first_index": "int64"})
    m = flows.merge(labels, on="first_index")
    result = {
        "bang": str(flows_path),
        "so_flow": len(m),
        "theo_trang_thai": {s: {"so_flow": int(n), "so_goi": int(p)} for s, (n, p) in
                            m.groupby("label_status")["packets"].agg(["size", "sum"]).iterrows()},
        "theo_quy_tac": {r: {"so_flow": int(n), "so_goi": int(p)} for r, (n, p) in
                         m.groupby("rule_id")["packets"].agg(["size", "sum"]).iterrows()},
        "nhom_mo_ho": ambiguous_groups(flows, labels),
    }
    result["doi_chieu_cic"] = [compare_with_cic(flows, labels, c) for c in cic_csvs]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Báo cáo nhãn của bảng flow.")
    parser.add_argument("flows", help="file <tên>.flows.csv đã có <tên>.flows.labels.csv")
    parser.add_argument("--cic-csv", action="append", help="CSV có nhãn của CIC để đối chiếu")
    args = parser.parse_args(argv)
    result = report(args.flows, args.cic_csv or ())
    checks = result["doi_chieu_cic"]
    out = labels_path(args.flows, "label_report").with_suffix(".json")
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{args.flows}: {result['so_flow']} flow")
    for s, v in result["theo_trang_thai"].items():
        print(f"  {s}: {v['so_flow']} flow, {v['so_goi']} gói")
    for c in checks:
        print(f"  Đối chiếu {Path(c['file_csv']).name}: ghép được {c['so_flow_csv_ghep_duoc']}, "
              f"đồng ý {c['ty_le_dong_y']}")
    print(f"Đã ghi: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

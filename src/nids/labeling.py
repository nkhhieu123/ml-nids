"""Gán nhãn bảng đặc trưng theo lịch tấn công (C05-T01, C05-T03).

Nguồn nhãn là ``config/label_schedule.csv``: mỗi dòng một đợt tấn công, gồm khung
giờ địa phương, độ lệch múi giờ, IP bên tấn công và nạn nhân như thấy trong PCAP,
và nhãn của đồ án. Flow nhận nhãn tấn công khi hai đầu là một cặp (bên tấn công,
nạn nhân) và khoảng [first_ts, last_ts] chạm khung giờ (nới ``tolerance_s`` hai
đầu). Chi tiết ở docs/26_gan_nhan.md (QĐ-025).

Cửa sổ host nhận nhãn từ các flow của host chồng lên cửa sổ (C05-T03,
docs/28_nhan_cua_so.md, QĐ-026). Lệnh dưới ghi nhãn cho bảng flow và, nếu có
``<tên>.windows.csv`` cùng chỗ, cho cả bảng cửa sổ:

    python -m nids.labeling output/features/cic17_wednesday.flows.csv
"""

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from .config import PROJECT_ROOT, load_config
from .scope import ATTACK_LABELS

DEFAULT_SCHEDULE = PROJECT_ROOT / "config" / "label_schedule.csv"
SCHEDULE_COLUMNS = ("id", "nguon", "ngay", "bat_dau", "ket_thuc", "utc_offset_h", "nhan_goc",
                    "nhan_attack", "ben_tan_cong", "nan_nhan", "cong_nan_nhan", "khoi", "ghi_chu")
EXCLUDED = "loai"            # đợt tấn công không thuộc ba lớp phân loại (DDoS, Heartbleed, bot)

# Trạng thái nhãn của một mẫu
STATUS_MATCHED = "khop"          # khớp một đợt tấn công thuộc lớp phân loại
STATUS_EXCLUDED = "loai"         # khớp đợt tấn công bị loại: chỉ dùng cho anomaly
STATUS_AMBIGUOUS = "mo_ho"       # cặp IP tấn công ngoài khung giờ, hoặc khớp hai nhãn khác nhau
STATUS_UNMATCHED = "khong_khop"  # không khớp đợt nào: bình thường
STATUSES = (STATUS_MATCHED, STATUS_EXCLUDED, STATUS_AMBIGUOUS, STATUS_UNMATCHED)

LABEL_COLUMNS = ("label_attack", "label_anomaly", "label_status", "rule_id")


@dataclass(frozen=True)
class Rule:
    id: str
    start_s: float           # giây UTC
    end_s: float
    day_start_s: float       # 00:00 và 24:00 giờ địa phương của ngày đó, theo UTC
    day_end_s: float
    attackers: frozenset
    victims: frozenset
    label: str               # dos, port_scan hoặc loai
    original: str
    block: str
    victim_ports: frozenset = frozenset()   # cổng dịch vụ bị tấn công phía nạn nhân; rỗng là mọi cổng

    def pair_mask(self, a, b, a_port=None, b_port=None):
        """Hai đầu (a, b) là một cặp bên tấn công – nạn nhân, theo chiều bất kỳ.

        Nếu đợt có ``victim_ports``, phía nạn nhân phải dùng một trong các cổng đó.
        """
        att, vic = list(self.attackers), list(self.victims)
        a_vic, b_vic = b.isin(att) & a.isin(vic), a.isin(att) & b.isin(vic)
        if self.victim_ports and a_port is not None:
            ports = list(self.victim_ports)
            a_vic &= a_port.isin(ports)
            b_vic &= b_port.isin(ports)
        return a_vic | b_vic


def _utc_seconds(day, hhmm, offset_h):
    local = datetime.strptime(f"{day} {hhmm}", "%Y-%m-%d %H:%M")
    return (local - timedelta(hours=offset_h)).replace(tzinfo=timezone.utc).timestamp()


def load_schedule(path=None) -> list[Rule]:
    """Đọc lịch tấn công. ``ket_thuc`` là phút cuối, tính hết phút đó."""
    path = Path(path) if path else DEFAULT_SCHEDULE
    rules = []
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if tuple(reader.fieldnames or ()) != SCHEDULE_COLUMNS:
            raise ValueError(f"{path}: cột phải là {SCHEDULE_COLUMNS}")
        for row in reader:
            label = row["nhan_attack"]
            if label not in ATTACK_LABELS + (EXCLUDED,) or label == "benign":
                raise ValueError(f"{path}: {row['id']}: nhan_attack không hợp lệ: {label}")
            off = float(row["utc_offset_h"])
            start = _utc_seconds(row["ngay"], row["bat_dau"], off)
            end = _utc_seconds(row["ngay"], row["ket_thuc"], off) + 60
            day0 = _utc_seconds(row["ngay"], "00:00", off)
            split = lambda v: frozenset(x.strip() for x in v.split(";") if x.strip())
            ports = frozenset(int(p) for p in split(row["cong_nan_nhan"]))
            rules.append(Rule(row["id"], start, end, day0, day0 + 86400, split(row["ben_tan_cong"]),
                              split(row["nan_nhan"]), label, row["nhan_goc"], row["khoi"], ports))
    return rules


def label_frame(a, b, first, last, rules, tolerance_s, a_port=None, b_port=None) -> pd.DataFrame:
    """Gán nhãn cho các mẫu có hai đầu (a, b) và khoảng thời gian [first, last] (giây UTC).

    ``a_port``, ``b_port``: cổng của hai đầu, dùng cho đợt có ``cong_nan_nhan``.

    Trả về DataFrame cùng chỉ số với đầu vào, gồm các cột LABEL_COLUMNS.
    """
    n = len(a)
    hit_label = pd.Series([None] * n, index=a.index, dtype=object)
    hit_rule = pd.Series([None] * n, index=a.index, dtype=object)
    conflict = pd.Series(False, index=a.index)
    pair_same_day = pd.Series(False, index=a.index)
    for r in rules:
        pair = r.pair_mask(a, b, a_port, b_port)
        if not pair.any():
            continue
        same_day = pair & (last >= r.day_start_s) & (first < r.day_end_s)
        pair_same_day |= same_day
        overlap = same_day & (last >= r.start_s - tolerance_s) & (first <= r.end_s + tolerance_s)
        new = overlap & hit_label.isna()
        hit_label[new] = r.label
        hit_rule[new] = r.id
        conflict |= overlap & hit_label.notna() & (hit_label != r.label)
    status = pd.Series(STATUS_UNMATCHED, index=a.index, dtype=object)
    status[pair_same_day & hit_label.isna()] = STATUS_AMBIGUOUS
    status[hit_label.notna() & (hit_label != EXCLUDED)] = STATUS_MATCHED
    status[hit_label == EXCLUDED] = STATUS_EXCLUDED
    status[conflict] = STATUS_AMBIGUOUS

    label_attack = pd.Series(None, index=a.index, dtype=object)
    label_attack[status == STATUS_UNMATCHED] = "benign"
    label_attack[status == STATUS_MATCHED] = hit_label[status == STATUS_MATCHED]
    label_anomaly = pd.Series(None, index=a.index, dtype=object)
    label_anomaly[status == STATUS_UNMATCHED] = "normal"
    label_anomaly[status.isin([STATUS_MATCHED, STATUS_EXCLUDED])] = "anomaly"
    rule_id = hit_rule.where(status != STATUS_AMBIGUOUS, None)
    rule_id[conflict] = "nhieu_quy_tac"
    out = pd.DataFrame({"label_attack": label_attack, "label_anomaly": label_anomaly,
                        "label_status": status, "rule_id": rule_id})
    return out.astype(object).where(out.notna(), None)   # ô trống luôn là None, không phải NaN


FLOW_KEY = ("first_index",)


def load_flows_for_labels(path) -> pd.DataFrame:
    return pd.read_csv(path, usecols=["first_index", "first_ts", "last_ts", "fwd_ip", "bwd_ip",
                                      "fwd_port", "bwd_port"],
                       dtype={"fwd_ip": str, "bwd_ip": str, "first_index": "int64",
                              "first_ts": "float64", "last_ts": "float64",
                              "fwd_port": "float64", "bwd_port": "float64"})


def label_flows(flows: pd.DataFrame, rules, tolerance_s) -> pd.DataFrame:
    """Nhãn của bảng flow; khóa nối là ``first_index``."""
    ports = (flows["fwd_port"], flows["bwd_port"]) if "fwd_port" in flows else (None, None)
    labels = label_frame(flows["fwd_ip"], flows["bwd_ip"], flows["first_ts"], flows["last_ts"],
                         rules, tolerance_s, *ports)
    return pd.concat([flows[list(FLOW_KEY)], labels], axis=1)


WINDOW_KEY = ("host", "window_start")
WINDOW_LABEL_COLUMNS = LABEL_COLUMNS + ("attack_share", "n_flows", "n_attack_flows")
CLASS_LABELS = tuple(l for l in ATTACK_LABELS if l != "benign")


def label_windows(windows: pd.DataFrame, flows: pd.DataFrame, flow_labels: pd.DataFrame,
                  min_attack_share: float) -> pd.DataFrame:
    """Nhãn cửa sổ host từ nhãn của các flow có host làm một đầu và chồng lên cửa sổ.

    Flow chồng lên [start, end) khi first_ts < end và last_ts >= start. Quy tắc ở
    docs/28_nhan_cua_so.md. Trả về bảng theo thứ tự của ``windows``.
    """
    f = flows.merge(flow_labels, on="first_index")
    cat = f["label_status"].where(f["label_status"] != STATUS_MATCHED, f["label_attack"])
    sides = pd.concat([
        pd.DataFrame({"host": f["fwd_ip"], "first": f["first_ts"], "last": f["last_ts"], "cat": cat}),
        pd.DataFrame({"host": f["bwd_ip"], "first": f["first_ts"], "last": f["last_ts"], "cat": cat})
        [f["bwd_ip"] != f["fwd_ip"]],
    ], ignore_index=True)
    cats = CLASS_LABELS + (STATUS_EXCLUDED, STATUS_AMBIGUOUS, STATUS_UNMATCHED)
    counts = {c: np.zeros(len(windows), dtype=np.int64) for c in cats}
    starts = windows["window_start"].to_numpy(dtype=float)
    ends = windows["window_end"].to_numpy(dtype=float)
    win_pos = windows.groupby("host").indices
    for (host, c), g in sides.groupby(["host", "cat"]):
        pos = win_pos.get(host)
        if pos is None:
            continue
        first = np.sort(g["first"].to_numpy())
        last = np.sort(g["last"].to_numpy())
        # Số flow chồng lên cửa sổ = số flow bắt đầu trước end − số flow kết thúc trước start
        counts[c][pos] = (np.searchsorted(first, ends[pos], "left")
                          - np.searchsorted(last, starts[pos], "left"))
    n_all = sum(counts.values())
    attack = sum(counts[c] for c in CLASS_LABELS)
    n_classes = sum((counts[c] > 0).astype(int) for c in CLASS_LABELS)
    top = np.array(CLASS_LABELS, dtype=object)[np.argmax(np.vstack([counts[c] for c in CLASS_LABELS]), axis=0)]
    share = np.where(n_all > 0, attack / np.maximum(n_all, 1), 0.0)

    status = np.full(len(windows), STATUS_UNMATCHED, dtype=object)
    label_attack = np.full(len(windows), "benign", dtype=object)
    label_anomaly = np.full(len(windows), "normal", dtype=object)
    rule = np.full(len(windows), None, dtype=object)
    amb_only = (attack == 0) & (counts[STATUS_AMBIGUOUS] > 0)
    status[amb_only], label_attack[amb_only], label_anomaly[amb_only] = STATUS_AMBIGUOUS, None, None
    has_attack = attack > 0
    ok = has_attack & (n_classes == 1) & (share >= min_attack_share)
    status[ok], label_attack[ok], label_anomaly[ok] = STATUS_MATCHED, top[ok], "anomaly"
    weak = has_attack & ~ok
    status[weak], label_attack[weak], label_anomaly[weak] = STATUS_AMBIGUOUS, None, "anomaly"
    rule[weak & (n_classes > 1)] = "nhieu_lop"
    rule[weak & (n_classes == 1)] = "it_flow_tan_cong"
    excl = counts[STATUS_EXCLUDED] > 0
    status[excl], label_attack[excl], label_anomaly[excl] = STATUS_EXCLUDED, None, "anomaly"
    rule[excl] = None
    out = pd.DataFrame({
        "host": windows["host"].to_numpy(), "window_start": windows["window_start"].to_numpy(),
        "label_attack": label_attack, "label_anomaly": label_anomaly, "label_status": status,
        "rule_id": rule, "attack_share": np.round(share, 6), "n_flows": n_all,
        "n_attack_flows": attack,
    })
    return out.astype({c: object for c in LABEL_COLUMNS}).where(out.notna(), None)


def load_windows_for_labels(path) -> pd.DataFrame:
    return pd.read_csv(path, usecols=["host", "window_start", "window_end"],
                       dtype={"host": str, "window_start": "float64", "window_end": "float64"})


def labels_path(table_path, suffix="labels") -> Path:
    """``x.flows.csv`` -> ``x.flows.labels.csv``."""
    p = Path(table_path)
    return p.with_name(p.name[:-len(".csv")] + f".{suffix}.csv")


def summarize(labels: pd.DataFrame) -> dict:
    return {
        "so_mau": len(labels),
        "theo_trang_thai": labels["label_status"].value_counts().to_dict(),
        "theo_nhan_attack": labels["label_attack"].value_counts(dropna=False)
                                                  .rename(index=lambda k: k if isinstance(k, str) else "trong")
                                                  .to_dict(),
        "theo_quy_tac": labels["rule_id"].value_counts().to_dict(),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Gán nhãn bảng flow và cửa sổ host theo lịch tấn công.")
    parser.add_argument("flows", nargs="+", help="file <tên>.flows.csv của nids.feature_export")
    parser.add_argument("--schedule", help="lịch tấn công, mặc định config/label_schedule.csv")
    parser.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)["labeling"]
    rules = load_schedule(args.schedule)
    for path in args.flows:
        flows = load_flows_for_labels(path)
        labels = label_flows(flows, rules, cfg["tolerance_s"])
        _write(labels, labels_path(path), "flow")
        win_path = Path(str(path)[:-len(".flows.csv")] + ".windows.csv")
        if str(path).endswith(".flows.csv") and win_path.exists():
            wl = label_windows(load_windows_for_labels(win_path), flows, labels,
                               cfg["window_min_attack_share"])
            _write(wl, labels_path(win_path), "cửa sổ")
    return 0


def _write(labels, out, what):
    labels.to_csv(out, index=False)
    s = summarize(labels)
    print(f"{out}: {s['so_mau']} {what}; {s['theo_trang_thai']}")
    print(f"  nhãn attack: {s['theo_nhan_attack']}")
    out.with_suffix(".json").write_text(json.dumps(s, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())

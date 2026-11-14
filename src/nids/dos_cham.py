"""Giữ nhãn ``dos`` theo host qua nhiều cửa sổ, để vớt DoS HTTP chậm (Slowhttptest, Slowloris).

DoS chậm giữ kết nối mở thật lâu: giữa hai đợt gửi, cửa sổ 10 giây của nạn nhân gần như không có kết nối mới
nên bộ phân loại trả ``benign`` (docs/44). Thay vì thêm đặc trưng dài hơn cửa sổ (phải trích xuất lại toàn bộ),
ở đây thêm một lớp **sau** bộ phân loại, giống lớp gộp theo host của module botnet (docs/69):

    một cửa sổ ``benign`` của host H được nâng lên ``dos`` nếu trong ``lookback_s`` giây ngay trước nó,
    H đã có ít nhất ``min_count`` cửa sổ được bộ phân loại gán ``dos``.

Lớp này chỉ nhìn về quá khứ (dùng được realtime), không đổi nhãn ``port_scan``. Hai tham số chọn trên
validation theo macro-F1, rồi đọc test một lần.

    cd src
    python -m nids.dos_cham ../output/features/cic17_wednesday ../output/features/cic17_friday \
        --model ../models/phan_loai_rf_windows.joblib --out ../docs/hinh
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from . import classifier as clf
from .config import load_config
from .labeling import load_schedule

GRID_LOOKBACK_S = (20, 30, 60, 120, 300)
GRID_MIN_COUNT = (1, 2, 3, 5)


def hold_dos(pred, host, start, lookback_s, min_count) -> np.ndarray:
    """Nâng ``benign`` lên ``dos`` khi host đã có đủ cửa sổ ``dos`` trong ``lookback_s`` giây ngay trước."""
    pred = np.asarray(pred, dtype=object).copy()
    host, start = np.asarray(host), np.asarray(start, float)
    order = np.lexsort((start, host))
    h, t, raw = host[order], start[order], (pred[order] == "dos")
    out = pred[order].copy()
    lo = 0
    for i in range(len(order)):
        if i and h[i] != h[i - 1]:
            lo = i
        while t[lo] < t[i] - lookback_s:
            lo += 1
        if out[i] == "benign" and raw[lo:i].sum() >= min_count:      # chỉ đếm dự đoán gốc, không đếm cửa sổ đã nâng
            out[i] = "dos"
    res = pred.copy()
    res[order] = out
    return res


class DosHolder:
    """``hold_dos`` dạng tăng dần: nhớ các cửa sổ ``dos`` gần đây của từng host, dùng chung cho pipeline offline
    và cảm biến realtime (cửa sổ tới theo thứ tự thời gian). Cấu hình: ``pipeline.dos_hold`` (QĐ-074)."""

    def __init__(self, lookback_s, min_count):
        self.lookback_s, self.min_count = float(lookback_s), int(min_count)
        self.recent = {}                    # (session, host) -> deque thời điểm bắt đầu các cửa sổ dos gốc

    @classmethod
    def from_config(cls, cfg):
        h = ((cfg or {}).get("pipeline") or {}).get("dos_hold")
        return cls(h["lookback_s"], h["min_count"]) if h else None

    def apply(self, frame):
        """Sửa cột ``du_doan`` của bảng dự đoán tại chỗ; thêm cột ``giu_dos`` đánh dấu cửa sổ được nâng."""
        from collections import deque

        pred = frame["du_doan"].to_numpy(dtype=object).copy()
        start = frame["window_start"].to_numpy(float)
        host = frame["host"].astype(str).to_numpy()
        sess = frame["session"].astype(str).to_numpy() if "session" in frame else np.full(len(frame), "")
        held = np.zeros(len(frame), bool)
        for i in np.argsort(start, kind="stable"):
            q = self.recent.setdefault((sess[i], host[i]), deque())
            while q and q[0] < start[i] - self.lookback_s:
                q.popleft()
            if pred[i] == "benign" and len(q) >= self.min_count:
                pred[i], held[i] = "dos", True
            elif pred[i] == "dos":
                q.append(start[i])
        if len(self.recent) > 10000:        # dọn host không còn cửa sổ dos nào để state không phình
            self.recent = {k: q for k, q in self.recent.items() if q}
        frame["du_doan"] = pred
        frame["giu_dos"] = held
        return frame


def per_tool(frame, pred, rules) -> dict:
    groups = clf.class_groups(frame, rules)
    y = frame[clf.LABEL_COL].to_numpy()
    return {g: {"so_mau": int(m.sum()), "recall": round(float((pred[m] == y[m]).mean()), 4)}
            for g in sorted(set(groups[y == "dos"])) for m in [(groups == g) & (y == "dos")]}


def report(frame, pred, rules) -> dict:
    m = clf.multiclass_metrics(frame[clf.LABEL_COL], pred)
    return {"macro_f1": m["macro_f1"], "dos": m["theo_lop"]["dos"], "benign": m["theo_lop"]["benign"],
            "theo_cong_cu": per_tool(frame, pred, rules)}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Giữ nhãn dos theo host: chọn tham số trên validation, đo trên test.")
    ap.add_argument("prefixes", nargs="+")
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True, help="thư mục ghi dos_cham.json")
    a = ap.parse_args(argv)
    cfg = clf.classifier_config(load_config())
    rules = load_schedule()
    model = clf.load_model(a.model)
    data = clf.prepare_data(clf.load_data(a.prefixes, cfg["sessions"]), None, cfg["random_seed"], cfg["drop_train_duplicates"])
    val, test = data["validation"], data["test"]
    pv, pt = model.predict(val), model.predict(test)
    key = lambda f: (f["session"].astype(str) + "|" + f["host"].astype(str)).to_numpy()
    rows = []
    for lb in GRID_LOOKBACK_S:
        for mc in GRID_MIN_COUNT:
            p = hold_dos(pv, key(val), val["window_start"], lb, mc)
            r = clf.multiclass_metrics(val[clf.LABEL_COL], p)
            rows.append({"lookback_s": lb, "min_count": mc, "macro_f1": r["macro_f1"],
                         "recall_dos": r["theo_lop"]["dos"]["recall"], "precision_dos": r["theo_lop"]["dos"]["precision"]})
    best = max(rows, key=lambda r: (r["macro_f1"], -r["lookback_s"], r["min_count"]))
    out = {"validation": {"goc": report(val, pv, rules), "luoi": rows, "chon": best,
                          "sau_khi_giu": report(val, hold_dos(pv, key(val), val["window_start"], best["lookback_s"],
                                                                best["min_count"]), rules)},
           "test": {"goc": report(test, pt, rules),
                    "sau_khi_giu": report(test, hold_dos(pt, key(test), test["window_start"], best["lookback_s"],
                                                         best["min_count"]), rules)}}
    od = Path(a.out)
    od.mkdir(parents=True, exist_ok=True)
    (od / "dos_cham.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print("chọn:", best)
    for part in ("validation", "test"):
        for k in ("goc", "sau_khi_giu"):
            r = out[part][k]
            print(part, k, r["macro_f1"], r["dos"], r["theo_cong_cu"])
    return 0


if __name__ == "__main__":
    sys.exit(main())

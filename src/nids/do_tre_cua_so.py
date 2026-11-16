"""Độ trễ phát hiện của bộ phân loại theo độ dài cửa sổ host, đo trên lần chạy lab (QĐ-075, QĐ-081).

Với mỗi cấu hình (file cấu hình + mô hình phân loại học với cấu hình đó): trích xuất bản thu lab, dự đoán từng
cửa sổ host, rồi với mỗi đợt quét cổng hoặc DoS trong nhật ký lần chạy lấy **cửa sổ đầu tiên** của máy tấn công
hoặc máy nạn nhân được gán đúng nhãn. Độ trễ = thời điểm cửa sổ đó được chấm (cuối cửa sổ + thời gian chờ bắt
tay, như cảm biến realtime) trừ giờ bắt đầu đợt. Cũng đếm số cửa sổ ``benign`` của lần chạy bị gán tấn công.

Chỉ đo bộ phân loại: Gaussian và botnet không phụ thuộc phép so sánh này.

    cd src
    python -m nids.do_tre_cua_so ../data/pcap/lab/k2-*-test-1[234].pcap ../data/pcap/lab/k3-*-test-1[234].pcap \
        --nhat-ky ../data/run_logs --net 192.168.50.0/24 \
        --cau-hinh w10=../config/default.yaml:../models/phan_loai_rf_windows.joblib \
        --cau-hinh w20=../output/cfg_w20.yaml:../output/w20_mo_hinh/phan_loai_rf_windows.joblib \
        --out ../docs/hinh/do_tre_cua_so.json
"""

import argparse
import json
import statistics
import sys
import tempfile
from pathlib import Path

import numpy as np

from .classifier import load_model, predict_frame
from .config import load_config
from .pipeline import extract, load_windows
from .thuc_nghiem import attacks_from_runlog, load_runlog


def measure(pcap, runlog_dir, networks, config_path, model) -> list:
    cfg = load_config(config_path)
    observe = cfg["flow"]["handshake_observe_s"]
    with tempfile.TemporaryDirectory() as d:
        prefix = extract(pcap, d, networks, config_path)
        win = load_windows(prefix)
    pred = predict_frame(model, win)["du_doan"].to_numpy()
    host = win["host"].astype(str).to_numpy()
    ws, we = win["window_start"].to_numpy(float), win["window_end"].to_numpy(float)
    attacks = [a for a in attacks_from_runlog(load_runlog(runlog_dir, pcap), networks) if a.loai in ("port_scan", "dos")]
    in_attack = np.zeros(len(win), bool)
    rows = []
    for a in attacks:
        mine = np.isin(host, list(a.hosts))
        in_attack |= mine & (we > a.t0) & (ws < a.t1 + cfg["windows"]["flow"]["size_s"])
        ok = mine & (pred == a.loai) & (we > a.t0)
        rows.append({"pcap": Path(pcap).name, "nhan": a.loai,
                     "do_tre_s": round(float(we[ok].min() + observe - a.t0), 2) if ok.any() else None,
                     "so_cua_so_dung": int(ok.sum())})
    fa = int(((pred != "benign") & ~in_attack).sum())
    for r in rows:
        r["cua_so_bao_nham_ca_lan"] = fa
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="Độ trễ phát hiện theo độ dài cửa sổ, trên lần chạy lab.")
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--nhat-ky", required=True)
    ap.add_argument("--net", action="append", required=True)
    ap.add_argument("--cau-hinh", action="append", required=True, metavar="TEN=CONFIG:MODEL")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    out = {}
    for item in a.cau_hinh:
        name, rest = item.split("=", 1)
        config_path, model_path = rest.split(":", 1)
        model = load_model(model_path)
        rows = [r for p in a.pcap for r in measure(p, a.nhat_ky, a.net, config_path, model)]
        tong = {}
        for lab in ("port_scan", "dos"):
            rs = [r for r in rows if r["nhan"] == lab]
            lat = [r["do_tre_s"] for r in rs if r["do_tre_s"] is not None]
            tong[lab] = {"so_dot": len(rs), "phat_hien": len(lat), "do_tre_trung_vi_s": statistics.median(lat) if lat else None,
                         "do_tre_nho_nhat_s": min(lat) if lat else None, "do_tre_lon_nhat_s": max(lat) if lat else None}
        tong["cua_so_bao_nham"] = sum({r["pcap"]: r["cua_so_bao_nham_ca_lan"] for r in rows}.values())
        out[name] = {"cau_hinh": config_path, "mo_hinh": model_path, "tong": tong, "theo_dot": rows}
        print(name, json.dumps(tong, ensure_ascii=False), flush=True)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

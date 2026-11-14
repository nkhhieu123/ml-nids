"""Độ nhạy của bộ phân loại với tham số flow, đo bằng **trích xuất lại CIC và huấn luyện lại**.

``nids.do_nhay_flow`` chỉ đổi tham số rồi chấm bằng mô hình đã khóa trên lab. Ở đây mỗi cấu hình có bảng đặc trưng
CIC-IDS2017 (thứ Tư, thứ Sáu) trích xuất lại với tham số đó; với mỗi bảng: gán nhãn lại, chia tập lại, fit Random
Forest với tham số đã chọn ở C07-T04 trên train, đo trên **validation**. Không đọc test.

    cd src
    python -m nids.feature_export <PCAP thứ Tư> --out ../output/features_h1 --name cic17_wednesday \
        --net 192.168.10.0/24 --net 172.16.0.0/24 --config <cấu hình đổi một tham số>        # tương tự thứ Sáu
    python -m nids.do_nhay_flow_cic hien_tai=../output/features h1=../output/features_h1 \
        --chon ../docs/hinh/phan_loai_chon.json --out ../docs/hinh
"""

import argparse
import json
import sys
import time
from pathlib import Path

from . import classifier as clf
from .config import load_config
from .labeling import label_flows, label_windows, labels_path, load_flows_for_labels, load_schedule, load_windows_for_labels
from .splits import split_tables

SESSIONS = ("cic17_wednesday", "cic17_friday")


def prepare_dir(directory, cfg, rules) -> list:
    """Gán nhãn và chia tập cho bảng trong ``directory`` nếu chưa có; trả về danh sách tiền tố."""
    prefixes = []
    for s in SESSIONS:
        prefix = Path(directory) / s
        flows_path, win_path = f"{prefix}.flows.csv", f"{prefix}.windows.csv"
        if not labels_path(win_path).exists():
            flows = load_flows_for_labels(flows_path)
            fl = label_flows(flows, rules, cfg["labeling"]["tolerance_s"])
            fl.to_csv(labels_path(flows_path), index=False)
            label_windows(load_windows_for_labels(win_path), flows, fl,
                          cfg["labeling"]["window_min_attack_share"]).to_csv(labels_path(win_path), index=False)
        if not Path(f"{prefix}.windows.split.csv").exists():
            sp = cfg["split"]
            ratios = (sp["train"], sp["validation"], sp["test"])
            split_tables(flows_path, rules, ratios, sp["embargo_s"], sp.get("stratify_scan_proto", False))   # tự ghi file
        prefixes.append(str(prefix))
    return prefixes


def evaluate_dir(directory, cfg, rules, best) -> dict:
    t = time.perf_counter()
    ccfg = clf.classifier_config(cfg)
    df = clf.load_data(prepare_dir(directory, cfg, rules), ccfg["sessions"])
    data = clf.prepare_data(df, best["ty_le_can_bang"], ccfg["random_seed"], ccfg["drop_train_duplicates"])
    model = clf.AttackClassifier("random_forest", best["tham_so"], ccfg["random_seed"]).fit(data["train"], data["train_full"])
    m = clf.multiclass_metrics(data["validation"][clf.LABEL_COL], model.predict(data["validation"]))
    meta = json.loads(Path(directory, f"{SESSIONS[0]}.meta.json").read_text(encoding="utf-8"))["tham_so"]
    return {"tham_so_flow": {**meta["flow"], "handshake_observe_s": meta["cua_so"]["handshake_observe_s"]},
            "cua_so": {k: v for k, v in meta["cua_so"].items() if k != "handshake_observe_s"},
            "lop_train": data["info"]["lop_train"], "lop_validation": data["info"]["lop_validation"],
            "macro_f1_validation": m["macro_f1"],
            **{f"{k}_{c}": m["theo_lop"][c][k] for c in ("port_scan", "dos") for k in ("precision", "recall")},
            "giay": round(time.perf_counter() - t, 1)}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Độ nhạy tham số flow bằng trích xuất lại CIC và huấn luyện lại.")
    ap.add_argument("bang", nargs="+", help="tên=thư mục bảng đặc trưng, ví dụ h1=../output/features_h1")
    ap.add_argument("--chon", required=True)
    ap.add_argument("--out", required=True, help="thư mục ghi kết quả")
    ap.add_argument("--config", help="cấu hình dùng khi gán nhãn, chia tập (ví dụ embargo bằng độ dài cửa sổ)")
    ap.add_argument("--ten", default="flow_do_nhay_cic", help="tên file JSON kết quả, không có đuôi")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    rules = load_schedule()
    best = json.loads(Path(a.chon).read_text(encoding="utf-8"))["mo_hinh"]["random_forest"]["tot_nhat"]
    out = {}
    for item in a.bang:
        name, directory = item.split("=", 1)
        out[name] = evaluate_dir(directory, cfg, rules, best)
        print(name, json.dumps(out[name], ensure_ascii=False), flush=True)
    od = Path(a.out)
    od.mkdir(parents=True, exist_ok=True)
    (od / f"{a.ten}.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Độ nhạy của kết quả phát hiện với bốn tham số flow, đo trên các lần chạy ``val`` của lab.

QĐ-017 và QĐ-023 đặt tạm ``flow.idle_timeout_s`` = 60, ``active_timeout_s`` = 120, ``close_grace_s`` = 10 và
``handshake_observe_s`` = 3, hẹn chỉnh trên validation. Ở đây mỗi lần đổi một tham số, trích xuất lại đặc trưng
của các PCAP ``val`` với tham số đó rồi chấm bằng **mô hình đã khóa** (không huấn luyện lại), so với nhật ký lần
chạy. Mô hình được học với bộ tham số hiện tại, nên phép đo này trả lời "kết quả có đổi khi tham số lệch đi
không", không tìm bộ tham số tối ưu tuyệt đối (muốn vậy phải trích xuất và huấn luyện lại toàn bộ CIC).

    cd src
    python -m nids.do_nhay_flow ../data/pcap/lab/*-val-01.pcap --nhat-ky ../data/run_logs --out ../docs/hinh
"""

import argparse
import copy
import json
import sys
import tempfile
from pathlib import Path

import yaml

from .config import DEFAULT_CONFIG, load_config
from .thuc_nghiem import run_scenario, load_runlog

GRID = {"idle_timeout_s": (30, 120), "active_timeout_s": (60, 300), "close_grace_s": (5, 20),
        "handshake_observe_s": (1, 5)}


def settings(base) -> list:
    """Cấu hình hiện tại, rồi từng tham số đổi sang từng giá trị thử (các tham số khác giữ nguyên)."""
    out = [dict(base)]
    for key, values in GRID.items():
        for v in values:
            if v != base[key]:
                out.append({**base, key: v})
    return out


def summarize(scenarios) -> dict:
    dots = [d for s in scenarios for d in s["phat_hien"]["theo_dot"]]
    by = {}
    for d in dots:
        g = by.setdefault(d["loai"], {"so_dot": 0, "phat_hien": 0, "cua_so_canh_bao": 0, "do_tre_s": []})
        g["so_dot"] += 1
        g["phat_hien"] += d["phat_hien"]
        g["cua_so_canh_bao"] += d["so_canh_bao"]
        if d["phat_hien"]:
            g["do_tre_s"].append(d["do_tre_s"])
    fa = {}
    for s in scenarios:
        for m, n in s["bao_gia"]["theo_module"].items():
            fa[m] = fa.get(m, 0) + n
    return {"theo_loai": by, "bao_gia": sum(fa.values()), "bao_gia_theo_module": fa,
            "flow": sum(s["hieu_nang"]["flow"] or 0 for s in scenarios),
            "cua_so": sum(s["hieu_nang"]["cua_so"] for s in scenarios)}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Độ nhạy của kết quả phát hiện với tham số flow, trên lần chạy val của lab.")
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--net", action="append", help="mạng giám sát; mặc định lab.subnet")
    ap.add_argument("--nhat-ky", required=True)
    ap.add_argument("--out", required=True, help="thư mục ghi flow_do_nhay.json")
    a = ap.parse_args(argv)
    raw = yaml.safe_load(Path(DEFAULT_CONFIG).read_text(encoding="utf-8"))
    nets = a.net or [raw["lab"]["subnet"]]
    base = {k: raw["flow"][k] for k in GRID}
    rows = []
    for st in settings(base):
        cfg_raw = copy.deepcopy(raw)
        cfg_raw["flow"].update(st)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "config.yaml"
            path.write_text(yaml.safe_dump(cfg_raw, allow_unicode=True), encoding="utf-8")
            cfg = load_config(path)
            scenarios = [run_scenario(p, nets, cfg, runlog=load_runlog(a.nhat_ky, p), config_path=str(path))
                         for p in a.pcap]
        row = {"tham_so": st, "doi": {k: v for k, v in st.items() if v != base[k]}, **summarize(scenarios)}
        rows.append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)
    od = Path(a.out)
    od.mkdir(parents=True, exist_ok=True)
    out = {"hien_tai": base, "pcap": [Path(p).name for p in a.pcap], "cac_lan_thu": rows}
    (od / "flow_do_nhay.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Đã ghi: {od / 'flow_do_nhay.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

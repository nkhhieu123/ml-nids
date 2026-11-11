"""Chặng 11 — tổng hợp kết quả các lần chạy lab theo biến thể, và vẽ biểu đồ (C11-T07, C11-T08).

Đầu vào là các file JSON do ``nids.thuc_nghiem`` ghi (mỗi file một nhóm kịch bản) và nhật ký lần chạy
(``data/run_logs/<run_id>.json``) để lấy số gói bắt được và số gói nhân bỏ.

    cd src
    python -m nids.thuc_nghiem_lab ../docs/hinh/thuc_nghiem/lab/k*.json ../docs/hinh/thuc_nghiem/lab/doi_chung.json \
        --nhat-ky ../data/run_logs --out ../docs/hinh/thuc_nghiem/lab
"""

import argparse
import json
import statistics
import sys
from pathlib import Path

MODULES = ("anomaly", "attack_classification", "botnet_topology")


def variant_of(run_id) -> str:
    """'k3-dos-muc2-test-01(.pcap)' -> 'k3-dos-muc2'."""
    parts = Path(run_id).stem.split("-")
    return "-".join(parts[:-2])


def per_variant(scenarios, logs=None) -> list:
    """Gộp các lần chạy cùng biến thể: số đợt, phát hiện, bỏ sót, độ trễ, báo động giả mỗi giờ, hiệu năng."""
    groups = {}
    for s in scenarios:
        groups.setdefault(variant_of(s["pcap"]), []).append(s)
    rows = []
    for v, runs in sorted(groups.items()):
        dots = [d for s in runs for d in s["phat_hien"]["theo_dot"]]
        lat = sorted(d["do_tre_s"] for d in dots if d["phat_hien"])
        ano = sorted(d["anomaly_do_tre_s"] for d in dots if d.get("anomaly_do_tre_s") is not None)
        hours = sum(s["gio"] for s in runs)
        fa = {m: sum(s["bao_gia"]["theo_module"].get(m, 0) for s in runs) for m in MODULES}
        row = {"bien_the": v, "so_lan_chay": len(runs), "so_dot": len(dots),
               "phat_hien": sum(d["phat_hien"] for d in dots), "bo_sot": sum(not d["phat_hien"] for d in dots),
               "do_tre_s": lat, "do_tre_trung_vi_s": statistics.median(lat) if lat else None,
               "anomaly_thay": len(ano), "anomaly_do_tre_trung_vi_s": statistics.median(ano) if ano else None,
               "gio": round(hours, 3), "bao_gia": sum(fa.values()), "bao_gia_theo_module": fa,
               "bao_gia_moi_gio": round(sum(fa.values()) / hours, 1) if hours else None,
               "bao_gia_tung_lan": [s["bao_gia"]["so_su_kien_bao_gia"] for s in runs],
               "flow": sum(s["hieu_nang"]["flow"] or 0 for s in runs),
               "cua_so": sum(s["hieu_nang"]["cua_so"] for s in runs),
               "thoi_gian_xu_ly_s": round(sum(sum(s["hieu_nang"]["thoi_gian_s"].values()) for s in runs), 1),
               "thoi_luong_thu_s": round(sum(s["khoang_giay"] for s in runs), 1)}
        if logs:
            caps = [logs[Path(s["pcap"]).stem]["ban_thu"] for s in runs if Path(s["pcap"]).stem in logs]
            row["goi_bat_duoc"] = sum(c["goi_bat_duoc"] or 0 for c in caps)
            row["goi_nhan_bo"] = sum(c["goi_nhan_bo"] or 0 for c in caps)
        rows.append(row)
    return rows


def totals(rows) -> dict:
    lat = sorted(x for r in rows for x in r["do_tre_s"])
    hours = sum(r["gio"] for r in rows)
    t = {"so_lan_chay": sum(r["so_lan_chay"] for r in rows), "so_dot": sum(r["so_dot"] for r in rows),
         "phat_hien": sum(r["phat_hien"] for r in rows), "bo_sot": sum(r["bo_sot"] for r in rows),
         "do_tre_trung_vi_s": statistics.median(lat) if lat else None, "do_tre_lon_nhat_s": lat[-1] if lat else None,
         "gio": round(hours, 3), "bao_gia": sum(r["bao_gia"] for r in rows),
         "bao_gia_theo_module": {m: sum(r["bao_gia_theo_module"][m] for r in rows) for m in MODULES},
         "goi_bat_duoc": sum(r.get("goi_bat_duoc", 0) for r in rows),
         "goi_nhan_bo": sum(r.get("goi_nhan_bo", 0) for r in rows),
         "thoi_gian_xu_ly_s": round(sum(r["thoi_gian_xu_ly_s"] for r in rows), 1),
         "thoi_luong_thu_s": round(sum(r["thoi_luong_thu_s"] for r in rows), 1)}
    t["ty_le_phat_hien"] = round(t["phat_hien"] / t["so_dot"], 3) if t["so_dot"] else None
    t["bao_gia_moi_gio"] = round(t["bao_gia"] / hours, 1) if hours else None
    return t


def plot(rows, out_dir) -> list:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out_dir = Path(out_dir)
    paths = []
    atk = [r for r in rows if r["so_dot"]]
    fig, ax = plt.subplots(figsize=(8, 0.5 * len(atk) + 1.6))
    for i, r in enumerate(atk):
        ax.scatter(r["do_tre_s"], [i] * len(r["do_tre_s"]), color="#1f77b4", zorder=3)
        ax.text(1.01, i, f"{r['phat_hien']}/{r['so_dot']} đợt" + (f", bỏ sót {r['bo_sot']}" if r["bo_sot"] else ""),
                transform=ax.get_yaxis_transform(), va="center", fontsize=9,
                color="#d62728" if r["bo_sot"] else "black")
    ax.set_yticks(range(len(atk)), [r["bien_the"] for r in atk])
    ax.set_ylim(len(atk) - 0.5, -0.5)
    ax.set_xlim(left=0)
    ax.set_xlabel("Độ trễ phát hiện (giây, gồm thời gian tích lũy cửa sổ)")
    ax.set_title("Lab: độ trễ phát hiện của từng đợt tấn công")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    paths.append(out_dir / "lab_do_tre.png")
    fig.savefig(paths[-1], dpi=130)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8, 0.45 * len(rows) + 1.6))
    left = [0.0] * len(rows)
    for m, c in zip(MODULES, ("#7f7f7f", "#ff7f0e", "#2ca02c")):
        vals = [r["bao_gia_theo_module"][m] / r["gio"] if r["gio"] else 0 for r in rows]
        ax.barh(range(len(rows)), vals, left=left, color=c, label=m)
        left = [a + b for a, b in zip(left, vals)]
    ax.set_yticks(range(len(rows)), [r["bien_the"] for r in rows])
    ax.invert_yaxis()
    ax.set_xlabel("Sự kiện báo động giả mỗi giờ")
    ax.set_title("Lab: báo động giả theo biến thể và module")
    ax.legend(fontsize=8)
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    paths.append(out_dir / "lab_bao_gia.png")
    fig.savefig(paths[-1], dpi=130)
    plt.close(fig)
    return [str(p) for p in paths]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Chặng 11: tổng hợp kết quả lab theo biến thể và vẽ biểu đồ.")
    ap.add_argument("ket_qua", nargs="+", help="các file JSON của nids.thuc_nghiem")
    ap.add_argument("--nhat-ky", help="thư mục nhật ký lần chạy, để lấy số gói bắt được và nhân bỏ")
    ap.add_argument("--out", required=True, help="thư mục ghi tong_hop.json và ảnh")
    ap.add_argument("--khong-ve", action="store_true")
    a = ap.parse_args(argv)
    scenarios = [s for p in a.ket_qua for s in json.loads(Path(p).read_text(encoding="utf-8"))["kich_ban"]]
    logs = None
    if a.nhat_ky:
        logs = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in Path(a.nhat_ky).glob("*.json")}
    rows = per_variant(scenarios, logs)
    out = {"theo_bien_the": rows, "tong": totals(rows)}
    od = Path(a.out)
    od.mkdir(parents=True, exist_ok=True)
    if not a.khong_ve:
        out["anh"] = [Path(p).name for p in plot(rows, od)]
    (od / "tong_hop.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    for r in rows:
        print(f"{r['bien_the']:<16} {r['so_lan_chay']} lần | {r['phat_hien']}/{r['so_dot']} đợt | trễ {r['do_tre_s']} | "
              f"báo giả {r['bao_gia']} ({r['bao_gia_moi_gio']}/giờ) {r['bao_gia_theo_module']}")
    print("Tổng:", out["tong"])
    return 0


if __name__ == "__main__":
    sys.exit(main())

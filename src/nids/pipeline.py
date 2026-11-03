"""Pipeline offline: PCAP → flow, cửa sổ → ba module → cảnh báo (Chặng 9).

- C09-T01: nạp artifact (mô hình, biến đổi, ngưỡng) và kiểm tra schema trước khi chạy
  (docs/53_nap_artifact.md, QĐ-043).

    python -m nids.pipeline kiem-tra

Ba module dùng mô hình đã lưu ở Chặng 6–8; pipeline không học gì.
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .config import PROJECT_ROOT, load_config
from .scope import MODULE_ANOMALY, MODULE_ATTACK, MODULE_BOTNET, MODULES

# File mô hình mặc định của từng module, trong paths.model_dir
DEFAULT_MODELS = {MODULE_ANOMALY: "gaussian_windows.joblib", MODULE_ATTACK: "phan_loai_rf_windows.joblib",
                  MODULE_BOTNET: "botnet_rf.joblib"}
# Bảng đầu vào của từng module
INPUT_TABLE = {MODULE_ANOMALY: "windows", MODULE_ATTACK: "windows", MODULE_BOTNET: "host_windows_120s"}
ERROR, WARNING = "loi", "canh_bao"


@dataclass
class Artifact:
    module: str
    path: Path
    model: object
    meta: dict = field(default_factory=dict)

    @property
    def features(self) -> list:
        return list(self.model.features)

    @property
    def threshold(self):
        return getattr(self.model, "threshold", None)


def pipeline_config(cfg=None) -> dict:
    p = dict((cfg or {}).get("pipeline") or {})
    model_dir = Path((cfg or {}).get("paths", {}).get("model_dir", "models"))
    if not model_dir.is_absolute():
        model_dir = PROJECT_ROOT / model_dir
    models = {m: str(model_dir / f) for m, f in DEFAULT_MODELS.items()}
    models.update({k: v if Path(v).is_absolute() else str(PROJECT_ROOT / v) for k, v in (p.get("models") or {}).items()})
    p["models"] = models
    p.setdefault("mode", "doc_lap")
    p.setdefault("merge_gap_s", 30.0)
    return p


def _loader(module):
    if module == MODULE_ANOMALY:
        from .gaussian import load_model
    elif module == MODULE_ATTACK:
        from .classifier import load_model
    else:
        from .botnet import load_model
    return load_model


def load_artifacts(cfg=None, modules=MODULES) -> dict:
    """Nạp mô hình của từng module kèm file .json metadata. Lỗi nạp (thiếu file, sai loại) báo ngay."""
    pc = pipeline_config(cfg)
    out = {}
    for m in modules:
        path = Path(pc["models"][m])
        if not path.exists():
            raise FileNotFoundError(f"{m}: không có file mô hình {path}")
        model = _loader(m)(path)
        meta_path = path.with_suffix(".json")
        meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
        out[m] = Artifact(m, path, model, meta)
    return out


def expected_inputs(module) -> list:
    """Cột đầu vào hợp lệ của module: đặc trưng cửa sổ 10 giây theo schema, hoặc đặc trưng host–cửa sổ 120 giây."""
    if module in (MODULE_ANOMALY, MODULE_ATTACK):
        from .dataset import feature_columns
        return feature_columns("windows")
    from .graph_features import BEACON_FEATURES, GRAPH_FEATURES
    return GRAPH_FEATURES + BEACON_FEATURES


def check_artifact(a: Artifact) -> list:
    """Danh sách vấn đề (mức, nội dung) của một artifact: đặc trưng, metadata, ngưỡng, phiên bản mã."""
    problems = []
    allowed = set(expected_inputs(a.module))
    missing = [f for f in a.features if f not in allowed]
    if missing:
        problems.append((ERROR, f"đặc trưng không có trong schema đầu vào ({INPUT_TABLE[a.module]}): {missing}"))
    if not a.meta:
        problems.append((ERROR, "thiếu file .json metadata"))
    elif a.meta.get("dac_trung") and list(a.meta["dac_trung"]) != a.features:
        problems.append((ERROR, "danh sách đặc trưng trong .json khác mô hình"))
    if a.module in (MODULE_ANOMALY, MODULE_BOTNET) and a.threshold is None:
        problems.append((ERROR, "mô hình chưa có ngưỡng"))
    if a.module == MODULE_ATTACK:
        from .scope import ATTACK_LABELS
        classes = set(a.model.classes)
        if not classes <= set(ATTACK_LABELS):
            problems.append((ERROR, f"lớp ngoài tập nhãn đã chốt: {sorted(classes - set(ATTACK_LABELS))}"))
    src = a.meta.get("ma_nguon") or {}
    if src.get("co_sua_chua_commit"):
        problems.append((WARNING, f"tạo khi mã nguồn có sửa chưa commit (commit {str(src.get('commit'))[:8]}); "
                                  "nên huấn luyện lại từ mã đã commit"))
    if not src.get("commit"):
        problems.append((WARNING, "metadata không ghi commit mã nguồn"))
    return problems


def check_table(df, artifact) -> None:
    """Báo lỗi nếu bảng đầu vào thiếu cột đặc trưng mà mô hình cần."""
    missing = [f for f in artifact.features if f not in df.columns]
    if missing:
        raise ValueError(f"{artifact.module}: bảng đầu vào thiếu cột {missing}")


def check_all(cfg=None) -> dict:
    """Nạp và kiểm tra mọi artifact; trả về báo cáo (không dừng ở cảnh báo, dừng ở lỗi nạp)."""
    arts = load_artifacts(cfg)
    report = {}
    for m, a in arts.items():
        report[m] = {"file": str(a.path), "loai": type(a.model).__name__, "so_dac_trung": len(a.features),
                     "nguong": a.threshold, "commit": (a.meta.get("ma_nguon") or {}).get("commit"),
                     "van_de": [{"muc": lv, "noi_dung": msg} for lv, msg in check_artifact(a)]}
    report["hop_le"] = all(p["muc"] != ERROR for m in MODULES for p in report[m]["van_de"])
    return report


def cmd_check(args):
    rep = check_all(load_config(args.config))
    for m in MODULES:
        r = rep[m]
        print(f"{m}: {r['loai']}, {r['so_dac_trung']} đặc trưng, ngưỡng {r['nguong']}, commit {str(r['commit'])[:8]}")
        for p in r["van_de"]:
            print(f"   [{p['muc']}] {p['noi_dung']}")
    print("Hợp lệ:", rep["hop_le"])
    if args.out:
        Path(args.out).write_text(json.dumps(rep, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return 0 if rep["hop_le"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Pipeline offline: PCAP qua ba module, cảnh báo hợp nhất.")
    sub = parser.add_subparsers(dest="lenh", required=True)
    p = sub.add_parser("kiem-tra", help="nạp và kiểm tra artifact của ba module (C09-T01)")
    p.add_argument("--out", help="ghi báo cáo JSON")
    p.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    p.set_defaults(func=cmd_check)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

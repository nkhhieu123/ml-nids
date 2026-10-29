"""Đọc cấu hình chung từ config/default.yaml."""

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "default.yaml"


def load_config(path=None) -> dict:
    """Trả về cấu hình dạng dict. ``path`` mặc định là config/default.yaml."""
    path = Path(path) if path else DEFAULT_CONFIG
    with path.open(encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    _validate(cfg, path)
    return cfg


def _validate(cfg, path):
    for name in ("flow", "graph"):
        win = cfg["windows"][name]
        if not 0 < win["step_s"] <= win["size_s"]:
            raise ValueError(
                f"{path}: windows.{name} cần 0 < step_s <= size_s, nhận {win}"
            )
    for name in ("idle_timeout_s", "active_timeout_s", "close_grace_s",
                 "direction_memory_s", "fragment_timeout_s", "handshake_observe_s"):
        if cfg["flow"][name] <= 0:
            raise ValueError(f"{path}: flow.{name} phải > 0")

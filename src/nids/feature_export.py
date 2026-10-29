"""Xuất bảng đặc trưng flow và cửa sổ host kèm schema và metadata (C04-T08).

Một lượt đọc PCAP cho bốn file trong thư mục ``--out``:

    <tên>.flows.csv     một dòng một flow (C04-T01 đến T04)
    <tên>.windows.csv   một dòng một cặp (host, cửa sổ) (C04-T05 đến T07)
    <tên>.schema.json   kiểu, đơn vị, vai trò, mô tả của từng cột
    <tên>.meta.json     nguồn, mã băm, tham số, phiên bản mã, thống kê

    python -m nids.feature_export data/pcap/<file>.pcap --net 192.168.10.0/24 --out output/features

``read_table`` đọc lại một bảng đúng kiểu và từ chối bảng không khớp schema.
Chi tiết ở docs/25_xuat_bang_dac_trung.md (QĐ-024).
"""

import argparse
import csv
import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .config import PROJECT_ROOT, load_config
from .flow_features import BASIC_FEATURES, STAT_FEATURES
from .flows import CSV_COLUMNS as FLOW_COLUMNS, FlowSettings, csv_row as flow_row
from .manifest import load_manifest, sha256_file
from .packets import ParseStats, extract_packets
from .window_features import (
    CSV_COLUMNS as WINDOW_COLUMNS, WINDOW_FEATURES, WindowPipeline, csv_row as window_row,
)

SCHEMA_VERSION = "1.0"

# Vai trò của cột
ROLE_FEATURE = "dac_trung"     # đưa vào mô hình
ROLE_ID = "dinh_danh"          # IP, cổng server, thời điểm: dùng để gán nhãn, chia dữ liệu; không đưa vào mô hình
ROLE_CONTEXT = "ngu_canh"      # thuộc tính phân loại của flow; dùng có cân nhắc
ROLE_CHECK = "kiem_tra"        # kiểm tra chất lượng dữ liệu
ROLES = (ROLE_FEATURE, ROLE_ID, ROLE_CONTEXT, ROLE_CHECK)

# Kiểu dữ liệu trong CSV
TYPE_INT, TYPE_FLOAT, TYPE_STR = "int", "float", "str"
TYPE_TIME = "thoi_diem"        # giây từ epoch UTC, chuỗi thập phân 9 chữ số
TYPES = (TYPE_INT, TYPE_FLOAT, TYPE_STR, TYPE_TIME)

# Cột không phải đặc trưng: (kiểu, đơn vị, vai trò, có thể trống, mô tả)
FLOW_BASE = {
    "first_index": (TYPE_INT, "", ROLE_ID, False, "Chỉ số packet đầu tiên của flow trong file"),
    "first_ts": (TYPE_TIME, "giây", ROLE_ID, True, "Thời điểm gói đầu (nhỏ nhất) của flow"),
    "last_ts": (TYPE_TIME, "giây", ROLE_ID, True, "Thời điểm gói cuối (lớn nhất) của flow"),
    "ip_version": (TYPE_INT, "", ROLE_CONTEXT, False, "4 hoặc 6"),
    "protocol": (TYPE_INT, "", ROLE_CONTEXT, False, "Số hiệu giao thức: 6 TCP, 17 UDP, 1 ICMP, ..."),
    "fwd_ip": (TYPE_STR, "", ROLE_ID, False, "IP của client (bên mở kết nối, QĐ-016)"),
    "fwd_port": (TYPE_INT, "", ROLE_ID, True, "Cổng của client; trống nếu giao thức không có cổng"),
    "bwd_ip": (TYPE_STR, "", ROLE_ID, False, "IP của server"),
    "bwd_port": (TYPE_INT, "", ROLE_ID, True, "Cổng của server; trống nếu giao thức không có cổng"),
    "direction_basis": (TYPE_STR, "", ROLE_CHECK, False, "Quy tắc xác định client (QĐ-016)"),
    "continuation": (TYPE_INT, "", ROLE_CONTEXT, False, "1 nếu là phần tiếp nối của kết nối trước (QĐ-017)"),
    "end_reason": (TYPE_STR, "", ROLE_CONTEXT, False, "Lý do kết thúc flow (QĐ-017)"),
    "fragments_attached": (TYPE_INT, "gói", ROLE_CHECK, False, "Số mảnh IP không mang cổng gắn vào flow"),
    "payload_unknown": (TYPE_INT, "gói", ROLE_CHECK, False, "Số gói TCP/UDP không tính được payload"),
}
WINDOW_BASE = {
    "host": (TYPE_STR, "", ROLE_ID, False, "Địa chỉ IP của host"),
    "window_start": (TYPE_TIME, "giây", ROLE_ID, False, "Đầu cửa sổ (tính cả)"),
    "window_end": (TYPE_TIME, "giây", ROLE_ID, False, "Cuối cửa sổ (không tính)"),
    "packets_out": (TYPE_INT, "gói", ROLE_FEATURE, False, "Số gói host gửi trong cửa sổ"),
    "packets_in": (TYPE_INT, "gói", ROLE_FEATURE, False, "Số gói host nhận trong cửa sổ"),
    "bytes_out": (TYPE_INT, "byte", ROLE_FEATURE, False, "Tổng ip_len host gửi"),
    "bytes_in": (TYPE_INT, "byte", ROLE_FEATURE, False, "Tổng ip_len host nhận"),
    "first_ts": (TYPE_TIME, "giây", ROLE_ID, False, "Gói đầu của host trong cửa sổ"),
    "last_ts": (TYPE_TIME, "giây", ROLE_ID, False, "Gói cuối của host trong cửa sổ"),
}

# Đặc trưng là số nguyên (đếm); các đặc trưng còn lại là số thực
INT_FEATURES = {
    "packets", "fwd_packets", "bwd_packets", "bytes", "fwd_bytes", "bwd_bytes",
    "payload_bytes", "fwd_payload_bytes", "bwd_payload_bytes",
    "syn_count", "fin_count", "rst_count", "psh_count", "ack_count", "urg_count", "ece_count",
    "cwr_count", "dst_hosts", "dst_ports", "dst_host_ports", "new_conn_out", "src_hosts",
    "new_conn_in", "tcp_attempts_out", "incomplete_out", "no_reply_out", "rejected_out",
    "half_open_out", "tcp_attempts_in", "incomplete_in",
    "fwd_pkt_len_min", "fwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_max",
    "pkt_len_min", "pkt_len_max",
}
# Đặc trưng có thể trống (không có dữ liệu để tính, docs/20, 21, 23, 24)
NULLABLE_FEATURES = {
    "payload_bytes", "fwd_payload_bytes", "bwd_payload_bytes", "duration_s",
    *(f"{p}_{s}" for p in ("fwd_pkt_len", "bwd_pkt_len", "iat", "fwd_iat", "bwd_iat")
      for s in ("min", "max", "mean", "std")),
    "dst_port_entropy", "incomplete_ratio_out", "incomplete_ratio_in",
}


def _feature_columns(features: dict) -> dict:
    cols = {}
    for name, (unit, text) in features.items():
        kind = TYPE_INT if name in INT_FEATURES else TYPE_FLOAT
        cols[name] = (kind, unit, ROLE_FEATURE, name in NULLABLE_FEATURES, text)
    return cols


def table_schemas() -> dict:
    """Schema của hai bảng: {bảng: [{ten, kieu, don_vi, vai_tro, co_the_trong, mo_ta}]}."""
    defs = {
        "flows": {**FLOW_BASE, **_feature_columns(BASIC_FEATURES), **_feature_columns(STAT_FEATURES)},
        "windows": {**WINDOW_BASE, **_feature_columns(WINDOW_FEATURES)},
    }
    order = {"flows": FLOW_COLUMNS, "windows": WINDOW_COLUMNS}
    out = {}
    for table, columns in order.items():
        missing = set(columns) ^ set(defs[table])
        if missing:
            raise RuntimeError(f"schema bảng {table} thiếu hoặc thừa cột: {sorted(missing)}")
        out[table] = [
            {"ten": c, "kieu": defs[table][c][0], "don_vi": defs[table][c][1],
             "vai_tro": defs[table][c][2], "co_the_trong": defs[table][c][3],
             "mo_ta": defs[table][c][4]}
            for c in columns
        ]
    return out


def schema_document() -> dict:
    return {
        "phien_ban_schema": SCHEMA_VERSION,
        "vai_tro": {
            ROLE_FEATURE: "Đưa vào mô hình",
            ROLE_ID: "Chỉ để gán nhãn, chia dữ liệu, truy vết; không đưa vào mô hình (tránh học thuộc địa chỉ)",
            ROLE_CONTEXT: "Thuộc tính phân loại của flow; chỉ dùng nếu chứng minh được không gây rò rỉ",
            ROLE_CHECK: "Kiểm tra chất lượng dữ liệu",
        },
        "kieu": {
            TYPE_INT: "Số nguyên", TYPE_FLOAT: "Số thực", TYPE_STR: "Chuỗi",
            TYPE_TIME: "Giây từ epoch UTC, chuỗi thập phân 9 chữ số",
        },
        "o_trong": "Ô trống nghĩa là không có dữ liệu để tính (không phải 0)",
        "bang": table_schemas(),
    }


def _git_version() -> dict:
    def git(*args):
        try:
            return subprocess.run(["git", *args], cwd=PROJECT_ROOT, capture_output=True,
                                  text=True, timeout=10, check=True).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return None
    commit = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--", "src", "config")
    return {"commit": commit, "co_sua_chua_commit": None if status is None else bool(status)}


def _source_hash(path: Path, compute: bool) -> dict:
    if compute:
        return {"sha256": sha256_file(path), "nguon_ma_bam": "tinh_lai"}
    for row in load_manifest():
        if row["sha256"] and row["file"].replace("\\", "/").split("/")[-1] == path.name:
            return {"sha256": row["sha256"], "nguon_ma_bam": f"manifest:{row['id']}"}
    return {"sha256": None, "nguon_ma_bam": None}


def export(path, out_dir, name=None, networks=None, config_path=None, compute_hash=False) -> dict:
    """Ghi bốn file; trả về metadata."""
    path = Path(path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = name or path.stem
    cfg = load_config(config_path)
    settings = FlowSettings.from_config(cfg)
    win = cfg["windows"]["flow"]
    observe_s = cfg["flow"]["handshake_observe_s"]
    files = {k: out_dir / f"{name}.{k}" for k in ("flows.csv", "windows.csv", "schema.json", "meta.json")}

    started = time.time()
    stats = ParseStats()
    counts = {"flows": 0, "windows": 0}
    with open(files["flows.csv"], "w", newline="", encoding="utf-8") as ff, \
            open(files["windows.csv"], "w", newline="", encoding="utf-8") as fw:
        flow_writer = csv.DictWriter(ff, fieldnames=FLOW_COLUMNS)
        win_writer = csv.DictWriter(fw, fieldnames=WINDOW_COLUMNS)
        flow_writer.writeheader()
        win_writer.writeheader()

        def write_flow(flow):
            flow_writer.writerow(flow_row(flow))
            counts["flows"] += 1

        pipe = WindowPipeline(settings, win["size_s"], win["step_s"], networks, observe_s,
                              flow_sink=write_flow)
        for rec in extract_packets(path, stats):
            for w in pipe.add(rec):
                win_writer.writerow(window_row(w))
                counts["windows"] += 1
        for w in pipe.finish():
            win_writer.writerow(window_row(w))
            counts["windows"] += 1

    schema = schema_document()
    files["schema.json"].write_text(json.dumps(schema, ensure_ascii=False, indent=2), encoding="utf-8")
    meta = {
        "phien_ban_schema": SCHEMA_VERSION,
        "tao_luc_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "thoi_gian_chay_s": round(time.time() - started, 1),
        "nguon": {"file": str(path), "kich_thuoc_byte": path.stat().st_size,
                  **_source_hash(path, compute_hash)},
        "ma_nguon": {**_git_version(), "python": platform.python_version()},
        "tham_so": {
            "flow": settings.__dict__,
            "cua_so": {"size_s": win["size_s"], "step_s": win["step_s"],
                       "handshake_observe_s": observe_s,
                       "dai_mang": None if networks is None else list(networks)},
        },
        "bang": {
            "flows": {"file": files["flows.csv"].name, "so_dong": counts["flows"]},
            "windows": {"file": files["windows.csv"].name, "so_dong": counts["windows"]},
            "schema": files["schema.json"].name,
        },
        "thong_ke": {"packet": stats.as_dict(), "flow": pipe.flows.summary(),
                     "cua_so": pipe.windows.summary()},
    }
    files["meta.json"].write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return meta


_PARSERS = {TYPE_INT: int, TYPE_FLOAT: float, TYPE_STR: str, TYPE_TIME: str}


def read_table(csv_path, schema_path=None, table=None):
    """Đọc một bảng đã xuất, đổi kiểu theo schema; ô trống thành None.

    Báo lỗi nếu phiên bản schema khác, cột khác schema, hay ô trống ở cột không được
    trống. ``schema_path`` mặc định là file .schema.json cùng tên; ``table`` suy từ
    đuôi tên file (``.flows.csv`` / ``.windows.csv``).
    """
    csv_path = Path(csv_path)
    table = table or csv_path.name.rsplit(".", 2)[-2]
    if schema_path is None:
        schema_path = csv_path.with_name(csv_path.name.rsplit(".", 2)[0] + ".schema.json")
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    if schema["phien_ban_schema"] != SCHEMA_VERSION:
        raise ValueError(f"{schema_path}: schema {schema['phien_ban_schema']}, cần {SCHEMA_VERSION}")
    cols = {c["ten"]: c for c in schema["bang"][table]}
    rows = []
    with open(csv_path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if list(reader.fieldnames or ()) != list(cols):
            raise ValueError(f"{csv_path}: cột không khớp schema bảng {table}")
        for line_no, raw in enumerate(reader, start=2):
            row = {}
            for name, value in raw.items():
                col = cols[name]
                if value == "":
                    if not col["co_the_trong"]:
                        raise ValueError(f"{csv_path}:{line_no}: cột {name} không được trống")
                    row[name] = None
                else:
                    row[name] = _PARSERS[col["kieu"]](value)
            rows.append(row)
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description="Xuất bảng đặc trưng flow và cửa sổ host.")
    parser.add_argument("file")
    parser.add_argument("--out", required=True, help="thư mục ghi kết quả")
    parser.add_argument("--name", help="tên file kết quả, mặc định theo tên PCAP")
    parser.add_argument("--net", action="append", help="dải mạng của host lập cửa sổ; lặp lại được")
    parser.add_argument("--hash", action="store_true",
                        help="tính lại SHA-256 của PCAP (mặc định lấy từ manifest nếu có)")
    parser.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    args = parser.parse_args(argv)
    meta = export(args.file, args.out, args.name, args.net, args.config, args.hash)
    t = meta["bang"]
    print(f"{args.file}: {t['flows']['so_dong']} flow, {t['windows']['so_dong']} cửa sổ host, "
          f"{meta['thoi_gian_chay_s']} giây")
    print(f"Đã ghi vào {args.out}: {t['flows']['file']}, {t['windows']['file']}, {t['schema']}, "
          f"{Path(t['flows']['file']).name.rsplit('.', 2)[0]}.meta.json")
    if meta["thong_ke"]["packet"]["loi_file"]:
        print(f"  Lỗi file: {meta['thong_ke']['packet']['loi_file']}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

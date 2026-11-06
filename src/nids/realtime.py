"""Chạy realtime: gói từ card mạng hoặc PCAP phát lại → cùng bộ trích xuất → ba module → cảnh báo (Chặng 10).

- C10-T03: nguồn gói live (``nids.nguon_goi``), dùng lại ``parse_packet`` và ``WindowPipeline`` của
  pipeline offline (B12); chấm cửa sổ 10 giây khi đóng, chấm botnet cho cửa sổ 120 giây theo từng bước
  (docs/61_realtime.md, QĐ-051).
- C10-T04: hàng đợi giới hạn giữa luồng đọc gói và luồng xử lý (đầy thì bỏ gói và đếm), nhịp thời gian khi
  mạng im lặng, trần số flow mở và bảng flow gần đây (docs/62_hang_doi_don_state.md, QĐ-052).
- C10-T05: đo gói nhận, xử lý, bỏ (hàng đợi, kernel), tốc độ, độ trễ xử lý, CPU, RAM, state; ghi định kỳ
  (docs/63_do_hieu_nang.md, QĐ-053).
- C10-T06: dừng êm khi nhận SIGINT/SIGTERM (xử lý nốt hàng đợi có giới hạn thời gian, chấm nốt cửa sổ, đóng
  file), log xoay vòng, mã thoát (docs/64_dung_va_log.md, QĐ-054).

    python -m nids.realtime --iface eth1 --net 192.168.50.0/24 --out output/realtime
    python -m nids.realtime --pcap output/pcap/fri_quet.pcap --net 192.168.10.0/24 --out output/realtime

Cùng mô hình, cùng chế độ (``pipeline.mode``) như pipeline offline.
"""

import argparse
import logging
import queue
import sys
import threading
import time
from collections import deque
from pathlib import Path

import numpy as np
import pandas as pd

from .alerts import AlertSink
from .flows import FlowSettings, csv_row as flow_row
from .packets import parse_packet
from .scope import MODULE_ANOMALY, MODULE_ATTACK, MODULE_BOTNET
from .window_features import WindowPipeline, csv_row as window_row

NS = 10**9


def realtime_config(cfg=None) -> dict:
    r = dict((cfg or {}).get("realtime") or {})
    r.setdefault("queue_size", 100_000)        # gói chờ giữa luồng đọc và luồng xử lý
    r.setdefault("tick_s", 1.0)                # nhịp đẩy thời gian khi không có gói
    r.setdefault("max_active_flows", 200_000)  # trần flow đang mở
    r.setdefault("max_flow_rows", 500_000)     # trần flow đã kết thúc giữ cho cửa sổ 120 giây
    r.setdefault("metrics_interval_s", 10.0)   # ghi số liệu mỗi khoảng này (giờ thật)
    r.setdefault("stop_timeout_s", 30.0)       # khi dừng: tối đa bấy nhiêu giây để xử lý nốt hàng đợi
    r.setdefault("log_dir", "output/realtime/log")
    r.setdefault("log_max_mb", 10)
    r.setdefault("log_backups", 5)
    return r


LOG = logging.getLogger("nids.realtime")
LOG.addHandler(logging.NullHandler())        # chưa gọi setup_logging thì không in gì (ví dụ khi kiểm thử)


def setup_logging(log_dir, max_mb=10, backups=5, level=logging.INFO, console=True) -> Path:
    """Log ra file xoay vòng (``nids_realtime.log``, tối đa ``max_mb`` MB × ``backups`` bản cũ) và ra stderr."""
    from logging.handlers import RotatingFileHandler
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / "nids_realtime.log"
    LOG.setLevel(level)
    for h in list(LOG.handlers):
        LOG.removeHandler(h)
        h.close()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = RotatingFileHandler(path, maxBytes=int(max_mb * 2**20), backupCount=backups, encoding="utf-8")
    fh.setFormatter(fmt)
    LOG.addHandler(fh)
    if console:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        LOG.addHandler(sh)
    LOG.propagate = False
    return path


def rss_mb() -> float | None:
    """RAM thường trú của tiến trình (MB): psutil nếu có, nếu không đọc /proc/self/status (Linux)."""
    try:
        import psutil
        return round(psutil.Process().memory_info().rss / 2**20, 1)
    except ImportError:
        pass
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return round(int(line.split()[1]) / 1024, 1)
    except OSError:
        pass
    return None


def _percentile(values, q):
    if not values:
        return None
    v = sorted(values)
    return round(v[min(len(v) - 1, int(q * (len(v) - 1) + 0.5))], 4)


class Metrics:
    """Số liệu vận hành của cảm biến (C10-T05), ghi mỗi ``interval_s`` giây thật thành một dòng JSON.

    CPU tính từ ``os.times()`` (user + system) chia thời gian thật: 100% là một lõi bận hoàn toàn.
    Độ trễ xử lý là thời gian một gói chờ từ lúc tới (theo nhịp nguồn) tới lúc được xử lý.
    """

    def __init__(self, runner, path=None, interval_s=10.0, clock=time.monotonic):
        import os
        self.runner, self.path, self.interval_s, self.clock = runner, path, interval_s, clock
        self.t0 = self.t_last = clock()
        self.cpu0 = self.cpu_last = sum(os.times()[:2])
        self.processed_last = 0
        self.kernel_drops = 0
        self.lags = []
        self.rows = []
        self.peak_rss = None
        if path is not None:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(path, "w", encoding="utf-8")
        else:
            self._fh = None

    def lag(self, seconds):
        self.lags.append(seconds)

    def maybe_report(self, force=False):
        now = self.clock()
        if not force and now - self.t_last < self.interval_s:
            return None
        return self.report(now)

    def report(self, now=None):
        import json
        import os
        now = self.clock() if now is None else now
        r, eng = self.runner, self.runner.engine
        cpu = sum(os.times()[:2])
        dt = max(now - self.t_last, 1e-9)
        self.kernel_drops += r.source.kernel_drops() if hasattr(r.source, "kernel_drops") else 0
        rss = rss_mb()
        if rss is not None:
            self.peak_rss = rss if self.peak_rss is None else max(self.peak_rss, rss)
        processed = r.processed
        row = {"thoi_gian_chay_s": round(now - self.t0, 1), "goi_nhan": getattr(r.source, "received", None),
               "goi_xu_ly": processed, "goi_bo_hang_doi": r.dropped, "goi_bo_kernel": self.kernel_drops,
               "goi_khong_phai_ip": eng.stats["goi_khong_phai_ip"],
               "toc_do_goi_s": round((processed - self.processed_last) / dt, 1),
               "hang_doi_hien_tai": r.q.qsize(), "hang_doi_sau_nhat": r.max_depth,
               "cpu_phan_tram": round(100 * (cpu - self.cpu_last) / dt, 1), "ram_mb": rss,
               "do_tre_xu_ly_s": {"p50": _percentile(self.lags, 0.5), "p95": _percentile(self.lags, 0.95),
                                  "lon_nhat": round(max(self.lags), 4) if self.lags else None},
               "canh_bao": eng.stats["canh_bao"], "su_kien": eng.events.closed, **eng.state_size()}
        self.t_last, self.cpu_last, self.processed_last = now, cpu, processed
        self._all_lags = getattr(self, "_all_lags", []) + self.lags
        self.lags = []
        self.rows.append(row)
        LOG.info("số liệu: %s gói/s, xử lý %s, bỏ hàng đợi %s, bỏ kernel %s, hàng đợi %s, CPU %s%%, RAM %s MB, "
                 "độ trễ p95 %s s, cảnh báo %s", row["toc_do_goi_s"], processed, r.dropped, self.kernel_drops,
                 row["hang_doi_hien_tai"], row["cpu_phan_tram"], rss, row["do_tre_xu_ly_s"]["p95"], row["canh_bao"])
        if r.dropped > getattr(self, "_dropped_logged", 0):
            LOG.warning("đã bỏ %d gói vì hàng đợi đầy: xử lý không kịp lưu lượng", r.dropped)
            self._dropped_logged = r.dropped
        if self._fh:
            self._fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            self._fh.flush()
        return row

    def summary(self) -> dict:
        import os
        now = self.clock()
        lags = getattr(self, "_all_lags", []) + self.lags
        r, eng = self.runner, self.runner.engine
        wall = max(now - self.t0, 1e-9)
        received = getattr(r.source, "received", None)
        lost = r.dropped + self.kernel_drops
        return {"thoi_gian_chay_s": round(wall, 1), "goi_nhan": received, "goi_xu_ly": r.processed,
                "goi_bo_hang_doi": r.dropped, "goi_bo_kernel": self.kernel_drops,
                "ty_le_bo": round(lost / max((received or 0) + self.kernel_drops, 1), 6),
                "toc_do_trung_binh_goi_s": round(r.processed / wall, 1),
                "cpu_trung_binh_phan_tram": round(100 * (sum(os.times()[:2]) - self.cpu0) / wall, 1),
                "ram_lon_nhat_mb": self.peak_rss, "hang_doi_sau_nhat": r.max_depth,
                "do_tre_xu_ly_s": {"p50": _percentile(lags, 0.5), "p95": _percentile(lags, 0.95),
                                   "p99": _percentile(lags, 0.99), "lon_nhat": round(max(lags), 4) if lags else None},
                "cua_so_10s": eng.stats["cua_so_10s"], "cua_so_120s": eng.stats["cua_so_120s"],
                "canh_bao": eng.stats["canh_bao"], "su_kien": eng.events.closed,
                "flow_ket_thuc_do_tran": eng.stats["flow_ket_thuc_do_tran"],
                "thoi_gian_cham_s": {k: round(v, 2) for k, v in eng.stats["thoi_gian_cham_s"].items()}}

    def close(self):
        if self._fh:
            self._fh.close()
            self._fh = None


def _numeric(rows, keep_str=("host",)) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    for c in df.columns:
        if c not in keep_str:
            df[c] = pd.to_numeric(df[c], errors="coerce")       # ô trống "" thành NaN
    return df


class EventMerger:
    """Gộp cảnh báo lặp thành sự kiện ngay khi chạy (cùng quy tắc ``pipeline.merge_events``, QĐ-048).

    Sự kiện đóng khi quá ``gap_s`` giây (theo thời gian gói) không có cảnh báo mới cùng khóa; ``on_close``
    nhận từng sự kiện đã đóng.
    """

    def __init__(self, gap_s=30.0, on_close=None):
        self.gap_s = gap_s
        self.on_close = on_close
        self.open = {}
        self.closed = 0

    def add(self, a):
        if not a.is_alert:
            return
        key = (a.module, a.label, a.src_ip)
        e = self.open.get(key)
        if e is not None and a.window_start <= e["ket_thuc"] + self.gap_s:
            e["ket_thuc"] = max(e["ket_thuc"], a.window_end)
            e["_diem"].append(a.score)
            e["_n"] += 1
            return
        if e is not None:
            self._close(key)
        self.open[key] = {"module": a.module, "label": a.label, "src_ip": a.src_ip, "bat_dau": a.window_start,
                          "ket_thuc": a.window_end, "_diem": [a.score], "_n": 1, "nguong": a.threshold,
                          "run_id": a.run_id, "canh_bao_dau_tao_luc": a.created_at}

    def _close(self, key):
        e = self.open.pop(key)
        scores = [s for s in e.pop("_diem") if s is not None]
        e["so_canh_bao"] = e.pop("_n")
        e["diem_lon_nhat"] = round(max(scores), 6) if scores else None
        e["diem_trung_binh"] = round(sum(scores) / len(scores), 6) if scores else None
        e["thoi_luong_s"] = round(e["ket_thuc"] - e["bat_dau"], 3)
        self.closed += 1
        if self.on_close:
            self.on_close(e)

    def expire(self, now_s):
        for key in [k for k, e in self.open.items() if now_s - e["ket_thuc"] > self.gap_s]:
            self._close(key)

    def close_all(self):
        for key in list(self.open):
            self._close(key)


def single_thread(model) -> int:
    """Đặt ``n_jobs = 1`` cho mọi mô hình scikit-learn bên trong ``model``; trả số mô hình đã đổi.

    Realtime chấm từng lô nhỏ (một bước cửa sổ); Random Forest lưu với ``n_jobs = 4`` thì mỗi lần gọi lại
    dựng rồi hủy một nhóm luồng, tốn khoảng 0,13 giây, nhiều hơn chính phép chấm. Kết quả dự đoán không đổi.
    """
    seen, n, stack = set(), 0, [model]
    while stack:
        obj = stack.pop()
        if id(obj) in seen or obj is None or isinstance(obj, (str, bytes, int, float)):
            continue
        seen.add(id(obj))
        if hasattr(obj, "n_jobs") and hasattr(obj, "get_params"):
            obj.n_jobs = 1
            n += 1
        if hasattr(obj, "named_steps"):
            stack.extend(obj.named_steps.values())
        for attr in ("estimator", "pipeline", "model"):
            if hasattr(obj, attr):
                stack.append(getattr(obj, attr))
    return n


class RealtimeEngine:
    """Nhận ``RawPacket`` từng gói; trả cảnh báo qua ``alert_sink`` (và mọi dự đoán qua ``score_sink``)."""

    def __init__(self, cfg, networks, arts=None, mode=None, run_id="realtime", alert_sink=None, score_sink=None,
                 event_sink=None):
        from .botnet import topology_rule
        from .graph_features import beacon_config, graph_window
        from .pipeline import load_artifacts, pipeline_config

        self.cfg = dict(cfg)
        self.cfg["botnet"] = {**(cfg.get("botnet") or {}), "local_nets": list(networks)}
        pc = pipeline_config(cfg)
        self.mode = mode or pc["mode"]
        if self.mode not in ("doc_lap", "tuan_tu", "ket_hop"):
            raise ValueError(f"chế độ chưa hỗ trợ: {self.mode}")
        self.networks = list(networks)
        self.run_id = run_id
        self.arts = arts or load_artifacts(cfg)
        for art in self.arts.values():
            single_thread(art.model)
        win = cfg["windows"]["flow"]
        self.observe_s = cfg["flow"]["handshake_observe_s"]
        self.pipe = WindowPipeline(FlowSettings.from_config(cfg), win["size_s"], win["step_s"], networks,
                                   self.observe_s, flow_sink=self._on_flow)
        self.g_size, self.g_step = graph_window(cfg)
        self.lookback_s = beacon_config(cfg)["lookback_s"]
        self.rule = topology_rule(cfg)
        self.alert_sink, self.score_sink = alert_sink, score_sink
        self.rt = realtime_config(cfg)
        self.events = EventMerger(pc["merge_gap_s"], event_sink)
        self.flow_rows = deque()            # flow đã kết thúc (dòng bảng flow), theo thứ tự kết thúc
        self.unexplained = {}               # host -> deque[(ws, we)] bất thường chưa giải thích
        self.seen_hosts = {}                # host -> lần cuối có flow (giây)
        self.next_graph_end = None          # cuối cửa sổ 120 giây kế tiếp cần chấm (giây)
        self.now_s = None                   # thời điểm gói mới nhất (giây)
        self.stats = {"goi": 0, "goi_khong_phai_ip": 0, "cua_so_10s": 0, "cua_so_120s": 0, "canh_bao": 0,
                      "su_kien": 0, "flow_ket_thuc_do_tran": 0, "flow_bo_khoi_bang_do_tran": 0, "nhip": 0, "thoi_gian_cham_s": {MODULE_ANOMALY: 0.0, MODULE_ATTACK: 0.0, MODULE_BOTNET: 0.0}}

    # ---- nhận gói ----

    def _on_flow(self, flow):
        self.flow_rows.append(flow_row(flow))
        if len(self.flow_rows) > self.rt["max_flow_rows"]:
            self.flow_rows.popleft()
            self.stats["flow_bo_khoi_bang_do_tran"] += 1

    def process(self, raw):
        rec = parse_packet(raw)
        self.stats["goi"] += 1
        if rec is None:
            self.stats["goi_khong_phai_ip"] += 1
            return
        if rec.ts_ns is not None:
            self.now_s = rec.ts_ns / NS if self.now_s is None else max(self.now_s, rec.ts_ns / NS)
        self._windows(self.pipe.add(rec))
        if self.pipe.flows.active_count > self.rt["max_active_flows"]:
            self.stats["flow_ket_thuc_do_tran"] += self.pipe.flows.evict_oldest(self.rt["max_active_flows"])
            self.pipe._drain_flows()
        self._graph_until(self.now_s)

    def tick(self, now_s):
        """Đẩy thời gian khi không có gói (mạng im lặng): flow hết hạn, cửa sổ đóng, botnet được chấm.

        ``now_s`` là thời điểm hiện tại theo cùng đồng hồ với dấu thời gian gói.
        """
        if self.now_s is None or now_s <= self.now_s:
            return
        self.now_s = now_s
        now_ns = int(now_s * NS)
        self.stats["nhip"] += 1
        self.pipe.flows.expire(now_ns)
        self.pipe._drain_flows()
        self.pipe.windows._close_until(now_ns)
        self._windows(self.pipe.windows.pop_finished())
        self._graph_until(now_s)

    def state_size(self) -> dict:
        """Kích thước state hiện tại (để đo ở C10-T05 và kiểm tra dọn state)."""
        return {"flow_dang_mo": self.pipe.flows.active_count, "flow_gan_day": len(self.flow_rows),
                "cua_so_dang_mo": sum(len(h) for h in self.pipe.windows._open.values()),
                "host_bat_thuong": len(self.unexplained), "su_kien_dang_mo": len(self.events.open)}

    def finish(self):
        """Hết dữ liệu: đóng mọi flow, cửa sổ, chấm nốt botnet, đóng sự kiện."""
        self._windows(self.pipe.finish())
        if self.now_s is not None:
            self._graph_until(self.now_s + self.g_size, final=True)
        self.events.close_all()

    # ---- cửa sổ 10 giây: anomaly, phân loại ----

    def _emit(self, alerts):
        for a in alerts:
            if self.score_sink is not None:
                self.score_sink.emit(a)
            if a.is_alert:
                self.stats["canh_bao"] += 1
                if self.alert_sink is not None:
                    self.alert_sink.emit(a)
                self.events.add(a)

    def _windows(self, windows):
        from .pipeline import module_alerts, score_anomaly, score_attack
        if not windows:
            return
        df = _numeric([window_row(w) for w in windows])
        df.insert(0, "session", self.run_id)
        self.stats["cua_so_10s"] += len(df)
        t = time.perf_counter()
        an = score_anomaly(self.arts[MODULE_ANOMALY], df)
        self.stats["thoi_gian_cham_s"][MODULE_ANOMALY] += time.perf_counter() - t
        flagged = (an["du_doan"] == "anomaly").to_numpy()
        t = time.perf_counter()
        sub = df[flagged].reset_index(drop=True) if self.mode == "tuan_tu" else df
        at = score_attack(self.arts[MODULE_ATTACK], sub) if len(sub) else None
        self.stats["thoi_gian_cham_s"][MODULE_ATTACK] += time.perf_counter() - t
        self._emit(module_alerts(MODULE_ANOMALY, an, self.arts[MODULE_ANOMALY], self.run_id,
                                 log_all=self.score_sink is not None))
        if at is not None:
            self._emit(module_alerts(MODULE_ATTACK, at, self.arts[MODULE_ATTACK], self.run_id,
                                     log_all=self.score_sink is not None))
            at_flag = at if self.mode == "tuan_tu" else at[flagged]
            for r in at_flag[at_flag["du_doan"] == "benign"].itertuples(index=False):
                self.unexplained.setdefault(str(r.host), deque()).append((float(r.window_start), float(r.window_end)))
        if self.next_graph_end is None:
            first = float(df["window_start"].min())
            self.next_graph_end = (np.floor(first / self.g_step) + 1) * self.g_step + self.g_size - self.g_step

    # ---- cửa sổ 120 giây: botnet, topology ----

    def _flow_table(self, since_s) -> pd.DataFrame:
        """Flow đã kết thúc và flow đang mở (ảnh chụp số đếm hiện tại) bắt đầu từ ``since_s``."""
        from .ctu13 import from_project_flows
        active = self.pipe.flows.active_flows()      # gồm cả flow đang đóng (FIN/RST), không đếm hai lần
        rows = list(self.flow_rows) + [flow_row(f) for f in active]
        if not rows:
            return pd.DataFrame()
        df = _numeric(rows, keep_str=("fwd_ip", "bwd_ip", "direction_basis", "end_reason"))
        df = df[df["first_ts"] >= since_s]
        if df.empty:
            return df
        df["protocol"] = df["protocol"].astype("Int64").astype(str)
        return from_project_flows(df, self.run_id)

    def _graph_until(self, now_s, final=False):
        """Chấm mọi cửa sổ 120 giây đã đủ dữ liệu: cuối cửa sổ + thời gian quan sát ≤ thời điểm hiện tại."""
        if self.next_graph_end is None or now_s is None:
            return
        while self.next_graph_end + self.observe_s <= now_s or (final and self.next_graph_end <= now_s):
            self._score_graph_window(self.next_graph_end - self.g_size, self.next_graph_end)
            self.next_graph_end += self.g_step
        self._prune(now_s)

    def _graph_hosts(self, ws, we, flows) -> list:
        from .pipeline import monitored_hosts
        if self.mode == "doc_lap":
            active = flows[(flows["ts"] >= ws) & (flows["ts"] < we)]
            return monitored_hosts(active, self.networks) if len(active) else []
        return sorted(h for h, spans in self.unexplained.items() if any(s < we and e > ws for s, e in spans))

    def _score_graph_window(self, ws, we):
        from .botnet import SUSPECT, recognize_topology
        from .graph_features import build_features
        from .pipeline import module_alerts
        t = time.perf_counter()
        flows = self._flow_table(we - max(self.lookback_s, 2 * self.g_size))
        hosts = self._graph_hosts(ws, we, flows) if len(flows) else []
        if hosts:
            flows = flows[flows["ts"] < we]
            feats = build_features(flows, hosts, self.cfg)
            # so tuyệt đối: isclose mặc định có sai số tương đối 1e-5, tức khoảng 15 000 giây với epoch hiện nay
            feats = feats[np.isclose(feats["window_start"], ws, rtol=0, atol=1e-3)].reset_index(drop=True)
            if len(feats):
                art = self.arts[MODULE_BOTNET]
                score = art.model.score(feats)
                out = feats[["session", "host", "window_start"]].copy()
                out["window_end"] = we
                out["diem"] = score
                out["du_doan"] = np.where(score >= art.threshold, SUSPECT, "normal_host")
                out["topology"] = recognize_topology(feats, out["du_doan"] == SUSPECT, self.rule)
                self.stats["cua_so_120s"] += len(out)
                self._emit(module_alerts(MODULE_BOTNET, out, art, self.run_id, log_all=self.score_sink is not None))
        self.stats["thoi_gian_cham_s"][MODULE_BOTNET] += time.perf_counter() - t

    def _prune(self, now_s):
        """Bỏ flow và bất thường đã quá cũ để không cần cho cửa sổ nào nữa (chi tiết dọn state ở C10-T04)."""
        keep_from = now_s - max(self.lookback_s, 2 * self.g_size) - self.g_size
        while self.flow_rows and float(self.flow_rows[0]["first_ts"] or 0) < keep_from and \
                float(self.flow_rows[0]["last_ts"] or 0) < keep_from:
            self.flow_rows.popleft()
        for h in list(self.unexplained):
            q = self.unexplained[h]
            while q and q[0][1] < now_s - 2 * self.g_size:
                q.popleft()
            if not q:
                del self.unexplained[h]
        self.events.expire(now_s)


_END = object()


class ThreadedRunner:
    """Luồng đọc gói → hàng đợi giới hạn → luồng xử lý (C10-T04).

    - Hàng đợi đầy thì **bỏ gói mới và đếm** (``dropped``), không chặn luồng đọc: chặn sẽ làm bộ đệm socket
      tràn và kernel bỏ gói mà không biết gói nào.
    - Không có gói trong ``tick_s`` giây thì gọi ``engine.tick`` với thời điểm ước tính: thời điểm gói cuối +
      thời gian thật đã trôi × ``clock_rate`` (1 khi bắt trực tiếp; hệ số khi phát lại theo nhịp; 0 là không
      đẩy, khi phát lại nhanh nhất có thể).
    """

    def __init__(self, source, engine, queue_size=100_000, tick_s=1.0, clock_rate=1.0):
        self.source, self.engine = source, engine
        self.q = queue.Queue(maxsize=queue_size)
        self.tick_s, self.clock_rate = tick_s, clock_rate
        self.dropped = 0
        self.enqueued = 0
        self.processed = 0
        self.max_depth = 0
        self.error = None
        self.metrics = None
        self.stop_reason = None
        self.stop_timeout_s = 30.0
        self.discarded_on_stop = 0
        self._stop_deadline = None
        self._reader = threading.Thread(target=self._read, name="doc-goi", daemon=True)

    def stop(self, reason="dung"):
        """Yêu cầu dừng (gọi từ trình xử lý tín hiệu): nguồn ngừng đọc; gói còn trong hàng đợi được xử lý nốt
        trong tối đa ``stop_timeout_s`` giây, phần còn lại bị bỏ và đếm."""
        if self.stop_reason is None:
            self.stop_reason = reason
            self._stop_deadline = time.monotonic() + self.stop_timeout_s
            self.source.stop()

    def _read(self):
        try:
            for raw in self.source:
                try:
                    self.q.put_nowait((raw, time.monotonic()))
                    self.enqueued += 1
                except queue.Full:
                    self.dropped += 1
        except Exception as exc:                    # lỗi nguồn: báo cho luồng xử lý rồi dừng
            self.error = exc
        finally:
            self.q.put(_END)

    def run(self, on_packet=None) -> int:
        self._reader.start()
        n = 0
        last_wall = time.monotonic()
        while True:
            try:
                item = self.q.get(timeout=self.tick_s)
            except queue.Empty:
                if self.clock_rate and self.engine.now_s is not None:
                    self.engine.tick(self.engine.now_s + (time.monotonic() - last_wall) * self.clock_rate)
                    last_wall = time.monotonic()
                if self.metrics:
                    self.metrics.maybe_report()
                continue
            if item is _END:
                break
            if self._stop_deadline is not None and time.monotonic() > self._stop_deadline:
                self.discarded_on_stop += 1 + self._drain_discard()
                break
            raw, arrived = item
            self.max_depth = max(self.max_depth, self.q.qsize() + 1)
            self.engine.process(raw)
            last_wall = time.monotonic()
            if self.metrics:
                self.metrics.lag(last_wall - arrived)     # chờ trong hàng đợi + thời gian xử lý gói
                self.metrics.maybe_report()
            n += 1
            self.processed = n
            if on_packet:
                on_packet(n)
        self._reader.join(timeout=5)
        self.engine.finish()
        if self.metrics:
            self.metrics.report()
        if self.error is not None:
            raise self.error
        return n


def _drain_discard_impl(q) -> int:
    n = 0
    while True:
        try:
            item = q.get_nowait()
        except queue.Empty:
            return n
        if item is not _END:
            n += 1


ThreadedRunner._drain_discard = lambda self: _drain_discard_impl(self.q)


def install_signal_handlers(runner):
    """SIGINT, SIGTERM (và SIGHUP trên Linux): dừng êm; tín hiệu thứ hai trong lúc đang dừng thì thoát ngay."""
    import os
    import signal

    def handler(signum, frame):
        name = signal.Signals(signum).name
        if runner.stop_reason is not None:
            LOG.warning("nhận %s lần nữa trong lúc đang dừng: thoát ngay, không xử lý nốt", name)
            os._exit(130)
        LOG.info("nhận %s: dừng đọc gói, xử lý nốt hàng đợi (tối đa %.0f s)", name, runner.stop_timeout_s)
        runner.stop(name)

    names = ["SIGINT", "SIGTERM"] + (["SIGHUP"] if hasattr(signal, "SIGHUP") else [])
    for n in names:
        signal.signal(getattr(signal, n), handler)
    return names


def run(source, engine, on_packet=None):
    """Đưa từng gói của ``source`` vào ``engine`` (một luồng); trả số gói."""
    n = 0
    for raw in source:
        engine.process(raw)
        n += 1
        if on_packet:
            on_packet(n)
    engine.finish()
    return n


def main(argv=None):
    from .config import load_config

    ap = argparse.ArgumentParser(description="Cảm biến realtime: ba module trên traffic trực tiếp hoặc PCAP phát lại.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="card mạng giám sát (Linux)")
    src.add_argument("--pcap", help="phát lại file PCAP thay cho card mạng")
    ap.add_argument("--toc-do", type=float, help="phát lại theo nhịp thật × hệ số này; bỏ trống là nhanh nhất có thể")
    ap.add_argument("--net", action="append", help="mạng giám sát; mặc định lab.subnet")
    ap.add_argument("--out", default="output/realtime", help="thư mục ghi cảnh báo, điểm, sự kiện")
    ap.add_argument("--ten", default=None, help="tiền tố file ra và run_id; mặc định realtime_<giờ bắt đầu>")
    ap.add_argument("--che-do", choices=("doc_lap", "tuan_tu", "ket_hop"))
    ap.add_argument("--ghi-diem", action="store_true", help="ghi mọi dự đoán kèm điểm (file lớn)")
    ap.add_argument("--log-dir", help="thư mục log, mặc định realtime.log_dir")
    ap.add_argument("--im-lang", action="store_true", help="không in cảnh báo và log ra terminal (chạy nền)")
    ap.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    rt = realtime_config(cfg)
    from .config import PROJECT_ROOT
    log_dir = Path(a.log_dir or rt["log_dir"])
    if not log_dir.is_absolute() and not a.log_dir:         # giá trị trong cấu hình: tính từ thư mục dự án
        log_dir = PROJECT_ROOT / log_dir
    log_path = setup_logging(log_dir, rt["log_max_mb"], rt["log_backups"], console=not a.im_lang)
    try:
        return _main(a, cfg, rt, log_path)
    except Exception:
        LOG.exception("cảm biến dừng vì lỗi")
        return 1


def _main(a, cfg, rt, log_path):
    from .feature_export import _git_version
    from .nguon_goi import open_source
    from .pipeline import EVENT_COLUMNS

    nets = a.net or [cfg["lab"]["subnet"]]
    name = a.ten or time.strftime("realtime_%Y%m%d_%H%M%S")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    LOG.info("khởi động %s: nguồn %s, mạng %s, chế độ %s, commit %s, log %s", name,
             f"card {a.iface}" if a.iface else f"pcap {a.pcap}", nets, a.che_do or "theo cấu hình",
             str(_git_version().get("commit"))[:8], log_path)
    for suffix in ("alerts.csv", "diem.csv", "su_kien.csv", "so_lieu.jsonl", "so_lieu_tong.json"):
        old = out / f"{name}.{suffix}"
        if old.exists():                 # cùng tên với lần chạy trước: giữ bản cũ, không ghi lẫn (trước khi mở file nào)
            backup = old.with_name(f"{name}.cu.{suffix}")
            old.replace(backup)
            LOG.warning("đã có %s từ lần chạy trước: đổi tên thành %s", old.name, backup.name)
    import csv

    from .alerts import _iso
    ev_file = (out / f"{name}.su_kien.csv").open("w", newline="", encoding="utf-8")
    ev_writer = csv.DictWriter(ev_file, fieldnames=EVENT_COLUMNS)
    ev_writer.writeheader()

    def on_event(e):
        row = dict(e)
        for k in ("bat_dau", "ket_thuc", "canh_bao_dau_tao_luc"):
            row[k] = _iso(row[k])
        ev_writer.writerow({k: "" if row.get(k) is None else row[k] for k in EVENT_COLUMNS})
        ev_file.flush()

    score_sink = AlertSink(out / f"{name}.diem.csv", stream=open(Path("nul" if sys.platform == "win32" else "/dev/null"), "w"),
                           log_all=True) if a.ghi_diem else None
    stream = open(Path("nul" if sys.platform == "win32" else "/dev/null"), "w") if a.im_lang else None
    with AlertSink(out / f"{name}.alerts.csv", stream=stream) as sink, open_source(a.iface, a.pcap, a.toc_do) as source:
        engine = RealtimeEngine(cfg, nets, mode=a.che_do, run_id=name, alert_sink=sink, score_sink=score_sink,
                                event_sink=on_event)
        rate = 1.0 if a.iface else (a.toc_do or 0.0)
        runner = ThreadedRunner(source, engine, rt["queue_size"], rt["tick_s"], rate)
        runner.stop_timeout_s = rt["stop_timeout_s"]
        install_signal_handlers(runner)
        runner.metrics = Metrics(runner, out / f"{name}.so_lieu.jsonl", rt["metrics_interval_s"])
        t0 = time.perf_counter()
        n = runner.run()
        dt = time.perf_counter() - t0
        summary = runner.metrics.summary()
        summary["ly_do_dung"] = runner.stop_reason or "het_nguon"
        summary["goi_bo_khi_dung"] = runner.discarded_on_stop
        runner.metrics.close()
    if score_sink:
        score_sink.close()
    ev_file.close()
    s = engine.stats
    import json
    (out / f"{name}.so_lieu_tong.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Số liệu:", json.dumps(summary, ensure_ascii=False))
    LOG.info("dừng (%s): %s gói, %s cảnh báo, %s sự kiện, bỏ khi dừng %s gói", summary["ly_do_dung"], n,
             s["canh_bao"], engine.events.closed, runner.discarded_on_stop)
    print(f"Hàng đợi: bỏ {runner.dropped} gói, sâu nhất {runner.max_depth}; flow kết thúc do trần "
          f"{s['flow_ket_thuc_do_tran']}; state cuối {engine.state_size()}")
    print(f"{n} gói trong {dt:.1f} s ({n / max(dt, 1e-9):.0f} gói/s); {s['cua_so_10s']} cửa sổ 10 s, "
          f"{s['cua_so_120s']} host–cửa sổ 120 s; {s['canh_bao']} cảnh báo, {engine.events.closed} sự kiện")
    return 0


if __name__ == "__main__":
    sys.exit(main())

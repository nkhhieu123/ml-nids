"""Chạy realtime: gói từ card mạng hoặc PCAP phát lại → cùng bộ trích xuất → ba module → cảnh báo (Chặng 10).

- C10-T03: nguồn gói live (``nids.nguon_goi``), dùng lại ``parse_packet`` và ``WindowPipeline`` của
  pipeline offline (B12); chấm cửa sổ 10 giây khi đóng, chấm botnet cho cửa sổ 120 giây theo từng bước
  (docs/61_realtime.md, QĐ-051).
- C10-T04: hàng đợi giới hạn giữa luồng đọc gói và luồng xử lý (đầy thì bỏ gói và đếm), nhịp thời gian khi
  mạng im lặng, trần số flow mở và bảng flow gần đây (docs/62_hang_doi_don_state.md, QĐ-052).

    python -m nids.realtime --iface eth1 --net 192.168.50.0/24 --out output/realtime
    python -m nids.realtime --pcap output/pcap/fri_quet.pcap --net 192.168.10.0/24 --out output/realtime

Cùng mô hình, cùng chế độ (``pipeline.mode``) như pipeline offline.
"""

import argparse
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
    return r


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
        self.max_depth = 0
        self.error = None
        self._reader = threading.Thread(target=self._read, name="doc-goi", daemon=True)

    def _read(self):
        try:
            for raw in self.source:
                try:
                    self.q.put_nowait(raw)
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
                raw = self.q.get(timeout=self.tick_s)
            except queue.Empty:
                if self.clock_rate and self.engine.now_s is not None:
                    self.engine.tick(self.engine.now_s + (time.monotonic() - last_wall) * self.clock_rate)
                    last_wall = time.monotonic()
                continue
            if raw is _END:
                break
            self.max_depth = max(self.max_depth, self.q.qsize() + 1)
            self.engine.process(raw)
            last_wall = time.monotonic()
            n += 1
            if on_packet:
                on_packet(n)
        self._reader.join(timeout=5)
        self.engine.finish()
        if self.error is not None:
            raise self.error
        return n


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
    from .nguon_goi import open_source
    from .pipeline import EVENT_COLUMNS

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
    ap.add_argument("--config", help="file cấu hình, mặc định config/default.yaml")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    nets = a.net or [cfg["lab"]["subnet"]]
    name = a.ten or time.strftime("realtime_%Y%m%d_%H%M%S")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
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
    with AlertSink(out / f"{name}.alerts.csv") as sink, open_source(a.iface, a.pcap, a.toc_do) as source:
        engine = RealtimeEngine(cfg, nets, mode=a.che_do, run_id=name, alert_sink=sink, score_sink=score_sink,
                                event_sink=on_event)
        rt = realtime_config(cfg)
        rate = 1.0 if a.iface else (a.toc_do or 0.0)
        runner = ThreadedRunner(source, engine, rt["queue_size"], rt["tick_s"], rate)
        t0 = time.perf_counter()
        n = runner.run()
        dt = time.perf_counter() - t0
    if score_sink:
        score_sink.close()
    ev_file.close()
    s = engine.stats
    print(f"Hàng đợi: bỏ {runner.dropped} gói, sâu nhất {runner.max_depth}; flow kết thúc do trần "
          f"{s['flow_ket_thuc_do_tran']}; state cuối {engine.state_size()}")
    print(f"{n} gói trong {dt:.1f} s ({n / max(dt, 1e-9):.0f} gói/s); {s['cua_so_10s']} cửa sổ 10 s, "
          f"{s['cua_so_120s']} host–cửa sổ 120 s; {s['canh_bao']} cảnh báo, {engine.events.closed} sự kiện")
    return 0


if __name__ == "__main__":
    sys.exit(main())

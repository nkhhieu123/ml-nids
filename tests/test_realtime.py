import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.moi_truong import (FAIL, OK, WARN, capabilities, check_capture_permission, check_interface, check_ntp,
                             check_packages, check_python)


class EnvironmentTest(unittest.TestCase):
    """C10-T01: kiểm tra môi trường trước khi chạy cảm biến."""

    def test_python_and_packages(self):
        self.assertEqual(check_python((3, 12, 1))[0], OK)
        self.assertEqual(check_python((3, 9, 0))[0], FAIL)
        res = dict((msg.split()[0] if lv == OK else msg, lv) for lv, msg in
                   check_packages(required=("json",), optional=("khong_co_thu_vien_nay",)))
        self.assertEqual(res["json"], OK)
        self.assertEqual(res["thiếu thư viện khong_co_thu_vien_nay (tùy chọn)"], WARN)
        self.assertEqual(check_packages(required=("khong_co_x",), optional=())[0][0], FAIL)

    def test_capture_permission(self):
        status = "Name:\tpython\nCapEff:\t0000000000003000\n"                      # bit 12, 13
        self.assertEqual(capabilities(status), 0x3000)
        self.assertIsNone(capabilities("Name: x\n"))
        self.assertEqual(check_capture_permission("Linux", euid=0)[0], OK)
        self.assertEqual(check_capture_permission("Linux", euid=1000, status_text=status)[0], OK)
        self.assertEqual(check_capture_permission("Linux", euid=1000, status_text="CapEff:\t0\n")[0], FAIL)
        self.assertEqual(check_capture_permission("Windows")[0], WARN)

    def test_interface(self):
        with TemporaryDirectory() as d:
            (Path(d) / "eth1").mkdir()
            (Path(d) / "eth1" / "operstate").write_text("up\n")
            (Path(d) / "lo").mkdir()
            self.assertEqual(check_interface("eth1", "Linux", d)[0], OK)
            lv, msg = check_interface("eth0", "Linux", d)
            self.assertEqual(lv, FAIL)
            self.assertIn("eth1", msg)                                              # gợi ý card có thật
        self.assertEqual(check_interface(None, "Linux")[0], WARN)

    def test_ntp(self):
        yes = lambda *a, **k: SimpleNamespace(stdout="yes\n")
        no = lambda *a, **k: SimpleNamespace(stdout="no\n")
        def broken(*a, **k):
            raise OSError("không có")
        self.assertEqual(check_ntp("Linux", yes)[0], OK)
        self.assertEqual(check_ntp("Linux", no)[0], WARN)
        self.assertEqual(check_ntp("Linux", broken)[0], WARN)


def handshake_packets(n=30, t0=1_500_000_000.0, server="192.168.50.30"):
    """n kết nối TCP đủ bắt tay từ 192.168.50.41 tới ``server``:80; mỗi gói (giây, khung)."""
    from test_pipeline import frame
    pk = []
    for k in range(n):
        t = t0 + k
        c = ("192.168.50.41", server, 50000 + k, 80)
        s = (server, "192.168.50.41", 80, 50000 + k)
        pk += [(t, frame(*c, 0x02)), (t + 0.01, frame(*s, 0x12)), (t + 0.02, frame(*c, 0x10)),
               (t + 0.5, frame(*c, 0x11)), (t + 0.51, frame(*s, 0x11)), (t + 0.52, frame(*c, 0x10))]
    return pk


class SensorTest(unittest.TestCase):
    """C10-T02: cảm biến thấy traffic hai chiều."""

    def run_on(self, packets, lab_hosts=None):
        from nids.cam_bien import analyze, read_with_digest
        from test_pipeline import write_pcap
        with TemporaryDirectory() as d:
            path = write_pcap(Path(d) / "x.pcap", sorted(packets, key=lambda x: x[0]))
            return analyze(read_with_digest(path), ["192.168.50.0/24"], lab_hosts)

    def test_two_way(self):
        r = self.run_on(handshake_packets(), ["192.168.50.41", "192.168.50.30", "192.168.50.42"])
        self.assertEqual((r["ty_le_flow_tcp_hai_chieu"], r["ty_le_co_phan_hoi_trong_mang"]), (1.0, 1.0))
        self.assertEqual(r["ty_le_nhan_doi"], 0.0)
        self.assertEqual(r["ket_luan"], "dat")
        self.assertFalse(r["may_lab"]["192.168.50.42"])
        self.assertTrue(any("192.168.50.42" in x for x in r["ly_do"]))               # máy lab chưa thấy

    def test_one_way(self):
        only_client = [p for p in handshake_packets() if p[1][26:30] == bytes([192, 168, 50, 41])]
        r = self.run_on(only_client)
        self.assertEqual(r["ty_le_flow_tcp_hai_chieu"], 0.0)
        self.assertEqual(r["ket_luan"], "loi")
        self.assertEqual(r["so_cap_mot_chieu"], 1)
        self.assertEqual(r["cap_mot_chieu"][0]["goi_b_sang_a"] + r["cap_mot_chieu"][0]["goi_a_sang_b"], 120)

    def test_duplicates(self):
        pk = handshake_packets()
        r = self.run_on(pk + [(t + 2e-6, f) for t, f in pk])                      # mỗi gói có một bản sao sau 2 µs
        self.assertAlmostEqual(r["ty_le_nhan_doi"], 0.5)
        self.assertEqual(r["ty_le_flow_tcp_hai_chieu"], 1.0)                        # bản sao không làm hỏng flow
        self.assertEqual(r["ket_luan"], "canh_bao")

    def test_too_few_flows(self):
        r = self.run_on(handshake_packets(n=5))
        self.assertEqual(r["ket_luan"], "canh_bao")
        self.assertIn("flow TCP", r["ly_do"][0])

    def test_digest_ignores_ttl(self):
        from nids.cam_bien import ip_digest
        from nids.pcap_reader import RawPacket
        from test_pipeline import frame
        f = bytearray(frame("192.168.50.41", "192.168.50.30", 1, 80, 0x02))
        g = bytearray(f)
        g[14 + 8] = 1                                                               # TTL khác
        h = bytearray(f)
        h[14 + 4] = 9                                                               # IP ID khác: gói khác
        dg = lambda b: ip_digest(RawPacket(0, 0, len(b), len(b), 1, bytes(b)))
        self.assertEqual(dg(f), dg(g))
        self.assertNotEqual(dg(f), dg(h))


class FakeSocket:
    """Socket giả cho AfPacketSource: trả các khung đã định rồi timeout."""

    def __init__(self, frames, stats=(10, 3)):
        import socket
        self.frames = list(frames)
        self.stats = stats
        self.timeout = socket.timeout

    def recvmsg(self, bufsize, ancbufsize, flags):
        import socket
        import struct
        if not self.frames:
            raise socket.timeout()
        ts, data = self.frames.pop(0)
        anc = [(socket.SOL_SOCKET, 35, struct.pack("qq", int(ts), int(round((ts % 1) * 1e9))))]
        return data, anc, 0, None

    def getsockopt(self, level, opt, size):
        import struct
        return struct.pack("II", *self.stats)

    def close(self):
        pass


class LiveSourceTest(unittest.TestCase):
    """C10-T03: nguồn gói live và bộ máy realtime dùng lại bộ trích xuất."""

    def test_af_packet_with_fake_socket(self):
        from nids.nguon_goi import AfPacketSource, parse_timestamp, promisc_mreq
        from test_pipeline import frame
        frames = [(1_500_000_000.25, frame("10.0.0.1", "10.0.0.2", 1, 80, 0x02))]
        src = AfPacketSource("eth9", sock=FakeSocket(frames))
        it = iter(src)
        pkt = next(it)
        self.assertEqual(pkt.ts_ns, 1_500_000_000_250_000_000)
        self.assertEqual((pkt.linktype, pkt.caplen, pkt.origlen), (1, len(frames[0][1]), len(frames[0][1])))
        self.assertEqual(src.kernel_drops(), 3)
        self.assertEqual(src.dropped_total, 3)
        src.stop()
        self.assertEqual(list(it), [])                                          # dừng được khi đang chờ gói
        self.assertEqual(len(promisc_mreq(2)), 16)
        self.assertIsNone(parse_timestamp([]))

    def test_replay_pacing_and_stop(self):
        import time
        from nids.nguon_goi import PcapReplaySource, open_source
        from test_pipeline import frame, write_pcap
        with TemporaryDirectory() as d:
            p = write_pcap(Path(d) / "x.pcap", [(100.0 + 0.2 * i, frame("10.0.0.1", "10.0.0.2", 1, 80, 2))
                                               for i in range(4)])
            t = time.monotonic()
            self.assertEqual(len(list(PcapReplaySource(p, speed=1.0))), 4)
            self.assertGreaterEqual(time.monotonic() - t, 0.55)                  # theo nhịp thật: 0,6 giây
            src = PcapReplaySource(p)
            for i, _ in enumerate(src):
                src.stop()
            self.assertEqual(src.received, 1)
            with self.assertRaises(ValueError):
                open_source()

    def test_engine_matches_offline_windows(self):
        from nids.pipeline import extract, load_windows
        from nids.config import load_config
        from nids.nguon_goi import PcapReplaySource
        from nids.realtime import RealtimeEngine, run
        from test_pipeline import fake_artifacts, scan_pcap
        with TemporaryDirectory() as d:
            pcap = scan_pcap(Path(d) / "scan.pcap")
            offline = load_windows(extract(pcap, Path(d) / "off", ["192.168.10.0/24"]))
            got = []
            sink = SimpleNamespace(emit=got.append)
            eng = RealtimeEngine(load_config(), ["192.168.10.0/24"], arts=fake_artifacts(), mode="doc_lap",
                                 run_id="t", alert_sink=sink)
            run(PcapReplaySource(pcap), eng)
        self.assertEqual(eng.stats["cua_so_10s"], len(offline))                # cùng số cửa sổ với offline
        labels = {(a.module, a.label, a.src_ip) for a in got}
        self.assertIn(("attack_classification", "port_scan", "192.168.10.5"), labels)
        self.assertIn(("anomaly", "anomaly", "192.168.10.5"), labels)
        self.assertIn(("botnet_topology", "suspect_host", "192.168.10.5"), labels)
        self.assertFalse(any(a.src_ip == "192.168.10.7" and a.module == "attack_classification" for a in got))
        self.assertGreater(eng.events.closed, 0)
        self.assertEqual(eng.events.open, {})

    def test_each_graph_window_scored_once(self):
        """Mỗi (host, cửa sổ 120 giây) chỉ được chấm một lần (lỗi isclose với sai số tương đối)."""
        from collections import Counter
        from nids.config import load_config
        from nids.nguon_goi import PcapReplaySource
        from nids.realtime import RealtimeEngine, run
        from test_pipeline import fake_artifacts, scan_pcap
        with TemporaryDirectory() as d:
            pcap = scan_pcap(Path(d) / "scan.pcap")
            scores = []
            eng = RealtimeEngine(load_config(), ["192.168.10.0/24"], arts=fake_artifacts(), mode="doc_lap",
                                 run_id="t", score_sink=SimpleNamespace(emit=scores.append))
            run(PcapReplaySource(pcap), eng)
        host_rows = [(a.src_ip, a.window_start) for a in scores
                     if a.module == "botnet_topology" and a.label in ("suspect_host", "normal_host")]
        self.assertTrue(host_rows)
        self.assertEqual(max(Counter(host_rows).values()), 1)
        self.assertTrue(all((a.window_end - a.window_start) == 120 for a in scores if a.module == "botnet_topology"))

    def test_event_merger_and_single_thread(self):
        from nids.alerts import Alert
        from nids.realtime import EventMerger, single_thread
        closed = []
        m = EventMerger(30, closed.append)
        for s in (0, 2, 4, 100):
            m.add(Alert("anomaly", "anomaly", s, s + 10, src_ip="a", score=float(s)))
        m.add(Alert("anomaly", "normal", 0, 10, src_ip="a"))                   # không phải cảnh báo
        self.assertEqual(len(closed), 1)                                          # 100 cách 14 tới 86 giây > 30: đóng sự kiện đầu
        self.assertEqual((closed[0]["bat_dau"], closed[0]["ket_thuc"], closed[0]["so_canh_bao"]), (0, 14, 3))
        m.expire(200)
        self.assertEqual(len(closed), 2)
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.pipeline import Pipeline
        rf = RandomForestClassifier(n_jobs=4)
        wrapped = SimpleNamespace(pipeline=Pipeline([("mo_hinh", rf)]))
        self.assertEqual(single_thread(wrapped), 1)                              # Pipeline không có n_jobs; chỉ rừng
        self.assertEqual(rf.n_jobs, 1)


class QueueStateTest(unittest.TestCase):
    """C10-T04: hàng đợi giới hạn, nhịp thời gian, dọn state."""

    def engine(self, **rt):
        from nids.config import load_config
        from nids.realtime import RealtimeEngine
        from test_pipeline import fake_artifacts
        cfg = load_config()
        cfg["realtime"] = {**cfg.get("realtime", {}), **rt}
        return RealtimeEngine(cfg, ["192.168.10.0/24"], arts=fake_artifacts(), mode="doc_lap", run_id="t")

    def test_queue_drops_when_full(self):
        from nids.realtime import ThreadedRunner
        from test_pipeline import scan_pcap

        class SlowEngine:
            now_s = None
            processed = 0

            def process(self, raw):
                import time
                time.sleep(0.002)
                self.processed += 1

            def finish(self):
                pass

        from nids.nguon_goi import PcapReplaySource
        with TemporaryDirectory() as d:
            src = PcapReplaySource(scan_pcap(Path(d) / "s.pcap"))
            eng = SlowEngine()
            r = ThreadedRunner(src, eng, queue_size=5, tick_s=0.05, clock_rate=0)
            n = r.run()
        self.assertGreater(r.dropped, 0)                                           # đầy thì bỏ, không chặn
        self.assertEqual(n + r.dropped, src.received)                              # mọi gói đều được đếm
        self.assertLessEqual(r.max_depth, 5)

    def test_tick_closes_windows_and_flows(self):
        from nids.nguon_goi import PcapReplaySource
        from test_pipeline import scan_pcap
        eng = self.engine()
        with TemporaryDirectory() as d:
            for raw in PcapReplaySource(scan_pcap(Path(d) / "s.pcap")):
                eng.process(raw)
        before = eng.state_size()
        self.assertGreater(before["flow_dang_mo"], 0)
        self.assertGreater(before["cua_so_dang_mo"], 0)
        eng.tick(eng.now_s + 1000)                                                  # mạng im lặng 1 000 giây
        after = eng.state_size()
        self.assertEqual((after["flow_dang_mo"], after["cua_so_dang_mo"]), (0, 0))  # hết hạn mà không cần gói mới
        self.assertEqual(after["flow_gan_day"], 0)                                 # flow quá cũ bị dọn
        self.assertEqual(after["su_kien_dang_mo"], 0)
        self.assertGreater(eng.stats["cua_so_10s"], 0)
        eng.tick(eng.now_s - 5)                                                    # thời gian lùi: bỏ qua
        self.assertEqual(eng.stats["nhip"], 1)

    def test_flow_cap(self):
        from nids.nguon_goi import PcapReplaySource
        from test_pipeline import scan_pcap
        eng = self.engine(max_active_flows=10, max_flow_rows=50)
        with TemporaryDirectory() as d:
            for raw in PcapReplaySource(scan_pcap(Path(d) / "s.pcap")):
                eng.process(raw)
                self.assertLessEqual(eng.pipe.flows.active_count, 10)
                self.assertLessEqual(len(eng.flow_rows), 50)
        self.assertGreater(eng.stats["flow_ket_thuc_do_tran"], 0)
        self.assertGreater(eng.stats["flow_bo_khoi_bang_do_tran"], 0)

    def test_evicted_open_flows_reason(self):
        """Flow chưa đóng bị ép kết thúc mang lý do gioi_han_bo_nho; flow cũ nhất bị ép trước."""
        from nids.nguon_goi import PcapReplaySource
        from test_pipeline import write_pcap
        open_only = [p for i, p in enumerate(handshake_packets(n=20)) if i % 6 < 3]   # bỏ FIN: kết nối còn mở
        eng = self.engine(max_active_flows=5)
        with TemporaryDirectory() as d:
            for raw in PcapReplaySource(write_pcap(Path(d) / "o.pcap", open_only)):
                eng.process(raw)
        evicted = [r for r in eng.flow_rows if r["end_reason"] == "gioi_han_bo_nho"]
        self.assertEqual(len(evicted), 15)
        self.assertEqual(sorted(int(r["fwd_port"]) for r in evicted), list(range(50000, 50015)))

    def test_snapshot_counts_closing_flow_once(self):
        """Flow đã đóng bằng FIN nhưng còn chờ gói cuối chỉ xuất hiện một lần trong bảng flow."""
        from nids.nguon_goi import PcapReplaySource
        from test_pipeline import write_pcap
        from test_realtime import handshake_packets
        eng = self.engine()
        with TemporaryDirectory() as d:
            p = write_pcap(Path(d) / "h.pcap", sorted(handshake_packets(n=1), key=lambda x: x[0]))
            for raw in PcapReplaySource(p):
                eng.process(raw)
        self.assertEqual(len(eng.pipe.flows._closing), 1)
        table = eng._flow_table(0)
        self.assertEqual(len(table), 1)


class MetricsTest(unittest.TestCase):
    """C10-T05: đo gói xử lý, gói bỏ, tốc độ, độ trễ, tài nguyên."""

    def fake_runner(self):
        import queue
        engine = SimpleNamespace(stats={"goi_khong_phai_ip": 2, "canh_bao": 7, "cua_so_10s": 3, "cua_so_120s": 1,
                                        "flow_ket_thuc_do_tran": 0,
                                        "thoi_gian_cham_s": {"anomaly": 0.1, "attack_classification": 0.2,
                                                             "botnet_topology": 0.3}},
                                 events=SimpleNamespace(closed=4), state_size=lambda: {"flow_dang_mo": 5})
        source = SimpleNamespace(received=120, kernel_drops=lambda: 3)
        return SimpleNamespace(engine=engine, source=source, q=queue.Queue(), processed=0, dropped=0, max_depth=9)

    def test_report_interval_rate_and_drops(self):
        import json
        from nids.realtime import Metrics
        t = [0.0]
        r = self.fake_runner()
        with TemporaryDirectory() as d:
            m = Metrics(r, Path(d) / "m.jsonl", interval_s=10, clock=lambda: t[0])
            r.processed = 50
            t[0] = 5.0
            self.assertIsNone(m.maybe_report())                                   # chưa tới 10 giây
            t[0] = 10.0
            m.lag(0.1)
            m.lag(0.3)
            row = m.maybe_report()
            self.assertEqual(row["toc_do_goi_s"], 5.0)                            # 50 gói / 10 giây
            self.assertEqual(row["goi_bo_kernel"], 3)
            self.assertEqual(row["do_tre_xu_ly_s"]["lon_nhat"], 0.3)
            self.assertEqual(row["flow_dang_mo"], 5)
            r.processed, r.dropped = 110, 10
            t[0] = 20.0
            m.report()
            s = m.summary()
            m.close()
            lines = (Path(d) / "m.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])["toc_do_goi_s"], 6.0)
        self.assertEqual(s["goi_bo_kernel"], 6)                                   # cộng dồn hai lần đọc
        self.assertAlmostEqual(s["ty_le_bo"], (10 + 6) / (120 + 6), places=5)
        self.assertEqual(s["toc_do_trung_binh_goi_s"], 5.5)
        self.assertEqual(s["do_tre_xu_ly_s"]["p50"], 0.3)                         # trung vị của 0,1 và 0,3 (làm tròn lên)

    def test_rss_and_percentile(self):
        from nids.realtime import _percentile, rss_mb
        mb = rss_mb()
        self.assertTrue(mb is None or mb > 1)
        self.assertEqual(_percentile([1, 2, 3, 4, 5], 0.5), 3)
        self.assertEqual(_percentile([1, 2, 3, 4, 5], 0.95), 5)
        self.assertIsNone(_percentile([], 0.5))


if __name__ == "__main__":
    unittest.main()

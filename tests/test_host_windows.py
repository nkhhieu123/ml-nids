import csv
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.host_windows import CSV_COLUMNS, HostWindower, main
from nids.packets import PacketRecord
from test_packets import ether, ipv4, pcap_file, tcp

A, B, OUT = "192.168.50.41", "192.168.50.30", "8.8.8.8"
S = 10**9


def pkt(src=A, dst=B, ts=0.0, ip_len=40, index=0):
    """Gói tối giản; ``ts`` tính bằng giây."""
    return PacketRecord(index, None if ts is None else round(ts * S), src, dst, 4, 6,
                        ip_len + 14, ip_len, ip_len + 14, 34, False, 40000, 80, 0x10)


def run(packets, **kw):
    w = HostWindower(**kw)
    out = []
    for p in packets:
        w.add(p)
        out += w.pop_finished()
    w.finish_all()
    return w, out + w.pop_finished()


class WindowStartTest(unittest.TestCase):
    def test_each_packet_in_size_over_step_windows(self):
        w = HostWindower(10, 2)
        self.assertEqual(list(w.window_starts(13 * S)), [s * S for s in (4, 6, 8, 10, 12)])

    def test_boundaries(self):
        w = HostWindower(10, 2)
        # ts = 10 s đúng bằng end của cửa sổ [0, 10): không thuộc cửa sổ đó
        self.assertEqual(list(w.window_starts(10 * S))[0], 2 * S)
        self.assertEqual(list(w.window_starts(10 * S - 1))[0], 0)

    def test_non_dividing_step(self):
        w = HostWindower(10, 3)
        starts = list(w.window_starts(20 * S))
        self.assertEqual(starts, [s * S for s in (12, 15, 18)])
        self.assertTrue(all(s <= 20 * S < s + 10 * S for s in starts))

    def test_rejects_bad_step(self):
        with self.assertRaises(ValueError):
            HostWindower(10, 12)


class WindowCountTest(unittest.TestCase):
    def test_both_endpoints_counted(self):
        _, ws = run([pkt(ts=1, ip_len=60), pkt(B, A, ts=1.5, ip_len=1000, index=1)],
                    size_s=10, step_s=10)
        by_host = {w.host: w for w in ws}
        a, b = by_host[A], by_host[B]
        self.assertEqual((a.packets_out, a.packets_in, a.bytes_out, a.bytes_in), (1, 1, 60, 1000))
        self.assertEqual((b.packets_out, b.packets_in), (1, 1))
        self.assertEqual((a.first_ts_ns, a.last_ts_ns), (1 * S, round(1.5 * S)))

    def test_sliding_windows_overlap(self):
        _, ws = run([pkt(ts=5)], size_s=10, step_s=2)
        mine = sorted(w.start_ns // S for w in ws if w.host == A)
        self.assertEqual(mine, [-4, -2, 0, 2, 4])

    def test_network_filter(self):
        _, ws = run([pkt(A, OUT, ts=1)], size_s=10, step_s=10, networks=["192.168.50.0/24"])
        self.assertEqual({w.host for w in ws}, {A})

    def test_ipv6_filter_does_not_match_ipv4_net(self):
        _, ws = run([pkt("fe80::1", "fe80::2", ts=1)], size_s=10, step_s=10,
                    networks=["192.168.50.0/24"])
        self.assertEqual(ws, [])

    def test_silent_host_has_no_window(self):
        _, ws = run([pkt(ts=1), pkt(ts=35, index=1)], size_s=10, step_s=10)
        self.assertEqual(sorted({w.start_ns // S for w in ws}), [0, 30])

    def test_no_time_packets_skipped(self):
        w, ws = run([pkt(ts=None)], size_s=10, step_s=10)
        self.assertEqual((ws, w.no_time_packets), ([], 1))


class StreamingTest(unittest.TestCase):
    def test_window_closes_when_packet_time_reaches_end(self):
        w = HostWindower(10, 10)
        w.add(pkt(ts=1))
        w.add(pkt(ts=9.999))
        self.assertEqual(w.pop_finished(), [])
        w.add(pkt(ts=10, index=2))           # thời điểm = end của [0, 10)
        done = w.pop_finished()
        self.assertEqual([(x.host, x.packets_out) for x in done], [(B, 0), (A, 2)])

    def test_late_packet_whose_windows_all_closed(self):
        w = HostWindower(10, 2)
        w.add(pkt(ts=0))
        w.add(pkt(ts=20, index=1))            # đóng mọi cửa sổ có end <= 20 (start <= 10)
        w.add(pkt(ts=11, index=2))            # 11 s thuộc cửa sổ start 2..10: đều đã đóng
        self.assertEqual(w.late_packets, 1)
        w.finish_all()
        rows = [(x.start_ns // S, x.packets_out) for x in w.pop_finished() if x.host == A]
        # Gói trễ không vào đâu; các cửa sổ còn lại chỉ có gói 20 s
        self.assertEqual([r for r in rows if r[0] >= 12], [(12, 1), (14, 1), (16, 1), (18, 1), (20, 1)])

    def test_late_packet_kept_in_windows_still_open(self):
        w = HostWindower(10, 2)
        w.add(pkt(ts=0))
        w.add(pkt(ts=13, index=1))            # đóng cửa sổ có end <= 13 (start <= 2)
        w.add(pkt(ts=5, index=2))             # 5 s thuộc start -4..4; -4..2 đã đóng, 4 còn mở
        self.assertEqual(w.late_packets, 1)
        w.finish_all()
        counts = {x.start_ns // S: x.packets_out for x in w.pop_finished() if x.host == A}
        self.assertEqual(counts[4], 2)        # cửa sổ [4, 14): gói 5 s và 13 s
        self.assertEqual(counts[0], 1)        # cửa sổ [0, 10) đóng trước khi gói 5 s tới

    def test_emit_delay(self):
        w = HostWindower(10, 10, emit_delay_s=3)
        w.add(pkt(ts=1))
        w.add(pkt(ts=12, index=1))            # end = 10, nhưng còn chờ tới 13
        self.assertEqual(w.pop_finished(), [])
        w.add(pkt(ts=13, index=2))
        self.assertEqual({x.start_ns // S for x in w.pop_finished()}, {0})

    def test_late_packet_after_gap_keeps_order(self):
        # Có thời gian chờ, gói trễ sau khoảng lặng tạo cửa sổ nằm trước cửa sổ đang mở.
        w = HostWindower(10, 2, emit_delay_s=3)
        w.add(pkt(ts=5))
        w.add(pkt(ts=20, index=1))
        w.add(pkt(ts=17, index=2))
        w.finish_all()
        starts = [x.start_ns for x in w.pop_finished() if x.host == A]
        self.assertEqual(starts, sorted(starts))

    def test_streaming_equals_batch(self):
        packets = [pkt(A if i % 3 else B, B if i % 3 else A, ts=i * 0.7, index=i) for i in range(60)]
        _, batch = run(packets, size_s=10, step_s=2)
        w = HostWindower(10, 2)
        for p in packets:
            w.add(p)
        w.finish_all()
        once = w.pop_finished()
        shape = lambda ws: sorted((x.host, x.start_ns, x.packets_out, x.packets_in) for x in ws)
        self.assertEqual(shape(batch), shape(once))


class CliTest(unittest.TestCase):
    def test_cli_writes_csv(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp)
            pcap = pcap_file(d / "t.pcap", [ether(ipv4(payload=tcp())) for _ in range(3)])
            with redirect_stdout(io.StringIO()) as out:
                code = main([str(pcap), "--csv", str(d / "w.csv"), "--net", "192.168.50.20/32"])
            self.assertEqual(code, 0)
            with open(d / "w.csv", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        self.assertEqual(tuple(rows[0]), CSV_COLUMNS)
        self.assertEqual({r["host"] for r in rows}, {"192.168.50.20"})
        # 3 gói ở giây 100, 101, 102 (pcap_file): [92, 102) chứa hai gói, [94, 104) chứa cả ba
        counts = {r["window_start"]: r["packets_out"] for r in rows}
        self.assertEqual((counts["92.000000000"], counts["94.000000000"]), ("2", "3"))
        self.assertIn("3 gói IP", out.getvalue())


if __name__ == "__main__":
    unittest.main()

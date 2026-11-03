import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nids.ctu13 import (FLOW_COLUMNS, extract, flow_group, from_project_flows, is_cc, load_flows,
                        pick_background, prepare_scenario, scan)
from nids.graph_features import host_ports, to_graph, window_edges

BINETFLOW_HEADER = "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n"


def binetflow_rows(rows):
    """rows: (giây kể từ 10:00:00, proto, src, sport, dst, dport, gói, byte, byte nguồn, nhãn)."""
    lines = []
    for t, proto, src, sport, dst, dport, pk, by, sb, lab in rows:
        stamp = pd.Timestamp("2011-08-18 10:00:00") + pd.Timedelta(seconds=t)
        lines.append(f"{stamp.strftime('%Y/%m/%d %H:%M:%S.%f')},1.0,{proto},{src},{sport},  ->,{dst},{dport},"
                     f"CON,0,0,{pk},{by},{sb},flow={lab}\n")
    return BINETFLOW_HEADER + "".join(lines)


def flows_frame(rows):
    """rows: (ts, src, dst, dport, proto, dst_bytes)."""
    df = pd.DataFrame(rows, columns=["ts", "src", "dst", "dport", "proto", "dst_bytes"])
    df["session"] = "s"
    df["end_ts"] = df["ts"] + 1
    df["sport"] = 1000
    df["packets"] = 2
    df["bytes"] = 100
    df["src_bytes"] = 100 - df["dst_bytes"]
    df["state"] = ""
    df["label"] = ""
    return df[FLOW_COLUMNS]


class Ctu13Test(unittest.TestCase):
    """C08-T01: đọc .binetflow thành bảng flow chung."""

    def test_labels(self):
        labels = ["flow=From-Botnet-V52-1-ICMP", "flow=From-Botnet-V52-2-TCP-CC106-IRC-Not-Encrypted",
                  "flow=From-Normal-V52-Grill", "flow=To-Normal-V52-x", "flow=Background-UDP", "flow=To-Botnet-x"]
        self.assertEqual(list(flow_group(labels)), ["tu_bot", "tu_bot", "tu_normal", "toi_normal", "background",
                                                    "toi_bot"])
        self.assertEqual(list(is_cc(labels)), [True if i == 1 else False for i in range(6)])

    def test_scan_and_extract(self):
        rows = [(0, "tcp", "147.32.84.165", 1025, "1.1.1.1", 6667, 10, 1000, 400, "From-Botnet-V52-1-TCP-CC1-IRC"),
                (5, "icmp", "147.32.84.165", "0x0008", "2.2.2.2", "0x0303", 1, 60, 60, "From-Botnet-V52-1-ICMP"),
                (7, "udp", "9.9.9.9", 4000, "147.32.84.165", 5000, 1, 80, 80, "From-Botnet-V53-1-UDP"),
                (9, "tcp", "147.32.84.170", 2000, "3.3.3.3", 80, 6, 900, 300, "From-Normal-V52-Grill"),
                (12, "tcp", "147.32.86.1", 2000, "3.3.3.3", 80, 6, 900, 300, "Background-TCP-Established"),
                (13, "tcp", "4.4.4.4", 2000, "5.5.5.5", 80, 6, 900, 300, "Background")]
        with TemporaryDirectory() as d:
            path = Path(d) / "x.binetflow"
            path.write_text(binetflow_rows(rows), encoding="utf-8")
            info = scan(path, "s")
            self.assertEqual(info["so_flow"], 6)
            self.assertEqual(info["bot"], {"147.32.84.165": 2, "9.9.9.9": 1})
            self.assertEqual(info["so_flow_cc"], 1)
            self.assertEqual(info["_background_src"], {"147.32.86.1": 1})       # chỉ host nội bộ
            f = extract(path, "s", ["147.32.84.165"])
            self.assertEqual(len(f), 3)
            self.assertEqual(f.loc[1, "dport"], 0x0303)                         # cổng ICMP dạng hex
            self.assertAlmostEqual(f.loc[0, "dst_bytes"], 600)
            self.assertAlmostEqual(f.loc[1, "ts"] - f.loc[0, "ts"], 5, places=4)
            res = prepare_scenario(path, 11, d, n_background=5)
            self.assertEqual(res["host"]["bot"], ["147.32.84.165"])            # peer ngoài không là host xét
            self.assertEqual(res["peer_bot_ben_ngoai"], ["9.9.9.9"])
            self.assertEqual(res["host"]["binh_thuong"], ["147.32.84.170"])
            self.assertEqual(len(load_flows(d, [11])), 4)

    def test_pick_background(self):
        src = {f"147.32.1.{i}": 30 for i in range(10)} | {"147.32.9.9": 5}
        a = pick_background(src, {"147.32.1.0"}, 3, seed=1)
        self.assertEqual(len(a), 3)
        self.assertNotIn("147.32.1.0", a)
        self.assertNotIn("147.32.9.9", a)                                      # quá ít flow
        self.assertEqual(a, pick_background(src, {"147.32.1.0"}, 3, seed=1))

    def test_from_project_flows(self):
        df = pd.DataFrame({"first_ts": [1.0], "last_ts": [2.0], "protocol": ["6"], "fwd_ip": ["a"], "fwd_port": [1],
                           "bwd_ip": ["b"], "bwd_port": [80], "packets": [3], "bytes": [10], "fwd_bytes": [4],
                           "bwd_bytes": [6]})
        out = from_project_flows(df, "cic")
        self.assertEqual(list(out.columns), FLOW_COLUMNS)
        self.assertEqual(out.loc[0, "proto"], "tcp")
        self.assertEqual((out.loc[0, "src"], out.loc[0, "dst"], out.loc[0, "dport"]), ("a", "b", 80))


class WindowGraphTest(unittest.TestCase):
    """C08-T01: cạnh theo cửa sổ 120 giây, bước 10 giây."""

    def test_flow_in_twelve_windows(self):
        f = flows_frame([(25.0, "h", "p", 80, "tcp", 50)])
        e = window_edges(f, ["h"], 120, 10)
        self.assertEqual(sorted(e["window_start"]), list(np.arange(-90.0, 30.0, 10.0)))   # mọi ws có ws <= 25 < ws+120
        self.assertTrue((e["so_flow"] == 1).all())
        self.assertTrue((e["huong"] == "ra").all())

    def test_weights_and_directions(self):
        f = flows_frame([(1.0, "h", "p", 80, "tcp", 50), (2.0, "h", "p", 443, "tcp", 0), (3.0, "q", "h", 22, "udp", 0),
                         (4.0, "h", "g", 53, "udp", 10)])
        e = window_edges(f, ["h", "g"], 120, 10)
        w = e[e["window_start"] == 0]
        hp = w[(w["host"] == "h") & (w["peer"] == "p")].iloc[0]
        self.assertEqual((hp["so_flow"], hp["so_cong"], hp["so_flow_khong_tra_loi"]), (2, 2, 1))
        hq = w[(w["host"] == "h") & (w["peer"] == "q")].iloc[0]
        self.assertEqual((hq["huong"], hq["so_flow_udp"]), ("vao", 1))
        gh = w[(w["host"] == "g")].iloc[0]                                      # g cũng là host xét: thấy cạnh vào
        self.assertEqual((gh["peer"], gh["huong"]), ("h", "vao"))
        g = to_graph(w)
        self.assertEqual(g.number_of_edges(), 3)                                # h->g chỉ tính một lần
        self.assertTrue(g.has_edge("q", "h"))
        ports = host_ports(f, ["h"], 120, 10)
        self.assertEqual(int(ports.loc[ports["window_start"] == 0, "so_cong_ra"].iloc[0]), 3)

    def test_window_must_be_multiple(self):
        with self.assertRaises(ValueError):
            window_edges(flows_frame([(1.0, "h", "p", 80, "tcp", 0)]), ["h"], 125, 10)


if __name__ == "__main__":
    unittest.main()

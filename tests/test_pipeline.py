import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.dataset import feature_columns
from nids.pipeline import (ERROR, WARNING, Artifact, Timer, check_artifact, check_table, expected_inputs, extract,
                           load_artifacts, load_flows, load_windows, monitored_hosts, pipeline_config,
                           run_independent)


def fake(module, features, threshold=1.0, meta=None, classes=None):
    model = SimpleNamespace(features=features, threshold=threshold, classes=classes or ["benign", "dos"])
    meta = {"dac_trung": features, "ma_nguon": {"commit": "abc", "co_sua_chua_commit": False}} if meta is None else meta
    return Artifact(module, Path("x.joblib"), model, meta)


class ArtifactTest(unittest.TestCase):
    """C09-T01: nạp artifact và kiểm tra schema."""

    def test_valid(self):
        feats = feature_columns("windows")[:5]
        self.assertEqual(check_artifact(fake("anomaly", feats)), [])

    def test_problems(self):
        bad = fake("anomaly", ["khong_co_cot"], threshold=None)
        levels = [lv for lv, _ in check_artifact(bad)]
        self.assertEqual(levels.count(ERROR), 2)                                   # cột lạ, thiếu ngưỡng
        dirty = fake("botnet_topology", expected_inputs("botnet_topology")[:3],
                     meta={"dac_trung": expected_inputs("botnet_topology")[:3],
                           "ma_nguon": {"commit": "abc", "co_sua_chua_commit": True}})
        self.assertEqual([lv for lv, _ in check_artifact(dirty)], [WARNING])       # mã chưa commit: chỉ cảnh báo
        mismatch = fake("attack_classification", feature_columns("windows")[:3],
                        meta={"dac_trung": ["a"], "ma_nguon": {"commit": "abc"}}, classes=["benign", "ddos"])
        msgs = " ".join(m for _, m in check_artifact(mismatch))
        self.assertIn("khác mô hình", msgs)
        self.assertIn("ddos", msgs)
        self.assertIn("thiếu file .json", " ".join(m for _, m in check_artifact(fake("anomaly", [], meta={}))))

    def test_check_table(self):
        a = fake("anomaly", ["x", "y"])
        check_table(pd.DataFrame({"x": [1], "y": [2], "z": [3]}), a)
        with self.assertRaises(ValueError):
            check_table(pd.DataFrame({"x": [1]}), a)

    def test_load(self):
        from nids.botnet import BotnetDetector, feature_names, save_model
        rng = np.random.default_rng(0)
        df = pd.DataFrame(rng.random((60, len(feature_names()))), columns=feature_names())
        df["label_host"] = ["suspect_host", "normal_host"] * 30
        with TemporaryDirectory() as d:
            save_model(BotnetDetector("logistic_regression", {}).fit(df), Path(d) / "b.joblib")
            cfg = {"pipeline": {"models": {"botnet_topology": str(Path(d) / "b.joblib"),
                                           "anomaly": str(Path(d) / "khong_co.joblib")}}}
            arts = load_artifacts(cfg, modules=("botnet_topology",))
            self.assertEqual(arts["botnet_topology"].features, feature_names())
            self.assertTrue(arts["botnet_topology"].meta)
            with self.assertRaises(FileNotFoundError):
                load_artifacts(cfg, modules=("anomaly",))
        self.assertTrue(pipeline_config({})["models"]["anomaly"].endswith("gaussian_windows.joblib"))


import socket
import struct


def frame(src, dst, sport, dport, flags):
    """Khung Ethernet + IPv4 + TCP tối thiểu (checksum 0: bộ đọc không kiểm tra checksum)."""
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 65535, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + ip + tcp


def write_pcap(path, packets):
    """packets: (giây, khung). PCAP nano giây."""
    out = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 262144, 1)
    for t, fr in packets:
        sec, ns = divmod(int(round(t * 1e9)), 10 ** 9)
        out += struct.pack("<IIII", sec, ns, len(fr), len(fr)) + fr
    Path(path).write_bytes(out)
    return Path(path)


def scan_pcap(path, t0=1_500_000_000.0):
    """192.168.10.5 quét SYN 200 cổng của .50 trong 20 giây; .7 có vài kết nối bắt tay đầy đủ tới .50:80."""
    pk = []
    for i in range(200):
        t = t0 + 0.1 * i
        pk.append((t, frame("192.168.10.5", "192.168.10.50", 40000, 1 + i, 0x02)))
        pk.append((t + 0.001, frame("192.168.10.50", "192.168.10.5", 1 + i, 40000, 0x14)))      # RST+ACK
    for k in range(5):
        t = t0 + 5 * k
        pk += [(t, frame("192.168.10.7", "192.168.10.50", 50000 + k, 80, 0x02)),
               (t + 0.01, frame("192.168.10.50", "192.168.10.7", 80, 50000 + k, 0x12)),
               (t + 0.02, frame("192.168.10.7", "192.168.10.50", 50000 + k, 80, 0x10)),
               (t + 0.5, frame("192.168.10.7", "192.168.10.50", 50000 + k, 80, 0x11)),
               (t + 0.51, frame("192.168.10.50", "192.168.10.7", 80, 50000 + k, 0x11))]
    return write_pcap(path, sorted(pk, key=lambda x: x[0]))


class FakeWindowModel:
    """Mô hình giả: báo bất thường / port_scan khi số cổng đích lớn."""

    def __init__(self, features=("dst_ports",), threshold=50.0):
        self.features = list(features)
        self.threshold = threshold
        self.classes = ["benign", "dos", "port_scan"]

    def predict_frame(self, df):
        out = df[["session", "host", "window_start", "window_end"]].copy()
        out["d2"] = df["dst_ports"].fillna(0).to_numpy(float)
        out["du_doan"] = np.where(out["d2"] > self.threshold, "anomaly", "normal")
        return out

    def predict_proba(self, df):
        scan = (df["dst_ports"].fillna(0).to_numpy(float) > self.threshold).astype(float)
        return np.column_stack([1 - scan, np.zeros(len(df)), scan])


class FakeBotnet:
    def __init__(self):
        from nids.botnet import feature_names
        self.features = feature_names()
        self.threshold = 0.5

    def score(self, df):
        return (df["so_cong_ra"].to_numpy(float) > 50).astype(float)


def fake_artifacts():
    return {"anomaly": Artifact("anomaly", Path("a"), FakeWindowModel()),
            "attack_classification": Artifact("attack_classification", Path("b"), FakeWindowModel()),
            "botnet_topology": Artifact("botnet_topology", Path("c"), FakeBotnet())}


class PcapPipelineTest(unittest.TestCase):
    """C09-T02: PCAP qua toàn bộ pipeline."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.pcap = scan_pcap(self.dir / "scan.pcap")

    def test_cut(self):
        from nids.pcap_cut import cut, parse_time
        from nids.pcap_reader import read_packets
        r = cut(self.pcap, self.dir / "cut.pcap", 1_500_000_005.0, 1_500_000_010.0, slack_s=1.0)
        back = list(read_packets(self.dir / "cut.pcap"))
        self.assertEqual(len(back), r["goi_ghi"])
        self.assertTrue(all(5e9 <= p.ts_ns - 1_500_000_000 * 10 ** 9 < 10e9 for p in back))
        self.assertLess(r["goi_doc"], 460)                                        # dừng sớm sau ket_thuc + du
        self.assertEqual(parse_time("2017-07-07 15:00", -3), parse_time("2017-07-07 18:00", 0))

    def test_extract_and_run(self):
        prefix = extract(self.pcap, self.dir / "out", ["192.168.10.0/24"])
        windows, flows = load_windows(prefix), load_flows(prefix)
        self.assertEqual(monitored_hosts(flows, ["192.168.10.0/24"]), ["192.168.10.5", "192.168.10.50", "192.168.10.7"])
        self.assertEqual(len(flows), 205)
        timer = Timer()
        res = run_independent(fake_artifacts(), windows, flows, ["192.168.10.0/24"], {}, timer)
        self.assertEqual(set(timer.steps), {"anomaly", "attack_classification", "botnet_topology"})
        scan = res["attack_classification"]
        self.assertIn("port_scan", set(scan.loc[scan["host"] == "192.168.10.5", "du_doan"]))
        self.assertNotIn("port_scan", set(scan.loc[scan["host"] == "192.168.10.7", "du_doan"]))
        bot = res["botnet_topology"]
        self.assertTrue((bot.loc[bot["host"] == "192.168.10.5", "du_doan"] == "suspect_host").any())
        self.assertTrue(set(bot.loc[bot["du_doan"] == "suspect_host", "topology"]) <= {"centralized", "p2p"})
        self.assertTrue(((bot["window_end"] - bot["window_start"]) == 120).all())


if __name__ == "__main__":
    unittest.main()

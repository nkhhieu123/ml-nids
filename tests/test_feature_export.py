import csv
import hashlib
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nids.feature_export import (
    ROLE_FEATURE, ROLE_ID, ROLES, SCHEMA_VERSION, TYPES, export, main, read_table, table_schemas,
)
from nids.flows import CSV_COLUMNS as FLOW_COLUMNS
from nids.packets import TCP_ACK, TCP_RST, TCP_SYN
from nids.window_features import CSV_COLUMNS as WINDOW_COLUMNS
from test_packets import IP_A, IP_B, ether, ipv4, pcap_file, tcp, udp


class SchemaTest(unittest.TestCase):
    def test_every_column_described_in_order(self):
        schemas = table_schemas()
        self.assertEqual([c["ten"] for c in schemas["flows"]], list(FLOW_COLUMNS))
        self.assertEqual([c["ten"] for c in schemas["windows"]], list(WINDOW_COLUMNS))
        for table in schemas.values():
            for col in table:
                self.assertIn(col["vai_tro"], ROLES, col["ten"])
                self.assertIn(col["kieu"], TYPES, col["ten"])
                self.assertTrue(col["mo_ta"], col["ten"])

    def test_addresses_and_times_are_not_features(self):
        roles = {(t, c["ten"]): c["vai_tro"] for t, cols in table_schemas().items() for c in cols}
        for t, name in (("flows", "fwd_ip"), ("flows", "bwd_port"), ("flows", "first_ts"),
                        ("windows", "host"), ("windows", "window_start")):
            self.assertEqual(roles[(t, name)], ROLE_ID, name)
        self.assertEqual(roles[("flows", "iat_mean")], ROLE_FEATURE)
        self.assertEqual(roles[("windows", "incomplete_ratio_out")], ROLE_FEATURE)


class ExportTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        frames = [
            ether(ipv4(payload=tcp(40000, 80, TCP_SYN))),
            ether(ipv4(payload=tcp(80, 40000, TCP_SYN | TCP_ACK), src=IP_B, dst=IP_A)),
            ether(ipv4(payload=tcp(40000, 80, TCP_ACK, b"GET /"))),
            ether(ipv4(payload=tcp(40001, 23, TCP_SYN))),
            ether(ipv4(payload=tcp(23, 40001, TCP_RST | TCP_ACK), src=IP_B, dst=IP_A)),
            ether(ipv4(17, udp())),
        ]
        self.pcap = pcap_file(self.dir / "lab.pcap", frames)
        self.out = self.dir / "out"
        self.meta = export(self.pcap, self.out, networks=["192.168.50.0/24"], compute_hash=True)

    def test_four_files_and_metadata(self):
        names = sorted(p.name for p in self.out.iterdir())
        self.assertEqual(names, ["lab.flows.csv", "lab.meta.json", "lab.schema.json", "lab.windows.csv"])
        m = json.loads((self.out / "lab.meta.json").read_text(encoding="utf-8"))
        self.assertEqual(m["phien_ban_schema"], SCHEMA_VERSION)
        self.assertEqual(m["nguon"]["sha256"], hashlib.sha256(self.pcap.read_bytes()).hexdigest())
        self.assertEqual(m["bang"]["flows"]["so_dong"], 3)
        self.assertEqual(m["tham_so"]["cua_so"]["dai_mang"], ["192.168.50.0/24"])
        self.assertEqual(m["thong_ke"]["packet"]["giu_lai"], 6)
        self.assertIn("idle_timeout_s", m["tham_so"]["flow"])

    def test_read_back_with_types(self):
        flows = read_table(self.out / "lab.flows.csv")
        self.assertEqual(sum(r["packets"] for r in flows), 6)
        http = next(r for r in flows if r["bwd_port"] == 80)
        self.assertEqual((http["payload_bytes"], http["syn_count"], http["fwd_ip"]),
                         (5, 2, "192.168.50.20"))
        self.assertIsInstance(http["pkt_len_mean"], float)
        udp_flow = next(r for r in flows if r["protocol"] == 17)
        self.assertIsNone(udp_flow["iat_mean"])                  # một gói: không có khoảng cách
        wins = read_table(self.out / "lab.windows.csv")
        best = max(wins, key=lambda r: r["tcp_attempts_out"])
        self.assertEqual((best["host"], best["tcp_attempts_out"], best["incomplete_out"],
                          best["incomplete_ratio_out"]), ("192.168.50.20", 2, 1, 0.5))

    def test_rejects_changed_columns(self):
        path = self.out / "lab.windows.csv"
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("dst_hosts", "dst_host", 1), encoding="utf-8")
        with self.assertRaises(ValueError):
            read_table(path)

    def test_rejects_empty_required_cell(self):
        path = self.out / "lab.flows.csv"
        with path.open(encoding="utf-8", newline="") as f:
            rows = list(csv.reader(f))
        rows[1][rows[0].index("packets")] = ""
        with path.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)
        with self.assertRaises(ValueError):
            read_table(path)

    def test_rejects_other_schema_version(self):
        schema = self.out / "lab.schema.json"
        doc = json.loads(schema.read_text(encoding="utf-8"))
        doc["phien_ban_schema"] = "0.9"
        schema.write_text(json.dumps(doc), encoding="utf-8")
        with self.assertRaises(ValueError):
            read_table(self.out / "lab.flows.csv")

    def test_cli(self):
        with redirect_stdout(io.StringIO()) as out:
            code = main([str(self.pcap), "--out", str(self.dir / "cli"), "--name", "x"])
        self.assertEqual(code, 0)
        self.assertTrue((self.dir / "cli" / "x.windows.csv").exists())
        self.assertIn("3 flow", out.getvalue())


if __name__ == "__main__":
    unittest.main()

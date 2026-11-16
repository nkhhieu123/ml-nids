"""Kế hoạch lần chạy của scripts/lab_ao.py phải khớp tham số kịch bản đã chốt trong config/default.yaml (QĐ-062)."""

import importlib.util
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nids.config import load_config

spec = importlib.util.spec_from_file_location("lab_ao", ROOT / "scripts" / "lab_ao.py")
lab_ao = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab_ao)

LAB = load_config()["lab"]


def behavior(variant, lan):
    return lab_ao.plan(variant, lan, random.Random(1))["hanh_vi"][0]


class LabPlanMatchesConfigTest(unittest.TestCase):
    def test_hosts(self):
        self.assertEqual({lab_ao.ip(h) for h in lab_ao.HOSTS}, set(LAB["hosts"]))
        self.assertEqual(lab_ao.ip(lab_ao.SERVER), LAB["may_chu_dich"])

    def test_scan(self):
        q = LAB["quet"]
        for variant, extra, gap in (("k2-quet-cham", q["nmap_cham"], q["toc_do_cham_s"]),
                                    ("k2-quet-nhanh", q["nmap_nhanh"], q["toc_do_nhanh_s"])):
            b = behavior(variant, 1)
            cmd = b["lenh"][lab_ao.TESTER]
            self.assertEqual(cmd, ["nmap", *q["nmap_chung"][:3], "-p", f"{q['cong_dau']}-{q['cong_cuoi']}",
                                   *q["nmap_chung"][3:], *extra, LAB["may_chu_dich"]])
            self.assertEqual(b["tham_so"]["gian_cach_s"], gap)

    def test_connection_load(self):
        t = LAB["tai_ket_noi"]
        levels = {m: t[f"muc{m}_moi_giay"] for m in (1, 2, 3)}
        traffic_spec = importlib.util.spec_from_file_location("sinh_traffic", ROOT / "scripts" / "sinh_traffic.py")
        traffic = importlib.util.module_from_spec(traffic_spec)
        traffic_spec.loader.exec_module(traffic)
        self.assertEqual(traffic.DOS_LEVELS, levels)
        self.assertEqual(traffic.DOS_MAX_S, t["thoi_gian_toi_da_s"])
        for m in levels:
            self.assertEqual(behavior(f"k3-dos-muc{m}", 1)["tham_so"], {"cong": 80, "muc": m, "thoi_gian_s": 60})

    def test_centralized(self):
        c = LAB["tap_trung"]
        for variant, key in (("k4-co-dinh", "jitter_co_dinh"), ("k4-bien-thien", "jitter_bien_thien"),
                             ("k4-doi-chung", "jitter_doi_chung")):
            for lan in (1, 2, 3):
                p = behavior(variant, lan)["tham_so"]
                self.assertEqual((p["chu_ky_s"], p["jitter"], p["thoi_gian_s"]),
                                 (c["chu_ky_s"][lan - 1], c[key][lan - 1], c["thoi_gian_s"]), (variant, lan))
        self.assertEqual(behavior("k4-co-dinh", 1)["tham_so"]["cong"], c["cong"])

    def test_p2p(self):
        n = LAB["ngang_hang"]
        self.assertEqual(len(lab_ao.CLIENTS), n["so_bot"])
        for lan in (1, 2, 3):
            p = behavior("k5-p2p", lan)["tham_so"]
            self.assertEqual((p["cong"], p["chu_ky_s"], p["jitter"], p["thoi_gian_s"]),
                             (n["cong"], n["chu_ky_s"][lan - 1], n["jitter"][lan - 1], n["thoi_gian_s"]))
            per_bot = {len(v) for v in p["peer"].values()}
            self.assertEqual(per_bot, {2} if n["peer"][lan - 1] == "luoi" else {1})
        self.assertEqual(behavior("k5-doi-chung", 1)["tham_so"]["cong"], n["cong_doi_chung"])

    def test_five_bots(self):
        c = LAB["nam_bot"]
        self.assertEqual(len(lab_ao.BOTS5), c["so_bot"])
        self.assertEqual(lab_ao.BOTS5[:3], lab_ao.CLIENTS)            # kịch bản 1–5 vẫn dùng ba máy cũ
        for lan in (1, 2, 3):
            t = behavior("k6-tap-trung", lan)
            self.assertEqual(len(t["nguon"]), 5)
            self.assertEqual((t["tham_so"]["cong"], t["tham_so"]["chu_ky_s"], t["tham_so"]["jitter"]),
                             (c["tap_trung_cong"], c["tap_trung_chu_ky_s"][lan - 1], c["tap_trung_jitter"][lan - 1]))
            p = behavior("k6-p2p", lan)["tham_so"]
            self.assertEqual((p["cong"], p["chu_ky_s"], p["jitter"]),
                             (c["p2p_cong"], c["p2p_chu_ky_s"][lan - 1], c["p2p_jitter"][lan - 1]))
            want = {"luoi": 4, "vong": 1, "hai_ke": 2}[c["peer"][lan - 1]]
            self.assertEqual({len(v) for v in p["peer"].values()}, {want})
            self.assertTrue(all(lab_ao.ip(lab_ao.CC) not in v for v in p["peer"].values()))
            d = behavior("k6-doi-chung", lan)
            self.assertEqual((d["nhan"], d["dich"], d["tham_so"]["chu_ky_s"]),
                             ("benign", [lab_ao.SERVER], c["doi_chung_chu_ky_s"][lan - 1]))
        for v in lab_ao.MAIN_VARIANTS:                                 # .44, .45 im lặng ngoài kịch bản 6
            p = lab_ao.plan(v, 1, random.Random(1))
            used = set(p["nen"]) | {h for b in p["hanh_vi"] for h in b["lenh"]}
            self.assertFalse(used & {44, 45}, v)


if __name__ == "__main__":
    unittest.main()

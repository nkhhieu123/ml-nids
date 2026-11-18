"""LightGBM và mô hình học sâu cho bộ phân loại tấn công, so với Random Forest (mô hình cơ sở) (QĐ-084).

Mọi mô hình dùng cùng dữ liệu, cùng chia tập, cùng bộ tiền xử lý với Chặng 7 (``classifier.prepare_data``,
``Preprocessor`` fit trên train). Tham số và số vòng học chọn trên **validation**; test chỉ đọc một lần ở cuối.

- ``lightgbm``: cây tăng cường theo gradient (LightGBM), dò lưới tham số trên validation. Không phải học sâu.
- ``mlp``: mạng nơ-ron truyền thẳng (PyTorch), đầu vào là 20 đặc trưng của cửa sổ hiện tại.
- ``gru``: mạng hồi quy GRU (PyTorch), đầu vào là **chuỗi** cửa sổ hiện tại và ``K`` cửa sổ **trước đó** của cùng
  máy, kèm khoảng cách thời gian. Chỉ nhìn về quá khứ nên dùng được trong realtime. Ý tưởng: DoS HTTP chậm và quét
  chậm trải dài nhiều cửa sổ; một cửa sổ đơn lẻ có thể trông bình thường nhưng chuỗi thì không.

Mạng nơ-ron học bằng Adam, hàm mất mát entropy chéo có trọng số lớp (căn bậc hai nghịch tần suất), dừng sớm theo
macro-F1 validation. Seed cố định; kết quả mỗi mô hình là trung bình và độ lệch của ``--so-lan`` seed.

    cd src
    python -m nids.hoc_sau ../output/features/cic17_wednesday ../output/features/cic17_friday \\
        --chon ../docs/hinh/phan_loai_chon.json --out ../docs/hinh/hoc_sau
"""

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

from . import classifier as clf
from .dataset import feature_columns
from .preprocessing import Preprocessor, log_columns

LABELS = list(clf.ATTACK_LABELS)                  # benign, port_scan, dos
LGB_GRID = [{"num_leaves": nl, "learning_rate": lr, "min_child_samples": mc, "class_weight": cw}
            for nl in (31, 63, 127) for lr in (0.05, 0.1) for mc in (10, 40) for cw in (None, "balanced")]


def metrics(y, pred) -> dict:
    m = clf.multiclass_metrics(np.asarray(LABELS)[y], np.asarray(LABELS)[pred])
    benign = y == 0
    m["ty_le_benign_bi_bao"] = round(float((pred[benign] != 0).mean()), 5)
    return m


# ---------------------------------------------------------------- dữ liệu

def build(prefixes, cfg, k):
    """Ma trận đặc trưng đã tiền xử lý của cả bảng, chỉ số mẫu từng tập, và chỉ số K cửa sổ trước của mỗi dòng."""
    full = clf.load_data(prefixes, cfg["sessions"]).sort_values(["session", "host", "window_start"]).reset_index(drop=True)
    data = clf.prepare_data(full, None, cfg["random_seed"], cfg["drop_train_duplicates"])
    feats = feature_columns(clf.TABLE)
    pre = Preprocessor(clf.TABLE, feats, log_columns(clf.TABLE, feats)).fit(data["train_full"])
    X = pre.transform(full).astype(np.float32)
    key = lambda d: list(zip(d["session"], d["host"], d["window_start"]))
    pos = {t: i for i, t in enumerate(key(full))}
    idx = {s: np.array([pos[t] for t in key(data[s])]) for s in ("train", "validation", "test")}
    y = {s: np.array([LABELS.index(v) for v in data[s][clf.LABEL_COL]]) for s in idx}
    # K cửa sổ trước của cùng (phiên, máy); -1 nếu không có. Khoảng cách thời gian tới cửa sổ hiện tại (log giây).
    grp = (full["session"] + "|" + full["host"].astype(str)).to_numpy()
    ws = full["window_start"].to_numpy(float)
    prev = np.full((len(full), k), -1, dtype=np.int64)
    for j in range(1, k + 1):
        ok = np.r_[np.zeros(j, bool), grp[j:] == grp[:-j]]
        prev[ok, k - j] = np.flatnonzero(ok) - j
    gap = np.where(prev >= 0, np.log1p(np.clip(ws[:, None] - ws[np.clip(prev, 0, None)], 0, None)), 0.0).astype(np.float32)
    return {"X": X, "idx": idx, "y": y, "prev": prev, "gap": gap, "info": data["info"],
            "so_dac_trung": X.shape[1], "full": full, "data": data}


def sequences(b, rows):
    """Tensor (n, K+1, d+2): K cửa sổ trước và cửa sổ hiện tại; thêm kênh khoảng cách thời gian và kênh có/không."""
    X, prev, gap = b["X"], b["prev"][rows], b["gap"][rows]
    n, k = prev.shape
    d = X.shape[1]
    out = np.zeros((n, k + 1, d + 2), np.float32)
    has = prev >= 0
    out[:, :k, :d] = np.where(has[..., None], X[np.clip(prev, 0, None)], 0.0)
    out[:, :k, d] = gap
    out[:, :k, d + 1] = has
    out[:, k, :d] = X[rows]
    out[:, k, d + 1] = 1.0
    return out


# ---------------------------------------------------------------- LightGBM

def run_lightgbm(b, seed, log, context=False):
    """``context``: đầu vào là chuỗi K cửa sổ trước + cửa sổ hiện tại trải phẳng, cùng thông tin GRU được thấy."""
    import lightgbm as lgb

    feat = (lambda s: sequences(b, b["idx"][s]).reshape(len(b["idx"][s]), -1)) if context else (lambda s: b["X"][b["idx"][s]])
    Xtr, ytr = feat("train"), b["y"]["train"]
    Xva, yva = feat("validation"), b["y"]["validation"]
    rows = []
    best = None
    for p in LGB_GRID:
        t0 = time.perf_counter()
        m = lgb.LGBMClassifier(n_estimators=2000, random_state=seed, n_jobs=4, verbose=-1, **p)
        m.fit(Xtr, ytr, eval_set=[(Xva, yva)], callbacks=[lgb.early_stopping(100, verbose=False)])
        f1 = metrics(yva, m.predict(Xva))["macro_f1"]
        rows.append({**p, "so_vong": int(m.best_iteration_ or m.n_estimators), "macro_f1_validation": f1,
                     "giay": round(time.perf_counter() - t0, 1)})
        if best is None or f1 > best[0]:
            best = (f1, p, m)
    log(f"LightGBM{' + ngữ cảnh' if context else ''} tốt nhất trên validation: {best[1]} macro-F1 {best[0]}")
    best[2].feat = feat
    return best[2], {"luoi": rows, "chon": {**best[1], "so_vong": rows[[r["macro_f1_validation"] for r in rows].index(best[0])]["so_vong"]}}


# ---------------------------------------------------------------- PyTorch

TORCH_DEFAULT = {"an": 64, "luy_thua_trong_so": 0.5, "lr": 1e-3}
TORCH_GRID = [{"an": an, "luy_thua_trong_so": w, "lr": lr} for an in (64, 128) for w in (0.0, 0.25, 0.5) for lr in (1e-3, 3e-4)]


def run_torch(kind, b, seed, epochs=40, patience=8, log=print, params=None):
    """Học một mạng; trả (hàm dự đoán xác suất theo tập, thông tin). Dừng sớm theo macro-F1 validation."""
    p = {**TORCH_DEFAULT, **(params or {})}
    h = p["an"]
    import torch
    from torch import nn

    torch.manual_seed(seed)
    np.random.seed(seed)
    torch.set_num_threads(4)
    get = (lambda s: b["X"][b["idx"][s]]) if kind == "mlp" else (lambda s: sequences(b, b["idx"][s]))
    Xtr, Xva = torch.tensor(get("train")), torch.tensor(get("validation"))
    ytr = torch.tensor(b["y"]["train"])
    d = Xtr.shape[-1]
    if kind == "mlp":
        net = nn.Sequential(nn.Linear(d, 2 * h), nn.ReLU(), nn.Dropout(0.2), nn.Linear(2 * h, h), nn.ReLU(),
                            nn.Dropout(0.2), nn.Linear(h, len(LABELS)))
    else:
        class Seq(nn.Module):
            def __init__(self):
                super().__init__()
                self.inp = nn.Linear(d, h)
                self.gru = nn.GRU(h, h, batch_first=True)
                self.head = nn.Sequential(nn.ReLU(), nn.Dropout(0.2), nn.Linear(2 * h, len(LABELS)))

            def forward(self, x):
                h, _ = self.gru(torch.relu(self.inp(x)))
                cur = torch.relu(self.inp(x[:, -1]))          # cửa sổ hiện tại đi thẳng tới đầu ra
                return self.head(torch.cat([h[:, -1], cur], 1))
        net = Seq()
    counts = np.bincount(b["y"]["train"], minlength=len(LABELS))
    w = torch.tensor((counts.sum() / np.maximum(counts, 1)) ** p["luy_thua_trong_so"], dtype=torch.float32)
    loss_fn = nn.CrossEntropyLoss(weight=w / w.mean())
    opt = torch.optim.Adam(net.parameters(), lr=p["lr"], weight_decay=1e-5)

    def proba(X):
        net.eval()
        with torch.no_grad():
            return torch.cat([torch.softmax(net(X[i:i + 4096]), 1) for i in range(0, len(X), 4096)]).numpy()

    predict = lambda X: proba(X).argmax(1)

    best, best_state, bad, hist = -1.0, None, 0, []
    for ep in range(epochs):
        net.train()
        perm = torch.randperm(len(Xtr))
        for i in range(0, len(perm), 512):
            j = perm[i:i + 512]
            opt.zero_grad()
            loss_fn(net(Xtr[j]), ytr[j]).backward()
            opt.step()
        f1 = metrics(b["y"]["validation"], predict(Xva))["macro_f1"]
        hist.append(f1)
        if f1 > best:
            best, best_state, bad = f1, {k: v.clone() for k, v in net.state_dict().items()}, 0
        else:
            bad += 1
            if bad >= patience:
                break
    net.load_state_dict(best_state)
    log(f"{kind} {p} seed {seed}: macro-F1 validation tốt nhất {best} sau {hist.index(best) + 1} vòng")
    return (lambda s: proba(torch.tensor(get(s)))), {"vong_tot_nhat": hist.index(best) + 1, "lich_su_validation": hist,
                                                       "macro_f1_validation": best}


# ---------------------------------------------------------------- chạy

def main(argv=None):
    from .config import load_config

    ap = argparse.ArgumentParser(description="LightGBM, MLP và GRU cho bộ phân loại tấn công, so với Random Forest.")
    ap.add_argument("prefixes", nargs="+")
    ap.add_argument("--chon", required=True, help="JSON của nids.classifier chon (tham số Random Forest cơ sở)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--k", type=int, default=5, help="số cửa sổ trước đưa vào GRU")
    ap.add_argument("--so-lan", type=int, default=3, help="số seed cho mỗi mô hình")
    ap.add_argument("--config")
    ap.add_argument("--chi-ngu-canh", action="store_true",
                    help="chỉ chạy LightGBM + ngữ cảnh rồi thêm vào hoc_sau.json đã có")
    a = ap.parse_args(argv)
    cfg = clf.classifier_config(load_config(a.config))
    b = build(a.prefixes, cfg, a.k)
    log = lambda s: print(s, flush=True)
    yva, yte = b["y"]["validation"], b["y"]["test"]
    res = {"du_lieu": b["info"], "k_cua_so_truoc": a.k, "mo_hinh": {}}
    old = Path(a.out) / "hoc_sau.json"
    if a.chi_ngu_canh:
        res = json.loads(old.read_text(encoding="utf-8"))

    def record(name, preds_by_seed, extra):
        val = [metrics(yva, p["validation"]) for p in preds_by_seed]
        te = [metrics(yte, p["test"]) for p in preds_by_seed]
        f = lambda ms: {"trung_binh": round(float(np.mean([m["macro_f1"] for m in ms])), 4),
                        "do_lech": round(float(np.std([m["macro_f1"] for m in ms])), 4)}
        res["mo_hinh"][name] = {"macro_f1_validation": f(val), "macro_f1_test": f(te), "test_lan_dau": te[0],
                                "test_theo_seed": [m["macro_f1"] for m in te], **extra}
        log(f"{name}: validation {f(val)} test {f(te)}")
        return te[0]

    if a.chi_ngu_canh:
        m, info = run_lightgbm(b, 42, log, context=True)
        record("lightgbm + ngữ cảnh K cửa sổ", [{p: m.predict(m.feat(p)) for p in ("validation", "test")}],
               {"chon_tham_so": info["chon"], "luoi": info["luoi"]})
        old.write_text(json.dumps(res, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return 0
    # Mô hình cơ sở: Random Forest với tham số đã chọn ở Chặng 7, trên cùng ma trận đặc trưng
    from sklearn.ensemble import RandomForestClassifier
    rf_par = json.loads(Path(a.chon).read_text(encoding="utf-8"))["mo_hinh"]["random_forest"]["tot_nhat"]["tham_so"]
    preds = []
    for s in range(a.so_lan):
        t0 = time.perf_counter()
        rf = RandomForestClassifier(random_state=42 + s, n_jobs=4, **rf_par).fit(b["X"][b["idx"]["train"]], b["y"]["train"])
        preds.append({p: rf.predict(b["X"][b["idx"][p]]) for p in ("validation", "test")})
    record("random_forest (cơ sở)", preds, {"tham_so": rf_par, "giay_hoc_mot_lan": round(time.perf_counter() - t0, 1)})

    preds, info = [], None
    for s in range(a.so_lan):
        t0 = time.perf_counter()
        m, info_s = run_lightgbm(b, 42 + s, log) if s == 0 else (None, None)
        if s == 0:
            info, chosen = info_s, {k: v for k, v in info_s["chon"].items() if k != "so_vong"}
            n_iter = info_s["chon"]["so_vong"]
        else:
            import lightgbm as lgb
            m = lgb.LGBMClassifier(n_estimators=n_iter, random_state=42 + s, n_jobs=4, verbose=-1, **chosen)
            m.fit(b["X"][b["idx"]["train"]], b["y"]["train"])
        preds.append({p: m.predict(b["X"][b["idx"][p]]) for p in ("validation", "test")})
    record("lightgbm", preds, {"chon_tham_so": info["chon"], "luoi": info["luoi"]})

    for kind in ("mlp", "gru"):
        # Dò tham số trên validation với một seed, rồi học lại bằng ``so_lan`` seed với tham số chọn.
        search = []
        for params in TORCH_GRID:
            _, info_s = run_torch(kind, b, 42, log=log, params=params)
            search.append({**params, "macro_f1_validation": info_s["macro_f1_validation"], "vong": info_s["vong_tot_nhat"]})
        best = max(search, key=lambda r: r["macro_f1_validation"])
        chosen = {k: best[k] for k in TORCH_DEFAULT}
        log(f"{kind}: chọn {chosen} (validation {best['macro_f1_validation']})")
        preds, probs, extra = [], [], []
        for s in range(a.so_lan):
            t0 = time.perf_counter()
            prob, info_s = run_torch(kind, b, 42 + s, log=log, params=chosen)
            pr = {p: prob(p) for p in ("validation", "test")}
            probs.append(pr)
            preds.append({p: v.argmax(1) for p, v in pr.items()})
            extra.append({**{k: v for k, v in info_s.items() if k != "lich_su_validation"},
                          "giay": round(time.perf_counter() - t0, 1)})
        record(f"{kind} (học sâu)", preds, {"do_tham_so": search, "chon_tham_so": chosen, "theo_seed": extra})
        # Gộp các seed: trung bình xác suất (một mô hình duy nhất, không chọn trên test)
        avg = {p: np.mean([pr[p] for pr in probs], 0).argmax(1) for p in ("validation", "test")}
        record(f"{kind} gộp {a.so_lan} seed (học sâu)", [avg], {"chon_tham_so": chosen})

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "hoc_sau.json").write_text(json.dumps(res, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    log(f"Đã ghi {out / 'hoc_sau.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

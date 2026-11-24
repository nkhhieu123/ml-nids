"""Sinh các notebook của Chặng 12 (C12-T01): EDA, phân loại tấn công, botnet. Notebook Gaussian đã có (06).

    python scripts/tao_notebook.py                 # ghi notebooks/05_eda.ipynb, 07_phan_loai.ipynb, 08_botnet.ipynb
    cd notebooks && jupyter nbconvert --to notebook --execute --inplace 05_eda.ipynb 07_phan_loai.ipynb 08_botnet.ipynb

Mỗi notebook dùng mã trong ``src/nids`` (không chép lại thuật toán), đọc bảng đặc trưng trong ``output/`` và mô
hình trong ``models/`` (hai thư mục này không có trong git; tạo lại theo README).
"""

from pathlib import Path

import nbformat as nbf

ROOT = Path(__file__).resolve().parents[1]
SETUP = '''import sys, json
from pathlib import Path

ROOT = Path.cwd().parent if Path.cwd().name == "notebooks" else Path.cwd()
sys.path.insert(0, str(ROOT / "src"))

import numpy as np
import pandas as pd
from IPython.display import Image, display

pd.set_option("display.width", 160)
pd.set_option("display.max_columns", 30)
F = ROOT / "output" / "features"
H = ROOT / "docs" / "hinh"'''


def nb(cells):
    book = nbf.v4.new_notebook()
    book.metadata = {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                     "language_info": {"name": "python"}}
    book.cells = [nbf.v4.new_markdown_cell(c[1]) if c[0] == "md" else nbf.v4.new_code_cell(c[1]) for c in cells]
    return book


EDA = [
    ("md", """# Chặng 5 và 12 — EDA ba bộ dữ liệu

Notebook phân tích khám phá dữ liệu: CIC-IDS2017 (cửa sổ host 10 giây), CTU-13 (host–cửa sổ 120 giây) và lab ảo.
Giải thích chi tiết ở `docs/31_eda.md` và `docs/81_eda_tong_hop.md`. Mã: `src/nids/eda.py`, `src/nids/eda_tong_hop.py`.

**Chống rò rỉ:** thống kê theo nhãn chỉ dùng tập train."""),
    ("code", SETUP + '''

from nids.dataset import feature_columns, load_table
win = load_table([str(F / s) for s in ("cic17_monday", "cic17_wednesday", "cic17_friday")], "windows")
feats = feature_columns("windows")
print(len(win), "cửa sổ;", len(feats), "đặc trưng")'''),
    ("md", "## 1. Phân bố lớp theo tập: mất cân bằng nặng"),
    ("code", '''sure = win[win["split"].isin(["train", "validation", "test"]) & win["label_attack"].isin(["benign", "port_scan", "dos"])]
pd.crosstab(sure["label_attack"], sure["split"], margins=True)'''),
    ("md", "## 2. Chất lượng dữ liệu (train): ô trống, giá trị vô hạn, trùng lặp"),
    ("code", '''tr = sure[sure["split"] == "train"]
X = tr[feats].apply(pd.to_numeric, errors="coerce")
q = pd.DataFrame({"ty_le_trong": X.isna().mean(), "ty_le_bang_0": (X == 0).mean(),
                  "so_vo_han": np.isinf(X.to_numpy(float)).sum(0)})
print("Cửa sổ train trùng hệt cả đặc trưng lẫn nhãn:", round(tr.duplicated(subset=feats + ["label_attack"]).mean(), 3))
q.round(3)'''),
    ("md", "## 3. Thống kê mô tả và độ lệch: đặc trưng đếm lệch phải rất mạnh nên phải lấy log"),
    ("code", '''X.describe(percentiles=[0.5, 0.99]).T.assign(skew=X.skew()).round(2)'''),
    ("md", "## 4. Trung vị theo lớp: tấn công khác bình thường ở đâu"),
    ("code", '''tr.groupby("label_attack")[["packets_in", "new_conn_in", "new_conn_out", "dst_ports", "dst_port_entropy",
                              "tcp_attempts_in", "incomplete_ratio_out", "src_hosts"]].median().T'''),
    ("md", "## 5. Hình đã vẽ: theo lớp, tương quan, AUC một biến, lệch CIC–lab"),
    ("code", '''for f in ("eda_cua_so_theo_lop.png", "eda_tuong_quan_cua_so.png", "eda_tong_hop/cic_auc_dac_trung.png",
          "eda_tong_hop/ctu13_auc_dac_trung.png", "eda_tong_hop/lech_cic_lab.png"):
    display(Image(filename=str(H / f)))'''),
    ("md", "## 6. Tóm tắt số liệu EDA tổng hợp"),
    ("code", '''e = json.loads((H / "eda_tong_hop" / "eda_tong_hop.json").read_text(encoding="utf-8"))
print("Mất cân bằng train:", e["cic"]["mat_can_bang_train"])
print("CTU-13 theo tập:", e["ctu13"]["theo_tap_nhan"])
pd.DataFrame(e["lab"]["trung_vi_binh_thuong"]).T'''),
]

CLASSIFIER = [
    ("md", """# Chặng 7 và 12 — Phân loại tấn công: Random Forest, baseline, LightGBM, học sâu

Bài toán: phân loại cửa sổ host 10 giây thành `benign` / `port_scan` / `dos` trên CIC-IDS2017 (thứ Tư, thứ Sáu).
Chia 60/20/20 theo thời gian; tham số chọn trên validation; test chỉ để đánh giá cuối.
Giải thích: `docs/39`–`44` (Random Forest), `docs/78` (8 baseline), `docs/82` (LightGBM, MLP, GRU)."""),
    ("code", SETUP + '''

from nids import classifier as clf
from nids.config import load_config
cfg = clf.classifier_config(load_config())
df = clf.load_data([str(F / "cic17_wednesday"), str(F / "cic17_friday")], cfg["sessions"])
data = clf.prepare_data(df, None, cfg["random_seed"], cfg["drop_train_duplicates"])
data["info"]'''),
    ("md", "## 1. Mô hình đã lưu và đánh giá trên test: Accuracy, Precision, Recall, F1, macro-F1, confusion matrix"),
    ("code", '''model = clf.load_model(ROOT / "models" / "phan_loai_rf_windows.joblib")
y, pred = data["test"][clf.LABEL_COL].to_numpy(), model.predict(data["test"])
m = clf.multiclass_metrics(y, pred)
print("accuracy", m["accuracy"], "| macro-F1", m["macro_f1"])
display(pd.DataFrame(m["theo_lop"]).T)
pd.DataFrame(m["confusion"]["ma_tran"], index=[f"thật {c}" for c in m["confusion"]["nhan"]],
             columns=[f"đoán {c}" for c in m["confusion"]["nhan"]])'''),
    ("md", "## 2. Theo từng công cụ tấn công, và vì sao accuracy không dùng được"),
    ("code", '''r = json.loads((H / "phan_loai_test.json").read_text(encoding="utf-8"))["mo_hinh"]["random_forest"]
print("Accuracy nếu đoán mọi cửa sổ là benign:", round((y == "benign").mean(), 4))
pd.Series({g: v["recall"] for g, v in r["theo_dot"].items()}, name="recall theo đợt")'''),
    ("md", "## 3. Độ quan trọng đặc trưng"),
    ("code", '''pd.Series(model.estimator.feature_importances_, index=model.preprocessor.output_names).sort_values(ascending=False).head(10)'''),
    ("md", "## 4. So với 8 baseline (cùng dữ liệu, cùng tiền xử lý)"),
    ("code", '''b = json.loads((H / "so_sanh_mo_hinh.json").read_text(encoding="utf-8"))
pd.DataFrame({k: {"validation": v["validation"]["macro_f1"], "test": v["test"]["macro_f1"],
                  "benign_bi_bao": v["test"]["ty_le_benign_bi_bao"]} for k, v in b["mo_hinh"].items()}).T'''),
    ("md", "## 5. LightGBM và học sâu (MLP, GRU đọc chuỗi 5 cửa sổ trước)"),
    ("code", '''d = json.loads((H / "hoc_sau" / "hoc_sau.json").read_text(encoding="utf-8"))
display(pd.DataFrame({k: {"validation": v["macro_f1_validation"]["trung_binh"], "test": v["macro_f1_test"]["trung_binh"],
                          "test_do_lech": v["macro_f1_test"]["do_lech"]} for k, v in d["mo_hinh"].items()}).T)
display(Image(filename=str(H / "hoc_sau" / "so_sanh_hoc_sau.png")))'''),
]

BOTNET = [
    ("md", """# Chặng 8 và 12 — Phát hiện botnet và nhận diện topology

Dữ liệu: CTU-13 (13 kịch bản botnet thật), chia theo kịch bản. Đặc trưng đồ thị liên lạc và gọi định kỳ
(beaconing) trên host–cửa sổ 120 giây. Hai mô hình: Logistic Regression và Random Forest. Topology tập trung/ngang
hàng theo quy tắc. Giải thích: `docs/45`–`52`, lab: `docs/73`, `76`, `80`."""),
    ("code", SETUP + '''

from nids import botnet as bn
df = bn.load_labeled(ROOT / "output" / "ctu13", sorted(bn.SCENARIOS))
pd.crosstab(df["split"], df[bn.LABEL_COL].fillna("bo"))'''),
    ("md", "## 1. Hai mô hình phát hiện host bot trên test CTU-13"),
    ("code", '''rows = {}
for name in ("botnet_lr", "botnet_rf"):
    m = bn.load_model(ROOT / "models" / f"{name}.joblib")
    r = bn.evaluate(m, df, "test")
    rows[name] = {**r["tong"], "background_bi_bao": r["background_bi_bao"], "nguong": m.threshold}
pd.DataFrame(rows).T'''),
    ("md", "## 2. Đặc trưng quan trọng của Random Forest: gọi định kỳ và đồ thị"),
    ("code", '''pd.Series(bn.importance(bn.load_model(ROOT / "models" / "botnet_rf.joblib"), top=12))'''),
    ("md", "## 3. Beaconing: bot gọi đều, máy bình thường thì không"),
    ("code", '''tr = df[(df["split"] == "train") & df[bn.LABEL_COL].isin([bn.SUSPECT, bn.NORMAL])]
tr.groupby(bn.LABEL_COL)[["beacon_so_cap_deu", "beacon_cv_nho_nhat", "beacon_chu_ky", "so_peer",
                          "tap_trung_ra", "ty_le_khong_tra_loi_ra"]].median().T'''),
    ("md", "## 4. Lab: năm bot, topology tập trung và ngang hàng, đối chứng lành tính"),
    ("code", '''for f in ("bot_lab3.json", "bot_b2.json"):
    s = json.loads((H / "thuc_nghiem" / "lab" / "bo3" / f).read_text(encoding="utf-8"))["tong_hop"]
    print(f)
    display(pd.DataFrame(s).T[["so_lan_chay", "bot_bi_bao", "tong_bot", "ty_le_topology", "cua_so_bao_nham"]])'''),
]


def main():
    out = ROOT / "notebooks"
    for name, cells in (("05_eda.ipynb", EDA), ("07_phan_loai.ipynb", CLASSIFIER), ("08_botnet.ipynb", BOTNET)):
        nbf.write(nb(cells), out / name)
        print("đã ghi", out / name)


if __name__ == "__main__":
    main()

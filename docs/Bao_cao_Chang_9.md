# Báo cáo Chặng 9 — Tích hợp pipeline offline

**Đề tài:** Ứng dụng học máy phát hiện tấn công mạng dựa trên dữ liệu lưu lượng
mạng (*Machine Learning-Based Network Intrusion Detection Using Network Traffic
Data*)

| Mục | Thông tin |
|---|---|
| Kho mã nguồn | https://github.com/nkhhieu123/ml-nids (nhánh `main`) |
| Thời gian | 03/11/2026 |
| Trạng thái | Xong 6/6 task |
| Chặng trước | [Bao_cao_Chang_8.md](Bao_cao_Chang_8.md) |

## 1. Tóm tắt

Chặng 9 nối các phần của Chặng 4–8 thành **một pipeline offline**: đọc một file PCAP, chạy ba module
bằng mô hình đã lưu, rồi ghi cảnh báo, điểm và sự kiện.

```
kiểm tra artifact (T01)
PCAP ─> feature_export ─> cửa sổ 10 s ─┬─> Gaussian ───────────┐
       (T02, cùng mã lúc học)          ├─> phân loại ──────────┤  độc lập (T03) / tuần tự (T04) / kết hợp (T05)
                          flow ─> đồ thị 120 s ─> botnet + topology ┘
     ─> cảnh báo hợp nhất (T03) ─> alerts.csv, diem.csv (mọi điểm), su_kien.csv (gộp lặp) (T06)
```

Chạy trên bốn đoạn PCAP CIC-IDS2017 nằm trọn trong **khoảng test** của Chặng 5 (tổng khoảng 1,1 triệu gói):

| | Độc lập | Tuần tự | **Kết hợp (mặc định)** |
|---|---|---|---|
| Phân loại chạy trên | Mọi cửa sổ | Cửa sổ Gaussian báo | Mọi cửa sổ |
| Kiểm tra botnet | Mọi host | Host có bất thường chưa giải thích | Host có bất thường chưa giải thích |
| Gọi đúng tên: quét / slowloris / Hulk | 46% / 95% / 80% | 44% / 92% / 72% | **46% / 95% / 80%** |
| Bỏ sót (bất kỳ cảnh báo): quét / slowloris / Hulk / bot | 0% / 0% / 0% / 5–7% | 35% / 9% / 28% / 7–9% | 34% / 5% / 20% / 5–7% |
| Cửa sổ bình thường bị báo | 17–40% | 4–19% | **4–19%** |
| Thời gian mô hình mỗi đoạn | 0,25–0,95 s | 0,16–0,75 s | 0,19–0,82 s |

Thời gian trích xuất (3–25 giây, khoảng 22 000 gói/giây) chiếm 90–99% tổng thời gian.

## 2. Các task

| Task | Nội dung | Tài liệu |
|---|---|---|
| C09-T01 | Bộ nạp artifact và kiểm tra schema | [53_nap_artifact.md](53_nap_artifact.md) |
| C09-T02 | Chạy PCAP qua toàn bộ pipeline | [54_chay_pcap.md](54_chay_pcap.md) |
| C09-T03 | Đầu ra độc lập và hợp nhất cảnh báo | [55_hop_nhat_canh_bao.md](55_hop_nhat_canh_bao.md) |
| C09-T04 | Chế độ Gaussian → phân loại → kiểm tra botnet | [56_che_do_tuan_tu.md](56_che_do_tuan_tu.md) |
| C09-T05 | So sánh độc lập với tuần tự: bỏ sót, thời gian | [57_so_sanh_che_do.md](57_so_sanh_che_do.md) |
| C09-T06 | Ghi cảnh báo, điểm mô hình, gộp sự kiện lặp | [58_ghi_canh_bao_su_kien.md](58_ghi_canh_bao_su_kien.md) |

Mã nguồn: `src/nids/pipeline.py`, `src/nids/pcap_cut.py`. Kiểm thử: `tests/test_pipeline.py`.

## 3. Kết quả từng task

### 3.1. C09-T01 — Nạp và kiểm tra artifact

- Nạp ba mô hình theo `pipeline.models`.
- Lỗi thì dừng: đặc trưng không thuộc schema đầu vào, `.json` khác mô hình, thiếu ngưỡng, lớp phân loại
  ngoài tập nhãn.
- Chỉ cảnh báo: mô hình tạo khi mã chưa commit.
- Lần kiểm tra đầu phát hiện **cả ba mô hình mang cờ "mã chưa commit"**. Đã huấn luyện lại từ commit
  `7536876`, cùng dữ liệu và seed; kết quả trùng với trước, không còn cảnh báo.

### 3.2. C09-T02 — PCAP qua pipeline

- Trích xuất bằng đúng `nids.feature_export` của lúc huấn luyện (B12).
- Module botnet xét mọi IP trong mạng giám sát `--net`.
- Công cụ `nids.pcap_cut` cắt đoạn thời gian từ PCAP CIC (8–13 GB) ra file nhỏ trong vài chục giây.
- Bốn đoạn: thứ Sáu bình thường có bot ARES (20 phút), thứ Sáu quét cổng (21 phút), thứ Tư slowloris
  (5 phút), thứ Tư Hulk (3 phút); tất cả nằm trong khoảng test của Chặng 5.

### 3.3. C09-T03 — Đầu ra độc lập, hợp nhất

- Mỗi module đổi dự đoán thành `Alert` theo schema chung (docs/02); module botnet ghi nhóm host và nhóm
  topology thành hai dòng.
- Một file cảnh báo sắp theo thời gian, không cộng điểm khác thang đo. Kèm tổng hợp theo host; host có
  ≥ 2 module cùng báo được liệt kê riêng.
- Trên đoạn quét: máy quét 172.16.0.1 và máy bị quét 192.168.10.50 bị cả ba module báo; máy bot ARES bị
  Gaussian và module botnet báo, bộ phân loại không báo (đúng vai trò).

### 3.4. C09-T04 — Chế độ tuần tự

- Gaussian chấm mọi cửa sổ.
- Bộ phân loại chỉ chấm cửa sổ bất thường (5–23% số cửa sổ).
- Module botnet chỉ kiểm tra host có bất thường mà bộ phân loại cho là benign (3–11 thay vì 15–16 host).

### 3.5. C09-T05 — So sánh

- **Báo nhầm của chế độ độc lập gần như hoàn toàn do module botnet** (16–38% cửa sổ bình thường), vì
  cảnh báo 120 giây phủ 12 cửa sổ và mô hình học từ CTU-13 không hợp với CIC. Gaussian 0,3–3,3%, phân
  loại 0%.
- **Chế độ tuần tự làm mất cảnh báo của bộ phân loại**: cửa sổ quét và Hulk mà Gaussian cho là bình
  thường bị bỏ qua.
- Thêm chế độ **kết hợp**: phân loại độc lập, botnet sau Gaussian. Giữ gọi đúng tên như độc lập, báo
  nhầm như tuần tự. Đặt làm mặc định (QĐ-047).
- Thời gian offline gần như không đổi giữa các chế độ, vì trích xuất chiếm 90–99%.

### 3.6. C09-T06 — Ghi cảnh báo, điểm, sự kiện

- Mỗi lần chạy ghi `alerts.csv`, `diem.csv` (mọi dự đoán kèm điểm), `su_kien.csv`, bảng dự đoán của từng
  module và `pipeline.json`.
- Gộp cảnh báo cùng module, nhãn, host cách nhau ≤ 30 giây: **378–1 189 cảnh báo còn 11–104 sự kiện**.
  DoS liên tục thành vài sự kiện. Quét cổng tách theo từng lượt Nmap: 108 cảnh báo của máy quét thành
  3 sự kiện.

## 4. Sửa ở chặng trước

- Huấn luyện lại Gaussian, bộ phân loại và mô hình botnet từ mã đã commit (C09-T01); kết quả không đổi.
- docs/02 mục 1: thêm ghi chú về chế độ `ket_hop` (QĐ-047). Phân loại vẫn không bị Gaussian chặn; riêng
  module botnet chạy sau.
- docs/54: số liệu ở đó đo bằng chế độ độc lập (mặc định lúc làm T02). Từ T05, lệnh `chay` mặc định là
  `ket_hop`; muốn tái lập bảng của docs/54 thì thêm `--che-do doc_lap`.

## 5. Quyết định kỹ thuật

| Mã | Quyết định | Trạng thái |
|---|---|---|
| QĐ-043 | Pipeline nạp mô hình đã lưu, kiểm tra trước khi chạy | Đã chốt |
| QĐ-044 | Trích xuất bằng đúng mã lúc huấn luyện; host botnet là mọi IP trong mạng giám sát; chạy thử trên đoạn PCAP thuộc khoảng test | Đã chốt |
| QĐ-045 | Hợp nhất cảnh báo theo schema chung, không cộng điểm; đánh dấu host có nhiều module báo | Đã chốt |
| QĐ-046 | Thêm chế độ tuần tự | Đã chốt |
| QĐ-047 | Mặc định là chế độ kết hợp | Đã chốt cho CIC (xem lại trên lab) |
| QĐ-048 | Ghi mọi dự đoán kèm điểm; gộp sự kiện theo module, nhãn, host, khoảng 30 giây | Đã chốt (khoảng gộp chỉnh được) |

Cấu hình mới: mục `pipeline` trong `config/default.yaml`:
- `models`: đường dẫn ba mô hình;
- `mode`: chế độ chạy, mặc định `ket_hop`;
- `merge_gap_s`: khoảng gộp sự kiện, 30 giây.

## 6. Kiểm thử

`python -m unittest discover -s tests`: **356/356 ca đạt** (Chặng 8 kết thúc ở 340).
`tests/test_pipeline.py` có 16 ca:

| Task | Số ca | Nội dung |
|---|---|---|
| T01 | 4 | Artifact hợp lệ; các loại lỗi và cảnh báo; bảng thiếu cột; nạp mô hình thật, thiếu file |
| T02 | 2 | Cắt PCAP; PCAP tổng hợp (máy quét SYN) qua trích xuất và ba module giả |
| T03 | 2 | Đổi dự đoán thành cảnh báo, hợp nhất, tổng hợp theo host; ghi CSV |
| T04 | 2 | Bất thường đã giải thích không kiểm tra botnet; chưa giải thích thì kiểm tra đúng host, đúng cửa sổ |
| T05 | 3 | Phủ cảnh báo 10 s và 120 s; bỏ sót, gọi đúng tên, báo nhầm; chế độ kết hợp |
| T06 | 3 | Gộp sự kiện theo khoảng; sự kiện topology; ghi đủ năm loại file |

## 7. Cách chạy

```bash
cd src
python -m nids.pipeline kiem-tra
python -m nids.pcap_cut ../data/pcap/cic-ids2017/Friday-WorkingHours.pcap ../output/pcap/fri_quet.pcap \
    --bat-dau "2017-07-07 15:08:30" --ket-thuc "2017-07-07 15:29:30" --utc-offset -3
python -m nids.pipeline chay ../output/pcap/fri_quet.pcap --net 192.168.10.0/24 --net 172.16.0.0/24 \
    --out ../output/pipeline [--che-do doc_lap|tuan_tu|ket_hop] [--ma-lan-chay <mã>] [--in-su-kien]
python -m nids.pipeline so-sanh ../output/pcap/*.pcap --net 192.168.10.0/24 --net 172.16.0.0/24 \
    --bang ../output/pipeline_so_sanh --out ../docs/hinh/pipeline_so_sanh.json
```

## 8. Điểm cần lưu ý

1. **Module botnet trên CIC** dùng mô hình học từ CTU-13 nên báo nhầm nhiều. Chế độ kết hợp giảm phần
   này, nhưng kết quả botnet thật phải đo trên lab sau khi học lại (docs/52).
2. **Bỏ sót quét cổng 34%** ở chế độ mặc định (theo nghĩa "bất kỳ cảnh báo"): phần lớn là cửa sổ quét ít
   hoạt động và các kiểu quét UDP/SCTP mà bộ phân loại chưa nhận ra (docs/44).
3. **Bốn đoạn PCAP ngắn** (3–21 phút), một mạng. Con số so sánh chế độ phải đo lại trên lab.
4. **Offline**: đọc hết file rồi mới chấm. `created_at` của cảnh báo là thời điểm chạy pipeline, chưa có
   ý nghĩa độ trễ; độ trễ đo ở realtime (Chặng 10, 11).
5. **Mô hình đã tạo lại từ mã sạch.** Từ giờ, mỗi lần đổi mã ở `src/` hay `config/`, chạy
   `pipeline kiem-tra` để biết mô hình có cần học lại không.

## 9. Việc tiếp theo

**Chặng 10 — Realtime**:
- bắt gói trực tiếp trên card mạng;
- chấm điểm mỗi khi một cửa sổ đóng, dùng cùng `pipeline.py` và cùng chế độ;
- đo độ trễ, tốc độ, mất gói, CPU, RAM (B20, B21).

Song song: dựng lab; các việc đang dở ở `docs/Viec_con_thieu.md` mục 0.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Pipeline offline | Chuỗi xử lý đọc một file PCAP có sẵn rồi chấm điểm |
| Artifact | Mô hình, phép biến đổi, ngưỡng đã lưu để dùng lại |
| Chế độ độc lập / tuần tự / kết hợp | Ba module chạy song song / module sau chỉ chạy trên phần module trước đánh dấu / phân loại song song, botnet sau Gaussian |
| Cảnh báo hợp nhất | Cảnh báo của mọi module trong một danh sách chung, cùng định dạng |
| Sự kiện | Nhiều cảnh báo lặp của cùng module, nhãn, host gộp lại |
| Gọi đúng tên | Cảnh báo đúng loại hành vi |
| Bỏ sót, báo nhầm | Tấn công không bị cảnh báo nào chạm tới; cửa sổ bình thường bị báo |
| Khoảng test | Phần dữ liệu mô hình chưa học, dành cho đánh giá cuối |
| Realtime | Chạy trực tiếp trên lưu lượng đang đến |

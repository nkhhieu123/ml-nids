# C05-T05 — Kiểm tra thiếu, vô hạn, trùng và phân bố lớp

Mã nguồn: `src/nids/dataset.py` (đọc bảng kèm nhãn và tập), `src/nids/data_quality.py`.
Kiểm thử: `tests/test_data_quality.py`.

```bash
python -m nids.data_quality output/features/cic17_monday output/features/cic17_wednesday \
    output/features/cic17_friday --out output/quality.json
```

Kết quả dưới đây là của cả ba ngày CIC-IDS2017, chia theo
[29_chia_du_lieu.md](29_chia_du_lieu.md), ngày 30/10/2026.

## 1. Quy mô

| Bảng | Mẫu | Dùng (có tập) | Bỏ ở ranh giới | Đặc trưng |
|---|---|---|---|---|
| Flow | 1 442 894 | 1 387 400 | 55 494 (3,8%) | 44 |
| Cửa sổ host | 465 393 | 458 240 | 7 153 (1,5%) | 20 |

| Phiên | Flow train / validation / test | Cửa sổ train / validation / test |
|---|---|---|
| Thứ Hai | 228 512 / 75 703 / 76 232 | 88 929 / 31 009 / 32 275 |
| Thứ Tư | 296 642 / 88 688 / 96 815 | 100 039 / 23 199 / 35 664 |
| Thứ Sáu | 319 110 / 98 139 / 107 559 | 71 299 / 26 481 / 49 345 |

## 2. Phân bố lớp

`label_attack` (module phân loại), chỉ tính mẫu có tập:

| Lớp | Flow train | Flow validation | Flow test | Cửa sổ train | Cửa sổ validation | Cửa sổ test |
|---|---|---|---|---|---|---|
| `benign` | 567 545 | 185 906 | 220 000 | 251 154 | 76 515 | 111 352 |
| `dos` | 108 004 | 30 768 | 33 320 | 2 270 | 648 | 727 |
| `port_scan` | 104 614 | 22 054 | 18 553 | 671 | 50 | 462 |
| Không có nhãn (`loai`, `mo_ho`) | 64 101 | 23 802 | 8 733 | 6 172 | 3 476 | 4 743 |

`label_anomaly` (module anomaly):

| Lớp | Flow train | Flow validation | Flow test | Cửa sổ train | Cửa sổ validation | Cửa sổ test |
|---|---|---|---|---|---|---|
| `normal` | 567 545 | 185 906 | 220 000 | 251 154 | 76 515 | 111 352 |
| `anomaly` | 276 435 | 76 614 | 60 600 | 8 963 | 4 094 | 5 858 |

**Mất cân bằng nặng ở bảng cửa sổ:** trong train, `benign` gấp 111 lần `dos` và 374 lần
`port_scan`. Xử lý ở C05-T07 (chỉ trên train). Validation và test giữ nguyên tỷ lệ thật,
nên khi đánh giá phải dùng Precision, Recall, F1 theo lớp, không dùng Accuracy.

## 3. Giá trị thiếu

Ô trống là **có chủ ý** (QĐ-020): không có dữ liệu để tính, khác với 0.

| Bảng | Cột | Tỷ lệ trống | Lý do |
|---|---|---|---|
| Flow | `bwd_iat_*` | 26,4% | Dưới 2 gói chiều về (SYN không trả lời, UDP một chiều) |
| Flow | `fwd_iat_*` | 25,1% | Dưới 2 gói chiều đi (DNS: một yêu cầu, một trả lời) |
| Flow | `bwd_pkt_len_*` | 1,6% | Không có gói chiều về |
| Flow | `iat_*` | 0,6% | Flow một gói |
| Flow | `payload_bytes`, `fwd_payload_bytes`, `bwd_payload_bytes` | 0,04% | Flow không phải TCP/UDP |
| Flow | `fwd_pkt_len_*` | 0,02% | Không có gói chiều đi (bắt giữa chừng) |
| Cửa sổ | `incomplete_ratio_in` | 94,0% | Cửa sổ không có lần thử TCP tới host |
| Cửa sổ | `incomplete_ratio_out` | 73,9% | Cửa sổ không có lần thử TCP từ host |
| Cửa sổ | `dst_port_entropy` | 13,4% | Host không gửi gói TCP/UDP nào trong vai client |

Không có cột nào khác có ô trống. Vì trống mang ý nghĩa, C05-T07 thêm cột 0/1 đánh dấu ô
vốn trống thay vì chỉ điền giá trị.

## 4. Giá trị vô hạn

**Không có giá trị vô hạn hay NaN ngoài các ô trống trên**, ở cả hai bảng. Đây là kết quả
của QĐ-018: tỷ lệ gửi/nhận là phần trong tổng và không tính tốc độ byte/giây. CSV của CIC
có 1 586 ô `Infinity` chỉ riêng file thứ Tư (docs/06 mục 7.5).

## 5. Mẫu trùng

Hai mẫu **trùng** khi vector đặc trưng giống hệt nhau (coi ô trống bằng nhau). Mẫu test
trùng mẫu train làm kết quả đẹp hơn thực tế, nên phải đo.

| Bảng, lớp | Trùng trong train | Mẫu test trùng một mẫu train |
|---|---|---|
| Flow `benign` | 7,2% | 10,6% |
| Flow `dos` | 2,3% | 1,7% |
| Flow **`port_scan`** | **98,9%** | **98,3%** |
| Cửa sổ `benign` | 46,1% | 36,9% |
| Cửa sổ `dos` | 4,6% | 1,4% |
| Cửa sổ `port_scan` | 33,7% | 0,2% |

**Nhận xét:**
- **Flow `port_scan` gần như một mẫu lặp lại.** Mỗi lượt dò là SYN → RST: 2 gói, kích thước
  cố định, khoảng cách rất nhỏ. Điểm số phân loại ở mức flow của lớp này gần như không nói
  gì về khả năng tổng quát: 98% mẫu test mô hình đã thấy y hệt. Đây là đặc điểm của hành
  vi, không phải lỗi chia dữ liệu.
- **Bảng cửa sổ không có vấn đề đó ở lớp tấn công** (0,2–1,4% mẫu test trùng train), nên là
  đơn vị đánh giá đáng tin hơn. Cửa sổ `benign` trùng nhiều vì host nhàn rỗi chỉ có vài
  gói nền giống nhau.
- **Đề xuất cho Chặng 7:** lấy bảng cửa sổ làm đơn vị đánh giá chính; nếu báo cáo ở mức flow
  thì kèm kết quả sau khi bỏ mẫu test trùng train.

**Vector giống hệt nhưng khác nhãn** (trong train): 3 vector ở bảng flow (1 722 mẫu), 12
vector ở bảng cửa sổ (3 970 mẫu). Không mô hình nào phân biệt được các mẫu này, chúng tạo
ra một mức sai không thể tránh. Cả 3 vector ở bảng flow đều là **flow chỉ có một gói**:

| Gói duy nhất của flow | `port_scan` | `dos` | `benign` |
|---|---|---|---|
| SYN, 60 byte | 277 | 29 | 3 |
| RST+ACK từ client, 40 byte | 443 | 0 | 738 |
| RST+ACK từ server, 40 byte | 93 | 0 | 139 |

## 6. Mẫu không dùng

| Loại | Flow | Cửa sổ | Dùng cho |
|---|---|---|---|
| `loai` (DDoS, Heartbleed, bot) | 100 540 | 14 305 | Chỉ anomaly |
| `mo_ho` | 300 | 353 | Không dùng (cửa sổ có flow tấn công vẫn là `anomaly`) |
| `bo` (ranh giới tập) | 55 494 | 7 153 | Không dùng |

## 7. Kiểm thử

Kiểm thử tự động (4 ca): đọc bảng kèm nhãn và tập theo khóa; cột đặc trưng không gồm IP,
cổng, thời điểm, giao thức; báo cáo ô trống, vô hạn, phân bố lớp; đếm mẫu trùng giữa các
tập.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Mẫu | Một dòng dữ liệu: một flow hoặc một cửa sổ host |
| Vector đặc trưng | Dãy các giá trị đặc trưng của một mẫu |
| Mẫu trùng | Các mẫu có vector đặc trưng giống hệt nhau |
| Mất cân bằng lớp | Một lớp có nhiều mẫu hơn hẳn lớp khác |
| Accuracy | Tỷ lệ mẫu đoán đúng; dễ gây hiểu nhầm khi lớp mất cân bằng |
| Precision, Recall, F1 | Trong các mẫu đoán là tấn công, bao nhiêu đúng / trong các tấn công thật, bắt được bao nhiêu / trung bình điều hòa của hai số đó |
| Infinity, NaN | Giá trị vô hạn / không phải số, thường do chia cho 0 |
| Tổng quát | Khả năng làm đúng trên dữ liệu chưa từng thấy |
| Host nhàn rỗi | Máy gần như không hoạt động, chỉ có vài gói nền |

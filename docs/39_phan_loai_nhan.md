# C07-T01 — Chốt nhãn thực tế: Benign, PortScan, DoS

Mã nguồn: `class_report`, `host_roles` trong `src/nids/classifier.py`. Kiểm thử:
`tests/test_classifier.py`. Kết quả: `docs/hinh/phan_loai_nhan.json`.

```bash
cd src
python -m nids.classifier nhan ../output/features/cic17_wednesday ../output/features/cic17_friday --out ../docs/hinh
```

## 1. Bài toán

| Mục | Chốt |
|---|---|
| Đơn vị mẫu | **Cửa sổ host** 10 giây (bảng `windows`, 20 đặc trưng). Bảng flow có 98,3% mẫu `port_scan` test trùng hệt train (docs/30 mục 5), nên không dùng làm đơn vị đánh giá chính |
| Lớp | `benign`, `port_scan`, `dos` (`src/nids/scope.py`, QĐ-004) |
| Phiên | Thứ Tư và thứ Sáu CIC-IDS2017 (QĐ-009, `preprocess.sessions`) |
| Mẫu dùng | Nhãn chắc chắn: trạng thái `khop` (khớp một đợt của lớp) hoặc `khong_khop` (bình thường). Bỏ `mo_ho` và `loai` |
| Chia tập | Theo thời gian trong từng khối tấn công (QĐ-027); vùng đệm `bo` không dùng |

Nhãn của một cửa sổ là nhãn của host trong 10 giây đó: **cả bên tấn công lẫn nạn nhân** đều mang
nhãn tấn công (docs/28). Ở CIC, bên tấn công luôn là `172.16.0.1` (NAT) và nạn nhân là
`192.168.10.50`, mỗi bên khoảng một nửa số mẫu tấn công. Mô hình không thấy IP, chỉ thấy đặc trưng.

## 2. Số mẫu

| Lớp | Train | Validation | Test |
|---|---|---|---|
| benign | 163 292 | 53 949 | 67 713 |
| port_scan | 671 | **50** | 462 |
| dos | 2 270 | 648 | 727 |
| Tổng | 166 233 | 54 647 | 68 902 |

Số train ở đây là trước khi bỏ trùng và cân bằng; hai bước đó làm trên train ở C07-T02.

Theo đợt tấn công (cột `nhan_goc` của lịch):

| Đợt | Lớp | Train | Validation | Test |
|---|---|---|---|---|
| DoS slowloris | dos | 748 | 206 | 318 |
| DoS Slowhttptest | dos | 561 | 192 | 195 |
| DoS Hulk | dos | 659 | 172 | 190 |
| DoS GoldenEye | dos | 290 | 78 | **24** |
| PortScan (2 đợt: tường lửa bật và tắt) | port_scan | 671 | 50 | 462 |

12 cửa sổ `dos` của train không khớp riêng đợt nào khi đối chiếu ngược theo giờ (sát ranh giới hai
đợt); vẫn là `dos`.

Theo vai trò host (theo IP trong lịch):

| Lớp | Bên tấn công | Nạn nhân | Host khác |
|---|---|---|---|
| benign (train) | 1 651 | 71 077 | 90 564 |
| port_scan (train) | 338 | 333 | 0 |
| dos (train) | 1 137 | 1 133 | 0 |

Có 1 651 cửa sổ **benign** của chính IP `172.16.0.1` (ngoài khung giờ tấn công). Nhờ vậy mô hình
không thể học "IP này luôn là tấn công" từ đặc trưng mang dấu vết của IP.

## 3. Những gì bị loại và vì sao

| Đợt | Train | Validation | Test | Lý do |
|---|---|---|---|---|
| Bot (ARES) | 5 707 | 2 355 | 3 554 | Thuộc module botnet (Chặng 8) |
| DDoS (LOIT) | 712 | 214 | 206 | Một đợt 20 phút, nhiều nguồn sau NAT; không đủ đợt độc lập |
| Heartbleed | 514 | 254 | 402 | Một kết nối khai thác TLS; lưu lượng trông bình thường |

Mẫu mơ hồ (`mo_ho`): 88 train, 80 validation, 178 test, không dùng.

Theo điều kiện nghiệm thu, **brute-force, exploit hoặc DDoS chỉ thêm khi có dữ liệu và kiểm thử
tương ứng**. CIC thứ Ba (FTP/SSH brute-force) và thứ Năm (tấn công web) chưa tải; DDoS chỉ có một
đợt. Các cửa sổ bị loại vẫn được dùng ở C07-T06 để xem mô hình đoán gì với tấn công chưa từng học.

## 4. Hạn chế đã biết

1. **Validation `port_scan` chỉ 50 mẫu** (25 cửa sổ mỗi bên). Quét chạy theo từng lượt Nmap ngắn,
   phần 20% validation của mỗi đợt rơi vào khoảng ít lượt quét. Một mẫu sai làm F1 của lớp này lệch
   khoảng 1–2 điểm phần trăm, nên chọn mô hình theo macro-F1 validation có nhiễu (C07-T04).
2. **GoldenEye chỉ 24 cửa sổ test**: recall riêng đợt này dao động lớn.
3. **DoS là tầng HTTP** (slowloris, Slowhttptest, Hulk, GoldenEye). DoS kiểu SYN của lab chưa có
   mẫu (docs/06 mục 6); mô hình chưa chắc nhận ra SYN flood.
4. **Một nguồn tấn công, một nạn nhân.** Train và test cùng cặp máy, chỉ khác thời điểm.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Phân loại đa lớp | Mô hình chọn một trong nhiều nhãn (ở đây ba lớp) cho mỗi mẫu |
| Cửa sổ host | Đặc trưng của một máy trong 10 giây |
| `khop`, `khong_khop`, `mo_ho`, `loai` | Trạng thái nhãn: khớp đợt tấn công; bình thường; không chắc; khớp đợt bị loại |
| Bên tấn công, nạn nhân | Máy gửi tấn công; máy bị tấn công |
| NAT | Tường lửa thay địa chỉ IP, làm mọi máy tấn công hiện ra cùng một IP |
| Nmap | Công cụ quét cổng |
| DoS tầng HTTP, SYN flood | Làm nghẽn web server bằng yêu cầu HTTP; làm nghẽn bằng gói mở kết nối TCP |
| DDoS, Heartbleed, Bot | Tấn công từ chối dịch vụ nhiều nguồn; khai thác lỗi OpenSSL; máy bị điều khiển từ xa |
| Brute-force, exploit | Dò mật khẩu; khai thác lỗ hổng phần mềm |
| Train, validation, test | Tập học; tập chọn tham số; tập đánh giá cuối |
| Macro-F1 | Trung bình F1 của các lớp, mỗi lớp nặng như nhau |
| Recall | Tỷ lệ mẫu của một lớp được đoán đúng |

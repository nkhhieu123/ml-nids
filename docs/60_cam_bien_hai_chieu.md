# C10-T02 — Xác minh vị trí cảm biến thấy traffic hai chiều

Mã nguồn: `analyze`, `verdict`, `ip_digest`, `read_with_digest` trong `src/nids/cam_bien.py`. Kiểm
thử: `tests/test_realtime.py`.

> **Trạng thái: chưa chạy trên lab thật.** Công cụ đã kiểm tra trên PCAP CIC-IDS2017 và một bản giả lập
> mirror một chiều. Khi dựng lab, làm theo mục 1 và ghi kết quả vào mục 5.

## 1. Cách làm trên Kali

Yêu cầu B13: trước khi chạy mô hình, Kali phải thấy **cả hai chiều** traffic qua cổng mirror.

```bash
# 1. Trong lúc các máy lab tạo traffic (duyệt web, ping, kết nối tới máy chủ dịch vụ), bắt thử 1–2 phút
sudo tcpdump -i eth1 -w /tmp/thu.pcap -c 20000
# 2. Kiểm tra (mặc định mạng giám sát là lab.subnet, danh sách máy lab là lab.hosts)
cd /opt/ml-nids && .venv/bin/python -m nids.cam_bien /tmp/thu.pcap --out output/cam_bien.json
```

Mã thoát 1 nếu kết luận `loi`.

## 2. Đo gì

| Chỉ số | Cách tính | Vì sao |
|---|---|---|
| Flow TCP hai chiều | Phần flow TCP (một đầu trong mạng giám sát) có gói theo cả hai hướng | Mirror một hướng thì mọi flow chỉ có một chiều |
| Phản hồi bắt tay (trong mạng) | Trong các kết nối có SYN của client tới **máy chủ trong mạng giám sát**, phần thấy SYN+ACK hoặc RST của máy chủ | Máy trong lab luôn trả lời nếu thấy được chiều về; máy ngoài Internet có thể không trả lời nên chỉ ghi để tham khảo |
| Cặp một chiều | Cặp IP có ≥ 10 gói một hướng và 0 gói hướng ngược | Chỉ ra máy hay đoạn mạng nào mirror thiếu |
| Gói nhân đôi | Hai gói có **cùng nội dung IP** (bỏ TTL và checksum) cách nhau ≤ 1 ms | Mirror cả cổng vào lẫn cổng ra làm mỗi gói xuất hiện hai lần; đặc trưng đếm gói bị gấp đôi |
| Máy lab | Mỗi IP trong `lab.hosts` có xuất hiện không | Máy không nằm trên cổng được mirror |

Gói nhân đôi bị loại trước khi ghép flow, nên không làm sai số liệu hai chiều.

Cách nhận diện nhân đôi đã sửa một lần trong lúc làm task. Lần đầu so **chữ ký** (IP, cổng, độ dài, số
thứ tự TCP) và báo 20% gói nhân đôi. Nhưng các gói ACK thuần của TCP giữ nguyên số thứ tự, nên đó là
báo nhầm. Bản cuối so **nội dung gói IP**. Kiểm tra lại các cặp còn lại trên CIC: cùng MAC, cùng TTL,
cách nhau trung vị 3 µs, đúng là bản sao.

**Kết luận** (QĐ-050):

| Mức | Điều kiện |
|---|---|
| `loi` | Flow TCP hai chiều < 50%, hoặc phản hồi bắt tay trong mạng < 50% |
| `canh_bao` | Một trong hai < 90%; hoặc gói nhân đôi > 5%; hoặc ít hơn 20 flow TCP (bắt lâu hơn) |
| `dat` | Còn lại |

Nếu có máy lab chưa xuất hiện, công cụ ghi thêm lý do nhưng không đổi mức.

## 3. Kết quả trên dữ liệu CIC-IDS2017 (cổng mirror của CIC)

| Đoạn | Gói | Nhân đôi | Flow TCP | Hai chiều | Phản hồi (mọi máy / trong mạng) | Cặp một chiều | Kết luận |
|---|---|---|---|---|---|---|---|
| `fri_binh_thuong` | 75 873 | 11,8% | 2 027 | 99,8% | 99,7% / 100% | 3 | `canh_bao` (nhân đôi) |
| `fri_quet` | 371 094 | 6,5% | 25 272 | 99,1% | 99,5% / 99,5% | 4 | `canh_bao` (nhân đôi) |
| `wed_slowloris` | 72 653 | 6,2% | 3 148 | 89,1% | 81,2% / **57,9%** | 0 | `canh_bao` |
| `wed_hulk` | 558 897 | 0,7% | 30 029 | 99,9% | 99,9% / 99,9% | 1 | `dat` |
| **Giả lập một chiều** (`fri_binh_thuong`, chỉ giữ gói do máy trong mạng gửi) | 44 208 | 18,9% | 1 863 | **8,2%** | 9,1% / 100% | **382** | **`loi`** |

- Cảm biến của CIC thấy **đủ hai chiều**. Trên `wed_slowloris`, máy chủ web đang bị DoS không trả lời
  SYN, nên phản hồi trong mạng chỉ 58%. Đây là bản chất của tấn công, không phải lỗi mirror. Khi đọc kết
  quả trên lab, cần bắt thử lúc mạng đang bình thường.
- Bản giả lập một chiều bị phát hiện ngay: 382 cặp chỉ thấy một hướng. Tỷ lệ phản hồi trong mạng vẫn
  100%, vì cả hai máy đều trong mạng nên cả hai hướng đều được giữ. Do đó kết luận dựa vào cả hai chỉ số.
- **PCAP của CIC có 0,7–11,8% gói nhân đôi**. Bộ trích xuất của dự án **không** bỏ bản sao. Trên CIC
  điều này không gây lệch, vì train và test cùng bị như nhau. Nhưng nếu mạng lab nhân đôi ít hoặc nhiều
  hơn, đặc trưng đếm gói sẽ lệch. Cần đo tỷ lệ này trên lab rồi quyết định có bỏ bản sao khi trích xuất
  hay không (đã ghi vào docs/Viec_con_thieu.md).

## 4. Hạn chế

- Chỉ xét TCP. Lab chỉ có UDP thì không kết luận được về hai chiều.
- Công cụ đọc file bắt sẵn. Bản đọc trực tiếp card mạng dùng nguồn gói của C10-T03.

## 5. Kết quả trên lab

Chưa có. Cần ghi: card giám sát, cấu hình mirror (hướng, cổng nguồn), thời gian bắt, bảng như mục 3.

## 6. Kiểm thử

- 30 kết nối đủ bắt tay: hai chiều 100%, kết luận `dat`; máy lab không xuất hiện được ghi lý do.
- Chỉ giữ gói của client: hai chiều 0%, một cặp một chiều, kết luận `loi`.
- Mỗi gói có bản sao sau 2 µs: nhân đôi 50%, flow vẫn đúng, kết luận `canh_bao`.
- Quá ít flow: `canh_bao` và hướng dẫn bắt lâu hơn.
- Mã băm nội dung bỏ qua TTL nhưng phân biệt IP ID.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Cảm biến | Máy (Kali) nhận bản sao traffic để phân tích |
| Mirror (cổng SPAN) | Switch sao chép traffic của cổng khác sang cổng của cảm biến |
| Hai chiều | Thấy cả gói đi lẫn gói về của một kết nối |
| SYN, SYN+ACK, RST | Gói mở kết nối của client; gói đồng ý của server; gói từ chối |
| Gói nhân đôi | Cùng một gói xuất hiện hai lần trong bản bắt |
| TTL | Trường trong header IP giảm 1 mỗi khi gói qua router |
| tcpdump | Công cụ bắt gói trên Linux |

# C10-T03 — Nguồn packet live, tái sử dụng bộ trích xuất

Mã nguồn: `src/nids/nguon_goi.py` (nguồn gói), `src/nids/realtime.py` (`RealtimeEngine`,
`EventMerger`, `single_thread`, `run`). Kiểm thử: `tests/test_realtime.py`.

```bash
# Trên Kali, đọc thẳng card giám sát (cần root hoặc CAP_NET_RAW, docs/59)
.venv/bin/python -m nids.realtime --iface eth1 --net 192.168.50.0/24 --out output/realtime
# Ở mọi máy: phát lại PCAP (nhanh nhất có thể, hoặc --toc-do 1 theo nhịp thật)
cd src
python -m nids.realtime --pcap ../output/pcap/fri_quet.pcap --net 192.168.10.0/24 --net 172.16.0.0/24 --out ../output/realtime
```

## 1. Nguồn gói

Mọi nguồn trả `RawPacket` giống bộ đọc PCAP (`nids.pcap_reader`). Vì vậy phần sau dùng **đúng mã** của
pipeline offline (B12).

| Nguồn | Cách đọc | Dấu thời gian | Gói kernel bỏ |
|---|---|---|---|
| `AfPacketSource` (`--iface`) | Socket `AF_PACKET` của Linux, `ETH_P_ALL`, chế độ promiscuous, bộ đệm nhận 32 MB, chờ 0,5 giây để dừng được | Kernel gắn (`SO_TIMESTAMPNS`), không phải lúc Python đọc | `PACKET_STATISTICS` (đặt lại sau mỗi lần đọc) |
| `PcapReplaySource` (`--pcap`) | Bộ đọc PCAP/PCAPNG của dự án | Của file | Không có |

`AfPacketSource` không cần thư viện ngoài (không scapy, không libpcap). Gói dài hơn `snaplen` (65 535
byte) bị cắt và được đánh dấu như gói bị cắt trong PCAP. Phát lại có thể chạy nhanh nhất có thể (đo
năng lực), hoặc theo nhịp thật nhân hệ số `--toc-do` (thử như đang bắt trực tiếp).

## 2. Bộ máy realtime

```
gói ─> parse_packet ─> WindowPipeline (ghép flow + cửa sổ 10 s, đúng mã offline)
          │                    │ cửa sổ đóng
          │                    └─> Gaussian, phân loại ─> cảnh báo ─┐
          │ flow kết thúc ─> bảng flow gần đây                       │
          └─ mỗi bước 10 s: cửa sổ 120 s vừa đủ dữ liệu ─> đồ thị, beaconing ─> botnet, topology ─┤
                                                                     ├─> alerts.csv (+ terminal), diem.csv
                                                                     └─> gộp sự kiện ngay ─> su_kien.csv
```

- **Cửa sổ 10 giây** được chấm ngay khi `WindowPipeline` trả ra, tức là sau cuối cửa sổ cộng 3 giây chờ
  quan sát bắt tay. Chấm theo đúng chế độ (`pipeline.mode`, mặc định `ket_hop`, QĐ-047).
- **Cửa sổ 120 giây** được chấm khi thời gian gói vượt quá cuối cửa sổ cộng 3 giây, mỗi bước 10 giây. Bảng
  flow gồm:
  - flow đã kết thúc trong khoảng nhìn ngược (600 giây cho beaconing);
  - **ảnh chụp các flow đang mở**, với số đếm hiện tại.

  Flow dài (timeout 60/120 giây) chưa kết thúc vẫn được tính. Đây là chỗ realtime có thể khác offline một
  chút (đo ở C10-T08).
- **Chế độ `ket_hop`/`tuan_tu`**: chỉ host có bất thường chưa giải thích chồng lên cửa sổ 120 giây mới được
  kiểm tra botnet, như pipeline offline (C09-T04).
- **Cảnh báo** theo schema chung, ghi CSV và in terminal (`AlertSink`); `--ghi-diem` ghi thêm mọi dự
  đoán. `created_at` là giờ thật lúc phát cảnh báo, dùng tính độ trễ (Chặng 11).
- **Sự kiện** được gộp ngay khi chạy (`EventMerger`, cùng quy tắc QĐ-048). Sự kiện đóng khi quá 30 giây
  (thời gian gói) không có cảnh báo mới cùng khóa, và được ghi ngay vào `su_kien.csv`.

## 3. Hai lỗi phát hiện khi chạy thử, đã sửa

1. **Chậm vì nhóm luồng.**
   - Random Forest được lưu với `n_jobs = 4`. Mỗi lần chấm một lô nhỏ, joblib lại dựng rồi hủy một nhóm
     luồng, mất khoảng 0,13 giây mỗi lần, chiếm 44/53 giây khi phát lại slowloris.
   - Bộ máy đặt `n_jobs = 1` cho mọi mô hình lúc nạp (`single_thread`); dự đoán không đổi.
   - Phần còn lại là chi phí của chính 300 cây: khoảng 55 ms mỗi lô, mỗi lô 2 giây một lần.
2. **Chấm lặp cửa sổ 120 giây.**
   - Lần đầu, bộ lọc "đúng cửa sổ đang chấm" dùng `np.isclose` mặc định. Hàm này có sai số tương đối
     1e-5, tức khoảng 15 000 giây với dấu thời gian epoch hiện nay, nên mọi cửa sổ trong bảng đều bị chấm
     lại ở mỗi bước. Đoạn quét cổng vì thế ra 41 788 host–cửa sổ và 9 829 cảnh báo.
   - Đã sửa sang so tuyệt đối, và thêm kiểm thử "mỗi (host, cửa sổ 120 giây) chỉ được chấm một lần".

## 4. Kết quả phát lại (nhanh nhất có thể, máy phát triển)

| Đoạn | Gói | Thời lượng traffic | Thời gian xử lý | Nhanh hơn nhịp thật | Cửa sổ 10 s (realtime / offline) | Host–cửa sổ 120 s đã chấm | Cảnh báo (realtime / offline `ket_hop`) | Sự kiện (realtime / offline) |
|---|---|---|---|---|---|---|---|---|
| `wed_slowloris` | 73 284 | 5,3 phút | 17,5 s (4 193 gói/s) | khoảng 18 lần | 1 964 / 1 964 | 30 | 654 / 656 | 9 / 11 |
| `fri_quet` | 373 396 | 21 phút | 121,0 s (3 086 gói/s) | khoảng 10 lần | 7 464 / 7 464 | 732 | 1 155 / 1 189 | 109 / 104 |

- Số cửa sổ 10 giây **trùng hoàn toàn** với pipeline offline: cùng bộ trích xuất, cùng tham số.
- Số cảnh báo lệch 0,3–3%. Lệch đến từ cửa sổ 120 giây: realtime dùng ảnh chụp flow đang mở, còn offline
  dùng flow đã kết thúc trọn vẹn. C10-T08 đo chi tiết.
- Tốc độ phát lại tối đa khoảng 3 000–4 000 gói/giây trên máy phát triển, thấp hơn trích xuất offline
  (khoảng 22 000 gói/giây). Lý do: realtime chấm từng lô nhỏ và dựng lại đồ thị 120 giây mỗi bước 10 giây.
  Vẫn nhanh hơn nhịp thật 10–18 lần với traffic CIC. Giới hạn khi traffic lab lớn hơn được đo ở C10-T05.
- Chế độ một luồng ở bước này: khi xử lý không kịp, gói chờ trong bộ đệm socket. Hàng đợi giới hạn và đếm
  gói bỏ thêm ở C10-T04.

## 5. Kiểm thử

- `AfPacketSource` với socket giả: dấu thời gian kernel đúng tới nano giây, độ dài, số gói kernel bỏ;
  dừng được khi đang chờ gói. Cấu trúc `packet_mreq` đúng kích thước.
- Phát lại theo nhịp thật mất đúng khoảng thời gian bản bắt; dừng giữa chừng; phải chọn đúng một nguồn.
- PCAP tổng hợp (máy quét) qua bộ máy realtime với mô hình giả:
  - cùng số cửa sổ 10 giây với pipeline offline;
  - máy quét bị báo ở cả ba module, máy thường không bị báo `port_scan`;
  - mọi sự kiện được đóng.
- Mỗi (host, cửa sổ 120 giây) chỉ được chấm một lần; cửa sổ dài đúng 120 giây.
- Gộp sự kiện ngay khi chạy; `single_thread` đổi `n_jobs` của rừng bên trong `Pipeline`.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Realtime | Xử lý gói ngay khi chúng đến từ card mạng |
| `AF_PACKET` | Loại socket của Linux nhận nguyên khung Ethernet từ card mạng |
| Promiscuous | Card nhận cả gói không gửi cho nó, cần cho cổng mirror |
| Dấu thời gian kernel | Thời điểm kernel nhận gói, chính xác hơn lúc chương trình đọc |
| Phát lại PCAP | Đưa gói của file vào bộ máy như thể đang bắt trực tiếp |
| Ảnh chụp flow đang mở | Số đếm hiện tại của flow chưa kết thúc |
| `n_jobs` | Số luồng scikit-learn dùng khi chấm; lô nhỏ thì nhiều luồng lại chậm hơn |
| Lô | Nhóm cửa sổ được chấm cùng một lần |

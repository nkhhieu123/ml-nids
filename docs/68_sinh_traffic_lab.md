# Script sinh traffic lab cho kịch bản 1–3

Mã nguồn: `scripts/sinh_traffic.py` (sinh traffic và ghi nhật ký), `scripts/nhat_ky_sang_lich.py` (đổi nhật
ký thành lịch gán nhãn). Kiểm thử: `tests/test_sinh_traffic.py`. Tham số: mục `lab` của `config/default.yaml`.
Việc này nằm trong danh sách việc còn thiếu (`docs/Viec_con_thieu.md` mục 1, việc 5 của phần "chặn", và mục 3).

Script sinh traffic cho **botnet** (kịch bản 4, 5) đã có từ Chặng 8: `scripts/sinh_topology.py` (docs/50).
Tài liệu này bổ sung ba kịch bản còn thiếu, theo đúng kế hoạch thu ở [09_du_lieu_lab.md](09_du_lieu_lab.md).

## 1. An toàn (B24)

Dùng cùng khuôn với `sinh_topology.py`:

- **Chỉ trong mạng lab.** `check_target` từ chối ngay mọi IP ngoài `192.168.50.0/24`. Không có đường ra
  Internet trong lab.
- **Vô hại.** Chỉ mở/đóng kết nối TCP thường và gửi HTTP GET bình thường (`User-Agent: nids-lab`) tới máy
  chủ dịch vụ của lab. Không chèn mã, không khai thác lỗ hổng, không gửi mã độc, không dùng mẫu của CTU-13.
- **Kịch bản 3 là bộ sinh tải kết nối**, không phải bộ tạo gói thô: mở rồi đóng ngay socket TCP **thường**
  của hệ điều hành, nhiều kết nối mỗi giây, nên nhiều kết nối không kịp hoàn tất bắt tay — đúng mẫu đặc trưng
  mà module phân loại cần (cờ TCP, tỷ lệ kết nối không hoàn tất, docs/22). Không giả mạo IP nguồn. Thời gian
  bị **chặn cứng** ở 60 giây (B16) và chỉ nhắm một máy chủ của lab.
- `--thu` chỉ in kế hoạch, không gửi gì. `--seed` để lặp lại đúng lịch.

## 2. Ba kịch bản

| Kịch bản | Lệnh con | Hành vi | Nhãn |
|---|---|---|---|
| 1 — bình thường (B14) | `binh-thuong` | Duyệt web theo nhịp người dùng (nghỉ 1–6 giây), xen tác vụ kiểm tra trạng thái `api/status` mỗi ~30 giây | `benign` |
| 2 — quét cổng (B15) | `quet` | Nối lần lượt từng cổng trong dải; hai tốc độ chậm/nhanh | `port_scan` |
| 3 — tải kết nối (B16) | `tai-ket-noi` | Mở/đóng kết nối TCP liên tục, ba mức tải, tối đa 60 giây | `dos` |

Tham số chốt ở `config/default.yaml` → `lab`:
- quét: dải cổng 1–1024; giãn cách chậm 0,5 giây, nhanh 0 giây;
- tải kết nối: mức 1/2/3 = 50/200/600 kết nối mỗi giây; tối đa 60 giây.

### Ví dụ

```bash
# Kịch bản 1 — client sinh traffic bình thường 10 phút (chạy trên 192.168.50.41–43)
python scripts/sinh_traffic.py binh-thuong --may-chu 192.168.50.30 --cong 80 --thoi-gian 600 --vai-tro train --lan 01
# Kịch bản 2 — quét cổng chậm (chạy trên máy thử nghiệm 192.168.50.20)
python scripts/sinh_traffic.py quet --may-chu 192.168.50.30 --cong-dau 1 --cong-cuoi 1024 --toc-do cham --vai-tro val --lan 01
# Kịch bản 3 — tải kết nối 60 giây, mức trung bình
python scripts/sinh_traffic.py tai-ket-noi --may-chu 192.168.50.30 --cong 80 --muc 2 --thoi-gian 60 --vai-tro train --lan 01
```

Khi thu thật, kịch bản 2 nên chạy **Nmap** trên máy thử nghiệm (connect scan) để traffic giống công cụ thật;
lúc đó dùng `python scripts/sinh_traffic.py quet ... --thu` chỉ để ghi nhật ký, còn traffic do Nmap sinh. Lệnh
con `quet` khi chạy thật (không `--thu`) chỉ là bản thay thế khi không có Nmap.

## 3. Nhật ký lần chạy và gán nhãn

Mỗi lần chạy (không `--thu`) ghi một dòng vào `data/run_logs/nhat_ky.jsonl`, cùng định dạng với
`sinh_topology.py`:

```json
{"ma_lan_chay": "k3-dos-muc2-train-01", "bien_the": "k3-dos-muc2", "vai_tro": "train", "kieu": "tai-ket-noi",
 "nhan": "dos", "bat_dau": "...", "ket_thuc": "...", "ip_nguon": "192.168.50.20", "ip_dich": "192.168.50.30",
 "tham_so": {"cong": 80, "muc": 2, "thoi_gian": 60, "seed": null}, "so_lan_thu": 11998, "so_lan_noi_duoc": 320}
```

Mã lần chạy theo quy ước docs/09: `<biến thể>-<vai trò>-<số>`. **Vai trò (`train`/`val`/`test`) là bắt buộc
và phải ghi trước khi chạy** (B11, B19).

Nhật ký là **căn cứ gán nhãn độc lập với dự đoán** (B10). `scripts/nhat_ky_sang_lich.py` đổi nhật ký thành
một CSV đúng định dạng `config/label_schedule.csv`, để `nids.labeling` gán nhãn cho PCAP lab y hệt cách gán
cho CIC-IDS2017:

```bash
python scripts/nhat_ky_sang_lich.py data/run_logs/nhat_ky.jsonl --out config/label_schedule_lab.csv
cd src && python -m nids.labeling ../output/features/<run_id>.flows.csv --schedule ../config/label_schedule_lab.csv
```

Dòng `benign` không tạo luật (không luật nào thì flow mặc định bình thường); `port_scan` và `dos` mỗi dòng
thành một luật với khung giờ [bắt đầu, kết thúc] và múi giờ lấy từ nhật ký.

## 4. Kiểm thử

Không chạm mạng lab: dùng `--thu` và một máy chủ loopback `127.0.0.1` với mạng cho phép tạm mở thành
`127.0.0.0/8`.

- `check_target` từ chối IP ngoài lab (`8.8.8.8`, `192.168.51.5`), nhận IP trong lab.
- Tải kết nối bị chặn ở 60 giây dù xin lâu hơn.
- Kế hoạch bình thường/quét có số yêu cầu/cổng đúng; `--thu` không ghi nhật ký.
- Gửi thật trên loopback: client bình thường nối được, tải kết nối thử được ít nhất một lần và dừng đúng hạn.
- Đổi nhật ký: `benign` không tạo luật; `dos`/`port_scan` ra đúng IP, giờ, múi giờ, cổng; **cột CSV khớp đúng
  `SCHEDULE_COLUMNS` của `nids.labeling`**.

## 5. Còn lại (cần lab thật)

Script đã sẵn sàng; phần phải chạy trong lab (Chặng 11): dựng mạng 7 node, kiểm tra mirror hai chiều, đồng bộ
đồng hồ, bắt gói bằng tcpdump trên Kali, rồi gán nhãn bằng nhật ký. Mỗi kịch bản lặp ≥ 3 lần với lịch khác
nhau (B19); các lần `test` thu sau khi mô hình đã khóa.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Kịch bản / biến thể | Loại hành vi cần thu / một cách chạy cụ thể của kịch bản |
| Quét cổng (connect scan) | Thử mở kết nối tới nhiều cổng để biết cổng nào đang mở |
| Tải kết nối (DoS SYN mô phỏng) | Mở/đóng liên tục nhiều kết nối TCP thường để tạo nhiều kết nối dở dang |
| Kết nối không hoàn tất | Có gói mở (SYN) nhưng không có trao đổi dữ liệu tiếp theo |
| Nhật ký lần chạy | File ghi thông tin mỗi lần chạy, dùng làm căn cứ gán nhãn |
| Lịch gán nhãn | Bảng khung giờ và cặp IP tấn công để gán nhãn cho flow |
| Vai trò (train/val/test) | Lần chạy dùng để học / chọn tham số / đánh giá cuối |
| Múi giờ | Độ lệch giờ địa phương so với UTC |
| Loopback | Địa chỉ 127.0.0.1, chỉ nói chuyện trong cùng máy |
| Nmap | Công cụ quét cổng phổ biến |

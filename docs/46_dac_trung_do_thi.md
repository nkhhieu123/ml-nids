# C08-T02 — Số peer, bậc vào/ra, tính tương hỗ và mức tập trung

Mã nguồn: `host_features`, `build_features`, `in_networks` trong `src/nids/graph_features.py`.
Kiểm thử: `tests/test_botnet.py`. Kết quả: `output/ctu13/<phiên>.host_windows.csv.gz` (không lên git).

```bash
cd src
python -m nids.graph_features dac-trung ../output/ctu13 --scenario 11 --scenario 12 --out ../output/ctu13
```

## 1. Đặc trưng

Mỗi **host–cửa sổ** (host cần xét × cửa sổ 120 giây) có một dòng, tính từ bảng cạnh của C08-T01.
"Ra" là flow host khởi tạo; "vào" là flow peer khởi tạo tới host.

| Nhóm | Đặc trưng | Định nghĩa |
|---|---|---|
| Số peer, bậc | `so_peer` | Số IP khác nhau có flow với host |
| | `so_peer_ra`, `so_peer_vao` | Bậc ra (số peer host gọi tới), bậc vào (số peer gọi tới host) |
| | `so_flow_ra/vao`, `so_byte_ra/vao`, `so_goi_ra/vao` | Tổng flow, byte, gói mỗi hướng |
| Tương hỗ | `ty_le_tuong_ho` | Phần peer có flow **cả hai hướng** (host gọi peer và peer gọi host) |
| Mức tập trung | `tap_trung_ra`, `tap_trung_vao` | Phần flow dồn vào **một** peer nhiều nhất |
| | `entropy_peer_ra`, `entropy_peer_vao` | Entropy của flow theo peer, chia cho log(số peer): 0 là dồn hết vào một peer, 1 là chia đều |
| Khác | `so_cong_ra` | Số cổng đích khác nhau host gọi tới |
| | `ty_le_khong_tra_loi_ra` | Phần flow ra mà bên kia không gửi byte nào |
| | `ty_le_udp` | Phần flow UDP |
| | `ty_le_peer_noi_bo` | Phần peer trong mạng nội bộ (`botnet.local_nets`: 147.32.0.0/16 cho CTU-13, 192.168.50.0/24 cho lab) |
| | `ty_le_peer_moi` | Phần peer **không** xuất hiện ở cửa sổ không chồng lấn ngay trước (120 giây trước) |

Quy ước khi thiếu dữ liệu (QĐ-037): hướng không có flow nào thì mức tập trung, entropy và
`ty_le_khong_tra_loi_ra` để **trống**, không điền 0, vì "không gọi ai" khác với "gọi đều nhiều
người". Mô hình ở C08-T05 điền trống bằng trung vị train và thêm cột đánh dấu, như Chặng 5.

Vì sao chọn các đặc trưng này:
- **Botnet tập trung**: bot gọi lặp lại một vài máy điều khiển → bậc ra nhỏ, `tap_trung_ra` cao,
  peer ít đổi (`ty_le_peer_moi` thấp).
- **Botnet ngang hàng**: bot nói chuyện với nhiều peer, peer đổi liên tục, nhiều kết nối không được trả
  lời, thường dùng UDP, và peer cũng gọi lại bot → bậc vào cao, entropy cao, tương hỗ.
- **Tấn công do bot thực hiện** (spam, quét, DDoS): rất nhiều peer hoặc rất nhiều flow tới một nạn
  nhân, tỷ lệ không trả lời cao.

## 2. Kết quả trên scenario 11 và 12

10 160 host–cửa sổ, 26 host mỗi scenario (3 bot, 3 máy bình thường, 20 Background). Trung vị
theo vai trò host (chưa gán nhãn theo cửa sổ; nhãn ở C08-T04):

| Đặc trưng | Bot (1 315) | Máy bình thường (1 299) | Background mẫu (7 546) |
|---|---|---|---|
| `so_peer` | **52** | 8 | 3 |
| `so_peer_ra` / `so_peer_vao` | 1 / **45** | 8 / 0 | 2 / 0 |
| `so_flow_ra` / `so_flow_vao` | 2 / 47 | 52 / 0 | 4 / 0 |
| `tap_trung_ra` | 0,25 | 0,67 | 0,67 |
| `entropy_peer_vao` | **1,00** | 0,00 | 0,81 |
| `ty_le_khong_tra_loi_ra` | **0,38** | 0,00 | 0,00 |
| `ty_le_udp` | **1,00** | 0,62 | 0,50 |
| `ty_le_peer_noi_bo` | 0,00 | 0,11 | 0,50 |
| `ty_le_peer_moi` | 1,00 | 0,73 | 0,88 |
| `ty_le_tuong_ho` | 0 | 0 | 0 |

Bot ở đây chủ yếu là scenario 12 (P2P): nhiều peer **bên ngoài** gọi vào qua UDP, mỗi peer một
flow (entropy vào 1,0), peer đổi liên tục, 38% flow ra không được trả lời. Máy bình thường chủ động
gọi khoảng 8 đích, lặp lại một đích chính. Tính tương hỗ có trung vị 0 ở cả ba nhóm, vì trong 120
giây hiếm khi cả hai bên cùng khởi tạo flow với nhau; đặc trưng này chỉ khác 0 ở một phần cửa sổ.

Số liệu đủ 13 scenario, tách theo nhãn host–cửa sổ, ở C08-T04.

## 3. Hạn chế

- Chỉ dùng hàng xóm trực tiếp (QĐ-036): không tính được độ trung tâm của host trong toàn mạng, hay
  việc nhiều bot cùng gọi một máy điều khiển. Phần đó làm ở bộ nhận diện topology (C08-T07), trên
  đồ thị gộp các host nghi vấn.
- `ty_le_peer_moi` ở cửa sổ đầu tiên của phiên luôn là 1 (chưa có cửa sổ trước).
- Trọng số theo số flow; một kết nối dài truyền nhiều byte vẫn chỉ là một flow.

## 4. Kiểm thử

- Ví dụ tính tay: số peer, bậc ra/vào, tương hỗ 0,5, tập trung 0,75, entropy chuẩn hóa, số cổng,
  tỷ lệ không trả lời, UDP, peer nội bộ.
- Peer mới so với cửa sổ 120 giây trước; hướng không có flow thì để trống.
- `in_networks` bỏ qua chuỗi không phải IP và khác phiên bản IP.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Host–cửa sổ | Một máy trong một cửa sổ 120 giây; đơn vị đánh giá module botnet |
| Peer | Máy có trao đổi trực tiếp với host |
| Bậc ra / bậc vào | Số peer host gọi tới / số peer gọi tới host |
| Tính tương hỗ | Hai máy cùng chủ động gọi nhau |
| Mức tập trung | Lưu lượng dồn vào ít peer hay chia đều cho nhiều peer |
| Entropy chuẩn hóa | Độ "chia đều", từ 0 (dồn hết một chỗ) tới 1 (đều tuyệt đối) |
| Cửa sổ không chồng lấn | Cửa sổ ngay trước, không trùng phần thời gian nào |
| Mạng nội bộ | Dải địa chỉ của mạng đang giám sát |
| UDP | Giao thức gửi gói không cần mở kết nối; nhiều botnet P2P dùng |
| P2P (ngang hàng) | Các bot nói chuyện trực tiếp với nhau, không có máy trung tâm |

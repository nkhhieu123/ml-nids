# C08-T07 — Bộ nhận diện topology: dùng QUY TẮC, không dùng ML

Mã nguồn: `recognize_topology`, `topology_rule`, `run_topology`, `topology_confusion` trong
`src/nids/botnet.py`. Cấu hình: `botnet.topology_rule` trong `config/default.yaml`. Kiểm thử:
`tests/test_botnet.py`. Kết quả: `docs/hinh/botnet_danh_gia.json` (mục `topology`).

## 1. Quy tắc hay ML: chọn **quy tắc** (QĐ-042)

| | Quy tắc | ML (ví dụ Random Forest 3 lớp) |
|---|---|---|
| Dữ liệu P2P có nhãn | Không cần nhiều; chỉ để kiểm tra ngưỡng | Cần nhiều lần chạy P2P độc lập để học **và** kiểm thử riêng |
| CTU-13 | 1 scenario P2P (12), 3 bot | Học trên 12 thì test không còn P2P nào (B11) |
| Giải thích | Đọc được: "≥ 5 peer gọi vào, ≥ 50% UDP" | Khó giải thích vì sao gọi một host là P2P |
| Chuyển sang lab | Ngưỡng chỉnh bằng cấu hình | Phải học lại khi có dữ liệu lab |

Với một scenario P2P, ML chỉ học thuộc scenario 12. Vì vậy dùng quy tắc trên đặc trưng của C08-T02.
Khi lab có đủ lần chạy P2P (B18, B19: ≥ 3 lần mỗi kịch bản), có thể thử ML và so với quy tắc này.

## 2. Quy tắc

Bộ nhận diện chạy **sau** bộ phát hiện botnet (C08-T05), trên từng host–cửa sổ:

```
nếu host–cửa sổ không bị nghi là bot            -> none
ngược lại, nếu  số peer gọi vào   >= 5           (so_peer_vao,      min_peer_vao)
         và     phần flow UDP     >= 0,5         (ty_le_udp,        min_udp)
         và     entropy flow vào  >= 0,8         (entropy_peer_vao, min_entropy_vao)
                                                 -> p2p
ngược lại                                        -> centralized
```

Ý nghĩa:
- Bot ngang hàng **được nhiều peer chủ động gọi tới**, mỗi peer một ít (entropy cao), qua UDP.
- Bot tập trung chủ yếu **gọi ra**: tới máy điều khiển và tới nạn nhân của spam, quét, DDoS.

**Topology của cả lần chạy hoặc scenario** (`run_topology`): nhãn chiếm đa số trong các cửa sổ bị
nghi; không có cửa sổ bị nghi thì `none`.

**Ngưỡng đặt bằng dữ liệu nào**: chỉ CTU-13 train (scenario 3, 5, 7, 10, 11, 12) và lần chạy giả lập
thứ nhất của mỗi kiểu. Phân vị 10% của cửa sổ bot P2P (scenario 12): 12,6 peer gọi vào, UDP 0,89,
entropy vào 1,0. Trung vị cửa sổ bot tập trung: 1 peer gọi vào, UDP 0. Giả lập P2P lần 1: 8 peer gọi
vào, UDP 0,73. Ngưỡng 5 / 0,5 / 0,8 nằm giữa hai nhóm, nghiêng về phía bắt được P2P có ít peer.

## 3. Kết quả trên dữ liệu dùng để đặt ngưỡng

Chỉ đo bộ nhận diện: chạy trên **đúng các cửa sổ bot thật** (nhãn `suspect_host`), để tách lỗi của
bộ nhận diện khỏi lỗi của bộ phát hiện.

| Dữ liệu | Cửa sổ tập trung đúng | Cửa sổ P2P đúng | Scenario đúng |
|---|---|---|---|
| CTU-13 train | 8 878 / 8 878 (100%) | 663 / 697 (95,1%) | 6 / 6 |
| CTU-13 validation (4, 13) | 6 555 / 6 555 (100%) | không có P2P | 2 / 2 |

34 cửa sổ P2P bị xếp thành tập trung: cửa sổ đầu và cuối của scenario 12, khi bot mới có ít peer gọi
vào. Kết quả trên test và trên toàn bộ giả lập ở C08-T08.

## 4. Hạn chế

- **Đối chứng tập trung lành tính có cùng hình dạng** với botnet tập trung. Bộ nhận diện không phân
  biệt được; chỉ không báo khi bộ phát hiện không nghi host đó.
- P2P chu kỳ dài (ít peer gọi vào trong 120 giây) sẽ bị xếp thành tập trung (giả lập p2p_2, chu kỳ
  60 giây, ở C08-T08).
- P2P dùng TCP sẽ không đạt điều kiện UDP. Cả CTU-13 scenario 12 và giả lập đều dùng UDP; cần kiểm
  tra lại với dữ liệu lab.
- Chưa dùng thông tin **nhóm** (nhiều host nghi vấn cùng gọi một máy, hoặc gọi lẫn nhau) vì đồ thị chỉ
  có một bước quanh từng host (QĐ-036). Đây là hướng mở rộng khi có lab 7 node, nơi đồ thị toàn mạng nhỏ.

## 5. Kiểm thử

- Cửa sổ không bị nghi là `none`; đủ ba điều kiện là `p2p`; thiếu một điều kiện (ít peer, ít UDP,
  entropy trống) là `centralized`; đổi ngưỡng thì kết quả đổi theo.
- Topology của lần chạy là nhãn đa số của cửa sổ bị nghi, không có thì `none`.
- Confusion matrix và độ chính xác đúng trên ví dụ tính tay.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Topology | Hình dạng giao tiếp của botnet |
| Tập trung (centralized) | Các bot cùng gọi một máy điều khiển |
| Ngang hàng (p2p) | Các bot gọi trực tiếp lẫn nhau, không có máy trung tâm |
| Quy tắc | Điều kiện viết tay trên đặc trưng, không học từ dữ liệu |
| Peer gọi vào | Máy khác chủ động mở flow tới host |
| Entropy flow vào | Mức chia đều flow vào giữa các peer, 0 tới 1 |
| Phân vị 10% | Giá trị mà 10% số mẫu nhỏ hơn |
| Nhãn đa số | Nhãn xuất hiện nhiều nhất |
| Confusion matrix | Bảng đếm theo nhãn thật (hàng) và nhãn đoán (cột) |

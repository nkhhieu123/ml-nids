# Demo trực tiếp nhiều cửa sổ

Mỗi loại tấn công một terminal riêng. Cửa sổ giám sát `.10` phát hiện và hiện lên ngay; dừng một cửa sổ tấn công
thì vài giây sau `.10` ngừng hiện loại đó. Tất cả dùng chung một lab ảo (số 8) và mô hình lab (`config/lab.yaml`).

## Thứ tự chạy

1. **Cửa sổ 1 — giám sát** (chạy trước tiên):
   ```bash
   bash demo/truc_tiep/giam_sat.sh
   ```
   Dựng lab, bật máy chủ web `.30`, bật máy điều khiển botnet `.50`, rồi bật cảm biến realtime trên `.10`.
   Màn hình chỉ in: **giờ · loại tấn công phát hiện · máy nào**. Đóng cửa sổ này (Ctrl+C) là tự dọn lab.

2. **Các cửa sổ tấn công** (mở thêm, mỗi cái một terminal, gõ là tấn công; Ctrl+C để dừng):
   ```bash
   bash demo/truc_tiep/tancong_dos.sh                 # .20 tải kết nối (DoS) vào .30
   bash demo/truc_tiep/tancong_nmap.sh                # .20 quét cổng (Nmap) .30
   bash demo/truc_tiep/tancong_botnet.sh              # .41 .42 .43 gọi máy điều khiển .50 (tập trung)
   bash demo/truc_tiep/tancong_botnet.sh ngang-hang   # botnet ngang hàng: các bot gọi lẫn nhau
   ```

Chạy được đồng thời cả ba cửa sổ tấn công. Các script tự xin quyền `sudo`.

## Thời gian phát hiện

| Loại | Hiện trên `.10` sau | Khi dừng, tắt sau |
|---|---|---|
| Quét cổng, DoS | 1–3 giây | vài giây |
| Botnet | khoảng 10–20 giây | tới ~120 giây (module botnet nhìn lại cửa sổ đồ thị 120 giây) |

## An toàn

Mọi lưu lượng chỉ đi giữa các máy ảo trong `192.168.50.0/24`, không có đường ra ngoài; DoS mỗi đợt tối đa 60 giây;
bot chỉ gửi tin nhắn vô hại. **Không nhắm các lệnh này vào máy hay IP thật** (yêu cầu an toàn B24).

## Nếu cửa sổ tấn công báo "Lab chưa chạy"

Hãy mở cửa sổ giám sát (`giam_sat.sh`) trước và đợi dòng `CẢM BIẾN .10 ĐANG GIÁM SÁT`.

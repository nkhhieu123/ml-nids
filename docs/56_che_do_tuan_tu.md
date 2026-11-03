# C09-T04 — Chế độ tuần tự Gaussian → phân loại → kiểm tra botnet

Mã nguồn: `run_sequential` trong `src/nids/pipeline.py`. Cấu hình: `pipeline.mode` (`doc_lap` mặc
định, hoặc `tuan_tu`). Kiểm thử: `tests/test_pipeline.py`.

```bash
cd src
python -m nids.pipeline chay ../output/pcap/fri_quet.pcap --net 192.168.10.0/24 --net 172.16.0.0/24 \
    --out ../output/pipeline --che-do tuan_tu          # ghi output/pipeline/fri_quet_tuan_tu.*
```

## 1. Cách chạy

```
mọi cửa sổ 10 s ──> Gaussian ──normal──> dừng (không phân loại, không kiểm tra botnet)
                       │
                    anomaly
                       v
               Random Forest phân loại ──port_scan/dos──> cảnh báo tấn công (đã giải thích)
                       │
                     benign  (bất thường chưa giải thích được)
                       v
         kiểm tra botnet cho host đó: đồ thị, beaconing 120 s chỉ của các host này,
         giữ cửa sổ 120 s chồng lên cửa sổ bất thường chưa giải thích ──> suspect_host, topology
```

Ý tưởng (QĐ-046):
- Gaussian rẻ và nhạy, làm **bộ lọc đầu**.
- Bộ phân loại **gọi tên** bất thường nếu là loại đã học.
- Phần bất thường còn lại mới cần module botnet, đắt nhất vì phải dựng đồ thị.

Đầu ra cùng dạng chế độ độc lập, nên dùng chung bước cảnh báo và hợp nhất (C09-T03). Khác biệt:
- bảng phân loại chỉ có cửa sổ đã xét;
- bảng botnet chỉ có host được kiểm tra;
- `<tên>.pipeline.json` có mục `tuan_tu`: số cửa sổ bất thường, số cửa sổ đã phân loại, số cửa sổ
  chưa giải thích, danh sách host kiểm tra botnet.

**Chế độ độc lập vẫn là mặc định**, đúng thiết kế ở docs/02 mục 1 (anomaly không là cổng lọc bắt
buộc). Chế độ tuần tự là lựa chọn thêm, được so sánh ở C09-T05.

## 2. Kết quả trên bốn đoạn PCAP

| Đoạn | Cửa sổ 10 s | Gaussian báo (= cửa sổ phân loại) | Chưa giải thích | Host kiểm tra botnet (độc lập: mọi host) | Cảnh báo port_scan/dos (độc lập → tuần tự) | Cảnh báo suspect_host (độc lập → tuần tự) |
|---|---|---|---|---|---|---|
| `fri_binh_thuong` | 4 633 | 421 | 405 | 6 (15) | 34 → 16 | 153 → 25 |
| `fri_quet` | 7 464 | 814 | 598 | 11 (16) | 225 → 216 | 292 → 75 |
| `wed_slowloris` | 1 964 | 319 | 19 | 3 (16) | 311 → 300 | 170 → 13 |
| `wed_hulk` | 1 406 | 179 | 40 | 6 (16) | 155 → 139 | 116 → 22 |

- Bộ phân loại chỉ chạy trên **5–23%** số cửa sổ.
- Module botnet chỉ kiểm tra **3–11** host thay vì 15–16.
- Khi đang có DoS (`wed_slowloris`), gần hết bất thường được bộ phân loại giải thích là `dos`; chỉ 19
  cửa sổ cần kiểm tra botnet.
- Cảnh báo tấn công giảm nhẹ (225 → 216 trên `fri_quet`): đó là các cửa sổ bộ phân loại báo nhưng
  Gaussian không thấy bất thường. Chúng **bị bỏ qua** trong chế độ tuần tự.
- Cảnh báo botnet giảm mạnh (292 → 75): phần lớn cảnh báo botnet ở chế độ độc lập rơi vào cửa sổ
  Gaussian cho là bình thường, hoặc đã được giải thích là quét cổng.

Giảm cảnh báo **không có nghĩa là tốt hơn**: có thể là bớt báo nhầm, cũng có thể là bỏ sót. C09-T05 đo
bằng nhãn.

## 3. Kiểm thử

- Trên PCAP tổng hợp có máy quét: chỉ cửa sổ bất thường được phân loại; quét được giải thích nên không
  kiểm tra botnet.
- Khi bộ phân loại (giả) cho là `benign`: chỉ máy bất thường được kiểm tra botnet, và mọi cửa sổ 120
  giây giữ lại đều chồng lên một cửa sổ bất thường của chính máy đó.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Chế độ độc lập | Ba module chạy song song trên toàn bộ dữ liệu |
| Chế độ tuần tự | Module sau chỉ chạy trên phần module trước đánh dấu |
| Bộ lọc đầu | Bước rẻ, chạy trước để loại phần chắc chắn bình thường |
| Bất thường chưa giải thích | Cửa sổ Gaussian báo bất thường nhưng bộ phân loại cho là benign |
| Chồng lên (thời gian) | Hai khoảng thời gian có phần chung |

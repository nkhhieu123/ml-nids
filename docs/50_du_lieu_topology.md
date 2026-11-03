# C08-T06 — Dữ liệu topology tập trung, ngang hàng và đối chứng lành tính

Mã nguồn: `src/nids/topology_sim.py` (flow giả lập), `scripts/sinh_topology.py` (traffic thật trong
lab). Kiểm thử: `tests/test_botnet.py`. Dữ liệu: `output/topology_sim/` (không lên git).

```bash
cd src
python -m nids.topology_sim --out ../output/topology_sim         # 12 lần chạy, vài giây
```

## 1. Vì sao cần dữ liệu riêng

CTU-13 có 12 scenario botnet **tập trung** nhưng chỉ **một** scenario ngang hàng (12, ba bot), và
không có đối chứng lành tính có cùng hình dạng. Nhận diện topology cần cả bốn loại (B17, B18):

| Kiểu | Topology | Hình dạng |
|---|---|---|
| Botnet tập trung | `centralized` | Mỗi bot gọi một máy điều khiển theo chu kỳ |
| Botnet ngang hàng | `p2p` | Bot gọi lẫn nhau và gọi peer ngoài qua UDP; danh sách peer đổi dần; peer gọi lại; một phần không được trả lời |
| Đối chứng tập trung lành tính | `none` | Ba máy hỏi máy chủ dịch vụ theo chu kỳ (như kiểm tra cập nhật): **cùng hình dạng** với botnet tập trung |
| Đối chứng ngang hàng lành tính | `none` | Ba máy chia sẻ file với nhau và vài peer ngoài theo từng đợt: TCP, nhiều byte, không đều |

Có hai cách tạo dữ liệu.

## 2. Flow giả lập (`nids.topology_sim`)

Chỉ sinh **bản ghi flow** theo bảng flow chung (docs/45), **không gửi gói nào**. Dùng ngay được khi
chưa có lab.
- Ba host 192.168.50.41–43 là đối tượng của lần chạy.
- 192.168.50.20 chỉ duyệt web.
- Mọi host có nền duyệt web (Poisson, khoảng 6 kết nối mỗi phút) và DNS, để hành vi lẫn trong traffic
  thường.

Mỗi kiểu chạy **3 lần với lịch khác nhau** (B19), mỗi lần 15 phút (≥ 10 phút theo B17, B18):

| Kiểu | Lần 1 | Lần 2 | Lần 3 |
|---|---|---|---|
| Tập trung | chu kỳ 30 s, jitter 0 | 60 s, ±20% | 45 s, ±40% |
| Ngang hàng | 30 s, ±30% | 60 s, ±50% | 20 s, ±40% |
| Đối chứng tập trung | 30 s, 0 | 60 s, ±10% | 45 s, ±30% |
| Đối chứng ngang hàng | đợt ngẫu nhiên | đợt ngẫu nhiên | đợt ngẫu nhiên |

Mỗi lần chạy có **nhật ký** (`nhat_ky.jsonl`, B10): mã lần chạy, bắt đầu, kết thúc, IP tham gia, máy
điều khiển, hành vi, chu kỳ, jitter, seed, cờ `gia_lap`. **Nhãn lấy từ nhật ký**, không từ đặc trưng
(`label_runs`):
- host tham gia có flow hành vi trong cửa sổ thành `suspect_host` (botnet) hoặc `normal_host` (đối
  chứng);
- 192.168.50.20 là `normal_host`;
- chỉ giữ cửa sổ nằm trọn trong lần chạy.

Kết quả: 12 lần chạy, 5 600–13 500 flow. Số host–cửa sổ: tập trung 711 bot + 237 bình thường; ngang
hàng 711 + 237; đối chứng tập trung 948 bình thường; đối chứng ngang hàng 682 bình thường (266 cửa sổ
`bo` giữa các đợt).

Trung vị đặc trưng của ba host tham gia (cùng mã C08-T02, T03 như CTU-13):

| Đặc trưng | Tập trung | Ngang hàng | Đối chứng tập trung | Đối chứng ngang hàng |
|---|---|---|---|---|
| `so_peer` | 12 | 24 | 12 | 14 |
| `so_peer_vao` | 0 | **8** | 0 | 1 |
| `ty_le_udp` | 0,20 | **0,73** | 0,19 | 0,17 |
| `ty_le_khong_tra_loi_ra` | 0 | **0,17** | 0 | 0 |
| `ty_le_tuong_ho` | 0 | **0,21** | 0 | 0,07 |
| `beacon_so_cap_deu` | **1** | 0 | **1** | 0 |
| `beacon_cv_nho_nhat` | **0,12** | 0,45 | **0,06** | 0,87 |

Botnet tập trung và đối chứng tập trung **giống nhau về đặc trưng** (đúng thiết kế): chỉ khác ở đích
gọi tới là máy điều khiển hay máy chủ dịch vụ. Một bộ phát hiện chỉ dựa trên hình dạng sẽ báo nhầm đối
chứng này; C08-T08 đo đúng điều đó.

**Giới hạn**: đây là dữ liệu do chính đồ án sinh ra theo giả định về hành vi bot, nên chỉ dùng để
kiểm tra bộ nhận diện chạy đúng logic. Không coi là bằng chứng mô hình hoạt động trên botnet thật
(B25). Kết quả trên giả lập luôn báo cáo riêng với CTU-13.

## 3. Traffic thật trong lab (`scripts/sinh_topology.py`)

Script chạy trên các máy lab, sinh traffic thật cho bốn kiểu trên:

| Lệnh | Vai trò |
|---|---|
| `may-chu --cong N [--udp]` | Máy nhận / máy điều khiển mô phỏng: trả lời "ok", không xử lý nội dung |
| `tap-trung --may-chu IP --cong N --chu-ky T --jitter J` | Bot tập trung: gọi về theo chu kỳ |
| `ngang-hang --peer IP ... --cong N --chu-ky T` | Bot ngang hàng: vừa nghe vừa gửi UDP tới danh sách peer |
| `doi-chung-tap-trung --may-chu IP --cong N --chu-ky T` | Đối chứng: hỏi máy chủ dịch vụ định kỳ |
| `doi-chung-ngang-hang --peer IP ... --cong N` | Đối chứng: chia sẻ khối dữ liệu 200 KB–2 MB theo đợt |

An toàn (B24):
- chỉ gửi chuỗi `nids-lab thong diep vo hai`, không thực thi gì nhận được, không dùng mã độc;
- **từ chối mọi đích ngoài 192.168.50.0/24**;
- `--thu` chỉ in kế hoạch, không gửi.

Mỗi lần chạy ghi một dòng nhật ký vào `data/run_logs/nhat_ky.jsonl` (mã lần chạy, giờ bắt đầu và kết
thúc, IP máy, IP đích, hành vi, topology, tham số). Đây cũng là đề xuất **định dạng nhật ký lần chạy**
còn thiếu ở docs/Viec_con_thieu.md mục 3.

Chưa chạy được vì lab chưa dựng. Khi có lab: bắt PCAP trên Kali, ghép flow bằng `nids.flows`, đổi
sang bảng flow chung bằng `nids.ctu13.from_project_flows`, rồi dùng đúng các bước của Chặng 8.

## 4. Kiểm thử

- Giả lập: đúng cột; chu kỳ cố định cho đúng khoảng 30 giây; P2P có UDP và peer gọi lại; đối chứng có
  topology `none`; kiểu lạ báo lỗi; bộ mặc định đủ 4 kiểu × 3 lần.
- Nhãn từ nhật ký: bot của lần chạy tập trung là `suspect_host`/`centralized`; đối chứng là
  `normal_host`; chỉ giữ cửa sổ trong lần chạy.
- Script lab: từ chối đích ngoài mạng lab; lịch gửi đúng chu kỳ ± jitter; chạy thử không gửi gì.

## Thuật ngữ

Giải thích ngắn các thuật ngữ dùng trong tài liệu này.

| Thuật ngữ | Giải thích |
|---|---|
| Topology tập trung / ngang hàng | Các bot cùng gọi một máy điều khiển / các bot gọi trực tiếp lẫn nhau |
| Đối chứng lành tính | Traffic hợp lệ có hình dạng giống botnet, để đo báo nhầm |
| Flow giả lập | Bản ghi flow do chương trình tạo ra, không có gói tin thật |
| Jitter | Độ lệch ngẫu nhiên quanh chu kỳ |
| Nhật ký lần chạy | File ghi mỗi lần thử nghiệm; căn cứ gán nhãn (B10) |
| Seed | Số khởi tạo ngẫu nhiên; cố định để sinh lại đúng dữ liệu |
| Poisson | Mô hình số sự kiện ngẫu nhiên trong một khoảng thời gian |
| Mạng lab cô lập | Mạng thử nghiệm không nối ra ngoài (B13, B24) |

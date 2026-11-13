#!/usr/bin/env bash
# Demo trực tiếp: dựng một lab ảo, bật cảm biến realtime trên máy giám sát, chạy một kịch bản rút gọn và in
# cảnh báo ngay khi cảm biến phát ra. Cuối cùng so giờ tấn công (nhật ký lần chạy) với giờ cảnh báo đầu tiên.
# Chạy bằng root trên WSL2 (thường gọi qua các file demo/*.bat):
#   bash scripts/demo_lab.sh <biến thể> [tỉ lệ thời gian]
#   bash scripts/demo_lab.sh k2-quet-nhanh        # quét cổng bằng Nmap, khoảng 3 phút
#   bash scripts/demo_lab.sh k3-dos-muc2          # tải kết nối 60 giây, khoảng 3 phút
# Tỉ lệ thời gian (mặc định 0.2) chỉ co đoạn chờ trước và sau tấn công; bản thân tấn công giữ nguyên.
# Kết quả demo nằm ở output/demo/, không ghi vào data/ nên không lẫn với các lần chạy dùng để đánh giá.
set -u
cd "$(dirname "$0")/.."
v="${1:-k2-quet-nhanh}"; tile="${2:-0.2}"
lab=45; lan=99
PY="${PY:-/opt/c11-venv/bin/python}"
run="$v-test-$lan"
out="/root/nids_lab/demo_$run"
alerts="$out/$run.alerts.csv"

don_dep() {
  pkill -KILL -f "nids.realtime --iface eth0 .*--ten $run " 2>/dev/null
  [ -n "${tail_pid:-}" ] && kill "$tail_pid" 2>/dev/null
  python3 scripts/lab_ao.py go --lab "$lab" >/dev/null 2>&1
}
trap don_dep EXIT

echo "=== DEMO: $v ==="
echo "[1/4] Dựng lab ảo 7 máy (192.168.50.0/24, không có đường ra ngoài)..."
python3 scripts/lab_ao.py go --lab "$lab" >/dev/null 2>&1
python3 scripts/lab_ao.py dung --lab "$lab" >/dev/null || { echo "Không dựng được lab. Chạy demo/0_kiem_tra.bat."; exit 1; }
echo "      .10 giám sát | .20 máy thử tấn công | .30 máy chủ web | .41-.43 máy trạm | .50 máy điều khiển"

echo "[2/4] Bật cảm biến realtime trên máy giám sát .10 (mô hình lab, config/lab.yaml)..."
rm -rf "$out"; mkdir -p "$out" output/demo
( cd src && exec ip netns exec "nl${lab}h10" "$PY" -W ignore -m nids.realtime --iface eth0 --net 192.168.50.0/24 \
    --out "$out" --ten "$run" --config ../config/lab.yaml --im-lang ) >"$out/cam_bien.txt" 2>&1 &
for i in $(seq 1 30); do [ -f "$alerts" ] && break; sleep 1; done
sleep 8
if ! pgrep -f "nids.realtime --iface eth0 .*--ten $run " >/dev/null; then
  echo "Cảm biến không chạy được:"; tail -5 "$out/cam_bien.txt"; exit 1
fi

if [ "$v" = k1-binh-thuong ]; then echo "[3/4] Chạy kịch bản đối chứng: chỉ có traffic bình thường, không được có cảnh báo nào (khoảng 2 phút)."
else echo "[3/4] Chạy kịch bản: traffic bình thường, rồi tấn công từ .20 vào .30. Cảnh báo hiện bên dưới khi có."; fi
echo "      (chỉ in cảnh báo có loại tấn công; cảnh báo bất thường chung được đếm ở phần tổng kết)"
echo
tail -n +1 -F "$alerts" 2>/dev/null | awk -F, '
  $1 != "anomaly" && $1 != "module" { printf "  >> %s  CẢNH BÁO %-10s host %-15s điểm %s\n",
                                      strftime("%H:%M:%S"), toupper($2), $5, $7; fflush() }' &
tail_pid=$!
python3 scripts/lab_ao.py chay --lab "$lab" --bien-the "$v" --vai-tro test --lan "$lan" --ti-le "$tile" >"$out/chay.txt" 2>&1 &
chay_pid=$!
while kill -0 "$chay_pid" 2>/dev/null; do
  sleep 5
done
sleep 12                                   # chờ các cửa sổ cuối được chấm
pkill -INT -f "nids.realtime --iface eth0 .*--ten $run "; sleep 3
kill "$tail_pid" 2>/dev/null; tail_pid=
echo

echo "[4/4] Tổng kết: so nhật ký lần chạy (giờ tấn công thật) với cảnh báo của cảm biến"
log="data/run_logs/$run.json"
if [ ! -f "$log" ]; then echo "Kịch bản không chạy xong:"; tail -5 "$out/chay.txt"; exit 1; fi
python3 - "$log" "$alerts" <<'EOF'
import csv, json, sys
from datetime import datetime, timezone

log = json.load(open(sys.argv[1], encoding="utf-8"))
rows = list(csv.DictReader(open(sys.argv[2], encoding="utf-8")))
ep = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
gio = lambda t: datetime.fromtimestamp(t).strftime("%H:%M:%S")
cap = log["ban_thu"]
print(f"  Bản thu: {cap['goi_bat_duoc']} gói, nhân bỏ {cap['goi_nhan_bo']} gói")
dung = set()
for b in log["hanh_vi"]:
    t0, t1 = b["bat_dau_epoch"], b["ket_thuc_epoch"]
    print(f"  Tấn công thật: {b['nhan']} ({b['kieu']}) từ {', '.join(b['ip_nguon'])} vào {', '.join(b['ip_dich'])}, "
          f"{gio(t0)} - {gio(t1)} ({t1 - t0:.0f} giây)")
    hit = [r for r in rows if r["label"] == b["nhan"] and r["src_ip"] in b["ip_nguon"] + b["ip_dich"]
           and ep(r["window_end"]) > t0 and ep(r["window_start"]) < t1 + 10]
    dung.update(id(r) for r in hit)
    if hit:
        first = min(ep(r["created_at"]) for r in hit)
        print(f"  => PHÁT HIỆN: {len(hit)} cảnh báo {b['nhan']}; cảnh báo đầu tiên lúc {gio(first)}, "
              f"sau khi tấn công bắt đầu {first - t0:.1f} giây")
    else:
        print("  => BỎ SÓT: không có cảnh báo đúng loại")
khac = [r for r in rows if r["module"] != "anomaly" and id(r) not in dung]
print(f"  Cảnh báo có loại tấn công nằm ngoài đợt tấn công (báo động giả): {len(khac)}")
print(f"  Cảnh báo bất thường chung (module Gaussian, không nêu loại): {sum(r['module'] == 'anomaly' for r in rows)}")
EOF
d="output/demo/$run"; rm -rf "$d"; mkdir -p "$d"
cp "$alerts" "$d/"; mv "$log" "$d/nhat_ky_lan_chay.json"
rm -rf "data/pcap/lab/$run.pcap" "data/service_logs/$run"
echo "  File: $d/$run.alerts.csv (cảnh báo), $d/nhat_ky_lan_chay.json (nhật ký)"
echo "=== Xong demo $v ==="

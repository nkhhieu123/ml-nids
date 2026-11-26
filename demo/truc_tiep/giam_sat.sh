#!/usr/bin/env bash
# CỬA SỔ GIÁM SÁT (máy .10). Chạy ĐẦU TIÊN, trước các cửa sổ tấn công.
#   bash demo/truc_tiep/giam_sat.sh
# Việc nó làm: dựng lab ảo, bật máy chủ web .30 và máy điều khiển .50, rồi bật cảm biến realtime trên .10.
# Màn hình chỉ in: GIỜ | loại tấn công phát hiện | máy nào. Đóng cửa sổ (Ctrl+C) là tự dọn lab.
source "$(dirname "$(readlink -f "$0")")/_lib.sh"
mo_trong_terminal "GIAM SAT .10" "$0"
can_root "$@"

web_pid=""; cc_pid=""; sensor_pid=""; tail_pid=""
don_dep() {
  echo; vang "Dọn lab và dừng mọi tiến trình..."
  for p in "$tail_pid" "$sensor_pid"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  [ -n "$sensor_pid" ] && kill -INT "$sensor_pid" 2>/dev/null
  TREN 30 pkill -f "http.server" 2>/dev/null
  TREN 50 pkill -f "sinh_topology.py may-chu" 2>/dev/null
  wait 2>/dev/null
  python3 scripts/lab_ao.py go --lab "$LAB" >/dev/null 2>&1
  xanh "Đã dọn xong."
}
trap don_dep EXIT INT TERM

modprobe -a act_mirred sch_ingress cls_matchall 2>/dev/null || true
xanh "[1/3] Dựng lab ảo (192.168.50.0/24, không có đường ra ngoài)..."
python3 scripts/lab_ao.py go --lab "$LAB" >/dev/null 2>&1
python3 scripts/lab_ao.py dung --lab "$LAB" >/dev/null || { do_ "Không dựng được lab. Chạy 'demo_linux.sh 0' để kiểm tra."; exit 1; }
echo "      .10 giám sát | .20 máy tấn công | .30 máy chủ web | .41 .42 .43 bot | .50 máy điều khiển"

xanh "[2/3] Bật máy chủ web .30 (cổng 80) và máy điều khiển botnet .50 (cổng 8080)..."
mkdir -p "$OUT/www" "$OUT/alerts"; echo "<h1>lab web .30</h1>" > "$OUT/www/index.html"
TREN 30 python3 -m http.server 80 --directory "$OUT/www" >"$OUT/web.txt" 2>&1 & web_pid=$!
TREN 50 "$PY" scripts/sinh_topology.py may-chu --cong 8080 --thoi-gian 36000 >"$OUT/cc.txt" 2>&1 & cc_pid=$!
sleep 1

xanh "[3/3] Bật cảm biến realtime trên .10 (mô hình lab). Đang chờ các cửa sổ tấn công..."
rm -f "$ALERTS"
( cd src && exec ip netns exec "$(NL 10)" "$PY" -W ignore -m nids.realtime --iface eth0 --net 192.168.50.0/24 \
    --out "$OUT/alerts" --ten giam_sat --config ../config/lab.yaml --im-lang ) >"$OUT/cam_bien.txt" 2>&1 & sensor_pid=$!
for i in $(seq 1 30); do [ -f "$ALERTS" ] && break; sleep 1; done; sleep 2
if ! kill -0 "$sensor_pid" 2>/dev/null; then do_ "Cảm biến không chạy được:"; tail -8 "$OUT/cam_bien.txt"; exit 1; fi

echo
xanh "================= CẢM BIẾN .10 ĐANG GIÁM SÁT ================="
echo "Mở các cửa sổ khác và gõ: tancong_dos.sh | tancong_nmap.sh | tancong_botnet.sh"
echo "Mỗi dòng dưới đây là một cửa sổ 2 giây mà cảm biến phát hiện tấn công."
echo "Dừng một cửa sổ tấn công (Ctrl+C) thì vài giây sau loại đó ngừng hiện ở đây."
echo "-------------------------------------------------------------"
# In cảnh báo có loại tấn công ngay khi cảm biến ghi vào file.
tail -n +1 -F "$ALERTS" 2>/dev/null | awk -F, '
  BEGIN { t["192.168.50.20"]="máy .20"; t["192.168.50.30"]="máy .30 (web)";
          t["192.168.50.41"]="bot .41"; t["192.168.50.42"]="bot .42"; t["192.168.50.43"]="bot .43";
          t["192.168.50.50"]="máy điều khiển .50";
          ten["PORT_SCAN"]="QUÉT CỔNG"; ten["DOS"]="DoS"; ten["SUSPECT_HOST"]="BOT (nghi vấn)";
          ten["CENTRALIZED"]="BOTNET tập trung"; ten["P2P"]="BOTNET ngang hàng" }
  $1!="anomaly" && $1!="module" {
    L=toupper($2); nh=(L in ten)?ten[L]:L; host=($5 in t)?t[$5]:$5;
    printf "  %s   ▶ PHÁT HIỆN %-18s  tại %-20s  (điểm %s)\n", strftime("%H:%M:%S"), nh, host, $7; fflush() }' &
tail_pid=$!
wait "$sensor_pid"

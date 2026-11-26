#!/usr/bin/env bash
# CỬA SỔ TẤN CÔNG 3 — botnet: ba bot .41 .42 .43 gọi định kỳ về máy điều khiển .50 (tập trung).
#   bash demo/truc_tiep/tancong_botnet.sh            # mặc định: tập trung
#   bash demo/truc_tiep/tancong_botnet.sh ngang-hang # ngang hàng: các bot gọi lẫn nhau
# Gõ là các bot bắt đầu gọi. Ctrl+C để dừng. Sau khi dừng, cảm biến .10 cần tới ~120 giây mới
# ngừng hiện botnet (module botnet nhìn lại cửa sổ đồ thị 120 giây), chậm hơn DoS và quét cổng.
source "$(dirname "$(readlink -f "$0")")/_lib.sh"
KIEU="${1:-tap-trung}"
mo_trong_terminal "TAN CONG BOTNET" "$0"
can_root "$@"
can_lab

pids=()
trap 'echo; vang "Đang dừng các bot..."; for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; vang "Đã dừng botnet."; exit 0' INT TERM

BOTS=(41 42 43)
if [ "$KIEU" = ngang-hang ] || [ "$KIEU" = p2p ]; then
  do_ "=== BOTNET NGANG HÀNG: bot .41 .42 .43 gọi lẫn nhau (UDP cổng 40000) ==="
  ips=(192.168.50.41 192.168.50.42 192.168.50.43)
  for b in "${BOTS[@]}"; do
    peers=(); for ip in "${ips[@]}"; do [ "$ip" = "192.168.50.$b" ] || peers+=(--peer "$ip"); done
    TREN "$b" "$PY" scripts/sinh_topology.py ngang-hang "${peers[@]}" --cong 40000 --chu-ky 8 --jitter 0.3 \
        --thoi-gian 3600 >"$OUT/bot_$b.txt" 2>&1 & pids+=($!)
  done
else
  do_ "=== BOTNET TẬP TRUNG: bot .41 .42 .43 gọi máy điều khiển .50 (cổng 8080) ==="
  for b in "${BOTS[@]}"; do
    TREN "$b" "$PY" scripts/sinh_topology.py tap-trung --may-chu 192.168.50.50 --cong 8080 --chu-ky 8 --jitter 0.2 \
        --thoi-gian 3600 >"$OUT/bot_$b.txt" 2>&1 & pids+=($!)
  done
fi
echo "Ba bot đang gọi định kỳ. Xem cảnh báo BOT / BOTNET ở cửa sổ GIÁM SÁT .10 (hiện sau ~10-20 giây)."
echo "Ctrl+C để dừng."
echo
# Đếm thời gian cho người xem biết demo đang chạy.
giay=0
while true; do sleep 10; giay=$((giay + 10)); vang "[botnet $KIEU] đã chạy $giay giây; ba bot .41 .42 .43 vẫn đang gọi"; done

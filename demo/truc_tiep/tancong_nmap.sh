#!/usr/bin/env bash
# CỬA SỔ TẤN CÔNG 2 — quét cổng (Nmap) từ máy .20 vào máy chủ .30.
#   bash demo/truc_tiep/tancong_nmap.sh
# Gõ là quét liên tục (lặp lại từng lượt quét 1-1024). Ctrl+C để dừng.
# Vài giây sau khi dừng, cửa sổ GIÁM SÁT .10 sẽ ngừng hiện dòng QUÉT CỔNG.
source "$(dirname "$(readlink -f "$0")")/_lib.sh"
mo_trong_terminal "TAN CONG Nmap .20 -> .30" "$0"
can_root "$@"
can_lab
command -v nmap >/dev/null 2>&1 || TREN 20 true  # nmap chạy trong namespace; kiểm tra tồn tại
if ! ip netns exec "$(NL 20)" bash -c 'command -v nmap' >/dev/null 2>&1; then
  do_ "Máy không có nmap. Cài: sudo apt-get install -y nmap"; read -r -p "Enter để đóng..." _; exit 1
fi

trap 'echo; vang "Đã dừng quét. Cửa sổ .10 sẽ ngừng hiện QUÉT CỔNG sau vài giây."; exit 0' INT TERM
do_ "=== MÁY .20 QUÉT CỔNG .30 (1-1024, Nmap) ==="
echo "Quét liên tục. Xem cảnh báo QUÉT CỔNG ở cửa sổ GIÁM SÁT .10. Ctrl+C để dừng."
echo
luot=0
while true; do
  luot=$((luot + 1))
  vang "[lượt $luot] .20 quét cổng 1-1024 của .30"
  TREN 20 nmap -sT -Pn -n -p 1-1024 --max-retries 0 -T4 192.168.50.30 2>&1 | grep -E "scan report|Nmap done|open" | sed 's/^/  /'
done

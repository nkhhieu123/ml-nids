#!/usr/bin/env bash
# CỬA SỔ TẤN CÔNG 1 — DoS từ máy .20 vào máy chủ web .30.
#   bash demo/truc_tiep/tancong_dos.sh
# Gõ là tấn công liên tục (mỗi đợt tải kết nối 60 giây rồi lặp lại). Ctrl+C để dừng.
# Vài giây sau khi dừng, cửa sổ GIÁM SÁT .10 sẽ ngừng hiện dòng DoS.
source "$(dirname "$(readlink -f "$0")")/_lib.sh"
mo_trong_terminal "TAN CONG DoS .20 -> .30" "$0"
can_root "$@"
can_lab

trap 'echo; vang "Đã dừng DoS. Cửa sổ .10 sẽ ngừng hiện DoS sau vài giây."; exit 0' INT TERM
do_ "=== MÁY .20 TẤN CÔNG DoS VÀO .30 (cổng 80) ==="
echo "Tải kết nối liên tục. Xem cảnh báo DoS hiện ở cửa sổ GIÁM SÁT .10. Ctrl+C để dừng."
echo
dot=0
while true; do
  dot=$((dot + 1))
  vang "[đợt $dot] .20 -> .30 : tải kết nối 60 giây (mức 2)"
  TREN 20 "$PY" scripts/sinh_traffic.py tai-ket-noi --may-chu 192.168.50.30 --cong 80 \
      --muc 2 --thoi-gian 60 --vai-tro test --lan truc_tiep 2>&1 | sed 's/^/  /'
done

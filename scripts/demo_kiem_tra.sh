#!/usr/bin/env bash
# Kiểm tra máy đã đủ điều kiện chạy demo chưa (gọi qua demo/0_kiem_tra.bat). Chạy bằng root trên WSL2.
set -u
cd "$(dirname "$0")/.."
PY="${PY:-/opt/c11-venv/bin/python}"
loi=0
kt() {                                     # kt <mô tả> <lệnh...>
  local ten="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "  [ĐẠT]  $ten"; else echo "  [LỖI]  $ten"; loi=1; fi
}
kt "Python của cảm biến ($PY) có numpy, pandas, scikit-learn" "$PY" -c "import numpy, pandas, sklearn, joblib, yaml"
kt "Có nmap" which nmap
kt "Có nginx" which nginx
kt "Có tcpdump" which tcpdump
kt "Có cấu hình lab (config/lab.yaml)" test -f config/lab.yaml
kt "Có mô hình lab (models/lab)" bash -c "ls models/lab/*.joblib"
python3 scripts/lab_ao.py go --lab 45 >/dev/null 2>&1
kt "Dựng được lab ảo" python3 scripts/lab_ao.py dung --lab 45
kt "Máy thử .20 gọi được máy chủ .30" ip netns exec nl45h20 ping -c 1 -W 2 192.168.50.30
python3 scripts/lab_ao.py go --lab 45 >/dev/null 2>&1
if [ "$loi" = 0 ]; then echo "Sẵn sàng demo."; else echo "Còn lỗi, xem demo/HUONG_DAN.md mục 5."; fi
exit "$loi"

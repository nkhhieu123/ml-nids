#!/usr/bin/env bash
# Cài cảm biến ml-nids thành dịch vụ systemd (C10-T07). Chạy sau scripts/cai_dat_kali.sh.
#
#   sudo bash scripts/cai_dich_vu.sh [--thu-muc /opt/ml-nids] [--iface eth1] [--net 192.168.50.0/24] [--khong-bat]
#
# Tạo user hệ thống "nids", phân quyền thư mục kết quả, chép unit và file môi trường, bật dịch vụ khi khởi động
# và chặn máy tự ngủ (máy ngủ thì cảm biến ngừng bắt gói, docs/63). Không khởi động ngay nếu có --khong-bat.
set -euo pipefail

DIR="/opt/ml-nids"
IFACE=""
NET=""
ENABLE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --thu-muc) DIR="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    --net) NET="$2"; shift 2 ;;
    --khong-bat) ENABLE=0; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "Tham số lạ: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Cần chạy bằng sudo" >&2; exit 1; }
[ -x "$DIR/.venv/bin/python" ] || { echo "Chưa cài dự án ở $DIR (chạy scripts/cai_dat_kali.sh trước)" >&2; exit 1; }

echo "== 1. User hệ thống nids"
id nids >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin nids
mkdir -p "$DIR/output/realtime/log" "$DIR/data/run_logs"
chown -R nids:nids "$DIR/output" "$DIR/data/run_logs"
# user nids cần đọc mã và mô hình
chmod -R o+rX "$DIR/src" "$DIR/config" "$DIR/models" "$DIR/.venv"

echo "== 2. File môi trường /etc/ml-nids/nids-realtime.env"
mkdir -p /etc/ml-nids
if [ ! -f /etc/ml-nids/nids-realtime.env ]; then
  sed "s|/opt/ml-nids|$DIR|g" "$DIR/deploy/nids-realtime.env" > /etc/ml-nids/nids-realtime.env
fi
[ -n "$IFACE" ] && sed -i "s|^NIDS_IFACE=.*|NIDS_IFACE=$IFACE|" /etc/ml-nids/nids-realtime.env
[ -n "$NET" ] && sed -i "s|--net [^ ]*|--net $NET|" /etc/ml-nids/nids-realtime.env
cat /etc/ml-nids/nids-realtime.env | grep -v '^#'

echo "== 3. Unit systemd"
sed "s|/opt/ml-nids|$DIR|g" "$DIR/deploy/nids-realtime.service" > /etc/systemd/system/nids-realtime.service
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/nids-realtime.service || true

echo "== 4. Chặn máy tự ngủ (cảm biến cần chạy liên tục)"
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target >/dev/null

if [ "$ENABLE" -eq 1 ]; then
  echo "== 5. Bật và khởi động"
  systemctl enable --now nids-realtime.service
  sleep 3
  systemctl --no-pager status nids-realtime.service | head -15
else
  echo "== 5. Chưa bật (--khong-bat). Bật bằng: sudo systemctl enable --now nids-realtime"
fi

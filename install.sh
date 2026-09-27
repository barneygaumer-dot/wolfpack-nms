#!/usr/bin/env bash
set -euo pipefail
APP=/opt/wolfpack/nms
[[ $EUID -eq 0 ]] || { echo "Run: sudo ./install.sh"; exit 1; }
apt-get update && apt-get install -y python3 python3-venv iputils-ping iputils-arping curl unzip sqlite3 netcat-openbsd
mkdir -p "$APP"; cp -a wolfpack_nms requirements.txt run.py update.sh "$APP/"
python3 -m venv "$APP/.venv"; "$APP/.venv/bin/pip" install -U pip; "$APP/.venv/bin/pip" install -r "$APP/requirements.txt"
cat >/etc/systemd/system/wolfpack-nms.service <<EOF
[Unit]
Description=WolfPack NMS
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
WorkingDirectory=$APP
Environment=WOLFPACK_NMS_DB=$APP/wolfpack.db
ExecStart=$APP/.venv/bin/waitress-serve --listen=0.0.0.0:8088 run:app
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now wolfpack-nms
echo "WolfPack NMS UP: http://$(hostname -I | awk '{print $1}'):8088"

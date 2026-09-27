#!/usr/bin/env bash
set -euo pipefail
ZIP="${1:-}"; APP=/opt/wolfpack/nms; BACK=/opt/wolfpack/nms-backups
[[ -f "$ZIP" ]] || { echo "Usage: sudo $0 release.zip"; exit 1; }
mkdir -p "$BACK"; STAMP=$(date +%Y%m%d-%H%M%S); cp -a "$APP" "$BACK/nms-$STAMP"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT; unzip -q "$ZIP" -d "$TMP"
SRC=$(find "$TMP" -maxdepth 3 -type f -name run.py -printf '%h\n'|head -1); [[ -n "$SRC" ]] || exit 2
cp "$SRC/update.sh" "$APP/update.sh.new"
systemctl stop wolfpack-nms
rm -rf "$APP/wolfpack_nms"; cp -a "$SRC/wolfpack_nms" "$APP/"
cp "$SRC/run.py" "$SRC/requirements.txt" "$APP/"
"$APP/.venv/bin/pip" install -r "$APP/requirements.txt"
systemctl start wolfpack-nms; sleep 4
if curl -fsS http://127.0.0.1:8088/api/health >/dev/null; then
 chmod +x "$APP/update.sh.new"; mv "$APP/update.sh.new" "$APP/update.sh"; echo "Update healthy."
else
 echo "Health failed — rollback."; systemctl stop wolfpack-nms||true; rm -rf "$APP"; cp -a "$BACK/nms-$STAMP" "$APP"; systemctl start wolfpack-nms; exit 3
fi

#!/usr/bin/env bash
# 대시보드를 Tailscale Serve 로 노출한다 (M3/P3.5). tailnet 내부에서만 접근 가능.
# Funnel(공개 인터넷 노출)은 쓰지 않으며, 켜져 있으면 끈다 (CC4: 인터넷 미노출).
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${NETMON_API_PORT:-8080}"

echo "[1/5] 프런트엔드 정적 빌드"
( cd web && npm ci && npm run build )

echo "[2/5] 빌드 산출물 배치 (/opt/netmon/web/build)"
sudo install -d -o netmon -g netmon /opt/netmon/web
sudo rm -rf /opt/netmon/web/build
sudo cp -r web/build /opt/netmon/web/build
sudo chown -R netmon:netmon /opt/netmon/web/build

echo "[3/5] API 유닛 설치·기동 (127.0.0.1:${PORT})"
sudo install -m 0644 systemd/netmon-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netmon-api.service

echo "[4/5] Funnel 비활성 보장 (공개 노출 금지)"
# Funnel 상태가 있으면 끈다. serve 만 사용한다.
if sudo tailscale funnel status >/dev/null 2>&1; then
  sudo tailscale funnel --https=443 off 2>/dev/null || true
fi

echo "[5/5] Tailscale Serve 로 프록시 (tailnet 전용, HTTPS 443 -> 127.0.0.1:${PORT})"
sudo tailscale serve --bg --https=443 "http://127.0.0.1:${PORT}"
echo
echo "serve 상태:"; sudo tailscale serve status || true
echo
echo "완료. tailnet 내부에서만 https://<이 노드의 MagicDNS 이름>/ 로 접근하세요."
echo "공개 인터넷 접근은 차단됩니다(Funnel 미사용)."

#!/bin/bash
# 2단계: Pi의 dnsmasq를 DHCP/DNS 서버로 활성화. 공유기 DHCP가 꺼져 있어야 함.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo로 실행하세요"; exit 1; }
PI_IP=192.168.45.162
echo "[검사] 공유기 DHCP가 아직 살아있는지 탐색 (10초)..."
if command -v nmap >/dev/null; then
  nmap --script broadcast-dhcp-discover -e eth0 2>/dev/null | grep -E 'Server Identifier|Router' | sed 's/^/   /' || true
fi
if [ "${FORCE:-0}" != "1" ]; then
  read -rp "공유기 관리 페이지에서 DHCP 서버를 껐습니까? (yes/no) " ans
  [ "$ans" = "yes" ] || { echo "공유기 DHCP를 먼저 끄세요. (강제: FORCE=1)"; exit 1; }
fi
systemctl enable --now dnsmasq
sleep 1
systemctl is-active dnsmasq | sed 's/^/   dnsmasq: /'
ss -lunp | grep -E ':67 |:53 ' | sed 's/^/   /'
echo "완료. 클라이언트가 임대를 갱신하면 게이트웨이가 $PI_IP 로 바뀝니다 (WiFi 껐다 켜기, 또는 최대 1시간)."
echo "임대 목록: cat /var/lib/misc/dnsmasq.leases"

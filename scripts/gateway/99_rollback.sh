#!/bin/bash
# 전체 되돌리기. 마지막에 공유기 DHCP를 다시 켜는 것을 잊지 말 것.
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo로 실행하세요"; exit 1; }
CON=$(nmcli -t -f NAME,DEVICE con show --active | awk -F: '$2=="eth0"{print $1}')
echo "[1/4] dnsmasq 중지"; systemctl disable --now dnsmasq 2>/dev/null; rm -f /etc/dnsmasq.d/netmon-gateway.conf
echo "[2/4] 게이트웨이 유닛/NAT 제거"; systemctl disable --now netmon-gateway.service 2>/dev/null
rm -f /etc/systemd/system/netmon-gateway.service /etc/netmon/gateway.nft; systemctl daemon-reload
nft delete table inet netmon_gateway 2>/dev/null
echo "[3/4] sysctl 복원"; rm -f /etc/sysctl.d/90-netmon-gateway.conf
sysctl -q -w net.ipv4.conf.all.send_redirects=1 net.ipv4.conf.default.send_redirects=1 net.ipv4.conf.eth0.send_redirects=1
systemctl is-active tailscaled >/dev/null || sysctl -q -w net.ipv4.ip_forward=0
echo "[4/4] eth0 DHCP 복원 (고정 IP 해제)"; nmcli con modify "$CON" ipv4.method auto ipv4.addresses "" ipv4.gateway "" ipv4.dns "" ipv4.ignore-auto-dns no; nmcli dev reapply eth0
echo "완료. 이제 공유기 관리 페이지에서 DHCP 서버를 다시 켜세요. 클라이언트는 임대 갱신 후 원래대로 돌아갑니다."

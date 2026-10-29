#!/bin/bash
# 1단계: Pi를 게이트웨이로 동작시킬 준비 (고정 IP, 포워딩, NAT, 도구 설치)
# 이 단계만으로는 아무 클라이언트도 영향받지 않음. 공유기 설정 변경(2단계) 전까지는 트래픽이 오지 않음.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo로 실행하세요"; exit 1; }
SRC=$(cd "$(dirname "$0")/../../config/gateway" && pwd)
PI_IP=192.168.45.162; GW=192.168.45.1; DNS="210.220.163.82 219.250.36.130"
CON=$(nmcli -t -f NAME,DEVICE con show --active | awk -F: '$2=="eth0"{print $1}')

echo "[1/6] eth0 고정 IP ($PI_IP) - 연결 '$CON', 세션 유지를 위해 reapply 사용"
nmcli con modify "$CON" ipv4.method manual ipv4.addresses $PI_IP/24 ipv4.gateway $GW ipv4.dns "$DNS" ipv4.ignore-auto-dns yes
nmcli dev reapply eth0

echo "[2/6] 패키지 설치 (tcpdump, dnsmasq, nftables)"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -q tcpdump dnsmasq nftables >/dev/null
systemctl disable --now dnsmasq >/dev/null 2>&1 || true   # 2단계에서 켬

echo "[3/6] sysctl (ip_forward, send_redirects)"
install -m 644 "$SRC/90-netmon-gateway.sysctl.conf" /etc/sysctl.d/90-netmon-gateway.conf

echo "[4/6] nftables 규칙 + systemd 유닛"
install -d -m 755 /etc/netmon /var/log/netmon
install -m 644 "$SRC/gateway.nft" /etc/netmon/gateway.nft
install -m 644 "$SRC/netmon-gateway.service" /etc/systemd/system/netmon-gateway.service
systemctl daemon-reload
systemctl enable --now netmon-gateway.service

echo "[5/6] dnsmasq 설정 배치 (아직 비활성)"
install -m 644 "$SRC/dnsmasq-netmon.conf" /etc/dnsmasq.d/netmon-gateway.conf
dnsmasq --test -C /etc/dnsmasq.conf >/dev/null && echo "   dnsmasq 설정 문법 OK"

echo "[6/6] 상태"
sysctl -n net.ipv4.ip_forward net.ipv4.conf.eth0.send_redirects | paste -sd' ' | sed 's/^/   ip_forward send_redirects = /'
nft list table inet netmon_gateway | grep -E 'counter' | sed 's/^/   /'
nmcli -t -f IP4.ADDRESS,IP4.GATEWAY dev show eth0 | sed 's/^/   /'
cat <<MSG

1단계 완료. 다음:
  (a) 공유기 관리 페이지(http://192.168.45.1) 로그인
      - DHCP 서버 설정에 "기본 게이트웨이" 항목이 있으면 -> $PI_IP 로 변경 (DNS도 $PI_IP 권장). 끝.
      - 그런 항목이 없으면 -> 공유기 DHCP 서버를 "사용 안 함"으로 끈 뒤
  (b) sudo bash $(dirname "$0")/02_enable_dhcp.sh   (Pi가 DHCP 서버가 됨)
  (c) 클라이언트를 재접속(또는 임대 갱신)하면 Pi를 거쳐 나감. verify.sh 로 확인.
되돌리기: sudo bash $(dirname "$0")/99_rollback.sh
MSG

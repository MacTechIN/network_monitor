#!/bin/bash
# 게이트웨이 동작 확인: 클라이언트 -> Pi 로 들어오는 인터넷행 패킷이 보이면 성공
PI_IP=192.168.45.162
echo "=== sysctl ==="; sysctl -n net.ipv4.ip_forward net.ipv4.conf.eth0.send_redirects | paste -sd' '
echo "=== nft counters (packets 가 증가해야 함) ==="; sudo nft list table inet netmon_gateway 2>/dev/null | grep counter
echo "=== DHCP 임대 (Pi가 DHCP 서버일 때) ==="; cat /var/lib/misc/dnsmasq.leases 2>/dev/null || echo "(dnsmasq 비활성 또는 임대 없음)"
echo "=== 15초간 클라이언트 -> 인터넷 패킷 샘플 (Pi 자신 제외) ==="
sudo timeout 15 tcpdump -i eth0 -nn -c 20 -q "src net 192.168.45.0/24 and not src host $PI_IP and not dst net 192.168.45.0/24 and not arp" 2>/dev/null \
  || echo "(패킷 없음: 아직 Pi를 게이트웨이로 쓰는 클라이언트가 없음)"
echo "=== 클라이언트별 집계 (최근 흐름, conntrack) ==="
sudo conntrack -L 2>/dev/null | grep -oE 'src=192\.168\.45\.[0-9]+' | grep -v "$PI_IP" | sort | uniq -c | sort -rn | head || echo "(conntrack 도구 없음: sudo apt install conntrack)"

#!/usr/bin/env bash
# netmon 서비스 배포 (M1/P1.3). 전용 사용자, 시스템 venv, 설정/룰 배치, systemd 유닛 설치.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/6] netmon 시스템 사용자"
id -u netmon >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin netmon

echo "[2/6] 상태 디렉터리"
sudo install -d -o netmon -g netmon /var/lib/netmon

echo "[3/6] Suricata 설정과 로컬 룰 배치"
sudo install -m 0644 config/suricata/netmon.yaml /etc/suricata/netmon.yaml
sudo install -m 0644 config/suricata/rules/netmon-local.rules /var/lib/suricata/rules/netmon-local.rules

echo "[4/6] 시스템 venv 에 netmon 설치 (수집기용)"
[ -d /opt/netmon/venv ] || sudo python3 -m venv /opt/netmon/venv
sudo /opt/netmon/venv/bin/pip install --quiet --upgrade pip
sudo /opt/netmon/venv/bin/pip install --quiet .

echo "[5/6] systemd 유닛 설치"
sudo install -m 0644 systemd/suricata-netmon.service /etc/systemd/system/
sudo install -m 0644 systemd/netmon-ingest.service /etc/systemd/system/
sudo systemctl daemon-reload

echo "[6/6] 기동"
sudo systemctl enable --now suricata-netmon.service netmon-ingest.service
echo "완료."

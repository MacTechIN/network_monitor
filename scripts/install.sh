#!/usr/bin/env bash
# network_monitor 설치 스크립트 (M1/P1.1). 멱등하게 재실행 가능하다.
# 센서(Pi)용 엔진·도구와 Python 가상환경을 준비한다. 차단/스푸핑 도구는 설치하지 않는다.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/4] apt 엔진·도구 설치"
sudo apt-get update
sudo apt-get install -y suricata suricata-update arp-scan nmap tcpreplay

echo "[2/4] 기본 suricata.service 비활성화 (전용 systemd 유닛을 대신 사용)"
sudo systemctl disable --now suricata 2>/dev/null || true

echo "[3/4] Python 가상환경과 휠"
[ -d .venv ] || python3 -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
pip install duckdb polars nfstream scikit-learn river statsmodels ruptures skops onnxruntime

echo "[4/4] ET Open 룰 갱신"
sudo suricata-update --no-test || true

echo "완료. EveBox(선택)는 scripts/install_evebox.sh 로 설치한다."

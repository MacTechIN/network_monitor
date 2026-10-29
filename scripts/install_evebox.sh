#!/usr/bin/env bash
# EveBox(원시 알림 뷰어) 설치·구성 (M1/P1.7). arm64 .deb, localhost 전용 바인딩.
set -euo pipefail
cd "$(dirname "$0")/.."
VER="${1:-0.31.0}"
URL="https://evebox.org/files/release/latest/evebox-${VER}-arm64.deb"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "다운로드: $URL"
curl -fsSL -o "$TMP/evebox-arm64.deb" "$URL"
file "$TMP/evebox-arm64.deb" | grep -q "Debian binary package"
sudo dpkg -i "$TMP/evebox-arm64.deb"
sudo install -m 0644 config/evebox/default /etc/default/evebox
sudo systemctl enable --now evebox
echo "EveBox 기동됨: http://127.0.0.1:5636 (Tailscale 너머로만 접근)."

#!/usr/bin/env bash
# Suricata 라이브 처리량·커널 드롭 측정 하버니스 (M1/P1.8).
# veth 쌍으로 호스트 밖으로 트래픽을 내보내지 않고(비파괴) 라이브 경로를 측정한다.
# 측정 전용 임시 설정에서만 stats 를 켠다(운영 설정은 건드리지 않음).
# 사용: sudo scripts/measure_throughput.sh <pcap> [mbps] [loops]
set -euo pipefail
cd "$(dirname "$0")/.."
PCAP="${1:?pcap 경로 필요}"; MBPS="${2:-100}"; LOOPS="${3:-300000}"
A=nm-meas-a; B=nm-meas-b
OUT="$(mktemp -d)"
CFG="$OUT/measure.yaml"
PY="$(pwd)/.venv/bin/python"; [ -x "$PY" ] || PY="$(command -v python3)"
cleanup() { ip link del "$A" 2>/dev/null || true; }
trap cleanup EXIT

# 운영 netmon.yaml 을 베이스로 stats + eve stats 타입만 켠 임시 설정 생성
"$PY" - "$CFG" <<'PYGEN'
import sys, pathlib, yaml
cfg = yaml.safe_load(pathlib.Path("config/suricata/netmon.yaml").read_text())
cfg["stats"] = {"enabled": True, "interval": 1}
for out in cfg.get("outputs", []):
    if "eve-log" in out:
        t = out["eve-log"].setdefault("types", [])
        if "stats" not in t:
            t.append("stats")
pathlib.Path(sys.argv[1]).write_text("%YAML 1.1\n---\n" + yaml.safe_dump(cfg))
print("measure config 생성")
PYGEN

ip link add "$A" type veth peer name "$B"
ip link set "$A" up; ip link set "$B" up
timeout 60 suricata -c "$CFG" -i "$B" -l "$OUT" --runmode workers >/dev/null 2>&1 &
SPID=$!
sleep 4
echo "재생: ${MBPS} Mbps, ${LOOPS} loops"
tcpreplay -i "$A" --mbps "$MBPS" --loop "$LOOPS" "$PCAP" 2>&1 | grep -iE 'Actual.*Mbps|Successful packets' | tail -3 || true
sleep 3
kill -INT "$SPID" 2>/dev/null || true
wait "$SPID" 2>/dev/null || true

echo "=== 드롭 통계 (마지막 stats 이벤트) ==="
"$PY" - "$OUT/eve.json" <<'PYSTAT'
import sys, json, pathlib
p = pathlib.Path(sys.argv[1])
last = None
if p.exists():
    for line in p.read_text().splitlines():
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if o.get("event_type") == "stats":
            last = o["stats"]
if not last:
    print("stats 이벤트 없음"); sys.exit(0)
cap = last.get("capture", {})
pk = cap.get("kernel_packets", 0); dr = cap.get("kernel_drops", 0)
dec = last.get("decoder", {})
pct = (dr / pk * 100) if pk else 0.0
print(f"kernel_packets={pk} kernel_drops={dr} drop={pct:.2f}%")
print(f"decoder.pkts={dec.get('pkts')} decoder.bytes={dec.get('bytes')}")
PYSTAT

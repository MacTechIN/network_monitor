# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

`network_monitor` is a home / small-office **network security sensor** running on a Raspberry Pi 5 (aarch64, Debian 13 trixie, kernel 6.18, NVMe boot). It passively captures LAN traffic on `eth0`, detects known threats (signatures) and unknown threats (per-device behavioral baselines), and explains findings in human-readable reports and alerts.

**As of 2026-10-29 the project is in the definition stage (M0). There is no code, no build, no tests.** The only artifacts are `README.md` and `doc/01_project_definition.md`. The definition doc is the source of truth for scope, requirements (FR-1…FR-27), architecture, stack, data model, milestones and open questions. Read it before proposing or writing anything. Project documentation is written in Korean; keep new docs in Korean unless asked otherwise.

There are no build / lint / test commands yet. When code is added, update this section with the real commands (the plan is Python 3.13 + `pytest`, with detection regression tests driven by replaying public malware PCAPs via `tcpreplay`).

## Hard constraints (do not violate, in any mode or default)

These come from sections 4 and 8 of the definition doc and are non-negotiable design boundaries:

- **Detect and report only. Never block.** This is an IDS, not an IPS/firewall. No traffic blocking, no iptables/nftables drop rules.
- **No ARP spoofing or any other offensive/active-MITM technique** to obtain traffic visibility. Option D in the doc is explicitly rejected.
- **No TLS decryption / MITM.** Encrypted traffic is analyzed by metadata only (SNI, JA3/JA4, certificates, flow patterns).
- **No payload storage.** Store flow metadata, protocol logs, and short alert-triggered PCAP snippets (ring buffer) only. Raw packets are not persisted by default.
- **Owned/administered networks only.** Config must require `monitoring_notice_acknowledged: true` as its first key. Nothing in design, docs, or defaults may support monitoring someone else's network.
- **Conservative defaults:** active scanning (arp-scan/nmap) OFF, external data transmission OFF, payload storage OFF. Dashboard reachable only via localhost or the Tailscale network, never exposed to the internet.
- Capture process runs as a dedicated user holding only `CAP_NET_RAW` / `CAP_NET_ADMIN`.

## Key design decision: traffic visibility

The Pi's `eth0` sits on an ordinary switch port, so promiscuous mode sees only broadcast/multicast (ARP, mDNS, DHCP, SSDP) and the Pi's own traffic. Decision (doc §5): **develop in passive mode (E) now, but architect for a SPAN/mirror port (A)** on a managed switch; inline bridge (B) is deferred to a possible IPS follow-up. Until mirror hardware exists, real-threat development and testing is done by replaying PCAPs, not by live capture.

## Intended architecture

Four layers in one Python process tree plus external engines (doc §9):

1. **Capture / engines** – Suricata 7 (apt, ET Open rules, EVE JSON output) is the signature engine; Zeek is optional/phase 2. A Python passive discoverer watches ARP/DHCP/mDNS/SSDP/LLDP; opt-in active scanning uses `arp-scan`/`nmap`.
2. **Processing (Python)** – ingest EVE/Zeek logs → normalize → enrich (GeoIP/ASN/threat-intel/OUI) → baseline learning & anomaly detection → correlate alerts into incidents → score severity (5 levels) → generate a 5-part narrative (what / which device / to where / why risky / what to do).
3. **Storage** – SQLite for config/devices/alerts/incidents; Parquet + DuckDB for flow analytics; PCAP snippet directory as a size-capped ring buffer. Retention targets: flows 90 d, alerts 1 y, PCAP 30 d, 50 GB cap.
4. **Presentation** – FastAPI backend, SPA dashboard (SvelteKit vs React undecided, ECharts for charts), daily/weekly Markdown/HTML reports, alert dispatcher (Telegram first, then email, webhook).

**Rationale to preserve:** the project deliberately does *not* build its own detection engine. Differentiation is (1) single-Pi integration and unattended operation, (2) per-device baseline anomaly detection, and (3) plain-language explanatory reports. Keep effort on those three, not on reimplementing Suricata/Zeek.

Deployment is systemd units + an install script (bash/Ansible). Docker is explicitly excluded for phase 1 because of AF_PACKET performance and capability complexity.

Core entities (doc §11): `Device`, `Flow`, `Alert`, `Incident`, `Baseline`, `Suppression`. Every anomaly alert must carry its score *and* its evidence (explainability, FR-15); every suppression must leave an audit trail (FR-23).

## Planned repository layout (doc §16)

```
doc/            01_project_definition.md, 02_architecture.md (before M1), 03_detection_catalog.md, adr/
config/         netmon.example.yaml, suricata/ overlays + custom rules
scripts/        install.sh, replay_pcap.sh
netmon/         Python package: ingest/ discovery/ enrich/ detect/ correlate/ notify/ report/ api/ storage/
web/            dashboard frontend
systemd/        unit files
tests/          pytest suites; tests/pcaps/ for public sample captures
```

When creating these, follow this layout rather than inventing a new one. Architecture decisions that deviate from the definition doc go in `doc/adr/`.

## Milestones

M0 definition (now) → M1 sensor up (Suricata + EVE→SQLite ingest + systemd) → M2 asset discovery → M3 dashboard v1 + Telegram → M4 enrichment & correlation → M5 behavioral detection & suppression → M6 reports & unattended ops → M7 optional Zeek/IPS review. Each has explicit done-criteria in doc §12; check them before declaring a milestone complete.

## Host environment (verified 2026-10-29)

Installed: Python 3.13.5, Node 24 / npm 11, Tailscale 1.104. Interfaces: `eth0` (up, the capture port), `wlan0` (down, out of scope), `tailscale0`.
Not yet installed: `suricata`, `zeek`, `arp-scan`, `nmap`, `tcpreplay` — M1 install scripts must add them via apt.

## Open questions (doc §15)

Managed switch model, alert-channel priority beyond Telegram, final retention/disk numbers, whether Zeek is in phase 1, SvelteKit vs React, and how household/office members are notified of monitoring. Don't silently resolve these in code; raise them or record a decision in `doc/adr/`.

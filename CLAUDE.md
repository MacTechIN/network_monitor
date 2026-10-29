# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

`network_monitor` is a home / small-office **network security sensor** running on a Raspberry Pi 5 (aarch64, Debian 13 trixie, kernel 6.18, NVMe boot). It passively captures LAN traffic on `eth0`, detects known threats (signatures) and unknown threats (per-device behavioral baselines), and explains findings in human-readable reports and alerts.

**As of 2026-10-29 the project is in the definition stage (M0). There is no code, no build, no tests.** The only artifacts are `README.md` and `doc/01_project_definition.md`. The definition doc (v0.2) is the source of truth for scope, requirements (FR-1…FR-34), architecture, stack, data model, milestones and open questions. Read it before proposing or writing anything. `doc/tech_research.md` is the technology library: every candidate tool, model, dataset, MCP server and reference, with adopt/defer/reject verdicts, license risks, and facts verified on this Pi (apt/pip availability). Check it before adding a dependency, and add a row (8 columns, no guessed values) when you evaluate a new one. Its section 6.2 lists pending amendments to the definition doc. Project documentation is written in Korean; keep new docs in Korean unless asked otherwise.

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

The Pi's `eth0` sits on an ordinary switch port, so promiscuous mode alone sees only broadcast/multicast and the Pi's own traffic. The ISP router (192.168.45.1, Boa web UI) offers no port mirroring and there is no second NIC, so **ADR-0001 (2026-10-30) adopts option F, "Pi gateway mode"**: the router's DHCP (or, if it can't set the gateway option, the Pi's own `dnsmasq` after the router's DHCP is switched off) hands clients the Pi (192.168.45.162, static) as default gateway and DNS; the Pi forwards with `nftables` masquerade back to the router and ICMP redirects disabled. Clients route through the Pi *explicitly* — this is not ARP spoofing. Files live in `config/gateway/` and `scripts/gateway/` (setup / enable-dhcp / verify / rollback). The nft table contains only forward-accept and masquerade rules; it must never gain drop rules (IDS-only constraint).

Consequences to keep in mind: the Pi is now a single point of failure for internet access (1 h leases + `99_rollback.sh` are the mitigation), throughput through one NIC tops out around 450–500 Mbps, router port-forwarding/UPnP into the LAN breaks, and LAN↔LAN traffic is still invisible. Capture filters should use `net 192.168.45.0/24 and not host 192.168.45.162` to see the client-side leg with real client IPs once. A SPAN/mirror port (option A) on a managed switch remains the preferred upgrade for internal-traffic visibility; inline bridge (B) stays deferred.

## Intended architecture

Four layers in one Python process tree plus external engines (doc §9):

1. **Capture / engines** – Suricata 7 (apt, ET Open rules, EVE JSON output) is the signature engine; Zeek is optional/phase 2. A Python passive discoverer watches ARP/DHCP/mDNS/SSDP/LLDP; opt-in active scanning uses `arp-scan`/`nmap`.
2. **Processing (Python)** – ingest EVE/Zeek logs → normalize → enrich (GeoIP/ASN/threat-intel/OUI) → **time-series aggregation (1 m / 5 m / 1 h buckets per device/destination/protocol)** → baseline learning & anomaly detection → correlate alerts into incidents → score severity (5 levels) → generate a 5-part narrative (what / which device / to where / why risky / what to do).
   A separate **batch learning pipeline** (doc §6.8, FR-28…FR-34) runs off the stored time series: feature extraction → join user/signature labels → periodic retraining (default nightly, nice 19, capped at 30 min / 1.5 GB, paused above 70 °C) → evaluation → promote or reject. Models are versioned with metrics and can be rolled back; a model that scores worse than the active one is never auto-promoted.
3. **Storage** – SQLite for config/devices/alerts/incidents and the model registry; Parquet (partitioned by date and bucket resolution) + DuckDB for flows, time-series rollups and training datasets; versioned model artifact directory; PCAP snippet directory as a size-capped ring buffer. Retention targets: flows 90 d, alerts 1 y, PCAP 30 d, tiered time series (1 m 30 d / 5 m 180 d / 1 h 2 y), datasets + models ≤ 10 GB, 50 GB overall cap.
4. **Presentation** – FastAPI backend, SPA dashboard (SvelteKit vs React undecided, ECharts for charts), daily/weekly Markdown/HTML reports, alert dispatcher (Telegram first, then email, webhook).

**Rationale to preserve:** the project deliberately does *not* build its own detection engine. Differentiation is (1) single-Pi integration and unattended operation, (2) per-device baseline anomaly detection that keeps learning from accumulated time-series data, and (3) plain-language explanatory reports. Keep effort on those three, not on reimplementing Suricata/Zeek.

**Data-flow rule:** the real-time path (capture → detect → alert) and the batch path (aggregate → features → train) meet only at the storage layer. Everything that detects, reports, or learns reads the same time-series store, and batch work must never slow the real-time path. Learning stays CPU-only and small (scikit-learn, river, statsmodels, pandas/polars); no deep-learning frameworks in phase 1. Dataset/model export is manual and off by default, with optional IP/MAC pseudonymization.

Deployment is systemd units + an install script (bash/Ansible). Docker is explicitly excluded for phase 1 because of AF_PACKET performance and capability complexity.

Core entities (doc §11): `Device`, `Flow`, `Alert`, `Incident`, `Baseline`, `Suppression`, plus learning entities `TimeSeriesBucket`, `TrainingSample`, `Model`, `Label`. Every anomaly alert must carry its score *and* its evidence (explainability, FR-15); every suppression must leave an audit trail (FR-23); every training sample must record its feature-schema version and source buckets so it can be reproduced (FR-30), and synthetic/replayed traffic must be flagged as such (FR-31).

## Planned repository layout (doc §16)

```
doc/            01_project_definition.md, tech_research.md, 02_architecture.md (before M1), 03_detection_catalog.md, adr/
config/         netmon.example.yaml, suricata/ overlays + custom rules
scripts/        install.sh, replay_pcap.sh
netmon/         Python package: ingest/ discovery/ enrich/ timeseries/ detect/ learn/ correlate/ notify/ report/ api/ storage/
web/            dashboard frontend
systemd/        unit files (incl. retraining timer)
data/           runtime-generated, git-ignored: parquet/ models/ pcap/
tests/          pytest suites; tests/pcaps/ for public sample captures
```

When creating these, follow this layout rather than inventing a new one. Architecture decisions that deviate from the definition doc go in `doc/adr/`.

## Milestones

M0 definition (now) → M1 sensor up (Suricata + EVE→SQLite ingest + flow→Parquet 1-min buckets + systemd) → M2 asset discovery → M3 dashboard v1 + Telegram → M4 enrichment & correlation → M4.5 time-series rollups, tiered retention, dataset extractor → M5 behavioral detection, suppression, label capture → M6 reports & unattended ops → M6.5 retraining pipeline with model registry → M7 optional Zeek/IPS review. Each has explicit done-criteria in doc §12; check them before declaring a milestone complete.

## Host environment (verified 2026-10-29)

Installed: Python 3.13.5, Node 24 / npm 11, Tailscale 1.104, nftables. Host runs headless (`multi-user.target`, lightdm disabled) since 2026-10-29. Interfaces: `eth0` (up, the capture port), `wlan0` (down, out of scope), `tailscale0`.
Not yet installed: `suricata`, `zeek`, `arp-scan`, `nmap`, `tcpreplay` — M1 install scripts must add them via apt.

## Open questions (doc §15)

Managed switch model, alert-channel priority beyond Telegram, final retention/disk numbers, whether Zeek is in phase 1, SvelteKit vs React, how household/office members are notified of monitoring, the concrete feature schema v1 and bucket sizes, per-device vs per-device-type models, and pseudonymization level for exports. Don't silently resolve these in code; raise them or record a decision in `doc/adr/`.

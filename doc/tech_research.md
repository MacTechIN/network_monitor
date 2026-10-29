# network_monitor 기술 조사 라이브러리 (Tech Research)

| 항목 | 내용 |
|---|---|
| 문서 버전 | 0.1 (초안) |
| 작성일 | 2026-10-30 |
| 기준 문서 | [01_project_definition.md](01_project_definition.md) v0.2 (FR-1~FR-34, M0~M7) |
| 대상 장비 | Raspberry Pi 5 8GB, Debian 13 (trixie) aarch64, Python 3.13.5, Node 24, 커널 6.18 |
| 목적 | 정의서의 요구사항을 구현하는 데 쓸 수 있는 오픈소스 기술·AI 에이전트·MCP 서버·데이터셋·참고 자료를 한곳에 모아 **채택/보류/제외 판정과 근거**를 기록하고, 이후 설계(02_architecture.md)와 ADR의 출처로 삼는다 |
| 조사 범위 | GitHub, Hugging Face(모델·데이터셋), 공식 문서·패키지 저장소(Debian apt, PyPI, OBS), 웹 검색, Naver(한국어 블로그·카페·뉴스) |
| 조사 방법 | 5개 영역을 병렬 조사. 스타 수·라이선스·최근 커밋은 GitHub API 조회값, "apt ✔"·"휠 ✔"·"실측"은 이 Pi에서 `apt-cache policy`, `pip download --only-binary`, `curl`로 직접 확인한 값. 확인하지 못한 항목은 **미확인**으로 남김 |
| 상태 | 조사 완료, 리뷰 포함(6장). 정의서 반영 제안은 6.2절 |

> **주의.** 스타 수와 버전은 2026-10-30 시점 스냅샷이다. 라이선스는 저장소 표기를 옮긴 것이므로 채택 전 원문을 다시 확인한다. 국내 Naver 검색은 서버 렌더링 결과에 블로그 본문이 잘 노출되지 않아 커버리지가 낮다(6.1절).

## 읽는 법

모든 표는 같은 8개 열을 쓴다.

| 열 | 뜻 |
|---|---|
| 이름 | 프로젝트·모델·데이터셋·자료 이름 |
| 링크 | 1차 출처 URL |
| 출처 | GitHub / HF(Hugging Face) / 공식 / Naver / 학술 |
| 라이선스 | 저장소 또는 모델 카드 표기. `미표기`는 LICENSE 파일 없음, `미확인`은 조사에서 확인 못 함 |
| 활동 | ★스타 수, 최근 커밋·릴리스 연월, 또는 다운로드 수 |
| ARM64/Pi5 적합성 | Debian 13 aarch64에서 설치 가능 여부와 자원 부담. `apt ✔`는 공식 저장소 패키지, `휠 ✔`는 PyPI aarch64 cp313 바이너리 |
| 관련 FR/단계 | 정의서의 기능 요구사항 번호와 마일스톤 |
| 한 줄 평가 | 채택·보류·제외 판정과 이유 |

판정 어휘: **채택**(1차 스택), **참고**(코드가 아니라 설계·알고리즘만 차용), **선택**(필요 시 추가), **2차**(M6.5 이후 검토), **비채택/제외**(이유 명시).

---

## 목차

- [0. 한눈에 보는 권장 스택](#0-한눈에-보는-권장-스택)
- [1. 수집·IDS 엔진·룰셋·위협 인텔·테스트 PCAP](#1-수집ids-엔진룰셋위협-인텔테스트-pcap)
- [2. 자산 발견·기기 핑거프린트·보강·상관](#2-자산-발견기기-핑거프린트보강상관)
- [3. 시계열 저장·특징 추출·ML 이상탐지·데이터셋·모델 관리](#3-시계열-저장특징-추출ml-이상탐지데이터셋모델-관리)
- [4. AI 에이전트·LLM·MCP·Claude Code 오케스트레이션](#4-ai-에이전트llmmcpclaude-code-오케스트레이션)
- [5. API·대시보드·알림·리포트·운영·테스트·유사 프로젝트](#5-api대시보드알림리포트운영테스트유사-프로젝트)
- [6. 리뷰](#6-리뷰)
- [7. 라이브러리 유지 규칙](#7-라이브러리-유지-규칙)

---

## 0. 한눈에 보는 권장 스택

정의서 10장의 "제안 스택"을 이번 조사로 검증한 결과다. 변경·추가된 항목은 굵게 표시했다.

| 계층 | 채택 (1차) | 선택·2차 | 제외 (이유) |
|---|---|---|---|
| 수집·엔진 | Suricata 7.0.10 (apt) + suricata-update + ET Open, AF_PACKET v3 workers, tcpdump 링버퍼(FR-3) | Suricata 8.0.7 (trixie-backports, JA4 필요 시), Zeek 9 (OBS 저장소, M7), nfstream (PCAP 특징 추출) | Snort 3 (apt 없음·이점 없음), Arkime (풀 PCAP), AF_XDP/PF_RING (Pi NIC 미지원) |
| 룰·위협 인텔 | ET Open, Feodo Tracker, SSLBL, Spamhaus DROP, **misp-warninglists(오탐 억제)**, **CISA KEV + EPSS(심각도 가중)** | URLhaus·ThreatFox (abuse.ch Auth-Key 발급 후), Snort Community, Sigma Correlation(규칙 포맷만), KISA C-TAS(가입 조건 확인) | ET Pro (유료·재배포 금지), MISP/OpenCTI 플랫폼 (자원 초과) |
| 자산 발견·핑거프린트 | scapy(브로드캐스트 BPF), python-zeroconf, async_upnp_client, pyroute2(netlink), arp-scan·nmap(opt-in), IEEE OUI CSV 3종 + Wireshark manuf | lldpd, p0f(apt), satori 시그니처, kyd DHCP DB, **Pi-hole v6 API(DNS 데이터원)**, Home Assistant 웹훅 | NetAlertX 통째 도입(Docker·능동 스캔 전제), IoT Inspector 코드(ARP 스푸핑), Fingerbank·macvendors API(외부 전송) |
| 보강 | **iptoasn(PDDL) + DB-IP Lite(CC BY)** 로컬 DB, ET 룰 메타데이터(ATT&CK·CVE·severity), mitreattack-python 배치 변환 | MaxMind GeoLite2 (사용자 키 + geoipupdate, EULA 준수 시), NVD on-demand(캐시), AbuseIPDB 공식 MCP(운영자 수동 조회) | IPinfo Lite (CC BY-SA 전파), VirusTotal/Shodan 자동 조회(내부 관측값 외부 전송) |
| 시계열·저장 | SQLite(WAL) + **DuckDB 2.x + pyarrow Parquet(hive 파티션 `res=/date=`) + polars** | DuckLake(스냅샷 관리), Grafana DuckDB 데이터소스(운영자 탐색) | QuestDB(JVM), TimescaleDB(PG), ClickHouse(32GB), InfluxDB 3(별도 데몬), VictoriaMetrics(흐름 카디널리티 부적합) |
| 행위 탐지·학습 | scikit-learn(IsolationForest·RobustScaler), river(증분 기준선), statsmodels MSTL, ruptures PELT, STUMPY(비컨 주기성), 자체 DGA n-gram 분류기(harpomaxx 데이터) | PyOD(ECOD/COPOD 앙상블), KitNET(집계 단위), statsforecast, Chronos-Bolt tiny ONNX(2차 실험), tslearn(기기 유형 군집) | RITA v5(ClickHouse), Slips 통째(GPL·4GB), dgad·Orion·NeuralProphet·Kats(3.13 불가), TimesFM(메모리), Merlion/Darts/sktime(과함) |
| 모델 관리·스케줄 | skops(내부 저장·가져오기 포맷), ONNX Runtime + skl2onnx, SQLite 모델 레지스트리, APScheduler 3.11(인프로세스), **systemd timer + cgroup 상한(재학습)** | modelstore | MLflow(과함), joblib/pickle 외부 파일 가져오기(신뢰 경계) |
| API·대시보드 | FastAPI + Pydantic v2 + pydantic-settings, SQLAlchemy 2 + Alembic, aiosqlite, uvicorn 단일 워커, **SvelteKit adapter-static**(1순위) 또는 React+Vite, **ECharts(트리셰이킹) + uPlot** | **EveBox(M1부터 원시 알림 뷰어)**, Grafana OSS(운영자 패널), htmx+Jinja2(리포트 화면) | Scirius/SELKS/Clear NDR·Security Onion·Malcolm·Kibana/OpenSearch(x86 또는 메모리), ntopng(중복 수집), NiceGUI(커스텀 UI 한계) |
| 알림·리포트 | **Apprise(채널 통합)** + 자체 dedup/조용한 시간, Telegram은 httpx Bot API 직접 호출 또는 aiogram(MIT), Jinja2 + Python-Markdown | ntfy 셀프호스트, Home Assistant 웹훅, WeasyPrint(PDF) | python-telegram-bot(GPL-3.0·apt 없음, 라이선스 정책에 따라), telegram-mcp(계정 전권) |
| LLM·에이전트 | **llama.cpp(llama-server, GBNF) + 1.3~2B 한국어 모델(Kanana-2 1.3B → Midm 2.0 Mini → Kanana 1.5 2.1B → HyperCLOVA X SEED 1.5B → Qwen3 1.7B)**, pydantic-ai(또는 instructor), outlines(제약 디코딩), Pydantic validator 기반 자체 가드레일 | Claude API(Haiku 5.5) opt-in + 가명화, Ollama(개발 실험), Claude Agent SDK(개발 PC 자동화), CySecBERT(분류) | EXAONE(NC), Qwen2.5-3B(연구 라이선스), 7~8B 보안 특화 모델(Pi 2 tok/s 이하), LangGraph/CrewAI/AutoGen/smolagents(과함), Prefect/Dagster/Temporal(서버 필요) |
| MCP (개발 PC 전용) | mcp-server-motherduck(읽기 전용), mcp-sqlite(읽기 전용), lidless-labs/suricata-mcp(변경 게이트), filesystem(레포 경로 한정), github 공식 | ha-mcp(HA 가정), AbuseIPDB 공식 MCP(수동 조사), SharkMCP(PCAP 파일 분석만) | 센서(Pi)에 MCP 상주 금지. nmap-mcp·mcp-for-security·pentest-mcp(스캔 권한 위임), Zeek-MCP(쉘 실행), telegram-mcp, VirusTotal/Shodan/OTX 자동 질의 |
| 운영·보안 | systemd 257 유닛(`User=netmon`, `AmbientCapabilities=CAP_NET_RAW [CAP_NET_ADMIN]`, `ProtectSystem=strict`, `systemd-analyze security`), tcpdump `-C/-W` 링버퍼, hwmon 온도 폴링(CPU·NVMe), unattended-upgrades, restic + sqlite backup API, **Tailscale Serve(identity header)** | Litestream, caddy-tailscale, ansible-role-security | Tailscale Funnel(외부 노출 금지), Authelia(과잉), setcap 바이너리(Arch wiki 비권고) |
| 테스트·CI | pytest + pytest-asyncio, Hypothesis(롤업 불변식), `suricata -r` 오프라인 회귀(suricata-verify 패턴), tcpreplay(Pi 수동 통합), ruff + mypy + pre-commit, **GitHub Actions `ubuntu-24.04-arm`** | Dalton(룰 검증, 개발 PC) | — |
| 테스트·학습 데이터 | IoT-23(Zeek conn 라벨, HF Parquet 미러), CTU-13(C2·비컨, CC-BY), Kitsune·N-BaIoT(UCI CC BY 4.0), CIC-IDS2017 CSV, malware-traffic-analysis.net(다운로드 스크립트), harpomaxx/dga-detection(CC BY 2.0), UNSW IoT Traces 2018(MIT-0) | UNSW-IoTraffic 2025(장기 기준선), CIC-IoT-2023, netrack/learn(DNS 유출 합성), KISA AI 데이터셋(신청제) | Mon(IoT)r(재배포 금지 계약), snsec DGA(NC), MAWILab(백본, 종료), UNSW-NB15·ToN_IoT 상업 조건 상충 |

**정의서 10장과 달라진 점 요약**

1. 알림 채널 라이브러리를 python-telegram-bot 단일에서 Apprise 통합 + Telegram 직접 호출로 바꿀 것을 제안 (GPL·apt 부재·다채널 요구).
2. GeoIP 1순위를 MaxMind GeoLite2에서 iptoasn + DB-IP Lite로 바꿀 것을 제안 (EULA의 30일 폐기·재배포 제한·향후 유료화 조항). GeoLite2는 사용자 키 opt-in으로 강등.
3. "패킷 처리 Python + scapy/dpkt"는 유지하되 흐름 특징 추출에 nfstream(cp313 aarch64 휠 확인)을 추가.
4. 시계열·학습 스택(DuckDB·polars·sklearn·river·statsmodels·ruptures·STUMPY·skops·ONNX Runtime)이 모두 aarch64 cp313 휠로 설치됨을 확인. 별도 TSDB 데몬 불필요.
5. LLM 계층이 정의서에 없었다. 로컬 우선(llama.cpp + 한국어 소형 모델), 클라우드 opt-in + 가명화, 서술 전용·탐지 비개입 원칙을 정의서에 추가할 것을 제안 (6.2절).
6. MCP는 센서가 아니라 개발 PC의 Claude Code에만 붙이는 것으로 경계를 명시.
7. FR-3 "알림 전후 N초 PCAP"은 Suricata 단독으로 불가능하므로 tcpdump 링버퍼 + 절단 2단계로 설계 변경 필요.
8. 기기 신원을 MAC 단일 키로 둘 수 없음(랜덤 MAC). 데이터 모델 변경 필요.

---


## 1. 수집·IDS 엔진·룰셋·위협 인텔·테스트 PCAP

정의서 6.1(수집), 6.3(시그니처 탐지), 10장(엔진·테스트), 13장(성능 리스크)에 대응한다.

### 수집 / 엔진

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| Suricata | https://github.com/OISF/suricata | GitHub/공식 | GPL-2.0 | ★6.8k, 2026-10 | trixie apt `1:7.0.10-1+deb13u4` arm64, trixie-backports `8.0.7-1~bpo13+1` arm64 확인 | FR-1~4, 9, 12 / M1 | 핵심 엔진. apt만으로 설치되며 AF_PACKET v3 workers 모드가 Pi 기본값으로 적합 |
| suricata-update | https://github.com/OISF/suricata-update | GitHub/공식 | GPL-2.0 | ★297, 2026-07 | trixie `1.3.4-1+deb13u1` | FR-10 / M1 | ET Open·oisf/trafficid 소스 관리, systemd timer로 매일 갱신하면 끝 |
| Zeek (+zkg, Spicy) | https://github.com/zeek/zeek | GitHub/공식 | BSD-3 | ★8.1k, 2026-10 | Debian 공식 저장소에서 제거됨(apt 불가). OBS `security:zeek/Debian_13/arm64`에 zeek 9.0.1 / 8.0.11 / 7.0.1 .deb 확인 | FR-13, 14, 28 / M7 | conn/dns/ssl 로그 품질 최고. OBS 저장소 추가로 설치 가능하나 Pi 메모리 실측 후 2단계 도입 |
| Snort 3 | https://github.com/snort3/snort3 | GitHub | GPL-2.0 | ★3.5k, 2026-10 | Debian trixie 미포함(snort 2.9.7이 buster에서 끝). aarch64 소스 빌드 필요 | 대안 엔진 | Suricata 대비 Pi 이점 없음. 비채택 |
| nDPI | https://github.com/ntop/nDPI | GitHub | LGPL-3.0 | ★4.7k, 2026-10 | trixie libndpi 4.2(구버전). ntop 저장소 `RaspberryPI/trixie_pi/arm64` 존재 | FR-7, 14 (앱 프로토콜 식별) | Suricata app-layer가 못 잡는 IoT/게임/채굴 프로토콜 식별 보조. nfstream 경유가 편함 |
| ntopng | https://github.com/ntop/ntopng | GitHub | GPL-3.0 | ★8.3k, 2026-10 | packages.ntop.org에 Pi용 trixie_pi arm64 저장소 | 대시보드 대안 | 기능 중복·무거움. 자체 대시보드 설계 참고용 |
| Arkime | https://github.com/arkime/arkime | GitHub | Apache-2.0 | ★7.6k, v6.9.1 2026-10 | `arkime_6.9.1-1.debian13_arm64.deb`, `ja4plus.arm64.so` 공식 제공 | 범위 밖 | 풀 PCAP + OpenSearch 전제 → FR-2(페이로드 미저장)와 충돌. 비채택 |
| nfdump | https://github.com/phaag/nfdump | GitHub | BSD-3 | ★925, 2026-10 | trixie `1.7.5-2+deb13u1` arm64 | FR-28 보조 | 공유기가 NetFlow/IPFIX를 내보내는 환경(C안)에서만 유용 |
| nfstream | https://github.com/nfstream/nfstream | GitHub/PyPI | LGPL-3.0 | ★1.2k, 2026-09 | PyPI 6.6.0 cp313 manylinux aarch64 휠 있음(이 Pi에서 실측, 6.1절) | FR-28, 30 특징 추출 | nDPI 내장 Python 흐름 추출기. 라이브 1Gbps는 무리, PCAP 오프라인 특징 추출·보조용 |
| tcpreplay | https://github.com/appneta/tcpreplay | GitHub | GPL-3.0 | ★1.4k, 2026-10 | trixie 4.5.1 arm64 | 테스트 / M1 | `replay_pcap.sh`의 표준 도구. `--mbps`로 Pi 부하 테스트 |
| AF_XDP / xdp-tools | https://github.com/xdp-project/xdp-tools | GitHub | GPL-2/LGPL-2.1/BSD-2 혼합 | ★909, 2026-10 | 로컬 확인: eth0 드라이버 `macb`(RP1), RX ring 최대 8192. macb 네이티브 XDP 패치는 2025-08~11 netdev 제출, Pi 6.18 커널 포함 여부 미확인 | FR-1 대안 | Suricata af-xdp는 7.0부터 지원하나 Pi에선 XDP_SKB 모드로 떨어질 가능성 큼. 1차는 AF_PACKET 유지 |
| PF_RING | https://github.com/ntop/PF_RING | GitHub | LGPL-2.1 | ★3.0k, 2026-10 | ZC 드라이버 Pi NIC 미지원. 바닐라 모드는 AF_PACKET 대비 이점 없음 | FR-1 대안 | Pi에서는 비채택 |
| bcc (eBPF) | https://github.com/iovisor/bcc | GitHub | Apache-2.0 | ★22.7k, 2026-10 | Debian `bpfcc-tools` arm64 | FR-4, 26 자가진단 | 드롭·소켓 통계 진단용 보조 도구. 선택 |
| EveBox | https://github.com/jasonish/evebox | GitHub | MIT | ★507, 2026-10 | 단일 바이너리, arm64 릴리스 제공 | M1 검증 | EVE JSON 확인용 경량 UI. 개발 중 디버깅에 유용, 최종 대시보드는 자체 구현 |
| Slips (Stratosphere) | https://github.com/stratosphereips/StratosphereLinuxIPS | GitHub | GPL-2.0 | ★897, 2026-10 | Python+Redis, ARM 동작 미확인 | FR-13, 14 설계 참고 | 흐름 기반 행위 탐지 모듈(비컨, 포트스캔, DGA) 구조가 M5 설계에 직접 참고됨 |
| Dalton | https://github.com/secureworks/dalton | GitHub | Apache-2.0 | ★524, 2026-10 | Docker x86 중심 | FR-12 룰 테스트 | 사용자 정의 룰을 PCAP에 대고 검증하는 웹 도구. 개발 PC에서 사용 |

### 룰셋

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| ET Open | https://rules.emergingthreats.net/open/suricata-7.0.3/ | 공식 | BSD (동봉 BSD-License.txt) | 2026-10-28 갱신, emerging.rules.tar.gz 5.6MB | 아키텍처 무관 | FR-9, 10 / M1 | 1차 룰셋. `suricata-8.0.0/` 경로도 200 응답 확인. 전체 활성화 시 Pi 드롭 위험 → 카테고리 선별 필수 |
| ET Pro | https://www.proofpoint.com/us/products/et-intelligence | 공식 | 상용, 센서당 연간 구독 | 2025~26 가격 미확인(2016년 $750/yr 기록) | 무관 | FR-9 선택 | 가정용엔 과함. OPNsense 텔레메트리 에디션은 데이터 역전송 조건. 비채택 |
| Snort 3 Community / Registered | https://www.snort.org/downloads/community/snort3-community-rules.tar.gz | 공식 | Community GPLv2(Oinkcode 불필요, 332KB) / Registered 무료 계정·30일 지연·재배포 제한 | 매일 갱신 | 무관 | FR-12 보조 | Snort 문법 일부만 Suricata 호환. ET Open과 중복 커 낮은 우선순위 |
| Sigma + sigma-cli | https://github.com/SigmaHQ/sigma , https://github.com/SigmaHQ/sigma-cli | GitHub | 룰 DRL 1.1 / cli LGPL-2.1 | ★11.4k / ★220, 2026-10 | Python | FR-14 보조 | 네트워크(Zeek) 카테고리 룰이 소수. EVE/Zeek 로그에 적용하려면 백엔드 자체 작성 필요. 선택 |
| MISP warninglists | https://github.com/MISP/misp-warninglists | GitHub | CC0 | ★658, 2026-10 | JSON | FR-23 / M4 | CDN·구글·MS·공용 DNS 등 "알려진 정상" 목록. TI 매칭 오탐 억제에 바로 사용 권장 |

### 위협 인텔

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| abuse.ch URLhaus | https://urlhaus.abuse.ch/ | 공식 | CC0 | 2025-06-30부터 Auth-Key 필수. `downloads/csv_recent/` 무키 접근 410 확인 | 무관 | FR-11 / M4 | 악성 URL·호스트. auth.abuse.ch 무료 가입 후 키 발급 필요 |
| abuse.ch Feodo Tracker | https://feodotracker.abuse.ch/downloads/ipblocklist.json | 공식 | CC0 | `ipblocklist.json` 무키 200 확인(2026-10) | 무관 | FR-11 | 봇넷 C2 IP. 가장 가볍고 즉시 통합 가능 |
| abuse.ch SSLBL | https://sslbl.abuse.ch/blacklist/ | 공식 | CC0 | JA3 fingerprint CSV 200 확인 | 무관 | FR-11, 14 | 악성 JA3·SSL 인증서 SHA1. 암호화 트래픽 메타데이터 매칭의 1차 소스 |
| abuse.ch ThreatFox | https://threatfox.abuse.ch/ | 공식 | CC0 | `export/json/recent/` 무키 410 → Auth-Key 필요 | 무관 | FR-11 | IOC(IP:port, 도메인, 해시) 통합 피드. 키 발급 후 사용 |
| Spamhaus DROP | https://www.spamhaus.org/drop/drop_v4.json | 공식 | 무료, 저작권·출처표기 유지, 시간당 1회 이하 조회 | drop_v4.json 200 확인 | 무관 | FR-11 | 하이재킹 넷블록. 적중률 낮지만 오탐 거의 없음 |
| MISP (+misp-galaxy) | https://github.com/MISP/MISP | GitHub | AGPL-3.0 / galaxy CC0 | ★6.6k, 2026-10 | PHP+MySQL+Redis, Pi엔 과중 | FR-17 참고 | 플랫폼은 비채택. galaxy의 위협행위자·악성코드 명칭 JSON만 설명문 보강에 활용 |
| OpenCTI | https://github.com/OpenCTI-Platform/opencti | GitHub | Apache-2.0 (CE) | ★10.2k, 2026-10 | Elasticsearch·RabbitMQ 필요 | 범위 밖 | Pi 자원으로 불가. 비채택 |
| KISA C-TAS 2.0 | https://www.boho.or.kr/ (사이버위협 분석·공유시스템) | 공식/Naver | 가입제(2021 개편 후 일반회원은 정보 제공 없이 가입 가능) | 2026-08 맞춤형 알림 시범운영 보도 | 무관 | FR-11 선택 | 국내 C2·유포지 정보. 개인/비기업 가입 가능 여부·API 제공 조건 미확인 |
| GeoIP: MaxMind GeoLite2 vs DB-IP Lite vs IPinfo Lite | https://www.maxmind.com/en/geolite2/eula , https://db-ip.com/db/lite.php | 공식 | GeoLite2 계정·EULA·키 필수, 재배포 제한 / DB-IP Lite CC BY 4.0(ASN 무료 DB 없음) / IPinfo Lite CC BY-SA | 월 갱신 | mmdb 리더 arm64 OK | FR-17 | 설치 스크립트에 키 주입 로직 필요. 대안으로 DB-IP(국가)+IPinfo Lite(ASN) 조합 검토 |

### 핑거프린트

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| JA4+ (FoxIO) | https://github.com/FoxIO-LLC/ja4 | GitHub | JA4(TLS 클라이언트)만 BSD-3, JA4S/H/L/X/SSH/T 등은 FoxIO License 1.1(내부·비상업 사용 허용, 수익화 시 OEM 라이선스), 특허 출원 중 | ★2.2k, 2026-10 | Suricata `ja4.hash` 키워드(7.0.x 빌드 옵션 의존, Debian 패키지 활성 여부 미확인; 8.x 권장), Zeek 패키지 제공 | FR-14, 28 | 가정용 비상업 IDS는 허용 범위로 보이나 프로젝트 공개 시 JA4(BSD) 중심으로 한정하는 것이 안전 |
| ja4db | https://ja4db.foxio.io/ | 공식 | 데이터 라이선스 미확인 | `/api/download/` 2026-10 현재 404 | 무관 | FR-14 | 공식 DB이나 다운로드 경로 불안정. 의존 금지, 가능하면 스냅샷 보관 |
| JA3 (salesforce) / ja3er | https://github.com/salesforce/ja3 | GitHub | BSD-3 | ★3.1k, 2025-05 아카이브 | Suricata/Zeek 내장 | FR-14 | JA3 자체는 계속 쓰되 ja3er.com은 서비스 중단·신뢰 불가. 매칭 소스는 SSLBL만 사용 |
| Community ID | https://github.com/corelight/community-id-spec | GitHub | BSD-3 | ★198, 2024-09 | Suricata·Zeek 모두 내장 | FR-16 / M4 | Suricata 알림 ↔ Zeek conn.log를 같은 흐름으로 묶는 키. 필수 활성화 |

### 테스트 데이터 · PCAP

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| malware-traffic-analysis.net | https://www.malware-traffic-analysis.net/ | 공식 | 명시 라이선스 없음(연구자 공유, 자기 책임) | 2013~2026 지속 게시 | 무관 | 테스트 / M1 | 실제 C2·피싱·로더 PCAP. zip 암호 규칙은 about 페이지 참조. 레포에 재배포하지 말고 다운로드 스크립트로 |
| CTU-13 (Stratosphere) | https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/ | 공식 | CC-BY | 전체 tar.bz2 약 1.9GB | 무관 | FR-31 synthetic 라벨, M5 | 봇넷 13 시나리오, 정상 트래픽 포함. zip 암호 `infected`. 비컨 탐지 회귀 테스트에 최적 |
| CIC-IDS2017 | https://www.unb.ca/cic/datasets/ids-2017.html | 공식 | 연구용 공개, 논문 인용 요구, 재배포 조건 미기재 | PCAP 합계 약 51GB | 무관 | FR-33 평가 | 스캔·브루트포스·DoS 라벨 PCAP. 용량 커서 일부 요일만 사용 |
| Zeek 테스트 트레이스 | https://github.com/zeek/zeek/tree/master/testing/btest/Traces | GitHub | BSD-3 | 193개 파일, 2026-10 | 무관 | 테스트 | 프로토콜별 소형 PCAP. 파서 단위 테스트용 |
| HF: IDS 흐름 데이터셋 | https://huggingface.co/datasets/bvsam/cic-ids-2017 , https://huggingface.co/datasets/Lystea/IOT23-PARQUET , https://huggingface.co/datasets/Mouwiya/UNSW-NB15 | HF | bvsam 미표기(9.9k DL) / IOT23-PARQUET CC-BY-4.0(961 DL, 2026-08) / UNSW 미표기(2.7k DL) | 2024~2026 | 무관 | FR-30, 33 | IoT-23 Parquet은 Zeek conn.log 기반이라 FR-28 집계 스키마 검증에 직접 활용 가능. 라이선스 미표기 항목은 원 출처 조건 적용 |
| HF: Suricata EVE 로그 샘플 | https://huggingface.co/datasets/yasirchemmakh/Cicids2017_Suricata_Logs , https://huggingface.co/datasets/mldiakhame/suricata-alerts-ctu-13 | HF | 미표기 | 44 DL / 15 DL, 2024 | 무관 | M1 수집기 테스트 | CICIDS/CTU-13을 Suricata로 돌린 EVE 출력. 수집기 파서 fixture로 유용. IDS 전용 HF 모델(예: gates04/DistilBERT-Network-Intrusion-Detection, 18 DL)은 실용성 낮음 |

### 올인원 배포판 · 허니팟

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| Security Onion | https://github.com/Security-Onion-Solutions/securityonion | GitHub/공식 | Elastic License 2.0 | ★5.0k, 2026-10 | 공식 문서: x86-64 전용 | 비채택 | Pi 불가. 알림→사건 묶기 UX만 참고 |
| Malcolm / Hedgehog Linux | https://github.com/cisagov/Malcolm | GitHub | Apache-2.0 | ★2.6k, 2026-10 | Hedgehog 센서는 Pi 4B 8GB 이상 지원 문서 있음. 파일 추출·풀 PCAP 끄기 권고 | 설계 참고 | Suricata+Zeek+Arkime를 Pi에서 돌린 공식 선례. 설정값(튜닝 권고)만 차용 |
| Wazuh | https://github.com/wazuh/wazuh | GitHub | GPL-2.0(예외 조항) | ★17.5k, 2026-10 | aarch64 매니저·에이전트 패키지 제공 | 범위 밖 | Suricata EVE 수집 디코더 있으나 HIDS 중심에 인덱서 무거움. 비채택 |
| T-Pot | https://github.com/telekom-security/tpotce | GitHub | GPL-3.0 | ★9.7k, 2026-10 | 24.04부터 Raspberry Pi 지원(Bookworm 기준) | 범위 밖 | 외부 노출 허니팟. 프로젝트 원칙(외부 노출 금지)과 충돌 |
| OpenCanary (+Cowrie) | https://github.com/thinkst/opencanary | GitHub | BSD-3 | ★3.1k, 2026-10 (Cowrie ★6.6k) | 순수 Python, Pi 공식 언급 | FR-14 내부 스캔·lateral movement 보조 | LAN 내부에만 띄우는 가짜 SMB/SSH/HTTP. 감염 기기의 내부 탐색을 거의 오탐 없이 잡는 저비용 센서. 2단계 추천 |
| RaPI-IDS / hookprobe | https://github.com/arturpzol/RaPI-IDS , https://github.com/hookprobe/hookprobe | GitHub | GPL-3.0 / 미확인 | ★2, 2026-10 / ★48, 2026-10 | Pi 5 전용 Suricata 8 + ET Open 이미지 | 참고 | 소규모지만 Pi 5 실동작 사례. hookprobe 블로그의 "Pi5 8GB 기가비트 처리" 주장은 근거 없고 같은 사이트 다른 글은 150Mbps 한계 보고 |

### 한국어 자료

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| IDS/IPS 구축: Snort vs Suricata vs OPNsense 비교 | https://blog.naver.com/japkey/224234748029 | Naver | - | 2026-03 | - | M0 선택 근거 | 국내 블로그 중 가장 최신 엔진 비교 글 |
| 침입 탐지(IDS) 시스템 구축 및 운영 | https://blog.naver.com/kklamd7/223920578254 | Naver | - | 2025-07 | - | M1 | Suricata 설치·룰 운영 입문 |
| Suricata + Wazuh를 같이 사용해보자 | https://velog.io/@jee-9/ (슬러그 "Suricata-Wazuh를-같이-사용해보자") | Naver/velog | - | 2026-03 | - | 참고 | EVE JSON을 외부 SIEM에 넘기는 국내 사례 |
| Rookies 보안관제 Security Onion 실습 | https://velog.io/@chltnals8520/ | Naver/velog | - | 2026-02 | x86 | 참고 | SK쉴더스 교육 과정 기록. 국내 교육이 Security Onion 중심임을 보여줌 |
| Suricata-Snort-SOC-Lab / mini-soc | https://github.com/sureasdufo1-hue/Suricata-Snort-SOC-Lab , https://github.com/park476/mini-soc | GitHub(한국어) | 미표기 | ★1, 2026-09 / ★0, 2026-10 | - | 참고 | 국내 Suricata 활용 레포는 교육 프로젝트 수준. 재사용 코드보다 한국어 설명문 어휘 참고 |
| Lightweighting_MLP (IoT 경량 침입탐지) | https://github.com/kimchiman123/Lightweighting_MLP | GitHub(한국어) | 미표기 | ★0, 2026-03 | - | FR-32 참고 | 저사양 기기용 경량 모델 실험. 학습 파이프라인 설계 참고 |

### 조사자 메모

- **Debian trixie 패키지 확정값(로컬 apt 확인):** suricata `1:7.0.10-1+deb13u4`, suricata-update `1.3.4`, tcpreplay `4.5.1`, nfdump `1.7.5`. Suricata 8.0.7은 trixie-backports arm64에 있으므로 JA4·성능 개선이 필요하면 backports 핀 고정으로 올릴 수 있다. zeek·ntopng·snort는 apt 후보 없음.
- **Zeek 설치 경로:** Debian에서 제거됐으나 OBS `security:zeek` 저장소가 Debian_13 arm64용 zeek 9.0.1(LTS 포함)·8.0.11·7.0.1 .deb를 제공한다. Malcolm 문서는 Pi 4B 8GB에서 Zeek 실행 시 파일 추출·대량 intel 로드·풀 PCAP을 끄라고 권고.
- **Pi 5 성능 수치는 신뢰할 만한 공개 벤치가 없다.** 유일한 구체 수치는 hookprobe의 "Pi 5 4GB, 균형 룰셋에서 약 150Mbps까지 양호, Lua 룰 켜면 CPU 90%·드롭 12%"이며 방법론 미공개. G1(1Gbps 5% 드롭)은 ET Open 전체 활성화로는 달성 불가능할 가능성이 높으므로 룰 카테고리 선별 + BPF 제외 필터 + 흐름 바이패스를 M1 설계에 포함해야 한다.
- **캡처 방식 결론:** 로컬 eth0은 `macb`(RP1) 드라이버, RX ring 최대 8192. 네이티브 XDP 패치는 2025년 하반기 netdev 제출 단계라 AF_XDP는 SKB 모드 폴백 가능성이 크고, PF_RING ZC는 Pi NIC 미지원. AF_PACKET tpacket-v3 + workers 모드 + `ethtool -K eth0 gro off lro off tso off gso off` + `ethtool -G eth0 rx 8192`가 1차 기준.
- **abuse.ch 피드는 2025-06-30부터 Auth-Key 필수.** 2026-10 실측: URLhaus csv_recent 410, ThreatFox export 410, Feodo ipblocklist.json 200, SSLBL JA3 CSV 200. FR-11 구현 시 무료 키 발급을 설치 스크립트 전제조건으로 두고, 키 없는 Feodo/SSLBL/Spamhaus만으로 동작하는 폴백을 만들 것.
- **라이선스 주의 3건:** (1) JA4+ 중 BSD-3는 TLS 클라이언트 JA4뿐이고 JA4S/H/X/SSH는 FoxIO 1.1(비상업 OK, 수익화 불가, 특허 출원). (2) MaxMind GeoLite2는 계정·EULA·키 필수에 재배포 제한 → DB-IP Lite(CC BY) + IPinfo Lite(CC BY-SA)가 대안. (3) ET Pro·Snort Registered는 재배포 금지라 레포에 포함 불가. ET Open·Feodo·SSLBL·CTU-13(CC-BY)·misp-warninglists(CC0)는 문제 없음.
- **ET Open 경로:** 현재 `open/suricata-7.0.3/`이 7.x용 최신 디렉터리이며 `suricata-8.0.0/` 경로도 200 응답. BSD-License.txt와 `SID-Descriptions-ETOpen.json.gz`(룰별 설명)가 동봉되어 FR-20 "쉬운 설명" 생성에 바로 쓸 수 있다.
- **피해야 할 것:** Security Onion(x86 전용), Arkime·Malcolm 풀스택(풀 PCAP·OpenSearch), MISP/OpenCTI(Pi 자원 초과), ja3er(서비스 중단), ja4db API(현재 404). (초안에 적혔던 "nfstream 3.13 휠 부재"는 실측 결과 오류로 확인되어 삭제, 6.1절.)
- **추가 가치가 큰 소형 구성요소:** misp-warninglists(오탐 억제), Community ID(Suricata↔Zeek 상관 키), OpenCanary(내부 lateral movement 저비용 탐지), IoT-23 Parquet(Zeek conn.log 기반, FR-28 스키마 검증용 학습 데이터).
- **한국어 자료 현황:** Naver에서 "Suricata 라즈베리파이"를 직접 다룬 한국어 글은 없고(Pi-hole, IP카메라 글만 걸림), IDS 글은 대부분 2025~2026 보안관제 교육 기록 수준. KISA C-TAS는 가입제라 개인 프로젝트 적용 조건은 미확인. 국내 참고보다 Suricata 공식 문서·Malcolm Pi 가이드가 실질적 기준이 된다.

---

## 2. 자산 발견·기기 핑거프린트·보강·상관

정의서 6.2(자산 발견), 6.5(상관·보강), 11장(Device 모델)에 대응한다.

> 활동 열의 ★와 연월은 GitHub API 실측값. ARM64 열의 "apt ✔ x.y"와 "pip 휠 ✔"는 이 Pi 5(Debian 13, aarch64, Python 3.13.5)에서 `apt-cache policy` / `pip download --only-binary`로 직접 확인한 값. 확인 못 한 항목은 미확인.

### 수동 발견 (Passive discovery)

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| NetAlertX (구 Pi.Alert) | https://github.com/jokob-sk/NetAlertX | GitHub | GPL-3.0 | ★7,341 / 2026-10 | Docker(host net) 필수, Pi 5 설치 가이드 다수 | FR-5~8, M2 | 기기 발견·새 기기 알림의 사실상 표준 셀프호스트 도구. arp-scan 기반 능동 스캔이 핵심이라 "수동 OFF 기본값"과 맞지 않음. 플러그인 구조(DHCP 리스·Pi-hole·SNMP 가져오기)와 기기 스키마는 참고 가치 높음 |
| Pi.Alert (leiweibau 포크) | https://github.com/leiweibau/Pi.Alert | GitHub | GPL-3.0 | ★1,216 / 2026-10 | bare-metal 설치 지향, Pi 대상 | FR-5~8 | 원본보다 가벼운 유지 포크. 웹 서비스 가용성 체크 포함 |
| Pi.Alert (pucherot 원본) | https://github.com/pucherot/Pi.Alert | GitHub | GPL-3.0 | ★2,775 / 2024-02 | - | - | 사실상 중단. 포크 두 개로 이전됨 |
| WatchYourLAN | https://github.com/aceberg/WatchYourLAN | GitHub | MIT | ★7,653 / 2025-09 | Go 단일 바이너리·Docker, arm64 빌드 미확인 | FR-5~8 | arp-scan 래퍼 + 이력·Grafana 내보내기. 단순하고 가벼우나 능동 스캔 전용 |
| IoT Inspector (NYU/Princeton) | https://github.com/noise-lab/iot-inspector-client | GitHub | Apache-2.0 | ★479 / 2026-10 | Python, Pi 동작 미확인 | FR-7(기기 유형), 참고 | 스마트홈 기기 식별 연구 도구. **트래픽 수집을 ARP 스푸핑으로 함** → 8장 위반, 코드 차용 불가. 기기 라벨링·식별 로직과 데이터셋만 참고 |
| python-zeroconf | https://github.com/python-zeroconf/python-zeroconf | GitHub | LGPL-2.1 | ★742 / 2026-10 | apt ✔ 0.147 / pip 휠 ✔ cp313-aarch64 | FR-5(mDNS) | mDNS 서비스 탐색·수동 관찰 표준. `_services._dns-sd` 브라우징으로 기기 모델명(Apple, 프린터, Chromecast 등) 획득 |
| async_upnp_client | https://github.com/StevenLooman/async_upnp_client | GitHub | Apache-2.0 | ★57 / 2026-10 | pip 휠 ✔ | FR-5(SSDP) | Home Assistant가 쓰는 SSDP/UPnP 클라이언트. SSDP NOTIFY 수동 수신과 device description XML 파싱 모두 가능 |
| lldpd | https://github.com/lldpd/lldpd | GitHub | ISC | ★718 / 2026-10 | apt ✔ 1.0.18 | FR-5(LLDP) | `lldpcli show neighbors -f json`으로 스위치/AP 이웃 정보. 패시브 수신만으로도 동작. 가정망엔 LLDP 송신 장비가 드묾 |
| arpwatch | Debian 패키지 (LBL) | 공식 | BSD | apt 2.1a15-9 | apt ✔ | FR-5, FR-8 | 새 MAC/IP 쌍 변화 탐지의 고전. 이메일 알림 중심이라 직접 쓰기보다 로직(flip-flop, new station) 참고 |
| p0f v3 | https://lcamtuf.coredump.cx/p0f3/ | 공식 | LGPL-2.1 | 상류 3.09b(2016) 이후 정체 | apt ✔ 3.09b arm64 | FR-7(OS 추정) | SYN 기반 수동 OS 추정. 상류는 멈췄지만 Debian이 패키징. 시그니처 DB(p0f.fp)가 오래돼 최신 OS는 "unknown" 많음 |
| satori | https://github.com/xnih/satori | GitHub | GPL-2.0 | ★229 / 2026-09 | Python 순수, 미확인 | FR-7 | p0f 계열 Python 재작성. DHCP/TCP/HTTP/SMB 등 다중 프로토콜 핑거프린트 XML이 재사용 가치 있음 |
| Fingerbank API | https://www.fingerbank.org/ | 공식 | 독점 (무료 API 300 req/h) | 운영 중 (Inverse/Akamai) | REST, GitHub 로그인 키 | FR-7 | DHCP option 55 + UA 조합 기기 식별 최강 DB. GitHub의 공개 DB 저장소는 사라짐(404). 외부 전송이라 opt-in 필요 |
| kyd (Know Your Device, Zeek 패키지) | https://github.com/fatemabw/kyd | GitHub | BSD-3 | ★31 / 2020-12 | Zeek 필요 | FR-7 | Zeek용 DHCP 핑거프린트. 중단됐지만 동봉 `dhcp-db.txt`(Fingerbank 질의 결과)는 오프라인 DHCP 시그니처 시드로 활용 가능 |
| Zeek | https://github.com/zeek/zeek | GitHub | BSD-3 | ★8,147 / 2026-10 | Debian 13 apt에 없음(실측). OBS `security:zeek` 저장소에 Debian_13 arm64 .deb 있음(1장 참조) | M7, FR-7 | known_hosts/software/dhcp.log가 기기 식별에 유용. Pi 자원·설치 비용 때문에 정의서대로 2단계 |
| pyroute2 | https://github.com/svinota/pyroute2 | GitHub | Apache-2.0/GPL-2.0 | ★1,071 / 2026-10 | pip 휠 ✔ (순수 Python) | FR-5, 모드 E | netlink으로 커널 ARP/neighbor 테이블·링크 이벤트 구독. raw 소켓 없이도 Pi 자신의 ARP 캐시 변화를 실시간 관찰 |

### 능동 스캔

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| arp-scan | https://github.com/royhills/arp-scan | GitHub | GPL-3.0 | ★1,314 / 2025-03 | apt ✔ 1.10.0 | FR-6 | /24 스캔 수 초. `get-oui`로 IEEE CSV 갱신. CAP_NET_RAW 필요 |
| nmap | https://github.com/nmap/nmap | GitHub | NPSL | ★13,899 / 2026-10 | apt ✔ 7.95 arm64 | FR-6, FR-7 | OS/서비스 탐지 표준. `-O`/`-sS`는 root 또는 setcap. 발열 시 중단 정책(7장)과 연동 필요 |
| python-nmap | https://pypi.org/project/python-nmap/ | 공식(Bitbucket) | GPL-3.0 | 0.7.1 (2021-10) 이후 릴리스 없음 | apt ✔ python3-nmap 0.7.1 / pip 휠 ✔ | FR-6 | 정체 상태지만 XML 파싱은 동작. `-oX` 출력을 직접 파싱하는 편이 의존성 덜함 |
| python3-nmap (wangoloj) | https://github.com/wangoloj/python3-nmap | GitHub | GPL-3.0 | ★321 / 2025-09 | pip 휠 ✔ 1.9.1 | FR-6 | 비교적 최근 유지. async 지원 |
| nmapthon2 | https://github.com/cblopez/nmapthon2 | GitHub | Apache-2.0 | ★18 / 2025-04 | 순수 Python | FR-6 | 소규모. Apache 라이선스가 필요할 때 대안 |
| masscan | https://github.com/robertdavidgraham/masscan | GitHub | AGPL-3.0 | ★26,108 / 2026-10 | apt ✔ 1.3.2 | (비권장) | 가정망 /24에는 과함. 시끄럽고 AGPL. 채택 불필요 |
| netdisco (home-assistant-libs) | https://github.com/home-assistant-libs/netdisco | GitHub | Apache-2.0 | 2021-10 **archived** | - | - | 중단. HA는 zeroconf/ssdp 컴포넌트로 대체 |
| ntopng + nDPI | https://github.com/ntop/ntopng | GitHub | GPL-3.0 / nDPI LGPL-3.0 | ★8,307 / 2026-10 | packages.ntop.org/RaspberryPI/**trixie_pi/arm64** 존재(실측) | 참고/대안 | 기기 자동 분류·L7 식별·행위 알림을 이미 갖춘 완성품. 커뮤니티 에디션 무료. 이 프로젝트의 "비교 대상"이자 nDPI는 nfstream 경유로 활용 |

### 기기 핑거프린트·데이터셋

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| UNSW IoT Traces (Sivanathan, TMC 2018) | https://iotanalytics.unsw.edu.au/iottraces.html | 공식 | MIT-0 | 2018 공개 | PCAP 20일치 | FR-13, FR-30~33 | 라이선스 가장 자유로운 기기 유형 학습용 데이터. 기기별 MAC 라벨 제공 |
| UNSW-IoTraffic (2025, Dryad) | https://datadryad.org/dataset/doi:10.5061/dryad.w0vt4b94b | 공식 | 미확인(Dryad 기본 CC0) | 2025-08 | 28 GB, 27기기 203일 | FR-13, FR-30 | 장기 기준선·계절성 학습(FR-29)에 가장 적합한 최신 데이터 |
| Mon(IoT)r IMC'19 | https://moniotrlab.khoury.northeastern.edu/?p=1468 | 공식 | 데이터 공유 계약(비영리 연구 한정, 재배포 금지) | 2019 | 이메일 신청 | 참고 | 34,586회 실험 PCAP. 계약상 제품 동봉·재배포 불가 → 연구 검증용에만 |
| IoT-23 (Stratosphere) | https://www.stratosphereips.org/datasets-iot23 | 공식 | CC BY 4.0 (HF 미러 표기 기준; 원 페이지는 명시 없음, 인용 요청) | 2020 | 20 GB(8.7 GB 축약) | FR-33(합성 시나리오) | IoT 악성(Mirai 등) + 정상 캡처. HF 미러 `Lystea/IOT23-PARQUET`(961 DL, CC-BY-4.0, 2026-08) |
| CIC IoT Dataset 2023 | https://www.unb.ca/cic/datasets/iotdataset-2023.html | 공식/HF | CC BY 4.0(HF 미러 표기) | 2023 | HF `bencorn/CIC-IoT-2023` 14,846 DL | FR-33 | 공격(DDoS 위주) 중심. 기기 식별보다 탐지 회귀 테스트용 |
| TON_IoT / NF-ToN-IoT-v2 | https://huggingface.co/datasets/codymlewis/TON_IoT_network | HF | 미표기 / Apache-2.0(NF v2) | 2024-12 | CSV/flow | FR-33 | NetFlow 특징 기반. 흐름 집계 스키마(FR-28) 설계 참고 |
| YourThings (Georgia Tech, ACSAC'22) | https://yourthings.info/ | 공식 | 미확인 | 2022 | PCAP 13개(각 ~10 GB) | 참고 | 가정 IoT 45종 장기 캡처. 라이선스 확인 필요 |
| HF 모델 `Rameen-Mahmood/iot-device-identification` | https://huggingface.co/Rameen-Mahmood/iot-device-identification | HF | CC-BY-NC-4.0 | 2026-09, 0 DL | LLM 기반, Pi 부적합 | 참고 | NYU IoT Inspector 데이터로 LLM 미세조정(arXiv 2510.13817). NC 라이선스·크기 모두 부적합 |
| HF 데이터셋 `IoTProber/iot-classification-data` | https://huggingface.co/datasets/IoTProber/iot-classification-data | HF | 미표기 | 2026-05, 252 DL | - | 참고 | 설명·라이선스 없음. 신뢰 어려움 |
| HF 전반 (검색 "iot traffic", "device fingerprint", "iot device identification") | https://huggingface.co/datasets?search=iot | HF | - | - | - | - | **즉시 쓸 만한 기기 유형 분류 모델 없음.** 대부분 CIC/UNSW-NB15/TON 미러와 과제용 저품질 모델(`gates04/DistilBERT-Network-Intrusion-Detection` 18 DL 등) |

### OUI/벤더

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| IEEE OUI CSV (MA-L/MA-M/MA-S) | https://standards-oui.ieee.org/oui/oui.csv (+ /oui28/mam.csv, /oui36/oui36.csv) | 공식 | 공개(IEEE 이용 약관) | 상시 갱신 | 로컬 파일 | FR-7, M2 | 1차 소스. 세 CSV를 모두 합쳐야 MA-M/MA-S 소형 블록(IoT 제조사 다수) 매칭됨 |
| Debian `ieee-data` | apt | 공식 | 공개 | 20240722 | apt ✔ | FR-7 | 오프라인 시드로만. 2년 이상 묵어 주기 갱신 필수 |
| Wireshark manuf | https://www.wireshark.org/download/automated/data/manuf | 공식 | GPL-2.0 | 매일 자동 생성 | 텍스트 1개 | FR-7 | IEEE 3종 + 수작업 보정(랜덤 MAC 범위 주석 등) 통합본. GitLab 원본 경로는 폐기됨 |
| netaddr | https://github.com/netaddr/netaddr | GitHub | BSD-3 | ★831 / 2024-07 | apt ✔ 1.3.0 / pip 휠 ✔ | FR-7 | `EUI(mac).oui.registration()` 내장 OUI 조회 + IP 연산. 내장 DB는 릴리스 시점 고정 |
| manuf (Python) | https://github.com/coolbho3k/manuf | GitHub | Apache-2.0/GPLv3 | 1.1.5(2022-01), 커밋 2023-08 | pip 휠 ✔ | - | 자동 갱신 URL이 옛 GitLab 경로라 깨짐. 비권장 |
| mac-vendor-lookup | https://github.com/bauerj/mac_vendor_lookup | GitHub | Apache-2.0 | ★85 / 2025-11 | pip 휠 ✔ | FR-7 | macvendors.com 목록을 받아 로컬 캐시. 단순 |
| macvendors.com API | https://macvendors.com/api | 공식 | 무료 1,000/일, 1 rps | 운영 중 | REST | (비권장) | MAC을 외부로 보냄 → 8장 "외부 전송 OFF"와 충돌. 로컬 CSV 우선 |
| maclookup.app API | https://maclookup.app/api-v2/rate-limits | 공식 | 무료 10 rps·25K/6h(키 불필요) | 운영 중 | REST | (비권장) | 위와 동일 이유. 벌크 CSV 다운로드만 선택적 사용 |

### GeoIP/ASN/pDNS/인증서

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| MaxMind GeoLite2 + geoipupdate | https://github.com/maxmind/geoipupdate | 공식/GitHub | GeoLite2 EULA(2026-02-12 개정) / geoipupdate Apache-2.0 | ★981 / 2026-10 | apt ✔ geoipupdate 7.1.0; `geoip2` pip 휠 ✔ 5.3.0 (apt python3-geoip2는 2.9.0으로 낡음) | FR-17, M4 | City/Country/ASN mmdb. 계정+라이선스 키 필수, 조건은 메모 참조 |
| DB-IP Lite | https://db-ip.com/db/lite.php | 공식 | CC BY 4.0 | 월간 갱신 | mmdb(country/city/asn) | FR-17 | 계정 불필요한 대체재. 표기 의무만. 정확도는 GeoLite2보다 낮음 |
| IPinfo Lite | https://ipinfo.io/lite | 공식 | CC BY-SA 4.0 | 2025 출시, 일간 | 단일 mmdb(country+ASN) | FR-17 | ASN 조직명 포함, 무제한. SA 조항이 내보내기 데이터(FR-34)에 미칠 영향 검토 필요. 다운로드 토큰 필요 여부 미확인 |
| iptoasn.com | https://iptoasn.com/ | 공식 | PDDL(퍼블릭 도메인) | 매시간 | TSV gz | FR-17, FR-14(신규 ASN) | 라이선스 부담 0. ASN+국가 TSV를 DuckDB에 적재해 range join 하면 mmdb 없이도 됨 |
| pyasn | https://github.com/hadiasghari/pyasn | GitHub | MIT | ★330 / 2024-12, pypi 1.6.2(2023) | **sdist만** → Pi에서 C 확장 빌드 필요(build-essential) | FR-17 | RouteViews RIB 기반 오프라인 ASN. 정확하나 RIB 다운로드/변환 작업 포함 |
| sapics/ip-location-db | https://github.com/sapics/ip-location-db | GitHub | 소스별(DB-IP CC BY, PDDL 등) | ★2,238 / 2026-10(일간) | mmdb/CSV, npm/jsDelivr 배포 | FR-17 | 여러 무료 소스 통합·자동 갱신. MaxMind 제외라 라이선스 깔끔 |
| ipwhois | https://github.com/secynic/ipwhois | GitHub | BSD-2 | ★595 / 2024-10 | pip 휠 ✔ | FR-17(보조) | RDAP로 ASN·조직·abuse 연락처. 외부 질의라 사건 상세 열람 시 on-demand만 |
| passivedns | https://github.com/gamelinux/passivedns | GitHub | GPL-2.0 | ★1,736 / 2026-10 | C, apt 없음(소스 빌드) | FR-17(역DNS 대체) | 별도 도구 불필요: Suricata EVE dns 로그를 DuckDB에 축적하면 자체 pDNS가 됨. 역방향 DNS보다 "그 기기가 조회한 이름" 매핑이 더 설명력 있음 |
| JA4 / ja4plus | https://github.com/FoxIO-LLC/ja4 | GitHub | JA4(TLS 클라이언트)=BSD-3, **JA4+ 나머지=FoxIO 1.1**(내부 사용 허용, 상용 OEM 별도) | ★2,154 / 2026-10; pypi ja4plus 1.4.0 휠 ✔ | 순수 Python | FR-14, FR-28 | Suricata EVE의 ja3/ja4 필드 쓰는 게 우선. ja4db.com 조회는 외부 전송 |
| salesforce/ja3 | https://github.com/salesforce/ja3 | GitHub | BSD-3 | 2025-05 **archived** | - | - | 규격은 Suricata/Zeek에 내장돼 있어 저장소 불필요. abuse.ch SSLBL JA3 목록(FR-11)은 계속 갱신됨 |
| certspotter | https://github.com/SSLMate/certspotter | GitHub | MPL-2.0 | ★1,194 / 2026-10 | Go, arm64 빌드 가능 | (선택) | 자기 도메인 CT 감시용. IDS 보강엔 crt.sh on-demand 조회가 충분 |
| certstream-server-go / certstream-python | https://github.com/d-Rickyy-b/certstream-server-go | GitHub | MIT | ★238 / 2026-10; python 클라이언트 2024-07 | 전체 CT 스트림은 Pi에 과부하 | (비권장) | Calidog 공개 서비스 상태 미확인. 이 프로젝트 범위에선 가치 낮음 |

### 위협 컨텍스트 (CVE/KEV/EPSS/ATT&CK)

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| NVD API 2.0 + nvdlib | https://github.com/Vehemont/nvdlib | 공식/GitHub | 공공 데이터 / MIT | nvdlib 0.9.0, 2026-09 | pip 휠 ✔ | FR-17, FR-20 | 키 없이 5 req/30 s, 키 있으면 50. 알림에 붙은 CVE만 on-demand 조회 + SQLite 캐시 |
| CISA KEV JSON | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 공식 | 미국 정부 공개 | 실측 Last-Modified 2026-10-28 | 단일 JSON | FR-18 | 심각도 가중의 가장 신뢰도 높은 신호. 일 1회 다운로드 |
| FIRST EPSS API / 일간 CSV | https://api.first.org/data/v1/epss (CSV: https://epss.cyentia.com/epss_scores-current.csv.gz) | 공식 | 무료(재배포 조건 미확인) | 실측 응답 OK(2026-10-29 데이터) | CSV 수 MB | FR-18 | CVE 배치 100개 질의 또는 CSV 전체 적재. KEV와 함께 점수 가중치 |
| ET Open 룰 메타데이터 | https://community.emergingthreats.net/t/signature-metadata/96 | 공식 | BSD(ET Open) | 실측: alert 룰 51,552건 중 `mitre_tactic_id`/`mitre_technique_id` 33,493건, `cve` 3,156건, `signature_severity`·`confidence` 거의 전부 | 이미 FR-9로 설치 | FR-17, FR-18 | ATT&CK 매핑과 심각도의 1차 출처가 이미 룰 안에 있음. `attack_target IOT` 값은 0건 → IoT 프로파일은 자체 구현 |
| mitreattack-python + attack-stix-data | https://github.com/mitre-attack/mitreattack-python | GitHub | Apache-2.0 | ★754 / 2026-10, 6.3.1 휠 ✔ | STIX 번들 로딩 메모리 큼 → 배치로 1회 변환 | FR-20 | 기술 ID → 이름/설명/완화책 테이블을 SQLite로 사전 생성해 설명문(FR-20)에 사용 |
| ATT&CK Navigator | https://github.com/mitre-attack/attack-navigator | GitHub | Apache-2.0 | ★2,489 / 2026-10 | 웹앱(Angular) | FR-21(선택) | 주간 리포트에 레이어 JSON 첨부 정도. 필수 아님 |
| vulnerability-lookup / cve-search | https://github.com/cve-search/vulnerability-lookup | GitHub | AGPL-3.0 | ★598 / 2026-10 | 자체 호스팅은 무거움 | (선택) | 공개 인스턴스 API(vulnerability.circl.lu)를 NVD 보조로. AGPL은 API 사용엔 무관 |

### 상관·점수화·설명

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| ElastAlert2 | https://github.com/jertel/elastalert2 | GitHub | Apache-2.0 | ★1,137 / 2026-10 | Elasticsearch/OpenSearch 필수 → Pi 스택 부적합 | 참고 | frequency/spike/flatline/new_term 룰 타입 분류는 FR-14 탐지기 설계에 그대로 참고 |
| Praeco | https://github.com/johnsusek/praeco | GitHub | GPL-3.0 | ★576 / 2026-10 | 위와 동일 | - | ElastAlert UI. 부적합 |
| Wazuh | https://github.com/wazuh/wazuh | GitHub | GPL-2.0 | ★17,490 / 2026-10 | 매니저+인덱서 무거움 | 참고 | 룰 level 0~15와 `frequency`/`timeframe`/`if_matched_sid` 상관 모델이 가볍게 베낄 만한 설계 |
| Sigma 규격 + pySigma | https://github.com/SigmaHQ/pySigma | GitHub | LGPL-2.1 | ★603 / 2026-10, 2.0.1 휠 ✔ | 순수 Python | FR-16, FR-12 | Sigma Correlation(event_count/value_count/temporal/temporal_ordered) YAML 스키마를 사건 묶기 규칙 포맷으로 채택하면 사용자 정의 룰(FR-12)과 통일됨. SQLite 백엔드 존재 여부 미확인 |
| EveBox | https://evebox.org/ | 공식/GitHub(jasonish/evebox) | MIT | ★507 / 2026-10, 0.31.0 | **arm64 .deb 배포 실측** | FR-19 참고, M1 디버깅 | Suricata EVE 전용 뷰어(SQLite 백엔드). 상관 엔진은 아니지만 M1~M3 개발 중 즉시 쓸 수 있는 검증 도구 |
| Slips (Stratosphere) | https://github.com/stratosphereips/StratosphereLinuxIPS | GitHub | GPL-2.0 | ★897 / 2026-10 | Python이나 Redis+Zeek 의존, Pi 성능 미확인 | FR-15, FR-16 참고 | "evidence 누적 → threat level 임계 → alert" 구조가 FR-15(점수+근거)·FR-16(사건 묶기)과 가장 가까운 오픈소스 선례. 설계 참고 1순위 |
| DFIR-IRIS | https://github.com/dfir-iris/iris-web | GitHub | LGPL-3.0 | ★1,615 / 2026-10 | Docker+Postgres | (비권장) | 사건 관리 플랫폼. 단일 Pi엔 과함. TheHive OSS는 2025-07 archived |
| Malcolm (CISA) | https://github.com/cisagov/Malcolm | GitHub | BSD-3 | ★2,571 / 2026-10 | Suricata+Zeek+Arkime+OpenSearch, Pi 5 성능 미확인 | 참고 | 전체 NSM 스택의 참고 구현. 이 프로젝트가 피하려는 무게 |
| SELKS | https://github.com/StamusNetworks/SELKS | GitHub | GPL-3.0 | ★1,591 / 2025-09 | x86 ELK 기반 | 참고 | Suricata 중심 NDR 배포판. 대시보드 UX 참고 |

### Python 패킷 라이브러리

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| scapy | https://github.com/secdev/scapy | GitHub | GPL-2.0 | ★12,655 / 2026-10 | apt ✔ 2.6.1 / pip 휠 ✔ 2.8.0 | FR-5, FR-6, M2 | 수동 발견기(ARP/DHCP/mDNS/SSDP/LLDP contrib) 수준엔 충분. 순수 Python이라 수천 pps 이상은 무리 → BPF로 브로드캐스트만 받기 |
| dpkt | https://github.com/kbandla/dpkt | GitHub | BSD-3 | ★1,162 / 2024-07, 1.9.8 | apt ✔ / pip 휠 ✔ | FR-3(PCAP 스니펫 파싱) | 빠른 파서. 캡처 기능 없음. 유지보수 느림 |
| pyshark | https://github.com/KimiNewt/pyshark | GitHub | MIT | ★2,499 / 2026-03 | pip 휠 ✔ (apt 없음), tshark 4.4 apt ✔ | 개발·디버깅 | tshark 서브프로세스 래퍼. 운영 경로엔 무겁고, 프로토콜 디코딩 검증용으로 적합 |
| nfstream | https://github.com/nfstream/nfstream | GitHub | LGPL-3.0 | ★1,223 / 2026-09, 6.6.0 | **cp313 manylinux aarch64 휠 실측 ✔** | FR-28(흐름 집계), M7 대안 | nDPI 내장 흐름 생성기 + ML 특징 추출. Zeek 없이 app_proto 포함 흐름을 얻는 가장 가벼운 경로 |
| pyroute2 | (수동 발견 참조) | GitHub | Apache-2.0/GPL-2.0 | ★1,071 / 2026-10 | pip 휠 ✔ | FR-5 | 넷링크 이웃 테이블·인터페이스 통계(FR-4 드롭 카운터 수집에도 사용) |
| ipaddress(표준) + netaddr | https://docs.python.org/3/library/ipaddress.html | 공식 | PSF / BSD-3 | - | 내장 | 전 단계 | 내부/외부 판정, CIDR 집계, MAC/OUI는 netaddr |

### 한국어 자료

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| Naver 검색 4건("네트워크 자산 식별 오픈소스", "라즈베리파이 네트워크 모니터링 기기 탐지", "NetAlertX 설치", "Pi.Alert 설치") | https://search.naver.com/ | Naver | - | 2026-10-30 실행 | - | - | 서버 렌더링 HTML에 블로그 본문 결과가 없고 사전·지도·쇼핑·일반 IT 기사(ITWorld 라즈베리파이 활용 10가지, 보안뉴스 ATM 사건)만 노출됨. **직접 관련된 한국어 설치기·기술 글을 확인하지 못함** |
| "시놀/헤놀에서 네트워크 스캐너 Pi.Alert Docker로 설치 및 사용하기" (2023-07) | NetAlertX README 참고 링크 목록에 Korean 표기 | GitHub(README 경유) | - | 2023-07 | Synology 대상 | FR-5~8 | 존재는 README에서 확인, 원문 URL 미확인. Docker host 네트워크 설정 부분은 Pi에도 적용 가능 |
| labex.io 한국어 튜토리얼 "무단 네트워크 탐색 감지 방법" | https://labex.io/ko/tutorials/nmap-how-to-detect-unauthorized-network-probes-419255 | 웹 | - | - | - | FR-14(스캔 탐지) | 번역 교육 자료. 깊이는 낮음 |
| AcornPublishing/wireshark-packet-analysis-3e (『와이어샤크를 활용한 실전 패킷 분석 3/e』 예제) | https://github.com/AcornPublishing/wireshark-packet-analysis-3e | GitHub | GPL-3.0 | 2021-05 | - | 교육 | 한국어 패킷 분석 교재 코드. 탐지 시나리오별 PCAP 참고 |
| kimchiman123/Lightweighting_MLP | https://github.com/kimchiman123/Lightweighting_MLP | GitHub | 미표기 | 2026-03, ★0 | 경량 MLP | 참고 | "IoT 친화적 경량 MLP 침입탐지" 한국어 프로젝트. 품질 미확인 |
| 한국 학술 논문(KISA IoT 보안 가이드 기반 점검 체계) | https://www.koreascience.kr/article/JAKO202412754006178.page | 학술 | - | 2024 | - | 참고 | KISA 공식 기기 식별 오픈소스는 미발견. 트래픽 핑거프린팅보다 점검 체크리스트 성격 |

### 조사자 메모

- **MaxMind GeoLite2 조건(EULA 2026-02-12판 확인):** 계정+라이선스 키 필수, MaxMind 표기 문구 필수, 갱신본 공개 후 **30일 내 구버전 폐기**(요청 시 서면 확인), 제3자 재배포는 사전 서면 동의 필요, 가구/개인/주소 식별 목적 사용 금지, 향후 유료화 가능성 명시. → 저장소·설치 스크립트에 mmdb를 동봉하지 말고 사용자 키로 `geoipupdate` systemd 타이머(주 1회)를 돌릴 것. 키 없이 가려면 DB-IP Lite(CC BY) 또는 iptoasn(PDDL). IPinfo Lite는 CC BY-**SA**라 FR-34 내보내기 파일에 SA가 전파될 수 있음.
- **nmap on ARM:** Debian 13 arm64에 7.95 패키지 있음(실측). OS 핑거프린트 DB는 아키텍처 무관. `-O`/`-sS`에 CAP_NET_RAW+CAP_NET_ADMIN 필요 → 전용 사용자에 `setcap` 또는 sudoers 한 줄. python-nmap은 2021년 이후 릴리스가 없으니 `-oX`를 직접 파싱하는 편이 안전. masscan은 불필요.
- **랜덤 MAC과 기기 정체성:** iOS·Android는 SSID별 랜덤 MAC이 기본(두 번째 16진수 자리가 2/6/A/E = locally administered 비트). 유선 센서도 AP를 거쳐 오는 스마트폰은 랜덤 MAC으로 보이고 OUI 조회가 비게 됨 → Device의 기본 키를 MAC 단일로 두지 말고 (MAC, DHCP 호스트명, DHCP option 55 지문, DHCP client-id, mDNS 이름)을 묶은 복합 신원 + 수동 병합 기능을 데이터 모델(11장)에 넣어야 함. 그렇지 않으면 FR-8 "새 기기 알림"이 오탐 폭주함. 랜덤 MAC은 `randomized` 태그로 표시.
- **IoT Inspector는 ARP 스푸핑으로 트래픽을 끌어옴** → 8장 원칙상 코드 재사용 불가. 기기 라벨 사전·식별 로직만 참고.
- **중단/폐기 프로젝트:** pucherot/Pi.Alert(2024-02), home-assistant-libs/netdisco(archived 2021), salesforce/ja3(archived 2025-05), TheHive OSS(archived 2025-07), kyd(2020), coolbho3k/manuf(2023, 갱신 URL 깨짐), python-nmap(2021), p0f 상류(3.09b, Debian 패키지로만 생존), ipinfo/python-db(2023), Fingerbank 공개 GitHub DB(404).
- **Zeek는 Debian 13 apt에 없음(실측).** OBS 저장소에 arm64 .deb가 있으나(1장) 정의서대로 M7로 미루고, 흐름+app_proto가 필요하면 nfstream(cp313 aarch64 휠 확인됨) 또는 Suricata flow/EVE로 대체.
- **상관 도구는 전부 ES/OpenSearch 또는 무거운 스택 전제** → 자체 구현이 맞음. 차용할 것: Sigma Correlation YAML(규칙 포맷), Wazuh level 0~15(심각도 척도), ET `signature_severity`+`confidence`+KEV/EPSS(가중치), Slips의 evidence 누적→threat level(FR-15/16 구조).
- **ET Open 메타데이터 실측:** 룰의 약 65%에 ATT&CK 전술/기술 ID가 있고 CVE는 3,156건뿐, `attack_target IOT`는 0건. ATT&CK 이름·설명은 mitreattack-python으로 배치 변환해 SQLite 테이블로 두고 핫패스에서 STIX를 로드하지 말 것.
- **외부 전송 OFF 원칙과 충돌하는 보강 소스:** macvendors/maclookup API(MAC 유출), Fingerbank API(DHCP 지문 유출), ipinfo API·RDAP·NVD on-demand(목적지 IP/CVE 유출). 기본은 로컬 DB(IEEE CSV 3종, mmdb, iptoasn TSV, KEV JSON, EPSS CSV)로 하고 외부 질의는 사용자 opt-in + 사건 상세 열람 시에만.
- **데이터셋:** Mon(IoT)r은 비영리 연구 한정·재배포 금지 계약, HF 유일 기기 식별 모델은 CC-BY-NC. 제품에 동봉 가능한 것은 UNSW 2018(MIT-0)·UNSW-IoTraffic 2025·IoT-23(CC BY)·CIC-IoT-2023(CC BY). 기기 유형 기준선 학습엔 UNSW 계열, FR-33 합성 시나리오 재생엔 IoT-23이 적합. HF 검색 결과는 전반적으로 미러와 과제물 수준이라 모델 재사용은 기대하지 말 것.

---

## 3. 시계열 저장·특징 추출·ML 이상탐지·데이터셋·모델 관리

정의서 6.4(행위 탐지), 6.8(시계열 저장과 학습, FR-28~34), 7장(학습 부하), 11장(TimeSeriesBucket·TrainingSample·Model)에 대응한다.

### 시계열 저장

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| DuckDB | https://github.com/duckdb/duckdb | GitHub/PyPI | MIT | ★42.7k, 2026-10 | pip 2.0.0 aarch64 cp313 휠 O (py≥3.11) | FR-28/29/34, M1·M4.5 | 핵심 선택. `time_bucket`·윈도우·`COPY … PARTITION_BY`로 Parquet 롤업/계층 보존을 SQL만으로 처리 |
| DuckLake | https://github.com/duckdb/ducklake | GitHub | MIT | ★3.3k, 2026-10 | DuckDB 확장, 카탈로그를 SQLite/DuckDB에 둠 | FR-28 계층 보존, FR-34 | Parquet 스냅샷·파티션·삭제 관리를 자동화할 후보. 신생이라 M4.5 이후 검토 |
| pyarrow | https://github.com/apache/arrow | GitHub/PyPI | Apache-2.0 | 26.0.0, 2026-10 | aarch64 cp313 휠 O | FR-28/30/34 | Parquet 스키마 버전 명시·압축(zstd) 쓰기 표준. DuckDB와 zero-copy |
| polars | https://github.com/pola-rs/polars | GitHub/PyPI | MIT | ★40.2k, 2026-10 | 2.1.0은 메타패키지 + `polars-runtime-32` cp311-abi3 aarch64 휠 O | FR-30 특징 추출 | pandas보다 메모리·속도 유리. lazy scan_parquet로 1.5GB 상한 지키기 쉬움 |
| pandas | https://pandas.pydata.org | PyPI | BSD-3 | 3.1.0, 2026-10 | aarch64 cp313 휠 O | FR-30 | sklearn 생태계 호환용. 주 처리기는 polars, 모델 입력 직전만 pandas 권장 |
| SQLite + sqlite-utils | https://github.com/simonw/sqlite-utils | GitHub/PyPI | Apache-2.0 | ★2.2k, 2026-10 | 순수 파이썬 | FR-31/32 모델 레지스트리·라벨 | 설정/자산/알림/모델 레지스트리. CLI로 운영 점검 편리 |
| QuestDB | https://github.com/questdb/questdb | GitHub/공식 | Apache-2.0 | ★17.5k, 2026-10 | ARM64 지원, 공식 Pi5(4GB) 벤치 블로그 존재. JVM 상주 | 대안 | 성능은 충분하나 JVM 메모리·별도 데몬. 단일 스택 원칙(DuckDB)과 충돌 → 비채택 |
| VictoriaMetrics | https://github.com/VictoriaMetrics/VictoriaMetrics | GitHub | Apache-2.0 | ★17.9k, 2026-10 | Go 단일 바이너리 arm64, Debian 패키지 있음. 메모리 캡 플래그 제공 | FR-26 자가진단 메트릭(선택) | 메트릭 모델이라 기기×목적지 카디널리티 큰 흐름 집계엔 부적합. 시스템 지표 전용이면 가장 가벼운 TSDB |
| InfluxDB 3 Core | https://github.com/influxdata/influxdb | GitHub/공식 | Apache-2.0 | ★31.8k, 2026-10 | Linux ARM64 tarball 공식 제공(3.9.x), 이미지 134MB. 최소 RAM 공식 수치 미확인 | 대안 | Rust+Parquet이지만 별도 서비스. Core 에디션 질의 범위 제한 공지 이력 있어 장기 보존 용도엔 재확인 필요 |
| TimescaleDB | https://github.com/timescale/timescaledb | GitHub | Apache-2.0 + TSL | ★23.8k, 2026-10 | PostgreSQL 필요, arm64 패키지 있음 | 대안 | 연속 집계·보존 정책은 모범 사례지만 PG 서버 운영 비용이 Pi에 과함. 설계 참고만 |
| ClickHouse | https://github.com/ClickHouse/ClickHouse | GitHub/공식 | Apache-2.0 | ★50.7k, 2026-10 | aarch64 바이너리 제공, 권장 RAM 32GB(최저 2GB·튜닝 필요) | 대안 | Pi 4GB 메모리 상한과 맞지 않음. RITA v5가 의존하므로 RITA 도입도 같이 배제 |

### 특징 추출

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| Suricata EVE (flow/dns/tls) | https://suricata.io | 공식 | GPL-2.0 | 7.x apt | Debian 13 arm64 apt | FR-28 1차 소스, M1 | 이미 채택. flow 레코드(bytes/pkts/age)+dns+tls(JA3/JA4, SNI)로 FR-28 지표 대부분 충족 |
| nfstream | https://github.com/nfstream/nfstream | GitHub/PyPI | LGPL-3.0 | ★1.2k, 2026-09 / pip 6.6.0 (2026-02) | cp313 aarch64 manylinux 휠 O (이 Pi에서 실측) | FR-28/30, 테스트 PCAP 특징화 | nDPI 내장 양방향 흐름 통계+SPLT(초기 패킷 길이/간격) → 비컨 특징에 유용. 라이브 1Gbps는 무리, PCAP 오프라인·보조용 |
| nDPI | https://github.com/ntop/nDPI | GitHub | LGPL-3.0 | ★4.7k, 2026-10 | C, ARM 빌드 가능 | FR-14 Stratum·앱 프로토콜 | nfstream 경유로 사용. 채굴 풀(Stratum) 등 앱 프로토콜 분류 보강 |
| CICFlowMeter (Java) | https://github.com/ahlashkari/CICFlowMeter | GitHub | NOASSERTION(자체) | ★717, 2023-12 | Java, 구동 가능하나 정체 | FR-33 공개 데이터셋 호환 | CIC 계열 데이터셋(80+ 특징)과 동일 스키마가 필요할 때만 |
| cicflowmeter (Python, hieulw) | https://github.com/hieulw/cicflowmeter | GitHub/PyPI | MIT | ★92, 2026-03 / pip 0.5.0 (py≥3.12) | 순수 파이썬(scapy) | FR-33 | 느리지만 설치 간단. 재생 PCAP의 CIC식 특징 생성용 |
| NTLFlowLyzer | https://github.com/ahlashkari/NTLFlowLyzer | GitHub | GPL-3.0 | ★81, 2026-05 | Python, 휠 미확인 | FR-30 참고 | CIC의 차세대 Python 흐름 분석기. GPL이라 코드 차용 주의 |
| Zeek 7 | https://github.com/zeek/zeek | GitHub/OBS | BSD-3 (API: NOASSERTION) | ★8.1k, 2026-10 | OBS `security:zeek` Debian_13 arm64에 zeek-7.0 7.0.1 .deb 확인 | M7(선택) | conn/dns/ssl 로그 품질 최고. 메모리 실측 후 도입. IoT-23 라벨 포맷과 동일 |
| ZAT (Zeek Analysis Tools) | https://github.com/SuperCowPowers/zat | GitHub/PyPI | MIT | ★456, 2026-06 / pip 0.4.9 | 순수 파이썬 | M7, FR-30 | Zeek 로그→pandas/Parquet 변환기. Zeek 도입 시 바로 사용 |
| Joy (Cisco) | https://github.com/cisco/joy | GitHub | NOASSERTION | ★1.4k, archived 2024-04 | C | — | 보관 처리됨. SPLT/바이트 분포 개념만 참고 |
| tsfresh | https://github.com/blue-yonder/tsfresh | GitHub/PyPI | MIT | ★9.5k, 2026-07 / pip 0.21.2 | 순수 파이썬 | FR-30(선택) | 수백 개 통계 특징 자동 생성. 느리고 특징 폭발 → 스키마 v1엔 수작업 특징 권장 |

### 범용 이상탐지 라이브러리

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| scikit-learn | https://github.com/scikit-learn/scikit-learn | GitHub/PyPI | BSD-3 | ★68k, 2026-10 / 1.9.1 | aarch64 cp313 휠 O | FR-13/14/32, M5 | IsolationForest·LOF(novelty)·OneClassSVM·EllipticEnvelope·RobustScaler. 핵심 |
| PyOD | https://github.com/yzhao062/pyod | GitHub/PyPI | BSD-2 | ★10k, 2026-10 / 3.6.7 | 순수 파이썬(딥러닝 모델만 torch) | FR-14, M5 | ECOD/COPOD/HBOS는 파라미터 없이 빠르고 설명 가능. IF와 앙상블(평균 순위) 후보 |
| river | https://github.com/online-ml/river | GitHub/PyPI | BSD-3 | ★6.1k, 2026-10 / 0.26.1 | cp313 aarch64 휠 O | FR-13 증분 기준선, FR-32 | HalfSpaceTrees, 러닝 통계, ADWIN 드리프트 → 일 재학습 사이의 실시간 기준선 갱신 |
| PySAD | https://github.com/selimfirat/pysad | GitHub/PyPI | BSD-3 | ★315, 2026-10 / 0.7.0 | 순수 파이썬 | FR-13(보조) | xStream/LODA 스트리밍 탐지기. river로 부족할 때 |
| statsmodels | https://github.com/statsmodels/statsmodels | GitHub/PyPI | BSD-3 | ★11.7k, 2026-10 / 0.15.0 | aarch64 cp313 휠 O | FR-29 계절성 | STL/MSTL(시간대+요일 이중 계절), robust 잔차 z-score로 추세 이상 |
| ruptures | https://github.com/deepcharles/ruptures | GitHub/PyPI | BSD-2 | ★2.1k, 2026-10 / 1.1.10 | aarch64 cp313 휠 O (requires <3.14) | FR-29 변화점 | PELT/BinSeg로 기기별 행동 변화점. 1시간 집계 2년치도 가벼움 |
| STUMPY | https://github.com/TDAmeritrade/stumpy | GitHub/PyPI | BSD-3 (API: NOASSERTION) | ★4.2k, 2026-10 / 1.14.1 | 순수 + numba(cp313 aarch64 O). JIT 첫 컴파일 수십 초 | FR-14 비컨 주기성, FR-29 | 매트릭스 프로파일로 반복 패턴(비컨)·디스코드 탐지. 1분 집계 30일(43k점)이면 Pi에서 수초 |
| statsforecast | https://github.com/Nixtla/statsforecast | GitHub/PyPI | Apache-2.0 | ★5k, 2026-10 / 2.1.1 | aarch64 cp313 휠 O | FR-29 예측 기반 이상(선택) | numba 기반 ETS/MSTL/AutoARIMA가 Prophet보다 훨씬 빠름. 예측 구간 이탈을 이상으로 |
| Prophet | https://github.com/facebook/prophet | GitHub/PyPI | MIT | ★20.5k, 2026-10 / 1.5.0 | `py3-none-manylinux_2_28_aarch64` 휠(cmdstan 내장) O | FR-29(선택) | 설치는 되나 기기당 피팅 수초~수십초. 수십 기기 일 1회면 가능, 1차 제외 |
| ADTK | https://github.com/arundo/adtk | GitHub/PyPI | MPL-2.0 | ★1.2k, 2024-08 / 0.6.2(2020) | 순수 파이썬 | FR-14 룰형 탐지(참고) | 룰·임계치 탐지기 조합 API가 깔끔. 유지보수 정체라 코드 참고용 |
| luminol | https://github.com/linkedin/luminol | GitHub | Apache-2.0 | ★1.2k, 2025-08 / pip 0.4(2017) | 순수 | — | 사실상 종료. 비권장 |
| Merlion | https://github.com/salesforce/Merlion | GitHub/PyPI | BSD-3 | ★4.5k, 2026-03 / pip 2.0.4(2024-06) | 순수지만 의존 무거움 | — | 올인원이나 Pi엔 과함. 변화점·앙상블 설계 참고 |
| Darts | https://github.com/unit8co/darts | GitHub/PyPI | Apache-2.0 | ★9.6k, 2026-10 / 0.48.1 | 순수(torch 선택) | — | 예측 프레임워크. 과함 |
| sktime | https://github.com/sktime/sktime | GitHub/PyPI | BSD-3 | ★10k, 2026-09 / 1.2.0 | 순수(<3.15) | — | 통합 프레임워크 무게. 필요 알고리즘만 직접 쓰는 편이 가벼움 |
| tslearn | https://github.com/tslearn-team/tslearn | GitHub/PyPI | BSD-2 | ★3.2k, 2026-10 / 0.10.0 | 순수 | 미결사항 8(기기 유형 군집) | DTW k-means로 기기 유형별 공유 모델 군집화에 선택 |
| Kats | https://github.com/facebookresearch/Kats | GitHub/PyPI | MIT | ★6.5k, 2026-10 / pip 0.2.0(2022) | 설치 의존 충돌 잦음 | — | 비권장 |
| Orion | https://github.com/sintel-dev/Orion | GitHub/PyPI | MIT | ★1.4k, 2026-10 / 0.7.1 | requires <3.12 | — | Python 3.13 불가. 비권장 |
| NeuralProphet | https://github.com/ourownstory/neural_prophet | GitHub/PyPI | MIT | ★4.3k, 2026-10 / 0.9.0 | requires ≤3.12, torch | — | 3.13 불가. 비권장 |

### 시계열 분석·파운데이션 모델

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| Chronos-Bolt tiny/small | https://huggingface.co/amazon/chronos-bolt-tiny | HF/GitHub(★6.2k, 2026-10) | Apache-2.0 | HF 다운로드 tiny 1.17M, small 7.0M | tiny 9M 파라미터, torch cp313 aarch64 휠 O(용량 수백MB). Pi 실측 벤치 미확인 | FR-29 예측 기반 이상(2차) | 유일하게 Pi에서 시도해 볼 만한 FM. 학습 불필요(제로샷). 1차 범위 밖, M6.5 이후 실험 |
| chronos-bolt-tiny-onnx | https://huggingface.co/bakshinghampalace/chronos-bolt-tiny-onnx | HF | 미확인 | 139 dl | ONNX Runtime aarch64로 torch 없이 실행 가능성 | FR-29(실험) | 커뮤니티 변환본. 전처리 호환성 검증 필요 |
| Chronos-2 small (28M) | https://huggingface.co/autogluon/chronos-2-small | HF | 미확인(모델카드 확인) | 2025-10 공개 | 112MB, CPU 가능하나 Pi 실측 미확인 | FR-29(실험) | 다변량·공변량 지원. Bolt tiny보다 무거움 |
| TimesFM 2.5 (200M) | https://github.com/google-research/timesfm | GitHub/HF | Apache-2.0 | ★34.8k, 2026-09 | CPU RAM 1.5~4GB(비공식) → 학습 상한 1.5GB 초과 | — | Pi 부적합 |
| Moirai / uni2ts | https://github.com/SalesforceAIResearch/uni2ts | GitHub/HF | Apache-2.0 | ★1.6k, 2026-06 | 파라미터·CPU 요구 미확인 | — | 연구용. 비권장 |

### 네트워크 특화 탐지기

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| Kitsune / KitNET | https://github.com/ymirsky/Kitsune-py | GitHub | MIT | ★401, 2026-03 | 순수 numpy, 경량 | FR-13/14, M5 | AfterImage 증분 통계(감쇠 윈도우)+오토인코더 앙상블. 패킷 단위는 Pi에 무리 → 1분 집계/흐름 단위로 KitNET만 차용 |
| RITA v5 | https://github.com/activecm/rita | GitHub | GPL-3.0 | ★667, 2026-10 / v5.1.2 | 릴리스 자산 소스 tar.gz만, 공식 지원 amd64·ClickHouse 의존 | FR-14 비컨 | 도입 불가. 비컨 점수(간격 분산·데이터 크기 반복성·연결 수) 알고리즘을 Python으로 재구현 |
| Slips | https://github.com/stratosphereips/StratosphereLinuxIPS | GitHub | GPL-2.0 | ★897, 2026-10 | Python 3.12.3 고정, RAM 4GB+, RPi 설치 문서(베타) | FR-14 전반 | 전체 도입은 자원·GPL 부담. 모듈별 탐지 로직(포트스캔·비컨·DGA·수직/수평 스캔 임계)을 설계 참고 |
| flare | https://github.com/austin-taylor/flare | GitHub | MIT | ★458, 2022-12 | 순수 Python(ES 의존) | FR-14 비컨 | 비컨 탐지 알고리즘(간격 중앙값·CV) 참고. MIT라 차용 용이 |
| Zeek `policy/misc/scan.zeek` + scan-NG | https://github.com/initconf/scan-NG | 공식/GitHub | BSD / NOASSERTION | 내장 / ★16, 2025-01 | Zeek 도입 시 | FR-14 포트스캔, M7 | 내장 스크립트(15포트/5분 기본)가 충분. scan-NG는 Zeek 7 호환 미확인 |
| dgad (COSSAS) | https://github.com/COSSAS/dgad | GitHub/PyPI | Apache-2.0 | ★45, 2024-08 / pip 4.1.1 (py<3.11) | TF 의존, 3.13 불가 | FR-14 DGA | 비권장. 대신 문자 n-gram+로지스틱(아래 HF Reynier/dga-logit 방식)을 자체 학습 |
| exp0se/dga_detector | https://github.com/exp0se/dga_detector | GitHub | 미표기 | ★68, archived 2018 | 순수 | FR-14 DGA | 바이그램 빈도+엔트로피 휴리스틱. 라이선스 없음 → 아이디어만 |
| netrack/learn | https://github.com/netrack/learn | GitHub | Apache-2.0 | ★29, 2022-09 | 데이터+Python | FR-31 합성 라벨, FR-33 | 라벨된 DNS 유출 데이터셋·알고리즘. DNS 터널링 합성 시나리오 재료 |
| praveenrajasneo/dns-tunneling-detection | https://github.com/praveenrajasneo/dns-tunneling-detection | GitHub | 미표기 | ★70, 2026-05 | Python | FR-14 DNS | 라이선스 없음. 특징 설계(길이·엔트로피·TXT 비율) 참고만 |
| pcap-hunter | https://github.com/ninedter/pcap-hunter | GitHub | MIT | ★166, 2026-10 | Python | FR-14 참고 | 비컨·스캔 헌팅 워크벤치. 점수화 휴리스틱 참고 |
| nids-datasets | https://github.com/rdpahalavan/nids-datasets | GitHub/HF | 미표기 | ★33, 2023-08 | HF `load_dataset` 래퍼 | FR-33 | UNSW-NB15·CIC-IDS2017을 Parquet로 부분 로드 |

### 데이터셋

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성(크기) | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| CIC-IDS2017 | https://www.unb.ca/cic/datasets/ids-2017.html | 공식/HF | 공개(논문 인용 조건), UNB 전체 정책은 재배포 허용 | 2017 | 일별 PCAP 7.8~13GB(합계 ~51GB), CSV는 수백MB | FR-33 평가 | 포트스캔·봇·DoS 라벨. HF 미러 `bvsam/cic-ids-2017`(9.9k dl), `rdpahalavan/CIC-IDS2017`(apache-2.0 표기, Parquet 1.5~35GB) |
| CSE-CIC-IDS2018 | https://www.unb.ca/cic/datasets/ids-2018.html | 공식(AWS S3)/HF | 인용 조건 | 2018 | 전체 크기 미확인(수백GB급 PCAP) | FR-33 | HF `c01dsnap/CIC-IDS2018`, `bencorn/CICIDS2018` 미러로 CSV만 받는 편이 현실적 |
| UNSW-NB15 | https://research.unsw.edu.au/projects/unsw-nb15-dataset | 공식/HF | 학술 무료, 상업은 저자 협의(한 페이지는 금지로 상충) | 2015 | CSV 2.54M 레코드, 수백MB | FR-33 | HF `Mouwiya/UNSW-NB15`(2.7k dl), `rdpahalavan/UNSW-NB15`. 정찰·퍼징 라벨 |
| CTU-13 | https://www.stratosphereips.org/datasets-ctu13 | 공식 | CC-BY (mcfp 페이지 표기; 상위 페이지는 인용 요청만) | 2011 | 시나리오별 수GB, 전체 약 1.9GB tar.bz2 | FR-33 비컨 평가 | 봇넷·C2 흐름 수동 라벨. 비컨 탐지기 검증에 가장 적합 |
| IoT-23 (v2) | https://www.stratosphereips.org/datasets-iot23 | 공식/HF | 원 페이지 라이선스 미기재(인용 요청), HF Parquet 미러는 cc-by-4.0 표기 | 2020 | 전체 20~21GB, conn.log.labeled만 8.7~8.8GB | FR-31/33, M5 | Zeek conn 포맷 라벨 → 본 프로젝트 흐름 스키마와 매핑 쉬움. HF `Lystea/IOT23-PARQUET`(961 dl) |
| ToN_IoT / Bot-IoT | https://research.unsw.edu.au/projects/toniot-datasets | 공식/HF | 학술 무료 영구, 상업 협의 | 2019-2020 | Bot-IoT PCAP 69.3GB·CSV 16.7GB·5% 추출 1.07GB | FR-33 | IoT 환경 라벨. HF `SilverDragon9/UNSW_TON-IoT_*`(afl-3.0) |
| Kitsune Network Attack / N-BaIoT | https://archive.ics.uci.edu/dataset/516/kitsune+network+attack+dataset | UCI | CC BY 4.0 | 2018 | 27.17M 인스턴스, 파일당 2~3GB | FR-33, M5 | IP 카메라·IoT 환경(Mirai, 스캔, ARP MitM) → 가정 환경과 가장 유사. N-BaIoT(UCI 442)도 CC BY 4.0 |
| MAWILab | https://mawi.wide.ad.jp/mawi/ | 공식 | 미확인 | 2024-12 운영 종료 | v1.1 2007-2024, 6.5TB | — | 백본 트래픽·비지도 라벨. 가정용 센서엔 부적합 |
| harpomaxx/dga-detection | https://huggingface.co/datasets/harpomaxx/dga-detection | HF | cc-by-2.0 | 142 dl, ♥4 | 1M~10M 도메인, 수십MB | FR-14 DGA 학습 | 자체 DGA 분류기 학습 데이터로 적당. 상업 가능 |
| snsec-net/dga-detection-drift26dsn | https://huggingface.co/datasets/snsec-net/dga-detection-drift26dsn | HF | cc-by-nc-sa-3.0 | 592 dl | 100M~1B급 | FR-14 DGA | 비상업 조건. 평가 전용 |
| keys-i/netFlow, quailrobot/netflow-v1-sample | https://huggingface.co/datasets/keys-i/netFlow | HF | other / cc-by-nc-sa-4.0 | 232 / 114 dl | 소규모 | FR-33(보조) | HF에 NetFlow 전용 양질 데이터셋은 거의 없음. 합성·소규모 |
| KISA 사이버보안 AI 데이터셋·정보보호 R&D 데이터셋 | https://www.kisis.or.kr (정보보호산업진흥포털) | 공식/Naver | 국내 기업·연구자 신청제 | 2021-2024 누적 ~20억 건 | 네트워크 트래픽 포함, 개인 프로젝트 접근성 미확인 | FR-33(선택) | 국내 침해사고 재현 데이터. 신청 자격·용량 확인 후 결정 |

### HF 모델

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| Reynier/dga-logit | https://huggingface.co/Reynier/dga-logit | HF | 미확인 | 54 DGA 패밀리, acc 0.928(자체 보고) | TF-IDF 문자 n-gram+로지스틱 → sklearn만으로 Pi 즉시 실행 | FR-14 DGA | 가장 현실적인 DGA 접근. 동일 방식 자체 재학습 권장 |
| Reynier/dga-cnn, modernbert-dga-detector | https://huggingface.co/Reynier/modernbert-dga-detector | HF | 미확인 | 49 dl | CNN은 가능, ModernBERT는 Pi 부담 | FR-14 | 정확도 소폭↑ 대비 비용↑. 2차 |
| harpomaxx/dga-detector | https://huggingface.co/harpomaxx/dga-detector | HF | 미확인 | 1D-CNN(Catania 2018) | 소형 CNN, CPU 가능 | FR-14 | 데이터셋과 세트로 제공되어 재현 쉬움 |
| ccss17/dga-transformer-encoder | https://huggingface.co/spaces/ccss17/dga-detector | HF | 미확인 | 3.2M 파라미터, Gradio 데모 | CPU 가능 | FR-14 | ExtraHop DGA 데이터 학습. 비교 기준용 |
| gates04/DistilBERT-Network-Intrusion-Detection | https://huggingface.co/gates04/DistilBERT-Network-Intrusion-Detection | HF | 미확인 | 18 dl | 흐름을 텍스트화해 BERT → Pi 비효율 | — | 비권장. HF "intrusion" 검색 결과 전반이 학생 프로젝트 수준 |
| sniperyyc/NetFID-NetFlow | https://huggingface.co/sniperyyc/NetFID-NetFlow | HF | 미확인 | 8 dl, fill-mask | 연구용 | — | NetFlow 사전학습 모델 존재 확인 정도. 비권장 |

### 모델 관리·스케줄링

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| joblib | https://github.com/joblib/joblib | GitHub/PyPI | BSD-3 | ★4.4k, 2026-10 / 1.6.0 | 순수 | FR-32 | sklearn 기본 직렬화. pickle이라 가져오기(FR-34) 시 신뢰 경계 주의 |
| skops | https://github.com/skops-dev/skops | GitHub/PyPI | MIT | ★531, 2026-10 / 0.16.0 | 순수 | FR-32/34 | pickle 없이 안전한 sklearn 영속화 + 모델 카드. 외부 모델 가져오기 포맷으로 권장 |
| ONNX Runtime | https://github.com/microsoft/onnxruntime | GitHub/PyPI | MIT | ★22.2k, 2026-10 / 1.31.1 | aarch64 cp313 휠 O | FR-34 내보내기, 추론 고정 | 추론 경로를 sklearn 버전과 분리. Chronos-Bolt ONNX도 같은 런타임 |
| skl2onnx | https://github.com/onnx/sklearn-onnx | GitHub/PyPI | Apache-2.0 | ★632, 2026-10 / 1.20.0 | 순수 | FR-34 | IsolationForest·OneClassSVM 변환 지원(공식 표), LOF는 미확인 → 설치 후 `supported_converters()` 확인 |
| MLflow / mlflow-skinny | https://github.com/mlflow/mlflow | GitHub/PyPI | Apache-2.0 | ★28.6k, 2026-10 / 3.17.2 | 순수지만 의존 다수 | — | 서버 없이도 가능하나 과함. SQLite `Model` 테이블+디렉터리 레지스트리 직접 구현 권장 |
| modelstore | https://pypi.org/project/modelstore | PyPI | README 참조 | 0.0.82, 2026-02 | 순수 | FR-32(선택) | 파일시스템 백엔드 모델 레지스트리. 자체 구현 전 참고 |
| APScheduler | https://github.com/agronholm/apscheduler | GitHub/PyPI | MIT | ★7.7k, 2026-10 / 3.11.3 (4.x는 알파) | 순수 | FR-32, 롤업 | 인프로세스 잡(1m/5m/1h 롤업). 3.x 고정 권장 |
| systemd timer + 리소스 제어 | https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html | 공식 | LGPL | Debian 13 기본 | `Nice=19` `IOSchedulingClass=idle` `CPUQuota=150%` `MemoryMax=1.5G` `OOMPolicy=kill` | FR-32, NFR 학습 부하 | 재학습은 별도 유닛으로 분리해 cgroup 상한 강제. APScheduler보다 신뢰성 높음 |
| psutil | https://github.com/giampaolo/psutil | GitHub/PyPI | BSD-3 | 7.2.2, 2026-01 | aarch64 cp313 휠 O | FR-26/32 | `/sys/class/thermal` 온도·RSS 감시로 70°C/1.5GB 초과 시 재학습 중단 |

### 한국어 자료

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| GeekNews "시계열 이상 탐지: 10년간의 리뷰" | https://news.hada.io/topic?id=18613 | Naver→GeekNews | — | 2025-01 | — | FR-29 | arXiv 리뷰 요약. 거리/밀도/예측 기반 분류, 댓글에 Matrix Profile·IsolationForest 언급 |
| PyTorchKR Merlion 소개 | https://discuss.pytorch.kr/t/merlion-feat-salesforce/6256 | Naver→PyTorchKR | — | 2025-03 | — | FR-29 | Merlion 기능 한국어 개요. 설계 참고 |
| Anomstack Docker 설치 가이드 | https://blog.jackerlab.com/anomstack-docker-install-guide/ | Naver | — | 2026-08 | Dagster 기반이라 Pi엔 무거움 | FR-29 | SQL로 지표 정의→PyOD 이상탐지→Slack 알림 구조가 본 프로젝트 FR-29/22와 유사. 원본 github.com/andrewm4894/anomstack |
| reopt 핸드북 DuckDB 시계열·분석 SQL | https://handbook.reopt.ai/ko/books/duckdb-advanced/temporal-analytical-sql | Naver | — | 2026-05 | — | FR-28/29 | ASOF JOIN·QUALIFY·범위 조인 한국어 설명. time_bucket은 미포함 |
| BanApp/ARGOS | https://github.com/BanApp/ARGOS | GitHub(한국어) | 미표기 | ★2, 2023-04 | Python | FR-14 참고 | 패킷량 기반 네트워크 이상탐지 학생 프로젝트 |
| cosmosweet/NetworkAnomalyDetection | https://github.com/cosmosweet/NetworkAnomalyDetection | GitHub(한국어) | MIT | 2026-07 | Python | FR-14 참고 | 비지도 이상점수 통합(메타학습). 점수 결합 아이디어 참고 |
| hyeonggulim/DACON_HAICON2021 | https://github.com/hyeonggulim/DACON_HAICON2021 | GitHub(한국어) | 미표기 | 2021-11 | — | FR-29 참고 | HAI(ICS) 다변량 시계열 이상탐지 대회 1위 코드. 국내 시계열 이상탐지 실전 사례 |
| KISA 데이터셋 보도 | https://byline.network/2023/07/0726_003/ | Naver/뉴스 | — | 2023-07 | — | FR-33 | 14억 건 AI 데이터셋 공개 경위. 신청 경로는 정보보호산업진흥포털 |

### 조사자 메모

- **최소 스택 권장(모두 aarch64 cp313 휠 확인됨):** DuckDB 2.x + pyarrow + polars(+pandas 호환층) / scikit-learn + river + statsmodels + ruptures / joblib·skops + ONNX Runtime / APScheduler(인프로세스 롤업) + systemd timer(재학습). 추가 데몬(TSDB) 없이 FR-28~34 전부 충족 가능.
- **FR-28 계층 보존 구현:** Parquet를 `data/ts/res=1m/date=YYYY-MM-DD/` 식 hive 파티션으로 쓰고, DuckDB `time_bucket()`으로 1m→5m→1h 롤업 후 `COPY … PARTITION_BY`. 보존은 디렉터리 삭제 잡으로 단순화. DuckDB의 `PARTITION_BY`는 식을 못 쓰므로 bucket 컬럼을 먼저 물리화할 것. DuckLake는 스냅샷·삭제 관리가 필요해지면 M4.5 이후 검토.
- **Pi에 너무 무거운 것:** ClickHouse(권장 32GB), TimescaleDB(PG), QuestDB(JVM), RITA v5(amd64+ClickHouse), Slips(Py3.12 고정·4GB+), TimesFM 2.5(1.5~4GB), Merlion/Darts/sktime/Kats(의존 과다), MLflow(과함). Orion·NeuralProphet·dgad·Kats(pip)는 Python 3.13에서 아예 설치 불가.
- **휠 주의사항:** polars 2.x는 `polars-runtime-32`(cp311-abi3 aarch64)로 분리됨. prophet/lightgbm/xgboost는 `py3-none-manylinux_aarch64` 휠(3.13 OK). hdbscan·pytdigest는 aarch64 휠 없음(소스 빌드). ruptures는 `<3.14` 제약이므로 3.14 전환 시 재확인.
- **FR-13/14 탐지기 매핑:** 기기 기준선=sklearn IsolationForest+RobustScaler(일 재학습)와 river HalfSpaceTrees(실시간 증분) 이중화; 비컨=연결 간격 중앙값·CV·데이터 크기 반복성(RITA/flare 알고리즘 재구현)+STUMPY 매트릭스 프로파일; DNS/DGA=문자 n-gram TF-IDF+로지스틱(Reynier/dga-logit 방식, harpomaxx 데이터 cc-by-2.0로 자체 학습)+엔트로피·길이·TXT 비율 룰; 변화점=ruptures PELT; 계절성=statsmodels MSTL. 모두 CPU 수초 내.
- **KitNET 차용 방식:** 패킷 단위 원본은 Pi에서 1Gbps 불가. AfterImage의 감쇠 윈도우 통계(λ별 평균/분산/공분산) 개념을 1분 집계 특징에 적용하고, KitNET(numpy 오토앙상블, MIT)만 선택적 2차 모델로.
- **FR-33 평가 데이터 우선순위:** ① IoT-23 conn.log.labeled(8.7GB, Zeek 포맷이라 스키마 매핑 쉬움, HF Parquet 미러 cc-by-4.0) ② CTU-13(비컨/C2 라벨) ③ Kitsune·N-BaIoT(UCI, CC BY 4.0로 라이선스 가장 명확, 카메라/IoT 환경) ④ CIC-IDS2017 CSV(포트스캔·봇). UNSW 계열은 상업 조건 상충, snsec DGA는 NC. 50GB 상한 때문에 PCAP 전체 대신 CSV/Parquet 미러와 소량 PCAP 스니펫(tcpreplay용)만 보관.
- **합성 라벨(FR-31 `synthetic`):** 비컨·스캔·DNS 터널링은 공개 데이터보다 자체 재생이 재현성 높음. netrack/learn(Apache-2.0) DNS 유출 데이터, CTU-13 C2 구간 PCAP 발췌, nmap/arp-scan 자체 실행을 tcpreplay로 주입하고 구간을 `synthetic=true`로 라벨.
- **모델 레지스트리(FR-32/34):** SQLite `Model` 테이블 + `data/models/<kind>/<version>/{model.skops, model.onnx, metrics.json, schema.json}`. 내부 저장은 skops(안전), 외부 가져오기도 skops 또는 ONNX만 허용(pickle/joblib 외부 파일 금지). ONNX 변환은 IsolationForest·OCSVM 지원, LOF는 설치 후 확인.
- **재학습 자원 통제:** APScheduler가 아니라 `netmon-retrain.timer`(OnCalendar=03:30) + `.service`에 `Nice=19 IOSchedulingClass=idle CPUQuota=150% MemoryMax=1.5G`를 걸어 cgroup으로 강제. 서비스 내부에서 psutil로 온도 70°C·RSS 체크 후 자진 중단. 30분 상한은 `RuntimeMaxSec=1800`.
- **파운데이션 모델은 2차:** Chronos-Bolt tiny(9M, Apache-2.0)만 Pi 실험 후보. torch 휠(수백MB) 부담이 크므로 ONNX 변환본+onnxruntime로 시도하고, 이득이 statsforecast MSTL 대비 유의미할 때만 채택.
- **한국어 자료 결론:** 국내 공개 코드는 학생 프로젝트 수준(★0~2)이라 직접 차용 가치는 낮고, 한국어 해설(GeekNews 리뷰, reopt DuckDB 핸드북, Anomstack 가이드)은 팀 온보딩 문서로 유용. KISA 데이터셋은 신청 자격 확인이 선행.

---

## 4. AI 에이전트·LLM·MCP·Claude Code 오케스트레이션

정의서 6.5(설명문 생성), 6.6(리포트), 8장(외부 전송 OFF), 9장(아키텍처)에 대응한다. 개발 시 Claude Code 오케스트레이션(MCP·서브에이전트·스킬·훅)도 여기서 다룬다.

### MCP 서버: 네트워크·IDS

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| lidless-labs/suricata-mcp | https://github.com/lidless-labs/suricata-mcp | GitHub | MIT | ★3, 2026-10 | Node 20+, EVE JSON/Zeek TSV 파일 읽기만 → Pi5 가능 | FR-9/16/17, M4 | 41개 도구(알림·flow·DNS/TLS/JA3·비컨·DGA·lateral 분석, MISP 조회). 기본 읽기 전용, 룰 생성·PCAP 재생 등 변경 도구는 `SURICATA_ALLOW_MUTATION=1`+`confirm:true` 이중 게이트. 별 수는 적지만 이 프로젝트 요구와 가장 잘 맞음 |
| Hackerobi/suricata-mcp-server | https://github.com/Hackerobi/suricata-mcp-server | GitHub | MIT | ★1, 2026-02 | Python FastMCP | FR-12, M1 룰 튜닝 | PCAP 분석·룰 관리·룰 린트 18개 도구, Suricata 8/ET Open 테스트. 설치 예시가 `sudo` 실행 → 권한 과다, 개발 PC 한정 |
| Medinios/SuricataMCP | https://github.com/medinios/SuricataMCP | GitHub | 미표기 | ★14, 2025-06 | Python | — | 디렉터리에 가장 많이 등재되지만 도구가 version/help 수준. 비채택 |
| GreyNoise-Intelligence/suricata-mcp | https://github.com/GreyNoise-Intelligence/suricata-mcp | GitHub | MIT | ★0, 2026-03 | Go(정적 바이너리) | FR-9 | GreyNoise 랩 실험작, 문서 빈약. 관찰만 |
| Gabbo01/Zeek-MCP | https://github.com/Gabbo01/Zeek-MCP | GitHub | Apache-2.0 | ★7, 2025-05 | Python, Zeek 바이너리 필요 | M7(Zeek) | `execzeek` 도구가 쉘로 Zeek 실행 → 임의 PCAP 경로 주입 위험. 1년 이상 정체 |
| lidless-labs/zeek-mcp | https://github.com/lidless-labs/zeek-mcp | GitHub | MIT | ★2, 2026-10 | Node | M7 | 위 suricata-mcp와 같은 제작자, Zeek 로그 질의·상관 전용 |
| cyproxio/mcp-for-security | https://github.com/cyproxio/mcp-for-security | GitHub | MIT | ★628, 2026-03 | TS; nmap/masscan/sqlmap/ffuf 등 공격 도구 호출 | FR-6(opt-in 스캔)만 간접 | 가장 큰 보안 MCP 모음이지만 공격 도구 래퍼. 센서에 올리면 안 되고 개발 PC에서도 nmap 모듈만 분리 검토 |
| PhialsBasement/nmap-mcp-server | https://github.com/PhialsBasement/nmap-mcp-server | GitHub | MIT | ★49, 2026-06 | JS, nmap 실행 | FR-6 | 임의 인자로 nmap 실행 → 네트워크 스캔 권한을 LLM에 위임하는 구조. 8장 원칙상 기본 OFF, 수동 승인 필수 |
| tuliperis/SharkMCP | https://github.com/tuliperis/SharkMCP | GitHub | MIT | ★35, 2025-06 | TS, tshark 필요(apt로 ARM64 제공) | FR-3 PCAP 스니펫 분석 | 캡처+분석, SSLKEYLOG 복호화 지원. 라이브 캡처 도구는 비활성화하고 PCAP 파일 분석에만 쓸 것 |
| schwarztim/sec-wireshark-mcp | https://github.com/schwarztim/sec-wireshark-mcp | GitHub | MIT | ★1, 2026-05 | JS, SSH로 원격 tshark | FR-3 | 자격증명 추출·HTTP 객체 추출 기능 포함 → 페이로드 미저장 원칙과 충돌, 비채택 |
| inovacc/sharkline | https://github.com/inovacc/sharkline | GitHub | MIT | ★0, 2026-03 | Go | FR-3 | tshark/capinfos/editcap/mergecap 래퍼. 초기 단계 |
| appsecco/vulnerable-mcp-servers-lab | https://github.com/appsecco/vulnerable-mcp-servers-lab | GitHub | MIT | ★280, 2025-12 | — | 설계 참고 | 일부러 취약하게 만든 MCP 서버 모음. 자체 MCP 서버 만들 때 피해야 할 패턴 교재 |

### MCP 서버: 위협 인텔

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| w0h1v/mcp-virustotal (구 BurtTheCoder) | https://github.com/w0h1v/mcp-virustotal | GitHub | MIT | ★152, 2026-10 | TS/npm | FR-17 | URL/파일/IP/도메인 조회. 질의 자체가 내부 관측 IP·도메인을 외부로 보내는 행위 → 운영자가 수동 조사할 때만 opt-in. 무료 키 쿼터 제한 있음(수치 미확인) |
| w0h1v/mcp-shodan | https://github.com/w0h1v/mcp-shodan | GitHub | MIT | ★182, 2026-10 | TS/npm | FR-17 | Shodan+CVEDB. 외부 목적지 IP의 노출 서비스 확인용. 동일한 외부 전송 주의 |
| AbuseIPDB/AbuseIPDB-MCP (공식) | https://github.com/AbuseIPDB/AbuseIPDB-MCP · PyPI mcp-server-abuseipdb | GitHub/공식 | MIT | ★5, 2026-08 | Python 3.11+, uv | FR-17 | 공식·읽기 전용·베타. 가장 가벼운 평판 조회. 무료 키 일 1,000회(공식 문서 기준, 재확인 권장) |
| GreyNoise-Intelligence/greynoise-mcp-server (공식) | https://github.com/GreyNoise-Intelligence/greynoise-mcp-server | GitHub/공식 | 미표기 | ★6, 2026-10 | npx | FR-17 | 공식 문서에 Enterprise API 키 필수 명시 → 가정/SOHO 부적합 |
| MISP/misp-mcp (공식 org) | https://github.com/MISP/misp-mcp | GitHub/공식 | 미표기 | ★15, 2026-06 | Python | FR-11 | MISP 인스턴스 필요(Pi 한 대 스택에 과함). 읽기 전용. MISP 도입 시에만 |
| zxzinn/opencti-mcp | https://github.com/zxzinn/opencti-mcp | GitHub | MIT | ★41, 2026-08 | Node | FR-11 | OpenCTI 서버 필요(최소 수 GB RAM) → Pi 외부에서만 의미. 비채택 |
| CooperCyberCoffee/opencti_mcp_server | https://github.com/CooperCyberCoffee/opencti_mcp_server | GitHub | 기타 | ★29, 2026-10 | Python | — | 자연어 OpenCTI 질의. 동일 사유로 참고만 |
| w0h1v/mcp-otx | https://github.com/w0h1v/mcp-otx · PyPI otx-mcp | GitHub | MIT | ★1, 2026-10 | Python | FR-11/17 | AlienVault OTX 무료 키로 펄스·수동 DNS 조회. 외부 전송 opt-in |
| aplaceforallmystuff/mcp-threatintel | https://github.com/aplaceforallmystuff/mcp-threatintel | GitHub | MIT | ★9, 2026-08 | Node | FR-11/17 | OTX+AbuseIPDB+GreyNoise+abuse.ch 통합. abuse.ch 피드는 FR-11과 겹치므로 피드 자체는 로컬 동기화가 정답, MCP는 조사용 |
| google/mcp-security | https://github.com/google/mcp-security | GitHub/공식 | Apache-2.0 | ★536, 2026-10 | Python | — | SecOps/SOAR/GTI/SCC 엔터프라이즈 제품 래퍼. GTI 도구는 `VT_APIKEY` 사용하나 무료 VT 키 동작 여부 미확인 |
| Censys Platform MCP (공식, 호스팅) | https://docs.censys.com/docs/platform-mcp-server | 공식 | 미확인 | 2026 | 원격 HTTP | FR-17 | mcp.platform.censys.io, PAT+org ID 필요. 셀프호스트 불가 |
| DMontgomery40/pentest-mcp | https://github.com/DMontgomery40/pentest-mcp | GitHub | AGPL-3.0 | ★150, 2026-10 | TS | — | 공격 도구 모음(nmap/nikto/john 등). IDS 프로젝트에 부적합, 참고만 |

### MCP 서버: 데이터·운영·알림

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| motherduckdb/mcp-server-motherduck | https://github.com/motherduckdb/mcp-server-motherduck | GitHub/공식 | MIT | ★536, 2026-10 | Python `uvx`, 로컬 DuckDB/Parquet 직접 | FR-28/29/30, M4.5 | 기본 읽기 전용(`--read-write` 명시 필요). 개발 시 Parquet 시계열·학습 데이터셋을 Claude Code로 탐색하기에 최적 |
| jparkerweb/mcp-sqlite | https://github.com/jparkerweb/mcp-sqlite | GitHub | MIT | ★130, 2026-04 | Node | FR-16/23 (사건·억제 DB) | 공식 SQLite 서버는 modelcontextprotocol/servers-archived(★305, 2025-05)로 보관 종료. 읽기 전용 모드로 개발용 |
| modelcontextprotocol/servers (filesystem) | https://github.com/modelcontextprotocol/servers | GitHub/공식 | MIT(서버별) | ★91.7k, 2026-10 | Node | 개발 전반 | 레포·config 디렉터리만 허용 경로로 지정. 로그 디렉터리 노출은 페이로드 유출 경로가 될 수 있음 |
| github/github-mcp-server | https://github.com/github/github-mcp-server | GitHub/공식 | MIT | ★34k, 2026-10 | Go | 개발 | 이슈·PR 자동화. Claude Code 개발 루프용 |
| grafana/mcp-grafana | https://github.com/grafana/mcp-grafana | GitHub/공식 | Apache-2.0 | ★3.6k, 2026-10 | Go | FR-19 대안 | 프로젝트는 자체 SPA 대시보드 계획이므로 선택. Grafana 도입 시에만 |
| pab1it0/prometheus-mcp-server | https://github.com/pab1it0/prometheus-mcp-server | GitHub | MIT | ★521, 2026-10 | Python | FR-4/26 | 드롭 카운터·온도 등 자가 진단을 Prometheus로 노출할 경우 질의용 |
| chigwell/telegram-mcp | https://github.com/chigwell/telegram-mcp | GitHub | Apache-2.0 | ★1.9k, 2026-10 | Python Telethon | FR-22 | MTProto 사용자 계정 전체 권한을 LLM에 부여(80+ 도구). 알림 발송은 봇 토큰 직접 호출이 안전. 비채택 |
| sparfenyuk/mcp-telegram | https://github.com/sparfenyuk/mcp-telegram | GitHub | MIT | ★190, 2025-03 | Python | — | 읽기 전용이지만 1년 이상 정체 |
| homeassistant-ai/ha-mcp | https://github.com/homeassistant-ai/ha-mcp | GitHub | MIT | ★5.3k, 2026-10 | Python, HA 애드온 | FR-7 기기 이름 보강 | HA 사용 가정이면 기기 친화명·영역 정보를 자산 목록에 매핑하는 용도로 가치 있음 |
| paulomac1000/openwrt-mcp | https://github.com/paulomac1000/openwrt-mcp | GitHub | MIT | ★1, 2026-08 | Python, SSH 읽기 전용 | 5장 방식 C | OpenWrt 공유기 상태 진단. 읽기 전용 설계가 장점, 성숙도 낮음 |
| HexSleeves/tailscale-mcp | https://github.com/HexSleeves/tailscale-mcp | GitHub | MIT | ★146, 2026-10 | Bun/TS | 7장 보안(접근) | ACL·키 변경 가능 → 개발 PC 한정. 읽기 전용이 필요하면 paulsmith/tailscale-mcp-server(Go, ★10, 2025-04) |
| elastic/mcp-server-elasticsearch · opensearch-project/opensearch-mcp-server-py | https://github.com/elastic/mcp-server-elasticsearch · https://github.com/opensearch-project/opensearch-mcp-server-py | GitHub/공식 | Apache-2.0 | ★727 · ★158, 2026-10 | Rust · Python | — | 스택이 SQLite+DuckDB라 불필요. ES/OS 도입 안 하는 결정의 근거로만 기록 |

### 에이전트 프레임워크

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| anthropics/claude-agent-sdk-python | https://github.com/anthropics/claude-agent-sdk-python | GitHub/공식 | MIT | ★8.4k, 2026-10 | Python 3.10+, Node+Claude Code CLI 필요 | 개발 자동화, 선택적 클라우드 서술 | `output_format={"type":"json_schema","schema":Model.model_json_schema()}` → `ResultMessage.structured_output`. Claude API 호출 전제라 센서 상주 서비스보다 개발자 PC·운영자 조사 도구에 적합 |
| pydantic/pydantic-ai | https://github.com/pydantic/pydantic-ai | GitHub | MIT | ★20.9k, 2026-10 | 순수 Python, pip ARM64 휠 | FR-20/21 서술 생성 | 구조화 출력이 1급 기능, Ollama(로컬)·Anthropic 모델 교체가 설정 한 줄. 스택이 이미 Pydantic이라 1순위 |
| 567-labs/instructor | https://github.com/567-labs/instructor | GitHub | MIT | ★14k, 2026-10 | 순수 Python | FR-20 | 검증 실패 시 재질의. 프레임워크 없이 "LLM 호출 1개 + Pydantic"만 필요하면 이쪽이 더 가벼움 |
| dottxt-ai/outlines | https://github.com/dottxt-ai/outlines | GitHub | Apache-2.0 | ★16k, 2026-09 | llama.cpp 백엔드 지원 | FR-20 로컬 | 토큰 단위 제약 디코딩으로 소형 로컬 모델에서도 스키마 준수 보장. 1~3B 모델의 JSON 깨짐 문제 해결책 |
| langchain-ai/langgraph | https://github.com/langchain-ai/langgraph | GitHub | MIT | ★44k, 2026-10 | Python | — | 상태 그래프·체크포인트. 이 프로젝트의 LLM 단계는 선형(사실 수집→서술→검증)이라 과함 |
| crewAIInc/crewAI | https://github.com/crewAIInc/crewAI | GitHub | MIT | ★60k, 2026-10 | Python, 의존성 많음 | — | 역할극 다중 에이전트. Pi 상주 서비스에 부적합 |
| ag2ai/ag2 · microsoft/agent-framework | https://github.com/ag2ai/ag2 · https://github.com/microsoft/agent-framework | GitHub | Apache-2.0 · MIT | ★5k · ★14k, 2026-10 | Python | — | AutoGen 계열 분기. 후자는 Semantic Kernel+AutoGen 통합 후속. 둘 다 다중 에이전트 지향이라 비채택 |
| huggingface/smolagents | https://github.com/huggingface/smolagents | GitHub | Apache-2.0 | ★30k, 2026-10 | Python | — | 에이전트가 Python 코드를 생성·실행하는 방식 → 센서에서 샌드박스 부담. 비채택 |
| openai/openai-agents-python | https://github.com/openai/openai-agents-python | GitHub | MIT | ★30k, 2026-10 | Python | — | 설계는 가볍지만 OpenAI 중심. 로컬 우선 정책과 안 맞음 |
| deepset-ai/haystack · microsoft/semantic-kernel | https://github.com/deepset-ai/haystack · https://github.com/microsoft/semantic-kernel | GitHub | Apache-2.0 · MIT | ★26.9k · ★28.7k | Python · C# 중심 | — | RAG 파이프라인/엔터프라이즈 지향. 불필요 |
| agronholm/apscheduler | https://github.com/agronholm/apscheduler | GitHub | MIT | ★7.7k, 2026-10 | 순수 Python | FR-10/21/32 | 이미 스택에 포함. 일간 리포트·재학습·룰 갱신 수준은 이것으로 충분 |
| PrefectHQ/prefect · dagster-io/dagster · temporalio/sdk-python | 각 GitHub | GitHub | Apache-2.0 · Apache-2.0 · MIT | ★24k · ★16k · ★1.2k | Prefect/Dagster는 서버+DB, Temporal은 별도 서버 | — | 단일 Pi 무인 운영 목표와 충돌(메모리 4GB 상한). 비채택 근거로 기록 |
| guardrails-ai/guardrails · NVIDIA-NeMo/Guardrails · protectai/llm-guard | 각 GitHub | GitHub | Apache-2.0 · 기타 · MIT | ★7.6k · ★7.4k · ★3.2k | Python; llm-guard는 변환기 모델 다운로드 | FR-20 검증 | 이 프로젝트의 가드레일은 "서술이 입력 증거 ID만 인용했는가" 같은 결정적 검사가 핵심 → Pydantic validator로 자작이 더 가볍다. llm-guard는 외부 PCAP/도메인 문자열의 프롬프트 인젝션 스캔용으로만 검토 |

### 보안 특화 LLM·에이전트 프로젝트

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| beenuar/AiSOC | https://github.com/beenuar/AiSOC | GitHub | MIT | ★5k, 2026-10 | Docker 16~22 서비스, 8~12GB RAM, Kafka/ClickHouse/Neo4j | 설계 참고 | 기본 LLM이 Ollama `llama3.2:3b-instruct-q4_K_M`(API 키 없이 동작), 모든 프롬프트·도구 호출을 "Investigation Ledger"에 기록, 대응은 사람 승인. Pi엔 못 올리지만 트리아지 로그·승인 설계는 그대로 빌릴 것 |
| stratosphereips/StratosphereLinuxIPS (Slips) | https://github.com/stratosphereips/StratosphereLinuxIPS | GitHub | GPL-2.0 | ★897, 2026-10 | Python, Zeek 기반 | FR-13/14 경쟁·참고 | 행위 기반 IDS. 문서에 Pi 5 LLM 성능 연구 페이지 보유(아래 런타임 표). GPL이라 코드 차용 시 라이선스 주의 |
| Al3grus/Argus-SOC | https://github.com/Al3grus/Argus-SOC | GitHub | MIT | ★1, 2026-10 | Python | FR-16~20 | Wazuh+Suricata+Zeek 홈랩에 Claude API 트리아지. 규모는 작지만 이 프로젝트와 구성이 가장 비슷한 선례 |
| aaronphifer/triagewall | https://github.com/aaronphifer/triagewall | GitHub | AGPL-3.0 | ★14, 2026-09 | Python | FR-18/23 | 로컬 LLM 알림 트리아지. AGPL 주의 |
| sergarsilla/wazuh-llm-triage | https://github.com/sergarsilla/wazuh-llm-triage | GitHub | Apache-2.0 | ★0, 2026-09 | Python | FR-18 | "저신뢰 시 판단 보류(abstention)·유한 큐·백프레셔·dry-run" 설계 원칙이 Pi 환경에 그대로 유효 |
| jiacwng/meerkat | https://github.com/jiacwng/meerkat | GitHub | MIT | ★3, 2026-10 | Python CLI | FR-21 | 하루치 Wazuh 알림을 다음 날 아침 리뷰 큐로 압축. 일간 리포트 UX 참고 |
| Agenius-AI-Labs/Wazuh-AI-Security-Analyzer | https://github.com/Agenius-AI-Labs/Wazuh-AI-Security-Analyzer | GitHub | MIT | ★8, 2026-08 | n8n | 비용 참고 | Claude Haiku로 알림당 약 $0.001 주장(자체 수치) |
| aliasrobotics/cai | https://github.com/aliasrobotics/cai | GitHub | 기타 | ★9.8k, 2026-08 | Python | — | 공격 측 AI 프레임워크. 범위 밖, 위협 모델 참고 |
| meta-llama/PurpleLlama (CyberSecEval, LlamaFirewall) | https://github.com/meta-llama/PurpleLlama | GitHub | 기타 | ★4.5k, 2026-10 | — | 모델 선정 | 모델이 공격 조력을 거부하는지 측정하는 벤치마크. 로컬 서술 모델 선정 시 참고, 운영 의존성 아님 |
| Dxsssu/SecAlertBench | https://github.com/Dxsssu/SecAlertBench | GitHub | 미표기 | ★0, 2026-05 | — | FR-18 평가 | 8,322개 알림·241 유형으로 16개 LLM Tier-1 트리아지 평가. 자체 평가셋 설계 참고 |
| 논문 "Let the Alerts Speak" (ARES 2026, LNCS 16901) | https://researchr.org/publication/ScharmerLSWS26 | 공식 | — | 2026 | — | FR-20 | NIDS/HIDS 알림을 LLM으로 해석. 빈도 이상·프로토콜 위반처럼 지표가 약한 알림은 해석 정확도가 떨어진다고 보고 → 행위 탐지(FR-14) 설명은 LLM에 맡기지 말고 근거를 코드가 생성해야 함 |
| arXiv 2412.10978 (NIDS 룰 → ATT&CK 라벨링) | https://arxiv.org/abs/2412.10978 | 공식 | — | 2024-12 | — | FR-12/20 | Snort/Suricata 룰을 ATT&CK 기법에 매핑. 룰 설명문을 개발 시점에 일괄 생성해 캐시하는 전략의 근거 |
| HelenGuohx/logbert · nokia-steward/LogGPT | https://github.com/HelenGuohx/logbert · https://github.com/nokia-steward/LogGPT | GitHub | MIT · 미표기 | ★363(2024-06) · ★61(2023-12) | PyTorch | FR-14 | 둘 다 정체. 시계열 집계 기반 통계·IsolationForest가 Pi엔 적절, 딥러닝 로그 이상탐지는 1차 제외 결정 유지 |
| hookprobe/hookprobe | https://github.com/hookprobe/hookprobe | GitHub | AGPL-3.0 + 일부 비공개 | ★48, 2026-10 | Pi 대상 주장 | 경쟁 참고 | 핵심 알고리즘 여럿이 비공개이고 성능 수치가 마케팅 수준. 참고만 |

### 온디바이스 LLM (모델)

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| Qwen/Qwen3-1.7B | https://huggingface.co/Qwen/Qwen3-1.7B | HF | Apache-2.0 | 2.03B, 2025-07 | Q4 약 1.2GB | FR-20 로컬 | 한국어 포함 다국어, 사고 모드 on/off. Pi5 실측치 미확인(Qwen2.5-1.5B 기준 약 10 tok/s) |
| Qwen/Qwen3-4B | https://huggingface.co/Qwen/Qwen3-4B | HF | Apache-2.0 | 4.02B, 2025-07 | Q4 약 2.5~3GB | FR-21 배치 | 품질 상한 후보. Pi5 수치 미확인(동급 Gemma 3 4B Q4가 약 3.5 tok/s) |
| Qwen/Qwen2.5-3B-Instruct | https://huggingface.co/Qwen/Qwen2.5-3B-Instruct | HF | 기타(Qwen Research) | 3.09B, 2024-09 | Pi5 5.2 tok/s, RAM 3.0GB(Stratosphere 실측) | — | 3B만 연구 라이선스. Qwen3로 대체 |
| google/gemma-3-1b-it · gemma-3-4b-it | https://huggingface.co/google/gemma-3-1b-it | HF(게이트) | Gemma 라이선스 | 1.0B · 4.3B, 2025 | 1B Q4: 생성 ~10, 프롬프트 ~25 tok/s / 4B Q4: ~3.5, QAT ~5 tok/s(kunalganglani 2026-09) | FR-20 | 1B는 Pi에서 가장 빠른 축(Stratosphere 11.5 tok/s, 1.4GB). 한국어 품질은 Qwen·국산 모델보다 낮음 |
| microsoft/Phi-4-mini-instruct | https://huggingface.co/microsoft/Phi-4-mini-instruct | HF | MIT | 3.84B, 2025-12 | Q4 약 2.5GB, Pi5 수치 미확인 | — | 영어 중심, 한국어 약함 |
| meta-llama/Llama-3.2-1B/3B-Instruct | https://huggingface.co/meta-llama/Llama-3.2-3B-Instruct | HF(게이트) | Llama 3.2 | 1.24B · 3.21B, 2024-10 | 1B Q4 11.2 tok/s(2.4GB) · 3B Q4 4.7 tok/s(4.7GB) (Stratosphere) | — | 한국어 공식 미지원. AiSOC 기본 모델이기도 함 |
| fdtn-ai/Foundation-Sec-8B (Cisco) | https://huggingface.co/fdtn-ai/Foundation-Sec-8B | HF | Apache-2.0(베이스) / Instruct·1.1은 기타 | 8.03B, 2025-08(1.1: 2025-11) | Q4 약 4.5~5GB, Pi5 7~8B급 디코드 1.3~2.4 tok/s(NYU 리더보드) | 개발 PC용 | 보안 코퍼스 5.1B 토큰 사전학습. Pi엔 느려서 부적합, 개발 PC에서 룰 설명·분류 보조 후보 |
| trendmicro-ailab/Llama-Primus-Base/Reasoning | https://huggingface.co/trendmicro-ailab/Llama-Primus-Base | HF | MIT | 8.03B, 2025-03/06 | 동상 | 개발 PC용 | Llama 3.1 8B 보안 연속 사전학습. 다운로드 수 적음 |
| DeepHat/DeepHat-V1-7B (구 WhiteRabbitNeo) | https://huggingface.co/DeepHat/DeepHat-V1-7B | HF | Apache-2.0 | 7.6B, 2025-08 | 동상 | — | 공격 지향·무검열. IDS 설명용으로 부적합 |
| segolilylabs/Lily-Cybersecurity-7B-v0.2 | https://huggingface.co/segolilylabs/Lily-Cybersecurity-7B-v0.2 | HF | Apache-2.0 | 7.24B, 2024-01 | — | — | Mistral-7B 미세조정, 2년 정체 |
| markusbayer/CySecBERT · jackaduma/SecBERT | https://huggingface.co/markusbayer/CySecBERT | HF | Apache-2.0 | 110M · 84M | CPU로 ms 단위 | FR-18 보조 | 생성이 아니라 분류·임베딩용 인코더. 룰 메시지→카테고리 분류 같은 작은 작업엔 LLM보다 적합 |
| microsoft/bitnet-b1.58-2B-4T | https://huggingface.co/microsoft/bitnet-b1.58-2B-4T | HF | MIT | 2B | Pi5 8.1 tok/s, RAM 1.5GB(bitnet.cpp, Stratosphere) | 실험 | 메모리 효율 최고지만 생태계·한국어 미확인 |

### 온디바이스 LLM (런타임·벤치마크)

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| ggml-org/llama.cpp | https://github.com/ggml-org/llama.cpp | GitHub | MIT | ★133k, 2026-10 | `-march=armv8.2-a+dotprod+fp16fml`(Cortex-A76) 빌드 | FR-20/21 | Pi5에서 Ollama보다 10~20% 빠름(Stratosphere·타 블로그). GBNF 문법 제약·`llama-server` OpenAI 호환 API. 운영 배포용 1순위 |
| ollama/ollama | https://github.com/ollama/ollama | GitHub | MIT | ★185k, 2026-10 | Linux arm64 공식 바이너리 | 개발 편의 | 모델 교체·실험이 쉬움. Stratosphere도 "개발은 Ollama, 상주 배포는 llama.cpp" 선택 |
| mozilla-ai/llamafile | https://github.com/mozilla-ai/llamafile | GitHub | 기타 | ★26.5k, 2026-10 | aarch64 단일 실행파일 | — | 재설치 스크립트 단순화엔 매력. 모델 교체 유연성은 낮음 |
| Stratosphere Pi5 LLM 성능 연구 | https://stratospherelinuxips.readthedocs.io/en/develop/immune/research_rpi_llm_performance.html | 공식 문서 | — | 2025~ | Ollama Q4_K_M, 4스레드 | 모델 선정 | 실측: qwen2.5:3b 5.2 / llama3.2:3b 4.7 / qwen2.5:1.5b 10.0 / gemma3:1b 11.5 / llama3.2:1b 11.2 tok/s. 약 5,000토큰 Zeek 로그 프롬프트는 3B 모델 전부 타임아웃. 함수 호출은 대부분 실패 |
| NYU NAIRR Edge LLM Leaderboard (Pi 5 8GB) | https://benchmarklist.com/benchmarks/edge_llm_raspberry_pi_5 | 공식(HF Space) | — | 2026-05 갱신 | 126개 변형 | 모델 선정 | 7~9B Q4 디코드 1.3~2.4 tok/s, 프리필 4~14 tok/s. 8B급은 Pi 운영 불가의 근거 |
| Gemma 3 on Raspberry Pi 5 Benchmarked | https://kunalganglani.com/blog/gemma-3-raspberry-pi-5-benchmark | 블로그 | — | 2026-09 갱신 | Ollama, 8GB, 스왑 없음 | 모델 선정 | 1B Q4 생성 ~10/프롬프트 ~25 tok/s, 4B Q4 ~3.5/~8, 4B QAT ~5/~12, 1B 추론 중 약 8W |
| Raspberry Pi AI HAT+ 2 | https://blog.naver.com/no1_devicemart/224159936263 | Naver | — | 2026-01 | Pi5 전용 HAT | 선택 | 생성형 AI 가속 표방. 지원 모델·tok/s·가격 대비 효과 미확인, 1차 범위 밖 |

### 한국어 LLM

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| naver-hyperclovax/HyperCLOVAX-SEED-Text-Instruct-0.5B / 1.5B | https://huggingface.co/naver-hyperclovax/HyperCLOVAX-SEED-Text-Instruct-1.5B | HF | HyperCLOVA X SEED 라이선스(상업 허용, 재배포 시 "Powered by HyperCLOVA X" 표기·고지문 동봉) | 0.57B · 1.59B, 2025-07/10 | Q4 0.5~1GB, Pi5 수치 미확인(동급 1B가 10 tok/s대) | FR-20 한국어 서술 | 한국어 벤치(KMMLU·HAE-RAE·KoBEST)에서 동급 Qwen2.5·Gemma3 1B보다 우위(NAVER 자체 비교). 1.5B는 게이트(자동 승인) |
| kakaocorp/kanana-2-1.3b-instruct / kanana-2-3b-instruct | https://huggingface.co/kakaocorp/kanana-2-3b-instruct | HF | Kanana Open License(자체 서비스 운영은 별도 상업 계약 없이 가능, "Powered by Kanana" 표기 필수, 4.1항 예외 조건 미확인) | 1.29B · 3.51B, 2026-07/08 | Q4 약 0.9 / 2.2GB | FR-20/21 | 카카오 자체 평가 KoMT-Bench 6.54/6.92 vs Qwen3.5-2B 5.21. 2026년 10월 기준 가장 최신 국산 소형 모델 |
| kakaocorp/kanana-1.5-2.1b-instruct-2505 | https://huggingface.co/kakaocorp/kanana-1.5-2.1b-instruct-2505 | HF | Apache-2.0 | 2.32B, 2025-05 | Q4 약 1.4GB | FR-20 | 국산 소형 중 유일한 순수 Apache. 표기 의무 없이 쓰려면 이 모델 |
| K-intelligence/Midm-2.0-Mini-Instruct (KT) | https://huggingface.co/K-intelligence/Midm-2.0-Mini-Instruct | HF | MIT | 2.31B, 2025-10 | Q4 약 1.5GB | FR-20 | MIT로 가장 자유로움. 한국어 특화. Pi5 수치 미확인 |
| LGAI-EXAONE/EXAONE-3.5-2.4B-Instruct · EXAONE-4.0-1.2B | https://huggingface.co/LGAI-EXAONE/EXAONE-4.0-1.2B | HF | EXAONE License 1.1-NC / 1.2-NC(연구·교육 목적만, 상업 금지) | 2.41B · 1.28B | Ollama `exaone3.5:2.4b` 제공 | — | 한국어 품질은 좋으나 NC. 4.0의 "라이선스 갱신"은 출력물 소유권 조항 삭제일 뿐 상업 금지는 유지 → 사무실(SOHO) 사용 시 부적합 |
| Bllossom/llama-3.2-Korean-Bllossom-3B | https://huggingface.co/Bllossom/llama-3.2-Korean-Bllossom-3B | HF | Llama 3.2 | 3.21B, 2024-12 | Q4 약 2GB | — | 2년 가까이 갱신 없음. Kanana-2·Midm으로 대체 |
| skt/A.X-4.0-Light | https://huggingface.co/skt/A.X-4.0-Light | HF | Apache-2.0 | 7.26B, 2025-07 | Q4 약 4.5GB, Pi5 약 2 tok/s 추정 | 개발 PC용 | 국산 7B 중 라이선스·품질 균형 최고(ljy-dev 비교글 8GB 추천). Pi 상주엔 과함 |
| Motif-Technologies/Motif-2.6B | https://huggingface.co/Motif-Technologies/Motif-2.6B | HF | Apache-2.0 | 2.6B, 2025-08 | Q4 약 1.7GB | — | 국산 Apache 모델이지만 다운로드·커뮤니티 검증 적음 |

### Claude Code 활용

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| Hooks (33개 이벤트) | https://code.claude.com/docs/en/hooks | 공식 | — | 2026 | 개발 PC/Pi(SSH) | 개발 안전장치 | `PreToolUse`+exit 2로 차단. 이 레포엔 `Bash(nmap *)`, `Bash(arpspoof *)`, `Bash(tcpreplay *)`(테스트 인터페이스 외) 차단 훅과 `PostToolUse`(Edit→pytest) 훅이 1순위. 느린 훅은 게이트가 아니므로 하드 차단은 permissions deny 규칙과 병행 |
| Skills (`.claude/skills/*/SKILL.md`) | https://code.claude.com/docs/en/skills | 공식 | — | 2026 | — | M1/M4 | `/replay-pcap <file>`(allowed-tools 제한, `!`cmd로 인터페이스 상태 주입), `/triage-incident <id>`(context: fork, 읽기 전용 서브에이전트), `/tune-rule <sid>` 같은 반복 작업을 스킬화 |
| Subagents (`.claude/agents/*.md`) | https://code.claude.com/docs/en/sub-agents | 공식 | — | 2026 | — | FR-12/23 | `tools` 허용목록·`mcpServers` 인라인·`maxTurns`·`memory` 지정 가능. `rule-tuner`(suricata-mcp 읽기 전용+DuckDB), `fp-reviewer`(억제 이력 분석) 등을 읽기 전용 권한으로 분리 |
| MCP 설정 (`.mcp.json`, 스코프·권한) | https://code.claude.com/docs/en/mcp | 공식 | — | 2026 | — | 개발 | 프로젝트 스코프 `.mcp.json`에 duckdb/sqlite/suricata-mcp를 `${VAR:-default}` 경로로 정의. `mcp__서버__도구` 이름으로 permission·hook 매처 작성. `ANTHROPIC_API_KEY` 등은 서버 env로 자동 전달 안 됨(유출 방지) |
| Agent SDK 구조화 출력 | https://code.claude.com/docs/en/agent-sdk/structured-outputs | 공식 | MIT(SDK) | 2026 | Node 필요 | FR-20 | Pydantic `model_json_schema()`(draft-07) → `structured_output`. 실패 시 `error_max_structured_output_retries` → 템플릿 폴백 필수 |
| Claude API 구조화 출력·가격 | https://platform.claude.com/docs/en/build-with-claude/structured-outputs | 공식 | — | 2026-10 기준 | 클라우드 | FR-20 opt-in | `output_config.format` / `client.messages.parse()`. Haiku 5.5 입력 $0.10·출력 $0.50/MTok, Sonnet 5.5 $2/$10 → 사건당 2k 입력+0.5k 출력이면 Haiku 약 $0.0005, Batches API 50% 할인. 비용이 아니라 8장 외부 전송 원칙이 결정 요인 |
| 프롬프트 인젝션 표면 | https://www.elastic.co/kr/security-labs/mcp-tools-attack-defense-recommendations | 공식 블로그(한국어) | — | 2026 | — | 7장 보안 | 이 프로젝트의 LLM 입력은 공격자가 통제하는 문자열(DNS 질의명, SNI, HTTP UA, 인증서 CN)을 포함 → 입력을 데이터 블록으로 격리하고 도구 호출 권한이 없는 "서술 전용" 호출로 제한 |

### 한국어 자료

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| [2026년 10월] 한국어 로컬 LLM 비교 | https://blog.naver.com/ljy-dev/224442285783 | Naver | — | 2026-10-15 | — | 모델 선정 | A.X·Kanana·Mi:dm·HyperCLOVA X·EXAONE을 VRAM별로 정리. 8GB: A.X 4.0 Light Q4·Kanana-2 3B Q8 추천, 1~3B 한국어 작업엔 Kanana-2 SLM. 개발사 공개 수치만 인용한 점을 명시한 신뢰할 만한 정리 |
| 초소형 온디바이스 LLM 2026 | https://blog.naver.com/pioneer_law/224413714037 | Naver | — | 2026-09-16 | — | 모델 선정 | 1GB 이하 메모리 기기용 모델 선택 기준. "무엇을 시킬지 먼저 좁혀라"는 결론이 이 프로젝트의 서술 전용 용도와 일치 |
| 온디바이스 AI 회의록 1편: HF에서 한국어 LLM 찾기 | https://blog.naver.com/jjjjjjyoung/224363116210 | Naver | — | 2026-07-30 | Jetson Orin Nano 8GB | 참고 | 8GB 엣지 보드에서 한국어 모델 선정 과정 기록 |
| raspberry pi 5 llm 모델 구동기 | https://blog.naver.com/kimsjpk/224140405610 | Naver | — | 2026-01-09 | Pi5 4GB | 참고 | Ollama로 구동, "한글은 안 되고" 등 소형 영어 모델의 한국어 한계 체감기 |
| LLM을 라즈베리파이에서 구동하기 | https://blog.naver.com/seodaewoo/224188210794 | Naver | — | 2026-02-19 | Pi 4B 8GB | 참고 | Pi 4 기준이라 Pi 5보다 느림. 설치 절차 참고 |
| 라즈베리파이5 완벽 가이드(위키독스) | https://wikidocs.net/354364 | Naver/위키독스 | — | 2026 | Pi5 | 참고 | `qwen3:1.7b`를 한국어용으로 소개. 속도 수치 없음 |
| 'MCP 게이트웨이'란 무엇인가 | https://blog.naver.com/cloudnetworks/224377319756 | Naver | — | 2026-10-26 | — | 7장 보안 | MCP 접근 통제(인증·도구 허용목록·감사) 조건 정리 |
| MCP 도구 권한과 파일 경계 점검법 | https://blog.naver.com/litis_official/224433847865 | Naver | — | 2026-10-07 | — | 개발 | 에이전트가 읽을 수 있는 파일 범위 점검 절차. filesystem MCP 경로 제한 설계에 참고 |
| MCP 보안 위기 — 60일 만에 30개 CVE | https://jangwook.net/ko/blog/ko/mcp-security-crisis-30-cves-enterprise-hardening | 블로그 | — | 2026 | — | 7장 보안 | 2026년 1~2월 MCP 생태계 CVE 30건, 노출 서버 36% 무인증 주장(2차 자료). 서드파티 MCP를 센서에 올리지 않는 근거 |
| 기업 보안의 새 변수 MCP 서버 — CISO가 파악해야 할 18가지 | https://www.cio.com/article/4089875 | CIO Korea | — | 2026 | — | 7장 보안 | 도구 오염·간접 프롬프트 인젝션·토큰 집중 위험 정리 |
| [Day 6] 판단하는 관제 데스크 — LLM·AI 에이전트 | https://blog.naver.com/zeropoint_94/224397429499 | Naver | — | 2026-09-01 | Python | FR-18/22 | Python 관제 자동화 연재. while 루프+schedule+Flask 웹훅 위에 LLM 판단 단계를 얹는 소규모 구성 예 |
| 이글루코퍼레이션 AiR 자율형 SOC / KISA 과제 | https://m.boannews.com/html/detail.html?idx=144563 · https://ddaily.co.kr/page/view/2026060410140824024 | 보안뉴스/디지털데일리 | — | 2026-06~07 | — | 동향 | 국내 상용 SOC의 에이전틱 AI 방향(보안 특화 LLM+다중 에이전트). 로그프레소 Sonar 5.0도 동일 흐름 |
| AI 에이전트 위협 5계층 통제 모델 제안 | https://blog.naver.com/tigensoft/224455436552 | Naver | — | 2026-10-27 | — | 7장 보안 | 악성 지시 오인·과도한 권한을 계층별로 통제하는 모델 요약 |
| Agentic AI 시대 자율형 보안 에이전트의 가능성과 통제 과제 | https://blog.naver.com/homeland_seeker/224437464504 | Naver | — | 2026-10-10 | — | 동향 | 2026 AI보안 기술 전문가 워킹그룹 세미나 후기 |
| NDR+EDR 설계 Ver.1 | https://blog.naver.com/lastime1650/223885725553 | Naver | — | 2025-06-02 | — | 9장 아키텍처 | 개인이 Suricata 기반 NDR을 설계한 기록. 국내 Suricata+LLM 직접 결합 사례는 Naver에서 확인되지 않음 |
| ARTEX 한국어판 / 금융권 공격 사례 | https://blog.naver.com/rainlms/224439902235 · https://blog.naver.com/kuya_young/224437244286 | Naver | — | 2026-10 | — | 위협 모델 | LLM 다중 에이전트 침투 도구가 국내 금융권 공격에 쓰였다는 보도 요약. 이 센서가 탐지해야 할 상대도 에이전트라는 점 상기 |
| mumo-team/Icarus-Tether | https://github.com/mumo-team/Icarus-Tether | GitHub(국내) | 미표기 | ★0, 2026-09 | Python | 7장 보안 | 도구 호출 직전에 민감 데이터 외부 유출을 차단하는 MCP 게이트웨이. 초기 단계지만 "외부 전송 OFF" 강제 아이디어와 같음 |
| HyperCLOVA X SEED 소개(파이토치 한국 사용자 모임) | https://discuss.pytorch.kr/t/hyperclova-x-seed-ai/6858 | 커뮤니티 | — | 2025-04 | — | 모델 선정 | 0.5B/1.5B/3B 공개와 상업 이용 조건 요약 |

### 조사자 메모

- **LLM이 가치를 내는 곳은 FR-20·FR-21 두 곳뿐이다.** 5요소 서술(무엇/어떤 기기/어디와/왜 위험/조치)의 "사실"은 전부 코드가 수집한 구조화 데이터(Suricata 시그니처, GeoIP/ASN, 기기 프로파일, 기준선 편차)이고, LLM은 그것을 쉬운 한국어 문장으로 바꾸는 역할만 맡겨야 한다. ARES 2026 논문이 보고하듯 약한 지표(빈도 이상, 프로토콜 위반)에 대한 LLM 해석은 부정확하므로 FR-14 행위 탐지의 "근거"는 LLM이 아니라 탐지기가 생성해야 한다.
- **LLM을 넣지 말아야 할 곳:** 탐지(FR-13/14), 심각도 산정(FR-18, 결정적·설명 가능해야 함), 1분 이내 즉시 알림 경로(G6). 즉시 알림은 템플릿 문장으로 먼저 발송하고, LLM 서술은 사건이 열린 뒤 비동기로 덧붙이는 2단계가 Pi 성능과 신뢰성 모두에 맞다.
- **Pi 5 실측 현실(8GB, CPU, Q4):** 1B급 10~11 tok/s(RAM 1.4~2.4GB), 1.5~2B급 8~10 tok/s, 3B급 4.7~5.2 tok/s(RAM 3~4.7GB), 4B급 3.5 tok/s(QAT 5), 7~8B급 1.3~2.4 tok/s. 더 중요한 건 프롬프트 처리(프리필)가 1B 약 25 tok/s, 4B 약 8 tok/s라는 점이다. 사건 컨텍스트 1,500토큰 + 출력 400토큰이면 1.5B 모델로 약 2분, 4B 모델로 약 5분. Stratosphere는 5,000토큰 Zeek 로그 프롬프트에서 3B 모델 전부 타임아웃을 기록했다. 따라서 입력은 1,000토큰 이하로 압축하고 메모리 4GB 상한(7장) 안에서 1.3~2B Q4 모델을 상주시키거나, 서술 생성 시에만 로드하는 방식이어야 한다.
- **로컬 vs 클라우드 결정:** 8장 "외부 전송 OFF 기본"에 따라 기본값은 로컬(llama.cpp + 1.3~2B 한국어 모델). 클라우드는 `llm.provider: anthropic` 명시 opt-in으로만 허용하고, 보낼 때 내부 IP/MAC/호스트명을 가명 토큰으로 치환한 뒤 시그니처명·목적지 도메인/ASN·집계 수치만 전송한다. 비용은 Haiku 5.5 기준 사건당 $0.001 미만이라 결정 요인이 아니다. 주간 리포트처럼 품질이 중요하고 지연이 무관한 작업만 클라우드 후보.
- **한국어 로컬 모델 추천 순서:** Kanana-2 1.3B/3B(최신, 한국어 벤치 우위, "Powered by Kanana" 표기 필요) → Midm 2.0 Mini 2.3B(MIT) → Kanana 1.5 2.1B(Apache) → HyperCLOVA X SEED 1.5B(표기 의무) → Qwen3 1.7B/4B(다국어, Apache). EXAONE 3.5/4.0은 NC 라이선스라 사무실 사용 시 제외, Qwen2.5-3B는 연구 라이선스라 제외. Pi 5에서의 한국어 모델 tok/s 실측은 어디에도 없으므로 M4 전에 `llama-bench`로 직접 재야 한다.
- **출력 구조 강제:** `IncidentNarrative(what, device, destination, why_risky, actions[], evidence_ids[], confidence)` Pydantic 모델을 단일 진실로 두고, 로컬은 llama.cpp GBNF/outlines 제약 디코딩, 클라우드는 `output_config.format`(API) 또는 `output_format`(Agent SDK)을 쓴다. validator에서 `evidence_ids`가 입력에 존재하는 ID만 인용했는지, 입력에 없는 IP/도메인이 본문에 등장하지 않는지 검사하고 실패하면 템플릿 서술로 폴백한다. 별도 가드레일 라이브러리보다 이 결정적 검사가 더 중요하다.
- **보안 특화 LLM(Foundation-Sec-8B, Llama-Primus)은 Pi에서 쓸 수 없다.** 8B Q4는 디코드 2 tok/s 이하다. 개발 PC에서 ET Open 룰 메시지에 대한 한국어 설명문을 사전 생성해 SQLite에 캐시해 두는 오프라인 용도(arXiv 2412.10978의 룰→ATT&CK 매핑과 같은 패턴)로만 의미가 있다. 분류 작업은 CySecBERT 같은 110M 인코더가 CPU에서 더 적합하다.
- **센서(Pi)에 붙여도 되는 MCP는 사실상 없다.** MCP는 개발자 PC의 Claude Code에 붙이고, Pi의 데이터는 Tailscale 너머 읽기 전용으로 노출한다. 안전한 쪽: mcp-server-motherduck(읽기 전용 기본), SQLite 서버(읽기 전용), lidless-labs/suricata-mcp(변경 도구 이중 게이트), filesystem(레포 경로 한정), github 공식. 붙이면 안 되는 쪽: nmap-mcp·mcp-for-security·pentest-mcp(LLM에 스캔 권한 위임, 8장 위반), Gabbo01/Zeek-MCP(쉘 실행), chigwell/telegram-mcp(계정 전권), VirusTotal/Shodan/OTX(질의 자체가 내부 관측값의 외부 전송 → 운영자 수동 조사 시 opt-in만).
- **위협 인텔은 MCP가 아니라 피드다.** FR-11의 abuse.ch(URLhaus/Feodo/SSLBL)·Spamhaus DROP은 로컬 다운로드 후 DuckDB 조인으로 처리해야 외부 전송 없이 매칭된다. AbuseIPDB 공식 MCP(읽기 전용, 무료 키)는 운영자가 대시보드에서 "외부 조회" 버튼을 눌렀을 때만 호출하는 조사 도구로 한정.
- **에이전트 프레임워크는 pydantic-ai 하나로 충분하다.** 스택이 이미 Pydantic/FastAPI/APScheduler이고, 로컬(Ollama/llama-server)↔Anthropic 전환이 모델 문자열 하나다. LangGraph/CrewAI/AutoGen은 다중 에이전트·그래프 상태가 필요 없는 이 프로젝트엔 의존성 부담만 더한다. Prefect/Dagster/Temporal은 서버 프로세스가 필요해 4GB 메모리 상한과 충돌한다. Claude Agent SDK는 Node 런타임과 API 호출이 전제라 Pi 상주 서비스가 아니라 개발자 PC의 자동화(룰 튜닝 보조, 테스트 PCAP 트리아지)에 쓴다.
- **Claude Code 개발 오케스트레이션 최소 구성:** `.mcp.json`(duckdb+sqlite+suricata-mcp, 모두 읽기 전용 env), `.claude/agents/rule-tuner.md`(tools: Read/Grep + `mcp__suricata__*` 읽기 도구만, maxTurns 제한), `.claude/skills/replay-pcap`·`triage-incident`, `PreToolUse` 훅으로 `nmap`/`arpspoof`/비허용 인터페이스 `tcpreplay` 차단 + permissions deny 병행, `PostToolUse`로 netmon/ 편집 시 pytest. 서드파티 MCP는 2026년 초 두 달간 CVE 30건이 보고된 영역이므로 버전 고정·코드 리뷰 후에만 추가.
- **참고 선례:** 구조는 Argus-SOC(Wazuh+Suricata+Zeek+Claude 트리아지)와 Stratosphere Slips의 Pi 5 LLM 연구가 가장 가깝고, 운영 설계는 AiSOC의 "모든 프롬프트·도구 호출을 원장에 기록, 대응은 사람 승인"과 wazuh-llm-triage의 "저신뢰 시 판단 보류·유한 큐·백프레셔"를 그대로 가져올 가치가 있다. 국내 Suricata+LLM 결합 공개 사례는 Naver·GitHub에서 확인되지 않았다(미확인).

---

## 5. API·대시보드·알림·리포트·운영·테스트·유사 프로젝트

정의서 6.6(리포팅·알림), 6.7(운영), 7장(비기능), 10장(배포·테스트), 16장(레포 구조)에 대응한다.

### 백엔드·API

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| FastAPI | https://github.com/fastapi/fastapi | GitHub | MIT | ★104k / 2026-10 | 적합. Debian 13 apt `python3-fastapi 0.115` 확인 | FR-19, M3 | 정의서 선택 그대로. 비동기·Pydantic 통합·OpenAPI 자동 생성으로 SPA 백엔드에 충분 |
| Pydantic v2 | https://github.com/pydantic/pydantic | GitHub | MIT | ★29k / 2026-10 | 적합 (Rust 코어, aarch64 휠·apt 2.10 확인) | FR-27, 전체 | 설정·API 스키마·이벤트 정규화 모두 한 타입 시스템으로 |
| pydantic-settings | https://github.com/pydantic/pydantic-settings | GitHub | MIT | ★1.5k / 2026-10 | 적합 | FR-27 | YAML 소스 + 환경변수/secrets 디렉터리 소스 내장 → "단일 YAML + 비밀값 분리" 요구에 정확히 대응 |
| SQLModel | https://github.com/fastapi/sqlmodel | GitHub | MIT | ★18.5k / 2026-10 | 적합 | FR-7/16/23, 11장 | SQLAlchemy 2 + Pydantic 결합. 단순 CRUD엔 편하지만 복잡 질의·마이그레이션은 결국 SQLAlchemy/Alembic 직접 사용 |
| SQLAlchemy 2 | (apt `python3-sqlalchemy 2.0.40`) | 공식 | MIT | 2026-10 | 적합 | 저장 계층 | SQLModel 대신 순수 SQLAlchemy 2 + Alembic이 장기적으로 안전. 둘 중 하나로 조기 결정 권장 |
| aiosqlite | https://github.com/omnilib/aiosqlite | GitHub | MIT | ★1.6k / 2026-03 | 적합 (apt 0.21) | 저장 계층 | SQLite를 스레드로 감싼 async 래퍼. WAL 모드 + 단일 writer 패턴이면 Pi에서 충분 |
| APScheduler | https://github.com/agronholm/apscheduler | GitHub | MIT | ★7.7k / 3.11.3 릴리스 2026-06 | 적합 (apt 3.11) | FR-10/32, M6.5 | 4.0은 아직 알파(a6, 2025-04)로 "프로덕션 금지" 명시. 3.x 쓰거나, 재학습·룰 갱신 같은 무거운 배치는 systemd timer가 더 적합 |
| systemd timers | systemd 257 (Debian 13 기본) | 공식 | LGPL | 2026-10 | 내장 | FR-10/25/32 | 일간 재학습·suricata-update·보존 정리는 `OnCalendar` + `Nice=19` + `MemoryMax=1.5G`로 분리하면 7장 학습 부하 상한을 systemd가 강제해 줌 |
| structlog | https://github.com/hynek/structlog | GitHub | MIT/Apache-2.0 | ★5.0k / 2026-10 | 적합 (apt 25.3) | FR-26 | JSON 구조화 로그 → journald로 보내 `journalctl -o json`으로 자가진단에 재활용 가능 |
| loguru | https://github.com/Delgan/loguru | GitHub | MIT | ★24k / 2026-10 | 적합 (apt 0.7.3) | FR-26 | 편하지만 stdlib logging과 이질적. 라이브러리(Suricata 연동 등) 로그 통합엔 structlog가 유리 |
| uvicorn | https://github.com/Kludex/uvicorn | GitHub | BSD-3 | ★11k / 2026-10 | 적합 (apt 0.32, uvloop aarch64 휠) | M3 | 단일 워커 + systemd 소켓 활성화로 충분. gunicorn 불필요 |

### 대시보드 프런트엔드

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| SvelteKit | https://github.com/sveltejs/kit | GitHub | MIT | ★21k / 2026-10 | 빌드는 Pi(Node 24)에서 가능, 런타임은 정적 파일만 | FR-19, M3 | `adapter-static`으로 빌드 → FastAPI가 정적 서빙. 번들 가장 작고 Svelte 5 runes로 상태 관리 단순 |
| React + Vite | https://github.com/vitejs/vite | GitHub | MIT | ★84k / 2026-10 | 동일 | FR-19, M3 | 생태계·AI 코드 생성 품질 최고. 번들은 Svelte보다 크지만 Tailscale 내부 사용이라 체감 차이 작음 |
| htmx | https://github.com/bigskysoftware/htmx | GitHub | 0BSD | ★50k / 2026-10 | Node 빌드 자체가 불필요 | FR-19 | Jinja2 서버 렌더 + htmx면 리포트(FR-21)와 대시보드를 같은 템플릿으로. 다만 추이 차트 상호작용은 별도 JS 필요 |
| Alpine.js | https://github.com/alpinejs/alpine | GitHub | MIT | ★32k / 2026-10 | 동일 | FR-19 | htmx 보완용 소량 상태. 사건 상세 접기/필터 정도 |
| Datastar | https://github.com/starfederation/datastar | GitHub | MIT | ★5.2k / 2026-09 | 동일 | FR-19 | htmx+Alpine 대체 하이퍼미디어 프레임워크. SSE로 실시간 알림 스트림이 자연스럽지만 아직 젊음 |
| NiceGUI | https://github.com/zauberzeug/nicegui | GitHub | MIT | ★16k / 2026-10 | 적합 (FastAPI 위에서 동작) | FR-19 | Python만으로 UI. 프로토타입에 최적이나 Vue/Quasar 런타임이 무겁고 커스텀 UI 한계 |
| Apache ECharts | https://github.com/apache/echarts | GitHub | Apache-2.0 | ★68k / 2026-10 | 브라우저 측 부담만 | FR-19/29 | 히트맵·캘린더·dataZoom·대용량 시계열 모두 내장. 정의서 선택 타당. 트리셰이킹 필수(전체 ~1MB) |
| Chart.js | https://github.com/chartjs/Chart.js | GitHub | MIT | ★68k / 2026-10 | 동일 | FR-19 | 가볍고 쉽지만 수만 점 시계열·brush 줌은 플러그인 의존 |
| uPlot | https://github.com/leeoniya/uPlot | GitHub | MIT | ★10.6k / 2026-10 | 동일, ~50KB | FR-29 | 1분 집계 30일(4만 점)도 매끄러움. 추이 차트는 uPlot, 분포·히트맵은 ECharts로 혼용 가능 |
| Grafana OSS | https://github.com/grafana/grafana | GitHub | AGPL-3.0 | ★78k / 2026-10 | 공식 apt 저장소에 arm64 12.x 제공 (Debian 기본 apt엔 없음) | FR-19/29 대안 | 시계열 탐색엔 최고지만 Go 바이너리 400MB+·메모리 수백 MB. 사건 "5요소 설명" 같은 서술형 UI엔 부적합 |
| Grafana DuckDB datasource | https://github.com/motherduckdb/grafana-duckdb-datasource | GitHub | Apache-2.0 | ★166 / v0.4.6 2026-10-22 | glibc Linux 요구, 미서명 플러그인 허용 필요. arm64 빌드 여부 미확인 | FR-28/29 | Parquet 집계를 Grafana에서 바로 질의 가능. 운영자용 "탐색 패널"로 커스텀 대시보드와 병행 가치 |
| Grafana SQLite datasource | https://github.com/fr-ser/grafana-sqlite-datasource | GitHub | Apache-2.0 | ★161 / 2026-06 | arm64 릴리스 제공 | FR-19 | 알림/자산 SQLite 조회용. 유지보수 속도 느림 |

### 기존 IDS 대시보드

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| EveBox | https://github.com/jasonish/evebox · https://evebox.org | GitHub/공식 | MIT | ★507 / 2026-10, 0.31.0 arm64 .deb 2026-10-12 | 매우 적합. Rust 단일 바이너리, SQLite 백엔드 내장, 11MB | FR-9/19, M1~M3 | Suricata 알림 열람·에스컬레이션·아카이브를 바로 제공. M1에서 "진짜 알림이 보이는 화면"으로 즉시 쓰고, 커스텀 대시보드는 사건·설명·자산에 집중 |
| Scirius CE | https://github.com/StamusNetworks/scirius | GitHub | GPL-3.0 | ★685 / 2026-05 | Django+ES 전제, 무거움 | FR-10/12 | 룰셋 관리 UI는 참고 가치. Elasticsearch 의존이라 Pi 도입 비권장 |
| Clear NDR Community (구 SELKS) | https://github.com/StamusNetworks/Clear-NDR-ISO | GitHub/공식 | GPL-3.0 | ★1.6k / 2025-09 | x86 ISO·Docker, ES/Kibana/Arkime 포함 → 8GB Pi 부적합 | 참고 | SELKS는 2025-01-01부로 개발 종료, Clear NDR로 승계. Suricata+EveBox+Arkime 조합 설계 참고용 |
| OpenSearch Dashboards / Kibana | https://github.com/opensearch-project/OpenSearch-Dashboards | GitHub | Apache-2.0 (Kibana는 ELv2/SSPL/AGPL) | ★2.1k / 2026-10 | JVM 검색엔진 + Node UI. 메모리 수 GB → 4GB 상한과 충돌 | 제외 | SuricataPi류 Pi 프로젝트가 ELK를 썼지만 Pi 4에서도 버거웠음. 채택 안 함 |
| ntopng | https://github.com/ntop/ntopng | GitHub | GPL-3.0 | ★8.3k / 2026-10 | ntop가 Raspberry Pi용 arm64 패키지 제공, 6.2에서 메모리 절반 감축·`--limit-resources` | FR-19 비교 | 흐름·기기 시각화 UI 벤치마크. 다만 자체 캡처 엔진이라 Suricata와 중복 수집 |
| Arkime | https://github.com/arkime/arkime | GitHub | Apache-2.0 | ★7.6k / 2026-10 | OpenSearch 의존, 풀 PCAP 전제 → 부적합 | FR-2 대조 | 풀 PCAP 보관 철학은 FR-2(원시 미저장)와 반대. 세션 뷰어 UX만 참고 |
| Grafana 대시보드 #14893 (Suricata IDS/IPS) | https://grafana.com/grafana/dashboards/14893 | 공식 | 미확인 | Grafana 7/8·ES 7 미만 요구 | 구식 | 참고 | 패널 구성(상위 시그니처·국가·추이)만 참고. 그대로 재사용 불가 |

### 알림

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| python-telegram-bot | https://github.com/python-telegram-bot/python-telegram-bot | GitHub | GPL-3.0 | ★29.5k / 2026-10 | 적합. 단 Debian 13 apt엔 없음 → pip | FR-22, M3 | 비동기·완성도 높음. GPL-3.0이므로 프로젝트 라이선스와 호환 확인 필요 |
| aiogram | https://github.com/aiogram/aiogram | GitHub | MIT | ★5.9k / 2026-10 | 적합 (pip) | FR-22 | MIT·순수 asyncio. 라이선스가 걸리면 이쪽. 송신 전용이면 httpx로 Bot API 직접 호출도 충분 |
| Apprise | https://github.com/caronc/apprise | GitHub | BSD-2 | ★17.7k / 2026-10, apt 1.9.3 | 적합 | FR-22 | Telegram·이메일·ntfy·Gotify·HA·웹훅 100+ 채널을 URL 한 줄로. "심각도별 채널" 요구를 설정만으로 해결. 중복 제거·조용한 시간은 미제공 → 자체 구현 |
| ntfy | https://github.com/binwiederhier/ntfy | GitHub | Apache-2.0 | ★35k / 2026-10 | arm64 바이너리·셀프호스팅 가능 | FR-22 | Telegram 대안 푸시. 자체 서버를 Pi에 두면 외부 의존 0 (단 8장 "외부 전송 OFF" 기본값과 정합) |
| Gotify | https://github.com/gotify/server | GitHub | MIT | ★16k / 2026-10 | arm64 제공 | FR-22 | ntfy와 유사, 안드로이드 전용 앱. 둘 중 ntfy가 생태계 큼 |
| aiosmtplib | https://github.com/cole/aiosmtplib | GitHub | MIT | ★436 / 2026-10, apt 4.0 | 적합 | FR-22 | 이메일 채널 비동기 전송. Apprise 쓰면 불필요 |
| Prometheus Alertmanager | https://github.com/prometheus/alertmanager | GitHub | Apache-2.0 | ★8.7k / 2026-10 | arm64 바이너리 | FR-22/23 참고 | 그룹핑·억제(inhibit)·침묵(silence)·반복 간격 모델이 FR-23 억제 설계의 좋은 참조. 도입보다는 모델 차용 |
| Home Assistant | https://github.com/home-assistant/core | GitHub | Apache-2.0 | ★92k / 2026-10 | 별도 장비 | FR-22 | 인바운드 웹훅(`/api/webhook/<id>`, 토큰 불필요)으로 사건 전달 → HA 자동화/스피커 알림. 웹훅 채널 하나로 커버 |

### 리포트 생성

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| Jinja2 | https://github.com/pallets/jinja | GitHub | BSD-3 | ★11.8k / 2025-06 (안정) | 적합 (apt 3.1.6) | FR-20/21, M6 | 사건 설명문 5요소·일간/주간 리포트 템플릿. htmx 채택 시 대시보드 템플릿과 공유 |
| Python-Markdown | https://github.com/Python-Markdown/markdown | GitHub | BSD-3 | ★4.3k / 2026-10, apt 3.7 | 적합 | FR-21 | Markdown 리포트 → HTML 변환. 표·TOC 확장 내장 |
| WeasyPrint | https://github.com/Kozea/WeasyPrint | GitHub | BSD-3 | ★9.7k / 2026-10, apt 62.3 | 적합 (순수 Python + Pango) | FR-21 선택 | HTML→PDF. 헤드리스 브라우저 불필요. 주간 리포트 PDF 첨부가 필요할 때만 |

### systemd·보안 하드닝

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| systemd 257 capability 유닛 패턴 | systemd-networkd 유닛 (`AmbientCapabilities=CAP_NET_RAW ...`, `ProtectSystem=strict`, `RestrictAddressFamilies=AF_PACKET`) | 공식 | LGPL | Debian 13: 257.13 확인 | 내장 | 7장 보안, FR-24 | `User=netmon` + `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` + `CapabilityBoundingSet=` 동일값 + `NoNewPrivileges=yes`. setcap보다 안전(Arch wiki). `systemd-analyze security`로 점수 확인 |
| unattended-upgrades | https://github.com/mvo5/unattended-upgrades | GitHub | GPL-2.0 | ★366 / 2026-10, apt 2.12 | 적합 | G7, M6 | 보안 패치 자동. Suricata 패키지 업데이트 후 재시작 훅 필요 |
| ansible-role-security | https://github.com/geerlingguy/ansible-role-security | GitHub | MIT | ★960 / 2026-09 | 적합 (ansible apt 12.0) | 7장 유지보수, M6 | SSH·fail2ban·자동 업데이트 기본값. install.sh를 Ansible로 올릴 때 출발점. 단 Pi 1대엔 bash 스크립트가 더 단순 |
| Tailscale (Pi에 설치됨) | https://github.com/tailscale/tailscale | GitHub | BSD-3 | ★38k / 2026-10 | 적합 | 7장 보안 | 아래 "원격 접근" 참고 |

### 디스크·PCAP 순환

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| Suricata pcap-log (`conditional: alerts`) | https://github.com/OISF/suricata (suricata.yaml.in) | GitHub/공식 | GPL-2.0 | 7.0.10 apt 확인 | 적합 | FR-3, M1 | `conditional: alerts`는 **알림이 난 패킷과 그 흐름만** 기록 — 알림 "이전 N초" 컨텍스트는 없음(기능 요청만 열려 있음). `max-files`×`limit`는 스레드별 적용. FR-3 "전후 N초"는 별도 링버퍼 + 알림 시 절단 필요 |
| tcpdump `-C/-W/-G` | https://github.com/the-tcpdump-group/tcpdump | GitHub | BSD-3 | ★3.3k / 2026-10, apt 4.99.5 | 적합 | FR-3/25 | `-i eth0 -C 100 -W 30 -z` 로 링버퍼. BPF로 대용량 스트리밍 제외 가능. 가장 단순하고 검증됨 |
| dumpcap `-b` | https://github.com/wireshark/wireshark | GitHub | GPL-2.0 | ★10k / 2026-10, apt wireshark-common 4.4 | 적합 | FR-3 | `-b duration:60 -b files:30`, pcapng·드롭 카운터 출력. tcpdump 대비 설치 크기 큼 |
| Litestream | https://github.com/benbjohnson/litestream | GitHub | Apache-2.0 | ★14.6k / 2026-10 | arm64 바이너리 (apt 없음) | 백업 | SQLite WAL 스트리밍 복제. 아래 백업 참고 |

### 발열·하드웨어 (이 Pi에서 직접 확인)

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| vcgencmd (raspberrypi/utils) | https://github.com/raspberrypi/utils | GitHub | BSD-3 | ★350 / 2026-10 | 내장 | FR-26 | `measure_temp`=47.7°C, `get_throttled`=0x0 확인. 비트마스크로 과열/저전압 이력 판정 |
| sysfs thermal/hwmon | `/sys/class/thermal/thermal_zone0`, `/sys/class/hwmon/*` | 공식(커널 6.18) | GPL-2.0 | - | 내장 | FR-26, 7장 | 트립 포인트 50/60/67.5/75°C(팬 단계), 110°C(critical) 확인. **NVMe 온도도 hwmon `nvme` 노드로 루트 없이 읽힘**(현재 35.9°C) → smartctl 불필요 |
| Pi 5 액티브 쿨러 (공식) | https://www.raspberrypi.com/news/heating-and-cooling-raspberry-pi-5/ | 공식 | - | - | 적합 | 7장 발열 | 쿨러 없으면 스트레스 시 84~85°C로 스로틀, 쿨러 장착 시 55~68°C 보고(커뮤니티). 80°C 소프트 스로틀. 7장 70°C 상한은 현실적 |
| fstrim.timer / nvme-cli / smartmontools | util-linux, apt nvme-cli 2.13, smartmontools 7.4 | 공식 | GPL | - | 내장 | 7장 저장, FR-26 | `fstrim.timer` **이미 enabled** 확인. SMART 마모율(`percentage_used`)은 주간 리포트 자가진단 항목으로 |
| 하드웨어 워치독 (bcm2835_wdt + systemd) | `/dev/watchdog0`, `RuntimeWatchdogSec` | 공식 | GPL | - | 내장 | G7, FR-24 | 이 Pi는 이미 `RuntimeWatchdogUSec=1min` 설정됨. 서비스 수준은 `WatchdogSec=` + `sd_notify` 로 수집기 행 감지 |

### 원격 접근·인증

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| Tailscale Serve (identity headers) | https://tailscale.com/kb/1312/serve | 공식 | - | 2026 | 적합 | 7장 보안, M3 | `tailscale serve --bg 8000`이면 HTTPS 인증서·`Tailscale-User-Login` 헤더 자동. 스푸핑 헤더는 Serve가 제거, Funnel 트래픽엔 헤더 없음, 태그 장치엔 헤더 없음. FastAPI는 127.0.0.1 바인딩 + 이 헤더 신뢰면 로그인 UI 불필요 |
| Tailscale Funnel | https://tailscale.com/kb/1312/funnel | 공식 | - | - | - | 7장 | 공개 노출 → 7장 "외부 인터넷 노출 금지"와 충돌. 사용 금지 |
| caddy-tailscale | https://github.com/tailscale/caddy-tailscale | GitHub | Apache-2.0 | ★989 / 2026-08 | arm64 | 선택 | 리버스 프록시에서 tailnet 인증 처리. 단일 앱이면 Serve로 충분 |
| magicauth | https://github.com/invakid404/magicauth | GitHub | Unlicense | ★9 / 2025-10 | - | 참고 | Tailscale 기반 제로클릭 OIDC. 소규모·실험적 |
| Authelia | https://github.com/authelia/authelia | GitHub | Apache-2.0 | ★29k / 2026-10 | arm64 있음 | 비권장 | SSO 포털 자체가 Redis 등 의존. Tailscale 전용망에선 과잉 |

### 백업

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| restic | https://github.com/restic/restic | GitHub | BSD-2 | ★37k / 2026-10, apt 0.18 | 적합 | M6 | 설정·SQLite 스냅샷·모델 아티팩트를 NAS/USB로 중복제거 백업. systemd timer로 |
| sqlite3 online backup (`Connection.backup` / `VACUUM INTO`) | Python 3.13 stdlib | 공식 | PSF | - | 내장 | M6 | 서비스 중단 없이 일관 스냅샷. restic 직전에 실행하는 패턴 |
| Litestream | https://github.com/benbjohnson/litestream | GitHub | Apache-2.0 | ★14.6k / 2026-10 | arm64 바이너리 | 선택 | 지속 복제(S3/SFTP/로컬). 1대 운영에선 일간 backup+restic로 충분 |

### 테스트·CI

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| pytest / pytest-asyncio | https://github.com/pytest-dev/pytest-asyncio | GitHub | MIT / Apache-2.0 | ★14.7k·1.7k / 2026-10 | apt 제공 | 전체 | 표준. aiosqlite·FastAPI TestClient와 조합 |
| Hypothesis | https://github.com/HypothesisWorks/hypothesis | GitHub | MPL-2.0 | ★9.1k / 2026-10, apt 6.130 | 적합 | FR-14/28 | 집계 롤업(1m→5m→1h) 불변식·엔트로피 계산·비컨 간격 탐지의 속성 기반 테스트에 적합 |
| tcpreplay | https://github.com/appneta/tcpreplay | GitHub | GPL-3.0 | ★1.4k / 2026-10, apt 4.5.1 | 적합 | G2, M1 | 라이브 인터페이스 재생(통합 테스트). 단위 회귀는 `suricata -r pcap -l tmp -k none` 오프라인이 더 결정적(포럼에서 tcpreplay 경로 누락 사례 보고) |
| suricata-verify | https://github.com/jasonish/suricata-verify | GitHub | 미확인 | 활발 | 적합 | M1 테스트 | PCAP + 기대 eve.json 필터 선언형 검증. 우리 `tests/pcaps/` 회귀 패턴의 교과서 |
| GitHub Actions `ubuntu-24.04-arm` | https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/ | 공식 | - | GA 2025-08 | arm64 네이티브 | CI | 공개 저장소 무료(4 vCPU). aarch64 휠 설치·Suricata apt 설치까지 실제 아키텍처에서 CI 가능. 비공개 저장소는 2026-01부터 유료 제공(2차 출처) |
| ruff | https://github.com/astral-sh/ruff | GitHub | MIT | ★50k / 2026-10 | aarch64 휠 (apt 없음) | CI | lint+format 통합. pre-commit 훅으로 |
| mypy | https://github.com/python/mypy | GitHub | MIT | ★20.7k / 2026-10, apt 1.15 | 적합 | CI | Pydantic 플러그인과 함께. 느리면 CI에서만 |
| pre-commit | https://github.com/pre-commit/pre-commit | GitHub | MIT | ★15.7k / 2026-10, apt 4.2 | 적합 | CI | ruff·mypy·yaml 검증·secrets 탐지(detect-secrets) 묶음 |

### 유사 프로젝트

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| NetAlertX (구 Pi.Alert) | https://github.com/netalertx/NetAlertX | GitHub | GPL-3.0 | ★7.3k / 2026-10 | Pi 5 Docker 가이드 다수, arm64 이미지 | FR-5~8, M2 | ARP/DHCP/Pi-hole 기반 기기 발견·새 기기 알림·플러그인 알림이 M2와 거의 동일. 발견 로직·OUI·알림 템플릿 참고. 다만 Docker 전제·PHP 레거시 |
| Pi-hole v6 | https://github.com/pi-hole/pi-hole | GitHub | EUPL-1.2 | ★61.5k / 2026-10 | 적합 | FR-14 DNS 이상 (데이터 소스) | v6 REST API(`/api/queries`)로 DNS 질의 로그 수집 가능. 미러 포트 없어도 DNS 이상 탐지 데이터원 확보 |
| Security Onion 2.4 | https://github.com/Security-Onion-Solutions/securityonion | GitHub | ELv2 (저장소 "Other") | ★5.0k / 2026-10 | **x86-64 전용**, Eval 8GB·Standalone 24GB | 부적합 | 공식 문서가 ARM 미지원 명시. 사건(case) 데이터 모델·에스컬레이션 UX만 참고 |
| Malcolm | https://github.com/cisagov/Malcolm | GitHub | 미확인 ("Other") | ★2.6k / 2026-10 | v24.05부터 ARM64 지원하나 **최소 8코어·24GB RAM** 명시 | 부적합 | Suricata+Zeek+Arkime+OpenSearch 통합. 구성 요소 연결 방식과 Hedgehog 센서 분리 설계 참고 |
| PiRogue | https://github.com/PiRogueToolSuite/pirogue-os | GitHub | 없음(저장소) | ★161 / 2024-07 | Pi 전용 Debian 패키지 (Suricata+Grafana) | 참고 | 모바일 포렌식용이지만 "Pi + Suricata + 시계열 + Grafana"를 apt 패키지로 묶은 선례. 2024 이후 정체 |
| beep-projects/SuricataPi | https://github.com/beep-projects/SuricataPi | GitHub | GPL-3.0 | ★12 / 2024-04 | Pi + ELK | 참고 | 미러 포트 필수를 하드웨어 노트로 명시. ELK가 Pi에 무거움을 보여주는 반례 |
| ben3636/suricata-pi | https://github.com/ben3636/suricata-pi | Naver/GitHub | 미확인 | API 404 (삭제/이름 변경 추정) | Pi 4 + EveBox | 참고 | Suricata+EveBox 자동 설치 PoC. 인라인(DHCP) 방식이라 5장 방식 B에 해당 |
| Linux Magazine 279 "Building a Rasp Pi IDS" (2024) | https://www.linux-magazine.com/Issues/2024/279/Building-a-Rasp-Pi-IDS | 공식(잡지) | - | 2024 | Pi 3B+/4 | 참고 | ES 대신 SQLite EveBox 권장, 43k 룰 로드 3분(3B+). 미러 포트 없을 때 라우터 PCAP을 더미 인터페이스로 주입하는 우회법 |

### 한국어 자료 (Naver 블로그 검색)

| 이름 | 링크 | 출처 | 라이선스 | 활동 | ARM64/Pi5 적합성 | 관련 FR/단계 | 한 줄 평가 |
|---|---|---|---|---|---|---|---|
| velog @kyhw "pihole3" — Pi 4 + Pi-hole + Suricata | https://velog.io/@kyhw/pihole3 | Naver | - | 미확인(2025~26 추정) | Pi 4 2GB 실측 | FR-9, 7장 메모리 | **Suricata 단독 868MB(2GB의 45.8%)** → 룰 축소. 페이로드 못 보는 환경에선 IP 평판/C2 룰 위주로 — 5장 E 모드와 정확히 같은 상황 |
| velog @kyhw "pihole4" — 경량 ML 도메인 판정 | https://velog.io/@kyhw/pihole4 | Naver | - | 미확인 | Pi 4 | FR-14 DNS, M5 | Pi에서 LLM 대신 경량 ML로 DNS 로그 판정 → 알림. 6.8 학습 설계의 국내 선행 사례 |
| 대시클라우드 "텔레그램 봇 운영 수칙" | https://blog.naver.com/dashcloud/224448709120 | Naver | - | 2026-10 | - | FR-22 | "FastAPI 포트 열지 말고 롱폴링(`run_polling`)으로, 토큰은 코드에 넣지 말 것" — 송신 전용 봇이면 웹훅 불필요하다는 실무 조언 |
| velog @pangmeng_su00 "VEDA week07" | https://velog.io/@pangmeng_su00/VEDA-week07 | Naver | - | 2026-05 | Pi | FR-24 | `.service` 등록 + `Restart=` 로 무한 루프 스크립트 자동 재시작 실습 |
| 海底撈月 — Pi 데몬 systemd 운영기 | https://blog.naver.com/sympathyforthedevil/224426368090 | Naver | - | 2026-09 | Pi | FR-24 | 팀 프로젝트에서 "실행되면 끝"이 아닌 운영 관점으로 systemd 재시작 적용 후기 |
| 댄방이 IT — Pi 5 NVMe 부팅과 발열 | https://blog.naver.com/pocket5021/224275728815 | Naver | - | 2026-05 | Pi 5 | 7장 발열 | NVMe 부팅 속도와 함께 "쿨러·전원 필수"를 조건으로 정리 |
| hwac40 — Pi 5 액티브 쿨러 필수론 | https://blog.naver.com/hwac40/223727831390 | Naver | - | 미확인 | Pi 5 | 7장 발열 | 방열판만으로 장시간 성능 유지 불가, 액티브 쿨러 필수 |
| velog @rydhkstptkd — Pi 5 SSD 세팅 + k3s | https://velog.io/@rydhkstptkd/ | Naver | - | 2025-12 | Pi 5 | 운영 | NVMe 부팅 순서 설정 절차 |
| japkey — OPNsense + Suricata + ET Open | https://blog.naver.com/japkey/224234748029 | Naver | - | 미확인 | x86 공유기 | 5장 방식 C | 공유기 측에서 IDS 돌리는 대안 구성. ET Open 조합이 국내에서도 표준 |
| velog @jee-9 — Suricata + Wazuh | https://velog.io/@jee-9/ | Naver | - | 미확인 | - | FR-19 | "eve.json만 있고 알림·대시보드 없음 → ELK 또는 Wazuh 필요"라는 문제의식이 본 프로젝트 M3의 존재 이유 |
| 모두의 스마트홈 카페 — 홈 네트워크 IDS 구축기 | https://cafe.naver.com/stsmarthome/112925 | Naver | - | 2026-03 | - | 5장 | 가정용 IDS를 스위치(ProMax 16)와 연결한 사례. 미러 포트 확보 사례로 참고 |
| 국내 GitHub 저장소 검색 | GitHub 검색 "라즈베리파이 suricata" 등 | GitHub | - | - | - | - | 한국어 키워드 저장소 **0건**. 직접 비교 가능한 국내 오픈소스 선례 없음 → 본 프로젝트의 차별화 여지 |

### 조사자 메모

- **프런트엔드 권고: SvelteKit(adapter-static) 1순위, React+Vite 2순위, htmx는 리포트 전용.** 대시보드는 Tailscale 내부 소수 사용자용이라 번들 크기보다 "사건 상세·추이 차트·억제 UI" 개발 속도가 중요. 정적 빌드 산출물을 FastAPI가 서빙하면 Pi 런타임에 Node가 필요 없어 어느 쪽이든 Pi 부담은 0. 개발자가 React에 익숙하면 React가 맞고, 새로 배운다면 Svelte 5가 코드량이 적다. htmx+Jinja2는 FR-21 리포트 HTML과 템플릿을 공유할 수 있으니 "리포트 = 서버 렌더, 대시보드 = SPA"로 역할 분리 추천.
- **차트: ECharts(트리셰이킹) + uPlot 혼용.** 1분 집계 30일(기기당 4만 점) 추이는 uPlot(~50KB)이 가장 가볍고, 히트맵·캘린더·분포는 ECharts. Chart.js는 중간 지대라 굳이 셋 다 쓸 이유 없음.
- **EveBox는 M1부터 바로 설치, 커스텀 대시보드를 대체하진 않음.** 0.31.0 arm64 .deb(2026-10-12, 11MB, MIT, SQLite 내장)로 Suricata 알림 열람·에스컬레이션이 즉시 가능하다. 커스텀 M3 대시보드는 EveBox가 못 하는 것(자산·사건 묶기·5요소 설명·억제·시계열 추이)에 집중하고, 원시 알림 드릴다운은 EveBox로 링크하면 된다.
- **Grafana는 대체재가 아니라 "운영자 탐색 패널"로 선택적 병행.** 공식 apt에 arm64 12.x가 있고 DuckDB 데이터소스(v0.4.6, 2026-10)로 Parquet 집계를 바로 그릴 수 있지만, AGPL·수백 MB 메모리·서술형 UI 부재 때문에 M3 대체는 비권장. M4.5 이후 Parquet 검증용으로 고려.
- **Scirius/SELKS/Security Onion/Malcolm은 모두 제외.** SELKS는 2025-01-01 개발 종료(Clear NDR로 승계), Security Onion은 x86-64 전용 명시, Malcolm은 최소 24GB RAM. 참고 가치는 사건(case) 모델과 에스컬레이션 UX뿐.
- **수집 사용자 systemd 패턴(검증된 조합):** `User=netmon`, `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`, `CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/netmon /var/log/netmon`, `RestrictAddressFamilies=AF_PACKET AF_NETLINK AF_UNIX AF_INET AF_INET6`, `PrivateTmp=yes`. CAP_NET_ADMIN은 promiscuous 전환에만 필요하므로 Suricata(자체 설정)와 Python 수동 발견기를 별도 유닛으로 나누고 발견기는 CAP_NET_RAW만 주는 편이 낫다. 바이너리 setcap은 피할 것(Arch wiki 권고). 이 Pi는 systemd 257이라 `systemd-analyze security netmon.service`로 점수화 가능.
- **FR-3 "알림 전후 N초 PCAP"은 Suricata만으로 불가.** `pcap-log: conditional: alerts`는 알림 패킷과 해당 흐름만 기록하며 사전 컨텍스트 기능은 미구현(기능 요청만 존재). 설계: tcpdump `-C/-W` 링버퍼(BPF로 대용량 스트림 제외)를 전용 유닛으로 돌리고, 알림 수신 시 타임스탬프 ±N초를 `editcap`/`tcpdump -r` 로 잘라 증거 디렉터리로 옮기는 2단계 구조. `max-files`·`limit`가 Suricata 스레드별 적용인 점도 디스크 상한 계산 시 주의.
- **Pi 5 발열·NVMe 실측(이 장비):** 유휴 CPU 47.7°C, NVMe 35.9°C, `get_throttled=0x0`. 팬 트립 포인트 50/60/67.5/75°C, critical 110°C가 sysfs에서 확인됨. NVMe 온도는 `/sys/class/hwmon/hwmon1/temp1_input`(name=nvme)로 루트 없이 읽히므로 FR-26 자가진단은 smartctl 호출 없이 hwmon만 폴링하면 된다. 공식·커뮤니티 자료상 쿨러 없이는 84~85°C 스로틀, 쿨러 장착 시 55~68°C → 7장 70°C 상한은 달성 가능. `fstrim.timer`와 `RuntimeWatchdogSec=1min`은 이미 켜져 있음.
- **스케줄러: APScheduler 3.11(안정) + systemd timer 이원화.** APScheduler 4.0은 아직 알파(a6, 2025-04)로 프로덕션 금지 명시. 프로세스 내 짧은 주기(롤업·헬스체크)는 APScheduler 3.x, 재학습·suricata-update·보존 정리처럼 자원 상한이 필요한 작업은 systemd timer + `Nice=19` + `MemoryMax=1.5G` + `CPUWeight=`로 두면 7장 "학습 부하" 요구를 systemd가 강제한다.
- **알림은 Apprise 한 겹으로 통일 권장.** Telegram/이메일/웹훅/ntfy/HA를 설정 URL로 추가·제거할 수 있어 FR-22 "심각도별 채널"이 설정 문제로 바뀐다. 단 중복 제거·조용한 시간·반복 간격은 Apprise에 없으므로 Alertmanager의 group/inhibit/silence 모델을 참고해 `notify/` 안에 작게 구현. python-telegram-bot은 GPL-3.0이고 Debian 13 apt에 없으니, 송신만 필요하면 httpx로 Bot API 직접 호출이 의존성·라이선스 모두 가볍다.
- **Debian 13 apt 커버리지(실측):** suricata 7.0.10, tcpreplay 4.5.1, tcpdump, restic, ansible, apprise, weasyprint, fastapi/pydantic/sqlalchemy/aiosqlite/apscheduler/structlog, hypothesis, mypy, pre-commit, unattended-upgrades, arp-scan, nmap, nvme-cli, smartmontools 모두 apt 설치 가능. **apt에 없는 것:** python-telegram-bot, ruff, duckdb(pip), EveBox(.deb 직접), Grafana(외부 apt), Litestream(바이너리), zeek(패키지 없음 → Zeek 공식 저장소 필요, M7 검토 시 변수). 7장 "apt 또는 pip" 요구는 충족되나 install.sh에 외부 저장소 3개(EveBox, Grafana 선택, Zeek 선택)를 명시해야 한다.
- **원격 접근은 `tailscale serve` 하나로 끝.** HTTPS 인증서 자동, `Tailscale-User-Login` 헤더로 사용자 식별(Serve가 스푸핑 헤더 제거, Funnel·태그 장치엔 미부여). FastAPI는 127.0.0.1에만 바인딩하고 이 헤더를 신뢰하면 Authelia류 SSO는 불필요. Funnel은 7장 금지 사항과 충돌하므로 설치 스크립트에서 명시적으로 막을 것.
- **CI는 `ubuntu-24.04-arm`(공개 저장소 무료, GA 2025-08)에서 네이티브로.** aarch64 휠 설치·`apt install suricata`·`suricata -r tests/pcaps/*.pcap` 오프라인 회귀까지 실제 아키텍처에서 검증 가능. tcpreplay 라이브 재생은 Pi에서 수동 통합 테스트로 한정(포럼에 재생 경로 알림 누락 사례 있음).
- **국내 자료 요약:** 한국어 GitHub 저장소는 0건, 블로그도 Pi 4 + Pi-hole + Suricata(velog @kyhw) 정도가 유일한 실측 선례(Suricata 868MB/2GB Pi 4). "eve.json만 있고 대시보드가 없다"는 문제 인식(velog @jee-9)이 반복되는 점에서 한국어 설명형 리포트 + Pi 5 단일 장비라는 본 프로젝트 포지셔닝은 국내에 빈자리다.

---

## 6. 리뷰

조사 결과를 정의서 v0.2와 대조해 검토한 내용이다. 6.2절의 제안은 정의서 0.3 개정 후보다.

### 6.1 조사 신뢰도와 교차 검증

다섯 영역을 독립적으로 조사했기 때문에 같은 항목이 서로 다른 결론으로 나온 곳이 있었다. 이 Pi에서 직접 확인해 아래처럼 정리했다.

| 항목 | 상충 내용 | 확인 결과 | 문서 반영 |
|---|---|---|---|
| nfstream Python 3.13 휠 | 1장 조사: "cp310~cp312만 있음" / 2·3장 조사: "cp313 aarch64 휠 있음" | `pip download nfstream --only-binary` → `nfstream-6.6.0-cp313-cp313-manylinux2014_aarch64.whl` 수신. **휠 있음** | 1장 표의 nfstream 행을 수정함 |
| Zeek ARM64 패키지 | 2장 조사: "arm64 공식 바이너리 미확인" / 1·3장 조사: "OBS security:zeek Debian_13 arm64 .deb 있음" | `download.opensuse.org/repositories/security:/zeek/Debian_13/arm64/` HTTP 200. apt 공식 저장소엔 없음 | 2장 표를 OBS 경로로 통일 |
| IoT-23 라이선스 | "CC BY 4.0" vs "원 페이지 미기재" | 원 페이지는 인용 요청만, HF Parquet 미러가 CC-BY-4.0 표기 | 두 표 모두 "원 페이지 미기재, 미러 표기 CC BY 4.0"으로 통일. 채택 전 Stratosphere에 서면 확인 권장 |
| CTU-13 라이선스 | "CC-BY" vs "명시 없음" | mcfp 다운로드 페이지 CC-BY 표기, 상위 소개 페이지는 인용 요청 | 동일하게 병기 |
| apt 후보 (이 Pi, 2026-10-30) | — | suricata 1:7.0.10-1+deb13u4, suricata-update 1.3.4, arp-scan 1.10.0, nmap 7.95, tcpreplay 4.5.1. zeek·evebox·python3-duckdb는 apt 없음 | 0장 표 기준 |
| pip aarch64 cp313 휠 (이 Pi) | — | duckdb, polars, river, ruptures, scikit-learn, statsmodels, onnxruntime, skops, nfstream 모두 바이너리 설치 가능 | 0장 표 기준 |

조사 자체의 한계도 기록한다.

- **Pi 5에서 Suricata 처리량을 측정한 신뢰할 만한 공개 자료가 없다.** 유일한 수치(약 150 Mbps에서 양호, Lua 룰 시 드롭 12%)는 방법론이 공개되지 않은 블로그다. G1(1 Gbps에서 드롭 5% 이하)은 현재 근거 없는 목표다.
- **Pi 5에서 한국어 소형 LLM의 tok/s 실측이 없다.** 영어 모델(Gemma 3 1B, Llama 3.2, Qwen2.5)만 측정치가 있다.
- **Naver 검색 커버리지가 낮다.** 서버 렌더링 결과에 블로그 본문이 잘 나오지 않아 일부 영역(자산 발견)은 관련 한국어 글을 전혀 찾지 못했다. 찾은 글도 대부분 교육 과정 기록이나 체감기 수준이다. 한국어 GitHub 저장소는 전 영역에서 ★0~2 수준이었다.
- **Hugging Face에서 즉시 재사용 가능한 네트워크 보안 모델은 없었다.** 데이터셋 미러는 유용하지만, 모델은 과제물 수준이거나 Pi에 올릴 수 없는 크기다. DGA 분류기만 예외적으로 접근 방식(문자 n-gram + 로지스틱)을 차용할 가치가 있다.

### 6.2 정의서에 반영해야 할 변경 제안

번호 순서는 영향이 큰 순이다.

1. **G1 성능 목표를 재정의한다.** "1 Gbps 링크에서 드롭 5% 이하"를 "실사용 평균 50~200 Mbps에서 드롭 5% 이하, ET Open 카테고리 선별 + BPF 제외 필터 + 흐름 바이패스 적용 조건"으로 바꾸고, M1 완료 기준에 tcpreplay `--mbps` 단계별 드롭 측정을 넣는다. 근거: 1장 조사자 메모, Pi 4에서 Suricata 단독 868 MB 실측(5장 한국어 자료).
2. **FR-3 설계를 바꾼다.** Suricata `pcap-log: conditional: alerts`는 알림 패킷과 해당 흐름만 기록하고 "이전 N초"를 제공하지 않는다. tcpdump `-C/-W` 링버퍼 전용 유닛 + 알림 시 ±N초 절단(editcap) 2단계 구조로 FR-3을 다시 쓴다.
3. **Device 엔터티를 복합 신원으로 바꾼다.** 스마트폰의 SSID별 랜덤 MAC 때문에 MAC 단일 키는 FR-8 새 기기 알림을 오탐 폭주시킨다. (MAC, DHCP 호스트명, DHCP option 55 지문, DHCP client-id, mDNS 이름)을 묶은 신원 + `randomized` 태그 + 수동 병합을 11장에 추가한다.
4. **LLM·에이전트 절을 신설한다(6.9 또는 9장 보강).** 핵심 원칙: (a) LLM은 FR-20·FR-21 서술 생성에만 쓰고 탐지·심각도 산정·즉시 알림 경로에는 개입하지 않는다, (b) 기본은 로컬(llama.cpp + 1.3~2B 한국어 모델), 클라우드는 `llm.provider` 명시 opt-in이며 전송 전 내부 IP/MAC/호스트명을 가명화한다, (c) 출력은 `IncidentNarrative` Pydantic 스키마로 강제하고 입력에 없는 IP·도메인이 등장하면 템플릿으로 폴백한다, (d) LLM 입력은 공격자가 통제하는 문자열(DNS 이름, SNI, UA)을 포함하므로 데이터 블록으로 격리하고 도구 호출 권한을 주지 않는다, (e) 즉시 알림은 템플릿으로 먼저 보내고 LLM 서술은 비동기로 덧붙인다.
5. **MCP 경계를 8장 또는 7장 보안에 추가한다.** "센서(Pi)에는 MCP 서버를 상주시키지 않는다. MCP는 개발자 PC의 Claude Code에만 붙이며, 센서 데이터는 Tailscale 너머 읽기 전용으로 노출한다. 네트워크 스캔·쉘 실행 권한을 LLM에 위임하는 MCP(nmap, pentest 계열)는 어떤 환경에서도 금지."
6. **FR-11 위협 인텔에 인증 조건을 반영한다.** abuse.ch URLhaus·ThreatFox는 2025-06-30부터 Auth-Key가 필수다(실측 410). 설치 스크립트 전제조건으로 무료 키 발급을 두고, 키 없이도 Feodo·SSLBL·Spamhaus DROP·misp-warninglists만으로 동작하는 폴백을 명시한다. misp-warninglists(CC0)를 FR-23 오탐 억제의 기본 데이터로 추가한다.
7. **FR-17 GeoIP 1순위를 바꾼다.** MaxMind GeoLite2 EULA(2026-02 개정)는 계정·키 필수, 갱신본 공개 후 30일 내 구버전 폐기, 재배포 사전 서면 동의, 향후 유료화 가능성을 담고 있다. iptoasn(PDDL) + DB-IP Lite(CC BY)를 기본으로, GeoLite2는 사용자 키 입력 시에만 geoipupdate 타이머로 쓴다. IPinfo Lite는 CC BY-SA라 FR-34 내보내기 파일에 SA가 전파될 수 있어 제외한다.
8. **FR-18 심각도 산정 입력에 CISA KEV와 EPSS를 추가한다.** ET Open 룰의 65%에 ATT&CK 전술·기술 ID가 있고 `signature_severity`·`confidence`가 거의 전부 붙어 있으므로(실측 51,552건) 심각도의 1차 출처는 룰 메타데이터, 가중치는 KEV·EPSS로 한다. ATT&CK 이름·설명은 배치로 SQLite에 변환해 두고 핫패스에서 STIX를 로드하지 않는다.
9. **10장 스택 표를 0장 기준으로 갱신한다.** 특히 알림(Apprise), GeoIP(iptoasn + DB-IP), 흐름 특징(nfstream), LLM 계층, 프런트엔드 1순위(SvelteKit adapter-static), EveBox를 M1 개발 도구로 명시.
10. **7장 보안에 systemd 유닛 패턴을 구체화한다.** Suricata와 Python 발견기를 별도 유닛으로 나누고 발견기는 `CAP_NET_RAW`만 부여, `CapabilityBoundingSet` 동일값, `NoNewPrivileges`, `ProtectSystem=strict`, `RestrictAddressFamilies`. setcap 바이너리 방식은 쓰지 않는다. `systemd-analyze security` 점수를 M1 완료 기준에 넣는다.
11. **FR-34 가져오기 포맷을 제한한다.** 외부 모델 가져오기는 skops 또는 ONNX만 허용하고 pickle/joblib 파일은 거부한다(역직렬화 신뢰 경계).
12. **16장 레포 구조에 개발 오케스트레이션 파일을 추가한다.** `.mcp.json`(읽기 전용 DuckDB·SQLite·suricata-mcp), `.claude/agents/`(rule-tuner, fp-reviewer), `.claude/skills/`(replay-pcap, triage-incident), `.claude/settings.json`의 PreToolUse 훅(nmap·arpspoof·비허용 인터페이스 tcpreplay 차단) + permissions deny 병행.
13. **M1 완료 기준에 EveBox 설치와 Community ID 활성화를 넣는다.** EveBox는 arm64 .deb 단일 바이너리(MIT)로 M1부터 원시 알림을 볼 수 있고, Community ID는 M4 상관의 키이자 M7 Zeek 연동의 전제다.
14. **15장 미결 사항에 추가:** Zeek 설치 경로(OBS 저장소 신뢰 여부), 한국어 LLM 모델 최종 선택과 표기 의무("Powered by Kanana" 등) 수용 여부, 프로젝트 자체 라이선스(GPL 의존성인 Suricata·scapy·python-telegram-bot과의 관계).

### 6.3 아직 확인되지 않은 것 (M1 전 직접 측정 필요)

- Pi 5에서 ET Open 카테고리별 Suricata 메모리·드롭률 (tcpreplay 50/100/200 Mbps 단계).
- Suricata 7.0.10 Debian 패키지의 JA4 빌드 옵션 활성 여부. 미활성이면 8.0.7 backports로 갈지 결정.
- 한국어 소형 모델 4종(Kanana-2 1.3B, Midm 2.0 Mini, Kanana 1.5 2.1B, HyperCLOVA X SEED 1.5B)의 Pi 5 `llama-bench` 수치와 1,000토큰 입력 기준 서술 생성 시간.
- Zeek 9 OBS 패키지의 Pi 메모리 상주량 (M7 판단 근거).
- Grafana DuckDB 데이터소스 arm64 빌드 유무.
- skl2onnx의 LOF 변환 지원 여부.
- KISA C-TAS·KISA AI 데이터셋의 개인 신청 자격.
- IoT-23·CTU-13의 제품 동봉 가능 여부(Stratosphere 서면 확인).

### 6.4 라이선스 위험 요약

| 위험 | 대상 | 조치 |
|---|---|---|
| 재배포 금지·계정 필수 | MaxMind GeoLite2, ET Pro, Snort Registered, Mon(IoT)r | 레포·설치 이미지에 동봉하지 않음. 사용자 키 opt-in |
| 비상업(NC) | EXAONE 3.5/4.0, snsec DGA 데이터, HF iot-device-identification | SOHO 사용 가능성이 있으므로 제외 |
| 연구 전용 | Qwen2.5-3B, UNSW-NB15·ToN_IoT(상업 협의) | 제외 또는 평가 전용 |
| 특허·조건부 | JA4+ 중 JA4S/H/X/SSH(FoxIO 1.1, 수익화 시 OEM) | TLS 클라이언트 JA4(BSD-3)만 사용 |
| 카피레프트 전파 | python-telegram-bot(GPL-3.0), Slips(GPL-2.0), RITA(GPL-3.0), NTLFlowLyzer(GPL-3.0), masscan·triagewall·hookprobe(AGPL) | 코드 차용 금지, 알고리즘만 참고. Telegram은 httpx 직접 호출 또는 aiogram(MIT) |
| SA 전파 | IPinfo Lite(CC BY-SA) | 내보내기 데이터에 섞이지 않도록 제외 |
| 표기 의무 | Kanana(Powered by Kanana), HyperCLOVA X SEED, DB-IP Lite(CC BY), CTU-13·IoT-23(CC BY) | 대시보드 About 화면과 리포트 푸터에 고지문 자동 포함 |
| 라이선스 없음 | exp0se/dga_detector, dns-tunneling-detection, 다수 한국어 학생 프로젝트 | 아이디어만 참고, 코드 복사 금지 |

### 6.5 다음 행동

1. 6.2절 1~8번을 정의서 0.3에 반영하고 ADR 3건(GeoIP 소스, LLM 로컬 우선, MCP 경계)을 `doc/adr/`에 작성한다.
2. M1 착수 전 6.3절의 Suricata 드롭률·JA4 빌드 옵션·한국어 LLM 벤치 3건을 측정해 이 문서 0장을 갱신한다.
3. `config/netmon.example.yaml`에 `threat_intel.abusech_auth_key`, `geoip.provider`, `llm.provider`, `llm.pseudonymize` 키를 미리 잡아 둔다.
4. `.mcp.json`과 `.claude/` 최소 구성을 M1과 함께 커밋한다.

---

## 7. 라이브러리 유지 규칙

이 문서는 일회성 조사가 아니라 프로젝트가 끝날 때까지 갱신하는 **기술 라이브러리**다.

- **추가 규칙.** 새 기술을 채택·검토할 때는 해당 영역 표에 8개 열을 모두 채운 행을 추가한다. 라이선스와 활동은 반드시 1차 출처에서 확인하고, 확인하지 못한 값은 `미확인`으로 적는다. 추측값을 적지 않는다.
- **판정 변경.** 채택↔제외 판정이 바뀌면 행을 고치고 6장 아래에 날짜와 이유를 한 줄 남긴다. 아키텍처에 영향이 있으면 ADR을 쓰고 행에서 링크한다.
- **갱신 주기.** 마일스톤이 끝날 때마다 0장 권장 스택과 6.3절 미확인 항목을 다시 본다. 스타 수·버전은 ADR 결정 시점에만 다시 조회한다.
- **실측 표기.** 이 Pi에서 직접 확인한 값은 "실측", "apt ✔", "휠 ✔"로 표시해 2차 자료와 구분한다.
- **기계 판독 형식.** 행 수가 더 늘어나면 `doc/tech_library.yaml`로 옮기고 이 문서는 생성물로 전환하는 것을 고려한다. 현재(약 400행)는 Markdown 단일 파일이 검토·diff에 더 편하다.
- **한국어 자료.** Naver 검색은 수동 보강이 필요하다. 관련 국내 글을 발견하면 각 영역 "한국어 자료" 표에 추가하고, 교육 기록 수준인지 실측·설계 자료인지 평가 열에 구분한다.

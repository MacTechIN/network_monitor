# network_monitor 개발 계획서 (Development Plan, 마이크로 공정 기준)

| 항목 | 값 |
|---|---|
| 문서 버전 | 0.1 (최초 작성 2026-10-30) |
| 근거 문서 | `doc/01_project_definition.md` v0.3, `doc/tech_research.md`(0장 권장 스택·6장 리뷰), `doc/adr/0001-traffic-visibility-gateway-mode.md` |
| 대상 | Raspberry Pi 5 (aarch64, Debian 13 trixie, Python 3.13.5) 단일 노드 + 개발 PC |
| 범위 | M0~M7 전 공정을 마이크로 공정(micro-process)으로 분해하고, 각 공정의 입력·활동·산출물·도구·완료기준·검증·제약 게이트를 명세한다 |
| 작성 단위 | 공정 번호 `P<마일스톤>.<순번>` (예: P1.2 = M1의 두 번째 공정) |

이 계획서는 "무엇을 만들까"(정의서)와 "무엇으로 만들까"(기술 라이브러리)를 "어떤 순서의 어떤 공정으로 만들까"로 바꾼 실행 문서다. 공정 단위는 하루~사흘 안에 끝나고 결과를 기계적으로 검증할 수 있는 크기로 잡았다.

---

## 0. 이 계획서의 전제와 범위 확정

### 0.1 요청 대비 범위 조정 (중요)

최초 요청에는 "WiFi 스푸핑 포함"과 "검열"이 있었으나, 두 가지는 프로젝트의 확정된 하드 제약과 충돌하므로 아래와 같이 조정해 반영한다. 이 조정은 운영자(소유 네트워크 관리자)의 정당한 목적(자기 네트워크 감시·분석·대응 안내)을 그대로 달성하면서, 센서를 공격 도구로 만들지 않기 위한 것이다.

| 요청 표현 | 계획 반영 | 근거 |
|---|---|---|
| WiFi 스푸핑으로 트래픽 수집 | **제외.** 수집은 수동 모드(E) + 조건부 게이트웨이 모드(F, 클라이언트가 명시적으로 Pi 경유) + 향후 미러 포트(A)/인라인 브리지(B)로만 한다 | 정의서 §4·§5(방식 D "채택 안 함"), CLAUDE.md 하드 제약(공격적 능동 MITM 금지) |
| 검열(차단) | **"심층 검사·탐지·설명"으로 재해석.** 트래픽을 끊거나 막지 않는다. 문제를 찾아 심각도를 매기고 사람이 읽을 설명과 권고 조치를 제시한다 | 정의서 §4, CLAUDE.md 하드 제약(탐지·보고만, 차단 금지, IDS이지 IPS 아님) |
| AI 에이전트로 실시간 감시·판단 | LLM은 **서술 생성(FR-20·21) 전용**. 탐지·심각도·즉시 알림 경로에 개입하지 않는다. 실시간 탐지는 Suricata + 규칙 + 통계 모델이 담당 | tech_research §6.2 #4 |

### 0.2 고정 제약 (모든 공정이 통과해야 하는 게이트 → 5장 CC1~CC5)

- 탐지·보고만. 어떤 공정도 트래픽 차단/드롭 규칙을 만들지 않는다.
- 스푸핑·MITM·TLS 복호화 없음. 암호화 트래픽은 메타데이터(SNI·JA3/JA4·인증서·흐름)만 본다.
- 페이로드 저장 없음. 흐름 메타데이터·프로토콜 로그·알림 유발 PCAP 조각(링버퍼)만.
- 소유·관리 네트워크 전용. 설정 첫 키 `monitoring_notice_acknowledged: true` 필수.
- 보수적 기본값(능동 스캔 OFF, 외부 전송 OFF, 페이로드 저장 OFF). 대시보드는 localhost/Tailscale만.
- 수집 프로세스는 전용 사용자 + `CAP_NET_RAW`/`CAP_NET_ADMIN`만.

### 0.3 가시성 전제

현재 상태는 E(수동 모드)다(ADR-0001에서 F 시도 후 당일 원복). 따라서 **M1~M4 개발은 공개 악성 PCAP 재생(tcpreplay)으로 진행**하고, 실트래픽 가시성(A/B 또는 F 재시도)은 별도 트랙에서 확보한다. 가시성이 없다고 개발이 멈추지 않도록, 모든 수집 의존 공정의 완료기준은 "지정 PCAP 재생 시"로 1차 정의하고, 실트래픽 확보 후 재검증한다.

### 0.4 개발 위치 분리

| 위치 | 역할 | 비고 |
|---|---|---|
| Pi 5 (센서) | Suricata·수집·저장·탐지·API·알림 상주. MCP 서버 **상주 금지** | 운영 노드 |
| 개발 PC | 코드 작성, Claude Code + MCP(읽기 전용), PCAP 재생 검증, 룰 튜닝, Dalton | 센서 데이터는 Tailscale 너머 읽기 전용 |

---

## 1. 개발 원칙

1. **공정은 검증 가능한 산출물로 끝난다.** 완료기준(DoD)은 사람 판단이 아니라 명령·수치·파일 존재로 확인한다.
2. **실시간 경로와 배치 경로는 저장 계층에서만 만난다.** 배치 학습이 실시간 탐지를 늦추지 못한다(정의서 §9 데이터 흐름 규칙).
3. **추측 의존성 금지.** 새 라이브러리는 `doc/tech_research.md`에 8열 행을 추가하고 이 Pi에서 설치 확인(휠·apt) 후에만 공정에 넣는다.
4. **제약은 코드로 강제한다.** 스푸핑·스캔·차단은 문서 금지뿐 아니라 `.claude/` 훅과 설정 거부, systemd 능력 제한으로 막는다(5장 CC1·CC5).
5. **측정이 설계를 바꾼다.** §6.3 미확인 항목(Suricata 드롭률, JA4 빌드, 한국어 LLM tok/s)은 해당 공정 착수 전에 스파이크로 측정한다.
6. **한 번에 한 마일스톤.** 마일스톤 완료기준(정의서 §12)을 채우기 전 다음으로 넘어가지 않는다.

---

## 2. 전체 공정 지도

```
M0 정의·준비      P0.1 정의서 0.4  P0.2 ADR 3건  P0.3 설정 키  P0.4 개발 오케스트레이션  P0.5 측정 스파이크 3건  P0.6 레포 뼈대
        │
M1 센서 기동      P1.1 설치  P1.2 Suricata 구성  P1.3 systemd  P1.4 EVE→SQLite  P1.5 흐름→Parquet  P1.6 PCAP 링버퍼  P1.7 EveBox  P1.8 성능측정  P1.9 24h 소크
        │
M2 자산 발견      P2.1 수동 발견기  P2.2 복합 기기 신원  P2.3 OUI 매핑  P2.4 기기 API  P2.5 새 기기 알림
        │
M3 대시보드 v1    P3.1 FastAPI 골격  P3.2 SPA  P3.3 화면 3종  P3.4 알림 디스패처  P3.5 Tailscale Serve
        │
M4 보강·상관      P4.1 GeoIP/ASN  P4.2 위협 인텔  P4.3 심각도(KEV/EPSS)  P4.4 사건 상관  P4.5 설명문(템플릿)  P4.6 LLM 서술(비동기)
        │
M4.5 시계열 축적   P4.5.1 롤업  P4.5.2 계층 보존  P4.5.3 추이 차트  P4.5.4 데이터셋 추출기(스키마 v1)
        │
M5 행위 탐지      P5.1 특징 추출  P5.2 기준선 학습  P5.3 탐지기(비컨·스캔·DNS)  P5.4 억제  P5.5 라벨 캡처  P5.6 시뮬 탐지 검증
        │
M6 리포트·운영    P6.1 리포트  P6.2 디스크 순환  P6.3 자가 진단  P6.4 재설치 스크립트  P6.5 30일 무인
        │
M6.5 재학습       P6.5.1 재학습 배치  P6.5.2 모델 레지스트리  P6.5.3 평가 게이트  P6.5.4 승격·롤백  P6.5.5 내보내기
        │
M7 (선택)         P7.1 Zeek 통합  P7.2 인라인 타당성 보고서

교차 공정(전 구간): CC1 보안 하드닝 · CC2 라이선스 준수 · CC3 성능 측정 · CC4 제약 준수 · CC5 개발 오케스트레이션
```

실시간 경로 = 수집(P1.2) → 탐지(P1.2, P5.3) → 상관(P4.4) → 알림(P3.4). 배치 경로 = 집계(P4.5.1) → 특징(P5.1) → 학습(P6.5.1). 두 경로는 저장 계층(P1.4·P1.5)에서만 만난다.

---

## 3. 마이크로 공정 상세

각 공정은 **입력 / 활동 / 산출물 / 도구·근거 / 완료기준(DoD) / 검증 / 제약 게이트**로 명세한다. 도구는 `doc/tech_research.md` 0장 권장 스택을 1차로 따른다.

### 3.0 M0 — 정의·준비 (지금)

**P0.1 정의서 0.4 반영**
- 입력: tech_research §6.2 제안 1~9, §6.5
- 활동: G1 성능 목표 재정의(§6.2 #1), FR-3 tcpdump 링버퍼 재작성(#2), Device 복합 신원(#3), LLM·에이전트 절 신설(#4), MCP 경계(#5), FR-11 인증 조건(#6), FR-17 GeoIP 소스(#7), FR-18 KEV/EPSS(#8), §10 스택 표 0장 기준 갱신(#9)
- 산출물: `doc/01_project_definition.md` v0.4
- 도구·근거: tech_research §6.2
- DoD: 제안 1~9가 정의서에 반영되고 변경 이력 줄이 남음
- 검증: FR 번호와 §10 표가 0장과 불일치 0건
- 제약 게이트: CC4(재정의가 하드 제약을 약화시키지 않음)

**P0.2 ADR 3건 작성**
- 활동: ADR-0002 GeoIP 소스(iptoasn+DB-IP 기본, GeoLite2 opt-in), ADR-0003 LLM 로컬 우선·서술 전용, ADR-0004 MCP 경계(센서 비상주)
- 산출물: `doc/adr/0002~0004*.md`
- 근거: tech_research §6.5 #1
- DoD: 각 ADR에 결정·대안·결과(consequences) 절 존재
- 검증: 관련 FR·0장 표 행에서 ADR 역참조 링크

**P0.3 설정 키 선점**
- 활동: `config/netmon.example.yaml`에 `monitoring_notice_acknowledged`, `threat_intel.abusech_auth_key`, `geoip.provider`, `llm.provider`, `llm.pseudonymize`, `capture.bpf`, `capture.visibility_mode` 키를 기본값과 함께 정의
- 산출물: `config/netmon.example.yaml`
- 근거: §6.5 #3, 0장 제약
- DoD: 첫 키가 `monitoring_notice_acknowledged: false`, 능동 스캔·외부 전송·페이로드 저장 기본 OFF
- 제약 게이트: CC4

**P0.4 개발 오케스트레이션 구성**
- 활동: `.mcp.json`(mcp-server-motherduck·mcp-sqlite 읽기 전용, suricata-mcp 변경 게이트, filesystem 레포 한정, github), `.claude/agents/`(rule-tuner·fp-reviewer), `.claude/skills/`(replay-pcap·triage-incident), `.claude/settings.json` PreToolUse 훅(nmap·arp 스푸핑·비허용 인터페이스 tcpreplay 차단) + permissions deny
- 산출물: `.mcp.json`, `.claude/**`
- 근거: §6.2 #12, 0장 MCP 행
- DoD: 훅이 `arpspoof`·`nmap`·비허용 인터페이스 `tcpreplay` 호출을 실제로 거부
- 제약 게이트: CC5(센서엔 MCP 없음), CC4

**P0.5 측정 스파이크 3건 (M1 설계 확정 전 선행)**
- 활동: (a) Pi 5에서 Suricata + ET Open에 tcpreplay 50/100/200 Mbps 단계 재생해 드롭률·메모리 측정, (b) Suricata 7.0.10 Debian 패키지 JA4 빌드 옵션 활성 여부 확인, (c) 한국어 소형 모델 4종 `llama-bench` tok/s + 1,000토큰 입력 서술 시간 측정
- 산출물: 측정 결과를 tech_research §0·§6.3에 "실측" 표기로 반영
- 근거: §6.3, §6.1(Pi 5 Suricata·한국어 LLM 실측 공개 자료 없음)
- DoD: G1 목표가 측정 근거를 갖고, JA4 사용 가능 여부와 LLM 모델 1차 선택이 수치로 결정됨
- 검증: 측정 명령·환경을 문서에 재현 가능하게 기록
- 비고: (a)가 G1 재정의(P0.1)의 근거이므로 선행. 미측정 시 M1은 "목표 미검증" 꼬리표로 진행

**P0.6 레포 뼈대**
- 활동: 정의서 §16 레이아웃대로 `netmon/`(ingest·discovery·enrich·timeseries·detect·learn·correlate·notify·report·api·storage), `systemd/`, `tests/`(+`tests/pcaps/`), `data/`(git-ignored) 디렉터리와 빈 패키지 생성, `.gitignore`에 `data/` 추가
- 산출물: 패키지 뼈대, `pyproject.toml`(ruff·mypy·pytest)
- DoD: `ruff`·`mypy`·`pytest`가 빈 상태로 통과, `data/`가 커밋에서 제외
- 제약 게이트: CC2

### 3.1 M1 — 센서 기동 (2주)

목표(정의서 §12): 테스트 PCAP 재생 시 알림이 SQLite에, 흐름 1분 집계가 Parquet에 적재되고 24시간 무중단.

**P1.1 엔진·도구 설치 스크립트**
- 입력: 호스트 사실(suricata 1:7.0.10, suricata-update 1.3.4, arp-scan 1.10.0, nmap 7.95, tcpreplay 4.5.1 apt 후보; zeek·evebox·duckdb는 apt 없음)
- 활동: `scripts/install.sh`에 apt(suricata·suricata-update·arp-scan·nmap·tcpreplay)와 EveBox arm64 .deb 설치, pip 휠(duckdb·polars·nfstream·scikit-learn·river·statsmodels·ruptures·skops·onnxruntime)을 venv에 설치
- 산출물: `scripts/install.sh`
- 도구·근거: 0장 수집·엔진·테스트 행, §6.1 apt·휠 실측
- DoD: 새 venv에서 스크립트 한 번으로 전 의존성 설치, `suricata -V`·`evebox --version` 성공
- 검증: 깨끗한 사용자 계정에서 재실행 멱등
- 제약 게이트: CC2(ET Pro·GeoLite2 미동봉)

**P1.2 Suricata 구성·튜닝**
- 입력: P1.1 설치물, ET Open 룰(suricata-update)
- 활동: AF_PACKET v3 워커 구성, EVE JSON(alert·flow·dns·tls·http·anomaly) 출력, **Community ID 활성화**, BPF `net 192.168.45.0/24 and not host 192.168.45.162`(게이트웨이 모드 재시도 시 NAT 이후 중복 제거), ET Open 카테고리 선별, flowbits 유지, **drop 액션 미사용**
- 산출물: `config/suricata/` 오버레이 + 커스텀 룰 디렉터리
- 도구·근거: 0장 수집·엔진·룰 행, §6.2 #2·#9·#13
- DoD: `suricata -T` 통과, 테스트 PCAP 오프라인 재생(`suricata -r`) 시 EVE에 alert·flow·community_id 생성
- 검증: `suricata -r tests/pcaps/*.pcap` 회귀(suricata-verify 패턴)
- 제약 게이트: CC1, CC4(drop 룰 0건 — grep으로 확인)

**P1.3 systemd 유닛·권한 분리**
- 활동: `netmon` 전용 사용자 생성, Suricata 유닛과 Python 수집/발견 유닛 분리, `User=netmon`·`AmbientCapabilities=CAP_NET_RAW [CAP_NET_ADMIN]`·`CapabilityBoundingSet` 동일·`NoNewPrivileges`·`ProtectSystem=strict`·`RestrictAddressFamilies`, setcap 바이너리 미사용
- 산출물: `systemd/*.service`
- 도구·근거: 0장 운영·보안 행, §6.2 #10
- DoD: 유닛 기동, `systemd-analyze security` 점수 기준(예: ≤ 5.0 "OK") 충족
- 검증: `systemd-analyze security netmon-*.service`
- 제약 게이트: CC1

**P1.4 EVE→SQLite 수집기**
- 활동: EVE JSON tail 파서 → 정규화 → SQLite(WAL) alert·flow·incident 테이블 적재, SQLAlchemy 2 + Alembic 마이그레이션
- 산출물: `netmon/ingest/`, `netmon/storage/` 스키마
- 도구·근거: 0장 시계열·저장 행, API 행
- DoD: 재생한 PCAP의 알림 건수와 SQLite 행 수 일치
- 검증: 알려진 알림 수를 가진 PCAP로 카운트 대조
- 제약 게이트: CC4(페이로드 컬럼 없음)

**P1.5 흐름→Parquet 1분 버킷**
- 활동: nfstream으로 흐름 특징 추출 → polars 정규화 → pyarrow Parquet(hive 파티션 `res=1m/date=YYYY-MM-DD`) 적재, DuckDB 뷰 등록
- 산출물: `netmon/timeseries/`
- 도구·근거: 0장 시계열·저장·특징 행(nfstream cp313 휠 실측)
- DoD: 재생 트래픽이 1분 버킷 Parquet로 적재되고 DuckDB로 질의됨
- 검증: 버킷 합계 = 원 흐름 합계(Hypothesis 불변식)
- 제약 게이트: CC4

**P1.6 PCAP 링버퍼 유닛 (FR-3)**
- 활동: tcpdump `-C/-W` 링버퍼 전용 유닛(크기 상한), 알림 시 editcap으로 ±N초 절단 조각 생성·보관, 보존 30일·용량 캡
- 산출물: `systemd/netmon-pcap.service`, `netmon/notify/` 절단 훅
- 도구·근거: 0장 운영 행, §6.2 #2(Suricata 단독 불가 → 2단계)
- DoD: 알림 1건에 대해 전후 N초 PCAP 조각이 생성되고 링버퍼가 용량 상한에서 순환
- 검증: 용량 초과 주입 시 가장 오래된 파일 삭제 확인
- 제약 게이트: CC4(전체 페이로드 영구 저장 없음, 조각만)

**P1.7 EveBox 원시 알림 뷰어**
- 활동: EveBox를 Suricata EVE에 연결, Tailscale 뒤에서만 접근
- 산출물: `systemd/evebox.service`
- 근거: §6.2 #13(MIT, arm64 단일 바이너리)
- DoD: 재생 알림이 EveBox UI에 표시
- 제약 게이트: CC4(외부 미노출)

**P1.8 성능 측정 (G1 검증)**
- 활동: tcpreplay `--mbps` 50/100/200 단계 재생, 드롭률·메모리·CPU·온도 기록, BPF 제외 필터·흐름 바이패스 효과 비교
- 산출물: 측정 리포트 → tech_research §0 갱신
- 근거: §6.2 #1, §6.3
- DoD: 재정의된 G1(실사용 평균대역에서 드롭 5% 이하) 충족 또는 미달 수치 기록
- 검증: 수치·명령 재현 기록

**P1.9 24시간 소크**
- 활동: 재생 루프 또는 실트래픽(가시성 확보 시)로 24h 연속 가동, 메모리 누수·디스크 증가·온도 감시
- DoD: 24h 무중단, 메모리 상한 내, 크래시 0
- 검증: `systemctl status` + 리소스 로그
- 비고: **M1 완료 판정 게이트.** 정의서 §12 M1 done-criteria 충족 시에만 M2 착수

### 3.2 M2 — 자산 발견 (2주)

목표: 네트워크의 모든 활성 기기가 1시간 내 목록에 나타남.

**P2.1 수동 발견기**
- 활동: scapy 브로드캐스트 BPF(ARP·DHCP), python-zeroconf(mDNS), async_upnp_client(SSDP), pyroute2(netlink 이웃 테이블), 선택적 lldpd 감청. **능동 스캔 없음**(arp-scan·nmap은 opt-in, 기본 OFF)
- 산출물: `netmon/discovery/`
- 도구·근거: 0장 자산 발견 행
- DoD: 재생/실환경에서 관측된 기기가 1시간 내 device 테이블에 등장
- 제약 게이트: CC4(기본 수동, 능동 스캔 opt-in·기록)

**P2.2 복합 기기 신원 (랜덤 MAC 대응)**
- 활동: (MAC, DHCP 호스트명, DHCP option 55 지문, DHCP client-id, mDNS 이름) 복합 키로 Device 식별, `randomized` 태그, 수동 병합 API
- 산출물: `netmon/discovery/identity.py`, Device 스키마 확장
- 근거: §6.2 #3
- DoD: 같은 단말의 SSID별 랜덤 MAC이 새 기기 알림을 유발하지 않음(시나리오 테스트)
- 검증: 랜덤 MAC 2개 + 동일 지문 입력 시 기기 1건으로 병합
- 제약 게이트: CC4

**P2.3 OUI 매핑**
- 활동: IEEE OUI CSV 3종 + Wireshark manuf 로컬 DB로 벤더 매핑, 외부 API(macvendors 등) 미사용
- 산출물: `netmon/enrich/oui.py`, 로컬 OUI DB
- 근거: 0장 자산 발견 행(외부 전송 제외)
- DoD: 알려진 MAC 접두가 올바른 벤더로 매핑
- 제약 게이트: CC2(라이선스)·CC4(외부 미조회)

**P2.4 기기 목록 API**
- 활동: FastAPI 기기 목록·상세 엔드포인트(아직 UI 전)
- 산출물: `netmon/api/devices.py`
- DoD: `GET /devices`가 복합 신원·벤더·최근 활동 반환

**P2.5 새 기기 알림 (FR-8)**
- 활동: 복합 신원 기준 신규 기기 감지 → 알림 큐에 적재(디스패처는 M3)
- DoD: 신규 신원 1건당 알림 1건, 랜덤 MAC 오탐 0
- 검증: P2.2 시나리오 재사용

### 3.3 M3 — 대시보드 v1 + 알림 (2주)

목표: 외부 접속 없이 Tailscale로 기기/알림/사건 조회, Telegram 즉시 알림.

**P3.1 FastAPI 골격**
- 활동: FastAPI + Pydantic v2 + pydantic-settings, aiosqlite, uvicorn 단일 워커, 인증은 Tailscale identity header
- 산출물: `netmon/api/`
- 도구·근거: 0장 API 행
- DoD: `/healthz`·기기·알림·사건 엔드포인트 동작
- 제약 게이트: CC4(바인딩 localhost/tailscale0만)

**P3.2 SPA 프런트엔드**
- 활동: SvelteKit adapter-static(1순위) 정적 빌드, ECharts(트리셰이킹) + uPlot
- 산출물: `web/`
- 도구·근거: 0장 API·대시보드 행, 미결(SvelteKit vs React는 ADR로)
- DoD: 정적 번들이 FastAPI에서 서빙됨
- 비고: SvelteKit/React 최종 선택은 미결 → 착수 시 ADR

**P3.3 화면 3종**
- 활동: 기기 목록, 알림 목록, 사건 상세 화면
- DoD: 세 화면이 실데이터로 렌더

**P3.4 알림 디스패처**
- 활동: Apprise 통합 + 자체 dedup/조용한 시간, Telegram은 httpx Bot API 직접 호출(또는 aiogram MIT). python-telegram-bot(GPL) 미사용
- 산출물: `netmon/notify/`
- 도구·근거: 0장 알림 행, §6.4(GPL 회피)
- DoD: 새 기기·고심각도 알림이 Telegram으로 수신, 중복 억제 동작
- 제약 게이트: CC2(GPL), CC4

**P3.5 Tailscale Serve**
- 활동: Tailscale Serve로 대시보드 노출(identity header), Funnel 미사용
- DoD: Tailscale 네트워크 내에서만 접근, 공인 IP로 접근 불가
- 검증: 외부에서 접근 차단 확인
- 제약 게이트: CC4(인터넷 미노출)

### 3.4 M4 — 보강·상관 (2주)

목표: 알림 10개가 사건 2~3개로 묶이고 5요소 설명 자동 생성.

**P4.1 GeoIP/ASN 보강**
- 활동: iptoasn(PDDL) + DB-IP Lite(CC BY) 로컬 DB, GeoLite2는 사용자 키 opt-in(geoipupdate)
- 산출물: `netmon/enrich/geoip.py`
- 도구·근거: 0장 보강 행, §6.2 #7, ADR-0002
- DoD: 외부 IP에 ASN·국가 태깅, 키 없이 동작
- 제약 게이트: CC2(GeoLite2 미동봉), CC4(로컬 DB·외부 미조회)

**P4.2 위협 인텔**
- 활동: Feodo·SSLBL·Spamhaus DROP·misp-warninglists 기본 적재, URLhaus·ThreatFox는 `abusech_auth_key` 입력 시 opt-in, 키 없는 폴백 명시
- 산출물: `netmon/enrich/threat_intel.py`
- 도구·근거: 0장 룰·위협 인텔 행, §6.2 #6
- DoD: 키 없이 Feodo/SSLBL/Spamhaus/misp-warninglists만으로 매칭·오탐 억제 동작
- 제약 게이트: CC4(내부 관측값 외부 전송 없음)

**P4.3 심각도 산정 (KEV/EPSS)**
- 활동: 1차 출처는 ET 룰 메타데이터(ATT&CK·severity·confidence), 가중치는 CISA KEV + EPSS. ATT&CK는 배치로 SQLite 변환, 핫패스에서 STIX 미로드
- 산출물: `netmon/correlate/severity.py`
- 도구·근거: 0장 보강 행, §6.2 #8
- DoD: 알림에 5단계 심각도 + 근거(룰 메타·KEV/EPSS) 부여
- 제약 게이트: CC3(핫패스 STIX 로드 금지)

**P4.4 사건 상관**
- 활동: Community ID·시간·기기·대상 기준으로 알림을 사건으로 묶기
- 산출물: `netmon/correlate/`
- DoD: 알림 10 → 사건 2~3, 각 사건에 구성 알림 추적
- 근거: Community ID(P1.2)

**P4.5 설명문 생성 (템플릿 우선, FR-15·20·21)**
- 활동: 5요소(무엇·어느 기기·어디로·왜 위험·무엇을) 템플릿 생성, 모든 이상 알림에 점수 + 증거(explainability) 동봉
- 산출물: `netmon/report/narrative.py`, `IncidentNarrative` Pydantic 스키마
- DoD: 즉시 알림이 템플릿 설명으로 먼저 발송
- 제약 게이트: CC4

**P4.6 LLM 서술 (비동기·서술 전용)**
- 활동: llama.cpp(llama-server, GBNF) + 1.3~2B 한국어 모델로 템플릿 뒤에 서술 비동기 덧붙임. 출력은 `IncidentNarrative` 스키마 강제, 입력에 없는 IP·도메인 등장 시 템플릿 폴백. 입력(DNS·SNI·UA)은 데이터 블록으로 격리, 도구 호출 권한 없음. 클라우드는 `llm.provider` 명시 opt-in + 가명화
- 산출물: `netmon/report/llm.py`, 가드레일
- 도구·근거: 0장 LLM 행, §6.2 #4, ADR-0003
- DoD: LLM이 탐지·심각도·즉시 알림 경로에 개입하지 않음(코드 경로 검사), 폴백 동작
- 제약 게이트: CC4(탐지 비개입, 가명화 전 외부 전송 금지)

### 3.5 M4.5 — 시계열 축적 (1주)

목표: 7일치 집계가 끊김 없이 쌓이고 임의 기기 학습 샘플을 재현 가능하게 추출.

**P4.5.1 롤업** — 1분 → 5분/1시간 집계 배치(DuckDB). DoD: 롤업 합계 = 원 버킷 합계(불변식 테스트).
**P4.5.2 계층 보존** — 1분 30일 / 5분 180일 / 1시간 2년, 흐름 90일, 알림 1년, PCAP 30일, 데이터셋+모델 ≤10GB, 전체 50GB 캡. DoD: 보존 경과분 자동 삭제.
**P4.5.3 추이 차트** — 대시보드에 기기/대상/프로토콜별 추이(ECharts·uPlot). DoD: 7일 추이 렌더.
**P4.5.4 데이터셋 추출기 (FR-30·31)** — 특징 스키마 v1 정의, 샘플에 스키마 버전·소스 버킷 기록, 합성/재생 트래픽 `synthetic` 태그. DoD: 임의 기기·기간 샘플을 재현 가능하게 추출, 재추출 시 동일 결과.

### 3.6 M5 — 행위 탐지 (3주)

목표: 7일 학습 후 주입한 시뮬 비컨·스캔 탐지, 오탐 일 10건 이하, 사용자 판정이 학습 샘플 라벨로 저장.

**P5.1 특징 추출**
- 활동: 시계열 버킷에서 기기별 특징(연결 주기·목적지 수·바이트·프로토콜 분포·야간 활동) 추출, polars
- 산출물: `netmon/learn/features.py`
- DoD: 특징 스키마 v1(P4.5.4)로 기기별 특징 행 생성

**P5.2 기준선 학습**
- 활동: scikit-learn IsolationForest + RobustScaler, river 증분 기준선, statsmodels MSTL(계절성). CPU 전용·소형, 딥러닝 미사용
- 산출물: `netmon/learn/baseline.py`
- 도구·근거: 0장 행위 탐지 행
- DoD: 7일 데이터로 기기별 기준선 학습 완료

**P5.3 탐지기 (비컨·스캔·DNS)**
- 활동: STUMPY(비컨 주기성), ruptures PELT(변화점), 자체 DGA n-gram 분류기(harpomaxx 데이터, 코드 복사 없이 접근만 차용), 스캔 탐지
- 산출물: `netmon/detect/`
- 도구·근거: 0장 행위 탐지 행, §6.4(라이선스 없는 저장소 코드 미복사)
- DoD: 주입 시뮬 비컨·스캔을 탐지, 각 알림에 점수+증거(FR-15)
- 제약 게이트: CC2

**P5.4 억제 (FR-23)**
- 활동: misp-warninglists 기본 + 사용자 억제 규칙, 모든 억제에 감사 추적
- 산출물: `netmon/detect/suppression.py`
- DoD: 억제 1건당 사유·시각·주체 기록, 오탐 일 10건 이하
- 제약 게이트: CC4(감사 추적)

**P5.5 라벨 캡처 (FR-31)**
- 활동: 대시보드에서 사용자 판정(정탐/오탐)을 학습 샘플 Label로 저장, 합성 트래픽 `synthetic` 플래그 유지
- 산출물: Label 엔터티, API
- DoD: 판정이 TrainingSample.label로 저장되고 재현 메타 동반

**P5.6 시뮬 탐지 검증**
- 활동: tcpreplay로 알려진 비컨·스캔 PCAP 주입 → 탐지율·오탐 측정
- DoD: **M5 완료 판정 게이트.** 정의서 §12 M5 done-criteria 충족
- 제약 게이트: CC3

### 3.7 M6 — 리포트·운영 (2주)

목표: 새 매체에서 스크립트 한 번 복구, 30일 무인 운영.

**P6.1 리포트** — 일간/주간 Markdown·HTML(Jinja2 + Python-Markdown, 선택 WeasyPrint PDF). 라이선스 고지 푸터 자동 포함(§6.4). DoD: 일·주 리포트 자동 생성.
**P6.2 디스크 순환** — tcpdump 링버퍼·Parquet·모델 용량 상한 순환, 50GB 캡. DoD: 캡 초과 시 오래된 데이터부터 삭제.
**P6.3 자가 진단** — 유닛 상태·EVE 적재 지연·디스크·온도 점검 + 이상 시 알림. DoD: 구성요소 다운 시 알림.
**P6.4 재설치 스크립트** — install.sh + 복구 문서로 새 NVMe/SD에서 1회 복구. DoD: 깨끗한 매체에서 단일 실행 복구.
**P6.5 30일 무인** — 무인 가동 관찰. DoD: 30일 무중단(M6 완료 게이트).
- 제약 게이트: CC1·CC2·CC4 전체 재점검

### 3.8 M6.5 — 재학습 파이프라인 (2주)

목표: 매일 재학습이 자원 상한 내 완료, 성능 저하 모델 미승격, 2주간 오탐 감소 추세.

**P6.5.1 재학습 배치** — systemd timer + cgroup 상한(nice 19, ≤30분/1.5GB, 70°C 초과 시 일시정지), APScheduler 인프로세스. DoD: 야간 재학습이 상한 내 완료.
**P6.5.2 모델 레지스트리** — SQLite 레지스트리 + 버전·메트릭, skops 내부 저장. DoD: 모델 버전·메트릭 조회.
**P6.5.3 평가 게이트** — 신모델 vs 활성모델 메트릭 비교. DoD: 더 나쁜 모델 자동 승격 차단.
**P6.5.4 승격·롤백** — 더 나은 모델만 승격, 롤백 가능. DoD: 승격·롤백 왕복 동작.
**P6.5.5 내보내기 (FR-34)** — skops/ONNX만 허용(pickle/joblib 거부), 수동·기본 OFF, IP/MAC 가명화. DoD: 내보내기가 수동 트리거에서만, 가명화 적용.
- 도구·근거: 0장 모델 관리 행, §6.2 #11, §9 데이터 흐름 규칙(배치가 실시간 지연 금지)
- 제약 게이트: CC3(실시간 비간섭), CC4(가명화·수동)

### 3.9 M7 — Zeek·IPS 검토 (선택)

**P7.1 Zeek 통합** — OBS `security:zeek/Debian_13/arm64` .deb, Community ID 연동, 메모리 상주량 측정. DoD: Zeek conn 로그 수집, Pi 메모리 기준 내.
**P7.2 인라인 타당성 보고서** — 인라인/IPS 모드 타당성만 **문서로** 검토. 실제 차단 구현 금지. DoD: 보고서 산출, 하드 제약(탐지 전용) 재확인.
- 제약 게이트: CC4(IPS는 검토 문서까지만, 구현 안 함)

---

## 4. 교차 공정 (전 구간 상시)

| 코드 | 공정 | 활동 | 검증 |
|---|---|---|---|
| CC1 | 보안 하드닝 | systemd 능력 최소화, `ProtectSystem=strict`, 전용 사용자 | 각 유닛 `systemd-analyze security` 점수 기준 통과 |
| CC2 | 라이선스 준수 | 재배포 금지(GeoLite2·ET Pro·Mon(IoT)r) 미동봉, GPL 코드 미복사(알고리즘만), CC BY/SA·표기 의무 고지 | §6.4 위험표 대조, About·리포트 푸터 고지 자동화 확인 |
| CC3 | 성능 측정 | tcpreplay 단계 재생 드롭률, 배치가 실시간 경로 비간섭 | 드롭 5% 이하(재정의 G1), 배치 중 실시간 지연 측정 |
| CC4 | 제약 준수 | 차단·스푸핑·페이로드 저장·외부 전송·외부 노출 금지, notice ack | 공정별 게이트 체크리스트, drop 룰 grep 0건, 바인딩 점검 |
| CC5 | 개발 오케스트레이션 | `.mcp.json` 읽기 전용, `.claude/` 훅으로 nmap·arpspoof·비허용 tcpreplay 차단, 센서 MCP 비상주 | 훅 거부 동작 테스트, Pi에 MCP 프로세스 0 |

---

## 5. 일정·의존성·임계경로

| 구간 | 기간 | 선행 |
|---|---|---|
| M0 | 진행 중 | — (P0.5 측정은 P0.1 G1 재정의 선행) |
| M1 | 2주 | M0 (특히 P0.5 Suricata 측정, P0.6 뼈대) |
| M2 | 2주 | M1 (P1.4 저장) |
| M3 | 2주 | M2 (P2.4 API) |
| M4 | 2주 | M3 (P3.4 알림), M1 (Community ID) |
| M4.5 | 1주 | M1 (P1.5 Parquet) |
| M5 | 3주 | M4.5 (특징 스키마 v1) |
| M6 | 2주 | M5 |
| M6.5 | 2주 | M5 (라벨), M4.5 (데이터셋) |
| M7 | 선택 | M1 (Community ID) |

- **임계경로:** M0 → M1 → M2 → M3 → M4, 그리고 M1 → M4.5 → M5 → M6.5. M4.5는 M2·M3와 병행 가능(저장 계층만 의존).
- **가시성 트랙은 병행:** 실트래픽 확보(A/B/F 재시도)는 개발 임계경로를 막지 않는다. 미확보 시 전 구간 PCAP 재생으로 진행하고, 확보 후 수집 의존 공정(P1.8·P1.9·P2.1·P5.6)을 실트래픽으로 재검증한다.
- **측정 선행 의존:** P0.5(a) Suricata 드롭 측정 미완 시 G1·M1 완료 판정은 "목표 미검증" 상태로만 가능.

---

## 6. 리뷰 (자체 검토)

### 6.1 요구사항 추적 (FR → 공정)

정의서 FR-1~FR-34가 공정에 빠짐없이 매핑되는지 확인한다(대표 매핑).

| FR 묶음 | 내용 | 담당 공정 |
|---|---|---|
| FR-1~2 수집 | AF_PACKET 수집·EVE | P1.2, P1.4 |
| FR-3 PCAP 조각 | 알림 전후 N초 | P1.6 (tcpdump 2단계) |
| FR-4~7 자산 발견 | 수동 발견·OUI | P2.1, P2.3 |
| FR-8 새 기기 | 신규 알림 | P2.2, P2.5 |
| FR-9~13 시그니처·TI | ET Open·Feodo 등 | P1.2, P4.2 |
| FR-14~15 상관·설명가능성 | 사건·증거 | P4.4, P4.5 |
| FR-16~19 보강·심각도 | GeoIP·ASN·KEV/EPSS | P4.1, P4.3 |
| FR-20~21 서술 | 5요소·LLM | P4.5, P4.6 |
| FR-22~23 운영·억제 | 억제·감사 | P5.4 |
| FR-24~27 리포팅·알림·운영 | 리포트·디스패처·진단 | P3.4, P6.1, P6.3 |
| FR-28~29 시계열 | 롤업·보존 | P4.5.1, P4.5.2 |
| FR-30 재현 샘플 | 스키마 버전·소스 버킷 | P4.5.4 |
| FR-31 합성 플래그 | synthetic 태그 | P4.5.4, P5.5 |
| FR-32~33 재학습·레지스트리 | 배치·평가·승격 | P6.5.1~6.5.4 |
| FR-34 내보내기 | skops/ONNX·가명화 | P6.5.5 |

누락 점검 결과: FR 전 구간이 최소 1개 공정에 매핑됨. 세부 FR 문구 대조는 P0.1에서 정의서 0.4 확정 후 재대조 필요(현재 FR 번호는 v0.2 기준).

### 6.2 기술 스택 커버리지 (tech_research §0 → 공정)

0장 11개 계층이 모두 공정에 반영됨: 수집·엔진(P1.1·P1.2), 룰·TI(P1.2·P4.2), 자산 발견(P2.1~2.3), 보강(P4.1·P4.3), 시계열·저장(P1.5·P4.5), 행위·학습(P5.*·P6.5), 모델 관리(P6.5.2·P6.5.5), API·대시보드(P3.*), 알림·리포트(P3.4·P6.1), LLM·에이전트(P4.6·P0.4), MCP(P0.4), 운영·보안(P1.3·CC1), 테스트·CI(P0.6·CC3). 제외 판정 도구(Snort3·Arkime·python-telegram-bot·GeoLite2 기본·딥러닝)는 어느 공정에도 들어가지 않음을 확인.

### 6.3 제약 게이트 매핑

하드 제약 6개가 공정 게이트로 모두 강제됨: 차단 금지(CC4 + P1.2 drop 룰 0건 grep + P7.2 구현 금지), 스푸핑 금지(CC5 훅 + 가시성 방식 D 미채택), TLS 복호화 금지(P1.2 메타데이터만), 페이로드 저장 금지(CC4 + P1.4·P1.6 스키마), 소유 네트워크 전용(P0.3 notice ack 첫 키), 보수적 기본값·외부 미노출(P0.3 + P3.5 + CC4), 능력 최소화(CC1 + P1.3).

---

## 7. 검증 (Verification)

계획 자체가 타당·실행 가능한지 세 기준으로 검증했다: (1) 이 Pi의 사실과 정합하는가, (2) 완료기준이 측정 가능한가, (3) 하드 제약을 위반하지 않는가.

### 7.1 검증 결과

| # | 검증 항목 | 결과 | 근거 |
|---|---|---|---|
| V1 | 핵심 의존성이 이 Pi에 설치 가능한가 | **통과(실측)** | apt: suricata 7.0.10·arp-scan·nmap·tcpreplay. 휠: duckdb·polars·nfstream(cp313)·sklearn·river·statsmodels·ruptures·skops·onnxruntime. (tech_research §6.1) |
| V2 | EveBox·Zeek가 arm64로 확보되는가 | **통과(실측)** | EveBox arm64 .deb(MIT). Zeek OBS Debian_13/arm64 HTTP 200. apt엔 없음 → 설치 스크립트가 .deb/OBS 처리(P1.1·P7.1) |
| V3 | 각 공정 DoD가 측정 가능한가 | **통과** | 전 공정 DoD가 명령·수치·파일 존재로 정의됨(suricata -T, 행 수 대조, systemd-analyze, 불변식 테스트 등) |
| V4 | 하드 제약 위반 공정이 있는가 | **없음** | drop 룰 0건, 스푸핑·스캔 훅 차단, 페이로드 미저장, 외부 미노출이 공정 게이트로 강제(6.3절) |
| V5 | G1 성능 목표가 근거를 갖는가 | **미검증(차단 요인)** | Pi 5 Suricata 처리량 공개 실측 없음. P0.5(a)에서 측정 전까지 G1은 가정. (§6.1) |
| V6 | 실트래픽 가시성이 있는가 | **미확보(가정으로 진행)** | 현재 E(수동). F는 원복. M1~M4는 PCAP 재생으로 개발, 확보 후 재검증(0.3절·5장) |
| V7 | 한국어 LLM이 Pi 5에서 실용적인가 | **미측정(차단 요인)** | tok/s 실측 없음. P0.5(c) 측정 후 모델 확정. LLM은 서술 전용이라 미측정이 탐지 공정을 막지는 않음 |
| V8 | 라이선스 충돌 공정이 있는가 | **없음(조건부)** | GPL 코드 미복사·재배포 금지 데이터 미동봉·표기 의무 고지를 CC2로 강제. IoT-23/CTU-13 동봉은 Stratosphere 서면 확인 필요(§6.3) |

### 7.2 검증에서 드러난 문제와 처리

1. **WiFi 스푸핑 요청은 계획에 넣지 않았다.** 하드 제약 위반이자 센서 신뢰를 깨는 기법이라 수집 수단에서 제외하고, 허용된 가시성 방식으로 대체했다(0.1절). 센서 성격을 바꾸려면 프로젝트 재정의 ADR과 명시 지시가 필요하다.
2. **"검열(차단)"은 "검사·탐지·설명"으로 재해석했다.** IDS이지 IPS가 아니므로 차단 공정을 넣지 않았다(0.1절, P7.2는 타당성 문서까지만).
3. **G1(성능)과 한국어 LLM 실용성은 미검증 차단 요인**이라 M0의 P0.5 측정 스파이크로 선행 해소하도록 배치했다. 측정 전에는 M1/M4.6을 가정 상태로 진행한다.
4. **실트래픽 가시성 미확보**를 임계경로에서 분리해, 개발이 멈추지 않도록 PCAP 재생 전제로 전 공정 DoD를 세웠다.
5. **FR 번호는 정의서 v0.2 기준**이라, P0.1에서 0.4 확정 후 6.1 추적표를 재대조해야 한다(현재 매핑은 묶음 단위로는 완전).

### 7.3 검증 결론

계획은 **이 Pi에서 설치·측정 가능한 도구만으로 구성되고, 모든 공정이 기계 검증 가능한 완료기준을 가지며, 하드 제약을 어기는 공정이 없다.** 두 개의 미검증 차단 요인(Suricata 성능, 한국어 LLM 실측)은 M0의 측정 스파이크로 선행 해소하도록 배치했고, 가시성 미확보는 PCAP 재생 전제로 우회해 임계경로에서 분리했다. 즉시 착수 가능한 공정은 P0.1~P0.6이며, 그중 P0.5(a) Suricata 드롭 측정이 M1 설계 확정의 선행 조건이다.

---

## 8. 미결 사항과 다음 행동

- 정의서 미결(§15)과 공통: 관리형 스위치 모델, SvelteKit vs React(P3.2 착수 시 ADR), 특징 스키마 v1 구체값(P4.5.4), 기기별 vs 기기유형별 모델, 내보내기 가명화 수준, 가구/사무실 구성원 감시 고지 방법.
- 이 계획 고유 미결: F 재시도 전 WiFi 기기의 L2 구간 확인(ADR-0001), 한국어 LLM 모델 최종 선택과 표기 의무 수용, IoT-23/CTU-13 제품 동봉 가능 여부.
- 다음 행동: (1) P0.1 정의서 0.4 반영, (2) P0.2 ADR 3건, (3) P0.5 측정 스파이크 3건(특히 Suricata 드롭), (4) P0.4·P0.6 개발 뼈대. 이후 M1 착수.

---

*이 계획서는 마일스톤·요구사항·스택이 바뀌면 함께 갱신한다. 공정 추가·삭제 시 2장 공정 지도와 6.1 추적표를 같이 고친다. 아키텍처를 바꾸는 결정은 `doc/adr/`에 남기고 해당 공정에서 링크한다.*

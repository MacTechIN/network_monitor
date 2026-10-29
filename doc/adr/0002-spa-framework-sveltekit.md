# ADR-0002: 대시보드 SPA 프레임워크 — SvelteKit

- 날짜: 2026-10-30
- 상태: 채택
- 관련: 정의서 §15 열린 질문(SvelteKit vs React), 개발계획서 P3.2

## 맥락
- M3 대시보드는 FastAPI(P3.1) 뒤에서 **정적 번들**로 서빙한다. 서버 사이드 렌더링(SSR)·
  Node 런타임 상주는 범위가 아니다. 대시보드는 Tailscale 내부에서만 접근하며(CC4) 인터넷에
  노출하지 않는다.
- 운영 노드는 Raspberry Pi 5 한 대. 번들 크기와 런타임 자원이 작을수록 좋다.
- 차트는 ECharts(트리셰이킹) + uPlot를 쓴다(계획서 P3.2·P4.5.3).
- 정의서 §15가 SvelteKit vs React를 열린 질문으로 남겨 두었고, 계획서 P3.2가 "착수 시 ADR"을
  명시한다.

## 검토한 대안
| 대안 | 결론 |
|---|---|
| **SvelteKit + adapter-static** | 컴파일 타임에 프레임워크 런타임이 대부분 사라져 번들이 작다. adapter-static 으로 순수 정적 빌드(`web/build`) 산출 → FastAPI `StaticFiles` 로 서빙. 단일 Pi·내부 대시보드에 적합 → **채택** |
| React (Vite SPA) | 생태계·채용 친화적이고 ECharts 연동 사례가 많으나, 런타임·번들이 더 크고 이 프로젝트엔 과한 규모. 보류 |
| 서버 템플릿(Jinja) | 차트 상호작용·부분 갱신에 불리. 대시보드 요구에 미달 |

## 결정
1. 프런트엔드는 **SvelteKit + `@sveltejs/adapter-static`** 로 작성하고 prerender 로 정적 빌드한다.
2. 빌드 산출물은 `web/build/` 에 생성하고, FastAPI 가 `StaticFiles` 로 마운트해 같은 오리진에서
   서빙한다(별도 Node 런타임 상주 금지).
3. API 호출은 상대경로(`/devices`·`/alerts`·`/incidents`)로 같은 오리진에 보낸다. 인증은
   Tailscale identity header 에 위임한다(P3.5).
4. 차트는 ECharts(필요한 차트만 import) + uPlot 를 쓴다.

## 결과와 감수 사항
- 장점: 작은 정적 번들, Node 상주 불필요, 단일 오리진이라 CORS·인증 단순.
- SvelteKit 생태계는 React 대비 작다. ECharts 등은 프레임워크 무관 라이브러리라 영향이 적다.
- 빌드 도구(Node/npm)는 **개발 시에만** 필요하다. 센서(Pi) 런타임에는 정적 파일만 올라간다.
- 되돌리기: 정적 번들 + 상대경로 API 라는 계약만 지키면 이후 React 로 교체해도 백엔드는 불변.

## 적용 산출물
- `web/` : SvelteKit 프로젝트(adapter-static)
- `netmon/api/app.py` : 빌드 산출물을 `StaticFiles` 로 마운트(P3.2)

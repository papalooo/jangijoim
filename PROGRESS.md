# 🚀 JANGIJOIM Project Progress

이 파일은 팀 전체의 "공유 메모리"로 활용됩니다. 모든 개발자 및 AI 에이전트는 작업 시작 전 이 내용을 숙지하고, 완료 후 업데이트해야 합니다.

## 🏁 현재 마일스톤: V1.2 Core Stabilization & Cost Optimization

**목표:** 하이브리드 스캔 엔진의 범용성을 유지하면서, 학교 프로젝트의 토큰 예산을 고려하여 분석 수량을 최적화합니다.

---

## 💰 토큰 절약 전략 (Token Optimization)
프로젝트의 진단 범위(Vulnerability Types)를 특정 분야로 한정하지 않습니다. 대신, 전체 취약점 유형을 대상으로 하되 **분석 및 보고 수량만 제한**하여 효율적으로 운영합니다.

- **분석 제한:** 모든 탐지된 취약점 중 범용적으로 정탐 5개, 오탐 5개를 선별하여 상세 분석(LLM) 및 패치를 진행합니다.
- **제한 사유:** 학교 프로젝트 특성상 무분별한 LLM API 호출로 인한 토큰 비용 과다 발생 방지.
- **범용성 유지:** 특정 취약점(예: SQLi만 분석 등)에 특정되지 않고, 도구가 찾아낸 다양한 유형(XSS, IDOR, RCE 등)을 모두 수용합니다.

---

## ✅ 완료된 작업 (Recent Achievements)

### 2026-05-18
- **[Core] 위험도 기반 취약점 우선순위화(Prioritization) 도입**
    *   `core/orchestrator.py`: LLM 분석 대상 선정 시 Critical/High 위험도를 우선하도록 정렬 로직 추가.
    *   `scanner/parser.py`: 'Info' 레벨 탐지 결과에 대해 최대 5개로 제한하는 노이즈 필터 적용.
- **[Mapping] ast_parser.py 리팩토링 및 최적화**
    *   중복 코드 제거 및 휴리스틱 매핑 로직 통합.
    *   불필요한 파일 시스템 순회 최소화로 매핑 속도 개선.
    *   `MappedContext` 스키마 필드 불일치 수정.
- **[Bug Fix] NameError: 'Optional' is not defined 수정**
    *   `core/orchestrator.py` 및 `scanner/executor.py`에서 `Optional` 타입 힌트 사용 시 누락된 `typing` 임포트 추가.
- **[Exploit] 익스플로잇 실행 엔진 보완 (httpx 기반 세션/쿠키 대응)**
    *   `core/schemas.py`: `AuthConfig` 스키마 추가 (헤더, 쿠키, 사전 로그인 스크립트 지원).
    *   `core/orchestrator.py`: `run_scan_pipeline`에 사전 로그인 스크립트 실행 및 세션 획득 로직 통합.
    *   `scanner/executor.py`: `run_exploit` 호출 시 `auth_config`를 참조하여 모든 PoC 요청에 세션 정보가 자동 포함되도록 개선.
    *   `scanner/engine.py`: Nuclei 스캔 시에도 사용자 지정 인증 헤더가 전달되도록 보완.

---

## 🚧 진행 중인 작업 (In Progress)

- **[Frontend] 실시간 대시보드 고도화**
    - WebSocket 이벤트를 수신하여 스캔 단계별 프로그레스 바 및 실시간 로그 뷰어 구현.
- **[Mapping] LSP 기반 소스 매핑 엔진 연구**
    - AST 파싱을 넘어 언어 서버 프로토콜을 활용한 더 정확한 코드 위치 추적.

---

## 📅 향후 로드맵 (Long-term Development Plan)

1.  **[Mapping 고도화] Tree-sitter 기반 언어 독립적 매핑 엔진 구축**
    *   개별 언어 파서(Python, JS/TS)를 Tree-sitter로 통합하여 Java, Go, PHP 등 모든 지원 언어에 대해 동일한 수준의 정밀한 AST 매핑 제공.
2.  **[Data 정제] 데이터 흐름(Data Flow) 힌트 추적**
    *   사용자 입력이 어떤 변수로 할당되는지 LLM에게 전달할 맥락(Context) 정보 강화.
3.  **[Exploit 고도화] 익스플로잇 실행 엔진 보완**
    *   `requests`를 대체할 세션/쿠키/브라우저 환경 대응 익스플로잇 엔진(httpx/playwright) 도입.
4.  **[Validation 자동화] 패치 검증 파이프라인 통합**
    *   패치 적용 후 생성된 PoC를 재실행하여 '실패'를 검증하는 회귀 테스트 완전 자동화.
5.  **[Feedback Loop] 자가 수정(Self-healing) 익스플로잇**
    *   PoC 실행 실패 시 결과를 피드백하여 LLM이 페이로드를 스스로 수정하도록 유도.

---
*마지막 업데이트: 2026-05-18 (Gemini CLI)*

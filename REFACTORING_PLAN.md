# 🛠 JANGIJOIM 아키텍처 리팩토링 계획 (Refactoring Plan)

이 문서는 파이프라인의 견고함(Robustness)과 안정성을 확보하기 위한 핵심 리팩토링 계획을 상세히 기록합니다.

## 1. 내결함성(Fault Tolerance) 확보 (작업 예정)
현재 FastAPI의 `BackgroundTasks`에 전적으로 의존하는 단일 프로세스 구조를 분산 처리 구조로 개편합니다.
- **목표:** 스캔 중 서버가 다운되거나 재시작되어도 진행 중이던 작업을 잃지 않고 재개(Resume)할 수 있는 멱등성 확보.
- **상세 계획:**
  - Redis를 도입하여 스캔 Job 큐 관리 (또는 최소한 SQLite 기반의 Job Queue 구현).
  - 스캔의 각 단계(Scanning -> Mapping -> Verifying -> Testing -> Reporting)를 상태 머신(State Machine)으로 분리.
  - 에러 발생 시 특정 단계부터 재시도(Retry)할 수 있는 로직 추가.

## 2. 매핑(Mapping) 전략 고도화 (작업 예정)
단순 문자열 및 휴리스틱 검색으로 인한 오매핑(Mis-mapping)과 커버리지 누락을 해결합니다.
- **목표:** 정확한 소스코드 라인과 함수/클래스를 찾아내어 LLM의 할루시네이션(Hallucination) 방지.
- **상세 계획:**
  - 언어별 특성을 반영한 정밀 AST(Abstract Syntax Tree) 파싱 또는 LSP(Language Server Protocol) 기반 인덱싱 도입 고려.
  - 라우터 데코레이터(`@app.get`, `app.post`)와 실제 컨트롤러 로직을 잇는 정적 분석(Call Graph) 툴 통합.

## 3. 가시성(Observability) 및 Web UI 강화 (진행 중)
단순 터미널 로그(`docker logs`)에 의존하던 모니터링 체계를 개편하여, Web UI에서 실시간으로 세밀한 상태와 병목 지점을 파악할 수 있게 합니다.
- **목표:** 스캔 파이프라인의 각 단계별 진행률, LLM 판별 현황, PoC 테스트 결과를 Web UI에 실시간 스트리밍.
- **상세 계획 (진행 중):**
  - **Backend:** `core/ws_manager.py` 및 `core/orchestrator.py`를 수정하여, 각 취약점 항목의 분석 시작/종료, LLM 에이전트의 현재 작업 상태, 상세 로그 메시지를 WebSocket으로 브로드캐스트.
  - **Frontend:** React 기반 Web UI에서 WebSocket 이벤트를 수신하여, 단순 상태(Status)뿐만 아니라 터미널 콘솔 형태의 '실시간 로그 뷰어'와 '단계별 프로그레스 바' 구현.

# 🛠 JANGIJOIM 아키텍처 리팩토링 계획 (Refactoring Plan)

이 문서는 파이프라인의 견고함(Robustness)과 안정성을 확보하기 위한 핵심 리팩토링 계획을 상세히 기록합니다.

## 1. 내결함성(Fault Tolerance) 확보 (작업 예정)
현재 FastAPI의 `BackgroundTasks`에 전적으로 의존하는 단일 프로세스 구조를 분산 처리 구조로 개편합니다.
- **목표:** 스캔 중 서버가 다운되거나 재시작되어도 진행 중이던 작업을 잃지 않고 재개(Resume)할 수 있는 멱등성 확보.
- **상세 계획:**
  - Redis를 도입하여 스캔 Job 큐 관리 (또는 최소한 SQLite 기반의 Job Queue 구현).
  - 스캔의 각 단계(Scanning -> Mapping -> Verifying -> Reporting)를 상태 머신(State Machine)으로 분리.
  - 에러 발생 시 특정 단계부터 재시도(Retry)할 수 있는 로직 추가.

## 2. 매핑(Mapping) 전략 고도화 (작업 예정)
단순 문자열 및 휴리스틱 검색으로 인한 오매핑(Mis-mapping)과 커버리지 누락을 해결합니다.
- **목표:** 정확한 소스코드 라인과 함수/클래스를 찾아내어 LLM의 할루시네이션(Hallucination) 방지.
- **상세 계획:**
  - 언어별 특성을 반영한 정밀 AST(Abstract Syntax Tree) 파싱 또는 LSP(Language Server Protocol) 기반 인덱싱 도입 고려.
  - 라우터 데코레이터(`@app.get`, `app.post`)와 실제 컨트롤러 로직을 잇는 정적 분석(Call Graph) 툴 통합.

## 3. 가시성(Observability) 및 Web UI 강화 (고도화 단계)
단순 터미널 로그(`docker logs`)에 의존하던 모니터링 체계를 개편하여, Web UI에서 실시간으로 세밀한 상태와 병목 지점을 파악할 수 있게 합니다.
- **목표:** 스캔 파이프라인의 각 단계별 진행률, LLM 판별 현황, PoC 테스트 결과를 Web UI에 실시간 스트리밍.
- **현재 진행 상황:**
  - **Backend:** `core/ws_manager.py`를 통한 실시간 이벤트 브로드캐스트 로직 구현 완료.
  - **Frontend:** WebSocket 터미널 뷰어(`Terminal.tsx`) 및 단계별 인디케이터(`StatusStepper.tsx`) 구현 완료.
- **향후 고도화:**
  - 스캔 히스토리의 시각화 및 상세 보고서 PDF/Word 즉시 다운로드 기능 통합.

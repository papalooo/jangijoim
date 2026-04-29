# ♊ Gemini Project Instructions

이 프로젝트는 **LLM 기반 웹 취약점 진단 및 자동 패치 플랫폼**입니다. 아래 규칙은 이 저장소에서의 작업 및 협업 방식을 규정하며, 모든 AI 어시스턴트와 팀원은 이를 준수해야 합니다.

## 🏗 아키텍처 및 모듈 구조

프로젝트는 4개의 주요 Role로 구성된 마이크로 모듈 구조를 따릅니다.

1.  **`core/` (Role 1 - Orchestration):** 전체 파이프라인 제어, 공통 Pydantic 스키마(`schemas.py`), 데이터베이스 및 CLI(`cli.py`).
2.  **`scanner/` (Role 2 - Scanning & Execution):** Nuclei/Semgrep 등 스캐너 구동, HTTP 패킷 파싱, LLM 생성 페이로드 실행.
3.  **`intelligence/` (Role 3 - LLM & Reporting):** LLM 프롬프트 엔지니어링, 정오탐 판별, 패치 생성, 보고서 렌더링.
4.  **`mapping/` (Role 4 - Source Mapping):** DAST 결과와 소스코드 매핑 (AST 분석), 코드 패치 적용 및 롤백.

## 🛠 기술 스택 및 컨벤션

-   **언어:** Python 3.10+
-   **핵심 라이브러리:**
    -   `FastAPI` (비동기 처리)
    -   `Pydantic v2` (데이터 검증 및 스키마)
    -   `Typer` & `Rich` (CLI UI/UX)
    -   `google-genai` & `google-generativeai` (LLM 엔진)
-   **데이터 규격 (SSOT):** 모듈 간 모든 데이터 교환은 `core/schemas.py`에 정의된 Pydantic 모델을 사용합니다. **임의의 `dict` 사용을 금지**하며, 타입 힌트를 엄격히 적용합니다.
-   **비동기 프로그래밍:** I/O 바운드 작업(스캐너 호출, LLM API, DB 접근)은 `async/await`를 사용하여 비동기로 처리합니다.
-   **보안:** `.env` 파일을 통해 크리덴셜을 관리하며, 소스코드 내 API 키 하드코딩은 절대 금지합니다.

##  Git 및 협업 규칙

-   **브랜치 전략:** GitFlow 준수. `main` (배포), `develop` (통합), `feature/roleX-...` (기능 개발).
-   **커밋 메시지:** `타입: 요약` 형식 준수 (`feat`, `fix`, `refactor`, `docs`, `chore`).
-   **PR 및 리뷰:** `develop` 브랜치 병합 시 최소 1인 이상의 승인이 필요합니다. 단독 Merge는 금지됩니다.

## 📝 작업 가이드라인 (AI용)

1.  **수정 범위 제한:** 요청받은 Role의 디렉토리 외부 코드를 수정할 때는 반드시 `core/schemas.py`와의 호환성을 먼저 확인하십시오.
2.  **테스트 우선:** 코드 변경 후에는 `tests/` 폴더의 관련 테스트를 실행하거나, `target_app_mock/`을 활용하여 동작을 검증하십시오.
3.  **문서화:** 새로운 함수나 클래스 추가 시 Google 스타일 Docstring을 작성하고, 타입 힌트를 생략하지 마십시오.
4.  **에러 핸들링:** 파이프라인 중단 방지를 위해 적절한 `try-except` 블록을 사용하고, 실패 사유를 `ScanMetadata`의 `error_log`에 기록하십시오.

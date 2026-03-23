# 📌 프로젝트 Git 협업 및 브랜치 전략 가이드

이 문서는 "LLM 기반 웹 취약점 진단 및 자동 패치 플랫폼" 개발을 위한 팀 협업 규칙입니다. 코드 충돌과 파이프라인 붕괴를 막기 위해 모든 팀원은 아래의 GitFlow 전략과 커밋 규칙을 엄격히 준수해야 합니다.

---

## 1. 브랜치 전략 (GitFlow)
우리는 5가지 형태의 브랜치를 사용하여 코드를 격리하고 통합합니다.

* **`main`**: 최종적으로 실행 가능한 안정적인 배포 버전만 올라가는 브랜치입니다. (직접 Push 절대 금지)
* **`develop`**: 다음 배포를 위해 각자의 코드가 통합되는 **중심 브랜치**입니다. 개발 중인 최신 코드는 항상 여기에 모입니다. (직접 Push 금지, PR로만 병합)
* **`feature`**: 팀원들이 각자 할당된 기능(Role)을 개발하는 로컬 브랜치입니다. `develop`에서 파생됩니다.
* **`release`**: 통합 테스트 및 QA를 진행하기 위한 브랜치입니다.
* **`hotfix`**: `main` 브랜치에서 치명적인 버그가 발생했을 때 긴급 수정하는 브랜치입니다.

---

## 2. 브랜치 명명 규칙 (Branch Naming)
새로운 작업을 시작할 때 브랜치 이름은 반드시 직관적인 영문 소문자와 하이픈(`-`)으로 작성합니다.

* **규칙:** `타입/role번호-작업내용`
* **예시:**
  * `feature/role1-cli-skeleton` (CLI 뼈대 작업)
  * `feature/role4-ast-parser` (AST 파싱 로직 작업)
  * `fix/role2-nuclei-timeout` (스캐너 타임아웃 버그 수정)

---

## 3. 커밋 메시지 규칙 (Commit Convention)
커밋 메시지는 다른 팀원이 코드의 변경 목적을 한눈에 파악할 수 있도록 작성합니다.

* **규칙:** `타입: 작업 요약`
* **타입 종류:**
  * `feat:` 새로운 기능 추가
  * `fix:` 버그 수정
  * `refactor:` 코드 구조 개선 (기능 변경 없음)
  * `docs:` 문서 수정 (README.md 등)
  * `chore:` 패키지 매니저, 빌드 등 자잘한 수정
* **예시:** `feat: OpenAI API JSON 응답 강제화 로직 추가`

---

## 4. 작업 프로세스 (Step-by-Step)
코드를 작성하고 서버에 올리기까지의 필수 사이클입니다.

1. **최신화:** 작업 시작 전 로컬의 `develop` 브랜치를 최신 상태로 동기화합니다.
   `git checkout develop`
   `git pull origin develop`
2. **브랜치 생성:** 본인의 작업용 브랜치를 생성하고 이동합니다.
   `git checkout -b feature/roleX-작업내용`
3. **작업 및 커밋:** 코드를 작성하고 규칙에 맞춰 커밋합니다.
4. **Push:** 원격 저장소에 본인의 기능 브랜치를 업로드합니다.
   `git push -u origin feature/roleX-작업내용`
5. **PR (Pull Request) 생성:** GitHub 웹사이트에서 본인의 브랜치를 `develop` 브랜치로 병합해 달라는 PR을 엽니다.

---

## 5. Pull Request (PR) 및 코드 리뷰 규칙
* PR을 생성할 때는 제공된 PR 템플릿을 사용하여 **어떤 모듈을 어떻게 수정했는지** 명확히 작성합니다.
* **단독 Merge 금지:** PR은 본인이 직접 Merge할 수 없습니다. 반드시 **PM 또는 담당 모듈과 연관된 팀원 1명 이상의 리뷰 및 승인(Approve)**을 받아야만 `develop`에 병합됩니다.
* 리뷰어는 코드가 합의된 JSON 스키마를 준수하는지, 무한 루프 등 치명적 결함이 없는지 확인합니다.

---

## 6. Issue 트래킹 보드 활용
단순한 코드 작성 외에 모듈 단위의 작업 목표나 연구 과제는 GitHub Issues 탭에 등록하여 진행 상황을 추적합니다.

* 작업 등록 시 적절한 Label(`Role 1`, `bug`, `documentation` 등)을 부착합니다.
* **실습 및 연구 과제 등록 예시:**
  * `[실습] GitHub MCP 취약점 재현 및 파이프라인 연동 테스트`
  * `[실습] 최근 CVE 구조 분석 및 AST 매핑 정밀도 검증`
* PR 생성 시 관련된 Issue 번호를 내용에 적어 자동 링크되도록 합니다. (예: `Resolves #3`)

---

## ⚠️ 절대 주의사항
1. **API 키 하드코딩 금지:** `.env` 파일에 저장된 API 키나 크리덴셜을 절대로 코드에 직접 입력하여 커밋하지 마십시오.
2. **테스트 후 PR:** 로컬 환경에서 모의 데이터(Mock)로 스크립트가 정상 실행되는 것을 확인한 뒤에만 PR을 요청하십시오.

## [ Branch Timeline ]

```
main      hotfix       release       develop        feature (로컬 작업)
  │                                     │
  ├────────────────────────────────────>│ (최초 레포지토리 세팅 및 분기)
  │                                     │
  │                                     ├──> [feature/role1-cli-setup] (Role 1 작업 중)
  │                                     ├──> [feature/role2-dast-parser] (Role 2 작업 중)
  │                                     ├──> [feature/role3-llm-prompts] (Role 3 작업 중)
  │                                     ├──> [feature/role4-ast-mapping] (Role 4 작업 중)
  │                                     │
  │                                     │<── (PR 승인 후 병합) Role 1
  │                                     │<── (PR 승인 후 병합) Role 3
  │                                     │<── (PR 승인 후 병합) Role 2
  │                                     │<── (PR 승인 후 병합) Role 4
  │                                     │
  │                        ┌────────────┤ (통합 QA 준비)
  │                        │            │
  │                  [release/v1.0.0]   │
  │                        │            │
  │                        ├──> [버그 수정 커밋들...]
  │                        │            │
  │<───────────────────────┼───────────>│ (QA 완료 후 main과 develop 모두에 병합)
  │                        │            │
  │  [긴급 에러 발생!]      │            │
  ├──────┐                 │            │
  │ [hotfix/api-crash]     │            │
  │      │                 │            │
  │<─────┴─────────────────────────────>│ (긴급 패치 후 main과 develop 모두에 병합)
  │                                     │
 (v1.0.1 배포 유지)                    (v1.1.0 다음 기능 개발 계속...)
 ```

 ## 예상 프로젝트 구조
 ```
 apat-remediation-tool/
├── .git/                           # Git 로컬 저장소 (자동 생성)
├── .github/
│   └── pull_request_template.md    # [추가] PR 생성 시 팀원들이 작성할 표준 양식
├── .gitignore                      # API 키(.env), 가상환경(.venv), 캐시 등 제외 처리
├── README.md                       # 프로젝트 개요, 설치 및 실행 가이드
├── CONTRIBUTING.md                 # 깃 브랜치 전략, 커밋 룰, 협업 가이드라인
├── requirements.txt                # Python 패키지 의존성 목록
├── .env.example                    # 환경변수 템플릿 (API 키 구조만 명시, 실제 값 X)
├── main.py                         # 애플리케이션 진입점 (CLI 실행용)
│
├── core/                           # [Role 1] 오케스트레이션 및 공통 규격
│   ├── __init__.py
│   ├── cli.py                      # Typer 기반 커맨드라인 인터페이스 및 진행률 UI
│   ├── orchestrator.py             # FastAPI BackgroundTasks 기반 8단계 파이프라인 제어
│   └── schemas.py                  # (SSOT) 팀원 공통 사용 Pydantic JSON 모델 규격
│
├── scanner/                        # [Role 2] 스캐너 제어 및 트래픽 검증
│   ├── __init__.py
│   ├── dast_engine.py              # Nuclei 스캐너 구동 및 결과 수집 래퍼
│   ├── sast_engine.py              # Semgrep 스캐너 구동 및 결과 수집 래퍼
│   ├── parser.py                   # HTTP 에러 패킷 및 HTML 슬라이싱 로직
│   └── executor.py                 # LLM이 만든 익스플로잇 페이로드 발사 및 성공 검증
│
├── mapping/                        # [Role 4] 소스코드 역추적 및 조작
│   ├── __init__.py
│   ├── ast_parser.py               # 타겟 라우팅 파일 및 라인 번호 역추적 (AST)
│   ├── correlation.py              # DAST URL과 SAST 라인 번호 교차 검증 및 병합
│   └── patch_manager.py            # 패치 코드 임시 적용(Overwrite) 및 롤백 로직
│
├── intelligence/                   # [Role 3] LLM 추론 엔진 및 보고서 렌더링
│   ├── __init__.py
│   ├── llm_client.py               # OpenAI/Anthropic API 통신 및 JSON 출력 강제화
│   ├── prompts.py                  # 정오탐 판단, 페이로드 생성, 패치 생성용 시스템 프롬프트
│   ├── reporter.py                 # Markdown 및 PDF 보고서 생성 로직
│   └── templates/                  # 보고서 디자인용 Jinja2 (.html, .md) 템플릿 폴더
│
└── target_app_mock/                # 테스트용 타겟 웹 서비스 (로컬 QA용)
    ├── app.py                      # 더미 웹 서버 구동 파일
    ├── requirements.txt            # 더미 서버용 패키지
    └── src/
        ├── auth.py                 # 의도적으로 하드코딩된 취약점 파일 (SQLi 등)
        └── board.py                # 의도적으로 하드코딩된 취약점 파일 (XSS 등)
```        

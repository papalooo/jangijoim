# 📌 융합프로젝트 기여 가이드라인 (Contributing Guide)

본 프로젝트 "LLM 기반 웹 취약점 진단 및 자동 패치 플랫폼"에 참여하는 모든 팀원은 이 문서를 숙지하고 엄격히 준수해야 합니다. 

## 1. 기본 원칙
* **모듈 격리:** 각자 배정된 Role의 디렉토리(`core/`, `scanner/`, `intelligence/`, `mapping/`) 내에서만 작업합니다. 타인의 도메인 코드를 임의로 수정하지 않습니다.
* **단일 진실 공급원 (SSOT):** 모듈 간 통신에 사용되는 모든 데이터 규격은 `core/schemas.py`의 Pydantic 모델을 절대적으로 따릅니다. 임의의 딕셔너리(`dict`) 사용은 금지됩니다.
* **보안:** `.env`에 등록된 LLM API 키나 기타 크리덴셜을 소스코드 내에 하드코딩하여 커밋할 경우 즉각적인 과금이 발생하므로 절대 금지합니다.

## 2. 브랜치 전략 (GitFlow)
우리는 코드 충돌과 파이프라인 붕괴를 막기 위해 다음 브랜치를 사용합니다.

* `main`: 릴리즈가 완료된 안정적인 최종 배포 버전 (직접 푸시 불가)
* `develop`: 모든 기능이 통합되는 개발 중심 브랜치 (직접 푸시 불가, PR 병합만 허용)
* `feature/{role-name}`: 각자 할당된 기능을 개발하는 로컬 브랜치
* `hotfix/{bug-name}`: 치명적 오류 발생 시 긴급 수정을 위한 브랜치

## 3. 작업 프로세스 (Step-by-Step)
코드를 작성하고 서버에 병합하기까지의 필수 사이클입니다.

1. **최신화:** 작업 시작 전 원격의 `develop` 브랜치를 로컬과 동기화.
   ```bash
   git checkout develop
   git pull origin develop
2. **브랜치 생성:** 본인의 작업용 브랜치 생성.
    ```bash
    git checkout -b feature/role3-prompt-tuning
    ```
3. **코드 작성 및 로컬 테스트:** 가짜 데이터(Mock)를 활용하여 모듈 단독 실행 검증.

4. **커밋 및 푸시:** 커밋 컨벤션을 지켜서 원격 저장소에 업로드.

    ```bash
    git add .
    git commit -m "feat: 정오탐 판별 시스템 프롬프트 작성"
    git push -u origin feature/role3-prompt-tuning
    ```

5. PR 생성: GitHub에서 develop 브랜치로 Pull Request를 생성하고 PM의 리뷰를 대기.

## 4. 커밋 메시지 컨벤션
```feat```: 새로운 기능 추가

```fix```: 버그 수정

```refactor```: 코드 구조 개선 (기능 변경 없음)

```docs```: 문서 수정 (README.md, 주석 등)

```chore```: 패키지 설정, 의존성(requirements.txt) 추가 등

**작성 예시*: feat: Role 4 AST 매핑 모듈에 정규식 기반 fallback 추가

## 5. 코드 리뷰 및 Merge 규칙
단독 Merge 금지: 생성된 PR은 작성자 본인이 승인할 수 없습니다.

반드시 PM(Role 1) 또는 해당 기능과 연동되는 타 모듈 담당자 1인 이상의 **Approve(승인)**를 받아야만 develop 브랜치로 병합됩니다.
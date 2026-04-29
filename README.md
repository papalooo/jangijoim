# 🛡️ JANGIJOIM: AI-Driven Security Pipeline

JANGIJOIM은 LLM(대규모 언어 모델) 멀티 에이전트 시스템을 활용하여 웹 애플리케이션의 취약점을 탐지, 분석하고 시큐어 코딩 패치 제안을 생성하는 차세대 DevSecOps 자동화 플랫폼입니다.

---

## 🌟 주요 특징 (Core Features)

-   **🎯 하이브리드 스캔 (DAST + SAST):** Nuclei와 Semgrep을 병렬로 구동하여 웹 트래픽과 소스코드를 동시 분석합니다.
-   **🌍 범용 코드 매핑 (Universal Mapper):** 언어와 프레임워크에 상관없이(Python, JS/TS, Java 등) 탐지된 엔드포인트를 소스코드 내 함수 블록으로 역추적합니다.
-   **🧠 4중 LLM 에이전트 시스템:**
    -   **Triager:** DAST/SAST 결과를 교차 검증하여 정오탐을 판별하고 CVSS 점수를 산정합니다.
    -   **Red Teamer:** 실제 공격 가능성을 증명하기 위한 PoC 익스플로잇 페이로드를 생성합니다.
    -   **Blue Teamer:** 비즈니스 로직을 유지하면서 취약점을 차단하는 시큐어 코딩 패치를 제안합니다.
    -   **QA Auditor:** 제안된 패치 코드의 품질과 안정성을 최종 검수합니다.
-   **📊 자동 통합 보고서:** 모든 진단 프로세스와 AI의 분석 근거, 패치 전후 코드를 포함한 전문적인 Markdown 보고서를 자동 출력합니다.

---

## 🏗 시스템 아키텍처 (Architecture)

1.  **Core (Role 1):** FastAPI 기반 비동기 오케스트레이션 및 데이터 관리.
2.  **Scanner (Role 2):** 스캔 엔진 제어 및 PoC 페이로드 검증 실행.
3.  **Intelligence (Role 3):** Gemini API 연동 멀티 에이전트 추론 및 리포팅.
4.  **Mapping (Role 4):** AST 및 문자열 휴리스틱 기반 코드 블록 추출.

---

## 🚀 시작하기 (Getting Started)

### 📋 사전 요구 사항
-   **Docker & Docker Compose**
-   **Git** (분석 대상 소스코드 관리용)
-   **Gemini API Key** (`.env` 파일에 설정 필요)

### 1. 프로젝트 설치
```bash
git clone https://github.com/your-repo/jangijoim.git
cd jangijoim
cp .env.example .env # GEMINI_API_KEY 입력
```

### 2. 테스트 환경(OWASP Juice Shop) 및 엔진 가동
```bash
# 1. 소스코드 준비
git clone --depth 1 https://github.com/juice-shop/juice-shop.git juice-shop-src

# 2. 컨테이너 가동
docker-compose up --build -d
```

### 3. 진단 실행
```bash
docker exec -it gemini_engine python main.py scan start http://juice-shop:3000 ./juice-shop-src
```

### 4. 결과 확인
진단이 완료되면 컨테이너 내부의 `reports/` 폴더 또는 로컬의 매핑된 디렉토리에서 상세 Markdown 보고서를 확인할 수 있습니다.

---

## 🤝 협업 및 기여 규칙
본 프로젝트는 특정 브랜치 전략(GitFlow)과 커밋 컨벤션을 따릅니다. 상세 내용은 [CONTRIBUTING.md](./CONTRIBUTING.md) 및 [GEMINI.md](./GEMINI.md)를 참고해 주십시오.

---
*Developed with ♊ Gemini CLI - Empowering Automated Security.*

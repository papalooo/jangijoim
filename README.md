# ♊ JANGIJOIM: LLM-Based Web Vulnerability Scanner & Auto-Patcher

JANGIJOIM은 **다양한 웹서비스에 대해 로컬 환경에 설치되어 작동하는 지능형 웹 취약점 진단 및 자동 패치 플랫폼**입니다. 
소스코드에 SAST와 DAST를 실행하고, 두 결과를 매핑하여 LLM이 분석하기 좋은 데이터로 정제하는 과정을 거칩니다. 이후 LLM을 통해 정오탐 여부를 판별하고, 정탐에 대한 공격 페이로드를 직접 생성 및 수행하여 취약점의 근거를 확보한 뒤, 방어 코드 패치 제안까지 포함하는 상세 보고서를 자동으로 작성합니다.

---

## 🚀 빠른 시작 가이드 (Quick Start)

본 프로젝트는 **Docker** 환경에서 실행되는 것을 원칙으로 합니다. 로컬 환경에 복잡한 보안 도구를 직접 설치할 필요 없이 컨테이너 기반으로 동작합니다.

### 1. 운영체제별 레포지토리 클론 및 의존성 설치
먼저, JANGIJOIM 레포지토리를 로컬에 클론합니다.

> 💡 **로컬 파이썬 의존성 설치 안내:** `requirements.txt` 설치는 필수는 아니지만, IDE(VS Code 등)에서의 코드 자동 완성, 타입 체크 및 CLI 직접 제어를 위해 권장됩니다. 실제 보안 스캔 엔진은 Docker 컨테이너 내에서 독립적으로 실행됩니다.

**🖥️ Windows (PowerShell) 환경**
```powershell
# 1. 레포지토리 클론
git clone https://github.com/papalooo/jangijoim.git
cd jangijoim

# 2. 로컬 개발 환경 구성 (권장)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**🍎 Mac / 🐧 Linux (Bash/Zsh) 환경**
```bash
# 1. 레포지토리 클론
git clone https://github.com/papalooo/jangijoim.git
cd jangijoim

# 2. 로컬 개발 환경 구성 (권장)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. 환경 설정
프로젝트 루트에 `.env` 파일을 생성하고 Google AI Studio에서 발급받은 Gemini API 키를 입력합니다.

**🖥️ Windows (PowerShell) 환경**
```powershell
Set-Content -Path .env -Value "GEMINI_API_KEY=your_api_key_here" -Encoding utf8
```

**🍎 Mac / 🐧 Linux (Bash/Zsh) 환경**
```bash
echo "GEMINI_API_KEY=your_api_key_here" > .env
```

### 3. 엔진 및 서비스 가동 (Docker)
Docker Compose를 사용하여 스캔 엔진, 정밀 스캐너(ZAP), 그리고 테스트용 앱(Juice Shop)을 한 번에 실행합니다. (Node.js 사전 설치 필요)

**🖥️ Windows (PowerShell) 환경**
```powershell
# 프론트엔드 빌드 (정적 파일 생성)
cd frontend; npm install; npm run build; cd ..

# 컨테이너 백그라운드 실행
docker-compose up -d --build
```

**🍎 Mac / 🐧 Linux (Bash/Zsh) 환경**
```bash
# 프론트엔드 빌드 (정적 파일 생성)
cd frontend && npm install && npm run build && cd ..

# 컨테이너 백그라운드 실행
docker-compose up -d --build
```

### 4. CLI를 이용한 스캔 시작
모든 컨테이너가 정상적으로 실행되었다면, 로컬 터미널에서 `main.py`를 통해 스캔을 요청할 수 있습니다. 
엔진이 Docker 컨테이너 내부에 있으므로 로컬에 보안 도구를 설치하지 않아도 작동합니다.

(아래 파이썬 실행 명령어는 Windows와 Mac/Linux 환경에서 동일합니다)

CLI 명령어 예시:
```bash
# 기본 스캔 시작
python main.py scan start --target-url http://juice-shop:3000 --source-dir /app/juice-shop-src

# CLI 도움말 및 전체 명령어 확인
python main.py --help
python main.py scan --help
```

---

## 📁 프로젝트 구조 (Project Structure)

- **`core/`**: 파이프라인 제어 타워, 공통 데이터 스키마 및 CLI 정의 (Role 1)
- **`scanner/`**: Nuclei/Semgrep 기반 스캔 수행 및 결과 파싱 (Role 2)
- **`intelligence/`**: LLM 엔진, 정오탐 판별, PoC 생성 및 보고서 렌더링 (Role 3)
- **`mapping/`**: AST(Tree-sitter) 기반 소스코드 매핑 및 패치 적용 (Role 4)
- **`frontend/`**: React/Tailwind 기반 실시간 대시보드 웹 UI
- **`scripts/`**: 보고서 템플릿 생성 및 문서 처리 유틸리티
- **`tests/`**: 시스템 통합 테스트 및 단위 테스트 코드
- **`examples/`**: 사전 로그인 스크립트 등 사용 예제
- **`reports/`**: 생성된 보안 보고서(MD, DOCX) 및 PoC 매니페스트 저장소

---

## 🖥 주요 기능 활용법

### 1. 실시간 대시보드 (Web UI)
브라우저에서 `http://localhost:8000`에 접속하면 실시간으로 진행되는 공격 과정과 탐지 결과를 확인할 수 있습니다.
- **Dashboard:** 현재 진행 중인 스캔 단계(Stepper), 실시간 터미널 로그 및 탐지 취약점 현황 표시
- **Scan History:** 과거 스캔 기록 조회 및 상세 결과 재확인
- **Settings:** LLM 모델 설정(Gemini Pro 등) 및 스캔 옵션 관리

### 2. 지능형 파이프라인 프로세스
1. **Scanning:** DAST(Nuclei, Katana) 및 SAST(Semgrep) 스캔을 병렬로 수행하여 잠재적 취약점 식별
2. **Mapping & Refinement:** 탐지된 취약점과 소스코드를 AST 기반으로 정밀 매핑하고, LLM 분석을 위한 최적의 컨텍스트 생성
3. **Triage:** Gemini LLM의 추론 능력을 활용하여 높은 정확도로 정탐/오탐(TP/FP) 판별
4. **PoC Generation & Verification:** 정탐 건에 대해 유효한 공격 페이로드(PoC)를 생성하고 실제 타겟에 수행하여 증거 확보
5. **Patch Proposal & Reporting:** 취약점 방어 코드를 자동으로 생성하고, 상세 내용을 담은 보고서(Markdown 및 Word .docx)를 `reports/` 디렉토리에 생성

### 3. PoC 재실행 도구
스캔 완료 후 생성된 `JANGIJOIM_Summary_*.md` 결과와 함께 생성된 매니페스트를 사용하여 특정 취약점을 다시 테스트할 수 있습니다.
```bash
python main.py poc run ./reports/poc_manifest_XXXXXX.json
```

---

## 🛠 기술 스택
- **Backend:** FastAPI, Pydantic v2, Typer, SQLite
- **Frontend:** React (Vite), TailwindCSS, Lucide React
- **Security Tools:** Nuclei, Katana, Semgrep, OWASP ZAP
- **AI Engine:** Google Gemini 1.5 / 2.0 / 2.5 Pro

## 📝 참고 사항
- **Source Mapping:** `--source-dir` 경로는 엔진 컨테이너 내부 경로인 `/app/juice-shop-src` 등을 사용하거나, 컨테이너에 적절히 마운트된 경로여야 합니다.
- **Stability:** 본 프로젝트는 Docker 환경에서 최적의 성능과 안정성을 제공합니다.

---
**Happy Hacking & Patching!** 🛡️

# ♊ JANGIJOIM: LLM-Based Web Vulnerability Scanner & Auto-Patcher

JANGIJOIM은 **LLM(Large Language Model) 기반의 지능형 웹 취약점 진단 및 자동 패치 플랫폼**입니다. DAST(Katana, Nuclei)와 SAST(Semgrep)를 결합하여 취약점을 탐지하고, Google Gemini Pro를 통해 정오탐 판별 및 소스코드 패치를 자동으로 수행합니다.

---

## 🚀 빠른 시작 가이드 (Quick Start)

본 프로젝트는 **Docker** 환경에서 실행되는 것을 원칙으로 합니다. 로컬 환경에 별도의 보안 도구를 설치할 필요가 없습니다.

### 1. 운영체제별 레포지토리 클론 및 의존성 설치
먼저, JANGIJOIM 레포지토리를 로컬에 클론하고 파이썬 의존성을 설치합니다.

**🖥️ Windows (PowerShell) 환경**
```powershell
# 1. 레포지토리 클론
git clone https://github.com/papalooo/jangijoim.git
cd jangijoim

# 2. 로컬 파이썬 의존성 설치
pip install -r requirements.txt
```

**🍎 Mac / 🐧 Linux (Bash/Zsh) 환경**
```bash
# 1. 레포지토리 클론
git clone https://github.com/papalooo/jangijoim.git
cd jangijoim

# 2. 로컬 파이썬 의존성 설치
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

## 🖥 주요 기능 활용법

### 1. 실시간 대시보드 (Web UI)
브라우저에서 `http://localhost:8000`에 접속하면 실시간으로 진행되는 공격 과정과 탐지 결과를 확인할 수 있습니다.
- **Dashboard:** 현재 진행 중인 스캔 로그 및 취약점 리스트 표시
- **Scan History:** 과거 스캔 기록 조회 및 결과 재확인
- **Settings:** LLM 모델 설정 및 스캔 옵션(병렬 처리 등) 확인

### 2. 지능형 파이프라인 프로세스
1. **Scanning:** Katana(JS 크롤링) + Nuclei(DAST) + Semgrep(SAST) 병렬 구동
2. **Mapping:** 탐지된 취약점을 소스코드 위치와 매핑 (AST 분석)
3. **Triage:** Gemini LLM이 코드를 분석하여 정탐/오탐 최종 판별
4. **PoC Verify:** 생성된 페이로드를 실제 타겟에 전송하여 취약성 검증
5. **Reporting:** 상세 마크다운 보고서 및 재실행 가능한 PoC 매니페스트 생성

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
- **AI Engine:** Google Gemini 1.5 / 2.0 Pro

## 📝 참고 사항
- **Source Mapping:** `--source-dir` 경로는 엔진 컨테이너 내부 경로인 `/app/juice-shop-src` 등을 사용하거나, 컨테이너에 적절히 마운트된 경로여야 합니다.
- **Stability:** 본 프로젝트는 Docker 환경에서 최적의 성능과 안정성을 제공합니다.

---
**Happy Hacking & Patching!** 🛡️

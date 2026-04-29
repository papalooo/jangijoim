
# 1. 베이스 이미지 설정 (Python 3.11 Slim 버전 사용으로 이미지 최적화)
FROM python:3.11-slim

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 시스템 의존성 패키지 설치 (필요시 nmap 등 네트워크 도구 추가 가능)
# RUN apt-get update && apt-get install -y --no-install-recommends nmap tcpdump && rm -rf /var/lib/apt/lists/*

# 4. 의존성 파일 복사 및 설치
# requirements.txt만 먼저 복사하여 패키지 설치 단계를 도커 캐시로 활용
COPY ../requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y wget unzip nmap tcpdump && \
    wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip && \
    unzip -o nuclei_3.2.0_linux_amd64.zip && mv nuclei /usr/local/bin/ && rm nuclei_3.2.0_linux_amd64.zip && \
    wget https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip && \
    unzip -o katana_1.1.0_linux_amd64.zip && mv katana /usr/local/bin/ && rm katana_1.1.0_linux_amd64.zip && \
    pip install semgrep

# 5. 프로젝트 소스 코드 전체 복사 (.dockerignore에 명시된 파일 제외)
COPY . .

# 6. 컨테이너 외부에 노출할 포트 (FastAPI/Uvicorn 기본 포트에 맞춰 수정 가능)
EXPOSE 8000

# 7. 실행 명령어 (main.py가 진입점인 경우)
# 상황에 따라 python main.py 또는 uvicorn 명령어로 수정하십시오.
CMD ["python", "main.py","serve"]
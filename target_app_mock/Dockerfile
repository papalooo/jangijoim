# target_app_mock/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# 타겟 서버 구동에 필요한 최소한의 패키지 설치
RUN pip install --no-cache-dir fastapi uvicorn

# 모의 타겟 소스코드 복사
COPY . /app

# 3000번 포트로 Uvicorn 서버 실행
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "3000"]
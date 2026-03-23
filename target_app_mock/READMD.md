💡 이 샌드백 서버의 논리적 활용 방법 (팀원 가이드)
서버 구동 (터미널 3)

```bash
cd target_app_mock
uvicorn app:app --host 127.0.0.1 --port 3000 --reload
```

이제 http://localhost:3000에 취약한 타겟이 열렸습니다.

Role 2 (스캐너 제어 담당)의 검증

본인이 짠 코드(또는 Nuclei 바이너리)가 http://localhost:3000/api/login을 공격했을 때, 서버가 db_error_dump를 뱉어내거나 Welcome, admin!을 반환하는지 확인합니다. 성공했다면 스캐너 연동 로직이 정상 동작하는 것입니다.

Role 4 (소스코드 매핑 담당)의 검증

Role 2가 취약점을 찾아낸 URL(/api/login)을 입력으로 받습니다.

본인이 짠 AST 파서(Python ast 모듈 활용)가 target_app_mock/app.py 파일을 읽어들여, @app.post("/api/login") 데코레이터가 달린 login_sqli 함수의 시작 라인과 끝 라인을 정확히 잘라내는지(Slicing) 테스트합니다.

Role 3 (LLM 판별 및 패치 제안)의 검증

Role 4가 잘라준 login_sqli 소스코드와 Role 2가 넘겨준 공격 패킷 데이터를 합쳐서 LLM에게 던집니다.

LLM이 "f-string을 사용했으므로 명백한 SQLi 정탐이다. 패치는 파라미터화된 쿼리(cursor.execute("SELECT...", (user, pw)))를 사용해야 한다"고 객관적인 응답을 내놓는지 프롬프트를 조정합니다.
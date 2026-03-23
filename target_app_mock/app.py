import sqlite3
from fastapi import FastAPI, Query, Form
from fastapi.responses import HTMLResponse

app = FastAPI(title="Vulnerable Target App (jangijoim Testbed)")

# -----------------------------------------------------------------
# [데이터베이스 초기화] 인메모리 SQLite에 더미 데이터 생성
# -----------------------------------------------------------------
conn = sqlite3.connect(':memory:', check_same_thread=False)
cursor = conn.cursor()
cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_admin BOOLEAN)")
cursor.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'supersecret_admin_pw', 1)")
cursor.execute("INSERT INTO users (username, password, is_admin) VALUES ('guest', 'guest123', 0)")
conn.commit()


# -----------------------------------------------------------------
# 1. SQL Injection 취약점 엔드포인트 (Role 2, 4 테스트용)
# -----------------------------------------------------------------
@app.post("/api/login")
async def login_sqli(username: str = Form(...), password: str = Form(...)):
    """
    [취약점] 사용자 입력값을 검증이나 바인딩 처리 없이 SQL 쿼리 문자열에 직접 삽입(f-string)합니다.
    - Role 2 (스캐너): 이 엔드포인트에 "' OR 1=1 --" 같은 페이로드를 쏴서 뚫리는지 확인.
    - Role 4 (AST 추적): "/api/login" URL을 바탕으로 이 함수의 23~35라인을 정확히 매핑하는지 확인.
    """
    # ❌ 치명적 시큐어 코딩 위반: f-string을 사용한 Raw 쿼리 조합
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            return {"status": "success", "message": f"Welcome, {user[1]}!", "is_admin": user[3]}
        else:
            return {"status": "fail", "message": "Invalid credentials"}
    except sqlite3.OperationalError as e:
        # ❌ 에러 메시지 노출 (DAST 스캐너가 SQLi 취약점을 확신하게 만드는 힌트 제공)
        return {"status": "error", "db_error_dump": str(e)}


# -----------------------------------------------------------------
# 2. Reflected XSS 취약점 엔드포인트 (Role 2, 4 테스트용)
# -----------------------------------------------------------------
@app.get("/api/board/search", response_class=HTMLResponse)
async def search_xss(q: str = Query(default="")):
    """
    [취약점] 사용자 입력값(q)을 HTML 이스케이프 처리 없이 브라우저에 그대로 반사(Reflect)합니다.
    - Role 2 (스캐너): "?q=<script>alert(1)</script>" 페이로드 전송 후 응답에 스크립트가 그대로 박혀있는지 확인.
    """
    # ❌ 치명적 시큐어 코딩 위반: 입력값 검증 없이 HTML에 직접 삽입
    html_content = f"""
    <html>
        <body>
            <h2>검색 결과</h2>
            <p>당신이 검색한 키워드: <strong>{q}</strong></p>
            <p>검색된 항목이 없습니다.</p>
        </body>
    </html>
    """
    return html_content
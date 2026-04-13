import asyncio
import os
import sys

# 현재 파일 위치를 기준으로 프로젝트 최상위 폴더를 강제 인식시킵니다 (-m 옵션 불필요)
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.schemas import MappedContext, DastSastResult
from intelligence.llm_client import run_multi_agent_pipeline

async def main():
    print("🚀 Role 3 테스트를 위한 가짜(Mock) 데이터 생성 중...")
    mock_dast = DastSastResult(
        target_endpoint="/api/login",
        http_method="POST",
        vuln_type="SQL Injection",
        severity="High",
        payload="' OR 1=1 --",
        sliced_response="sqlite3.OperationalError: unrecognized token"
    )
    
    mock_context = MappedContext(
        dast_data=mock_dast,
        is_mapped=True,
        mapped_file_path="target_app_mock/app.py",
        ast_node_type="FunctionDef",
        start_line=23,
        end_line=35,
        code_snippet='''
@app.post("/api/login")
async def login_sqli(username: str = Form(...), password: str = Form(...)):
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
'''
    )

    print("🤖 멀티 에이전트 지능(OpenClaw) 가동! (약 5~15초 소요)")
    try:
        result = await run_multi_agent_pipeline(mock_context)
        print("\n✅ [테스트 대성공] 완벽한 JSON 구조로 응답을 받았습니다:\n")
        print(result.model_dump_json(indent=2))
    except Exception as e:
        print(f"\n❌ [테스트 실패] 오류 발생: {e}")

if __name__ == "__main__":
    asyncio.run(main())
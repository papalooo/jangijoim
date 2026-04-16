import asyncio
import os
import sys

# 현재 파일 위치를 기준으로 프로젝트 최상위 폴더를 강제 인식시킵니다
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from core.schemas import MappedContext, DastSastResult, FinalReportState, ScanMetadata
from intelligence.llm_client import run_multi_agent_pipeline
from intelligence.reporter import generate_markdown_report

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
        # 1. LLM 추론 파이프라인 실행
        result = await run_multi_agent_pipeline(mock_context)
        print("\n[+] LLM 1차 출력 완료 (JSON 파싱 성공)")
        
        # 2. 파이프라인 최종 상태(FinalReportState) 통합 목업 조립
        print("[+] 보고서 생성을 위한 상태(State) 데이터 통합 중...")
        mock_metadata = ScanMetadata(
            target_host="http://localhost:3000",
            source_dir="./target_app_mock"
        )
        
        final_state = FinalReportState(
            metadata=mock_metadata,
            dast_result=mock_dast,
            mapped_context=mock_context,
            verification=result.triager_result,   # LLM의 정오탐 분석 결과
            patch=result.blue_teamer_patch,       # LLM이 작성한 패치 코드
            # Red Teamer 페이로드는 나중에 QA/테스트(Role 2/4)로 넘겨주기 위해 구조체 안에는 있지만 보고서 출력용으로는 주로 patch와 verification 사용
        )
        
        # 3. 마크다운 보고서 렌더링 함수 호출
        report_path = generate_markdown_report(final_state)
        print(f"\n✅ 테스트 완료! 상세 보고서가 성공적으로 생성되었습니다.")
        print(f"👉 확인 경로: {report_path}")

    except ValueError as e:
        print(f"\n❌ [스키마/파싱 오류]: {e}")
    except RuntimeError as e:
        print(f"\n❌ [API 호출 오류]: {e}")
    except Exception as e:
        print(f"\n❌ [알 수 없는 오류]: {e}")

if __name__ == "__main__":
    asyncio.run(main())
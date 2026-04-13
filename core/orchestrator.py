import uuid
import asyncio
from datetime import datetime
from typing import Dict
from fastapi import FastAPI, BackgroundTasks, HTTPException
from mapping.ast_parser import map_vulnerability_to_code

# 앞서 작성한 core/schemas.py의 모든 규격을 임포트합니다.
from core.schemas import (
    ScanMetadata, ScanStatus, FinalReportState,
    DastSastResult, MappedContext, VerificationResult,
    ExploitPayload, ExecutionResult, PatchProposal, RegressionTestResult
)

app = FastAPI(title="Jangijoim Remediation Tool Pipeline")

# 인메모리 상태 저장소 (실제 운영 시에는 SQLite/Redis 등으로 대체 가능)
# Job ID를 키(Key)로 하여 전체 상태(FinalReportState)를 추적합니다.
job_store: Dict[uuid.UUID, FinalReportState] = {}


# =====================================================================
# [Mock Functions] 타 팀원(Role 2, 3, 4)이 구현할 함수들의 껍데기(인터페이스)
# 실제 통합 단계(Phase 3)에서 이 부분들을 팀원들의 실제 함수 임포트로 교체합니다.
# =====================================================================

async def mock_role2_scan(target_url: str) -> DastSastResult:
    """[Role 2] DAST 스캔 및 파싱 수행"""
    await asyncio.sleep(2) # 스캔 딜레이 모사
    return DastSastResult(
        target_endpoint=f"{target_url}/api/login",
        http_method="POST",
        vuln_type="SQL Injection",
        severity="High",
        payload="' OR 1=1 --",
        sliced_response="SQL syntax error near..."
    )

async def mock_role4_map_code(dast_result: DastSastResult, source_dir: str) -> MappedContext:
    """[Role 4] DAST 타격 URL을 소스코드 파일/라인으로 매핑"""
    await asyncio.sleep(1)
    return MappedContext(
        dast_data=dast_result,
        is_mapped=True,
        mapped_file_path="src/auth.py",
        start_line=20,
        end_line=50,
        code_snippet="def login(user, pw):\n  query = f'SELECT * FROM users WHERE id={user}'"
    )

async def mock_role3_verify(context: MappedContext) -> VerificationResult:
    """[Role 3] LLM 기반 정오탐 판별"""
    await asyncio.sleep(2)
    return VerificationResult(
        is_vulnerable=True,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        reason="사용자 입력값이 쿼리에 직접 바인딩되어 SQLi가 명확히 가능함."
    )

# ... (페이로드 생성, 실행, 패치, 회귀 테스트 모의 함수 생략 - 동일한 방식으로 연결) ...


# =====================================================================
# [Core Pipeline] Role 1의 메인 비동기 워커 로직
# =====================================================================

async def run_scan_pipeline(job_id: uuid.UUID, target_url: str, source_dir: str):
    state = job_store[job_id]
    
    try:
        # 1단계: 스캔
        state.metadata.current_status = ScanStatus.SCANNING
        dast_res = await mock_role2_scan(target_url)
        state.dast_result = dast_res
        
        # 2단계: 코드 매핑 (Mock 함수 대신 진짜 AST 매핑 로직 적용)
        state.metadata.current_status = ScanStatus.MAPPING
        mapped_ctx = await map_vulnerability_to_code(dast_res, source_dir)
        state.mapped_context = mapped_ctx
        
        if not mapped_ctx.is_mapped:
            raise Exception("소스코드에서 대상 엔드포인트 라우터를 찾을 수 없습니다.")
            
        # 3단계: LLM 판별
        state.metadata.current_status = ScanStatus.VERIFYING
        verification = await mock_role3_verify(mapped_ctx)
        state.verification = verification
        
        # 4단계: 방어 코드 적용 및 회귀 테스트
        state.metadata.current_status = ScanStatus.TESTING
        regression = await mock_role4_test(verification)
        state.regression_test = regression
        
        # 5단계: 완료
        state.metadata.current_status = ScanStatus.COMPLETED
        
    except Exception as e:
        # 에러가 나면 상태를 FAILED로 바꾸고 에러 메시지를 기록
        state.metadata.current_status = ScanStatus.FAILED
        state.metadata.error_log = str(e)


# =====================================================================
# [API Endpoints] CLI 인터페이스와 통신하는 엔드포인트
# =====================================================================

@app.post("/scan/start")
async def start_scan(target_url: str, source_dir: str, background_tasks: BackgroundTasks):
    """CLI에서 호출하여 스캔 작업을 큐에 등록합니다."""
    job_id = uuid.uuid4()
    
    # 초기 상태 생성
    metadata = ScanMetadata(target_host=target_url, source_dir=source_dir)
    job_store[job_id] = FinalReportState(metadata=metadata)
    
    # 파이프라인을 백그라운드로 넘김 (Non-blocking)
    background_tasks.add_task(run_scan_pipeline, job_id, target_url, source_dir)
    
    return {"job_id": job_id, "message": "Scan pipeline started in background."}


@app.get("/scan/status/{job_id}")
async def get_scan_status(job_id: uuid.UUID) -> FinalReportState:
    """CLI 화면의 프로그레스 바(Progress Bar)를 갱신하기 위해 폴링(Polling)하는 엔드포인트입니다."""
    if job_id not in job_store:
        raise HTTPException(status_code=404, detail="Job ID not found")
    
    return job_store[job_id]
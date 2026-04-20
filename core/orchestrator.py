import uuid
import asyncio
from pathlib import Path
from core import db_manager
from datetime import datetime
from typing import Dict
from fastapi import FastAPI, BackgroundTasks, HTTPException
from contextlib import asynccontextmanager # ✅ 이 줄을 추가합니다.

from mapping.ast_parser import map_vulnerability_to_code
from intelligence.llm_client import verify_vulnerabilities_batch
from core.schemas import (
    ScanMetadata, ScanStatus, FinalReportState,
    DastSastResult, MappedContext, VerificationResult,
    ExploitPayload, ExecutionResult, PatchProposal, RegressionTestResult
)

# ✅ 기존의 @app.on_event("startup") 부분을 지우고 아래 lifespan 함수로 교체합니다.
@asynccontextmanager
async def lifespan(app: FastAPI):
    db_manager.init_db()
    yield # 서버가 켜질 때 yield 앞의 코드가 실행됩니다.

app = FastAPI(title="Jangijoim Remediation Tool Pipeline", lifespan=lifespan)

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
    state = db_manager.get_job(str(job_id))
    if not state:
        return
    try:
        # 1단계: 스캔
        state.metadata.current_status = ScanStatus.SCANNING
        db_manager.save_job(str(job_id), state) # 상태가 바뀔 때마다 DB 저장
        
        dast_res = await mock_role2_scan(target_url)
        state.dast_result = dast_res
        
        # 2단계: 코드 매핑
        state.metadata.current_status = ScanStatus.MAPPING
        db_manager.save_job(str(job_id), state)
        
        mapped_ctx = await map_vulnerability_to_code(dast_res, source_dir)
        state.mapped_context = mapped_ctx
        
        if not mapped_ctx.is_mapped:
            raise Exception("소스코드에서 대상 엔드포인트 라우터를 찾을 수 없습니다.")
            
        # 3단계: LLM 멀티 에이전트 판별
        state.metadata.current_status = ScanStatus.VERIFYING
        db_manager.save_job(str(job_id), state)

        try:
            # ✅ 수정: 단일 객체인 state.mapped_context를 리스트로 감싸서 전달
            batch_results = await verify_vulnerabilities_batch([state.mapped_context])
            
            # ✅ 수정: 반환된 결과 배열의 첫 번째 항목을 단수형 필드인 verification에 저장
            if batch_results:
                state.verification = batch_results[0]
                
        except Exception as e:
            state.metadata.error_log = f"LLM Batch Verification Failed: {str(e)}"
            raise Exception(f"[Role 3 실패] {e}")
        
        db_manager.save_job(str(job_id), state)

        # 4단계: 페이로드 실행 및 회귀 테스트 (Role 2 executor 연동 예정)
        state.metadata.current_status = ScanStatus.TESTING
        db_manager.save_job(str(job_id), state)
        # TODO: await run_exploit(llm_result.red_teamer_payload)

        state.metadata.current_status = ScanStatus.COMPLETED
        db_manager.save_job(str(job_id), state)
        
    except Exception as e:
        state.metadata.current_status = ScanStatus.FAILED
        state.metadata.error_log = str(e)
        db_manager.save_job(str(job_id), state)


# =====================================================================
# [API Endpoints] CLI 인터페이스와 통신하는 엔드포인트
# =====================================================================

@app.post("/scan/start")
async def start_scan(target_url: str, source_dir: str, background_tasks: BackgroundTasks):
    # 절대경로 변환 후 허용 범위 검증
    resolved = Path(source_dir).resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise HTTPException(status_code=400, detail="유효하지 않은 source_dir 경로입니다.")
    
    job_id = uuid.uuid4()
    
    # DB에 초기 상태 기록
    metadata = ScanMetadata(target_host=target_url, source_dir=source_dir)
    initial_state = FinalReportState(metadata=metadata)
    db_manager.save_job(str(job_id), initial_state)
    
    background_tasks.add_task(run_scan_pipeline, job_id, target_url, source_dir)
    return {"job_id": job_id, "message": "Scan pipeline started in background."}


@app.get("/scan/status/{job_id}")
async def get_scan_status(job_id: uuid.UUID):
    state = db_manager.get_job(str(job_id))
    if not state:
        raise HTTPException(status_code=404, detail="Job not found in database")
    return state
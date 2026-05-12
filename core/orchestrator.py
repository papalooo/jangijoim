import uuid
import asyncio
import shutil
import httpx
from pathlib import Path
from core import db_manager
from datetime import datetime, timezone
from typing import Dict, List
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from core.ws_manager import manager as ws_manager

from mapping.ast_parser import map_vulnerability_to_code
from intelligence.llm_client import verify_vulnerabilities_batch
from intelligence.reporter import generate_markdown_report
from scanner.engine import run_nuclei, run_semgrep, run_katana, run_zap
from scanner.parser import normalize_and_merge_results
from scanner.executor import run_exploit

from core.schemas import (
    ScanMetadata, ScanStatus, FinalReportState,
    DastSastResult, MappedContext, VerificationResult,
    LlmVerification,
    ExploitPayload, ExecutionResult, PatchProposal, RegressionTestResult,
    VulnerabilityItem
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    db_manager.init_db()
    yield

app = FastAPI(title="Jangijoim Remediation Tool Pipeline", lifespan=lifespan)

@app.websocket("/ws/{job_id}")
async def websocket_endpoint(websocket: WebSocket, job_id: str):
    await ws_manager.connect(websocket, job_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, job_id)

# =====================================================================
# [Pre-flight] 필수 바이너리 및 타겟 유효성 검증
# =====================================================================

async def perform_pre_flight_checks(target_url: str) -> List[str]:
    """
    스캔 시작 전 필수 조건들을 검증합니다.
    실패 사유 목록을 반환하며, 목록이 비어있으면 검증 통과입니다.
    """
    errors = []
    
    # 1. 필수 바이너리 체크
    required_binaries = ["nuclei", "semgrep", "katana"]
    for bin_name in required_binaries:
        if not shutil.which(bin_name):
            errors.append(f"필수 도구를 찾을 수 없습니다: {bin_name} (PATH 환경변수를 확인하세요)")
            
    # 2. 타겟 URL 접근성 및 보안 체크
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(target_url, follow_redirects=True)
            if resp.status_code >= 500:
                errors.append(f"타겟 서버가 불안정합니다. (HTTP {resp.status_code})")
    except Exception as e:
        errors.append(f"타겟 서버에 접근할 수 없습니다: {str(e)}")
        
    # 3. SSRF 방지 (간단한 로컬 주소 체크)
    parsed = httpx.URL(target_url)
    if parsed.host in ["localhost", "127.0.0.1", "0.0.0.0"]:
        print(f"⚠️ [Security] 로컬 호스트({parsed.host}) 스캔이 요청되었습니다.")

    return errors

# =====================================================================
# [Core Pipeline] Role 1의 메인 비동기 워커 로직
# =====================================================================

@app.get("/scan/history")
async def get_scan_history(limit: int = 10):
    """
    최근 스캔 이력을 반환합니다.
    """
    jobs = db_manager.list_jobs(limit=limit)
    return jobs

async def run_scan_pipeline(job_id: uuid.UUID, target_url: str, source_dir: str):
    state = db_manager.get_job(str(job_id))
    if not state:
        return

    async def update_state(status: ScanStatus, message: str = None):
        state.metadata.current_status = status
        db_manager.save_job(str(job_id), state)
        await ws_manager.broadcast(str(job_id), {
            "type": "status",
            "status": status,
            "message": message or f"Status changed to {status}"
        })

    try:
        # [0단계] Pre-flight Checks (Idempotent)
        if state.metadata.current_status == ScanStatus.QUEUED:
            await update_state(ScanStatus.QUEUED, "Pre-flight checks starting...")
            pre_flight_errors = await perform_pre_flight_checks(target_url)
            if pre_flight_errors:
                raise RuntimeError("\n".join(pre_flight_errors))
            await update_state(ScanStatus.SCANNING, "Pre-flight checks passed.")

        # 1단계: 스캔 (Adaptive Hybrid DAST 가동)
        if state.metadata.current_status == ScanStatus.SCANNING:
            await update_state(ScanStatus.SCANNING, "Starting DAST/SAST Scanning...")
            
            katana_task = run_katana(target_url, job_id=str(job_id))
            sast_task = run_semgrep(source_dir, job_id=str(job_id))
            katana_urls, sast_raw = await asyncio.gather(katana_task, sast_task)
            
            dast_raw = await run_nuclei(katana_urls, job_id=str(job_id))
            merged_results = normalize_and_merge_results(dast_raw, sast_raw, None)
            
            if not merged_results:
                raise Exception("취약점이 발견되지 않았습니다.")
                
            if len(merged_results) > 50:
                msg = f"⚠️ 너무 많은 취약점({len(merged_results)}건)이 발견되어 상위 50건만 분석합니다."
                await ws_manager.broadcast(str(job_id), {"type": "log", "level": "warning", "message": msg})
                merged_results = merged_results[:50]

            state.vulnerabilities = [VulnerabilityItem(dast_result=res) for res in merged_results]
            await update_state(ScanStatus.MAPPING, "Scanning completed. Saving results.")

        # 2단계: 코드 매핑
        if state.metadata.current_status == ScanStatus.MAPPING:
            await update_state(ScanStatus.MAPPING, f"Mapping {len(state.vulnerabilities)} vulnerabilities to source code...")
            
            async def map_single_item(item):
                if item.mapped_context and item.mapped_context.is_mapped:
                    return # Skip if already mapped
                try:
                    mapped_ctx = await map_vulnerability_to_code(item.dast_result, source_dir)
                    item.mapped_context = mapped_ctx
                except Exception as e:
                    print(f"⚠️ 매핑 실패 ({item.dast_result.vuln_type}): {e}")

            await asyncio.gather(*(map_single_item(item) for item in state.vulnerabilities))
            await update_state(ScanStatus.VERIFYING, "Mapping completed.")

        # 3단계: LLM 멀티 에이전트 판별
        if state.metadata.current_status == ScanStatus.VERIFYING:
            await update_state(ScanStatus.VERIFYING, "Invoking LLM for vulnerability verification and triage...")

            # 판별이 안 된 항목들만 추출
            items_to_verify = [v for v in state.vulnerabilities if v.mapped_context and v.mapped_context.is_mapped and not v.llm_verification]
            
            if items_to_verify:
                try:
                    batch_results = await asyncio.wait_for(
                        verify_vulnerabilities_batch([v.mapped_context for v in items_to_verify], job_id=str(job_id)),
                        timeout=1800
                    )
                    for item, llm_res in zip(items_to_verify, batch_results):
                        item.llm_verification = llm_res
                except Exception as e:
                    msg = f"⚠️ LLM 판별 단계 실패 또는 타임아웃: {e}"
                    print(msg)
                    await ws_manager.broadcast(str(job_id), {"type": "log", "level": "error", "message": msg})
                    # 여기서 중단하지 않고 다음 단계(성공한 것만이라도)로 넘어가거나 저장
            
            await update_state(ScanStatus.TESTING, "LLM Verification completed.")

        # 4단계: 페이로드 실행 및 회귀 테스트 (병렬 실행)
        if state.metadata.current_status == ScanStatus.TESTING:
            await update_state(ScanStatus.TESTING, "Executing PoC payloads and regression testing (Parallel)...")
            
            async def verify_and_test(item):
                if item.execution: return # Skip if already tested
                if item.llm_verification and item.llm_verification.triager_result.is_vulnerable:
                    try:
                        execution_result = await run_exploit(
                            target_url,
                            item.dast_result,
                            item.llm_verification.red_teamer_payload,
                            job_id=str(job_id)
                        )
                        item.execution = execution_result
                        item.regression_test = RegressionTestResult(
                            is_mitigated=not execution_result.is_exploited,
                            http_status_after_patch=execution_result.http_status,
                            rollback_successful=True
                        )
                    except Exception as e:
                        print(f"⚠️ PoC 검증 실패 ({item.dast_result.vuln_type}): {e}")

            semaphore = asyncio.Semaphore(5)
            async def sem_verify(item):
                async with semaphore:
                    await verify_and_test(item)

            await asyncio.gather(*(sem_verify(item) for item in state.vulnerabilities))
            await update_state(ScanStatus.COMPLETED, "PoC testing completed.")

        # 완료 처리
        state.metadata.end_time = datetime.now(timezone.utc)
        await update_state(ScanStatus.COMPLETED, "Scan pipeline finished successfully.")
        
        # 5단계: 최종 보고서 생성
        generate_markdown_report(state)
        
    except Exception as e:
        state.metadata.error_log = str(e)
        # FAILED 상태로 가기 전 RECOVERY 시도 여부 판단 가능 (여기서는 단순 에러 기록)
        await update_state(ScanStatus.FAILED, f"Pipeline failed: {str(e)}")

# =====================================================================
# [API Endpoints] CLI 인터페이스와 통신하는 엔드포인트
# =====================================================================

@app.post("/scan/start")
async def start_scan(target_url: str, source_dir: str, background_tasks: BackgroundTasks):
    resolved = Path(source_dir).resolve()
    # 컨테이너 환경에서는 /app 기준이므로 로컬 경로가 아닌 컨테이너 내부 경로 확인
    if not resolved.exists() or not resolved.is_dir():
        # 폴백: /app 서브디렉토리 시도
        alt_path = Path("/app") / source_dir.lstrip("./")
        if alt_path.exists() and alt_path.is_dir():
            resolved = alt_path
        else:
            raise HTTPException(status_code=400, detail=f"유효하지 않은 source_dir 경로입니다: {source_dir}")
    
    job_id = uuid.uuid4()
    metadata = ScanMetadata(target_host=target_url, source_dir=str(resolved))
    initial_state = FinalReportState(metadata=metadata)
    db_manager.save_job(str(job_id), initial_state)
    
    background_tasks.add_task(run_scan_pipeline, job_id, target_url, str(resolved))
    return {"job_id": job_id, "message": "Scan pipeline started in background."}

@app.get("/scan/status/{job_id}")
async def get_scan_status(job_id: uuid.UUID):
    state = db_manager.get_job(str(job_id))
    if not state:
        raise HTTPException(status_code=404, detail="Job not found in database")
    return state

# Static File Serving (Web UI)
frontend_path = Path(__file__).parent.parent / "frontend" / "dist"
if frontend_path.exists():
    app.mount("/assets", StaticFiles(directory=frontend_path / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        if full_path.startswith("scan") or full_path.startswith("ws"):
            # This is a bit tricky, FastAPI handles routes by order. 
            # But since this is a catch-all, we need to ensure API routes are checked first.
            # In FastAPI, routes registered later don't override earlier ones unless explicitly handled.
            return None # Should not be reached for API paths
        
        file_path = frontend_path / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(frontend_path / "index.html")
else:
    print("⚠️ Warning: frontend/dist not found. Web UI will not be served.")

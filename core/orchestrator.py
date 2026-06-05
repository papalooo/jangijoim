import uuid
import asyncio
import shutil
import httpx
import json
from pathlib import Path
from core import db_manager
from datetime import datetime, timezone
from typing import Dict, List, Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from core.ws_manager import manager as ws_manager

from mapping.ast_parser import map_vulnerability_to_code
from intelligence.llm_client import verify_vulnerabilities_batch, run_red_teamer
from intelligence.reporter import generate_markdown_report, generate_word_report
from scanner.engine import run_nuclei, run_semgrep, run_katana
from scanner.parser import normalize_and_merge_results
from scanner.executor import run_exploit

from core.schemas import (
    ScanMetadata, ScanStatus, FinalReportState,
    DastSastResult, MappedContext, VerificationResult,
    LlmVerification,
    ExploitPayload, ExecutionResult, PatchProposal,
    VulnerabilityItem, AuthConfig
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

async def perform_pre_flight_checks(target_url: str) -> List[str]:
    errors = []
    required_binaries = ["nuclei", "semgrep", "katana"]
    for bin_name in required_binaries:
        if not shutil.which(bin_name):
            errors.append(f"필수 도구를 찾을 수 없습니다: {bin_name}")
            
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(target_url, follow_redirects=True)
            if resp.status_code >= 500:
                errors.append(f"타겟 서버가 불안정합니다. (HTTP {resp.status_code})")
    except Exception as e:
        errors.append(f"타겟 서버에 접근할 수 없습니다: {str(e)}")
        
    parsed = httpx.URL(target_url)
    if parsed.host in ["localhost", "127.0.0.1", "0.0.0.0"]:
        print(f"⚠️ [Security] 로컬 호스트({parsed.host}) 스캔이 요청되었습니다.")

    return errors

@app.get("/scan/history")
async def get_scan_history(limit: int = 10):
    return db_manager.list_jobs(limit=limit)

async def run_scan_pipeline(job_id: uuid.UUID, target_url: str, source_dir: str):
    state = db_manager.get_job(str(job_id))
    if not state: return

    async def update_state(status: ScanStatus, message: str = None):
        state.metadata.current_status = status
        db_manager.save_job(str(job_id), state)
        await ws_manager.broadcast(str(job_id), {"type": "status", "status": status, "message": message or f"Status changed to {status}"})

    try:
        if state.metadata.current_status == ScanStatus.QUEUED:
            await update_state(ScanStatus.QUEUED, "Pre-flight checks starting...")
            pre_flight_errors = await perform_pre_flight_checks(target_url)
            if pre_flight_errors:
                raise RuntimeError("\\n".join(pre_flight_errors))
            await update_state(ScanStatus.SCANNING, "Pre-flight checks passed.")

        if state.metadata.current_status == ScanStatus.SCANNING:
            await update_state(ScanStatus.SCANNING, "Starting DAST/SAST Scanning...")
            auth_headers = {}
            if state.metadata.auth_config:
                auth_headers.update(state.metadata.auth_config.headers)
                if state.metadata.auth_config.cookies:
                    auth_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in state.metadata.auth_config.cookies.items()])

            katana_urls, sast_raw = await asyncio.gather(
                run_katana(target_url, job_id=str(job_id)),
                run_semgrep(source_dir, job_id=str(job_id))
            )
            dast_raw = await run_nuclei(katana_urls, headers=auth_headers, job_id=str(job_id))
            merged_results = normalize_and_merge_results(dast_raw, sast_raw, None)
            
            if not merged_results:
                raise Exception("취약점이 발견되지 않았습니다.")
            
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Informational": 4}
            merged_results.sort(key=lambda x: severity_order.get(x.severity, 99))
            
            state.vulnerabilities = [VulnerabilityItem(dast_result=res) for res in merged_results[:15]]
            await update_state(ScanStatus.MAPPING, "Scanning completed.")
            await ws_manager.broadcast(str(job_id), {"type": "vulnerabilities", "data": [v.model_dump() for v in state.vulnerabilities]})

        if state.metadata.current_status == ScanStatus.MAPPING:
            await update_state(ScanStatus.MAPPING, "Mapping vulnerabilities to source code...")
            await asyncio.gather(*(map_single_item(item, source_dir) for item in state.vulnerabilities))
            await update_state(ScanStatus.VERIFYING, "Mapping completed.")
            await ws_manager.broadcast(str(job_id), {"type": "vulnerabilities", "data": [v.model_dump() for v in state.vulnerabilities]})

        if state.metadata.current_status == ScanStatus.VERIFYING:
            await update_state(ScanStatus.VERIFYING, "Invoking LLM for verification...")
            items_to_verify = [v for v in state.vulnerabilities if v.mapped_context and v.mapped_context.is_mapped and not v.llm_verification]
            if items_to_verify:
                batch_results = await verify_vulnerabilities_batch([v.mapped_context for v in items_to_verify], job_id=str(job_id))
                for item, llm_res in zip(items_to_verify, batch_results):
                    item.llm_verification = llm_res
            await update_state(ScanStatus.TESTING, "LLM Verification completed.")
            await ws_manager.broadcast(str(job_id), {"type": "vulnerabilities", "data": [v.model_dump() for v in state.vulnerabilities]})

        if state.metadata.current_status == ScanStatus.TESTING:
            await update_state(ScanStatus.TESTING, "Executing PoC payloads...")
            await asyncio.gather(*(verify_and_test(item, target_url, state.metadata.auth_config, str(job_id)) for item in state.vulnerabilities))
            await update_state(ScanStatus.COMPLETED, "PoC testing completed.")
            await ws_manager.broadcast(str(job_id), {"type": "vulnerabilities", "data": [v.model_dump() for v in state.vulnerabilities]})

        state.metadata.end_time = datetime.now(timezone.utc)
        await update_state(ScanStatus.COMPLETED, "Scan pipeline finished successfully.")
        generate_markdown_report(state)
        generate_word_report(state)
            
    except Exception as e:
        state.metadata.error_log = str(e)
        await update_state(ScanStatus.FAILED, f"Pipeline failed: {str(e)}")

async def map_single_item(item, source_dir):
    if not (item.mapped_context and item.mapped_context.is_mapped):
        try:
            item.mapped_context = await map_vulnerability_to_code(item.dast_result, source_dir)
        except Exception as e:
            print(f"⚠️ 매핑 실패 ({item.dast_result.vuln_type}): {e}")

async def verify_and_test(item, target_url, auth_config, job_id):
    if not item.execution and item.llm_verification and item.llm_verification.triager_result.is_vulnerable:
        try:
            item.execution = await run_exploit(target_url, item.dast_result, item.llm_verification.red_teamer_payload, auth_config, job_id)
        except Exception as e:
            print(f"⚠️ PoC 검증 실패 ({item.dast_result.vuln_type}): {e}")

@app.post("/scan/start")
async def start_scan(target_url: str, source_dir: str, background_tasks: BackgroundTasks, auth_config: Optional[AuthConfig] = None):
    try:
        resolved = Path(source_dir).resolve(strict=True)
    except FileNotFoundError:
        alt_path = Path("/app") / source_dir.lstrip("./")
        if alt_path.is_dir():
            resolved = alt_path
        else:
            raise HTTPException(status_code=400, detail=f"유효하지 않은 source_dir: {source_dir}")
    
    job_id = uuid.uuid4()
    metadata = ScanMetadata(target_host=target_url, source_dir=str(resolved), auth_config=auth_config)
    db_manager.save_job(str(job_id), FinalReportState(metadata=metadata))
    
    background_tasks.add_task(run_scan_pipeline, job_id, target_url, str(resolved))
    return {"job_id": job_id, "message": "Scan pipeline started."}

@app.get("/scan/status/{job_id}")
async def get_scan_status(job_id: uuid.UUID):
    state = db_manager.get_job(str(job_id))
    if not state:
        raise HTTPException(status_code=404, detail="Job not found")
    return state

frontend_path = Path(__file__).parent.parent / "frontend" / "dist"
if frontend_path.is_dir():
    app.mount("/assets", StaticFiles(directory=frontend_path / "assets"), name="assets")
    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        file_path = frontend_path / full_path
        if file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(frontend_path / "index.html")

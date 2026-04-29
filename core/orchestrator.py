import uuid
import asyncio
from pathlib import Path
from core import db_manager
from datetime import datetime, timezone
from typing import Dict
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks, HTTPException

from mapping.ast_parser import map_vulnerability_to_code
from intelligence.llm_client import verify_vulnerabilities_batch
from intelligence.reporter import generate_markdown_report
from scanner.engine import run_nuclei, run_semgrep, run_katana, run_zap
from scanner.parser import normalize_and_merge_results
from scanner.executor import run_exploit

from core.schemas import (
    ScanMetadata, ScanStatus, FinalReportState,
    DastSastResult, MappedContext, VerificationResult,
    LlmVerification,  # ✅ 추가
    ExploitPayload, ExecutionResult, PatchProposal, RegressionTestResult
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    db_manager.init_db()
    yield

app = FastAPI(title="Jangijoim Remediation Tool Pipeline", lifespan=lifespan)

job_store: Dict[uuid.UUID, FinalReportState] = {}


# =====================================================================
# [Core Pipeline] Role 1의 메인 비동기 워커 로직
# =====================================================================

async def run_scan_pipeline(job_id: uuid.UUID, target_url: str, source_dir: str):
    state = db_manager.get_job(str(job_id))
    if not state:
        return
    try:
        # 1단계: 스캔 (Adaptive Hybrid DAST 가동)
        state.metadata.current_status = ScanStatus.SCANNING
        db_manager.save_job(str(job_id), state)
        
        # [Tier 1-A] Katana 크롤링으로 공격 표면 확장
        katana_urls = await run_katana(target_url)
        
        # [Tier 1-B] Nuclei & Semgrep 병렬 가동
        dast_task = run_nuclei(katana_urls)
        sast_task = run_semgrep(source_dir)
        dast_raw, sast_raw = await asyncio.gather(dast_task, sast_task)
        
        # [Tier 2] 적응형 Fallback: DAST 탐지율이 SAST에 비해 너무 낮을 때 ZAP 가동
        zap_raw = None
        sast_count = len(sast_raw.get("results", []))
        dast_count = len(dast_raw)
        
        if sast_count >= 10 and dast_count <= 2:
            print(f"⚠️ [Adaptive] DAST 결과({dast_count})가 SAST({sast_count}) 대비 현저히 부족합니다. ZAP 심층 스캔을 시작합니다.")
            zap_raw = await run_zap(target_url)
        
        # 결과 통합 및 정규화
        merged_results = normalize_and_merge_results(dast_raw, sast_raw, zap_raw)
        
        if not merged_results:
            raise Exception("취약점이 발견되지 않았습니다. (DAST/SAST 모두 결과 없음)")
            
        # 다중 취약점 항목 초기화
        from core.schemas import VulnerabilityItem
        state.vulnerabilities = [VulnerabilityItem(dast_result=res) for res in merged_results]
        db_manager.save_job(str(job_id), state)

        # ---------------------------------------------------------
        # 이후 모든 단계(매핑, 판별, 검증)를 루프로 처리
        # ---------------------------------------------------------

        # 2단계: 코드 매핑
        state.metadata.current_status = ScanStatus.MAPPING
        db_manager.save_job(str(job_id), state)
        
        async def map_single_item(item):
            try:
                mapped_ctx = await map_vulnerability_to_code(item.dast_result, source_dir)
                item.mapped_context = mapped_ctx
            except Exception as e:
                print(f"⚠️ 매핑 실패 ({item.dast_result.vuln_type}): {e}")

        # 모든 항목에 대해 병렬 매핑 수행
        await asyncio.gather(*(map_single_item(item) for item in state.vulnerabilities))
        
        db_manager.save_job(str(job_id), state)

        # 3단계: LLM 멀티 에이전트 판별
        state.metadata.current_status = ScanStatus.VERIFYING
        db_manager.save_job(str(job_id), state)

        # 매핑 성공한 항목들만 모아서 배치 처리
        mapped_items = [v for v in state.vulnerabilities if v.mapped_context and v.mapped_context.is_mapped]
        if mapped_items:
            try:
                batch_results = await verify_vulnerabilities_batch([v.mapped_context for v in mapped_items])
                for item, llm_res in zip(mapped_items, batch_results):
                    item.llm_verification = llm_res
            except Exception as e:
                print(f"⚠️ LLM 판별 단계 실패: {e}")
        
        db_manager.save_job(str(job_id), state)

        # 4단계: 페이로드 실행 및 회귀 테스트
        state.metadata.current_status = ScanStatus.TESTING
        db_manager.save_job(str(job_id), state)
        
        for item in state.vulnerabilities:
            # LLM이 정탐으로 판별하고 페이로드를 생성한 경우만 실행
            if item.llm_verification and item.llm_verification.triager_result.is_vulnerable:
                try:
                    execution_result = await run_exploit(
                        target_url,
                        item.dast_result,
                        item.llm_verification.red_teamer_payload
                    )
                    item.execution = execution_result
                    item.regression_test = RegressionTestResult(
                        is_mitigated=not execution_result.is_exploited,
                        http_status_after_patch=execution_result.http_status,
                        rollback_successful=True
                    )
                except Exception as e:
                    print(f"⚠️ PoC 검증 실패 ({item.dast_result.vuln_type}): {e}")

        # 완료 처리
        state.metadata.current_status = ScanStatus.COMPLETED
        state.metadata.end_time = datetime.now(timezone.utc)
        db_manager.save_job(str(job_id), state)
        
        # 5단계: 최종 보고서 생성
        generate_markdown_report(state)
        
    except Exception as e:
        state.metadata.current_status = ScanStatus.FAILED
        state.metadata.error_log = str(e)
        state.metadata.end_time = datetime.now(timezone.utc)
        db_manager.save_job(str(job_id), state)


# =====================================================================
# [API Endpoints] CLI 인터페이스와 통신하는 엔드포인트
# =====================================================================

@app.post("/scan/start")
async def start_scan(target_url: str, source_dir: str, background_tasks: BackgroundTasks):
    resolved = Path(source_dir).resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise HTTPException(status_code=400, detail="유효하지 않은 source_dir 경로입니다.")
    
    job_id = uuid.uuid4()
    
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
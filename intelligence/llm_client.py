import os
import json
import asyncio
from google import genai
from google.genai import types
from typing import List, Optional
from core.schemas import (
    MappedContext,
    VerificationResult,
    ExploitPayload,
    PatchProposal,
    LlmVerification,
    LLMUsage,
)
from intelligence.prompts import (
    TRIAGER_PROMPT,
    RED_TEAMER_PROMPT,
    BLUE_TEAMER_PROMPT,
    QA_PROMPT,
)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
# 모델을 환경변수에서 가져오도록 변경 (기본값: 고성능 모델인 gemini-2.5-pro)
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-pro")

client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else genai.Client()


# =====================================================================
# [내부 헬퍼] 단일 Gemini API 호출 래퍼
# =====================================================================

async def _call_gemini(system_prompt: str, user_prompt: str) -> dict:
    """
    Gemini API를 호출하고 JSON 응답을 파싱하여 dict로 반환합니다.
    503 UNAVAILABLE 및 429 RESOURCE_EXHAUSTED 에러 발생 시 재시도 로직을 포함합니다.
    """
    max_retries = 5 # 재시도 횟수 상향
    base_delay = 5 # 기본 대기 시간 상향
    
    for attempt in range(max_retries):
        try:
            response = await client.aio.models.generate_content(
                model=GEMINI_MODEL,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    temperature=0.1,
                    response_mime_type="application/json",
                )
            )
            
            raw_text = response.text.strip()
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:-3].strip()
            elif raw_text.startswith("```"):
                raw_text = raw_text[3:-3].strip()
                
            try:
                parsed = json.loads(raw_text)
                if isinstance(parsed, list) and len(parsed) > 0:
                    return parsed[0] if isinstance(parsed[0], dict) else {"error": "Invalid list format"}
                return parsed if isinstance(parsed, dict) else {"error": "Invalid JSON format"}
            except json.JSONDecodeError:
                import re
                # JSON 표준 이스케이프가 아닌 단일 백슬래시를 이중 백슬래시로 변환
                fixed_text = re.sub(r'\\([^"\\/bfnrt])', r'\\\\\1', raw_text)
                parsed = json.loads(fixed_text)
                if isinstance(parsed, list) and len(parsed) > 0:
                    return parsed[0] if isinstance(parsed[0], dict) else {"error": "Invalid list format"}
                return parsed if isinstance(parsed, dict) else {"error": "Invalid JSON format"}
            
        except Exception as e:
            error_str = str(e)
            # 503 (Unavailable) 및 429 (Rate Limit/Quota) 모두 재시도 대상으로 포함
            if any(code in error_str for code in ["503", "429", "UNAVAILABLE", "RESOURCE_EXHAUSTED"]):
                if attempt < max_retries - 1:
                    # 지수 백오프 적용 (5, 10, 20, 40초 ...)
                    delay = base_delay * (2 ** attempt)
                    if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str:
                        # 쿼터 초과 시 더 긴 대기 시간을 가짐 (최대 1분 이상 대기하도록 유도)
                        delay += 10
                    
                    print(f"⚠️ Gemini API 부하/쿼터 제한 발생 ({error_str[:50]}...). {delay}초 후 재시도 중... ({attempt + 1}/{max_retries})")
                    await asyncio.sleep(delay)
                    continue
            raise RuntimeError(f"Gemini 호출 실패 (시도 {attempt+1}): {error_str}")

    raise RuntimeError("Gemini API 재시도 횟수 초과")


# =====================================================================
# [Agent 1] Triager - 정오탐 판별 + CVSS 산정
# =====================================================================

async def _run_triager(ctx: MappedContext) -> VerificationResult:
    """
    DAST 결과와 매핑된 소스코드를 교차 검증하여 정오탐을 판별합니다.
    """
    user_prompt = f"""
다음 취약점 데이터를 분석하여 정탐/오탐 여부를 판별하십시오.

[취약점 정보]
- 취약점 유형: {ctx.dast_data.vuln_type}
- 엔드포인트: {ctx.dast_data.http_method} {ctx.dast_data.target_endpoint}
- 공격 페이로드: {ctx.dast_data.payload}
- 스캐너 응답: {ctx.dast_data.sliced_response}
- 매핑 방식: {ctx.mapping_method.value}
- 매핑 신뢰도: {ctx.mapping_confidence} ({ctx.mapping_confidence_band.value})
- 매핑 근거: {', '.join(ctx.mapping_evidence) if ctx.mapping_evidence else '근거 없음'}

[매핑된 소스코드 ({ctx.mapped_file_path}, L{ctx.start_line}~{ctx.end_line})]
```python
{ctx.code_snippet}
```

[출력 JSON 형식]
{{
    "is_vulnerable": true 또는 false,
    "cvss_vector": "CVSS:3.1/AV:.../...",
    "cvss_score": 0.0~10.0,
    "confidence_score": 0.0~1.0,
    "reason": "판단 요약 (한국어, 마크다운 허용)",
    "evidence_points": ["증거 1", "증거 2"],
    "reasoning_process": ["단계 1", "단계 2"]
}}
"""
    result = await _call_gemini(TRIAGER_PROMPT, user_prompt)
    return VerificationResult(
        is_vulnerable=result.get("is_vulnerable", False),
        cvss_vector=result.get("cvss_vector"),
        cvss_score=result.get("cvss_score", 0.0),
        confidence_score=result.get("confidence_score", 0.0),
        reason=result.get("reason", "분석 사유 누락"),
        evidence_points=result.get("evidence_points", []),
        reasoning_process=result.get("reasoning_process", []),
    )


# =====================================================================
# [Agent 2] Red Teamer - PoC 익스플로잇 페이로드 생성
# =====================================================================

async def run_red_teamer(ctx: MappedContext, triager_result: VerificationResult, feedback: str = None) -> ExploitPayload:
    """
    Triager가 정탐으로 판별한 경우, 패치 검증용 PoC 페이로드를 생성합니다.
    실패 시 feedback을 받아 페이로드를 수정합니다.
    """
    if not triager_result.is_vulnerable:
        return ExploitPayload(
            method=ctx.dast_data.http_method,
            endpoint=ctx.dast_data.target_endpoint,
            body=ctx.dast_data.payload,
            expected_success_regex="N/A",
        )

    feedback_part = f"\n[이전 공격 실패 결과 및 피드백]\n{feedback}\n이 결과를 바탕으로 페이로드를 수정하십시오." if feedback else ""
    
    user_prompt = f"""
Triager가 아래 취약점을 정탐으로 판별했습니다.
패치 코드의 방어 로직을 검증하기 위한 PoC 익스플로잇 페이로드를 생성하십시오.
{feedback_part}

[취약점 정보]
- 유형: {ctx.dast_data.vuln_type}
- 추천 엔드포인트: {ctx.dast_data.target_endpoint}
- 추천 메서드: {ctx.dast_data.http_method}
- 기존 페이로드: {ctx.dast_data.payload}
- 판별 근거: {triager_result.reason}

[출력 JSON 형식]
{{
    "method": "메서드",
    "endpoint": "엔드포인트 경로",
    "headers": {{"Header-Name": "Value"}},
    "body": "페이로드",
    "expected_success_regex": "정규식"
}}
"""
    result = await _call_gemini(RED_TEAMER_PROMPT, user_prompt)
    
    # LLM이 잘못된 엔드포인트를 생성하는 경우를 대비한 방어 로직
    method = result.get("method", ctx.dast_data.http_method).upper()
    endpoint = result.get("endpoint", ctx.dast_data.target_endpoint)
    
    # 엔드포인트가 외부 URL(http://...)을 포함하는 경우 경로만 추출
    if endpoint.startswith("http"):
        from urllib.parse import urlparse
        endpoint = urlparse(endpoint).path
        if not endpoint: endpoint = "/"
    
    headers = result.get("headers") if isinstance(result.get("headers"), dict) else {}

    return ExploitPayload(
        method=method,
        endpoint=endpoint,
        headers=headers,
        body=result.get("body"),
        expected_success_regex=result.get("expected_success_regex", ".*"),
    )


# =====================================================================
# [Agent 3] Blue Teamer - 시큐어 코딩 패치 생성
# =====================================================================

async def _run_blue_teamer(ctx: MappedContext, triager_result: VerificationResult) -> PatchProposal:
    """
    취약한 코드를 입력받아 방어 로직이 적용된 패치 코드를 생성합니다.
    오탐이면 패치 불필요로 반환합니다.
    """
    if not triager_result.is_vulnerable:
        return PatchProposal(
            is_patch_generated=False,
            original_code=ctx.code_snippet or "",
            patched_code=ctx.code_snippet or "",
            remediation_steps=["오탐으로 판별되어 패치가 필요하지 않습니다."],
        )

    user_prompt = f"""
아래 취약한 코드에 대해 방어 로직이 적용된 패치 코드를 작성하십시오.

[취약점 유형]
{ctx.dast_data.vuln_type}

[원본 취약 코드 ({ctx.mapped_file_path})]
```python
{ctx.code_snippet}
```

[판별 근거]
{triager_result.reason}

[출력 JSON 형식]
{{
    "is_patch_generated": true,
    "original_code": "원본 코드 그대로",
    "patched_code": "방어 로직이 적용된 수정 코드",
    "remediation_steps": ["1. 조치 내용", "2. 조치 내용"]
}}
"""
    result = await _call_gemini(BLUE_TEAMER_PROMPT, user_prompt)
    return PatchProposal(
        is_patch_generated=result.get("is_patch_generated", False),
        original_code=result.get("original_code", ctx.code_snippet or ""),
        patched_code=result.get("patched_code", ctx.code_snippet or ""),
        remediation_steps=result.get("remediation_steps", []),
    )


# =====================================================================
# [Agent 4] QA - 패치 코드 품질 검수
# =====================================================================

async def _run_qa(patch: PatchProposal) -> tuple[bool, str]:
    """
    Blue Teamer가 생성한 패치 코드의 문법 오류, 무한 루프 등을 검수합니다.
    패치가 생성되지 않은 경우 자동 통과 처리합니다.
    """
    if not patch.is_patch_generated:
        return True, "패치 없음 (오탐) - QA 자동 통과"

    user_prompt = f"""
아래 패치 코드를 검수하십시오.

[원본 코드]
```python
{patch.original_code}
```

[패치 코드]
```python
{patch.patched_code}
```

[적용된 조치]
{chr(10).join(f"- {s}" for s in patch.remediation_steps)}

[출력 JSON 형식]
{{
    "qa_passed": true 또는 false,
    "qa_feedback": "검수 결과 및 피드백 (한국어)"
}}
"""
    result = await _call_gemini(QA_PROMPT, user_prompt)
    return result.get("qa_passed", False), result.get("qa_feedback", "QA 피드백 누락")


from core.ws_manager import manager as ws_manager
from datetime import datetime

async def log_to_ws(job_id: Optional[str], message: str, level: str = "info"):
    if job_id:
        timestamp = datetime.now().strftime("%H:%M:%S")
        await ws_manager.broadcast(job_id, {"type": "log", "message": message, "level": level, "timestamp": timestamp})

# =====================================================================
# [Public API] orchestrator.py에서 호출하는 메인 함수
# =====================================================================

async def verify_vulnerabilities_batch(mapped_contexts: List[MappedContext], job_id: Optional[str] = None) -> List[LlmVerification]:
    """
    [4중 멀티 에이전트 파이프라인 - 병렬 처리]
    각 항목에 대해 Triager → Red Teamer → Blue Teamer → QA 순서로 실행하며,
    여러 항목을 동시에 처리합니다.
    (기존 Semaphore(1) 제한을 풀고 3개 정도로 완화하며 지수 백오프에 의존합니다)
    """
    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY 환경변수가 설정되지 않았습니다.")

    if not mapped_contexts:
        return []

    # 동시 처리 개수를 3개로 완화 (Gemini Pro 등급 쿼터 고려)
    semaphore = asyncio.Semaphore(3)

    async def process_item(idx, ctx):
        async with semaphore:
            msg = f"🤖 [LLM Agent] 항목 {idx + 1} 처리 시작... ({ctx.dast_data.vuln_type})"
            print(msg)
            await log_to_ws(job_id, msg)
            try:
                # Agent 1: Triager
                await log_to_ws(job_id, f"  └ [Triager] 정오탐 판별 중... ({idx + 1})")
                triager_result = await _run_triager(ctx)

                # Agent 2: Red Teamer
                await log_to_ws(job_id, f"  └ [Red Teamer] 익스플로잇 페이로드 생성 중... ({idx + 1})")
                red_teamer_payload = await run_red_teamer(ctx, triager_result)

                # Agent 3: Blue Teamer
                await log_to_ws(job_id, f"  └ [Blue Teamer] 보안 패치 코드 작성 중... ({idx + 1})")
                blue_teamer_patch = await _run_blue_teamer(ctx, triager_result)

                # Agent 4: QA
                await log_to_ws(job_id, f"  └ [QA] 생성된 패치 검수 중... ({idx + 1})")
                qa_passed, qa_feedback = await _run_qa(blue_teamer_patch)

                done_msg = f"✅ [LLM Agent] 항목 {idx + 1} 파이프라인 완료"
                print(done_msg)
                await log_to_ws(job_id, done_msg, "success")
                return LlmVerification(
                    triager_result=triager_result,
                    red_teamer_payload=red_teamer_payload,
                    blue_teamer_patch=blue_teamer_patch,
                    qa_passed=qa_passed,
                    qa_feedback=qa_feedback,
                )

            except Exception as e:
                print(f"❌ [Agent Pipeline] 항목 {idx + 1} 처리 실패: {e}")
                return LlmVerification(
                    triager_result=VerificationResult(
                        is_vulnerable=False,
                        reason=f"에이전트 파이프라인 실패: {str(e)}",
                        cvss_score=0.0,
                    ),
                    red_teamer_payload=ExploitPayload(
                        method="N/A",
                        endpoint="N/A",
                        expected_success_regex="N/A",
                    ),
                    blue_teamer_patch=PatchProposal(
                        is_patch_generated=False,
                        original_code="",
                        patched_code="",
                        remediation_steps=[f"파이프라인 실패: {str(e)}"],
                    ),
                    qa_passed=False,
                    qa_feedback=f"파이프라인 오류로 QA 불가: {str(e)}",
                )

    # 모든 항목에 대해 병렬 작업 생성
    tasks = [process_item(i, ctx) for i, ctx in enumerate(mapped_contexts)]
    return await asyncio.gather(*tasks)

# =====================================================================
# [Tests] 모듈 자체 테스트 코드
# =====================================================================
if __name__ == "__main__":
    from core.schemas import DastSastResult, FinalReportState, ScanMetadata, VulnerabilityItem, RegressionTestResult, ExecutionResult
    from intelligence.reporter import generate_markdown_report

    async def run_pipeline_test():
        print("🚀 Role 3 테스트를 위한 가짜(Mock) 데이터 생성 중...")
        
        # 1. Mock 데이터 생성 (중복 취약점 테스트를 위해 2개 생성)
        mock_dast1 = DastSastResult(
            target_endpoint="/api/login",
            http_method="POST",
            vuln_type="SQL Injection",
            severity="High",
            payload="' OR 1=1 --",
            sliced_response="sqlite3.OperationalError: unrecognized token"
        )
        
        mock_context1 = MappedContext(
            dast_data=mock_dast1,
            is_mapped=True,
            mapped_file_path="juice-shop-src/routes/login.ts",
            ast_node_type="FunctionDef",
            start_line=10,
            end_line=20,
            code_snippet='''
    app.post('/api/login', (req, res) => {
      const query = `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${req.body.password}'`
      db.query(query).then(user => { ... })
    })
    '''
        )

        mock_dast2 = DastSastResult(
            target_endpoint="/api/login",
            http_method="POST",
            vuln_type="SQL Injection",
            severity="High",
            payload="' OR 'a'='a",
            sliced_response="sqlite3.OperationalError: unrecognized token"
        )
        
        mock_context2 = MappedContext(
            dast_data=mock_dast2,
            is_mapped=True,
            mapped_file_path="juice-shop-src/routes/login.ts",
            ast_node_type="FunctionDef",
            start_line=10,
            end_line=20,
            code_snippet='''
    app.post('/api/login', (req, res) => {
      const query = `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${req.body.password}'`
      db.query(query).then(user => { ... })
    })
    '''
        )

        print("🤖 멀티 에이전트 파이프라인 가동! (병렬 처리)")
        try:
            # 1. LLM 추론 파이프라인 실행
            llm_results = await verify_vulnerabilities_batch([mock_context1, mock_context2])
            print(f"\n[+] LLM {len(llm_results)}개 항목 처리 완료")
            
            # 2. 파이프라인 최종 상태(FinalReportState) 구성
            mock_metadata = ScanMetadata(
                target_host="http://localhost:3000",
                source_dir="./juice-shop-src"
            )
            
            vulnerabilities = []
            for i, (ctx, llm_res) in enumerate(zip([mock_context1, mock_context2], llm_results)):
                # [신규] 실제 실행 결과 시뮬레이션
                if i == 0:
                    execution = ExecutionResult(
                        is_exploited=True,
                        http_status=200,
                        execution_time_ms=150.5,
                        request_url=f"http://localhost:3000{ctx.dast_data.target_endpoint}",
                        request_method=ctx.dast_data.http_method,
                        request_headers={"Content-Type": "application/json", "User-Agent": "Gemini-Scanner"},
                        request_body=ctx.dast_data.payload,
                        response_snippet="HTTP/1.1 200 OK\nContent-Type: text/html\n\n[ERROR] sqlite3.OperationalError: unrecognized token near \"OR\"",
                        exploit_failure_reason=None
                    )
                else:
                    execution = ExecutionResult(
                        is_exploited=False,
                        http_status=403,
                        execution_time_ms=50.2,
                        request_url=f"http://localhost:3000{ctx.dast_data.target_endpoint}",
                        request_method=ctx.dast_data.http_method,
                        request_headers={"Content-Type": "application/json", "User-Agent": "Gemini-Scanner"},
                        request_body=ctx.dast_data.payload,
                        response_snippet="<html><head><title>403 Forbidden</title></head><body>Your request was blocked by WAF.</body></html>",
                        exploit_failure_reason="보안 장비(WAF/IPS)에 의한 차단 의심 (HTTP 403)"
                    )

                # 모의 회귀 테스트 결과 (하나는 성공, 하나는 실패로 시뮬레이션 가능)
                regression = RegressionTestResult(
                    is_mitigated=True if i == 0 else False,
                    http_status_after_patch=403 if i == 0 else 200,
                    rollback_successful=True
                )
                
                vulnerabilities.append(VulnerabilityItem(
                    dast_result=ctx.dast_data,
                    mapped_context=ctx,
                    llm_verification=llm_res,
                    execution=execution,
                    regression_test=regression
                ))
                
            final_state = FinalReportState(
                metadata=mock_metadata,
                vulnerabilities=vulnerabilities
            )
            
            # 3. 마크다운 보고서 렌더링 함수 호출
            report_path = generate_markdown_report(final_state)
            print(f"\n✅ 테스트 완료! 상세 보고서가 성공적으로 생성되었습니다.")
            print(f"👉 확인 경로: {report_path}")

        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"\n❌ [오류 발생]: {e}")

    asyncio.run(run_pipeline_test())
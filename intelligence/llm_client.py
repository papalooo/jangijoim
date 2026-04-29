import os
import json
import asyncio
from google import genai
from google.genai import types
from typing import List
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
# 모델을 환경변수에서 가져오도록 변경 (기본값은 고성능 모델인 gemini-2.5-pro)
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
            return json.loads(response.text)
            
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
    "reason": "판단 근거 (한국어, 마크다운 허용)"
}}
"""
    result = await _call_gemini(TRIAGER_PROMPT, user_prompt)
    return VerificationResult(
        is_vulnerable=result.get("is_vulnerable", False),
        cvss_vector=result.get("cvss_vector"),
        cvss_score=result.get("cvss_score", 0.0),
        reason=result.get("reason", "분석 사유 누락"),
    )


# =====================================================================
# [Agent 2] Red Teamer - PoC 익스플로잇 페이로드 생성
# =====================================================================

async def _run_red_teamer(ctx: MappedContext, triager_result: VerificationResult) -> ExploitPayload:
    """
    Triager가 정탐으로 판별한 경우, 패치 검증용 PoC 페이로드를 생성합니다.
    오탐인 경우 더미 페이로드를 반환합니다.
    """
    # 오탐이면 API 호출 없이 더미 반환 (비용 절감)
    if not triager_result.is_vulnerable:
        return ExploitPayload(
            method=ctx.dast_data.http_method,
            endpoint=ctx.dast_data.target_endpoint,
            body=ctx.dast_data.payload,
            expected_success_regex="N/A (오탐으로 판별됨)",
        )

    user_prompt = f"""
Triager가 아래 취약점을 정탐으로 판별했습니다.
패치 코드의 방어 로직을 검증하기 위한 PoC 익스플로잇 페이로드를 생성하십시오.

[취약점 정보]
- 유형: {ctx.dast_data.vuln_type}
- 엔드포인트: {ctx.dast_data.http_method} {ctx.dast_data.target_endpoint}
- 기존 페이로드: {ctx.dast_data.payload}
- 판별 근거: {triager_result.reason}

[출력 JSON 형식]
{{
    "method": "POST",
    "endpoint": "/api/login",
    "headers": {{"Content-Type": "application/x-www-form-urlencoded"}},
    "body": "페이로드 문자열",
    "expected_success_regex": "공격 성공 판별 정규식"
}}
"""
    result = await _call_gemini(RED_TEAMER_PROMPT, user_prompt)
    return ExploitPayload(
        method=result.get("method", ctx.dast_data.http_method),
        endpoint=result.get("endpoint", ctx.dast_data.target_endpoint),
        headers=result.get("headers", {}),
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


# =====================================================================
# [Public API] orchestrator.py에서 호출하는 메인 함수
# =====================================================================

async def verify_vulnerabilities_batch(mapped_contexts: List[MappedContext]) -> List[LlmVerification]:
    """
    [4중 멀티 에이전트 파이프라인 - 병렬 처리]
    각 항목에 대해 Triager → Red Teamer → Blue Teamer → QA 순서로 실행하며,
    여러 항목을 동시에 처리합니다. (API 쿼터 보호를 위해 세마포어 사용)
    """
    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY 환경변수가 설정되지 않았습니다.")

    if not mapped_contexts:
        return []

    # 쿼터 제한을 고려하여 동시 처리 개수 제한 (1개로 축소하여 순차적 처리 유도)
    semaphore = asyncio.Semaphore(1)

    async def process_item(idx, ctx):
        async with semaphore:
            print(f"[Agent Pipeline] 항목 {idx + 1} 처리 시작... ({ctx.dast_data.vuln_type})")
            try:
                # Agent 1: Triager
                triager_result = await _run_triager(ctx)

                # Agent 2: Red Teamer
                red_teamer_payload = await _run_red_teamer(ctx, triager_result)

                # Agent 3: Blue Teamer
                blue_teamer_patch = await _run_blue_teamer(ctx, triager_result)

                # Agent 4: QA
                qa_passed, qa_feedback = await _run_qa(blue_teamer_patch)

                print(f"✅ [Agent Pipeline] 항목 {idx + 1} 처리 완료")
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
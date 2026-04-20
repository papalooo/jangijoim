import os
import json
from google import genai
from google.genai import types
from typing import List
from core.schemas import MappedContext, VerificationResult

# 환경 변수에서 API 키 로드
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# 최신 SDK 규격에 맞춘 Client 초기화
# SDK는 기본적으로 GEMINI_API_KEY 환경변수를 자동 인식하지만, 명시적으로 주입합니다.
client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else genai.Client()

async def verify_vulnerabilities_batch(mapped_contexts: List[MappedContext]) -> List[VerificationResult]:
    """
    [Agent 1: Triager - Batch Mode]
    여러 개의 의심 취약점을 한 번의 API 호출로 일괄 분석하여 Rate Limit을 방지하고 속도를 극대화합니다.
    """
    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY 환경변수가 설정되지 않았습니다.")
        
    if not mapped_contexts:
        return []

    # ---------------------------------------------------------
    # 1. N개의 컨텍스트를 하나의 문자열로 압축 (Batching)
    # ---------------------------------------------------------
    batch_data_str = ""
    for idx, ctx in enumerate(mapped_contexts):
        batch_data_str += f"=== [항목 ID: {idx}] ===\n"
        batch_data_str += f"- 취약점 유형: {ctx.dast_data.vuln_type}\n"
        batch_data_str += f"- 엔드포인트: {ctx.dast_data.target_endpoint}\n"
        batch_data_str += f"- HTTP 메소드: {ctx.dast_data.http_method}\n"
        batch_data_str += f"- 공격 페이로드: {ctx.dast_data.payload}\n"
        batch_data_str += f"- 매핑된 코드:\n```python\n{ctx.code_snippet}\n```\n\n"

    # ---------------------------------------------------------
    # 2. 일괄 처리 시스템 프롬프트 작성
    # ---------------------------------------------------------
    prompt = f"""
    당신은 최고 수준의 AppSec 엔지니어입니다.
    다음은 동적 분석(DAST)으로 탐지된 의심 취약점들과 그에 매핑된 소스코드(AST) 목록입니다.
    입력된 **모든 항목(ID 0 ~ {len(mapped_contexts)-1})**에 대해 빠짐없이 정/오탐(True/False Positive)을 분석하십시오.

    [분석 대상 데이터]
    {batch_data_str}

    [출력 스키마 제약 조건]
    반드시 아래의 JSON 형식을 엄격히 따르는 객체를 반환해야 합니다:
    {{
        "results": [
            {{
                "id": 0,
                "is_vulnerable": true 또는 false,
                "reason": "코드의 어느 부분 때문에 정탐/오탐으로 판단했는지에 대한 구체적인 근거 (한국어)",
                "cvss_score": 0.0~10.0 사이의 실수
            }},
            ... (나머지 항목들도 동일한 구조로 추가)
        ]
    }}
    """

    try:
        # 단 1번의 API 호출로 전체 데이터 전송 (최신 SDK 비동기 방식 적용)
        response = await client.aio.models.generate_content(
            model="gemini-3.1-flash-lite-preview", # 이전 프롬프트에서 확인된 최신 모델인 gemini-2.5-flash로 변경을 권장합니다.
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
                response_mime_type="application/json",
            )
        )
        result_dict = json.loads(response.text)
        
        # ---------------------------------------------------------
        # 3. 반환된 JSON 배열을 VerificationResult 객체 리스트로 매핑
        # ---------------------------------------------------------
        verified_results = []
        returned_array = result_dict.get("results", [])
        
        for idx in range(len(mapped_contexts)):
            item_result = next((item for item in returned_array if item.get("id") == idx), None)
            
            if item_result:
                verified_results.append(VerificationResult(
                    is_vulnerable=item_result.get("is_vulnerable", False),
                    reason=item_result.get("reason", "분석 사유 누락"), # ✅ 수정 완료
                    cvss_score=item_result.get("cvss_score", 0.0)
                ))
            else:
                verified_results.append(VerificationResult(
                    is_vulnerable=False,
                    reason="LLM 분석 중 누락되거나 안전 필터에 의해 거부되었습니다.", # ✅ 수정 완료
                    cvss_score=0.0
                ))
                
        return verified_results

    except json.JSONDecodeError as e:
        raise RuntimeError(f"Gemini 응답 JSON 파싱 실패: {response.text}") from e
    except Exception as e:
        raise RuntimeError(f"Gemini Batch API 통신 오류: {str(e)}") from e
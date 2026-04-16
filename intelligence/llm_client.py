# intelligence/llm_client.py
import os
import json
from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import ValidationError

from core.schemas import MappedContext, LlmVerification
# 방금 작성한 4개의 프롬프트를 정확히 불러옵니다.
from intelligence.prompts import TRIAGER_PROMPT, RED_TEAMER_PROMPT, BLUE_TEAMER_PROMPT, QA_PROMPT

load_dotenv()

async def run_multi_agent_pipeline(context: MappedContext) -> LlmVerification:
    """
    [Role 3] 4중 멀티 에이전트를 가동하여 정오탐 판별 및 패치 코드를 생성합니다.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY가 설정되지 않았습니다. .env 파일을 확인하세요.")
    
    client = genai.Client(api_key=api_key)

    schema_blueprint = LlmVerification.model_json_schema()

    # 4개의 프롬프트를 하나의 시스템 프롬프트로 조립합니다.
    system_prompt = f"""
    당신은 4개의 자아(Triager, Red Teamer, Blue Teamer, QA)를 가진 통합 보안 지능입니다. 
    각 역할에 맞는 응답을 한글로 작성해야 합니다.

    [Role 1: Triager]
    {TRIAGER_PROMPT}

    [Role 2: Red Teamer]
    {RED_TEAMER_PROMPT}

    [Role 3: Blue Teamer]
    {BLUE_TEAMER_PROMPT}

    [Role 4: QA]
    {QA_PROMPT}

    [출력 규칙 - 절대 엄수]
    당신의 응답은 반드시 아래의 JSON Schema(설계도) 규격을 100% 준수해야 합니다.
    정의되지 않은 키를 임의로 만들지 말고, 요구된 모든 필수 필드를 채우십시오.

    Expected JSON Schema:
    {json.dumps(schema_blueprint, indent=2, ensure_ascii=False)}
    """

    user_payload = f"""
    [분석 대상 데이터]
    - 엔드포인트: {context.dast_data.target_endpoint}
    - 공격 페이로드: {context.dast_data.payload}
    - 응답 에러: {context.dast_data.sliced_response}
    - 타겟 소스코드:
    {context.code_snippet}
    """

    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=[system_prompt, user_payload],
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.1,
            ),
        )
    except Exception as e:
        raise RuntimeError(f"Gemini API 호출 실패: {e}")

    raw_text = response.text.strip()

    # 마크다운 찌꺼기 제거 (기존 로직 유지)
    if raw_text.startswith("```json"):
        raw_text = raw_text[7:-3].strip()
    elif raw_text.startswith("```"):
        raw_text = raw_text[3:-3].strip()

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM이 유효하지 않은 JSON을 반환했습니다: {e}\n원문: {raw_text[:300]}")

    if len(data) == 1 and isinstance(list(data.values())[0], dict):
        data = list(data.values())[0]

    try:
        result = LlmVerification.model_validate(data)
    except ValidationError as e:
        raise ValueError(f"LLM 응답이 스키마와 불일치합니다: {e}")

    return result
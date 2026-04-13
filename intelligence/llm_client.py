import os
import json
from dotenv import load_dotenv
from google import genai
from google.genai import types

from core.schemas import MappedContext
from intelligence.schemas import LlmVerification
from intelligence.prompts import TRIAGER_PROMPT, RED_TEAMER_PROMPT, BLUE_TEAMER_PROMPT, QA_PROMPT

load_dotenv()
my_api_key = os.getenv("GEMINI_API_KEY")
if not my_api_key:
    raise ValueError("🚨 .env 파일에서 GEMINI_API_KEY를 찾을 수 없습니다! 파일 위치와 이름을 확인해주세요.")

client = genai.Client(api_key=my_api_key)

async def run_multi_agent_pipeline(context: MappedContext) -> LlmVerification:
    """
    [Role 3] 4중 멀티 에이전트를 가동하여 정오탐 판별 및 패치 코드를 생성합니다.
    """
    # ⭐️ 핵심: Pydantic 모델의 구조(설계도)를 JSON 문자열로 자동 추출합니다.
    schema_blueprint = LlmVerification.model_json_schema()

    system_prompt = f"""
    당신은 4개의 자아(Triager, Red Teamer, Blue Teamer, QA)를 가진 통합 보안 지능(OpenClaw)입니다.
    다음의 각 역할을 순차적으로 수행하십시오.

    [역할 1] {TRIAGER_PROMPT}
    [역할 2] {RED_TEAMER_PROMPT}
    [역할 3] {BLUE_TEAMER_PROMPT}
    [역할 4] {QA_PROMPT}

    [출력 규칙 - 절대 엄수]
    당신의 응답은 반드시 아래의 JSON Schema(설계도) 규격을 100% 준수해야 합니다.
    정의되지 않은 키(예: 'triager_analysis')를 임의로 만들지 말고, 요구된 모든 필수 필드를 채우십시오.

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

    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=[
            system_prompt,
            user_payload
        ],
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.1,
        ),
    )

    raw_text = response.text.strip()
    
    # 마크다운 찌꺼기 1차 제거
    if raw_text.startswith("```json"):
        raw_text = raw_text[7:-3].strip()
    elif raw_text.startswith("```"):
        raw_text = raw_text[3:-3].strip()

    data = json.loads(raw_text)

    # Gemini가 혹시라도 바깥에 한 겹 더 포장했다면 벗겨냅니다.
    if len(data) == 1 and isinstance(list(data.values())[0], dict):
        data = list(data.values())[0]

    # 정제된 딕셔너리를 Pydantic 객체로 변환
    result = LlmVerification.model_validate(data)
    return result
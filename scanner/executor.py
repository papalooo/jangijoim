import requests
import asyncio
import time
import re
from core.schemas import ExecutionResult, ExploitPayload, DastSastResult

async def run_exploit(target_url: str, dast_res: DastSastResult, payload_data: ExploitPayload) -> ExecutionResult:
    """
    [Role 2] 4단계: AI가 생성한 페이로드를 실제 타겟에 전송하고 결과를 검증합니다.
    """
    print(f"\n[DEBUG] 🔫 타겟({target_url})으로 PoC 공격 발사 중...")

    # AI가 제안한 엔드포인트와 메서드 사용 (없으면 DAST 정보 활용)
    endpoint = payload_data.endpoint if payload_data.endpoint else dast_res.target_endpoint
    method = payload_data.method.upper() if payload_data.method else dast_res.http_method.upper()

    full_url = f"{target_url.rstrip('/')}{endpoint}"
    headers = payload_data.headers or {}
    body = payload_data.body

    # ⏱️ 시간 측정 시작
    start_time = time.time()

    try:
        # 비동기 환경에서의 요청 처리를 위해 루프에서 실행하거나 httpx 사용 권장
        # 여기서는 기존 requests 호환성을 위해 유지하되 timeout 설정

        response = None
        if method == "POST":
            # Body가 JSON 형태인지 일반 텍스트인지 판단 (기초적인 수준)
            if headers.get("Content-Type") == "application/json":
                response = requests.post(full_url, json=body, headers=headers, timeout=7)
            else:
                response = requests.post(full_url, data=body, headers=headers, timeout=7)
        elif method == "GET":
            response = requests.get(full_url, params=body, headers=headers, timeout=7)
        else:
            # 기타 메서드 처리
            response = requests.request(method, full_url, data=body, headers=headers, timeout=7)

        status_code = response.status_code
        response_text = response.text

        # ⏱️ 시간 측정 종료
        end_time = time.time()
        exec_time_ms = int((end_time - start_time) * 1000)

        # [핵심] 성공 여부 판별: AI가 지정한 정규식 매칭 여부 확인
        is_exploited = False
        success_regex = payload_data.expected_success_regex

        if success_regex and success_regex != "N/A":
            if re.search(success_regex, response_text, re.IGNORECASE | re.DOTALL):
                is_exploited = True
        else:
            # 정규식이 없는 경우 상태 코드로 보완 판단
            if status_code < 400:
                is_exploited = True

        print(f"[DEBUG] 💥 결과: HTTP {status_code}, 정규식 매칭({is_exploited}), {exec_time_ms}ms")

        return ExecutionResult(
            is_exploited=is_exploited,
            http_status=status_code,
            execution_time_ms=exec_time_ms,
            response_snippet=response_text[:1000], # 리포트용 슬라이싱
            error_message=None
        )

    except Exception as e:
        end_time = time.time()
        return ExecutionResult(
            is_exploited=False,
            http_status=0,
            execution_time_ms=int((end_time - start_time) * 1000),
            response_snippet="",
            error_message=str(e)
        )
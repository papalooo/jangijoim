import requests
import asyncio
import time
import re
from core.schemas import ExecutionResult, ExploitPayload, DastSastResult
from core.ws_manager import manager as ws_manager

async def run_exploit(target_url: str, dast_res: DastSastResult, payload_data: ExploitPayload, job_id: str = None) -> ExecutionResult:
    """
    [Role 2] 4단계: AI가 생성한 페이로드를 실제 타겟에 전송하고 결과를 검증합니다.
    """
    msg = f"🔫 타겟({target_url})으로 PoC 공격 발사 중..."
    print(f"\n[DEBUG] {msg}")
    
    if job_id:
        await ws_manager.broadcast(job_id, {
            "type": "log",
            "level": "info",
            "message": msg,
            "vuln_type": dast_res.vuln_type
        })

    # AI가 제안한 엔드포인트와 메서드 사용 (없으면 DAST 정보 활용)
    endpoint = payload_data.endpoint if payload_data.endpoint else dast_res.target_endpoint
    method = payload_data.method.upper() if payload_data.method else dast_res.http_method.upper()

    full_url = f"{target_url.rstrip('/')}{endpoint}"
    headers = payload_data.headers or {}
    body = payload_data.body

    # ⏱️ 시간 측정 시작
    start_time = time.time()

    # 타임아웃 설정 (연결 5초, 읽기 10초)
    TIMEOUT_CONFIG = (5.0, 10.0)

    try:
        if job_id:
            await ws_manager.broadcast(job_id, {
                "type": "request",
                "method": method,
                "url": full_url,
                "headers": headers,
                "body": body
            })

        response = None
        if method == "POST":
            # Body가 JSON 형태인지 일반 텍스트인지 판단 (기초적인 수준)
            if headers.get("Content-Type") == "application/json":
                response = requests.post(full_url, json=body, headers=headers, timeout=TIMEOUT_CONFIG, allow_redirects=False)
            else:
                response = requests.post(full_url, data=body, headers=headers, timeout=TIMEOUT_CONFIG, allow_redirects=False)
        elif method == "GET":
            response = requests.get(full_url, params=body, headers=headers, timeout=TIMEOUT_CONFIG, allow_redirects=False)
        else:
            # 기타 메서드 처리
            response = requests.request(method, full_url, data=body, headers=headers, timeout=TIMEOUT_CONFIG, allow_redirects=False)

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

        res_msg = f"💥 결과: HTTP {status_code}, 정규식 매칭({is_exploited}), {exec_time_ms}ms"
        print(f"[DEBUG] {res_msg}")

        if job_id:
            await ws_manager.broadcast(job_id, {
                "type": "execution_result",
                "is_exploited": is_exploited,
                "status_code": status_code,
                "exec_time_ms": exec_time_ms,
                "response_snippet": response_text[:1000]
            })

        return ExecutionResult(
            is_exploited=is_exploited,
            http_status=status_code,
            execution_time_ms=exec_time_ms,
            response_snippet=response_text[:1000]
        )

    except requests.exceptions.ConnectTimeout:
        err_msg = "❌ 서버 연결 타임아웃 (대상 서버가 응답하지 않음)"
    except requests.exceptions.ReadTimeout:
        err_msg = "❌ 서버 응답 읽기 타임아웃 (서버 처리가 너무 오래 걸림)"
    except requests.exceptions.ConnectionError:
        err_msg = "❌ 서버 연결 오류 (도메인 확인 불가 또는 포트 닫힘)"
    except requests.exceptions.TooManyRedirects:
        err_msg = "❌ 리디렉션 루프 발생"
    except Exception as e:
        err_msg = f"❌ PoC 실행 중 예외 발생: {str(e)}"

    # 에러 발생 시 처리
    end_time = time.time()
    exec_time_ms = int((end_time - start_time) * 1000)
    print(f"[DEBUG] {err_msg}")
    
    if job_id:
        await ws_manager.broadcast(job_id, {
            "type": "log",
            "level": "error",
            "message": err_msg
        })
        
    return ExecutionResult(
        is_exploited=False,
        http_status=0,
        execution_time_ms=exec_time_ms,
        response_snippet=None
    )

import asyncio
import time
import re
import httpx
from typing import Optional
from core.schemas import ExecutionResult, ExploitPayload, DastSastResult, AuthConfig
from core.ws_manager import manager as ws_manager

async def run_exploit(target_url: str, dast_res: DastSastResult, payload_data: ExploitPayload, auth_config: Optional[AuthConfig] = None, job_id: str = None) -> ExecutionResult:
    """
    [Role 2] 4단계: AI가 생성한 페이로드를 실제 타겟에 전송하고 결과를 검증합니다.
    httpx를 사용하여 비동기식으로 익스플로잇을 수행합니다.
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

    # AI가 제안한 엔드포인트와 메서드 사용
    endpoint = payload_data.endpoint if payload_data.endpoint else dast_res.target_endpoint
    if not endpoint.startswith('/'):
        endpoint = '/' + endpoint
    method = payload_data.method.upper() if payload_data.method else dast_res.http_method.upper()

    full_url = f"{target_url.rstrip('/')}{endpoint}"
    
    # 헤더 및 쿠키 병합 (AI 제안 헤더 > AuthConfig 공통 헤더)
    headers = auth_config.headers.copy() if auth_config else {}
    if payload_data.headers:
        headers.update(payload_data.headers)
        
    cookies = auth_config.cookies.copy() if auth_config else {}
    
    body = payload_data.body

    # ⏱️ 시간 측정 시작
    start_time = time.time()

    try:
        if job_id:
            await ws_manager.broadcast(job_id, {
                "type": "request",
                "method": method,
                "url": full_url,
                "headers": headers,
                "body": body
            })

        # 비동기 요청 수행
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.request(method, full_url, content=body if isinstance(body, bytes) else str(body), headers=headers)

        status_code = response.status_code
        response_text = response.text

        # ⏱️ 시간 측정 종료
        end_time = time.time()
        exec_time_ms = int((end_time - start_time) * 1000)

        # [핵심] 성공 여부 판별: AI가 지정한 정규식 매칭 여부 확인
        is_exploited = False
        failure_reason = None
        success_regex = payload_data.expected_success_regex
        response_snippet = response_text[:1000]

        if success_regex and success_regex != "N/A":
            try:
                match = re.search(success_regex, response_text, re.IGNORECASE | re.DOTALL)
                if match:
                    is_exploited = True
                    # 매칭된 부분 주위로 컨텍스트 캡처 (최대 1000자)
                    start = max(0, match.start() - 100)
                    end = min(len(response_text), match.end() + 100)
                    response_snippet = f"...{response_text[start:end]}..."
                else:
                    failure_reason = f"정규식 미매칭 (기대: {success_regex})"
            except re.error as e:
                failure_reason = f"잘못된 정규식 패턴: {str(e)}"
        else:
            # 정규식이 없는 경우 상태 코드 및 에러 메시지 기반 보완 판단
            sql_errors = ["sql syntax", "mysql_fetch", "sqlite3.operationalerror", "psycopg2", "unrecognized token", "driver stack trace"]
            found_sql_error = any(err in response_text.lower() for err in sql_errors)
            
            if status_code < 400:
                is_exploited = True
            elif found_sql_error:
                is_exploited = True
                failure_reason = "HTTP 에러 발생했으나 응답에서 SQL 오류 메시지 탐지됨"
            else:
                failure_reason = f"HTTP {status_code} 응답 및 성공 정규식 부재"

        # WAF 차단 의심 판별 (403, 406 등)
        if not is_exploited and status_code in [403, 406, 429]:
            failure_reason = f"보안 장비(WAF/IPS)에 의한 차단 의심 (HTTP {status_code})"

        res_msg = f"💥 결과: HTTP {status_code}, 정규식 매칭({is_exploited}), {exec_time_ms}ms"
        if failure_reason and not is_exploited:
            res_msg += f" (사유: {failure_reason})"
        print(f"[DEBUG] {res_msg}")

        if job_id:
            await ws_manager.broadcast(job_id, {
                "type": "execution_result",
                "is_exploited": is_exploited,
                "status_code": status_code,
                "exec_time_ms": exec_time_ms,
                "failure_reason": failure_reason,
                "response_snippet": response_snippet
            })

        return ExecutionResult(
            is_exploited=is_exploited,
            http_status=status_code,
            execution_time_ms=exec_time_ms,
            request_url=full_url,
            request_method=method,
            request_headers=headers,
            request_body=body if isinstance(body, str) else str(body) if body else None,
            response_snippet=response_snippet, 
            exploit_failure_reason=failure_reason,
            error_message=None
        )

    except Exception as e:
        end_time = time.time()
        err_msg = str(e)
        print(f"[DEBUG] ❌ PoC 실행 예외 발생: {type(e).__name__}: {err_msg}")
        if job_id:
            await ws_manager.broadcast(job_id, {
                "type": "error",
                "message": f"PoC 실행 중 오류 발생: {err_msg}"
            })
        return ExecutionResult(
            is_exploited=False,
            http_status=0,
            execution_time_ms=int((end_time - start_time) * 1000),
            request_url=full_url if 'full_url' in locals() else None,
            request_method=method if 'method' in locals() else None,
            request_headers=headers if 'headers' in locals() else {},
            request_body=body if 'body' in locals() else None,
            response_snippet="",
            error_message=err_msg
        )
import requests
import asyncio
import time  # 시간 측정을 위해 추가
from core.schemas import ExecutionResult, ExploitPayload, DastSastResult

async def run_exploit(target_url: str, dast_res: DastSastResult, payload_data: ExploitPayload) -> ExecutionResult:
    """
    [Role 2] 4단계: AI가 생성한 페이로드를 실제 타겟에 쏘고 결과를 확인합니다.
    """
    print(f"\n[DEBUG] 🔫 타겟({target_url})으로 공격 발사 준비 중...")
    
    target_endpoint = dast_res.target_endpoint
    method = dast_res.http_method.upper()
    payload_string = getattr(payload_data, 'payload', str(payload_data))
    
    full_url = f"{target_url.rstrip('/')}{target_endpoint}"
    
    # ⏱️ 스톱워치 시작
    start_time = time.time()
    
    try:
        await asyncio.sleep(0.5) 
        
        if method == "POST":
            response = requests.post(full_url, data={"username": payload_string, "password": "123"}, timeout=5)
        else:
            response = requests.get(full_url, params={"id": payload_string}, timeout=5)























            
            
        status_code = response.status_code
        response_text = response.text[:500] 
        
        # ⏱️ 스톱워치 종료 및 밀리초(ms) 계산
        end_time = time.time()
        exec_time_ms = int((end_time - start_time) * 1000)
        
        # 403이면 방어막에 막힘(해킹 실패), 200 등 기타면 뚫림(해킹 성공)으로 판단
        is_exploited = status_code != 403 
        
        print(f"[DEBUG] 💥 발사 결과: HTTP {status_code} (해킹 성공 여부: {is_exploited}, 소요시간: {exec_time_ms}ms)")
        
        # 🚨 PM님 양식(Schema)에 이름표 완벽하게 맞춤!
        return ExecutionResult(
            is_exploited=is_exploited,
            http_status=status_code,
            execution_time_ms=exec_time_ms,
            response_snippet=response_text,
            error_message=None
        )
        
    except Exception as e:
        end_time = time.time()
        print(f"[DEBUG] ❌ 발사 중 에러 발생: {e}")
        return ExecutionResult(
            is_exploited=False,
            http_status=0,
            execution_time_ms=int((end_time - start_time) * 1000),
            response_snippet="",
            error_message=str(e)
        )
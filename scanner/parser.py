from typing import List, Dict, Any
from urllib.parse import urlparse
from core.schemas import DastSastResult

def parse_nuclei_results(raw_results: List[Dict[str, Any]]) -> List[DastSastResult]:
    """
    Nuclei 스캐너의 원시 JSON 결과를 팀 표준 규격(DastSastResult)으로 변환하고
    LLM API 비용 절감을 위해 중복된 취약점을 제거한다.
    """
    parsed_results = []
    seen_signatures = set()

    for item in raw_results:
        # 1. 필요 데이터 추출 (Nuclei JSON 구조 기준)
        info = item.get("info", {})
        vuln_type = info.get("name", "Unknown Vulnerability")
        severity = info.get("severity", "info").capitalize()
        
        # HTTP 정보 추출
        target_url = item.get("matched-at", "")
        extracted_results = item.get("extracted-results", [])
        payload = extracted_results[0] if extracted_results else "No explicit payload"
        
        # HTTP Request/Response 파싱 (Nuclei는 request/response 텍스트를 통째로 반환하는 경우가 많음)
        request_raw = item.get("request", "")
        response_raw = item.get("response", "")
        
        # Method 추출 (GET, POST 등)
        http_method = "GET"
        if request_raw and len(request_raw.split(" ")) > 0:
            http_method = request_raw.split(" ")[0]
            
        # URL에서 엔드포인트 경로만 추출 (예: http://localhost/api/login -> /api/login)
        parsed_url = urlparse(target_url)
        target_endpoint = parsed_url.path if parsed_url.path else "/"
        
        # 2. 중복 제거 (Deduplication) 로직
        # 동일한 엔드포인트에 동일한 취약점이 발견되면 1개만 남긴다.
        signature = f"{target_endpoint}_{http_method}_{vuln_type}"
        if signature in seen_signatures:
            continue
            
        seen_signatures.add(signature)
        
        # 3. 응답 텍스트 슬라이싱 (LLM 컨텍스트 윈도우 초과 방지)
        sliced_resp = response_raw[:1000] + "..." if len(response_raw) > 1000 else response_raw

        # 4. Pydantic 표준 규격으로 객체 생성
        dast_result = DastSastResult(
            target_endpoint=target_endpoint,
            http_method=http_method,
            vuln_type=vuln_type,
            severity=severity,
            request_headers={}, # 고급 구현 시 request_raw에서 헤더 파싱 추가 가능
            payload=payload,
            sliced_response=sliced_resp
        )
        parsed_results.append(dast_result)

    return parsed_results
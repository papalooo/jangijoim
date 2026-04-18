from typing import List, Dict, Any
from urllib.parse import urlparse
from core.schemas import DastSastResult

def parse_nuclei_results(raw_results: List[Dict[str, Any]]) -> List[DastSastResult]:
    """
    Nuclei 스캐너의 원시 JSON 결과를 팀 표준 규격(DastSastResult)으로 변환하고
    LLM API 비용 절감을 위해 중복된 취약점을 제거한다.
    """
    # [Role 2 정석 디버깅] 스캐너로부터 받은 로우 데이터의 생얼을 확인합니다.
    print(f"\n[DEBUG] 📥 스캐너로부터 {len(raw_results)}개의 원시 결과를 수신했습니다.")
    
    if len(raw_results) > 0:
        # 데이터가 하나라도 있다면 필드 구조를 찍어서 파싱이 가능한지 봅니다.
        print(f"[DEBUG] 첫 번째 결과의 필드 목록: {list(raw_results[0].keys())}")
        if "matched-at" in raw_results[0]:
            print(f"[DEBUG] 샘플 타겟 주소: {raw_results[0]['matched-at']}")

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
        
        # HTTP Request/Response 파싱
        request_raw = item.get("request", "")
        response_raw = item.get("response", "")
        
        # Method 추출 (GET, POST 등)
        http_method = "GET"
        if request_raw and len(request_raw.split(" ")) > 0:
            http_method = request_raw.split(" ")[0]
            
        # URL에서 엔드포인트 경로만 추출 (예: http://localhost:3000/api/login -> /api/login)
        parsed_url = urlparse(target_url)
        target_endpoint = parsed_url.path if parsed_url.path else "/"
        
        # 2. 중복 제거 (Deduplication) 로직
        # 동일한 엔드포인트에 동일한 취약점이 발견되면 1개만 남깁니다.
        signature = f"{target_endpoint}_{http_method}_{vuln_type}"
        if signature in seen_signatures:
            print(f"[DEBUG] 중복 취약점 발견 및 제외: {signature}")
            continue
            
        seen_signatures.add(signature)
        
        # 3. 응답 텍스트 슬라이싱 (LLM 컨텍스트 윈도우 초과 방지)
        sliced_resp = response_raw[:1000] + "..." if len(response_raw) > 1000 else response_raw

        # 4. Pydantic 표준 규격으로 객체 생성
        # [수정] 경로가 IP이거나 이상한 경우를 걸러내는 로직 추가
        if "." in target_endpoint and "/" not in target_endpoint:
             target_endpoint = "/" # 호스트 정보만 있는 경우 루트로 간주
             
        dast_result = DastSastResult(
            target_endpoint=target_endpoint,
            http_method=http_method,
            vuln_type=vuln_type,
            severity=severity,
            request_headers={}, 
            payload=payload,
            sliced_response=sliced_resp
        )
        
        # [중요] 단순 탐지(Detect) 정보는 매핑할 코드가 없으므로 건너뜁니다.
        if "Detect" in vuln_type or "Fingerprint" in vuln_type:
            print(f"ℹ️ [건너뜀] 단순 탐지 정보는 매핑에서 제외: {vuln_type}")
            continue

        parsed_results.append(dast_result)

    # for문이 모두 끝난 후, 최종 완성된 리스트를 반환 (들여쓰기 주의)
    return parsed_results
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from core.schemas import DastSastResult

def parse_nuclei_results(raw_results: List[Dict[str, Any]]) -> List[DastSastResult]:
    """
    Nuclei 스캐너의 원시 JSON 결과를 팀 표준 규격(DastSastResult)으로 변환한다.
    """
    parsed_results = []
    seen_signatures = set()
    info_count = 0
    MAX_INFO_FINDINGS = 20 # Info 레벨 수용 한도를 늘려 가시성 확보 (기존 5개)

    for item in raw_results:
        info = item.get("info", {})
        vuln_type = info.get("name", "Unknown Vulnerability")
        severity = info.get("severity", "info").capitalize()
        
        # Info 레벨 제한 로직
        if severity in ["Info", "Informational"]:
            if info_count >= MAX_INFO_FINDINGS:
                continue
            info_count += 1

        target_url = item.get("matched-at", "")
        extracted_results = item.get("extracted-results", [])
        payload = extracted_results[0] if extracted_results else "No explicit payload"
        
        request_raw = item.get("request", "")
        response_raw = item.get("response", "")
        
        http_method = "GET"
        if request_raw and len(request_raw.split(" ")) > 0:
            http_method = request_raw.split(" ")[0]
            
        parsed_url = urlparse(target_url)
        target_endpoint = parsed_url.path if parsed_url.path else "/"
        
        signature = f"{target_endpoint}_{http_method}_{vuln_type}"
        if signature in seen_signatures:
            continue
            
        seen_signatures.add(signature)
        sliced_resp = response_raw[:1000] + "..." if len(response_raw) > 1000 else response_raw

        if "." in target_endpoint and "/" not in target_endpoint:
             target_endpoint = "/"
             
        dast_result = DastSastResult(
            target_endpoint=target_endpoint,
            http_method=http_method,
            vuln_type=vuln_type,
            severity=severity,
            request_headers={}, 
            payload=payload,
            sliced_response=sliced_resp
        )
        
        # 특정 패턴 필터링 (기존에는 Detect, Fingerprint를 제외했으나 가시성을 위해 완화)
        # LLM Triager가 최종적으로 정오탐을 걸러낼 수 있도록 모든 결과를 일단 허용합니다.
        
        parsed_results.append(dast_result)

    return parsed_results

def parse_semgrep_results(raw_results: Dict[str, Any]) -> List[DastSastResult]:
    """
    Semgrep 스캐너의 원시 JSON 결과를 팀 표준 규격(DastSastResult)으로 변환한다.
    """
    parsed_results = []
    results = raw_results.get("results", [])
    
    for item in results:
        vuln_type = item.get("check_id", "Unknown SAST Finding")
        extra = item.get("extra", {})
        
        # Semgrep severity를 표준 severity로 매핑
        raw_severity = extra.get("severity", "info").upper()
        severity_map = {
            "ERROR": "High",
            "WARNING": "Medium",
            "INFO": "Info"
        }
        severity = severity_map.get(raw_severity, "Info")
        
        message = extra.get("message", "")
        path = item.get("path")
        line = item.get("start", {}).get("line")
        
        dast_result = DastSastResult(
            target_endpoint="SAST_FINDING", 
            http_method="N/A",
            vuln_type=f"[SAST] {vuln_type}",
            severity=severity,
            request_headers={},
            payload=f"File: {path}, Line: {line}",
            sliced_response=message[:1000],
            source_file=path,
            source_line=line
        )
        parsed_results.append(dast_result)
        
    return parsed_results

def parse_zap_results(raw_results: List[Dict[str, Any]]) -> List[DastSastResult]:
    """
    OWASP ZAP의 원시 JSON 결과를 팀 표준 규격(DastSastResult)으로 변환한다.
    """
    parsed_results = []
    
    for alert in raw_results:
        vuln_type = alert.get("alert", "Unknown ZAP Alert")
        risk = alert.get("risk", "Informational")
        url = alert.get("url", "")
        evidence = alert.get("evidence", "")
        description = alert.get("description", "")
        method = alert.get("method", "GET")
        
        parsed_url = urlparse(url)
        target_endpoint = parsed_url.path if parsed_url.path else "/"
        
        dast_result = DastSastResult(
            target_endpoint=target_endpoint,
            http_method=method,
            vuln_type=f"[ZAP] {vuln_type}",
            severity=risk,
            request_headers={},
            payload=evidence if evidence else description[:200],
            sliced_response=description[:1000]
        )
        parsed_results.append(dast_result)
        
    return parsed_results

def normalize_and_merge_results(
    dast_raw: List[Dict[str, Any]], 
    sast_raw: Dict[str, Any],
    zap_raw: Optional[List[Dict[str, Any]]] = None
) -> List[DastSastResult]:
    """
    DAST(Nuclei), SAST(Semgrep), ZAP 결과를 통합하고 정규화한다.
    """
    dast_results = parse_nuclei_results(dast_raw)
    sast_results = parse_semgrep_results(sast_raw)
    
    # 사용자의 요청에 따라 DAST 결과를 최우선으로 처리합니다.
    # SAST 결과는 PoC 생성이 어려울 수 있으나, 가시성과 통합 분석을 위해 모두 포함하도록 변경합니다.
    combined = dast_results + sast_results
    
    if zap_raw:
        zap_results = parse_zap_results(zap_raw)
        combined += zap_results
        print(f"✅ [정규화] ZAP({len(zap_results)}) 결과 추가 통합")
    
    print(f"✅ [정규화] DAST({len(dast_results)}) + SAST({len(sast_results)}) 결과가 통합되었습니다.")
    
    return combined

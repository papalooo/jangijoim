import asyncio
import json
import os
import time
from typing import Any, Dict, List, Optional
from zapv2 import ZAPv2

SCAN_TIMEOUT_SECONDS = 1200 # ZAP 스캔을 고려하여 타임아웃 연장
ZAP_URL = os.getenv("ZAP_URL", "http://zap:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "jangijoim_zap_key")

async def run_katana(target_url: str) -> List[str]:
    """
    Katana 크롤러를 사용하여 타겟의 모든 숨겨진 URL을 수집합니다.
    """
    print(f"🕷️ [DAST] Katana 크롤링 시작: {target_url}")
    # -jc: JS 크롤링, -kf: 알려진 파일 탐색, -fs: fuzzaable 파라미터 위주
    cmd = ["katana", "-u", target_url, "-silent", "-jc", "-kf", "all", "-fs", "dn", "-retry", "2"]
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
        
        urls = [line.strip() for line in stdout.decode('utf-8').splitlines() if line.strip()]
        # 기본 URL도 포함
        if target_url not in urls:
            urls.append(target_url)
            
        print(f"✅ [DAST] Katana 탐색 완료: {len(urls)}개의 URL 수집됨")
        return urls
    except Exception as e:
        print(f"⚠️ [DAST] Katana 크롤링 실패: {e}")
        return [target_url] # 실패 시 기본 URL만 반환

async def run_nuclei(targets: List[str], headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """
    Nuclei 스캐너를 실행합니다. 다중 타겟(Katana 결과)을 지원합니다.
    """
    if not targets:
        return []

    tags = "cve,sqli,xss,lfi,misconfig,takeover"
    cmd = ["nuclei", "-tags", tags, "-silent", "-jsonl"]
    
    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    print(f"🔍 [DAST] Nuclei 실행 중 (타겟 {len(targets)}개)...")
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        input_data = "\n".join(targets).encode('utf-8')
        stdout, stderr = await asyncio.wait_for(process.communicate(input=input_data), timeout=SCAN_TIMEOUT_SECONDS)
        
    except Exception as e:
        raise RuntimeError(f"Failed to execute Nuclei: {str(e)}")

    results = []
    if stdout:
        for line in stdout.decode('utf-8').splitlines():
            if line.strip().startswith("{"):
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                
    return results

async def run_zap(target_url: str) -> List[Dict[str, Any]]:
    """
    OWASP ZAP을 사용하여 정밀 심층 스캔을 수행합니다. (Fallback용)
    """
    print(f"🕵️‍♂️ [DAST] OWASP ZAP 심층 스캔 가동: {target_url}")
    
    try:
        zap = ZAPv2(proxies={'http': ZAP_URL, 'https': ZAP_URL}, apikey=ZAP_API_KEY)
        
        # 1. Spider 시작
        print("  - [1/3] ZAP Spider 탐색 중...")
        scan_id = zap.spider.scan(target_url)
        while int(zap.spider.status(scan_id)) < 100:
            await asyncio.sleep(5)
            
        # 2. AJAX Spider (SPA 대응 핵심)
        print("  - [2/3] ZAP AJAX Spider 정밀 탐색 중...")
        zap.ajaxSpider.scan(target_url)
        # AJAX Spider 상태 체크는 약간 다름
        while True:
            status = zap.ajaxSpider.status
            if status != 'running':
                break
            await asyncio.sleep(10)
            
        # 3. Active Scan
        print("  - [3/3] ZAP Active Scan 취약점 공격 중...")
        scan_id = zap.ascan.scan(target_url)
        while int(zap.ascan.status(scan_id)) < 100:
            await asyncio.sleep(10)
            
        # 결과 수집 (Alerts)
        alerts = zap.core.alerts(baseurl=target_url)
        print(f"✅ [DAST] ZAP 스캔 완료: {len(alerts)}개의 경고 발견")
        return alerts
        
    except Exception as e:
        print(f"❌ [DAST] ZAP API 통신 실패: {e}")
        return []

async def run_semgrep(target_dir: str) -> Dict[str, Any]:
    """
    Semgrep SAST 스캐너를 실행합니다.
    """
    cmd = ["semgrep", "scan", target_dir, "--json", "--quiet"]
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SCAN_TIMEOUT_SECONDS)
    except Exception as e:
        raise RuntimeError(f"Failed to execute Semgrep: {str(e)}")

    if stdout:
        try:
            return json.loads(stdout.decode('utf-8'))
        except json.JSONDecodeError:
            pass
    return {}

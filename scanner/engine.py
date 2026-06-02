import asyncio
import json
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from core.ws_manager import manager as ws_manager
from datetime import datetime

SCAN_TIMEOUT_SECONDS = 1200

async def log_to_ws(job_id: Optional[str], message: str, level: str = "info"):
    if job_id:
        timestamp = datetime.now().strftime("%H:%M:%S")
        await ws_manager.broadcast(job_id, {"type": "log", "message": message, "level": level, "timestamp": timestamp})

async def run_katana(target_url: str, job_id: Optional[str] = None) -> List[str]:
    """
    Katana 크롤러를 사용하여 타겟의 모든 숨겨진 URL을 수집합니다.
    Docker 환경에서 실행되므로 헤드리스 브라우저(-jc)를 활성화하여 SPA 대응력을 높입니다.
    """
    msg = f"🕷️ [DAST] Katana 크롤링 시작: {target_url}"
    print(msg)
    await log_to_ws(job_id, msg)
    
    # Docker 환경이므로 -jc(JS Crawling)를 활성화하여 정밀 탐색
    cmd = ["katana", "-u", target_url, "-silent", "-kf", "all", "-jc", "-retry", "2", "-timeout", "10"]
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        # Katana는 크롤링 특성상 약간의 시간이 필요함 (최대 5분)
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
        
        urls = [line.strip() for line in stdout.decode('utf-8').splitlines() if line.strip()]
        
        # 정적 에셋 필터링 (의미 없는 파일 검사 제외)
        ignore_exts = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".ico", ".woff", ".woff2", ".ttf", ".eot"}
        filtered_urls = []
        for url in urls:
            parsed = urlparse(url)
            ext = os.path.splitext(parsed.path)[1].lower()
            if ext not in ignore_exts:
                filtered_urls.append(url)
                
        # 중복 제거 및 기본 URL 포함
        filtered_urls = list(set(filtered_urls))
        if target_url not in filtered_urls:
            filtered_urls.append(target_url)
            
        msg = f"✅ [DAST] Katana 탐색 완료: 원본 {len(urls)}개 중 유효한 타겟 {len(filtered_urls)}개 추출됨"
        print(msg)
        await log_to_ws(job_id, msg)
        return filtered_urls 
    except Exception as e:
        err_msg = f"⚠️ [DAST] Katana 크롤링 실패 또는 타임아웃: {e}"
        print(err_msg)
        await log_to_ws(job_id, err_msg, "error")
        # 실패 시 타겟 URL 하나라도 반환하여 Nuclei가 작동하게 함
        return [target_url]

async def run_nuclei(targets: List[str], headers: Optional[Dict[str, str]] = None, job_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Nuclei 스캐너를 실행합니다. 다중 타겟(Katana 결과)을 지원합니다.
    """
    if not targets:
        return []

    # Juice Shop과 같은 취약 앱 진단을 위해 태그를 대폭 확장합니다.
    # generic, vulnerabilities, exposure, default-login 등을 추가하여 탐지율 향상
    tags = "cve,sqli,xss,lfi,rce,misconfig,takeover,vulnerability,exposure,default-login,generic"
    # -c (concurrency), -bs (bulk-size), -rl (rate-limit) 옵션을 추가하여 속도 대폭 향상
    # -it (interactive/automatic template) 대신 모든 기본 템플릿 활용을 유도
    cmd = ["nuclei", "-tags", tags, "-silent", "-jsonl", "-c", "100", "-bs", "100", "-rl", "3000"]
    
    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    msg = f"🔍 [DAST] Nuclei 실행 중 (타겟 {len(targets)}개)..."
    print(msg)
    await log_to_ws(job_id, msg)
    
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
        err_msg = f"Failed to execute Nuclei: {str(e)}"
        await log_to_ws(job_id, err_msg, "error")
        raise RuntimeError(err_msg)

    results = []
    if stdout:
        for line in stdout.decode('utf-8').splitlines():
            if line.strip().startswith("{"):
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                
    done_msg = f"✅ [DAST] Nuclei 검사 완료: {len(results)}개의 취약점 패턴 탐지"
    print(done_msg)
    await log_to_ws(job_id, done_msg)
    return results

async def run_semgrep(target_dir: str, job_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Semgrep SAST 스캐너를 실행합니다.
    """
    msg = f"✍️ [SAST] Semgrep 코드 분석 중: {target_dir}"
    print(msg)
    await log_to_ws(job_id, msg)
    
    # OWASP Juice Shop (Node.js/TypeScript)에 맞춰 탐지 규칙 강화
    configs = [
        "p/ci",
        "p/expressjs",
        "p/javascript",
        "p/typescript",
        "p/owasp-top-ten",
        "p/secrets"
    ]
    
    cmd = ["semgrep", "scan"]
    for config in configs:
        cmd.extend(["--config", config])
        
    cmd.extend([
        target_dir, 
        "--json", "--quiet",
        "--exclude", "node_modules",
        "--exclude", "dist",
        "--exclude", ".git"
    ])
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SCAN_TIMEOUT_SECONDS)
    except Exception as e:
        err_msg = f"Failed to execute Semgrep: {str(e)}"
        await log_to_ws(job_id, err_msg, "error")
        raise RuntimeError(err_msg)

    result_data = {}
    if stdout:
        try:
            result_data = json.loads(stdout.decode('utf-8'))
        except json.JSONDecodeError:
            pass
            
    findings = result_data.get("results", [])
    done_msg = f"✅ [SAST] Semgrep 분석 완료: {len(findings)}개의 코드 결함 탐지"
    print(done_msg)
    await log_to_ws(job_id, done_msg)
    return result_data

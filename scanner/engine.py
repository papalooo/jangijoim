import asyncio
import json
import os
from typing import Any, Dict, List, Optional

SCAN_TIMEOUT_SECONDS = 600

async def run_nuclei(target_url: str, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    # 1. 파이썬이 헷갈리지 않게 절대 경로로 템플릿 위치를 쾅 박아줍니다.
    template_path = os.path.abspath("sqli.yaml")
    
    # 2. 디버깅을 위해 -silent를 잠시 뺍니다.
    cmd = ["nuclei", "-target", target_url, "-t", template_path, "-jsonl"]
    
    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SCAN_TIMEOUT_SECONDS)
        
        # 3. 터미널 2번(엔진)에 Nuclei의 실제 로그를 출력하게 만듭니다. (핵심)
        print("\n================ [T2 엔진] NUCLEI DEBUG ================")
        print(f"[실행 명령어] {' '.join(cmd)}")
        print(f"[STDERR 에러로그]\n{stderr.decode('utf-8')}")
        print("========================================================\n")
        
    except Exception as e:
        raise RuntimeError(f"Failed to execute Nuclei: {str(e)}")

    results = []
    for line in stdout.decode('utf-8').splitlines():
        # JSON 형식의 결과 데이터만 안전하게 추출
        if line.strip().startswith("{"):
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
                
    return results

async def run_semgrep(target_dir: str) -> Dict[str, Any]:
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
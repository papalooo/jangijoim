import asyncio
import json
from typing import Any, Dict, List, Optional

# 스캔 최대 허용 시간 (10분 = 600초)
SCAN_TIMEOUT_SECONDS = 600

async def run_nuclei(target_url: str, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """
    Nuclei(DAST) 스캐너를 비동기로 실행하고 타임아웃 및 인증 헤더를 처리한다.
    """
    cmd = ["nuclei", "-target", target_url, "-jsonl", "-silent"]
    
    # 인증(Authentication) 우회 스캔 로직: 헤더 딕셔너리가 존재하면 명령어에 추가
    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    try:
        # 서브프로세스 생성
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # 타임아웃(10분) 강제 적용 대기
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SCAN_TIMEOUT_SECONDS)
        
        if process.returncode != 0 and stderr:
            print(f"[!] Nuclei Execution Warning/Error: {stderr.decode('utf-8')}")
            
    except asyncio.TimeoutError:
        # 타임아웃 발생 시 오작동 방지를 위해 프로세스 강제 종료
        process.kill()
        raise TimeoutError(f"Nuclei scan exceeded maximum time limit of {SCAN_TIMEOUT_SECONDS} seconds for target {target_url}.")
    except Exception as e:
        raise RuntimeError(f"Failed to execute Nuclei: {str(e)}")

    results = []
    for line in stdout.decode('utf-8').splitlines():
        if line.strip():
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
                
    return results


async def run_semgrep(target_dir: str) -> Dict[str, Any]:
    """
    Semgrep(SAST) 스캐너를 비동기로 실행하고 타임아웃을 처리한다.
    (SAST는 로컬 파일 분석이므로 HTTP 인증 헤더가 불필요함)
    """
    cmd = ["semgrep", "scan", target_dir, "--json", "--quiet"]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SCAN_TIMEOUT_SECONDS)
        
        if process.returncode != 0 and stderr:
            print(f"[!] Semgrep Execution Warning/Error: {stderr.decode('utf-8')}")
            
    except asyncio.TimeoutError:
        process.kill()
        raise TimeoutError(f"Semgrep scan exceeded maximum time limit of {SCAN_TIMEOUT_SECONDS} seconds for directory {target_dir}.")
    except Exception as e:
        raise RuntimeError(f"Failed to execute Semgrep: {str(e)}")

    if stdout:
        try:
            return json.loads(stdout.decode('utf-8'))
        except json.JSONDecodeError:
            pass
            
    return {}

if __name__ == "__main__":
    # 방금 만든 파서를 불러옵니다.
    from scanner.parser import parse_nuclei_results

    async def test_scanners():
        print("[*] Nuclei 엔진 테스트 스캔 시작...")
        
        # 1. 원시 데이터 가져오기 (로컬 테스트 타겟)
        raw_nuclei_results = await run_nuclei("http://127.0.0.1:3000")
        print(f"[+] Nuclei 스캔 완료. 원본 데이터 수: {len(raw_nuclei_results)}")
        
        # 2. 파서를 통해 규격화 및 중복 제거
        if raw_nuclei_results:
            parsed_results = parse_nuclei_results(raw_nuclei_results)
            print(f"[+] 파싱 및 중복 제거 완료. 최종 남은 데이터 수: {len(parsed_results)}")
            
            # 3. Pydantic 객체를 JSON 텍스트로 예쁘게 출력
            if parsed_results:
                print("\n[최종 정제된 데이터 샘플]")
                print(parsed_results[0].model_dump_json(indent=2))

    asyncio.run(test_scanners())

import typer
import httpx
import time
import json
import asyncio
import uuid
import os
from typing import List, Optional
from rich.console import Console
from rich.status import Status
from rich.table import Table
from rich.panel import Panel

app = typer.Typer()
poc_app = typer.Typer()
console = Console()

API_BASE_URL = os.getenv("JANGIJOIM_API_URL", "http://127.0.0.1:8000")

@app.command("start")
def scan_start(
    target_url: str = typer.Option(..., help="타겟 URL (예: http://localhost:3000)"),
    source_dir: str = typer.Option(..., help="소스코드 디렉토리 경로"),
    auth_header: Optional[List[str]] = typer.Option(None, "--auth-header", "-H", help="추가 HTTP 헤더 (예: 'Authorization: Bearer ...')"),
    auth_cookie: Optional[List[str]] = typer.Option(None, "--auth-cookie", "-C", help="추가 쿠키 (예: 'sessionid=abc')"),
    login_script: Optional[str] = typer.Option(None, "--login-script", help="세션 획득용 로그인 스크립트 경로")
):
    """
    JANGIJOIM 보안 스캔 파이프라인을 시작합니다.
    """
    console.print(Panel.fit(
        f"""[bold green]JANGIJOIM Pipeline 요청[/bold green]
Target: [cyan]{target_url}[/cyan]
Source: [yellow]{source_dir}[/yellow]
Engine: [white]{API_BASE_URL}[/white]""",
        border_style="green"
    ))

    headers = {k.strip(): v.strip() for h in auth_header or [] for k, v in [h.split(":", 1)] if ":" in h}
    cookies = {k.strip(): v.strip() for c in auth_cookie or [] for k, v in [c.split("=", 1)] if "=" in c}
    auth_payload = {"headers": headers, "cookies": cookies, "login_script_path": login_script}
    
    try:
        resp = httpx.post(
            f"{API_BASE_URL}/scan/start", 
            params={"target_url": target_url, "source_dir": source_dir},
            json=auth_payload,
            timeout=10.0
        )
        resp.raise_for_status()
        job_id = resp.json()["job_id"]
        console.print(f"[bold blue]📡 스캔 작업이 접수되었습니다. ID: {job_id}[/bold blue]")
        _poll_status(job_id)
    except Exception as e:
        console.print(f"""[bold red]❌ 엔진 서버에 연결할 수 없습니다.[/bold red]
Docker 컨테이너가 실행 중인지 확인하세요: [yellow]docker-compose up -d[/yellow]
에러 상세: {e}""")

@poc_app.command("run")
def poc_run(
    manifest_path: str = typer.Argument(..., help="PoC 매니페스트 JSON 파일 경로"),
    target_url: str = typer.Option(None, help="타겟 호스트 (매니페스트 설정 무시)")
):
    """
    JSON 매니페스트의 PoC를 재실행하여 검증합니다.
    """
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        console.print(f"[bold red]❌ 매니페스트 파일 로드 실패: {e}[/bold red]")
        return

    base_url = target_url or manifest["metadata"]["target_host"]
    exploits = manifest.get("exploits", [])
    
    console.print(Panel.fit(f"""[bold magenta]PoC 재검증 시작[/bold magenta]
Target: [cyan]{base_url}[/cyan]
Exploits: [yellow]{len(exploits)}건[/yellow]""", border_style="magenta"))

    from scanner.executor import run_exploit
    from core.schemas import ExploitPayload, DastSastResult

    async def execute_all():
        table = Table(title="PoC 재검증 결과", header_style="bold blue")
        for col in ["No.", "취약점 유형", "메서드", "상태 코드", "결과"]:
            table.add_column(col, justify="center")

        for idx, exp in enumerate(exploits):
            payload = ExploitPayload(**exp)
            dummy_dast = DastSastResult(
                target_endpoint=exp["endpoint"], http_method=exp["method"],
                vuln_type=exp["vuln_type"], severity=exp["severity"],
                payload=str(exp.get("body", "")), sliced_response="", request_headers={}
            )
            result = await run_exploit(base_url, dummy_dast, payload)
            table.add_row(
                str(idx+1), exp["vuln_type"], exp["method"],
                f"[green]{result.http_status}[/green]" if result.http_status < 400 else f"[red]{result.http_status}[/red]",
                "[bold red]💥 취약함[/bold red]" if result.is_exploited else "[bold green]🛡️ 차단됨[/bold green]"
            )
        console.print(table)

    asyncio.run(execute_all())

def _poll_status(job_id: str):
    with Status("[bold blue]파이프라인 초기화 중...", spinner="dots") as status:
        while True:
            try:
                resp = httpx.get(f"{API_BASE_URL}/scan/status/{job_id}", timeout=5.0)
                if resp.status_code == 200:
                    if _update_status_ui(status, resp.json()):
                        break
                else:
                    status.update(f"[bold red]엔진 응답 이상 (HTTP {resp.status_code})[/bold red]")
            except httpx.RequestError:
                status.update("[bold red]서버와 통신 지연 중...[/bold red]")
            time.sleep(2)

def _update_status_ui(status: Status, data: dict) -> bool:
    meta = data.get("metadata", {})
    current_state = meta.get("current_status", "UNKNOWN")
    
    state_messages = {
        "SCANNING": "[1/5] DAST/SAST 스캔...", "MAPPING": "[2/5] 소스코드 매핑...",
        "VERIFYING": "[3/5] LLM 정오탐 판별...", "TESTING": "[4/5] PoC 검증 및 회귀 테스트..."
    }
    status.update(f"[bold cyan]{state_messages.get(current_state, current_state)}[/bold cyan]")
    
    if current_state in ["COMPLETED", "FAILED"]:
        console.print()
        if current_state == "COMPLETED":
            console.print("[bold green]✅ 파이프라인 스캔이 모두 완료되었습니다![/bold green]")
            render_and_save_report(data)
        else:
            console.print(f"[bold red]❌ 파이프라인 실패: {meta.get('error_log')}[/bold red]")
        return True
    return False

def render_and_save_report(data: dict):
    vulnerabilities = data.get("vulnerabilities", [])
    job_id = data.get("metadata", {}).get("job_id", "unknown")
    
    table = Table(title=f"취약점 검증 결과 (총 {len(vulnerabilities)}건)", header_style="bold magenta")
    for col in ["No.", "취약점 유형", "판별", "CVSS", "PoC"]:
        table.add_column(col, justify="center")
    
    md_content = f"""# JANGIJOIM Vulnerability Summary
- **Job ID:** {job_id}

"""
    
    for idx, item in enumerate(vulnerabilities):
        dast = item.get("dast_result", {})
        triager = item.get("llm_verification", {}).get("triager_result", {})
        is_vuln = triager.get("is_vulnerable", False) if triager else False
        cvss = triager.get("cvss_score", 0.0) if triager else 0.0
        exec_res = item.get("execution")
        poc_status = "✅" if exec_res and exec_res.get("is_exploited") else "❌" if exec_res else "N/A"
        
        table.add_row(
            str(idx+1), dast.get("vuln_type", "Unknown"),
            "[red]정탐[/red]" if is_vuln else "[green]오탐[/green]", f"{cvss:.1f}", poc_status
        )
        md_content += f"""### {idx+1}. {dast.get('vuln_type')}
- 상태: {'정탐' if is_vuln else '오탐'}
- CVSS: {cvss}
- PoC: {poc_status}

"""

    console.print(table)
    console.print()
    console.print("💡 [cyan]상세 보고서는 'reports/' 디렉토리를 확인하세요.[/cyan]")
    
    summary_filename = f"JANGIJOIM_Summary_{job_id[-6:]}.md"
    with open(summary_filename, "w", encoding="utf-8") as f:
        f.write(md_content)
    console.print(f"📄 [yellow]CLI 요약 보고서 생성:[/yellow] [underline]{summary_filename}[/underline]")

if __name__ == "__main__":
    app()

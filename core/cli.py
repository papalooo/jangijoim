import typer
import httpx
import time
import json
import asyncio
import uuid
import os
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
    source_dir: str = typer.Option(..., help="소스코드 디렉토리 경로")
):
    """
    JANGIJOIM 보안 스캔 파이프라인을 시작합니다. (Docker 컨테이너 엔진 사용 권장)
    """
    console.print(Panel.fit(
        f"[bold green]JANGIJOIM Pipeline 요청[/bold green]\nTarget: [cyan]{target_url}[/cyan]\nSource: [yellow]{source_dir}[/yellow]\nEngine: [white]{API_BASE_URL}[/white]",
        border_style="green"
    ))
    
    # 1. FastAPI 서버에 스캔 시작 요청
    try:
        resp = httpx.post(f"{API_BASE_URL}/scan/start", params={"target_url": target_url, "source_dir": source_dir}, timeout=10.0)
        resp.raise_for_status()
        job_id = resp.json()["job_id"]
        console.print(f"[bold blue]📡 스캔 작업이 접수되었습니다. ID: {job_id}[/bold blue]")
    except Exception as e:
        console.print(f"[bold red]❌ 엔진 서버에 연결할 수 없습니다.[/bold red]\n"
                      f"Docker 컨테이너가 실행 중인지 확인하세요: [yellow]docker-compose up -d[/yellow]\n"
                      f"에러 상세: {e}")
        return

    # 2. 상태 폴링(Polling) 및 Rich Status UI 표시
    _poll_status(job_id)

@app.command("local")
def scan_local(
    target_url: str = typer.Option(..., help="타겟 URL (예: http://localhost:3000)"),
    source_dir: str = typer.Option(..., help="소스코드 디렉토리 경로")
):
    """
    [경고] 서버 없이 로컬에서 즉시 스캔을 수행합니다. (바이너리 설치 필요)
    """
    console.print("[bold yellow]⚠️ 경고: 로컬 스캔은 nuclei, katana, semgrep이 PATH에 설치되어 있어야 합니다.[/bold yellow]")
    console.print("[bold cyan]💡 웬만하면 'jangijoim start' (Docker 기반) 명령어를 사용하세요.[/bold cyan]\n")
    
    from core.orchestrator import run_scan_pipeline
    from core.db_manager import init_db, save_job
    from core.schemas import ScanMetadata, FinalReportState

    console.print(Panel.fit(
        f"[bold green]JANGIJOIM Local 스캔 시작[/bold green]\nTarget: [cyan]{target_url}[/cyan]\nSource: [yellow]{source_dir}[/yellow]",
        border_style="green"
    ))

    # 초기화
    init_db()
    job_id = uuid.uuid4()
    metadata = ScanMetadata(target_host=target_url, source_dir=source_dir)
    initial_state = FinalReportState(metadata=metadata)
    save_job(str(job_id), initial_state)

    async def run_and_monitor():
        # 파이프라인을 백그라운드 태스크로 실행
        task = asyncio.create_task(run_scan_pipeline(job_id, target_url, source_dir))
        
        # 상태 모니터링
        await _poll_status_async(job_id, task)

    asyncio.run(run_and_monitor())

@poc_app.command("run")
def poc_run(
    manifest_path: str = typer.Argument(..., help="PoC 매니페스트 JSON 파일 경로"),
    target_url: str = typer.Option(None, help="타겟 호스트 (매니페스트 설정 무시하고 강제 지정)")
):
    """
    JSON 매니페스트에 정의된 PoC 페이로드들을 재실행하여 취약점을 재검증합니다.
    """
    if not os.path.exists(manifest_path):
        console.print(f"[bold red]❌ 매니페스트 파일을 찾을 수 없습니다: {manifest_path}[/bold red]")
        return

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    base_url = target_url or manifest["metadata"]["target_host"]
    exploits = manifest.get("exploits", [])

    console.print(Panel.fit(
        f"[bold magenta]PoC 재검증 시작[/bold magenta]\nTarget: [cyan]{base_url}[/cyan]\nExploits: [yellow]{len(exploits)}건[/yellow]",
        border_style="magenta"
    ))

    from scanner.executor import run_exploit
    from core.schemas import ExploitPayload, DastSastResult

    async def execute_all():
        table = Table(title="PoC 재검증 결과", show_header=True, header_style="bold blue")
        table.add_column("No.", justify="center")
        table.add_column("취약점 유형", justify="left")
        table.add_column("메서드", justify="center")
        table.add_column("상태 코드", justify="center")
        table.add_column("결과", justify="center")

        for idx, exp in enumerate(exploits):
            payload = ExploitPayload(
                method=exp["method"],
                endpoint=exp["endpoint"],
                headers=exp.get("headers", {}),
                body=exp.get("body"),
                expected_success_regex=exp["expected_success_regex"]
            )
            
            # dummy dast_res (run_exploit 내부에서 payload 위주로 사용하므로 최소 정보만 전달)
            dummy_dast = DastSastResult(
                target_endpoint=exp["endpoint"],
                http_method=exp["method"],
                vuln_type=exp["vuln_type"],
                severity=exp["severity"],
                payload=str(exp.get("body", "")),
                sliced_response=""
            )

            result = await run_exploit(base_url, dummy_dast, payload)
            
            status_text = f"[green]{result.http_status}[/green]" if result.http_status < 400 else f"[red]{result.http_status}[/red]"
            result_text = "[bold red]💥 취약함 (Vulnerable)[/bold red]" if result.is_exploited else "[bold green]🛡️ 차단됨 (Mitigated)[/bold green]"
            
            table.add_row(str(idx+1), exp["vuln_type"], exp["method"], status_text, result_text)
        
        console.print(table)

    asyncio.run(execute_all())

def _poll_status(job_id: str):
    """상태 폴링 루프 (동기)"""
    with Status("[bold blue]파이프라인 초기화 중...", spinner="dots") as status:
        while True:
            time.sleep(2)
            try:
                resp = httpx.get(f"{API_BASE_URL}/scan/status/{job_id}", timeout=5.0)
                if resp.status_code == 200:
                    data = resp.json()
                    if _update_status_ui(status, data):
                        break
                elif resp.status_code == 404:
                    status.update(f"[bold yellow]Job {job_id[:8]}를 기다리는 중... (404)[/bold yellow]")
                else:
                    status.update(f"[bold red]엔진 응답 이상 (HTTP {resp.status_code})[/bold red]")
            except httpx.RequestError:
                status.update("[bold red]서버와 통신 지연 중...[/bold red]")
            except Exception as e:
                status.update(f"[bold red]폴링 에러: {e}[/bold red]")

async def _poll_status_async(job_id: uuid.UUID, task: asyncio.Task):
    """상태 폴링 루프 (비동기, 로컬 실행용)"""
    from core.db_manager import get_job
    
    with Status("[bold blue]로컬 파이프라인 초기화 중...", spinner="dots") as status:
        while not task.done():
            await asyncio.sleep(1)
            state = get_job(str(job_id))
            if state:
                # dict 형태로 변환하여 UI 업데이트 함수 재사용
                if _update_status_ui(status, state.model_dump()):
                    break
        
        if task.exception():
            console.print(f"\n[bold red]❌ 실행 중 예외 발생: {task.exception()}[/bold red]")
        elif not task.done():
            # 태스크가 아직 안 끝났는데 루프가 종료된 경우 (Completed 상태 도달)
            await task

def _update_status_ui(status: Status, data: dict) -> bool:
    """UI 업데이트 로직 (공통) - 완료 시 True 반환"""
    if not data or not isinstance(data, dict):
        return False
        
    current_state = data.get("metadata", {}).get("current_status", "UNKNOWN")
    
    state_messages = {
        "SCANNING": "[1/5] DAST 및 SAST 취약점 스캔 진행 중...",
        "MAPPING": "[2/5] 소스코드 AST 추적 및 교차 매핑 중...",
        "VERIFYING": "[3/5] LLM 컨텍스트 주입 및 정오탐 판별 중...",
        "TESTING": "[4/5] 패치 후 회귀 테스트(Regression Test) 중..."
    }
    
    display_msg = state_messages.get(current_state, f"현재 상태: {current_state}")
    status.update(f"[bold cyan]{display_msg}[/bold cyan]")
    
    if current_state == "COMPLETED":
        console.print("\n[bold green]✅ 파이프라인 스캔이 모두 완료되었습니다![/bold green]")
        render_and_save_report(data, str(data.get("metadata", {}).get("job_id", "unknown")))
        return True
    elif current_state == "FAILED":
        error_log = data.get("metadata", {}).get("error_log", "알 수 없는 에러 발생")
        console.print(f"\n[bold red]❌ 파이프라인이 실패했습니다: {error_log}[/bold red]")
        return True
    return False

def render_and_save_report(data: dict, job_id: str):
    """결과를 터미널 표로 출력하고 Markdown 보고서를 생성합니다."""
    
    vulnerabilities = data.get("vulnerabilities", [])
    
    table = Table(title=f"취약점 검증 결과 (총 {len(vulnerabilities)}건)", show_header=True, header_style="bold magenta")
    table.add_column("No.", justify="center")
    table.add_column("취약점 유형", justify="left")
    table.add_column("판별 결과", justify="center")
    table.add_column("CVSS", justify="center")
    table.add_column("PoC 검증", justify="center")
    
    md_content = f"# JANGIJOIM Vulnerability Summary\n- **Job ID:** {job_id}\n\n"
    
    for idx, item in enumerate(vulnerabilities):
        vuln_type = item.get("dast_result", {}).get("vuln_type", "Unknown")
        llm_res = item.get("llm_verification", {})
        triager = llm_res.get("triager_result", {}) if llm_res else {}
        
        is_vuln = triager.get("is_vulnerable", False)
        cvss = triager.get("cvss_score", 0.0)
        
        exec_res = item.get("execution")
        poc_status = "✅ 성공" if exec_res and exec_res.get("is_exploited") else "❌ 실패" if exec_res else "N/A"
        
        vuln_status = "[red]정탐[/red]" if is_vuln else "[green]오탐[/green]"
        cvss_text = f"[red]{cvss}[/red]" if cvss >= 7.0 else f"[yellow]{cvss}[/yellow]" if cvss >= 4.0 else str(cvss)
        
        table.add_row(str(idx+1), vuln_type, vuln_status, cvss_text, poc_status)
        
        md_content += f"### {idx+1}. {vuln_type}\n"
        md_content += f"- **상태:** {'🚨 정탐' if is_vuln else '✅ 오탐'}\n"
        md_content += f"- **CVSS:** {cvss}\n"
        md_content += f"- **PoC 검증:** {poc_status}\n\n"

    console.print(table)
    console.print(f"\n💡 [bold cyan]상세 보고서는 reports/ 디렉토리 내의 최신 파일을 확인하세요.[/bold cyan]")
    
    summary_filename = f"JANGIJOIM_Summary_{job_id[-6:]}.md"
    with open(summary_filename, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    console.print(f"📄 [bold yellow]CLI 요약 보고서가 생성되었습니다:[/bold yellow] [underline]{summary_filename}[/underline]")

if __name__ == "__main__":
    app()
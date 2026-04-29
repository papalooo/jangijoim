import typer
import httpx
import time
import json
from rich.console import Console
from rich.status import Status
from rich.table import Table
from rich.panel import Panel

app = typer.Typer()
console = Console()

API_BASE_URL = "http://127.0.0.1:8000"

@app.command("start")
def scan_start(target_url: str, source_dir: str):
    """
    JANGIJOIM 보안 스캔 파이프라인을 시작하고 진행 상황을 모니터링합니다.
    """
    console.print(Panel.fit(
        f"[bold green]JANGIJOIM Pipeline 시작[/bold green]\nTarget: [cyan]{target_url}[/cyan]\nSource: [yellow]{source_dir}[/yellow]",
        border_style="green"
    ))
    
    # 1. FastAPI 서버에 스캔 시작 요청
    try:
        resp = httpx.post(f"{API_BASE_URL}/scan/start", params={"target_url": target_url, "source_dir": source_dir})
        resp.raise_for_status()
        job_id = resp.json()["job_id"]
    except Exception as e:
        console.print(f"[bold red]❌ 엔진 서버(FastAPI)에 연결할 수 없습니다.[/bold red] 서버가 켜져 있는지 확인하세요.\n({e})")
        return

    # 2. 상태 폴링(Polling) 및 Rich Status UI 표시
    with Status("[bold blue]파이프라인 초기화 중...", spinner="dots") as status:
        while True:
            time.sleep(2) # 2초 주기로 상태 확인
            try:
                status_resp = httpx.get(f"{API_BASE_URL}/scan/status/{job_id}").json()
                current_state = status_resp.get("metadata", {}).get("current_status", "UNKNOWN")
                
                # 상태별 메시지 매핑
                state_messages = {
                    "SCANNING": "[1/5] DAST 및 SAST 취약점 스캔 진행 중...",
                    "MAPPING": "[2/5] 소스코드 AST 추적 및 교차 매핑 중...",
                    "VERIFYING": "[3/5] LLM 컨텍스트 주입 및 정오탐 판별 중...",
                    "PATCHING": "[4/5] 시큐어 코딩(Patch) 생성 및 적용 중...",
                    "TESTING": "[5/5] 패치 후 회귀 테스트(Regression Test) 중..."
                }
                
                display_msg = state_messages.get(current_state, f"현재 상태: {current_state}")
                status.update(f"[bold cyan]{display_msg}[/bold cyan]")
                
                if current_state == "COMPLETED":
                    console.print("\n[bold green]✅ 파이프라인 스캔이 모두 완료되었습니다![/bold green]")
                    break
                elif current_state == "FAILED":
                    error_log = status_resp.get("metadata", {}).get("error_log", "알 수 없는 에러 발생")
                    console.print(f"\n[bold red]❌ 파이프라인이 실패했습니다: {error_log}[/bold red]")
                    return
                    
            except httpx.RequestError:
                status.update("[bold red]서버와 통신 지연 중... 재연결 시도...[/bold red]")

    # 3. 완료 후 터미널에 결과 표(Table) 출력 및 파일 저장
    render_and_save_report(status_resp, job_id)


def render_and_save_report(data: dict, job_id: str):
    """결과를 터미널 표로 출력하고 Markdown 보고서를 생성합니다."""
    
    # ✅ 다중 취약점 리스트 가져오기
    vulnerabilities = data.get("vulnerabilities", [])
    
    # 터미널 Table 출력
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
        
        # PoC 검증 결과
        exec_res = item.get("execution")
        poc_status = "✅ 성공" if exec_res and exec_res.get("is_exploited") else "❌ 실패" if exec_res else "N/A"
        
        # 터미널용 데이터 가공
        vuln_status = "[red]정탐[/red]" if is_vuln else "[green]오탐[/green]"
        cvss_text = f"[red]{cvss}[/red]" if cvss >= 7.0 else f"[yellow]{cvss}[/yellow]" if cvss >= 4.0 else str(cvss)
        
        table.add_row(str(idx+1), vuln_type, vuln_status, cvss_text, poc_status)
        
        # 마크다운용 요약 가공
        md_content += f"### {idx+1}. {vuln_type}\n"
        md_content += f"- **상태:** {'🚨 정탐' if is_vuln else '✅ 오탐'}\n"
        md_content += f"- **CVSS:** {cvss}\n"
        md_content += f"- **PoC 검증:** {poc_status}\n\n"

    console.print(table)
    console.print(f"\n💡 [bold cyan]상세 보고서는 reports/ 디렉토리 내의 최신 파일을 확인하세요.[/bold cyan]")
    
    # CLI 요약 리포트 저장 (상세 리포트는 이미 reporter.py에서 생성됨)
    summary_filename = f"JANGIJOIM_Summary_{job_id[-6:]}.md"
    with open(summary_filename, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    console.print(f"📄 [bold yellow]CLI 요약 보고서가 생성되었습니다:[/bold yellow] [underline]{summary_filename}[/underline]")

if __name__ == "__main__":
    app()
import time
import typer
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

# Typer 앱 및 Rich 콘솔 초기화
app = typer.Typer(help="jangijoim: LLM 기반 웹 취약점 진단 및 자동 패치 파이프라인")
console = Console()

# 로컬에서 백그라운드로 돌고 있는 FastAPI 오케스트레이터 주소
API_BASE_URL = "http://127.0.0.1:8000"

@app.command()
def start(
    target_url: str = typer.Argument(..., help="진단할 타겟 웹 서비스의 URL (예: http://localhost:3000)"),
    source_dir: str = typer.Argument(..., help="분석할 로컬 소스코드 디렉토리 경로 (예: ./src)")
):
    """
    jangijoim 파이프라인을 시작하고 진행 상태를 모니터링합니다.
    """
    console.print(Panel.fit(f"[bold blue]jangijoim Pipeline 시작[/bold blue]\nTarget: [green]{target_url}[/green]\nSource: [green]{source_dir}[/green]"))

    # 1. 오케스트레이터에 스캔 시작 요청 (POST)
    try:
        response = requests.post(
            f"{API_BASE_URL}/scan/start",
            params={"target_url": target_url, "source_dir": source_dir}
        )
        response.raise_for_status()
        job_data = response.json()
        job_id = job_data["job_id"]
    except requests.exceptions.ConnectionError:
        console.print("[bold red][오류][/bold red] FastAPI 오케스트레이터가 실행 중이지 않습니다. 'uvicorn main:app'을 먼저 실행하세요.")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red][오류][/bold red] 파이프라인 시작 실패: {e}")
        raise typer.Exit(code=1)

    # 2. 상태 폴링(Polling) 및 프로그레스 바 렌더링
    # Rich 라이브러리를 사용해 터미널이 멈추지 않고 애니메이션이 돌게 만듭니다.
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=False,
    ) as progress:
        
        task_id = progress.add_task("[cyan]파이프라인 초기화 중...", total=None)
        
        while True:
            try:
                # 1초마다 FastAPI 서버에 현재 작업 상태를 물어봅니다. (GET)
                status_res = requests.get(f"{API_BASE_URL}/scan/status/{job_id}")
                status_res.raise_for_status()
                state = status_res.json()
                
                current_status = state["metadata"]["current_status"]
                
                # 상태값에 따라 터미널 텍스트 업데이트
                if current_status == "SCANNING":
                    progress.update(task_id, description="[yellow]1/5 단계: DAST 및 SAST 취약점 스캔 진행 중...[/yellow]")
                elif current_status == "MAPPING":
                    progress.update(task_id, description="[magenta]2/5 단계: 소스코드 AST 추적 및 교차 매핑 중...[/magenta]")
                elif current_status == "VERIFYING":
                    progress.update(task_id, description="[blue]3/5 단계: LLM 컨텍스트 주입 및 정오탐 판별 중...[/blue]")
                elif current_status == "TESTING":
                    progress.update(task_id, description="[cyan]4/5 단계: 방어 코드 생성, 적용 및 회귀 테스트 중...[/cyan]")
                elif current_status == "COMPLETED":
                    progress.update(task_id, description="[bold green]✅ 모든 파이프라인 완료![/bold green]")
                    break
                elif current_status == "FAILED":
                    progress.update(task_id, description="[bold red]❌ 파이프라인 실행 중 오류 발생[/bold red]")
                    error_log = state["metadata"].get("error_log", "알 수 없는 오류")
                    console.print(f"\n[red]상세 에러:[/red] {error_log}")
                    raise typer.Exit(code=1)
                
                time.sleep(1) # 1초 대기 후 다시 확인
                
            except Exception as e:
                progress.update(task_id, description=f"[bold red]상태 확인 중 통신 오류 발생: {e}[/bold red]")
                time.sleep(2)

    # 3. 최종 결과 요약 출력
    console.print("\n[bold]📋 스캔 요약 리포트[/bold]")
    if state.get("verification") and state["verification"]["is_vulnerable"]:
        console.print(f"- [red]정탐 확인됨:[/red] CVSS Score {state['verification']['cvss_score']}")
        if state.get("regression_test") and state["regression_test"]["is_mitigated"]:
            console.print("- [green]자동 패치 및 방어 테스트 성공 (HTTP 403 확인)[/green]")
    else:
        console.print("- [yellow]발견된 내역이 모두 오탐으로 판별되어 안전합니다.[/yellow]")
        
    console.print("\n[bold cyan]상세 보고서가 PDF로 렌더링 되었습니다.[/bold cyan]")

if __name__ == "__main__":
    app()
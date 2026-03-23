import typer
import uvicorn
from core.cli import app as cli_app

# 최상위 Typer 애플리케이션 생성
app = typer.Typer(help="jangijoim: DevSecOps 자동 진단 및 패치 파이프라인 통합 CLI")

# core/cli.py에서 만든 운전대 명령어들을 'scan' 이라는 그룹으로 묶어서 가져옵니다.
app.add_typer(cli_app, name="scan", help="취약점 진단 및 상태 추적 명령어 그룹")

@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="서버 바인딩 호스트"),
    port: int = typer.Option(8000, help="서버 포트 번호")
):
    """
    [백그라운드 엔진] FastAPI 오케스트레이터 서버를 가동합니다.
    주의: 이 명령어를 실행해 둔 상태에서, 다른 터미널 창을 열어 scan 명령어를 실행해야 합니다.
    """
    typer.echo(f"🚀 jangijoim 파이프라인 오케스트레이터 엔진 시동 중... ({host}:{port})")
    # core/orchestrator.py 안의 'app' 객체를 uvicorn으로 실행
    uvicorn.run("core.orchestrator:app", host=host, port=port, reload=True)

if __name__ == "__main__":
    app()
# intelligence/reporter.py
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from core.schemas import FinalReportState

def generate_markdown_report(state: FinalReportState, output_dir: str = "./reports") -> str:
    """
    Jinja2 템플릿을 사용하여 파이프라인 결과를 Markdown 보고서로 생성합니다.
    """
    # 1. 출력 디렉토리 생성
    os.makedirs(output_dir, exist_ok=True)
    
    # 2. 템플릿 환경 설정
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report_template.md")
    
    # 3. 데이터 렌더링
    # state 객체를 dict로 변환하여 템플릿에 전달 (Pydantic 모델은 .model_dump() 사용)
    render_data = state.model_dump()
    # datetime 객체는 dict 변환 시 문자열이 될 수 있으므로 필요시 직접 전달하거나 처리
    # 여기서는 jinja2에서 직접 접근할 수 있도록 state 객체 자체의 속성도 활용 가능
    
    md_content = template.render(
        metadata=state.metadata,
        vulnerabilities=state.vulnerabilities
    )
    
    # 4. 파일 저장
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"Security_Report_{timestamp}.md"
    report_path = os.path.join(output_dir, report_filename)
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    print(f"✅ [보고서 생성] {report_path}")
    return report_path

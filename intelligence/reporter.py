# intelligence/reporter.py
import os
from datetime import datetime
from core.schemas import FinalReportState

def generate_markdown_report(state: FinalReportState, output_dir: str = "./reports") -> str:
    """
    파이프라인의 최종 마스터 상태(FinalReportState)를 Markdown 형식의 보안 진단 보고서로 렌더링합니다.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"Vulnerability_Report_{timestamp}.md"
    report_path = os.path.join(output_dir, report_filename)
    
    md_content = f"# 🛡️ 웹 애플리케이션 취약점 진단 및 조치 보고서\n\n"
    md_content += f"- **진단 일시:** {timestamp}\n"
    md_content += f"- **타겟 호스트:** {state.metadata.target_host}\n"
    md_content += f"- **분석 디렉토리:** {state.metadata.source_dir}\n\n"
    
    md_content += "--- \n\n"
    
    md_content += "## 1. 스캐너 탐지 요약 (DAST & SAST Mapping)\n"
    if state.dast_result:
        md_content += f"* **취약점 유형:** {state.dast_result.vuln_type}\n"
        md_content += f"* **발생 엔드포인트:** `{state.dast_result.http_method} {state.dast_result.target_endpoint}`\n"
        md_content += f"* **초기 위험도:** {state.dast_result.severity}\n"
    else:
        md_content += "> 탐지된 취약점 내역이 없습니다.\n"
    
    md_content += "\n## 2. 보안 지능 분석 및 검증 (LLM Verification)\n"
    if state.verification:
        is_vuln_str = "🔴 **정탐 (Vulnerable)**" if state.verification.is_vulnerable else "🟢 **오탐 (Safe/False Positive)**"
        md_content += f"* **최종 판별 결과:** {is_vuln_str}\n"
        md_content += f"* **CVSS v3.1 스코어:** {state.verification.cvss_score} ({state.verification.cvss_vector})\n"
        md_content += f"* **루트 원인 분석:**\n  > {state.verification.reason}\n"
        
    md_content += "\n## 3. 코드 단위 보안 패치 가이드 (Remediation)\n"
    if state.patch and state.patch.is_patch_generated:
        md_content += "### 💡 적용된 보안 조치 (Action Items)\n"
        for step in state.patch.remediation_steps:
            md_content += f"- {step}\n"
        md_content += f"\n### 🛠️ 패치 적용 코드 (Patched Snippet)\n```python\n{state.patch.patched_code}\n```\n"
    else:
        md_content += "> 생성된 패치 코드가 없습니다.\n"

    md_content += "\n## 4. 방어 로직 회귀 테스트 결과 (Regression Test)\n"
    if state.regression_test:
        result_str = "✅ **차단 성공**" if state.regression_test.is_mitigated else "❌ **방어 실패 (우회 가능)**"
        md_content += f"* **테스트 결과:** {result_str}\n"
        md_content += f"* **패치 후 상태 코드:** {state.regression_test.http_status_after_patch}\n"
        md_content += f"* **원본 코드 롤백:** {'성공' if state.regression_test.rollback_successful else '실패'}\n"

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    return report_path
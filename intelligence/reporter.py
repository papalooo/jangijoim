# intelligence/reporter.py
import os
import json
from datetime import datetime
from collections import defaultdict
from jinja2 import Environment, FileSystemLoader
from docxtpl import DocxTemplate
from core.schemas import FinalReportState, VulnerabilityItem

def prepare_report_data(state: FinalReportState):
    """
    보고서 렌더링을 위한 데이터를 준비합니다 (Markdown/Word 공통)
    """
    vulnerabilities = state.vulnerabilities
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    
    stats = {
        "total": len(vulnerabilities),
        "severity": defaultdict(int),
        "tp": 0,
        "fp": 0,
        "patch_success": 0,
        "patch_fail": 0
    }
    
    poc_manifest = {
        "metadata": {
            "target_host": state.metadata.target_host,
            "job_id": str(state.metadata.job_id),
            "generated_at": datetime.now().isoformat()
        },
        "exploits": []
    }
    
    grouped_vulns = defaultdict(list)
    
    for item in vulnerabilities:
        group_key = f"{item.dast_result.vuln_type} @ {item.dast_result.target_endpoint}"
        grouped_vulns[group_key].append(item)
        
        sev = item.dast_result.severity
        stats["severity"][sev] += 1
        
        if item.llm_verification:
            if item.llm_verification.triager_result.is_vulnerable:
                stats["tp"] += 1
                
                exploit = item.llm_verification.red_teamer_payload
                poc_manifest["exploits"].append({
                    "vuln_type": item.dast_result.vuln_type,
                    "severity": item.dast_result.severity,
                    "method": exploit.method,
                    "endpoint": exploit.endpoint,
                    "headers": exploit.headers,
                    "body": exploit.body,
                    "expected_success_regex": exploit.expected_success_regex
                })
                
                if item.regression_test and item.regression_test.is_mitigated:
                    stats["patch_success"] += 1
                elif item.regression_test:
                    stats["patch_fail"] += 1
            else:
                stats["fp"] += 1
    
    stats["tp_ratio"] = round((stats["tp"] / stats["total"] * 100), 1) if stats["total"] > 0 else 0
    stats["patch_success_rate"] = round((stats["patch_success"] / stats["tp"] * 100), 1) if stats["tp"] > 0 else 0
    
    display_groups = []
    for key, items in grouped_vulns.items():
        representative = items[0]
        display_groups.append({
            "vuln_type": representative.dast_result.vuln_type,
            "severity": representative.dast_result.severity,
            "endpoint": representative.dast_result.target_endpoint,
            "method": representative.dast_result.http_method,
            "instances": items,
            "count": len(items)
        })

    display_groups.sort(key=lambda x: severity_order.get(x["severity"], 99))
    
    return stats, display_groups, poc_manifest

def generate_markdown_report(state: FinalReportState, output_dir: str = "./reports") -> str:
    """
    Jinja2 템플릿을 사용하여 파이프라인 결과를 Markdown 보고서로 생성합니다.
    """
    os.makedirs(output_dir, exist_ok=True)
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report_template.md")
    
    stats, display_groups, poc_manifest = prepare_report_data(state)
    
    md_content = template.render(
        metadata=state.metadata,
        stats=stats,
        grouped_vulns=display_groups,
        vulnerabilities=state.vulnerabilities
    )
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"Security_Report_{timestamp}.md"
    report_path = os.path.join(output_dir, report_filename)
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    manifest_filename = f"poc_manifest_{timestamp}.json"
    manifest_path = os.path.join(output_dir, manifest_filename)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(poc_manifest, f, indent=2, ensure_ascii=False)
        
    print(f"✅ [Markdown 보고서 생성] {report_path}")
    print(f"📦 [PoC 매니페스트 생성] {manifest_path}")
    return report_path

def generate_word_report(state: FinalReportState, output_dir: str = "./reports") -> str:
    """
    docxtpl을 사용하여 파이프라인 결과를 Word(.docx) 보고서로 생성합니다.
    """
    os.makedirs(output_dir, exist_ok=True)
    template_path = os.path.join(os.path.dirname(__file__), "templates", "report_template.docx")
    
    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Word template not found at {template_path}")
        
    doc = DocxTemplate(template_path)
    
    stats, display_groups, _ = prepare_report_data(state)
    
    # docxtpl은 Pydantic 모델을 직접 다루지 못할 수 있으므로 dict로 변환하거나 속성에 직접 접근합니다.
    # Jinja2 렌더링 컨텍스트 생성
    context = {
        "metadata": state.metadata,
        "stats": stats,
        "grouped_vulns": display_groups,
        "vulnerabilities": state.vulnerabilities
    }
    
    doc.render(context)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"Security_Report_{timestamp}.docx"
    report_path = os.path.join(output_dir, report_filename)
    
    doc.save(report_path)
    
    print(f"✅ [Word 보고서 생성] {report_path}")
    return report_path




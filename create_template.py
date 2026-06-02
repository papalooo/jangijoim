from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
import os

def create_template():
    doc = Document()
    
    # 폰트 설정 (맑은 고딕 등을 기본으로 설정 시도 - 환경에 따라 다를 수 있음)
    style = doc.styles['Normal']
    font = style.font
    font.name = 'Arial'
    
    # --- 1. 커버 페이지 (Cover Page) ---
    doc.add_paragraph('\n\n\n\n\n\n')
    title = doc.add_paragraph('보안 취약점 진단 결과 보고서')
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_run = title.runs[0]
    title_run.font.size = Pt(28)
    title_run.font.bold = True
    
    doc.add_paragraph('\n\n\n')
    
    subtitle = doc.add_paragraph('LLM 기반 자동화 진단 파이프라인 산출물')
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle_run = subtitle.runs[0]
    subtitle_run.font.size = Pt(16)
    subtitle_run.font.color.rgb = RGBColor(100, 100, 100)
    
    doc.add_paragraph('\n\n\n\n\n\n')
    
    # 커버 정보 테이블
    info_table = doc.add_table(rows=3, cols=2)
    info_table.alignment = WD_ALIGN_PARAGRAPH.CENTER
    info_table.style = 'Table Grid'
    
    def set_cell_bg(cell, color_hex):
        shading_elm = doc.element.xpath('.//w:tcPr')[0] # Note: Simplified for script generation, actual manipulation requires deeper oxml access. We will just use bolding for headers.

    info_table.cell(0, 0).text = '진단 대상 시스템'
    info_table.cell(0, 1).text = '{{ metadata.target_host }}'
    info_table.cell(1, 0).text = '진단 일시'
    info_table.cell(1, 1).text = '{{ metadata.start_time }}'
    info_table.cell(2, 0).text = '진단 Job ID'
    info_table.cell(2, 1).text = '{{ metadata.job_id }}'
    
    for row in info_table.rows:
        for idx, cell in enumerate(row.cells):
            paragraphs = cell.paragraphs
            for paragraph in paragraphs:
                paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                if idx == 0:
                    for run in paragraph.runs:
                        run.font.bold = True

    doc.add_page_break()

    # --- 2. 진단 요약 (Executive Summary) ---
    doc.add_heading('1. 진단 결과 요약', level=1)
    
    summary_p = doc.add_paragraph()
    summary_p.add_run('본 보고서는 대상 시스템( ')
    summary_p.add_run('{{ metadata.target_host }}').bold = True
    summary_p.add_run(' )에 대한 보안 취약점 진단 결과를 포함합니다.\n')
    summary_p.add_run('총 ')
    summary_p.add_run('{{ stats.total }}').bold = True
    summary_p.add_run('개의 잠재적 취약점이 발견되었으며, LLM 기반 검증 결과 실제 위협(True Positive)은 ')
    summary_p.add_run('{{ stats.tp }}').bold = True
    summary_p.add_run('건으로 확인되었습니다.')

    doc.add_heading('위험도별 분포', level=2)
    
    stat_table = doc.add_table(rows=2, cols=5)
    stat_table.style = 'Light Shading Accent 1' # 내장 스타일 사용
    
    hdr_cells = stat_table.rows[0].cells
    hdr_cells[0].text = 'Critical'
    hdr_cells[1].text = 'High'
    hdr_cells[2].text = 'Medium'
    hdr_cells[3].text = 'Low'
    hdr_cells[4].text = 'Info'
    
    row_cells = stat_table.rows[1].cells
    row_cells[0].text = '{{ stats.severity["Critical"] }} 건'
    row_cells[1].text = '{{ stats.severity["High"] }} 건'
    row_cells[2].text = '{{ stats.severity["Medium"] }} 건'
    row_cells[3].text = '{{ stats.severity["Low"] }} 건'
    row_cells[4].text = '{{ stats.severity["Info"] }} 건'

    for row in stat_table.rows:
        for cell in row.cells:
            for paragraph in cell.paragraphs:
                paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                for run in paragraph.runs:
                    if row == stat_table.rows[0]:
                        run.font.bold = True

    doc.add_page_break()

    # --- 3. 상세 취약점 내역 (Vulnerability Details) ---
    doc.add_heading('2. 상세 취약점 내역', level=1)
    
    p_group_start = doc.add_paragraph()
    p_group_start.add_run('{% for group in grouped_vulns %}')
    
    # 각 취약점 그룹별 헤딩
    doc.add_heading('{{ loop.index }}. {{ group.vuln_type }} ({{ group.severity }})', level=2)
    
    doc.add_paragraph('발견된 엔드포인트 수: {{ group.count }}건').runs[0].bold = True
    
    p_item_start = doc.add_paragraph()
    p_item_start.add_run('{% for item in group.instances %}')
    
    doc.add_heading('{{ loop.index }}.{{ loop.index }} 대상: {{ group.method }} {{ group.endpoint }}', level=3)
    
    # 상세 정보 테이블
    vuln_table = doc.add_table(rows=5, cols=2)
    vuln_table.style = 'Table Grid'
    
    # 열 너비 설정 (근사치)
    for cell in vuln_table.columns[0].cells:
        cell.width = Inches(1.5)
    for cell in vuln_table.columns[1].cells:
        cell.width = Inches(5.0)

    # 1행: 상태
    vuln_table.cell(0, 0).text = '검증 상태'
    vuln_table.cell(0, 1).text = '{% if item.llm_verification %}{% if item.llm_verification.triager_result.is_vulnerable %}🚨 Vulnerable (True Positive){% else %}✅ False Positive{% endif %}{% else %}⏳ Pending Validation{% endif %}'
    
    # 2행: 스캐너 증거
    vuln_table.cell(1, 0).text = '발견 증거 (Evidence)'
    vuln_table.cell(1, 1).text = '페이로드: {{ item.dast_result.payload }}\n응답 요약: {{ item.dast_result.sliced_response }}'
    
    # 3행: LLM 공격 페이로드 (검증된 경우만 출력)
    vuln_table.cell(2, 0).text = 'PoC 페이로드'
    vuln_table.cell(2, 1).text = '{% if item.llm_verification and item.llm_verification.red_teamer_payload %}{{ item.llm_verification.red_teamer_payload.method }} {{ item.llm_verification.red_teamer_payload.endpoint }}\n{{ item.llm_verification.red_teamer_payload.body }}{% else %}-{% endif %}'
    
    # 4행: 패치 여부
    vuln_table.cell(3, 0).text = '자동 패치 결과'
    vuln_table.cell(3, 1).text = '{% if item.regression_test %}{% if item.regression_test.is_mitigated %}성공 (HTTP {{ item.regression_test.http_status_after_patch }}){% else %}실패 (HTTP {{ item.regression_test.http_status_after_patch }}){% endif %}{% else %}미수행{% endif %}'
    
    # 5행: 영향도/설명
    vuln_table.cell(4, 0).text = '상세 설명'
    vuln_table.cell(4, 1).text = '{% if item.llm_verification %}{{ item.llm_verification.triager_result.reason }}{% else %}스캐너가 식별한 잠재적 취약점입니다.{% endif %}'

    # 헤더 열 볼드 처리
    for i in range(5):
        for paragraph in vuln_table.cell(i, 0).paragraphs:
            for run in paragraph.runs:
                run.font.bold = True

    doc.add_paragraph('\n')
    
    p_item_end = doc.add_paragraph()
    p_item_end.add_run('{% endfor %}')
    
    p_group_end = doc.add_paragraph()
    p_group_end.add_run('{% endfor %}')

    # Save
    template_dir = os.path.join("intelligence", "templates")
    os.makedirs(template_dir, exist_ok=True)
    doc.save(os.path.join(template_dir, "report_template.docx"))

if __name__ == "__main__":
    create_template()

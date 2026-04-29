# 🛡️ 보안 취약점 진단 및 자동 패치 제안 보고서

진단 대상: {{ metadata.target_host }}
진단 일시: {{ metadata.start_time.strftime('%Y-%m-%d %H:%M:%S UTC') }}
총 발견 취약점: {{ vulnerabilities|length }}건

---

{% for item in vulnerabilities %}
# [취약점 #{{ loop.index }}] {{ item.dast_result.vuln_type }} ({{ item.dast_result.severity }})

## 1. 🔍 취약점 탐지 요약

### [취약점 정보]
- **유형:** {{ item.dast_result.vuln_type }}
- **위험도:** {{ item.dast_result.severity }}
- **엔드포인트:** `{{ item.dast_result.http_method }} {{ item.dast_result.target_endpoint }}`

### [탐지 증거]
- **사용 페이로드:** `{{ item.dast_result.payload }}`
- **응답 요약:**
```text
{{ item.dast_result.sliced_response }}
```

---

## 2. 📍 소스코드 매핑 정보

{% if item.mapped_context and item.mapped_context.is_mapped %}
- **대상 파일:** `{{ item.mapped_context.mapped_file_path }}` (L{{ item.mapped_context.start_line }} ~ L{{ item.mapped_context.end_line }})
- **매핑 방식:** {{ item.mapped_context.mapping_method.value }}
- **신뢰도:** {{ item.mapped_context.mapping_confidence_band.value }} ({{ (item.mapped_context.mapping_confidence * 100)|round(1) }}%)
- **매핑 근거:** {{ item.mapped_context.mapping_evidence|join(', ') }}

### [원본 취약 코드]
```python
{{ item.mapped_context.code_snippet }}
```
{% else %}
- 소스코드 매핑에 실패했습니다. (사유: {{ item.mapped_context.mapping_failure_reason if item.mapped_context else 'N/A' }})
{% endif %}

---

## 3. 🧠 지능형 보안 분석

{% if item.llm_verification %}
### [에이전트 판별 결과]
- **최종 판별:** {{ '🔴 정탐 (Vulnerable)' if item.llm_verification.triager_result.is_vulnerable else '🟢 오탐 (False Positive)' }}
- **CVSS v3.1 스코어:** **{{ item.llm_verification.triager_result.cvss_score }}** (`{{ item.llm_verification.triager_result.cvss_vector }}`)
- **분석 근거:**
> {{ item.llm_verification.triager_result.reason }}

{% if item.llm_verification.triager_result.is_vulnerable %}
### [PoC 검증 시나리오]
- **검증 페이로드:** `{{ item.llm_verification.red_teamer_payload.body or item.llm_verification.red_teamer_payload.endpoint }}`
- **성공 판별 정규식:** `{{ item.llm_verification.red_teamer_payload.expected_success_regex }}`
{% endif %}
{% else %}
- 분석 데이터가 존재하지 않습니다.
{% endif %}

---

## 4. 🛠️ 시큐어 코딩 패치 제안

{% if item.llm_verification and item.llm_verification.blue_teamer_patch.is_patch_generated %}
### [패치 가이드]
{% for step in item.llm_verification.blue_teamer_patch.remediation_steps %}
- {{ step }}
{% endfor %}

### [수정 제안 코드]
```python
{{ item.llm_verification.blue_teamer_patch.patched_code }}
```

### [QA 검수 결과]
- **검수 통과:** {{ '✅ 통과' if item.llm_verification.qa_passed else '❌ 재검토 필요' }}
- **피드백:** {{ item.llm_verification.qa_feedback }}
{% else %}
- 패치 제안이 생성되지 않았습니다.
{% endif %}

---

## 5. 🧪 패치 유효성 검증 (PoC 테스트)

{% if item.regression_test %}
- **방어 성공 여부:** {{ '✅ 차단 성공 (Mitigated)' if item.regression_test.is_mitigated else '❌ 방어 실패 (Bypass Possible)' }}
- **테스트 후 상태 코드:** `{{ item.regression_test.http_status_after_patch }}`
{% else %}
- 검증 테스트가 수행되지 않았습니다.
{% endif %}

---
{% if not loop.last %}
<div style="page-break-after: always;"></div>
{% endif %}
{% endfor %}

---
*본 보고서는 Gemini CLI Security Pipeline에 의해 자동 생성되었습니다.*

# 🛡️ 보안 취약점 진단 및 자동 패치 제안 보고서

## 📊 요약 대시보드 (Summary Dashboard)

| 항목 | 내용 |
| :--- | :--- |
| **진단 대상** | {{ metadata.target_host }} |
| **진단 일시** | {{ metadata.start_time.strftime('%Y-%m-%d %H:%M:%S UTC') }} |
| **총 발견 취약점** | {{ stats.total }}건 |
| **정탐/오탐 비율** | **정탐 {{ stats.tp }}** / 오탐 {{ stats.fp }} (정탐률: {{ stats.tp_ratio }}%) |
| **패치 성공률** | **성공 {{ stats.patch_success }}** / 대상 {{ stats.tp }} (성공률: {{ stats.patch_success_rate }}%) |

### 🚨 위험도별 현황
- **🔴 Critical:** {{ stats.severity.Critical }}건
- **🟠 High:** {{ stats.severity.High }}건
- **🟡 Medium:** {{ stats.severity.Medium }}건
- **🔵 Low:** {{ stats.severity.Low }}건
- **⚪ Info:** {{ stats.severity.Info }}건

---

{% for group in grouped_vulns %}
# [취약점 그룹 #{{ loop.index }}] {{ group.vuln_type }} ({{ group.severity }})
- **엔드포인트:** `{{ group.method }} {{ group.endpoint }}`
- **발견 횟수:** {{ group.count }}건

{% for item in group.instances %}
## 🔍 세부 인스턴스 분석 ({{ loop.index }}/{{ group.count }})

### 1. 🔍 취약점 탐지 요약
- **사용 페이로드:** `{{ item.dast_result.payload }}`
- **응답 요약:**
```text
{{ item.dast_result.sliced_response }}
```

### 2. 📍 소스코드 매핑 정보
{% if item.mapped_context and item.mapped_context.is_mapped %}
- **대상 파일:** `{{ item.mapped_context.mapped_file_path }}` (L{{ item.mapped_context.start_line }} ~ L{{ item.mapped_context.end_line }})
- **신뢰도:** {{ item.mapped_context.mapping_confidence_band.value }} ({{ (item.mapped_context.mapping_confidence * 100)|round(1) }}%)

#### [원본 취약 코드]
```typescript
{{ item.mapped_context.code_snippet }}
```
{% else %}
- 소스코드 매핑에 실패했습니다. (사유: {{ item.mapped_context.mapping_failure_reason if item.mapped_context else 'N/A' }})
{% endif %}

### 3. 🧠 지능형 보안 분석
{% if item.llm_verification %}
- **최종 판별:** {{ '🔴 정탐 (Vulnerable)' if item.llm_verification.triager_result.is_vulnerable else '🟢 오탐 (False Positive)' }}
- **CVSS v3.1 스코어:** **{{ item.llm_verification.triager_result.cvss_score }}** (`{{ item.llm_verification.triager_result.cvss_vector }}`)
- **분석 근거:**
> {{ item.llm_verification.triager_result.reason }}
{% else %}
- 분석 데이터가 존재하지 않습니다.
{% endif %}

### 4. 🛠️ 시큐어 코딩 패치 제안
{% if item.llm_verification and item.llm_verification.blue_teamer_patch.is_patch_generated %}
#### [패치 가이드]
{% for step in item.llm_verification.blue_teamer_patch.remediation_steps %}
- {{ step }}
{% endfor %}

#### [수정 제안 코드]
```typescript
{{ item.llm_verification.blue_teamer_patch.patched_code }}
```

#### [QA 검수 결과]
- **검수 통과:** {{ '✅ 통과' if item.llm_verification.qa_passed else '❌ 재검토 필요' }}
- **피드백:** {{ item.llm_verification.qa_feedback }}
{% else %}
- 패치 제안이 생성되지 않았습니다.
{% endif %}

### 5. 🧪 패치 유효성 검증 (PoC 테스트)
{% if item.regression_test %}
- **방어 성공 여부:** {{ '✅ 차단 성공 (Mitigated)' if item.regression_test.is_mitigated else '❌ 방어 실패 (Bypass Possible)' }}
- **테스트 후 상태 코드:** `{{ item.regression_test.http_status_after_patch }}`

{% if not item.regression_test.is_mitigated and item.llm_verification.triager_result.is_vulnerable %}
#### ⚠️ 후속 조치 계획 (Follow-up Action Plan)
1. **정밀 분석:** 자동 패치로 해결되지 않는 복합적인 비즈니스 로직 결함일 가능성이 높으므로 수동 코드 리뷰를 권장합니다.
2. **가상 패칭:** 즉각적인 조치가 어려운 경우 WAF 규칙을 통해 해당 공격 패턴을 차단하십시오.
3. **심층 방어:** 입력값 검증뿐만 아니라 출력 인코딩, 보안 헤더(CSP 등)를 강화하여 계층적 방어를 구축하십시오.
{% endif %}
{% else %}
- 검증 테스트가 수행되지 않았습니다.
{% endif %}

---
{% endfor %}
{% if not loop.last %}
<div style="page-break-after: always;"></div>
{% endif %}
{% endfor %}

## 🏁 결론 (Conclusion)

### 1. 우선 조치 권고
- **최우선 조치:** `Critical` 및 `High` 위험도의 정탐 항목 중 '방어 실패'로 판정된 항목을 즉시 보완하십시오.
- **상시 모니터링:** 패치가 적용된 엔드포인트에 대해 비정상적인 트래픽이나 우회 시도가 있는지 모니터링하십시오.

### 2. 재진단 계획
- 모든 패치 적용 완료 후 24시간 이내에 전체 보안 재진단을 실시하여 잔여 위험을 확인하십시오.
- 다음 정기 업데이트 시점에 이번에 발견된 취약점들에 대한 회귀 테스트를 포함하십시오.

---
*본 보고서는 Gemini CLI Security Pipeline에 의해 자동 생성되었습니다.*

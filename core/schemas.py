from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

# -----------------------------------------------------------------
# [공통/상태 관리] 파이프라인 상태 및 메타데이터 (Role 1)
# -----------------------------------------------------------------

class ScanStatus(str, Enum):
    """비동기 파이프라인의 현재 상태를 추적하는 열거형 (Enum)"""
    QUEUED = "QUEUED"
    SCANNING = "SCANNING"         # DAST/SAST 구동 중
    MAPPING = "MAPPING"           # 소스코드 AST 추적 중
    VERIFYING = "VERIFYING"       # LLM 1차 추론 중
    TESTING = "TESTING"           # 페이로드 검증 및 회귀 테스트 중
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class ScanMetadata(BaseModel):
    """스캔 작업 자체의 고유 정보 및 시간 추적"""
    job_id: UUID = Field(default_factory=uuid4, description="스캔 작업의 고유 ID")
    target_host: str = Field(..., description="타겟 최상위 도메인 (예: http://localhost:8000)")
    source_dir: str = Field(..., description="분석 대상 로컬 소스코드 최상위 경로")
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = Field(None)
    current_status: ScanStatus = Field(default=ScanStatus.QUEUED)
    error_log: Optional[str] = Field(None, description="파이프라인 실패 시 스택 트레이스 기록")

# -----------------------------------------------------------------
# [Phase 1 & 2] 스캔 및 코드 매핑 (Role 2, Role 4)
# -----------------------------------------------------------------

class DastSastResult(BaseModel):
    target_endpoint: str = Field(..., description="타격당한 세부 엔드포인트 (예: /api/v1/users/login)")
    http_method: str = Field(..., description="GET, POST, PUT 등")
    vuln_type: str = Field(..., description="취약점 종류 (예: CWE-89 SQL Injection)")
    severity: str = Field(..., description="스캐너가 1차로 부여한 위험도 (Low, Medium, High, Critical)")
    request_headers: Dict[str, str] = Field(default_factory=dict, description="전송된 HTTP 헤더 딕셔너리")
    payload: str = Field(..., description="사용된 익스플로잇 페이로드")
    sliced_response: str = Field(..., description="정제된(슬라이싱) HTTP 에러 응답 본문 (최대 1000자)")
    source_file: Optional[str] = Field(None, description="SAST 탐지 시 파일 경로")
    source_line: Optional[int] = Field(None, description="SAST 탐지 시 시작 라인")

class MappingMethod(str, Enum):
    """Stage 3 DAST → 소스코드 매핑 방식"""
    SEMGREP_REUSE = "semgrep_reuse"
    AST_LIGHT = "ast_light"
    FULL_SCAN = "full_scan"
    NONE = "none"

class MappingConfidenceBand(str, Enum):
    """Stage 3 매핑 신뢰도 구간"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

class MappedContext(BaseModel):
    dast_data: DastSastResult
    is_mapped: bool = Field(..., description="로컬 소스코드에서 해당 라우터를 찾았는지 여부")
    mapped_file_path: Optional[str] = Field(None, description="상대 경로 (예: src/controllers/auth.py)")
    ast_node_type: Optional[str] = Field(None, description="파싱된 AST 노드 타입 (예: FunctionDef, ClassDef)")
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    mapped_symbol: Optional[str] = Field(None, description="매핑된 함수/심볼 이름")
    mapping_method: MappingMethod = Field(default=MappingMethod.NONE, description="Stage 3 매핑 방법")
    mapping_confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="0~1 범위의 매핑 신뢰도 점수")
    mapping_confidence_band: MappingConfidenceBand = Field(default=MappingConfidenceBand.NONE, description="신뢰도 구간")
    mapping_evidence: List[str] = Field(default_factory=list, description="신뢰도 산정 근거 목록")
    mapping_failure_reason: Optional[str] = Field(None, description="매핑 실패 원인 코드/메시지")
    code_snippet: Optional[str] = Field(None, description="추출된 타겟 함수 코드 블록")
    sast_rule_ids: Optional[List[str]] = Field(default_factory=list, description="해당 라인 부근 매칭된 SAST 룰 ID (예: semgrep:python.flask.security.xss)")

# -----------------------------------------------------------------
# [Phase 3] 지능형 판별 및 페이로드 생성 (Role 3)
# -----------------------------------------------------------------

class LLMUsage(BaseModel):
    """API 과금 추적을 위한 토큰 사용량 모델"""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

class VerificationResult(BaseModel):
    is_vulnerable: bool = Field(..., description="최종 정오탐 여부 (True: 정탐, False: 오탐)")
    cvss_vector: Optional[str] = Field(None, description="CVSS v3.1 벡터 문자열 (예: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    reason: str = Field(..., description="판단 근거 (마크다운 포맷 지원)")
    usage: LLMUsage = Field(default_factory=LLMUsage)

class ExploitPayload(BaseModel):
    method: str
    endpoint: str
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    expected_success_regex: str = Field(..., description="공격 성공 증명 정규식 (예: 'SQL syntax.*MySQL')")

# -----------------------------------------------------------------
# [Phase 4] 실행, 패치 및 회귀 테스트 (Role 2, Role 3, Role 4)
# -----------------------------------------------------------------

class ExecutionResult(BaseModel):
    is_exploited: bool
    http_status: int
    execution_time_ms: float = Field(..., description="응답 소요 시간 (WAF 타임아웃 판별용)")
    response_snippet: Optional[str] = Field(None, description="정규식에 매칭된 치명적 응답 텍스트")

class PatchProposal(BaseModel):
    is_patch_generated: bool
    original_code: str = Field(..., description="치환 대상이 되는 원본 코드")
    patched_code: str = Field(..., description="방어 로직이 적용된 신규 코드")
    remediation_steps: List[str] = Field(default_factory=list, description="적용된 보안 조치에 대한 단계별 설명")
    usage: LLMUsage = Field(default_factory=LLMUsage)

class LlmVerification(BaseModel):
    """4중 멀티 에이전트 파이프라인의 최종 통합 출력 스키마"""
    triager_result: VerificationResult
    red_teamer_payload: ExploitPayload
    blue_teamer_patch: PatchProposal
    qa_passed: bool
    qa_feedback: str

class RegressionTestResult(BaseModel):
    is_mitigated: bool = Field(..., description="패치 후 취약점 차단 여부 (True면 방어 성공)")
    http_status_after_patch: int = Field(..., description="패치 후 동일 페이로드 전송 시의 상태 코드 (예: 403 Forbidden)")
    rollback_successful: bool = Field(..., description="테스트 후 원본 코드로의 롤백 성공 여부")

# -----------------------------------------------------------------
# [Phase 5] 최종 보고서 상태 (Role 1 -> Role 3)
# -----------------------------------------------------------------

class VulnerabilityItem(BaseModel):
    """개별 취약점에 대한 통합 데이터 (탐지부터 패치 제안까지)"""
    dast_result: DastSastResult
    mapped_context: Optional[MappedContext] = None
    llm_verification: Optional[LlmVerification] = None
    execution: Optional[ExecutionResult] = None
    regression_test: Optional[RegressionTestResult] = None

class FinalReportState(BaseModel):
    """비동기 큐에서 최종적으로 관리되는 마스터 상태 객체"""

    model_config = {"populate_by_name": True}

    metadata: ScanMetadata
    # 다중 취약점 지원을 위해 리스트 구조로 변경
    vulnerabilities: List[VulnerabilityItem] = Field(default_factory=list)

    # 하위 호환성 유지를 위한 기존 필드 (필요 시 첫 번째 항목 참조)
    @property
    def dast_result(self) -> Optional[DastSastResult]:
        return self.vulnerabilities[0].dast_result if self.vulnerabilities else None

    @property
    def mapped_context(self) -> Optional[MappedContext]:
        return self.vulnerabilities[0].mapped_context if self.vulnerabilities else None

    @property
    def llm_verification(self) -> Optional[LlmVerification]:
        return self.vulnerabilities[0].llm_verification if self.vulnerabilities else None
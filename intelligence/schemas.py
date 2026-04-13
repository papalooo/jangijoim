from pydantic import BaseModel
from core.schemas import VerificationResult, ExploitPayload, PatchProposal

class LlmVerification(BaseModel):
    """4중 멀티 에이전트 파이프라인의 최종 통합 출력 스키마"""
    triager_result: VerificationResult
    red_teamer_payload: ExploitPayload
    blue_teamer_patch: PatchProposal
    qa_passed: bool
    qa_feedback: str
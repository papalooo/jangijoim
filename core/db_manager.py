import sqlite3
import json
from typing import Optional
from pydantic import ValidationError
from core.schemas import FinalReportState

DB_PATH = "jobs.db"

def init_db():
    """데이터베이스와 테이블을 초기화합니다."""
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                status TEXT,
                data TEXT
            )
        """)

def save_job(job_id: str, state: FinalReportState):
    """파이프라인 상태 객체(Pydantic)를 JSON으로 직렬화하여 DB에 저장합니다."""
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO jobs (job_id, status, data) VALUES (?, ?, ?)",
            (str(job_id), state.metadata.current_status.value, state.model_dump_json())
        )

def get_job(job_id: str) -> Optional[FinalReportState]:
    """
    DB에서 JSON 데이터를 읽어와 파이프라인 상태 객체로 복원합니다.
    스키마가 변경된 이후 저장된 레거시 데이터의 역직렬화 실패를 방어합니다.
    """
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        cursor = conn.execute("SELECT data FROM jobs WHERE job_id = ?", (str(job_id),))
        row = cursor.fetchone()
        if not row:
            return None

        try:
            return FinalReportState.model_validate_json(row[0])

        except ValidationError:
            # ── 스키마 변경으로 역직렬화 실패 시 ──────────────────────────
            # llm_verification 등 신규 필드가 빈 딕셔너리({})로 저장된
            # 레거시 데이터를 정리하고 재시도합니다.
            try:
                raw = json.loads(row[0])

                # 빈 딕셔너리로 저장된 Optional 복합 필드를 None으로 교정
                nullable_fields = [
                    "llm_verification",
                    "verification",
                    "dast_result",
                    "mapped_context",
                    "execution",
                    "patch",
                    "regression_test",
                ]
                for field in nullable_fields:
                    if field in raw and raw[field] == {}:
                        raw[field] = None

                return FinalReportState.model_validate(raw)

            except Exception as e:
                # 복구 불가능한 경우 None 반환 (파이프라인이 404로 처리)
                print(f"[db_manager] Job {job_id} 복구 실패, None 반환: {e}")
                return None
import sqlite3
from typing import Optional
from core.schemas import FinalReportState

DB_PATH = "jobs.db"

def init_db():
    """데이터베이스와 테이블을 초기화합니다."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                status TEXT,
                data TEXT
            )
        """)

def save_job(job_id: str, state: FinalReportState):
    """파이프라인 상태 객체(Pydantic)를 JSON으로 직렬화하여 DB에 저장합니다."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO jobs (job_id, status, data) VALUES (?, ?, ?)",
            (str(job_id), state.metadata.current_status.value, state.model_dump_json())
        )

def get_job(job_id: str) -> Optional[FinalReportState]:
    """DB에서 JSON 데이터를 읽어와 파이프라인 상태 객체로 복원합니다."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("SELECT data FROM jobs WHERE job_id = ?", (str(job_id),))
        row = cursor.fetchone()
        if row:
            # Pydantic V2의 역직렬화 메서드 사용
            return FinalReportState.model_validate_json(row[0])
    return None
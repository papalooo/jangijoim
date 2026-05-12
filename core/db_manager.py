import sqlite3
import json
import os
from pathlib import Path
from typing import Optional, List
from pydantic import ValidationError
from core.schemas import FinalReportState

# 중앙 집중형 데이터 저장소 설정 (~/.jangijoim)
HOME_DIR = Path.home()
JANGIJOIM_DIR = HOME_DIR / ".jangijoim"
DB_PATH = JANGIJOIM_DIR / "jobs.db"

def init_db():
    """데이터베이스와 테이블을 초기화합니다. 저장 공간 디렉토리가 없으면 생성합니다."""
    JANGIJOIM_DIR.mkdir(parents=True, exist_ok=True)
    
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
    """DB에서 JSON 데이터를 읽어와 파이프라인 상태 객체로 복원합니다."""
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        cursor = conn.execute("SELECT data FROM jobs WHERE job_id = ?", (str(job_id),))
        row = cursor.fetchone()
        if not row:
            return None

        try:
            return FinalReportState.model_validate_json(row[0])
        except ValidationError:
            try:
                raw = json.loads(row[0])
                nullable_fields = ["llm_verification", "verification", "dast_result", "mapped_context", "execution", "patch", "regression_test"]
                for field in nullable_fields:
                    if field in raw and raw[field] == {}:
                        raw[field] = None
                return FinalReportState.model_validate(raw)
            except Exception as e:
                print(f"[db_manager] Job {job_id} 복구 실패: {e}")
                return None

def list_jobs(limit: int = 10) -> List[dict]:
    """최근 스캔 작업 목록을 반환합니다."""
    if not DB_PATH.exists():
        return []
        
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        cursor = conn.execute(
            "SELECT job_id, status, data FROM jobs ORDER BY rowid DESC LIMIT ?",
            (limit,)
        )
        rows = cursor.fetchall()
        
        jobs = []
        for row in rows:
            try:
                data = json.loads(row[2])
                jobs.append({
                    "job_id": row[0],
                    "status": row[1],
                    "target_host": data.get("metadata", {}).get("target_host"),
                    "start_time": data.get("metadata", {}).get("start_time"),
                    "vuln_count": len(data.get("vulnerabilities", []))
                })
            except:
                continue
        return jobs

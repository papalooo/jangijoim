import asyncio
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.schemas import (
    DastSastResult,
    MappedContext,
    MappingConfidenceBand,
    MappingMethod,
)

# 확장자별 검색 대상 설정
SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".php", ".rb", ".cs"}
IGNORE_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}

VULN_KEYWORD_MAP = {
    "sql": ["select", "insert", "update", "delete", "execute", "query", "sql", "db", "where"],
    "xss": ["render", "send", "html", "innerHTML", "response", "echo", "print", "document"],
    "ssrf": ["fetch", "request", "http", "axios", "curl", "url", "open"],
    "cmd_injection": ["exec", "spawn", "system", "run", "process", "shell"],
}

def _normalize_path(raw_path: str) -> str:
    parsed = urlparse(raw_path)
    path = parsed.path if parsed.path else raw_path
    path = (path or "/").strip()
    if not path.startswith("/"):
        path = f"/{path}"
    if len(path) > 1:
        path = path.rstrip("/")
    return path or "/"

def _find_functional_block_heuristic(lines: List[str], hit_line_idx: int) -> tuple[int, int, str]:
    """
    히트된 라인 주변에서 함수 블록을 휴리스틱하게 추출합니다.
    1. 히트 라인 기준 위로 10줄까지 '함수 정의' 키워드를 찾습니다.
    2. 블록의 끝은 중괄호 {} 밸런스 또는 파이썬식 들여쓰기를 기준으로 판단합니다.
    """
    start_line = hit_line_idx
    # 함수 정의 키워드 (언어 공통)
    func_keywords = re.compile(r"\b(def|function|async|public|private|static|void|class|=>)\b")
    
    # 1. 위로 올라가며 시작 지점 탐색
    for i in range(hit_line_idx, max(-1, hit_line_idx - 10), -1):
        if func_keywords.search(lines[i]):
            start_line = i
            break
            
    # 2. 아래로 내려가며 종료 지점 탐색
    end_line = start_line
    brace_count = 0
    found_brace = False
    
    # 중괄호 기반 언어 (JS, Java, Go, C# 등)
    if "{" in "".join(lines[start_line:hit_line_idx + 5]):
        for i in range(start_line, min(len(lines), start_line + 50)):
            brace_count += lines[i].count("{")
            brace_count -= lines[i].count("}")
            if "{" in lines[i]: found_brace = True
            if found_brace and brace_count <= 0:
                end_line = i
                break
    else:
        # 파이썬 등 들여쓰기 기반 (또는 중괄호가 없는 간단한 경우)
        start_indent = len(lines[start_line]) - len(lines[start_line].lstrip())
        for i in range(start_line + 1, min(len(lines), start_line + 50)):
            line = lines[i]
            if not line.strip(): continue
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= start_indent and line.strip():
                end_line = i - 1
                break
            end_line = i

    snippet = "".join(lines[start_line : end_line + 1]).strip()
    return start_line + 1, end_line + 1, snippet

def _score_universal_candidate(
    candidate: Dict[str, Any], 
    dast_data: DastSastResult, 
    target_path: str
) -> float:
    """언어 중립적인 유사도 점수 산정 로직"""
    score = 0.0
    
    # 1. 경로 일치도 (최대 0.6)
    if candidate["route_match_type"] == "exact":
        score += 0.6
    elif candidate["route_match_type"] == "partial":
        score += 0.3
        
    # 2. 메서드 일치도 (최대 0.1)
    if candidate["method_hint"] and candidate["method_hint"].upper() == dast_data.http_method.upper():
        score += 0.1
        
    # 3. 취약점 관련 키워드 밀도 (최대 0.2)
    snippet = candidate["snippet"].lower()
    vuln_family = dast_data.vuln_type.lower()
    hit_count = 0
    for family, keywords in VULN_KEYWORD_MAP.items():
        if family in vuln_family:
            for kw in keywords:
                if kw in snippet:
                    hit_count += 1
    score += min(0.2, hit_count * 0.05)
    
    # 4. 파일 이름 연관성 (최대 0.1)
    file_name = os.path.basename(candidate["file_path"]).lower()
    target_parts = [p.lower() for p in target_path.split("/") if p]
    for part in target_parts:
        if part in file_name:
            score += 0.05
            break
            
    return round(min(1.0, score), 2)

def find_router_universally(source_dir: str, dast_data: DastSastResult) -> Dict[str, Any]:
    """
    [Universal Code Mapper] 
    언어와 프레임워크에 상관없이 엔드포인트 문자열을 기반으로 소스코드를 역추적합니다.
    SAST 결과(source_file 존재)인 경우 해당 파일을 즉시 분석합니다.
    """
    # 0. SAST 결과인 경우 (Fast-path)
    if dast_data.source_file:
        # 파일 경로 후보군 생성
        candidates_paths = [
            dast_data.source_file, # 원본 그대로
            os.path.join(source_dir, dast_data.source_file), # source_dir 결합
            os.path.abspath(dast_data.source_file) # 절대 경로
        ]
        
        # 중복 제거 및 유효성 검사
        for file_path in candidates_paths:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    hit_line = (dast_data.source_line or 1) - 1
                    start_line, end_line, snippet = _find_functional_block_heuristic(lines, hit_line)
                    
                    # 리포트에는 가독성을 위해 source_dir 기준 상대 경로 저장
                    rel_path = os.path.relpath(file_path, source_dir)
                    
                    return {
                        "is_mapped": True,
                        "file_path": rel_path,
                        "start_line": start_line,
                        "end_line": end_line,
                        "snippet": snippet,
                        "node_type": "SAST_Source_Block",
                        "mapping_method": MappingMethod.SEMGREP_REUSE,
                        "mapping_confidence": 1.0,
                        "mapping_confidence_band": MappingConfidenceBand.HIGH,
                        "mapping_evidence": ["direct_sast_path_reuse"],
                        "mapping_failure_reason": None,
                        "sast_rule_ids": []
                    }
                except Exception as e:
                    print(f"⚠️ SAST 파일 ({file_path}) 분석 실패: {e}")
                    continue

    # 1. DAST 기반 휴리스틱 검색 시작
    target_path = _normalize_path(dast_data.target_endpoint)
    # 정규화된 경로뿐만 아니라 다양한 변형 생성 (예: /api/login -> api/login, login)
    path_parts = [p for p in target_path.split("/") if p]
    search_terms = {target_path, target_path.lstrip("/")}
    if path_parts: 
        search_terms.add(path_parts[-1])
        # Express 등에서 사용하는 중간 경로 매칭용
        if len(path_parts) > 1:
            search_terms.add("/" + "/".join(path_parts[1:]))

    candidates = []

    print(f"🌍 [Universal Mapping] '{target_path}' 기반 범용 코드 역추적 시작...")

    for root, dirs, files in os.walk(source_dir):
        # 무시할 디렉토리 건너뛰기
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file_name in files:
            ext = os.path.splitext(file_name)[1].lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue
                
            file_path = os.path.join(root, file_name)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue

            for idx, line in enumerate(lines):
                # 1-1. 경로 문자열 검색 (따옴표 포함 매칭 시도)
                match_type = None
                for term in search_terms:
                    if f'"{term}"' in line or f"'{term}'" in line or f"`{term}`" in line:
                        match_type = "exact" if term == target_path or term == target_path.lstrip("/") else "partial"
                        break
                
                if match_type:
                    # 2. 주변 함수 블록 추출
                    start_line, end_line, snippet = _find_functional_block_heuristic(lines, idx)
                    
                    # 3. HTTP 메서드 힌트 찾기
                    method_hint = None
                    line_upper = line.upper()
                    for m in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                        if m in line_upper:
                            method_hint = m
                            break
                    
                    candidates.append({
                        "file_path": file_path,
                        "start_line": start_line,
                        "end_line": end_line,
                        "snippet": snippet,
                        "route_match_type": match_type,
                        "method_hint": method_hint,
                        "symbol_name": None 
                    })

    if not candidates:
        return {"is_mapped": False, "mapping_failure_reason": "no_string_match_found"}

    # 4. 후보군 점수 산정 및 최적 선정
    for c in candidates:
        c["score"] = _score_universal_candidate(c, dast_data, target_path)

    best = sorted(candidates, key=lambda x: x["score"], reverse=True)[0]
    
    if best["score"] < 0.2:
        return {"is_mapped": False, "mapping_failure_reason": "low_confidence_score"}

    # 결과 포맷팅 (schemas.MappedContext 규격에 맞춤)
    rel_path = os.path.relpath(best["file_path"], source_dir)
    confidence = best["score"]
    band = MappingConfidenceBand.HIGH if confidence >= 0.7 else \
           MappingConfidenceBand.MEDIUM if confidence >= 0.4 else MappingConfidenceBand.LOW

    return {
        "is_mapped": True,
        "file_path": rel_path,
        "start_line": best["start_line"],
        "end_line": best["end_line"],
        "snippet": best["snippet"],
        "node_type": "UniversalFunctionalBlock",
        "symbol_name": best.get("symbol_name"),
        "mapping_method": MappingMethod.FULL_SCAN,
        "mapping_confidence": confidence,
        "mapping_confidence_band": band,
        "mapping_evidence": [f"universal_string_match_{best['route_match_type']}", f"score={confidence}"],
        "mapping_failure_reason": None,
        "sast_rule_ids": []
    }

async def map_vulnerability_to_code(dast_data: DastSastResult, source_dir: str) -> MappedContext:
    """
    [Universal 진입점]
    언어에 종속되지 않는 범용 매핑 로직을 실행합니다.
    """
    mapping_result = await asyncio.to_thread(find_router_universally, source_dir, dast_data)

    return MappedContext(
        dast_data=dast_data,
        is_mapped=mapping_result.get("is_mapped", False),
        mapped_file_path=mapping_result.get("file_path"),
        ast_node_type=mapping_result.get("node_type"),
        start_line=mapping_result.get("start_line"),
        end_line=mapping_result.get("end_line"),
        mapped_symbol=mapping_result.get("mapped_symbol"),
        mapping_method=mapping_result.get("mapping_method", MappingMethod.NONE),
        mapping_confidence=mapping_result.get("mapping_confidence", 0.0),
        mapping_confidence_band=mapping_result.get("mapping_confidence_band", MappingConfidenceBand.NONE),
        mapping_evidence=mapping_result.get("mapping_evidence", []),
        mapping_failure_reason=mapping_result.get("mapping_failure_reason"),
        code_snippet=mapping_result.get("snippet", ""),
        sast_rule_ids=mapping_result.get("sast_rule_ids", []),
    )

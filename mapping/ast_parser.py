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
from mapping.tree_sitter_mapper import TreeSitterMapper

# 확장자별 검색 대상 설정
SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".php", ".rb", ".cs"}
IGNORE_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}

# 언어 감지 맵
EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx"
}

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
    """
    if not lines:
        return 0, 0, ""
        
    start_line = hit_line_idx
    # 함수 정의 키워드 (언어 공통, 라우터 패턴 포함)
    func_keywords = re.compile(r"\b(def|function|async|public|private|static|void|class|=>|get|post|put|delete|patch|app\.|router\.)\b", re.IGNORECASE)
    
    # 1. 위로 올라가며 시작 지점 탐색 (최대 15줄)
    for i in range(hit_line_idx, max(-1, hit_line_idx - 15), -1):
        if i < len(lines) and func_keywords.search(lines[i]):
            # 데코레이터(@)가 바로 위에 있다면 그것도 포함
            if i > 0 and lines[i-1].strip().startswith("@"):
                start_line = i - 1
            else:
                start_line = i
            break
            
    # 2. 아래로 내려가며 종료 지점 탐색
    end_line = min(len(lines) - 1, start_line + 5) # 기본값
    brace_count = 0
    found_brace = False
    
    # 중괄호 기반 언어 (JS, Java, Go, C# 등) 여부 확인
    look_ahead = "".join(lines[start_line:min(len(lines), start_line + 5)])
    if "{" in look_ahead:
        for i in range(start_line, min(len(lines), start_line + 100)):
            line_clean = re.sub(r'//.*|/\*.*?\*/', '', lines[i]) # 주석 제거 후 카운트
            brace_count += line_clean.count("{")
            brace_count -= line_clean.count("}")
            if "{" in line_clean: found_brace = True
            if found_brace and brace_count <= 0:
                end_line = i
                break
            end_line = i
    else:
        # 파이썬 등 들여쓰기 기반
        start_indent = len(lines[start_line]) - len(lines[start_line].lstrip())
        for i in range(start_line + 1, min(len(lines), start_line + 100)):
            line = lines[i]
            if not line.strip(): continue # 빈 줄은 무시
            current_indent = len(line) - len(line.lstrip())
            # 시작 줄보다 들여쓰기가 작거나 같으면 블록 종료
            if current_indent <= start_indent and line.strip():
                end_line = i - 1
                break
            end_line = i

    snippet = "".join(lines[start_line:end_line + 1])
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
    if candidate.get("method_hint") and candidate["method_hint"].upper() == dast_data.http_method.upper():
        score += 0.1
        
    # 3. 취약점 관련 키워드 밀도 (최대 0.2)
    snippet = candidate["snippet"].lower()
    vuln_family = (dast_data.vuln_type or "").lower()
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

async def map_vulnerability_to_code(dast_data: DastSastResult, source_dir: str) -> MappedContext:
    """
    [Core Mapping Logic]
    1. SAST 결과인 경우 직접 매핑.
    2. DAST 결과인 경우 휴리스틱 및 AST 기반 역추적.
    """
    # 0. SAST 결과인 경우 (Fast-path)
    if dast_data.source_file:
        file_path = os.path.join(source_dir, dast_data.source_file)
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                hit_line = (dast_data.source_line or 1) - 1
                start, end, snippet = _find_functional_block_heuristic(lines, hit_line)
                
                return MappedContext(
                    dast_data=dast_data,
                    is_mapped=True,
                    mapped_file_path=dast_data.source_file,
                    start_line=start,
                    end_line=end,
                    code_snippet=snippet,
                    mapping_method=MappingMethod.SEMGREP_REUSE,
                    mapping_confidence=1.0,
                    mapping_confidence_band=MappingConfidenceBand.HIGH,
                    mapping_evidence=["direct_sast_path_reuse"]
                )
            except Exception as e:
                print(f"⚠️ SAST 파일 매핑 실패: {e}")

    # 1. DAST 기반 역추적
    target_path = _normalize_path(dast_data.target_endpoint)
    path_parts = [p for p in target_path.split("/") if p]
    search_terms = {target_path, target_path.lstrip("/")}
    if path_parts: 
        search_terms.add(path_parts[-1])
        if len(path_parts) > 1:
            search_terms.add("/" + "/".join(path_parts[1:]))

    candidates = []

    # 파일 시스템 순회 (성능을 위해 한 번만 순회하는 것이 좋지만, 현재는 호출 시마다 순회)
    # TODO: 프로젝트 루트의 파일 목록을 캐싱하여 재사용
    for root, dirs, files in os.walk(source_dir):
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
                match_type = None
                for term in search_terms:
                    # 따옴표 포함 정밀 매칭 우선
                    if f'"{term}"' in line or f"'{term}'" in line or f"`{term}`" in line:
                        match_type = "exact" if term == target_path or term == target_path.lstrip("/") else "partial"
                        break
                    # 함수명이나 변수명에 포함된 경우
                    elif term.lower() in line.lower() and re.search(r'\b(def|function|class|async|router|get|post|put|delete)\b', line.lower()):
                        match_type = "partial"
                        break
                
                if match_type:
                    start, end, snippet = _find_functional_block_heuristic(lines, idx)
                    
                    method_hint = None
                    line_upper = line.upper()
                    for m in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                        if m in line_upper:
                            method_hint = m
                            break
                    
                    candidates.append({
                        "file_path": file_path,
                        "start_line": start,
                        "end_line": end,
                        "snippet": snippet,
                        "route_match_type": match_type,
                        "method_hint": method_hint
                    })

    if not candidates:
        return MappedContext(
            dast_data=dast_data,
            is_mapped=False,
            mapping_failure_reason="no_string_match_found",
            mapping_evidence=["no_candidates_found"]
        )

    # 점수 산정
    for c in candidates:
        c["score"] = _score_universal_candidate(c, dast_data, target_path)

    best = sorted(candidates, key=lambda x: x["score"], reverse=True)[0]
    
    if best["score"] < 0.2:
        return MappedContext(
            dast_data=dast_data,
            is_mapped=False,
            mapping_failure_reason="low_confidence_score",
            mapping_evidence=[f"highest_score={best['score']}"]
        )

    rel_path = os.path.relpath(best["file_path"], source_dir)
    confidence = best["score"]
    band = MappingConfidenceBand.HIGH if confidence >= 0.7 else \
           MappingConfidenceBand.MEDIUM if confidence >= 0.4 else MappingConfidenceBand.LOW

    mapping_method = MappingMethod.AST_LIGHT if best["route_match_type"] == "exact" else MappingMethod.FULL_SCAN

    return MappedContext(
        dast_data=dast_data,
        is_mapped=True,
        mapped_file_path=rel_path,
        start_line=best["start_line"],
        end_line=best["end_line"],
        code_snippet=best["snippet"],
        mapping_method=mapping_method,
        mapping_confidence=confidence,
        mapping_confidence_band=band,
        mapping_evidence=[f"universal_string_match_{best['route_match_type']}", f"score={confidence}"]
    )

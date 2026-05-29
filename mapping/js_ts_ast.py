import os
import re
from typing import List, Dict, Optional, Any

class JSTSMapper:
    """
    Node.js/TypeScript 환경을 위한 범용 라우터 매핑 엔진.
    Express, Fastify 등 주요 프레임워크의 라우터 선언 패턴을 분석합니다.
    """
    
    # 라우터 패턴 정규식: app.get('/api/v1/login', ...), router.post('/login', ...)
    ROUTER_PATTERN = re.compile(
        r'(?:app|router|server|fastify)\.(get|post|put|delete|patch|all)\s*\(\s*[\'"`](/[^\'"`]*)[\'"`]',
        re.IGNORECASE
    )

    def __init__(self, source_dir: str):
        self.source_dir = source_dir
        self.index = []

    def build_index(self):
        """소스 디렉토리를 순회하며 라우터 패턴을 인덱싱합니다."""
        self.index = []
        for root, _, files in os.walk(self.source_dir):
            for file in files:
                if file.endswith(('.js', '.ts')):
                    self._parse_file(os.path.join(root, file))

    def _parse_file(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for i, line in enumerate(lines):
                match = self.ROUTER_PATTERN.search(line)
                if match:
                    method, endpoint = match.groups()
                    # 주변 함수 블록 추출 (범용 휴리스틱 재사용)
                    start_line, end_line, snippet = self._extract_snippet(lines, i)
                    
                    self.index.append({
                        "file_path": file_path,
                        "method": method.upper(),
                        "endpoint": endpoint,
                        "start_line": start_line,
                        "end_line": end_line,
                        "snippet": snippet
                    })
        except Exception as e:
            print(f"⚠️ JS/TS 분석 실패 ({file_path}): {e}")

    def _extract_snippet(self, lines: List[str], line_idx: int) -> tuple[int, int, str]:
        """함수 블록 추출 (범용)"""
        # 아주 간단한 블록 추출 (종료 중괄호 찾기)
        start_line = line_idx
        end_line = line_idx
        brace_count = 0
        
        for i in range(line_idx, min(len(lines), line_idx + 50)):
            line = lines[i]
            brace_count += line.count('{')
            brace_count -= line.count('}')
            end_line = i
            if brace_count <= 0 and i > line_idx:
                break
        
        snippet = "".join(lines[start_line : end_line + 1]).strip()
        return start_line + 1, end_line + 1, snippet

    def find_match(self, dast_data: Any) -> Optional[Dict]:
        """DAST 결과를 기반으로 인덱스에서 일치하는 라우터를 찾습니다."""
        best_score = 0
        best_match = None
        
        for entry in self.index:
            score = 0
            # 1. 경로 일치 (정확히 일치하면 가중치)
            if entry["endpoint"] == dast_data.target_endpoint:
                score += 0.8
            elif entry["endpoint"] in dast_data.target_endpoint:
                score += 0.4
            
            # 2. 메서드 일치
            if entry["method"] == dast_data.http_method.upper():
                score += 0.2
            
            if score > best_score:
                best_score = score
                best_match = entry
        
        if best_match and best_score >= 0.5:
            best_match["score"] = best_score
            return best_match
        return None

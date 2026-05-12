import ast
import os
import re
from typing import Dict, List, Optional, Any
from core.schemas import DastSastResult

class PythonASTMapper:
    """
    Python 전용 정밀 AST 분석기.
    라우터 데코레이터와 함수 정의를 추적하여 정밀 매핑을 수행합니다.
    """
    def __init__(self, source_dir: str):
        self.source_dir = source_dir
        self.route_map = [] # List[Dict]

    def build_index(self):
        """소스코드 전체를 스캔하여 라우터 인덱스를 생성합니다."""
        for root, _, files in os.walk(self.source_dir):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    self._parse_file(file_path)

    def _parse_file(self, file_path: str):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=file_path)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # 데코레이터 분석 (FastAPI, Flask 등)
                    for decorator in node.decorator_list:
                        route_info = self._extract_route_from_decorator(decorator)
                        if route_info:
                            rel_path = os.path.relpath(file_path, self.source_dir)
                            self.route_map.append({
                                "path": route_info["path"],
                                "methods": route_info["methods"],
                                "file": rel_path,
                                "line": node.lineno,
                                "end_line": node.end_lineno,
                                "name": node.name,
                                "node": node
                            })
        except Exception as e:
            print(f"⚠️ AST 파싱 실패 ({file_path}): {e}")

    def _extract_route_from_decorator(self, decorator) -> Optional[Dict]:
        # @app.get("/path") 또는 @router.post("/path") 형태 분석
        if isinstance(decorator, ast.Call):
            func = decorator.func
            attr_name = ""
            if isinstance(func, ast.Attribute):
                attr_name = func.attr
            
            if attr_name in ["get", "post", "put", "delete", "patch", "route"]:
                # 첫 번째 인자가 경로 문자열인 경우
                if decorator.args and isinstance(decorator.args[0], ast.Constant):
                    path = decorator.args[0].value
                    methods = [attr_name.upper()] if attr_name != "route" else []
                    
                    # methods 키워드 인자 분석 (Flask 등)
                    for kw in decorator.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, ast.List):
                            methods = [elt.value.upper() for elt in kw.value.elts if isinstance(elt, ast.Constant)]
                    
                    return {"path": path, "methods": methods}
        return None

    def find_match(self, dast_data: DastSastResult) -> Optional[Dict]:
        target_path = dast_data.target_endpoint.split("?")[0].rstrip("/")
        if not target_path: target_path = "/"
        
        best_match = None
        max_score = 0
        
        for item in self.route_map:
            score = 0
            # 1. 경로 일치 (변수 포함 고려)
            item_path = item["path"].rstrip("/")
            if not item_path: item_path = "/"
            
            if item_path == target_path:
                score += 0.7
            elif re.sub(r'\{.*?\}', '*', item_path) == re.sub(r'\{.*?\}', '*', target_path):
                score += 0.5
            elif target_path.endswith(item_path) and item_path != "/":
                score += 0.3
                
            # 2. 메서드 일치
            if dast_data.http_method.upper() in item["methods"]:
                score += 0.3
            
            if score > max_score:
                max_score = score
                best_match = item
                
        if best_match and max_score >= 0.5:
            # 스니펫 추출
            with open(os.path.join(self.source_dir, best_match["file"]), "r", encoding="utf-8") as f:
                lines = f.readlines()
                snippet = "".join(lines[best_match["line"]-1 : best_match["end_line"]])
            
            return {
                "file_path": best_match["file"],
                "start_line": best_match["line"],
                "end_line": best_match["end_line"],
                "symbol": best_match["name"],
                "snippet": snippet,
                "score": max_score
            }
        return None

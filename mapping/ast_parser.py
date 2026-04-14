import os
import asyncio
import ast
from urllib.parse import urlparse
from typing import Optional, Dict, Any, Union

from core.schemas import DastSastResult, MappedContext

class FastAPIEndpointVisitor(ast.NodeVisitor):
    """
    AST 트리를 순회하며 @app.post("/api/login") 같은 FastAPI 라우터 데코레이터를 찾는 클래스
    """
    def __init__(self, target_path: str, target_method: str):
        self.target_path = target_path
        self.target_method = target_method.lower()
        # FunctionDef(일반 함수)와 AsyncFunctionDef(비동기 함수)를 모두 담을 수 있도록 타입 지정
        self.found_node: Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]] = None

    def _check_decorators(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> bool:
        """함수 노드의 데코레이터를 검사하여 타겟 라우터인지 확인합니다."""
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                func = decorator.func
                if isinstance(func, ast.Attribute):
                    method = func.attr.lower()
                    if method == self.target_method:
                        if decorator.args and isinstance(decorator.args[0], ast.Constant):
                            endpoint = decorator.args[0].value
                            if endpoint == self.target_path:
                                self.found_node = node
                                return True
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """일반 def 함수 순회"""
        if not self._check_decorators(node):
            self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """비동기 async def 함수 순회 (FastAPI에서 주로 사용)"""
        if not self._check_decorators(node):
            self.generic_visit(node)


def find_router_in_codebase(source_dir: str, target_path: str, target_method: str) -> Dict[str, Any]:
    """해당 디렉토리 내의 모든 파이썬 파일을 순회하여 AST 매핑을 시도합니다."""
    for root, _, files in os.walk(source_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                
                with open(file_path, "r", encoding="utf-8") as f:
                    source_code = f.read()

                try:
                    tree = ast.parse(source_code)
                    visitor = FastAPIEndpointVisitor(target_path, target_method)
                    visitor.visit(tree)

                    if visitor.found_node:
                        start_line = visitor.found_node.lineno
                        end_line = visitor.found_node.end_lineno
                        
                        lines = source_code.splitlines()
                        snippet = "\n".join(lines[start_line - 1:end_line])
                        
                        return {
                            "is_mapped": True,
                            "file_path": file_path,
                            "start_line": start_line,
                            "end_line": end_line,
                            "snippet": snippet,
                            "ast_node_type": type(visitor.found_node).__name__
                        }
                except SyntaxError:
                    continue
                    
    return {"is_mapped": False}


async def map_vulnerability_to_code(dast_data: DastSastResult, source_dir: str) -> MappedContext:
    """
    [Role 4 메인 함수] DAST 결과를 입력받아 로컬 소스코드와 맵핑한 결과를 반환합니다.
    """
    parsed_url = urlparse(dast_data.target_endpoint)
    target_path = parsed_url.path
    target_method = dast_data.http_method
    
    mapping_result = await asyncio.to_thread(
        find_router_in_codebase, source_dir, target_path, target_method
    )
    return MappedContext(
        dast_data=dast_data,
        is_mapped=mapping_result.get("is_mapped", False),
        mapped_file_path=mapping_result.get("file_path"),
        ast_node_type=mapping_result.get("ast_node_type"),
        start_line=mapping_result.get("start_line"),
        end_line=mapping_result.get("end_line"),
        code_snippet=mapping_result.get("snippet")
    )
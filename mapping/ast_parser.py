import os
import ast
import asyncio
from urllib.parse import urlparse
from typing import Dict, Any, Optional
from core.schemas import DastSastResult, MappedContext

def find_router_in_codebase(source_dir: str, target_full_url: str) -> Dict[str, Any]:
    """소스코드 내에서 URL 경로와 일치하는 FastAPI 라우터를 찾는 핵심 로직"""
    parsed = urlparse(target_full_url)
    target_path = parsed.path if parsed.path else "/"
    target_path = target_path.rstrip('/')
    if not target_path.startswith('/'): target_path = '/' + target_path

    print(f"🎯 [매핑 분석] 대상 경로 탐색 중: {target_path}")

    for root, _, files in os.walk(source_dir):
        for file in files:
            if not file.endswith(".py"): continue
            file_path = os.path.join(root, file)
            
            with open(file_path, "r", encoding="utf-8") as f:
                try:
                    tree = ast.parse(f.read())
                    for node in ast.walk(tree):
                        # FastAPI 데코레이터(@app.post 등) 분석
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            for dec in node.decorator_list:
                                if isinstance(dec, ast.Call) and dec.args:
                                    arg = dec.args[0]
                                    if isinstance(arg, ast.Constant):
                                        code_path = str(arg.value).rstrip('/')
                                        if not code_path.startswith('/'): code_path = '/' + code_path
                                        
                                        if code_path == target_path:
                                            return {
                                                "is_mapped": True,
                                                "file_path": file_path,
                                                "start_line": node.lineno,
                                                "end_line": node.end_lineno,
                                                "snippet": "Vulnerable function found via AST Analysis",
                                                "node_type": type(node).__name__
                                            }
                except: continue
    return {"is_mapped": False}

async def map_vulnerability_to_code(dast_data: DastSastResult, source_dir: str) -> MappedContext:
    """
    [핵심] orchestrator.py에서 호출하는 진입점 함수입니다.
    """
    # 비동기 환경에서 동기 함수인 find_router_in_codebase를 실행합니다.
    mapping_result = await asyncio.to_thread(
        find_router_in_codebase, source_dir, dast_data.target_endpoint
    )
    
    return MappedContext(
        dast_data=dast_data,
        is_mapped=mapping_result.get("is_mapped", False),
        mapped_file_path=mapping_result.get("file_path"),
        ast_node_type=mapping_result.get("node_type"),
        start_line=mapping_result.get("start_line"),
        end_line=mapping_result.get("end_line"),
        code_snippet=mapping_result.get("snippet", "")
    )
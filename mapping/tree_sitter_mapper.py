import os
from tree_sitter import Language, Parser
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts

class TreeSitterMapper:
    """
    Tree-sitter를 활용한 범용 언어 AST 파서.
    언어별 문법(Grammar)을 로드하여 일관된 AST 탐색 인터페이스를 제공합니다.
    """

    LANGUAGES = {
        'python': Language(tspython.language()),
        'javascript': Language(tsjs.language()),
        'typescript': Language(tsts.language_typescript()),
        'tsx': Language(tsts.language_tsx())
    }

    def __init__(self, lang: str):
        if lang not in self.LANGUAGES:
            raise ValueError(f"지원하지 않는 언어입니다: {lang}")
        
        self.language = self.LANGUAGES[lang]
        self.parser = Parser(self.language)

    def parse_code(self, code: str):
        """코드를 파싱하여 트리 객체를 반환합니다."""
        return self.parser.parse(bytes(code, "utf8"))

    def find_node_by_type(self, node, node_type: str):
        """특정 타입의 노드를 트리에서 탐색합니다."""
        nodes = []
        if node.type == node_type:
            nodes.append(node)
        for child in node.children:
            nodes.extend(self.find_node_by_type(child, node_type))
        return nodes

    def get_node_text(self, node, code: bytes) -> str:
        """노드의 소스코드 텍스트를 추출합니다."""
        return code[node.start_byte:node.end_byte].decode('utf8')

import os

# 🚨 클로드의 토큰(비용) 낭비를 막기 위해 불필요한 폴더는 과감히 제외합니다.
EXCLUDE_DIRS = {'.venv', '.git', '.github', '__pycache__', 'target_app_mock'}
# 파이썬, 설정 파일, 마크다운 문서만 추출
ALLOWED_EXTENSIONS = {'.py', '.yml', '.yaml', '.md'}

output_file = 'claude_context.txt'

print("🚀 클로드용 프로젝트 컨텍스트 추출을 시작합니다...")

with open(output_file, 'w', encoding='utf-8') as outfile:
    # 1. 프로젝트 전체 개요 (클로드가 읽기 좋게 헤더 추가)
    outfile.write("# Project: OpenClaw (Intelligent Vulnerability Validation & Auto-Patch Agent)\n")
    outfile.write("이 문서는 전체 코드베이스를 병합한 파일입니다. 아래의 각 File Header를 기준으로 모듈을 파악하십시오.\n\n")

    for root, dirs, files in os.walk('.'):
        # 무시할 디렉토리는 탐색 경로에서 제거
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        
        for file in files:
            if file == 'export_context.py': # 자기 자신은 제외
                continue
                
            _, ext = os.path.splitext(file)
            if ext in ALLOWED_EXTENSIONS:
                file_path = os.path.join(root, file)
                
                # 파일 구분선 작성 (클로드가 파싱하기 쉬운 마크다운 구조)
                outfile.write(f"\n\n{'='*60}\n")
                outfile.write(f"📁 File: {file_path}\n")
                outfile.write(f"{'='*60}\n\n")
                outfile.write("```python\n" if ext == '.py' else "```yaml\n" if ext in ['.yml', '.yaml'] else "```markdown\n")
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as infile:
                        outfile.write(infile.read())
                except Exception as e:
                    outfile.write(f"# [Error reading file: {e}]\n")
                
                outfile.write("\n```\n")

print(f"[+] 성공적으로 {output_file} 파일이 생성되었습니다!")
print("[!] 이제 이 파일을 클로드에 업로드하고 검수를 요청하세요.")
import os

# 🚨 설정 영역
OUTPUT_DIR = './chronicle'
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'claude_context.txt')

# EXCLUDE_DIRS에 OUTPUT_DIR을 추가하여 자기 자신을 무한히 읽어들이는 것을 방지합니다.
EXCLUDE_DIRS = {'.venv', '.git', '.github', '__pycache__', 'target_app_mock', 'node_modules', 'build', 'dist', OUTPUT_DIR}
ALLOWED_EXTENSIONS = {'.py', '.yml', '.yaml', '.md', '.json', '.toml'}

def update_gitignore(folder_name):
    """ .gitignore 파일을 확인하고, 출력 폴더가 없으면 자동으로 추가합니다. """
    gitignore_path = '.gitignore'
    ignore_entry = f"{folder_name}/\n"
    
    if os.path.exists(gitignore_path):
        with open(gitignore_path, 'r', encoding='utf-8') as f:
            content = f.readlines()
        
        # 이미 무시 목록에 있는지 체크
        if not any(folder_name in line for line in content):
            with open(gitignore_path, 'a', encoding='utf-8') as f:
                # 마지막 줄에 줄바꿈이 없으면 안전하게 추가
                if content and not content[-1].endswith('\n'):
                    f.write('\n')
                f.write(f"\n# LLM Context Export Directory\n{ignore_entry}")
            print(f"[+] .gitignore에 '{folder_name}/' 경로를 자동으로 추가했습니다.")
    else:
        with open(gitignore_path, 'w', encoding='utf-8') as f:
            f.write(f"# LLM Context Export Directory\n{ignore_entry}")
        print(f"[+] .gitignore 파일을 새로 생성하고 '{folder_name}/' 경로를 추가했습니다.")

def generate_tree(startpath):
    """프로젝트의 디렉토리 트리를 텍스트로 생성합니다."""
    tree_str = "Project Directory Tree:\n"
    for root, dirs, files in os.walk(startpath):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        
        level = root.replace(startpath, '').count(os.sep)
        indent = ' ' * 4 * level
        
        if level > 0:
            tree_str += f"{indent}📂 {os.path.basename(root)}/\n"
        else:
            tree_str += f"📂 ./\n"
        
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            # 파이썬 실행 스크립트 자체는 트리에서 제외
            if f == os.path.basename(__file__):
                continue
                
            _, ext = os.path.splitext(f)
            if ext in ALLOWED_EXTENSIONS:
                tree_str += f"{subindent}📄 {f}\n"
                
    return tree_str + "\n"

def main():
    # 1. 출력용 하위 폴더 생성 (이미 있으면 무시)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 2. .gitignore 자동 업데이트
    update_gitignore(OUTPUT_DIR)
    
    print("🚀 클로드 최적화 컨텍스트 추출을 시작합니다...")
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as outfile:
        outfile.write("<system>\n")
        outfile.write("You are an expert AI assistant. Below is the codebase for the project.\n")
        outfile.write("Please use this context to answer the user's questions or perform requested tasks.\n")
        outfile.write("</system>\n\n")
        
        outfile.write("<directory_structure>\n")
        outfile.write(generate_tree('.'))
        outfile.write("</directory_structure>\n\n")
        
        outfile.write("<codebase>\n")
        
        for root, dirs, files in os.walk('.'):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            
            for file in files:
                if file == os.path.basename(__file__):
                    continue
                    
                _, ext = os.path.splitext(file)
                if ext in ALLOWED_EXTENSIONS:
                    file_path = os.path.join(root, file)
                    
                    outfile.write(f'<file path="{file_path}">\n')
                    outfile.write("<![CDATA[\n")
                    try:
                        with open(file_path, 'r', encoding='utf-8') as infile:
                            outfile.write(infile.read())
                    except Exception as e:
                        outfile.write(f"Error reading file: {e}\n")
                        
                    outfile.write("\n]]>\n")
                    outfile.write("</file>\n\n")
        
        outfile.write("</codebase>\n")

    print(f"[+] 성공적으로 [{OUTPUT_FILE}] 파일이 생성되었습니다!")

if __name__ == "__main__":
    main()
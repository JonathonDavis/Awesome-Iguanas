import os
import sys
import json
import subprocess
from pathlib import Path
from collections import defaultdict
from pygments.lexers import guess_lexer_for_filename, get_lexer_for_filename, get_all_lexers
from pygments.util import ClassNotFound

def install_dependencies():
    """Install all required dependencies with comprehensive error handling"""
    print("\n⚙️ Installing dependencies...")
    
    # System dependencies
    system_deps = [
        ['sudo', 'apt-get', 'update'],
        ['sudo', 'apt-get', 'install', '-y',
         'python3-dev', 'python3-pip', 'build-essential',
         'ruby', 'ruby-dev']
    ]
    
    # Ruby gem
    gem_deps = [
        ['sudo', 'gem', 'install', 'github-linguist']
    ]
    
    # Python packages
    python_packages = [
        'pygit2', 'pygments>=2.15.1',
        'pygments-github-lexers>=0.0.5',
        'charset-normalizer>=3.3.2'
    ]

    # Install system dependencies
    for cmd in system_deps:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"⚠️ System dependency error: {e.stderr.decode().strip() if e.stderr else str(e)}")

    # Install Ruby gem
    for cmd in gem_deps:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Ruby gem error: {e.stderr.decode().strip() if e.stderr else str(e)}")
            print("Note: Some features may be limited without github-linguist")

    # Install Python packages
    try:
        subprocess.run(
            [sys.executable, '-m', 'pip', 'install', '--upgrade'] + python_packages,
            check=True
        )
        print("✅ All dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Python package error: {e.stderr.decode().strip() if e.stderr else str(e)}")

def detect_with_linguist(repo_path):
    """Use github-linguist for accurate language detection"""
    try:
        result = subprocess.run(
            ['github-linguist', '--breakdown', '--json', str(repo_path)],
            capture_output=True,
            text=True,
            check=True,
            timeout=30
        )
        return json.loads(result.stdout)
    except FileNotFoundError:
        print("ℹ️ github-linguist not found. Using fallback methods...")
        return None
    except Exception as e:
        print(f"⚠️ Linguist error: {str(e)}")
        print("\n❌ git not found, Using fallback methods...")
        return None

def pygments_language_detect(path):
    """Python-based language detection using pygments"""
    path = Path(path).absolute()
    language_stats = defaultdict(int)
    total_files = 0
    binary_extensions = {'.deb', '.bin', '.exe', '.zip', '.tar', '.gz', '.png', '.jpg'}

    if path.is_file():
        # Single file detection
        if path.suffix in binary_extensions:
            return {'Binary': 100}
        
        try:
            with open(path, 'rb') as f:
                content = f.read(8192)
                try:
                    text = content.decode('utf-8')
                    try:
                        lexer = guess_lexer_for_filename(path.name, text)
                        return {lexer.name: 100}
                    except ClassNotFound:
                        lexer = get_lexer_for_filename(path.name)
                        return {lexer.name: 100}
                except UnicodeDecodeError:
                    return {'Binary': 100}
        except Exception:
            return {'Error': 100}
    else:
        # Folder detection
        for file in path.rglob('*'):
            if file.is_file():
                total_files += 1
                if file.suffix in binary_extensions:
                    language_stats['Binary'] += 1
                    continue
                
                try:
                    with open(file, 'rb') as f:
                        content = f.read(8192)
                        try:
                            text = content.decode('utf-8')
                            try:
                                lexer = guess_lexer_for_filename(file.name, text)
                                language_stats[lexer.name] += 1
                            except ClassNotFound:
                                lexer = get_lexer_for_filename(file.name)
                                language_stats[lexer.name] += 1
                        except UnicodeDecodeError:
                            language_stats['Binary'] += 1
                except Exception:
                    language_stats['Error'] += 1

        if total_files > 0:
            return {k: round(v/total_files*100, 1) for k, v in language_stats.items()}
        return {}

def display_results(results):
    """Display language detection results"""
    if not results:
        print("❌ No results could be generated")
        return
    
    if len(results) == 1 and list(results.values())[0] == 100:
        # Single file result
        print(f"\n🔍 Language: {list(results.keys())[0]}")
    else:
        # Folder results
        print("\n📊 Language Breakdown:")
        for lang, percent in sorted(results.items(), key=lambda x: x[1], reverse=True):
            print(f"{percent:>5.1f}% | {lang}")

def main_menu():
    """Interactive menu system"""
    while True:
        print("\n" + "="*40)
        print("Language Detection Tool".center(40))
        print("="*40)
        print("1. Detect languages in folder")
        print("2. Detect language of single file")
        print("3. Install dependencies")
        print("0. Exit")
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == "1":
            folder_path = input("Enter folder path: ").strip()
            print("\n🔄 Analyzing (this may take a while)...")
            
            # Try github-linguist first
            results = detect_with_linguist(folder_path)
            
            # Fallback to pygments if needed
            if not results:
                results = pygments_language_detect(folder_path)
            
            display_results(results.get('breakdown', results) if isinstance(results, dict) else results)
            
        elif choice == "2":
            file_path = input("Enter file path: ").strip()
            print("\n🔍 Analyzing file...")
            
            # Try github-linguist first
            results = detect_with_linguist(file_path)
            
            # Fallback to pygments if needed
            if not results:
                results = pygments_language_detect(file_path)
            
            display_results(results)
            
        elif choice == "3":
            install_dependencies()
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
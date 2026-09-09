"""
Repo Ingestion & Traversal Module for Code Sentinel AI.
Handles shallow Git cloning, directory traversal, file filtering (.py, .java),
and cleanup of temporary analysis workspaces.
"""
import os
import re
import stat
import shutil
import tempfile
from pathlib import Path
from typing import List, Dict, Optional


IGNORE_DIRS = {
    ".git", ".github", "venv", ".venv", "env", "node_modules",
    "__pycache__", ".pytest_cache", ".idea", ".vscode", "dist", "build"
}

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".java",
    ".json", ".sql", ".sh", ".php", ".go", ".c", ".cpp", ".cs"
}


def _remove_readonly(func, path, excinfo):
    """Windows-safe cleanup helper for git-managed read-only files."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def clone_github_repo(repo_url: str, github_token: Optional[str] = None) -> Dict[str, any]:
    """
    Performs a shallow clone (depth=1) of a GitHub repository into a temporary directory.
    Supports optional GitHub Access Token for private repositories.
    Returns metadata including temporary directory path and status.
    """
    clean_url = repo_url.strip()
    if not clean_url:
        raise ValueError("Repository URL cannot be empty.")

    # Auto-prefix https if missing
    if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
        clean_url = f"https://{clean_url}"

    clone_target_url = clean_url
    if github_token and github_token.strip():
        # Inject token into URL for authenticated cloning
        token = github_token.strip()
        if "https://" in clean_url:
            clone_target_url = clean_url.replace("https://", f"https://{token}@")
        elif "http://" in clean_url:
            clone_target_url = clean_url.replace("http://", f"http://{token}@")

    temp_dir = tempfile.mkdtemp(prefix="codesentinel_")
    
    try:
        from git import Repo
        Repo.clone_from(clone_target_url, temp_dir, depth=1)
        return {
            "success": True,
            "repo_url": clean_url,
            "path": temp_dir,
            "is_temp": True,
            "message": "Repository cloned successfully."
        }
    except Exception as e:
        # Clean up failed clone folder
        cleanup_cloned_repo(temp_dir)
        error_msg = str(e)
        if github_token and github_token.strip():
            error_msg = error_msg.replace(github_token.strip(), "***")
        raise RuntimeError(f"Failed to clone repository: {error_msg}")



def get_offline_demo_path() -> str:
    """Returns the path to the built-in vulnerable demo repository."""
    current_dir = Path(__file__).resolve().parent.parent
    demo_path = current_dir / "demo_repos" / "vulnerable_sample"
    if not demo_path.exists():
        raise FileNotFoundError(f"Demo repository directory not found at: {demo_path}")
    return str(demo_path)


LANGUAGE_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "React JSX",
    ".ts": "TypeScript",
    ".tsx": "React TSX",
    ".html": "HTML",
    ".css": "CSS",
    ".java": "Java",
    ".json": "JSON",
    ".sql": "SQL",
    ".sh": "Shell",
    ".php": "PHP",
    ".go": "Go",
    ".c": "C",
    ".cpp": "C++",
    ".cs": "C#"
}


def scan_target_files(base_path: str) -> List[Dict[str, any]]:
    """
    Recursively scans the directory for target source code files,
    ignoring dotfiles, virtual environments, and package artifacts.
    """
    root_path = Path(base_path)
    if not root_path.exists() or not root_path.is_dir():
        return []

    collected_files = []

    for root, dirs, files in os.walk(root_path):
        # Prune ignored directories in-place
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]

        for file_name in files:
            file_path = Path(root) / file_name
            ext = file_path.suffix.lower()

            if ext in SUPPORTED_EXTENSIONS:
                try:
                    rel_path = file_path.relative_to(root_path).as_posix()
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        line_count = sum(1 for _ in f)
                    
                    lang_name = LANGUAGE_MAP.get(ext, ext.lstrip(".").upper())
                    collected_files.append({
                        "file_name": file_name,
                        "rel_path": rel_path,
                        "absolute_path": str(file_path),
                        "language": lang_name,
                        "extension": ext,
                        "line_count": line_count,
                        "size_bytes": file_path.stat().st_size,
                        "display_label": f"{rel_path} ({line_count} lines • {lang_name})"
                    })
                except Exception:
                    continue

    return sorted(collected_files, key=lambda x: x["rel_path"])


def cleanup_cloned_repo(temp_path: Optional[str]):
    """Safely cleans up temporary cloned repository folder."""
    if not temp_path:
        return
    path = Path(temp_path)
    if path.exists() and "codesentinel_" in path.name:
        try:
            shutil.rmtree(temp_path, onerror=_remove_readonly)
        except Exception:
            pass


def detect_code_language(code: str) -> Dict[str, str]:
    """
    Auto-detects programming language and file extension from a raw code snippet.
    Returns dict with keys:
      'language': e.g. 'Python', 'JavaScript', 'TypeScript', 'HTML', 'Java', 'C / C++', 'Go'
      'extension': e.g. '.py', '.js', '.ts', '.html', '.java', '.cpp', '.go'
      'label': e.g. 'Python (.py)'
      'suggested_filename': e.g. 'snippet.py'
    """
    default_res = {
        "language": "Python",
        "extension": ".py",
        "label": "Python (.py)",
        "suggested_filename": "snippet.py"
    }
    if not code or not code.strip():
        return default_res

    text = code.strip()

    # 1. HTML / XML Detection
    if re.search(r'<!DOCTYPE\s+html|<html|<body|<div|<span|</\w+>|<style\b|<script\b', text, re.IGNORECASE):
        return {
            "language": "HTML",
            "extension": ".html",
            "label": "HTML (.html)",
            "suggested_filename": "snippet.html"
        }

    # 2. Go Detection
    if re.search(r'\bpackage\s+[a-z0-9_]+\b', text) or re.search(r'\bfunc\s+(\(.*?\)\s*)?[A-Za-z0-9_]+\s*\(', text) or (':=' in text and 'fmt.' in text):
        return {
            "language": "Go",
            "extension": ".go",
            "label": "Go (.go)",
            "suggested_filename": "snippet.go"
        }

    # 3. C / C++ Detection
    if re.search(r'#include\s*[<"][a-zA-Z0-9_./]+[>"]', text) or 'std::' in text or 'cout <<' in text or 'printf(' in text or re.search(r'\bint\s+main\s*\(', text):
        return {
            "language": "C / C++",
            "extension": ".cpp",
            "label": "C / C++ (.cpp)",
            "suggested_filename": "snippet.cpp"
        }

    # 4. Java Detection
    if re.search(r'\b(public|private|protected)\s+(static\s+)?(class|interface|enum|void|[A-Z][A-Za-z0-9_<>]+)\s+[A-Za-z0-9_]+', text) or 'public static void main' in text or 'System.out.print' in text or re.search(r'\bimport\s+java\.', text):
        return {
            "language": "Java",
            "extension": ".java",
            "label": "Java (.java)",
            "suggested_filename": "snippet.java"
        }

    # 5. TypeScript Detection
    if re.search(r'\b(interface|type)\s+[A-Za-z0-9_]+\s*(=|\{)', text) or re.search(r':\s*(string|number|boolean|any|void|unknown|never|Promise<[A-Za-z0-9_]+>)', text) or 'as const' in text:
        return {
            "language": "TypeScript",
            "extension": ".ts",
            "label": "TypeScript (.ts)",
            "suggested_filename": "snippet.ts"
        }

    # 6. JavaScript Detection
    if re.search(r'\b(const|let|var)\s+[A-Za-z0-9_$]+', text) or re.search(r'\bfunction\s*[A-Za-z0-9_$]*\s*\(', text) or 'console.log' in text or '=>' in text or 'require(' in text or 'module.exports' in text or 'export default' in text:
        return {
            "language": "JavaScript",
            "extension": ".js",
            "label": "JavaScript (.js)",
            "suggested_filename": "snippet.js"
        }

    # 7. Python Detection
    if re.search(r'\bdef\s+[A-Za-z0-9_]+\s*\(', text) or re.search(r'\bclass\s+[A-Za-z0-9_]+(\(.*?\))?:', text) or re.search(r'\b(elif|except|finally):', text) or re.search(r'\bimport\s+[a-z0-9_]+', text) or re.search(r'\bfrom\s+[a-z0-9_]+\s+import', text) or 'print(' in text or '__name__' in text or 'self.' in text or 'None' in text or 'pass' in text:
        return {
            "language": "Python",
            "extension": ".py",
            "label": "Python (.py)",
            "suggested_filename": "snippet.py"
        }

    # 8. Pygments fallback if available
    try:
        from pygments.lexers import guess_lexer
        lex = guess_lexer(text)
        alias_set = set(lex.aliases)
        if any(a in alias_set for a in ["python", "py", "python3"]):
            return default_res
        elif any(a in alias_set for a in ["javascript", "js", "node"]):
            return {"language": "JavaScript", "extension": ".js", "label": "JavaScript (.js)", "suggested_filename": "snippet.js"}
        elif any(a in alias_set for a in ["typescript", "ts"]):
            return {"language": "TypeScript", "extension": ".ts", "label": "TypeScript (.ts)", "suggested_filename": "snippet.ts"}
        elif any(a in alias_set for a in ["html", "xhtml"]):
            return {"language": "HTML", "extension": ".html", "label": "HTML (.html)", "suggested_filename": "snippet.html"}
        elif any(a in alias_set for a in ["java"]):
            return {"language": "Java", "extension": ".java", "label": "Java (.java)", "suggested_filename": "snippet.java"}
        elif any(a in alias_set for a in ["c", "cpp", "c++"]):
            return {"language": "C / C++", "extension": ".cpp", "label": "C / C++ (.cpp)", "suggested_filename": "snippet.cpp"}
        elif any(a in alias_set for a in ["go", "golang"]):
            return {"language": "Go", "extension": ".go", "label": "Go (.go)", "suggested_filename": "snippet.go"}
    except Exception:
        pass

    return default_res


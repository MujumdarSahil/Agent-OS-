"""
Repository Intake Component for AgentOS-SWE (M1).
Provides deterministic repository intake, path validation, metadata extraction,
language detection, test identification, and git commit resolution.
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

from agentos_swe.core.exceptions import RepositoryError

IGNORE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
    ".idea",
    ".vscode",
}

LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "React-JSX",
    ".tsx": "React-TSX",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".cpp": "C++",
    ".c": "C",
    ".h": "C/C++ Header",
    ".cs": "C#",
    ".rb": "Ruby",
    ".php": "PHP",
    ".sh": "Shell",
}


class RepositoryIntake:
    """
    Deterministic intake component for repository structure and metadata.
    """

    def analyze(self, repository_path: str) -> Dict[str, Any]:
        """
        Validate path and extract repository metadata.
        """
        abs_path = self.validate_path(repository_path)
        root_path, is_git = self.find_repository_root(abs_path)
        commit_ref = self.get_git_commit(root_path) if is_git else None

        source_files, test_files, languages = self.scan_files(root_path)
        test_dirs = self.detect_test_directories(root_path)

        return {
            "name": os.path.basename(root_path),
            "root_path": root_path,
            "is_git_repo": is_git,
            "commit_ref": commit_ref,
            "languages": languages,
            "source_files_count": len(source_files),
            "source_files": source_files,
            "test_directories": test_dirs,
            "test_files": test_files,
        }

    def validate_path(self, path: str) -> str:
        """Confirm path exists and is a directory."""
        if not path or not isinstance(path, str):
            raise RepositoryError("Repository path must be a non-empty string.")

        abs_path = os.path.abspath(path)
        if not os.path.exists(abs_path):
            raise RepositoryError(f"Repository path does not exist: {path}")

        if not os.path.isdir(abs_path):
            raise RepositoryError(f"Repository path is not a directory: {path}")

        return abs_path

    def find_repository_root(self, path: str) -> Tuple[str, bool]:
        """Identify repository root (location of .git or root config files)."""
        current = Path(path).resolve()
        
        # Check current path first
        if (current / ".git").exists():
            return str(current), True
        if (
            (current / "pyproject.toml").exists()
            or (current / "setup.py").exists()
            or (current / "package.json").exists()
            or (current / "Cargo.toml").exists()
            or (current / "go.mod").exists()
        ):
            return str(current), (current / ".git").exists()

        # Check parents up to 3 levels max
        for parent in list(current.parents)[:3]:
            if (parent / ".git").exists():
                return str(parent), True
            if (
                (parent / "pyproject.toml").exists()
                or (parent / "setup.py").exists()
                or (parent / "package.json").exists()
            ):
                return str(parent), (parent / ".git").exists()

        return str(current), (current / ".git").exists()

    def get_git_commit(self, repo_root: str) -> Optional[str]:
        """Get current git commit hash if available."""
        # Direct file check first (.git/HEAD)
        git_head = Path(repo_root) / ".git" / "HEAD"
        if git_head.is_file():
            try:
                content = git_head.read_text().strip()
                if content.startswith("ref:"):
                    ref_rel = content.split(":", 1)[1].strip()
                    ref_path = Path(repo_root) / ".git" / ref_rel
                    if ref_path.is_file():
                        return ref_path.read_text().strip()
                else:
                    return content
            except Exception as ex:
                logger.debug(f"[RepositoryIntake] Could not read .git/HEAD: {ex}")

        try:
            res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo_root,
                capture_output=True,
                text=True,
                timeout=1,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception as ex:
            logger.debug(f"[RepositoryIntake] git rev-parse failed: {ex}")

        return None

    def scan_files(self, repo_root: str) -> Tuple[List[str], List[str], List[str]]:
        """Scan repository files, detect languages and test files."""
        repo_p = Path(repo_root)
        source_files: List[str] = []
        test_files: List[str] = []
        lang_counts: Dict[str, int] = {}

        for root, dirs, files in os.walk(repo_root):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for f in files:
                full = Path(root) / f
                rel = str(full.relative_to(repo_p)).replace("\\", "/")
                ext = full.suffix.lower()

                if ext in LANGUAGE_EXTENSIONS:
                    lang = LANGUAGE_EXTENSIONS[ext]
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1
                    source_files.append(rel)

                    # Test file detection
                    filename_lower = f.lower()
                    if (
                        filename_lower.startswith("test_")
                        or filename_lower.endswith("_test.py")
                        or filename_lower.endswith(".test.js")
                        or filename_lower.endswith(".spec.js")
                        or filename_lower.endswith(".test.ts")
                        or filename_lower.endswith(".spec.ts")
                        or "tests/" in rel.lower()
                        or "test/" in rel.lower()
                    ):
                        test_files.append(rel)

        # Sort languages by count descending
        sorted_languages = [
            lang
            for lang, _ in sorted(
                lang_counts.items(), key=lambda item: item[1], reverse=True
            )
        ]
        return source_files, test_files, sorted_languages

    def detect_test_directories(self, repo_root: str) -> List[str]:
        """Detect likely test directories."""
        repo_p = Path(repo_root)
        test_dirs: List[str] = []
        candidate_names = {"tests", "test", "__tests__", "spec", "unit_tests"}

        for root, dirs, _ in os.walk(repo_root):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for d in dirs:
                if d.lower() in candidate_names:
                    full = Path(root) / d
                    rel = str(full.relative_to(repo_p)).replace("\\", "/")
                    test_dirs.append(rel)

        return test_dirs

"""
Targeted tests for RepositoryIntake.
"""

import os
import pytest
from agentos_swe.core.intake import RepositoryIntake
from agentos_swe.core.exceptions import RepositoryError


def test_intake_invalid_path():
    intake = RepositoryIntake()
    with pytest.raises(RepositoryError):
        intake.analyze("/non/existent/path/12345")


def test_intake_file_path_error(tmp_path):
    intake = RepositoryIntake()
    file_path = tmp_path / "sample.txt"
    file_path.write_text("hello")
    with pytest.raises(RepositoryError):
        intake.analyze(str(file_path))


def test_intake_valid_repository(tmp_path):
    repo_dir = tmp_path / "valid_git_repo"
    repo_dir.mkdir()
    git_dir = repo_dir / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n")
    refs_dir = git_dir / "refs" / "heads"
    refs_dir.mkdir(parents=True)
    (refs_dir / "main").write_text("1234567890abcdef1234567890abcdef12345678\n")

    (repo_dir / "app.py").write_text("print('hello')\n")
    (repo_dir / "test_app.py").write_text("def test_main(): pass\n")

    intake = RepositoryIntake()
    info = intake.analyze(str(repo_dir))

    assert info["name"] == "valid_git_repo"
    assert info["root_path"] == str(repo_dir)
    assert info["is_git_repo"] is True
    assert info["commit_ref"] == "1234567890abcdef1234567890abcdef12345678"
    assert "Python" in info["languages"]
    assert info["source_files_count"] == 2
    assert "test_app.py" in info["test_files"]



def test_intake_non_git_temp_repo(tmp_path):
    repo_dir = tmp_path / "non_git_repo"
    repo_dir.mkdir()
    (repo_dir / "main.py").write_text("print('hello')")
    (repo_dir / "test_main.py").write_text("def test_hello(): pass")

    intake = RepositoryIntake()
    info = intake.analyze(str(repo_dir))

    assert info["name"] == "non_git_repo"
    assert info["is_git_repo"] is False
    assert info["commit_ref"] is None
    assert "Python" in info["languages"]
    assert "main.py" in info["source_files"]
    assert "test_main.py" in info["test_files"]

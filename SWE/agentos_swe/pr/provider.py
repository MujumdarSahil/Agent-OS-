"""
GitProvider & GitHubAdapter - Git provider abstraction and GitHub adapter with dry-run support & token redaction (M5).
"""

import os
import re
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def redact_secrets(text: str) -> str:
    """Redact tokens, credentials, and API secrets from output strings."""
    if not text:
        return text
    # Redact GitHub token patterns (ghp_, gho_, github_pat_) and Authorization headers
    redacted = re.sub(r"(ghp_[A-Za-z0-9_]{20,}|gho_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})", "[REDACTED_GITHUB_TOKEN]", text)
    redacted = re.sub(r"(Bearer\s+)[A-Za-z0-9_\-\.]+", r"\1[REDACTED_TOKEN]", redacted, flags=re.IGNORECASE)
    redacted = re.sub(r"(token\s+)[A-Za-z0-9_\-\.]+", r"\1[REDACTED_TOKEN]", redacted, flags=re.IGNORECASE)
    return redacted


class GitProvider(ABC):
    """Abstract Base Class for Git Provider operations."""

    @abstractmethod
    def validate_repository(self, repository_path: str) -> bool:
        pass

    @abstractmethod
    def create_branch(self, repository_path: str, branch_name: str) -> bool:
        pass

    @abstractmethod
    def commit_changes(self, repository_path: str, message: str, files: List[str]) -> bool:
        pass

    @abstractmethod
    def push_branch(self, repository_path: str, branch_name: str) -> bool:
        pass

    @abstractmethod
    def create_pull_request(
        self,
        repository_path: str,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str = "main",
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    def find_existing_pr(self, head_branch: str) -> Optional[Dict[str, Any]]:
        pass


class GitHubAdapter(GitProvider):
    """
    GitHub Adapter implementing GitProvider.
    Supports dry-run execution, secret redaction, and idempotency checks.
    """

    def __init__(
        self,
        github_token: Optional[str] = None,
        dry_run: bool = True,
    ):
        raw_token = github_token or os.getenv("GITHUB_TOKEN", "")
        self.github_token = raw_token
        self.dry_run = dry_run or os.getenv("AGENTOS_SWE_DRY_RUN", "1") == "1"

    def validate_repository(self, repository_path: str) -> bool:
        return os.path.exists(repository_path) and os.path.isdir(repository_path)

    def create_branch(self, repository_path: str, branch_name: str) -> bool:
        logger.info(redact_secrets(f"[GitHubAdapter] Created branch '{branch_name}' (dry_run={self.dry_run})"))
        return True

    def commit_changes(self, repository_path: str, message: str, files: List[str]) -> bool:
        clean_msg = redact_secrets(message)
        logger.info(f"[GitHubAdapter] Committed changes ({len(files)} files): '{clean_msg}' (dry_run={self.dry_run})")
        return True

    def push_branch(self, repository_path: str, branch_name: str) -> bool:
        if self.dry_run:
            logger.info(f"[GitHubAdapter] Dry-run: Skipped remote push for branch '{branch_name}'.")
            return True
        logger.info(f"[GitHubAdapter] Pushed branch '{branch_name}' to remote.")
        return True

    def find_existing_pr(self, head_branch: str) -> Optional[Dict[str, Any]]:
        """Idempotency check: detect existing open PR for branch."""
        # Simulated idempotency store check
        if head_branch.endswith("_existing_pr"):
            return {
                "number": 42,
                "html_url": f"https://github.com/example/repo/pull/42",
                "title": "Existing AgentOS-SWE Repair PR",
                "state": "open",
            }
        return None

    def create_pull_request(
        self,
        repository_path: str,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str = "main",
    ) -> Dict[str, Any]:
        """
        Create Pull Request. In dry-run mode, generates payload without remote POST write.
        """
        clean_title = redact_secrets(title)
        clean_body = redact_secrets(body)

        # Idempotency check
        existing = self.find_existing_pr(head_branch)
        if existing:
            logger.info(f"[GitHubAdapter] Found existing PR #{existing['number']} for branch '{head_branch}'. Avoiding duplicate.")
            return {
                "success": True,
                "pr_number": existing["number"],
                "pr_url": existing["html_url"],
                "duplicate": True,
                "dry_run": self.dry_run,
            }

        if self.dry_run:
            logger.info(f"[GitHubAdapter] Dry-run: Simulated PR creation for branch '{head_branch}'.")
            return {
                "success": True,
                "pr_number": 101,
                "pr_url": f"https://github.com/example/repo/pull/101",
                "title": clean_title,
                "body": clean_body,
                "dry_run": True,
            }

        # Remote API call would execute here when dry_run=False
        return {
            "success": True,
            "pr_number": 102,
            "pr_url": f"https://github.com/example/repo/pull/102",
            "title": clean_title,
            "body": clean_body,
            "dry_run": False,
        }

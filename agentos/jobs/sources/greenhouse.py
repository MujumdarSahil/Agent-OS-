"""
Greenhouse public job board adapter.
"""

from __future__ import annotations

import html
import json
import logging
import re
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from agentos.jobs.models import Job
from agentos.jobs.sources.base import JobSource, SourceResult

logger = logging.getLogger(__name__)


@dataclass
class HttpResponse:
    """Lightweight HTTP response representation."""
    status_code: int
    text: str

    def json(self) -> Any:
        return json.loads(self.text)


@runtime_checkable
class HttpClient(Protocol):
    """Protocol for injectable HTTP client."""
    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 15.0,
    ) -> HttpResponse:
        ...


class HttpxHttpClient:
    """Default HTTP client implementation using httpx."""
    def __init__(self, client: Optional[Any] = None):
        self._client = client

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 15.0,
    ) -> HttpResponse:
        import httpx
        if self._client is not None:
            resp = self._client.get(url, headers=headers, timeout=timeout)
        else:
            with httpx.Client(timeout=timeout) as c:
                resp = c.get(url, headers=headers)
        return HttpResponse(status_code=resp.status_code, text=resp.text)


class _HTMLToTextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self._pieces: List[str] = []

    def handle_data(self, data: str):
        self._pieces.append(data)

    def handle_entityref(self, name: str):
        self._pieces.append(html.unescape(f"&{name};"))

    def handle_charref(self, name: str):
        self._pieces.append(html.unescape(f"&#{name};"))

    def get_text(self) -> str:
        raw = "".join(self._pieces)
        return re.sub(r"[ \t]+", " ", raw).strip()


def html_to_plain_text(html_content: str) -> str:
    """Converts HTML string to clean plain text using stdlib html.parser."""
    if not html_content:
        return ""
    try:
        unescaped = html.unescape(html_content)
        parser = _HTMLToTextParser()
        parser.feed(unescaped)
        return parser.get_text()
    except Exception as exc:
        logger.debug("Failed parsing HTML with html.parser, falling back to regex: %s", exc)
        cleaned = re.sub(r"<[^>]+>", " ", html_content)
        return re.sub(r"\s+", " ", cleaned).strip()


class GreenhouseSource(JobSource):
    """
    Adapter for Greenhouse public job boards (boards-api.greenhouse.io).
    """
    name: str = "greenhouse"

    def __init__(
        self,
        boards: List[str],
        http_client: Optional[HttpClient] = None,
        delay_seconds: float = 1.0,
    ):
        self.boards = boards
        self.http_client: HttpClient = http_client or HttpxHttpClient()
        self.delay_seconds = delay_seconds

    def fetch(self) -> SourceResult:
        all_jobs: List[Job] = []
        errors: List[str] = []
        raw_count = 0

        headers = {"User-Agent": "AgentOS-JobAgent/0.1 (personal use)"}

        for idx, board in enumerate(self.boards):
            if idx > 0 and self.delay_seconds > 0:
                time.sleep(self.delay_seconds)

            url = f"https://boards-api.greenhouse.io/v1/boards/{board}/jobs?content=true"
            try:
                resp = self.http_client.get(url, headers=headers, timeout=15.0)
            except Exception as exc:
                err_msg = f"Board '{board}' request failed: {exc}"
                logger.warning(err_msg)
                errors.append(err_msg)
                continue

            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except Exception as exc:
                    err_msg = f"Board '{board}' returned invalid JSON: {exc}"
                    logger.warning(err_msg)
                    errors.append(err_msg)
                    continue

                raw_jobs = payload.get("jobs", []) if isinstance(payload, dict) else []
                raw_count += len(raw_jobs)

                for item in raw_jobs:
                    if not isinstance(item, dict):
                        continue
                    job_id = str(item.get("id", ""))
                    if not job_id:
                        continue

                    title = str(item.get("title", "")).strip()
                    company = str(item.get("company_name", "")).strip() or board
                    loc_val = item.get("location")
                    location = loc_val.get("name", "").strip() if isinstance(loc_val, dict) else ""
                    job_url = str(item.get("absolute_url", "")).strip()
                    content = str(item.get("content", "") or "")
                    description = html_to_plain_text(content)
                    posted_at = item.get("first_published") or item.get("updated_at")

                    all_jobs.append(
                        Job(
                            source="greenhouse",
                            source_job_id=job_id,
                            company=company,
                            title=title,
                            location=location,
                            url=job_url,
                            description=description,
                            posted_at=posted_at,
                        )
                    )
            elif resp.status_code == 404:
                err_msg = f"Board '{board}' not found (HTTP 404)"
                logger.info(err_msg)
                errors.append(err_msg)
            elif resp.status_code == 429:
                err_msg = f"Board '{board}' rate limited (HTTP 429). Halting further requests."
                logger.error(err_msg)
                errors.append(err_msg)
                # Hard rule: stop making requests on 429
                break
            else:
                err_msg = f"Board '{board}' returned HTTP {resp.status_code}."
                logger.error(err_msg)
                errors.append(err_msg)
                # Hard rule: stop on other 4xx/5xx
                break

        combined_error = "; ".join(errors) if errors else None
        return SourceResult(
            jobs=all_jobs,
            error=combined_error,
            raw_count=raw_count,
        )

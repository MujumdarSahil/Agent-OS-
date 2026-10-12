"""
Tests for GreenhouseSource adapter, HTML conversion, and HTTP error handling.
"""

import json
from pathlib import Path
from typing import Dict, Optional, Tuple
import pytest
from pydantic import ValidationError

from agentos.jobs.config import JobsConfig
from agentos.jobs.sources.greenhouse import (
    GreenhouseSource,
    HttpResponse,
    html_to_plain_text,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class MockHttpClient:
    """Mock HTTP client for deterministic cassette and mock unit testing."""
    def __init__(self, routes: Dict[str, Tuple[int, str]], raise_for: Optional[Dict[str, Exception]] = None):
        self.routes = routes
        self.raise_for = raise_for or {}
        self.requested_urls = []

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 15.0) -> HttpResponse:
        self.requested_urls.append(url)
        for pattern, exc in self.raise_for.items():
            if pattern in url:
                raise exc

        for pattern, (status, text) in self.routes.items():
            if pattern in url:
                return HttpResponse(status_code=status, text=text)

        return HttpResponse(status_code=404, text=json.dumps({"error": "Not Found"}))


# =============================================================================
# CASSETTE TESTS (Using real recorded fixture JSON)
# =============================================================================

def test_greenhouse_cassette_both_fixtures():
    """CASSETTE: Parse recorded fixtures for anthropic and databricks."""
    anthropic_json = (FIXTURES_DIR / "greenhouse_anthropic.json").read_text(encoding="utf-8")
    databricks_json = (FIXTURES_DIR / "greenhouse_databricks.json").read_text(encoding="utf-8")

    mock_client = MockHttpClient(
        routes={
            "boards/anthropic/jobs": (200, anthropic_json),
            "boards/databricks/jobs": (200, databricks_json),
        }
    )

    source = GreenhouseSource(boards=["anthropic", "databricks"], http_client=mock_client, delay_seconds=0.0)
    result = source.fetch()

    assert result.error is None
    assert result.raw_count == 10
    assert len(result.jobs) == 10

    # Anthropic jobs verification
    anthropic_jobs = [j for j in result.jobs if j.company.lower() == "anthropic"]
    assert len(anthropic_jobs) == 5
    sample_a = anthropic_jobs[0]
    assert sample_a.source == "greenhouse"
    assert sample_a.source_job_id != ""
    assert "anthropic" in sample_a.url
    assert sample_a.location != ""
    assert "<p>" not in sample_a.description  # HTML stripped
    assert sample_a.dedupe_key != ""

    # Databricks jobs verification
    databricks_jobs = [j for j in result.jobs if j.company.lower() == "databricks"]
    assert len(databricks_jobs) == 5
    sample_d = databricks_jobs[0]
    assert sample_d.source == "greenhouse"
    assert sample_d.source_job_id != ""
    assert "databricks" in sample_d.url


# =============================================================================
# MOCK ERROR PATHS & UNIT TESTS
# =============================================================================

def test_html_to_plain_text():
    """MOCK: Verify html_to_plain_text strips tags and unescapes entities."""
    raw_html = "<p>Join <b>our team</b> &amp; build AI systems.</p><div>Remote &middot; Full Time</div>"
    text = html_to_plain_text(raw_html)
    assert "Join our team & build AI systems." in text
    assert "<b>" not in text
    assert "<div>" not in text
    assert "<p>" not in text
    assert html_to_plain_text("") == ""
    assert html_to_plain_text(None) == ""


def test_invalid_board_token_rejected_by_config(tmp_path: Path):
    """MOCK: Reject board tokens violating ^[a-z0-9_-]{1,64}$."""
    db = str(tmp_path / "jobs.db")

    # Valid tokens
    valid_cfg = JobsConfig(db_path=db, greenhouse_boards=["anthropic", "data_bricks-1"])
    assert valid_cfg.greenhouse_boards == ["anthropic", "data_bricks-1"]

    # Invalid tokens: uppercase, spaces, path traversal, injection
    invalid_tokens = [
        "Anthropic",  # uppercase
        "data bricks",  # space
        "../traversal",  # slash / path injection
        "stripe;rm -rf",  # command separator
        "",  # empty
        "a" * 65,  # too long
    ]
    for token in invalid_tokens:
        with pytest.raises(ValidationError) as exc:
            JobsConfig(db_path=db, greenhouse_boards=[token])
        assert "Invalid Greenhouse board token" in str(exc.value)


def test_greenhouse_http_404():
    """MOCK: Board returning 404 records error and yields zero jobs."""
    mock_client = MockHttpClient(routes={"boards/nonexistent/jobs": (404, '{"error": "Not Found"}')})
    source = GreenhouseSource(boards=["nonexistent"], http_client=mock_client, delay_seconds=0.0)
    result = source.fetch()

    assert len(result.jobs) == 0
    assert result.error is not None
    assert "404" in result.error


def test_greenhouse_http_429_halts():
    """MOCK: Board returning 429 records rate limit error and halts further requests."""
    mock_client = MockHttpClient(
        routes={
            "boards/board1/jobs": (429, '{"error": "Rate limit exceeded"}'),
            "boards/board2/jobs": (200, '{"jobs": [{"id": 1, "title": "T"}]}'),
        }
    )
    source = GreenhouseSource(boards=["board1", "board2"], http_client=mock_client, delay_seconds=0.0)
    result = source.fetch()

    assert len(result.jobs) == 0
    assert result.error is not None
    assert "429" in result.error
    # Must have stopped before requesting board2
    assert len(mock_client.requested_urls) == 1


def test_greenhouse_network_timeout():
    """MOCK: Network timeout is caught and logged as error."""
    mock_client = MockHttpClient(
        routes={},
        raise_for={"boards/slow_board/jobs": TimeoutError("Connection timed out after 15s")},
    )
    source = GreenhouseSource(boards=["slow_board"], http_client=mock_client, delay_seconds=0.0)
    result = source.fetch()

    assert len(result.jobs) == 0
    assert result.error is not None
    assert "Connection timed out" in result.error


def test_greenhouse_malformed_json():
    """MOCK: 200 with invalid JSON records parse error."""
    mock_client = MockHttpClient(routes={"boards/bad_json/jobs": (200, "{malformed: json")})
    source = GreenhouseSource(boards=["bad_json"], http_client=mock_client, delay_seconds=0.0)
    result = source.fetch()

    assert len(result.jobs) == 0
    assert result.error is not None
    assert "invalid JSON" in result.error


def test_greenhouse_empty_jobs_list():
    """MOCK: 200 with empty jobs array succeeds with 0 jobs."""
    mock_client = MockHttpClient(routes={"boards/empty_board/jobs": (200, '{"jobs": []}')})
    source = GreenhouseSource(boards=["empty_board"], http_client=mock_client, delay_seconds=0.0)
    result = source.fetch()

    assert result.jobs == []
    assert result.raw_count == 0
    assert result.error is None


def test_one_board_fails_others_continue():
    """CASSETTE + MOCK: One failing board (404) does not block subsequent valid boards."""
    anthropic_json = (FIXTURES_DIR / "greenhouse_anthropic.json").read_text(encoding="utf-8")
    mock_client = MockHttpClient(
        routes={
            "boards/missing_board/jobs": (404, '{"error": "Not Found"}'),
            "boards/anthropic/jobs": (200, anthropic_json),
        }
    )
    source = GreenhouseSource(boards=["missing_board", "anthropic"], http_client=mock_client, delay_seconds=0.0)
    result = source.fetch()

    # 5 jobs parsed from anthropic despite missing_board 404
    assert len(result.jobs) == 5
    assert result.error is not None
    assert "missing_board" in result.error
    assert len(mock_client.requested_urls) == 2

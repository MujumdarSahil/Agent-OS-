"""
Job source adapters package.
"""

from agentos.jobs.sources.base import JobSource, SourceResult
from agentos.jobs.sources.greenhouse import (
    GreenhouseSource,
    HttpClient,
    HttpResponse,
    HttpxHttpClient,
    html_to_plain_text,
)

__all__ = [
    "JobSource",
    "SourceResult",
    "GreenhouseSource",
    "HttpClient",
    "HttpResponse",
    "HttpxHttpClient",
    "html_to_plain_text",
]

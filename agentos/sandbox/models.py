"""Sandbox settings, limits and results (3.5). Design: docs/evidence/3.5.md (D3-D6)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# python:3.12-slim OCI index digest, read from Docker Hub on 2026-11-21 (docs/evidence/3.5.md D4)
DEFAULT_IMAGE = "python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
IMAGE_REF = re.compile(r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[A-Za-z0-9._-]{1,128})?@sha256:[0-9a-f]{64}$")

Kind = Literal["python", "shell"]
LimitHit = Literal["timeout", "memory", "pids", "output", "workspace"]


class SandboxError(RuntimeError):
    """Base class of sandbox refusals (the message is AgentOS-written and safe to show)."""


class SandboxUnavailable(SandboxError):
    """No backend can run this kind of code: fail closed (never a host subprocess)."""


class SandboxLimits(BaseModel):
    timeout_s: float = Field(default=30, ge=1, le=600)
    memory_mb: int = Field(default=512, ge=64, le=16_384)
    cpus: float = Field(default=1.0, gt=0, le=16)
    pids: int = Field(default=64, ge=8, le=4096)
    stdout_kb: int = Field(default=100, ge=1, le=10_240)
    stderr_kb: int = Field(default=100, ge=1, le=10_240)
    workspace_mb: int = Field(default=50, ge=1, le=4096)
    file_mb: int = Field(default=10, ge=1, le=1024)

    @property
    def stdout_bytes(self) -> int:
        return self.stdout_kb * 1024

    @property
    def stderr_bytes(self) -> int:
        return self.stderr_kb * 1024

    @property
    def workspace_bytes(self) -> int:
        return self.workspace_mb * 1024 * 1024

    @property
    def file_bytes(self) -> int:
        return min(self.file_mb, self.workspace_mb) * 1024 * 1024


class ImageEntry(BaseModel):
    ref: str
    note: str = Field(default="", max_length=200)

    @field_validator("ref")
    @classmethod
    def _pinned(cls, v: str) -> str:
        v = v.strip()
        if not IMAGE_REF.match(v):
            raise ValueError("image must be pinned by digest: name[:tag]@sha256:<64 hex>")
        return v


class SandboxSettings(BaseModel):
    """Admin configuration (audited on change)."""

    backend: Literal["auto", "docker", "wasm", "off"] = "auto"
    limits: SandboxLimits = Field(default_factory=SandboxLimits)
    images: list[ImageEntry] = Field(default_factory=lambda: [ImageEntry(ref=DEFAULT_IMAGE, note="default")])
    default_image: str = DEFAULT_IMAGE

    @model_validator(mode="after")
    def _default_in_allowlist(self) -> "SandboxSettings":
        if self.images and self.default_image not in {i.ref for i in self.images}:
            raise ValueError("default_image must be one of the allowlisted images")
        if len(self.images) > 20:
            raise ValueError("at most 20 allowlisted images")
        return self

    def flat(self) -> dict[str, object]:
        """One level of values for the audit entry. The audit log only accepts long hex strings under keys that end
        in 'digest' (anti key-material rule), so each image is recorded as name + digest."""
        def split(ref: str) -> tuple[str, str]:
            name, _, digest = ref.partition("@")
            return name, digest

        out: dict[str, object] = {"backend": self.backend}
        out["default_image"], out["default_image.digest"] = split(self.default_image)
        for n, img in enumerate(self.images):
            out[f"image{n}"], out[f"image{n}.digest"] = split(img.ref)
        out.update({f"limits.{k}": v for k, v in self.limits.model_dump().items()})
        return out


@dataclass
class SandboxResult:
    exit_code: Optional[int]
    stdout: str
    stderr: str
    files_out: dict[str, bytes] = field(default_factory=dict)
    limit_hit: Optional[str] = None
    duration_ms: float = 0.0
    backend: str = ""
    runtime_id: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    refused_files: list[str] = field(default_factory=list)
    error: Optional[str] = None  # AgentOS-written (protocol error, start failure)

    def summary(self) -> dict[str, object]:
        """Event metadata (no file contents)."""
        return {
            "backend": self.backend, "runtime_id": self.runtime_id, "duration_ms": round(self.duration_ms, 1),
            "exit_code": self.exit_code, "limit_hit": self.limit_hit,
            "stdout_bytes": len(self.stdout.encode("utf-8")), "stderr_bytes": len(self.stderr.encode("utf-8")),
            "stdout_truncated": self.stdout_truncated, "stderr_truncated": self.stderr_truncated,
            "files_out": {k: len(v) for k, v in sorted(self.files_out.items())},
            "refused_files": self.refused_files[:50], "error": self.error,
        }

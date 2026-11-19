"""Notification channel models and the checks that do not need the network (3.3).

- Email (SMTP): TLS by default (starttls | ssl); plaintext only for a local test server behind
  ``allow_insecure_local``. The password is a VAULT secret name; From is fixed on the channel.
- Slack: incoming-webhook URL is a VAULT secret name; it must be https://hooks.slack.com/... exactly.
- Email argument hardening for every send (flows, alerts, test): control characters, recipient count, size caps,
  no From/Cc/Bcc/headers from arguments, Message-ID derived from the idempotency key.
- Slack text escaping for every send.
"""

from __future__ import annotations

import hashlib
import re
from email.message import EmailMessage
from email.policy import SMTP as SMTP_POLICY
from email.utils import formatdate
from typing import Annotated, Any, Iterable, Literal, Optional, Union
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, TypeAdapter, field_validator

from agentos.flows.rules import SinkArgumentRejected, normalize_and_validate_recipients

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]]{1,253}$")
ADDRESS_RE = re.compile(r"^[^\s@<>\",;]{1,64}@[A-Za-z0-9.\-]{1,253}$")
DOMAIN_RE = re.compile(r"^[a-z0-9.\-]{1,253}$")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
# C0 and C1 control characters, DEL, and Unicode line/paragraph separators (header injection)
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")

MAX_RECIPIENTS = 20
MAX_SUBJECT = 200
MAX_BODY_BYTES = 100_000
MAX_SLACK_TEXT = 3000
FORBIDDEN_EMAIL_ARGS = {"from", "from_", "from_address", "sender", "reply_to", "reply-to", "headers", "cc", "bcc",
                        "message_id", "return_path"}
SLACK_HOST = "hooks.slack.com"


class ChannelError(ValueError):
    """A channel configuration is not acceptable (AgentOS-written message, safe to show)."""


def _no_ctrl(v: str, what: str) -> str:
    if CONTROL_RE.search(v):
        raise ValueError(f"{what} must not contain control characters")
    return v


def _address(v: str, what: str) -> str:
    v = _no_ctrl(v.strip(), what)
    if not ADDRESS_RE.fullmatch(v):
        raise ValueError(f"{what} is not a plain email address")
    return v.lower()


class _Base(BaseModel):
    name: str
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not NAME_RE.fullmatch(v):
            raise ValueError("name must be 1-40 characters: lowercase letters, digits, '-' or '_'")
        return v


class EmailChannel(_Base):
    type: Literal["email"] = "email"
    host: str
    port: int = Field(default=587, ge=1, le=65535)
    security: Literal["starttls", "ssl", "none"] = "starttls"
    allow_insecure_local: bool = False
    username: Optional[str] = Field(default=None, max_length=200)
    password_secret: Optional[str] = Field(default=None, max_length=120)  # vault secret NAME, never the value
    from_address: str
    allowed_recipient_domains: list[str] = Field(default_factory=list, max_length=50)
    alert_recipients: list[str] = Field(default_factory=list, max_length=MAX_RECIPIENTS)
    use_for_flows: bool = False

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip().lower()
        if not HOST_RE.fullmatch(v):
            raise ValueError("host must be a hostname or IP address")
        return v

    @field_validator("username")
    @classmethod
    def _user(cls, v: Optional[str]) -> Optional[str]:
        return _no_ctrl(v, "username") if v else None

    @field_validator("from_address")
    @classmethod
    def _from(cls, v: str) -> str:
        return _address(v, "from_address")

    @field_validator("alert_recipients")
    @classmethod
    def _recipients(cls, v: list[str]) -> list[str]:
        return [_address(a, "alert recipient") for a in v]

    @field_validator("allowed_recipient_domains")
    @classmethod
    def _domains(cls, v: list[str]) -> list[str]:
        out = []
        for d in v:
            d = d.strip().lower().lstrip("@")
            if not DOMAIN_RE.fullmatch(d):
                raise ValueError("allowed_recipient_domains must be plain domain names")
            out.append(d)
        return out

    def check_config(self) -> None:
        """Rules that do not need DNS: TLS unless a local test server behind the explicit flag."""
        local = self.host.strip("[]") in LOCAL_HOSTS
        if self.allow_insecure_local and not local:
            raise ChannelError("allow_insecure_local is only for a local test server (localhost / 127.0.0.1 / ::1)")
        if self.security == "none" and not (self.allow_insecure_local and local):
            raise ChannelError("plaintext SMTP is allowed only for localhost with allow_insecure_local; "
                               "use starttls or ssl")
        if self.alert_recipients and self.allowed_recipient_domains:
            bad = [a for a in self.alert_recipients if a.split("@", 1)[1] not in self.allowed_recipient_domains]
            if bad:
                raise ChannelError("every alert recipient must be in allowed_recipient_domains")

    def public(self) -> dict[str, Any]:
        d = self.model_dump()
        d["password_set"] = bool(self.password_secret)
        return d


class SlackChannel(_Base):
    type: Literal["slack"] = "slack"
    webhook_secret: Optional[str] = Field(default=None, max_length=120)  # vault secret NAME
    display_channel: str = Field(default="", max_length=80)  # label only; the webhook decides the real channel
    internal: bool = False  # admin: untrusted text may go here

    @field_validator("display_channel")
    @classmethod
    def _label(cls, v: str) -> str:
        return _no_ctrl(v, "display_channel")

    def check_config(self) -> None:
        return None

    def public(self) -> dict[str, Any]:
        d = self.model_dump()
        d["webhook_set"] = bool(self.webhook_secret)
        return d


Channel = Annotated[Union[EmailChannel, SlackChannel], Field(discriminator="type")]
_ADAPTER: TypeAdapter[Any] = TypeAdapter(Channel)


def parse_channel(doc: dict[str, Any]) -> EmailChannel | SlackChannel:
    return _ADAPTER.validate_python({k: v for k, v in doc.items() if k not in ("password_set", "webhook_set")})


# ---------------------------------------------------------------------------------------------- Slack URL + text

def check_slack_webhook_url(url: str) -> None:
    """https://hooks.slack.com/services/... exactly (no other host, port, scheme or userinfo)."""
    if not isinstance(url, str) or CONTROL_RE.search(url):
        raise ChannelError("the Slack webhook URL is not valid")
    p = urlsplit(url.strip())
    if p.scheme != "https" or (p.hostname or "").lower() != SLACK_HOST or p.port not in (None, 443) \
            or p.username or p.password:
        raise ChannelError("the Slack webhook URL must be https://hooks.slack.com/... (incoming webhooks only)")
    if not p.path.startswith("/services/") or p.query or p.fragment:
        raise ChannelError("the Slack webhook URL must look like https://hooks.slack.com/services/...")


_PING = re.compile(r"@(channel|here|everyone)\b", re.IGNORECASE)


def escape_slack(text: str) -> str:
    """Slack control characters escaped (no <!channel>, <@U..>, <url|label>), and a zero-width space after '@' in
    @channel / @here / @everyone (defense in depth)."""
    out = str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _PING.sub(lambda m: "@​" + m.group(1), out)


def slack_payload(text: str) -> dict[str, Any]:
    return {"text": escape_slack(text), "unfurl_links": False, "unfurl_media": False}


# ---------------------------------------------------------------------------------------------- email arguments

def validate_email_args(args: dict[str, Any], channel: Optional[EmailChannel]) -> tuple[list[str], str, str]:
    """(recipients, subject, body) or SinkArgumentRejected. Runs BEFORE sink_intent."""
    bad_keys = sorted(k for k in args if str(k).lower() in FORBIDDEN_EMAIL_ARGS)
    if bad_keys:
        raise SinkArgumentRejected(f"send_email: {', '.join(bad_keys)} cannot be set by a flow; "
                                   "From is fixed by the email channel")
    to = args.get("to")
    values = [to] if isinstance(to, str) else list(to or []) if isinstance(to, (list, tuple)) else None
    if values is None or not values:
        raise SinkArgumentRejected("send_email: 'to' must be an address or a list of addresses")
    if any(isinstance(v, str) and CONTROL_RE.search(v) for v in values):
        raise SinkArgumentRejected("send_email: control characters (CR/LF) in 'to' are refused")
    try:
        recipients = normalize_and_validate_recipients(to)
    except ValueError as e:
        raise SinkArgumentRejected(f"send_email: {e}") from None
    if any(not ADDRESS_RE.fullmatch(r) for r in recipients):
        raise SinkArgumentRejected("send_email: 'to' contains an address that is not a plain email address")
    if len(recipients) > MAX_RECIPIENTS:
        raise SinkArgumentRejected(f"send_email: at most {MAX_RECIPIENTS} recipients")
    subject = args.get("subject")
    subject = "" if subject is None else subject
    if not isinstance(subject, str):
        raise SinkArgumentRejected("send_email: 'subject' must be text")
    if CONTROL_RE.search(subject):
        raise SinkArgumentRejected("send_email: control characters (CR/LF) in 'subject' are refused")
    if len(subject) > MAX_SUBJECT:
        raise SinkArgumentRejected(f"send_email: 'subject' is longer than {MAX_SUBJECT} characters")
    body = _as_text(args.get("body"))
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise SinkArgumentRejected(f"send_email: 'body' is larger than {MAX_BODY_BYTES // 1000} KB")
    if channel is not None and channel.allowed_recipient_domains:
        outside = [r for r in recipients if r.split("@", 1)[1] not in channel.allowed_recipient_domains]
        if outside:
            raise SinkArgumentRejected(f"send_email: {len(outside)} recipient(s) outside the channel's allowed "
                                       "recipient domains")
    return recipients, subject, body


def _as_text(value: Any) -> str:
    """A body that is not text (a mapped object, a number) is sent as JSON / plain text, never rejected silently."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    import json

    try:
        return json.dumps(value, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def message_id(idempotency_key: str) -> str:
    return f"<{hashlib.sha256(idempotency_key.encode('utf-8')).hexdigest()[:40]}@agentos.invalid>"


def build_message(channel: EmailChannel, recipients: Iterable[str], subject: str, body: str,
                  idempotency_key: str) -> EmailMessage:
    msg = EmailMessage(policy=SMTP_POLICY)
    msg["From"] = channel.from_address
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg["Date"] = formatdate(usegmt=True)
    msg["Message-ID"] = message_id(idempotency_key)
    msg["X-AgentOS"] = "notification"
    msg.set_content(body, subtype="plain", charset="utf-8")
    return msg


# ---------------------------------------------------------------------------------------------- Slack arguments

def validate_slack_args(args: dict[str, Any]) -> tuple[str, str]:
    extra = sorted(k for k in args if k not in ("channel", "text"))
    if extra:
        raise SinkArgumentRejected(f"send_slack: unknown argument(s) {', '.join(map(str, extra))[:100]}")
    channel, text = args.get("channel"), _as_text(args.get("text"))
    if not isinstance(channel, str) or not NAME_RE.fullmatch(channel):
        raise SinkArgumentRejected("send_slack: 'channel' must be the name of a configured Slack channel")
    if not isinstance(text, str) or not text:
        raise SinkArgumentRejected("send_slack: 'text' must be non-empty text")
    if len(text) > MAX_SLACK_TEXT:
        raise SinkArgumentRejected(f"send_slack: 'text' is longer than {MAX_SLACK_TEXT} characters")
    return channel, text

"""Network senders for 3.3 notifications. Both raise ``DeliveryError`` with an AgentOS-written message: no server
response text, no secret, no exception text from the network library is passed through.

SMTP (smtplib, stdlib): the host is resolved and checked like net_guard (blocked ranges refused unless the admin
SMTP allowlist matches; loopback only for an ``allow_insecure_local`` channel), we connect to the CHECKED IP and TLS
verifies the certificate against the configured hostname. STARTTLS is required when configured (no fallback).

Slack: POST to https://hooks.slack.com/... through net_guard's HttpRequestTransport (SSRF checks, connect to the
checked IP), no redirects followed, small size cap, 10 s timeout. The text is always escaped (channels.escape_slack).
"""

from __future__ import annotations

import smtplib
import socket
import ssl
from typing import Any, Callable, Iterable, Optional

from agentos.flows.net_guard import (
    HttpRequestTransport,
    RawResponse,
    SSRFBlockedError,
    blocked_reason,
    default_resolver,
    host_matches_allowlist,
    httpx_sender,
)
from agentos.notify.channels import EmailChannel, LOCAL_HOSTS, check_slack_webhook_url, slack_payload

SMTP_TIMEOUT_S = 15.0
SLACK_TIMEOUT_S = 10.0
_LOOPBACK_REASON = "loopback"


class DeliveryError(Exception):
    """A send failed. ``str(err)`` is AgentOS-written and safe to show and store."""


# ------------------------------------------------------------------------------------------------------ SMTP

def check_smtp_host(channel: EmailChannel, smtp_allowlist: Iterable[str] = (),
                    resolver: Optional[Callable[[str, int], list[str]]] = None) -> str:
    """The IP to connect to, or DeliveryError. Same blocked ranges as net_guard."""
    host = channel.host.strip("[]")
    try:
        import ipaddress

        ips = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            ips = (resolver or default_resolver)(host, channel.port)
        except OSError:
            raise DeliveryError("the SMTP host name could not be resolved") from None
    if not ips:
        raise DeliveryError("the SMTP host name did not resolve to any address")
    allowlisted = host_matches_allowlist(host, ips, list(smtp_allowlist))
    for ip in ips:
        reason = blocked_reason(ip)
        if not reason or allowlisted:
            continue
        if reason == _LOOPBACK_REASON and channel.allow_insecure_local and host in LOCAL_HOSTS:
            continue
        raise DeliveryError(f"the SMTP host resolves to a blocked address ({reason}); an internal relay must be "
                            "in notifications.smtp_allowlist")
    return ips[0]


class _SMTP(smtplib.SMTP):
    """Connects to the checked IP; STARTTLS verifies the certificate against the configured hostname."""

    def __init__(self, hostname: str, ip: str, port: int, timeout: float) -> None:
        super().__init__(timeout=timeout)  # no host: no connect yet
        self._host = hostname  # server_hostname for STARTTLS (SNI + certificate check)
        self.connect(ip, port)


class _SMTP_SSL(smtplib.SMTP_SSL):
    def __init__(self, hostname: str, ip: str, port: int, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(timeout=timeout, context=context)
        self._host = hostname  # server_hostname for the implicit TLS handshake
        self.connect(ip, port)


def smtp_send(channel: EmailChannel, ip: str, password: Optional[str], msg: Any, recipients: list[str],
              ssl_context: Optional[ssl.SSLContext] = None, timeout: float = SMTP_TIMEOUT_S) -> dict[str, Any]:
    """One SMTP conversation. Blocking (run it in a thread). Returns {"refused": n}."""
    ctx = ssl_context or ssl.create_default_context()  # certificate + hostname verification on
    hostname = channel.host.strip("[]")
    client: Optional[smtplib.SMTP] = None
    try:
        if channel.security == "ssl":
            client = _SMTP_SSL(hostname, ip, channel.port, timeout, ctx)
            client.ehlo()
        else:
            client = _SMTP(hostname, ip, channel.port, timeout)
            client.ehlo()
            if channel.security == "starttls":
                if not client.has_extn("starttls"):
                    raise DeliveryError("the SMTP server does not offer STARTTLS; TLS is required for this channel")
                client.starttls(context=ctx)
                client.ehlo()
        if channel.username:
            if password is None:
                raise DeliveryError("the channel has a username but its password secret is missing in the vault")
            client.login(channel.username, password)
        refused = client.send_message(msg, from_addr=channel.from_address, to_addrs=recipients)
        try:
            client.quit()
        except Exception:
            pass
        return {"refused": len(refused or {})}
    except DeliveryError:
        raise
    except smtplib.SMTPAuthenticationError:
        raise DeliveryError("SMTP authentication failed") from None
    except smtplib.SMTPRecipientsRefused:
        raise DeliveryError("the SMTP server refused the recipient(s)") from None
    except smtplib.SMTPSenderRefused:
        raise DeliveryError("the SMTP server refused the From address") from None
    except smtplib.SMTPNotSupportedError:
        raise DeliveryError("the SMTP server does not support a required feature (STARTTLS or AUTH)") from None
    except ssl.SSLCertVerificationError:
        raise DeliveryError("TLS certificate verification failed for the SMTP server") from None
    except ssl.SSLError:
        raise DeliveryError("the TLS handshake with the SMTP server failed") from None
    except (socket.timeout, TimeoutError):
        raise DeliveryError("the SMTP server did not answer in time") from None
    except smtplib.SMTPServerDisconnected:
        raise DeliveryError("the SMTP server closed the connection") from None
    except smtplib.SMTPException:
        raise DeliveryError("the SMTP server returned an error") from None
    except OSError:
        raise DeliveryError("could not connect to the SMTP server") from None
    finally:
        if client is not None and client.sock is not None:
            try:
                client.close()
            except Exception:
                pass


# ------------------------------------------------------------------------------------------------------ Slack

def _no_redirect_sender(method: str, target: Any, pq: str, headers: dict[str, str], body: Any, timeout: float,
                        max_bytes: int) -> RawResponse:
    raw = httpx_sender(method, target, pq, headers, body, timeout, max_bytes)
    raw.headers.pop("location", None)  # a 3xx is returned as the final answer (an error), never followed
    return raw


class SlackSender:
    """``_test_endpoint`` / ``_test_allowlist``: constructor-only, used by tests to reach a local HTTP stand-in.
    The configured webhook URL is still checked (https://hooks.slack.com/...) before anything is sent."""

    def __init__(self, _test_endpoint: Optional[str] = None, _test_allowlist: Iterable[str] = (),
                 sender: Any = None) -> None:
        self._test_endpoint = _test_endpoint
        self._test_allowlist = list(_test_allowlist)
        self._sender = sender

    def post(self, webhook_url: str, text: str) -> dict[str, Any]:
        check_slack_webhook_url(webhook_url)  # ChannelError (a ValueError) if not hooks.slack.com
        url = self._test_endpoint or webhook_url
        transport = HttpRequestTransport(allowlist=self._test_allowlist if self._test_endpoint else (),
                                         sender=self._sender or _no_redirect_sender)
        try:
            res = transport.request("POST", url, headers={"Content-Type": "application/json"},
                                    body=slack_payload(text), timeout_s=SLACK_TIMEOUT_S, max_bytes=2000)
        except SSRFBlockedError:
            raise DeliveryError("the Slack webhook address was refused by the network guard") from None
        except Exception as e:
            if "timeout" in type(e).__name__.lower():
                raise DeliveryError("Slack did not answer in time") from None
            raise DeliveryError("could not connect to Slack") from None
        if res["status"] != 200:
            raise DeliveryError(f"Slack answered HTTP {int(res['status'])}")
        return {"status": "sent"}

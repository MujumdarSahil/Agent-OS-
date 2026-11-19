"""3.3 notifications: channels (SMTP email, Slack incoming webhook), real sends for flows, alerts with a persistent
outbox. Design: docs/evidence/3.3.md. Pure domain code (no FastAPI); the Mongo adapter is in agentos/storage/mongo.
"""

from agentos.notify.channels import (
    ChannelError,
    EmailChannel,
    SlackChannel,
    parse_channel,
)
from agentos.notify.service import DeliveryError, NotifyService

__all__ = ["ChannelError", "DeliveryError", "EmailChannel", "NotifyService", "SlackChannel", "parse_channel"]

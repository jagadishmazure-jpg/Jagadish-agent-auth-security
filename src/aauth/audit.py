"""Structured auth audit events.

Events are JSON lines with a stable schema so they can be exported as SOC alerts
(see `aauth.soc`) and correlated with Jagadish-azure-ai-soc.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AuditEvent:
    event: str  # login | token_issue | token_refresh | refresh_reuse | revoke | validate_fail | exchange | approval
    outcome: str  # success | failure
    subject: str = ""
    reason: str = ""
    client_id: str = ""
    token_id: str = ""
    scopes: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


class AuditLog:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: str, outcome: str, **kwargs: Any) -> AuditEvent:
        e = AuditEvent(event=event, outcome=outcome, **kwargs)
        self.events.append(e)
        return e

    def by_event(self, name: str) -> list[AuditEvent]:
        return [e for e in self.events if e.event == name]

    def failures(self) -> list[AuditEvent]:
        return [e for e in self.events if e.outcome == "failure"]

    def dumps(self) -> str:
        return "\n".join(json.dumps(e.to_dict(), sort_keys=True) for e in self.events)

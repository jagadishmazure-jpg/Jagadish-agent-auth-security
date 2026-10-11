"""Northglass Financial Services: a fictional mid-size lender.

Users, agents, roles and scopes used by every demo and test. Contact details use
the reserved `.example` TLD and 555 numbers; nothing here is a real person.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Principal:
    id: str
    kind: str  # user | agent | service
    name: str
    email: str
    roles: tuple[str, ...]
    scopes: tuple[str, ...]
    department: str = ""


@dataclass
class Company:
    name: str = "Northglass Financial Services"
    slug: str = "northglass"
    issuer: str = "https://auth.northglass.example"
    audience_api: str = "api://northglass-loan-api"
    audience_mcp: str = "api://northglass-mcp"
    audience_a2a: str = "api://northglass-a2a"
    tenant_id: str = "00000000-0000-0000-0000-0000000000a1"
    principals: dict[str, Principal] = field(default_factory=dict)


ROLES = {
    "loan.officer": ("loans:read", "loans:write", "docs:read", "tools:summarize"),
    "loan.underwriter": ("loans:read", "loans:decide", "docs:read", "credit:read"),
    "compliance.officer": ("loans:read", "audit:read", "docs:read"),
    "it.admin": ("admin:users", "admin:keys", "audit:read"),
    "agent.loan_assistant": ("loans:read", "docs:read", "tools:summarize"),
    "agent.doc_fetcher": ("docs:read", "tools:fetch"),
    "agent.risk_screener": ("loans:read", "credit:read", "tools:screen"),
    "service.apim": ("introspect",),
}

# High-risk scopes that always need a human approval before an agent may hold them.
HIGH_RISK_SCOPES = frozenset({"loans:decide", "admin:users", "admin:keys", "credit:write"})


def build() -> Company:
    c = Company()
    people = [
        Principal("u-ava", "user", "Ava Chen", "ava.chen@northglass.example", ("loan.officer",), ROLES["loan.officer"], "Lending"),
        Principal("u-ben", "user", "Ben Okonkwo", "ben.okonkwo@northglass.example", ("loan.underwriter",), ROLES["loan.underwriter"], "Underwriting"),
        Principal(
            "u-cara", "user", "Cara Singh", "cara.singh@northglass.example", ("compliance.officer",), ROLES["compliance.officer"], "Compliance"
        ),
        Principal("u-dev", "user", "Dev Patel", "dev.patel@northglass.example", ("it.admin",), ROLES["it.admin"], "IT"),
    ]
    agents = [
        Principal(
            "a-loan",
            "agent",
            "Loan Assistant",
            "loan-assistant@agents.northglass.example",
            ("agent.loan_assistant",),
            ROLES["agent.loan_assistant"],
            "Agents",
        ),
        Principal(
            "a-docs", "agent", "Doc Fetcher", "doc-fetcher@agents.northglass.example", ("agent.doc_fetcher",), ROLES["agent.doc_fetcher"], "Agents"
        ),
        Principal(
            "a-risk",
            "agent",
            "Risk Screener",
            "risk-screener@agents.northglass.example",
            ("agent.risk_screener",),
            ROLES["agent.risk_screener"],
            "Agents",
        ),
    ]
    services = [
        Principal("s-apim", "service", "APIM Gateway", "apim@svc.northglass.example", ("service.apim",), ROLES["service.apim"], "Platform"),
    ]
    for p in (*people, *agents, *services):
        c.principals[p.id] = p
    return c


COMPANY = build()

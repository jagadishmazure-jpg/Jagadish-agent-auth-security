"""Agent-to-agent (A2A) authentication.

Each agent presents a short-lived token audience-restricted to the peer agent
service. No shared secrets: tokens are signed by the platform key ring (in Azure
this maps to managed identity + Entra). The receiving agent verifies iss/aud/exp
and that the caller is in its allow-list.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aauth import jwt_tokens
from aauth.company import COMPANY
from aauth.keys import KeyRing
from aauth.store import AuthStore


@dataclass
class A2AService:
    ring: KeyRing
    store: AuthStore
    # agent_id -> set of peer agent ids allowed to call it
    allow: dict[str, set[str]] = field(default_factory=dict)

    def issue_peer_token(self, *, caller_id: str, callee_id: str, scopes: list[str]) -> jwt_tokens.AccessToken:
        return jwt_tokens.issue(
            self.ring,
            sub=caller_id,
            audience=f"{COMPANY.audience_a2a}/{callee_id}",
            scopes=scopes,
            store=self.store,
            extra={"caller": caller_id, "callee": callee_id},
        )

    def verify_peer(self, token: str, *, callee_id: str) -> dict:
        claims = jwt_tokens.verify(token, self.ring, audience=f"{COMPANY.audience_a2a}/{callee_id}", store=self.store)
        caller = claims["sub"]
        allowed = self.allow.get(callee_id, set())
        if caller not in allowed:
            raise jwt_tokens.TokenError("peer_not_allowed")
        return claims

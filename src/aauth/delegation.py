"""Agents acting for users: OAuth token exchange (RFC 8693) / Entra OBO shape.

An agent presents a user's access token (or a subject token) and receives a
downstream token whose scopes are the intersection of (user scopes) ∩ (agent
scopes) ∩ (requested scopes), further reduced by any audience restriction for
the target tool. High-risk scopes require a recorded human approval. The `act`
claim identifies the agent; tests prove the agent can never exceed the user.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aauth import jwt_tokens
from aauth.company import COMPANY, HIGH_RISK_SCOPES, Principal
from aauth.keys import KeyRing
from aauth.store import AuthStore


@dataclass
class Approval:
    approval_id: str
    user_sub: str
    agent_id: str
    scopes: list[str]
    approver: str


@dataclass
class DelegationService:
    ring: KeyRing
    store: AuthStore
    approvals: dict[str, Approval] = field(default_factory=dict)
    # tool_id -> required audience
    tool_audiences: dict[str, str] = field(default_factory=dict)

    def record_approval(self, approval: Approval) -> None:
        self.approvals[approval.approval_id] = approval

    def exchange(
        self,
        *,
        subject_token: str,
        agent: Principal,
        requested_scopes: list[str],
        target_audience: str,
        tool_id: str | None = None,
        approval_id: str | None = None,
    ) -> jwt_tokens.AccessToken:
        if agent.kind != "agent":
            raise jwt_tokens.TokenError("not_an_agent")
        user_claims = jwt_tokens.verify(subject_token, self.ring, audience=COMPANY.audience_api, store=self.store)
        user_scopes = set(user_claims.get("scope", "").split())
        agent_scopes = set(agent.scopes)
        requested = set(requested_scopes)
        granted = sorted(user_scopes & agent_scopes & requested)
        if not granted:
            raise jwt_tokens.TokenError("no_overlapping_scopes")
        risky = [s for s in granted if s in HIGH_RISK_SCOPES]
        if risky:
            if not approval_id or approval_id not in self.approvals:
                raise jwt_tokens.TokenError("approval_required")
            ap = self.approvals[approval_id]
            if ap.user_sub != user_claims["sub"] or ap.agent_id != agent.id:
                raise jwt_tokens.TokenError("approval_mismatch")
            if not set(risky) <= set(ap.scopes):
                raise jwt_tokens.TokenError("approval_insufficient")
        if tool_id and tool_id in self.tool_audiences:
            expected = self.tool_audiences[tool_id]
            if target_audience != expected:
                raise jwt_tokens.TokenError("wrong_tool_audience")
        # Actor claim: the agent is acting on behalf of the user.
        act = {"sub": agent.id, "may_act": {"sub": user_claims["sub"]}}
        return jwt_tokens.issue(
            self.ring,
            sub=user_claims["sub"],
            audience=target_audience,
            scopes=granted,
            roles=[],  # downstream token carries scopes, not the user's full roles
            store=self.store,
            act=act,
            extra={"client_id": agent.id, "azp": agent.id},
        )

    def agent_exceeds_user(self, subject_token: str, agent_token: str, agent_audience: str) -> list[str]:
        """Return scopes the agent token has that the user token does not. Should always be empty."""
        user = jwt_tokens.verify(subject_token, self.ring, audience=COMPANY.audience_api, store=self.store)
        agent_claims = jwt_tokens.verify(agent_token, self.ring, audience=agent_audience, store=self.store)
        return sorted(set(agent_claims.get("scope", "").split()) - set(user.get("scope", "").split()))

"""Agent Framework style agent that calls tools with delegated tokens.

Uses a deterministic offline plan (no hosted model). The agent never holds the
user's raw token for passthrough; it exchanges for a downstream token per tool
audience. A MockAuthChatClient matching the Agent Framework chat-client surface
is included for interview demos; run_loan_assistant does not require it.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from agent_framework import BaseChatClient, ChatResponse, Message
from agent_framework._tools import FunctionInvocationLayer
from pydantic import BaseModel, Field

from aauth.company import COMPANY, Principal
from aauth.delegation import Approval, DelegationService
from aauth.jwt_tokens import AccessToken


class ToolPlan(BaseModel):
    tool: str
    args: dict = Field(default_factory=dict)


class MockAuthChatClient(FunctionInvocationLayer, BaseChatClient):
    """Deterministic offline stand-in; same layering as the SOC repo's mock client."""

    OTEL_PROVIDER_NAME = "aauth-mock"

    async def _inner_get_response(self, *, messages, stream, options, **kwargs):  # type: ignore[override]
        msgs = list(messages)
        user = next((m.text for m in reversed(msgs) if m.role == "user"), "")
        m = re.search(r"loan\s+(L-\d+)", user, re.I)
        loan_id = m.group(1) if m else "L-1001"
        plan = ToolPlan(tool="summarize_loan", args={"loan_id": loan_id})
        return ChatResponse(messages=[Message(role="assistant", contents=[plan.model_dump_json()])], model="aauth-mock")


@dataclass
class AgentResult:
    tool: str
    scopes_used: list[str]
    audience: str
    exceeded_user: list[str]
    summary: str


def plan_from_text(user_text: str) -> ToolPlan:
    m = re.search(r"loan\s+(L-\d+)", user_text, re.I)
    loan_id = m.group(1) if m else "L-1001"
    return ToolPlan(tool="summarize_loan", args={"loan_id": loan_id})


def run_loan_assistant(
    delegation: DelegationService,
    *,
    user_token: str,
    agent: Principal,
    user_text: str,
) -> AgentResult:
    plan = plan_from_text(user_text)
    audience = COMPANY.audience_mcp
    delegated: AccessToken = delegation.exchange(
        subject_token=user_token,
        agent=agent,
        requested_scopes=["loans:read", "tools:summarize"],
        target_audience=audience,
        tool_id="summarize_loan",
    )
    exceeded = delegation.agent_exceeds_user(user_token, delegated.token, audience)
    summary = f"Agent {agent.id} summarized {plan.args['loan_id']} with scopes [{delegated.claims.get('scope')}] for audience {audience}"
    return AgentResult(
        tool=plan.tool,
        scopes_used=delegated.claims.get("scope", "").split(),
        audience=audience,
        exceeded_user=exceeded,
        summary=summary,
    )


def approve_high_risk(delegation: DelegationService, *, user_sub: str, agent_id: str, scopes: list[str], approver: str) -> Approval:
    ap = Approval(approval_id=uuid.uuid4().hex, user_sub=user_sub, agent_id=agent_id, scopes=scopes, approver=approver)
    delegation.record_approval(ap)
    return ap

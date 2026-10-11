"""OAuth 2.1 PKCE / client credentials and OBO delegation."""

import hashlib

import pytest

from aauth import jwt_tokens
from aauth.company import COMPANY
from aauth.delegation import Approval, DelegationService
from aauth.oauth_server import build_demo_server


def _challenge(verifier: str) -> str:
    import base64

    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def test_auth_code_pkce(ring, store):
    srv = build_demo_server(ring, store)
    verifier = "a" * 64
    redirect = srv.authorize(
        client_id="spa-loan-portal",
        redirect_uri="https://loans.northglass.example/callback",
        scope="loans:read docs:read openid",
        state="xyz",
        code_challenge=_challenge(verifier),
        sub="u-ava",
        password="pass-u-ava",
    )
    assert "code=" in redirect and "state=xyz" in redirect
    code = redirect.split("code=")[1].split("&")[0]
    tokens = srv.token_auth_code(
        client_id="spa-loan-portal", code=code, redirect_uri="https://loans.northglass.example/callback", code_verifier=verifier
    )
    claims = jwt_tokens.verify(tokens["access_token"], ring, audience=COMPANY.audience_api, store=store)
    assert claims["sub"] == "u-ava"
    assert "loans:read" in claims["scope"]


def test_pkce_rejects_bad_verifier(ring, store):
    srv = build_demo_server(ring, store)
    verifier = "b" * 64
    redirect = srv.authorize(
        client_id="spa-loan-portal",
        redirect_uri="https://loans.northglass.example/callback",
        scope="loans:read",
        state="s",
        code_challenge=_challenge(verifier),
        sub="u-ava",
        password="pass-u-ava",
    )
    code = redirect.split("code=")[1].split("&")[0]
    with pytest.raises(ValueError, match="pkce"):
        srv.token_auth_code(client_id="spa-loan-portal", code=code, redirect_uri="https://loans.northglass.example/callback", code_verifier="c" * 64)


def test_client_credentials_and_introspect(ring, store):
    srv = build_demo_server(ring, store)
    tokens = srv.token_client_credentials(client_id="svc-batch", client_conf="demo-only-not-a-real-secret", scope="loans:read")
    info = srv.introspect(tokens["access_token"])
    assert info["active"] is True and info["sub"] == "svc-batch"
    assert srv.introspect("not.a.token")["active"] is False


def test_refresh_via_oauth(ring, store):
    srv = build_demo_server(ring, store)
    verifier = "d" * 64
    redirect = srv.authorize(
        client_id="spa-loan-portal",
        redirect_uri="https://loans.northglass.example/callback",
        scope="loans:read",
        state="s",
        code_challenge=_challenge(verifier),
        sub="u-ava",
        password="pass-u-ava",
    )
    code = redirect.split("code=")[1].split("&")[0]
    tokens = srv.token_auth_code(
        client_id="spa-loan-portal", code=code, redirect_uri="https://loans.northglass.example/callback", code_verifier=verifier
    )
    nxt = srv.token_refresh(refresh_token=tokens["refresh_token"], client_id="spa-loan-portal")
    jwt_tokens.verify(nxt["access_token"], ring, audience=COMPANY.audience_api, store=store)


def test_delegation_intersection_and_act_claim(ring, store):
    user = COMPANY.principals["u-ava"]
    agent = COMPANY.principals["a-loan"]
    user_tok = jwt_tokens.issue(ring, sub=user.id, audience=COMPANY.audience_api, scopes=list(user.scopes), roles=list(user.roles), store=store)
    dele = DelegationService(ring=ring, store=store, tool_audiences={"summarize_loan": COMPANY.audience_mcp})
    at = dele.exchange(
        subject_token=user_tok.token,
        agent=agent,
        requested_scopes=["loans:read", "tools:summarize", "loans:write"],
        target_audience=COMPANY.audience_mcp,
        tool_id="summarize_loan",
    )
    # loans:write is user-only; tools:summarize is agent-only; intersection keeps loans:read + tools:summarize
    scopes = set(at.claims["scope"].split())
    assert scopes == {"loans:read", "tools:summarize"}
    assert at.claims["act"]["sub"] == agent.id
    assert dele.agent_exceeds_user(user_tok.token, at.token, COMPANY.audience_mcp) == []


def test_delegation_blocks_overreach_and_requires_approval(ring, store):
    underwriter = COMPANY.principals["u-ben"]
    agent = COMPANY.principals["a-loan"]
    user_tok = jwt_tokens.issue(
        ring, sub=underwriter.id, audience=COMPANY.audience_api, scopes=list(underwriter.scopes), roles=list(underwriter.roles), store=store
    )
    dele = DelegationService(ring=ring, store=store)
    with pytest.raises(jwt_tokens.TokenError, match="no_overlapping"):
        dele.exchange(subject_token=user_tok.token, agent=agent, requested_scopes=["loans:decide"], target_audience=COMPANY.audience_api)
    # Give agent a high-risk scope via a temporary principal? Agent doesn't have loans:decide.
    # Use underwriter's token with an agent that somehow requests credit:read (agent.risk has it)
    # credit:read is not high-risk; loans:decide is. Craft agent with loans:decide for this test:
    from aauth.company import Principal

    privileged_agent = Principal("a-tmp", "agent", "Tmp", "tmp@agents.northglass.example", ("x",), ("loans:decide", "loans:read"), "Agents")
    with pytest.raises(jwt_tokens.TokenError, match="approval_required"):
        dele.exchange(
            subject_token=user_tok.token,
            agent=privileged_agent,
            requested_scopes=["loans:decide"],
            target_audience=COMPANY.audience_api,
        )
    dele.record_approval(Approval("ap1", underwriter.id, "a-tmp", ["loans:decide"], "u-cara"))
    at = dele.exchange(
        subject_token=user_tok.token,
        agent=privileged_agent,
        requested_scopes=["loans:decide"],
        target_audience=COMPANY.audience_api,
        approval_id="ap1",
    )
    assert "loans:decide" in at.claims["scope"]

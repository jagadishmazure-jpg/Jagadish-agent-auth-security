"""FastAPI dual-path API, MCP auth, A2A, managed identity."""

import pytest
from httpx import ASGITransport, AsyncClient

from aauth import jwt_tokens
from aauth.a2a_auth import A2AService
from aauth.api import AppState, build_app
from aauth.company import COMPANY
from aauth.managed_identity import OfflineCredential
from aauth.mcp_auth import build_demo_mcp


@pytest.fixture
def app(ring, store):
    return build_app(AppState(ring=ring, store=store))


@pytest.mark.asyncio
async def test_jwt_and_session_paths(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as c:
        r = await c.get("/health")
        assert r.json()["ok"]
        jwks = await c.get("/.well-known/jwks.json")
        assert jwks.json()["keys"]
        login = await c.post("/auth/jwt/login", json={"sub": "u-ava"})
        token = login.json()["access_token"]
        loans = await c.get("/jwt/loans", headers={"Authorization": f"Bearer {token}"})
        assert loans.status_code == 200 and len(loans.json()["loans"]) == 2
        # session path
        slogin = await c.post("/auth/session/login", json={"sub": "u-ava"})
        csrf = slogin.json()["csrf"]
        assert "Set-Cookie" in slogin.headers or slogin.cookies
        # httpx keeps cookies from Set-Cookie
        loans2 = await c.get("/session/loans")
        assert loans2.status_code == 200
        note = await c.post("/session/loans/L-1001/note", json={"text": "looks good"}, headers={"X-CSRF-Token": csrf})
        assert note.status_code == 200
        bad = await c.post("/session/loans/L-1001/note", json={"text": "x"}, headers={"X-CSRF-Token": "nope"})
        assert bad.status_code == 401


@pytest.mark.asyncio
async def test_jwt_rejects_forged(app, ring, store):
    from aauth import naive

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as c:
        r = await c.get("/jwt/loans", headers={"Authorization": f"Bearer {naive.issue_none('u-ava')}"})
        assert r.status_code == 401


def test_mcp_metadata_and_tool_auth(ring, store):
    mcp = build_demo_mcp(ring, store)
    meta = mcp.protected_resource_metadata()
    assert meta["resource"].startswith("https://") and COMPANY.issuer in meta["authorization_servers"]
    # Token for API audience must not pass through
    api_tok = jwt_tokens.issue(ring, sub="a-loan", audience=COMPANY.audience_api, scopes=["tools:summarize", "loans:read"], store=store)
    with pytest.raises(jwt_tokens.TokenError):
        mcp.authorize_tool(api_tok.token, "summarize_loan")
    mcp_tok = jwt_tokens.issue(ring, sub="a-loan", audience=COMPANY.audience_mcp, scopes=["tools:summarize", "loans:read"], store=store)
    claims = mcp.authorize_tool(mcp_tok.token, "summarize_loan")
    assert claims["sub"] == "a-loan"
    with pytest.raises(jwt_tokens.TokenError, match="insufficient"):
        mcp.authorize_tool(mcp_tok.token, "screen_risk")


def test_a2a_allowlist(ring, store):
    a2a = A2AService(ring=ring, store=store, allow={"a-docs": {"a-loan"}})
    tok = a2a.issue_peer_token(caller_id="a-loan", callee_id="a-docs", scopes=["docs:read"])
    assert a2a.verify_peer(tok.token, callee_id="a-docs")["sub"] == "a-loan"
    bad = a2a.issue_peer_token(caller_id="a-risk", callee_id="a-docs", scopes=["docs:read"])
    with pytest.raises(jwt_tokens.TokenError, match="peer_not_allowed"):
        a2a.verify_peer(bad.token, callee_id="a-docs")


def test_managed_identity_offline(ring, store):
    cred = OfflineCredential(ring=ring, store=store)
    tok = cred.get_token(COMPANY.audience_api)
    claims = jwt_tokens.verify(tok.token, ring, audience=COMPANY.audience_api, store=store)
    assert claims["sub"] == "mi-northglass-api"

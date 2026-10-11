"""Local OAuth 2.1 / OIDC authorization server (offline mock).

Supports authorization code + PKCE (S256), client credentials, token
introspection (RFC 7662), and refresh. Not a full OIDC provider; enough to
exercise the flows the portfolio demonstrates. Entra ID is a separate adapter.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from aauth import jwt_tokens, refresh
from aauth.company import COMPANY
from aauth.keys import KeyRing
from aauth.store import AuthStore


def _b64u(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class Client:
    client_id: str
    client_conf: str | None  # None for public PKCE clients
    redirect_uris: list[str]
    grant_types: list[str]
    scopes: list[str]
    audience: str


@dataclass
class AuthCode:
    code: str
    client_id: str
    sub: str
    redirect_uri: str
    scopes: list[str]
    code_challenge: str
    code_challenge_method: str
    expires_at: float
    used: bool = False


@dataclass
class OAuthServer:
    ring: KeyRing
    store: AuthStore
    clients: dict[str, Client] = field(default_factory=dict)
    codes: dict[str, AuthCode] = field(default_factory=dict)
    users: dict[str, dict] = field(default_factory=dict)  # sub -> {password_hash, roles, scopes}

    def register_client(self, client: Client) -> None:
        self.clients[client.client_id] = client

    def register_user(self, sub: str, password: str, roles: list[str], scopes: list[str]) -> None:
        self.users[sub] = {"password": password, "roles": roles, "scopes": scopes}

    # --- authorize ---
    def authorize(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        sub: str,
        password: str,
    ) -> str:
        client = self.clients[client_id]
        if redirect_uri not in client.redirect_uris:
            raise ValueError("invalid_redirect_uri")
        if code_challenge_method != "S256":
            raise ValueError("invalid_challenge_method")
        user = self.users.get(sub)
        if user is None or user["password"] != password:
            raise ValueError("access_denied")
        requested = scope.split()
        granted = [s for s in requested if s in client.scopes and s in user["scopes"]]
        code = secrets.token_urlsafe(24)
        self.codes[code] = AuthCode(
            code=code,
            client_id=client_id,
            sub=sub,
            redirect_uri=redirect_uri,
            scopes=granted,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=time.time() + 60,
        )
        return f"{redirect_uri}?{urlencode({'code': code, 'state': state})}"

    def token_auth_code(
        self,
        *,
        client_id: str,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        client_conf: str | None = None,
    ) -> dict[str, Any]:
        client = self.clients[client_id]
        ac = self.codes.get(code)
        if ac is None or ac.used or time.time() > ac.expires_at:
            raise ValueError("invalid_grant")
        if ac.client_id != client_id or ac.redirect_uri != redirect_uri:
            raise ValueError("invalid_grant")
        if client.client_conf is not None and client.client_conf != client_conf:
            raise ValueError("invalid_client")
        digest = _b64u(hashlib.sha256(code_verifier.encode()).digest())
        if digest != ac.code_challenge:
            raise ValueError("invalid_grant_pkce")
        ac.used = True
        user = self.users[ac.sub]
        access = jwt_tokens.issue(self.ring, sub=ac.sub, audience=client.audience, scopes=ac.scopes, roles=user["roles"], store=self.store)
        rt = refresh.issue(self.store, sub=ac.sub, scopes=ac.scopes)
        return {
            "access_token": access.token,
            "token_type": "Bearer",
            "expires_in": int(access.expires_at - time.time()),
            "refresh_token": rt.token,
            "scope": " ".join(ac.scopes),
        }

    def token_client_credentials(self, *, client_id: str, client_conf: str, scope: str) -> dict[str, Any]:
        client = self.clients[client_id]
        if client.client_conf != client_conf:
            raise ValueError("invalid_client")
        if "client_credentials" not in client.grant_types:
            raise ValueError("unauthorized_client")
        requested = [s for s in scope.split() if s in client.scopes]
        access = jwt_tokens.issue(self.ring, sub=client_id, audience=client.audience, scopes=requested, roles=[], store=self.store)
        return {
            "access_token": access.token,
            "token_type": "Bearer",
            "expires_in": int(access.expires_at - time.time()),
            "scope": " ".join(requested),
        }

    def token_refresh(self, *, refresh_token: str, client_id: str) -> dict[str, Any]:
        client = self.clients[client_id]
        new_rt = refresh.rotate(self.store, refresh_token)
        user = self.users.get(new_rt.sub, {"roles": []})
        access = jwt_tokens.issue(
            self.ring, sub=new_rt.sub, audience=client.audience, scopes=new_rt.scopes, roles=user.get("roles", []), store=self.store
        )
        return {
            "access_token": access.token,
            "token_type": "Bearer",
            "expires_in": int(access.expires_at - time.time()),
            "refresh_token": new_rt.token,
            "scope": " ".join(new_rt.scopes),
        }

    def introspect(self, token: str, *, audience: str | None = None) -> dict:
        try:
            claims = jwt_tokens.verify(token, self.ring, audience=audience or COMPANY.audience_api, store=self.store)
        except jwt_tokens.TokenError:
            return {"active": False}
        return {
            "active": True,
            "sub": claims["sub"],
            "scope": claims.get("scope", ""),
            "aud": claims["aud"],
            "iss": claims["iss"],
            "exp": claims["exp"],
            "iat": claims["iat"],
            "jti": claims["jti"],
            "token_type": "access_token",
        }


def build_demo_server(ring: KeyRing, store: AuthStore) -> OAuthServer:
    srv = OAuthServer(ring=ring, store=store)
    srv.register_client(
        Client(
            client_id="spa-loan-portal",
            client_conf=None,
            redirect_uris=["https://loans.northglass.example/callback"],
            grant_types=["authorization_code", "refresh_token"],
            scopes=["loans:read", "loans:write", "docs:read", "openid", "profile"],
            audience=COMPANY.audience_api,
        )
    )
    srv.register_client(
        Client(
            client_id="svc-batch",
            client_conf="demo-only-not-a-real-secret",
            redirect_uris=[],
            grant_types=["client_credentials"],
            scopes=["loans:read", "docs:read"],
            audience=COMPANY.audience_api,
        )
    )
    for p in COMPANY.principals.values():
        if p.kind == "user":
            srv.register_user(p.id, password=f"pass-{p.id}", roles=list(p.roles), scopes=[*list(p.scopes), "openid", "profile"])
    return srv

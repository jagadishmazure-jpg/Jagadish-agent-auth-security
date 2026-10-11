"""MCP server authorization aligned with the current MCP authorization spec.

OAuth 2.1 for clients, Protected Resource Metadata (RFC 9728), resource
indicators (RFC 8707), and a hard rule: no token passthrough. The MCP server
validates tokens minted for its own audience and never forwards the caller's
token to a downstream API.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aauth import jwt_tokens
from aauth.company import COMPANY
from aauth.keys import KeyRing
from aauth.store import AuthStore


@dataclass
class MCPResource:
    resource: str  # canonical URI, e.g. https://mcp.northglass.example
    audience: str
    authorization_servers: list[str]
    scopes_supported: list[str]


@dataclass
class MCPAuth:
    ring: KeyRing
    store: AuthStore
    resource: MCPResource
    # tool -> required scopes
    tool_scopes: dict[str, list[str]] = field(default_factory=dict)

    def protected_resource_metadata(self) -> dict:
        """RFC 9728 metadata document."""
        return {
            "resource": self.resource.resource,
            "authorization_servers": self.resource.authorization_servers,
            "scopes_supported": self.resource.scopes_supported,
            "bearer_methods_supported": ["header"],
            "resource_documentation": "https://docs.northglass.example/mcp",
        }

    def authorize_tool(self, access_token: str, tool: str) -> dict:
        claims = jwt_tokens.verify(access_token, self.ring, audience=self.resource.audience, store=self.store)
        # Reject tokens meant for someone else (no passthrough of API tokens).
        if claims["aud"] != self.resource.audience:
            raise jwt_tokens.TokenError("token_passthrough_rejected")
        have = set(claims.get("scope", "").split())
        need = set(self.tool_scopes.get(tool, []))
        if not need <= have:
            raise jwt_tokens.TokenError("insufficient_scope")
        return claims


def build_demo_mcp(ring: KeyRing, store: AuthStore) -> MCPAuth:
    return MCPAuth(
        ring=ring,
        store=store,
        resource=MCPResource(
            resource="https://mcp.northglass.example",
            audience=COMPANY.audience_mcp,
            authorization_servers=[COMPANY.issuer],
            scopes_supported=["tools:summarize", "tools:fetch", "tools:screen", "docs:read", "loans:read"],
        ),
        tool_scopes={
            "summarize_loan": ["tools:summarize", "loans:read"],
            "fetch_document": ["tools:fetch", "docs:read"],
            "screen_risk": ["tools:screen", "loans:read"],
        },
    )

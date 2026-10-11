# aauth package

| File | What it does |
|---|---|
| `__init__.py` | Package version and paths |
| `paths.py` | Resolved paths |
| `company.py` | Northglass fictional principals |
| `keys.py` | JWKS key ring with rotation |
| `store.py` | Session / refresh / denylist store |
| `jwt_tokens.py` | Hardened JWT issue and verify |
| `sessions.py` | Server sessions with CSRF and timeouts |
| `refresh.py` | Refresh rotation and reuse detection |
| `dpop.py` | DPoP (RFC 9449) |
| `mtls.py` | Certificate-bound tokens (RFC 8705) |
| `naive.py` | Deliberately vulnerable JWT helpers (never default) |
| `oauth_server.py` | Local OAuth 2.1 / OIDC mock |
| `entra.py` | Entra ID / MSAL adapter (written, not run) |
| `delegation.py` | RFC 8693 / OBO token exchange |
| `mcp_auth.py` | MCP authorization |
| `a2a_auth.py` | Agent-to-agent auth |
| `managed_identity.py` | Offline MI credential |
| `api.py` | FastAPI dual-path demo |
| `agents.py` | Agent Framework stub agent |
| `attacks.py` | Attack suite |
| `benchmark.py` | JWT vs session measurements |
| `audit.py` | Auth audit log |
| `soc.py` | SOC alert export |
| `gate.py` | Release gate |
| `iac.py` | Infra summary |
| `cli.py` | `aauth` CLI |

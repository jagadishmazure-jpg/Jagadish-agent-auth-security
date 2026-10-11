# Agent auth security

[![ci](https://github.com/jagadishmazure-jpg/Jagadish-agent-auth-security/actions/workflows/ci.yml/badge.svg)](https://github.com/jagadishmazure-jpg/Jagadish-agent-auth-security/actions/workflows/ci.yml)
[![infra](https://github.com/jagadishmazure-jpg/Jagadish-agent-auth-security/actions/workflows/infra.yml/badge.svg)](https://github.com/jagadishmazure-jpg/Jagadish-agent-auth-security/actions/workflows/infra.yml)
[![codeql](https://github.com/jagadishmazure-jpg/Jagadish-agent-auth-security/actions/workflows/codeql.yml/badge.svg)](https://github.com/jagadishmazure-jpg/Jagadish-agent-auth-security/actions/workflows/codeql.yml)

End-to-end **authentication and authorization for users and AI agents**, offline-first.
Built for **Northglass Financial Services**, a fictional mid-size lender. **Nothing is deployed.**

Triggered by the common JWT-vs-sessions comparison table: this repo implements both paths,
measures every row for real, hardens JWTs (DPoP, refresh rotation, JWKS, token versioning),
runs an attack matrix against a labelled naive module, adds OAuth 2.1 / OIDC, on-behalf-of
delegation so agents cannot exceed the user, MCP and A2A auth with no token passthrough,
and maps the design onto Entra ID, APIM and Key Vault in Terraform and Bicep.

## At a glance (for recruiters)

* **What it shows:** JWT vs sessions measured side by side; hardened tokens; OAuth 2.1 PKCE;
  agent delegation with scope intersection; MCP resource auth; a 14-row attack matrix;
  Azure Entra / APIM / Key Vault IaC; SOC export to the companion AI SOC repo.
* **Size:** **108 automated tests** (pytest) plus Terraform plan tests, a 6-check release gate.
* **Real results (local microbench, in-memory store):** see the generated table below — session
  lookup can beat RS256 verify on a single process; the docs say so plainly.
* **Honest limits:** Entra/MSAL never run against a tenant; OAuth server is a teaching mock;
  nothing is deployed; see [limitations](docs/limitations.md).
* **Stack:** Python, FastAPI, PyJWT, cryptography, fakeredis, Microsoft Agent Framework, MCP,
  Terraform, Bicep, GitHub Actions (OIDC, CodeQL, gitleaks, SBOM).

## Built vs planned

| Part | Status |
|---|---|
| JWT vs session API + benchmark harness | Built |
| Hardened JWT (TTL, tv, denylist, JWKS rotation) | Built |
| Session hardening (cookie flags, CSRF, fixation, timeouts) | Built |
| Refresh rotation + reuse detection | Built |
| DPoP (RFC 9449) and mTLS-bound tokens (RFC 8705) | Built |
| Attack suite (14 cases) vs labelled naive module | Built |
| Local OAuth 2.1 AS (auth code + PKCE, client credentials, introspect) | Built |
| Entra ID / MSAL adapter and app-registration notes | Written, not run |
| RFC 8693 / OBO delegation with approvals | Built |
| MCP auth (RFC 9728 metadata, no passthrough) and A2A | Built |
| Managed identity offline credential | Built |
| Agent Framework stub agent | Built |
| SOC alert export for Jagadish-azure-ai-soc | Built |
| Terraform + Bicep (Key Vault, APIM, Entra apps, Log Analytics) | Built and tested offline, **never deployed** |
| Gated deploy / teardown workflows | Built, gated off, never run |
| JWE encrypted claims | Planned |
| Live Entra Conditional Access policies | Planned |
| Prompt Shields / production Foundry agent | Planned |

## Quick start

```bash
git clone https://github.com/jagadishmazure-jpg/Jagadish-agent-auth-security.git
cd Jagadish-agent-auth-security
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
aauth company
aauth benchmark --iterations 80
aauth attacks
aauth gate
pytest -q
```

## JWT vs sessions (measured)

<!-- output: benchmark --iterations 80 -->
```text
Store: in-memory dict; iterations: 80; host microbench (not a capacity plan).

| Dimension | JWT (stateless-ish) | Server session (stateful) | Notes |
|---|---|---|---|
| Scalability | Local verify; no shared store required for authZ check | Needs shared session store across 5+ instances | JWT still needs a denylist/version store for revocation |
| Performance (p50 verify) | 0.1122 ms (9060 ops/s) | 0.0139 ms (123520 ops/s) | Store=in-memory dict; single-process microbench |
| Revocation | Denylist hit in 0.4412 ms | Delete sid in 0.01 ms | Without a denylist, JWT revocation waits for TTL |
| Session / claim updates | immediate reject after tv bump (else up to access-token TTL) | next request sees new roles | Token version (tv) claim closes the JWT stale window |
| Data security | claims readable without key (sub=u-ava, roles=['loan.officer']) | opaque sid; data only in server store | JWTs are signed, not encrypted; keep PII out of claims (or use JWE) |
| Implementation complexity | JWKS, rotation, denylist, DPoP optional | Cookie flags, CSRF, fixation, idle/absolute TTL | Both need careful hardening |
| Best for | APIs, SPAs via BFF, service-to-service, agents | Server-rendered apps, simple sticky sessions | See docs/decision-guide.md |
| Avoid if | You cannot run a revocation/version store and need instant kill | You need pure horizontal scale with no shared store | Measured on this host; re-run with `aauth benchmark` |
```
<!-- /output -->

## Attack matrix

<!-- output: attacks -->
```text
| Attack | Hardened | Naive (labelled, never default) | Detail |
|---|---|---|---|
| alg=none | blocked:alg_not_allowed:none | accepted | unsigned token |
| RS256-to-HS256 key confusion | blocked:alg_not_allowed:HS256 | accepted | HMAC with RSA public key |
| kid injection / path traversal | blocked:unknown_kid | n/a (no file-based kid) | kid must exist in JWKS |
| jku/x5u spoofing | blocked:unknown_kid | n/a | JWKS is local; jku/x5u headers ignored |
| expired token | blocked:expired | n/a | exp enforced with skew |
| revoked / replayed jti | blocked:revoked | n/a | denylist |
| wrong audience | blocked:wrong_audience | accepted | aud check |
| tampered payload | blocked:bad_signature | n/a | signature covers payload |
| weak HMAC brute force | blocked:RS256_only | accepted:secret=passwordpasswordpasswordpassword | wordlist size 5 |
| stolen bearer without DPoP | blocked:dpop_malformed | n/a | cnf.jkt + proof required |
| refresh token reuse | blocked:reuse_detected | n/a | family revoked on reuse |
| CSRF | blocked:csrf_mismatch | n/a | double-submit CSRF token |
| session fixation | blocked:new_sid | n/a | sid rotated on login |
| JWT in localStorage (XSS exfil) | blocked:by_design_BFF_cookies | accepted:if_stored_in_localStorage | Decision guide: prefer BFF + HttpOnly cookies for SPAs |

hardened blocked 14/14
```
<!-- /output -->

## Companions

* [Jagadish-agent-identity-security](https://github.com/jagadishmazure-jpg/Jagadish-agent-identity-security) — who *can* do what (posture)
* [Jagadish-azure-ai-soc](https://github.com/jagadishmazure-jpg/Jagadish-azure-ai-soc) — what *happened* (alerts)
* This repo — how a request proves who it is (authentication)

## Docs

Start at [docs/README.md](docs/README.md). Decision guide: [docs/decision-guide.md](docs/decision-guide.md).
Threat model: [docs/threat-model.md](docs/threat-model.md).

## License

MIT. See [LICENSE](LICENSE).

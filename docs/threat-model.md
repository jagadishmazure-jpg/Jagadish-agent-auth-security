# Threat model

## Assets

Access tokens, refresh tokens, session ids, signing keys, delegated agent tokens, audit logs.

## STRIDE (summary)

| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | alg=none, key confusion, stolen bearer | RS256 allowlist, JWKS kid, DPoP/mTLS |
| Tampering | Modified payload | Signature verify; session data server-side |
| Repudiation | Denied login | Structured audit events → SOC export |
| Info disclosure | JWT claims readable | No PII in claims; opaque sessions; JWE planned |
| DoS | Huge JWKS / key spam | Single ring, rotation controlled |
| Elevation | Agent exceeds user; CSRF; fixation | Scope intersection, approvals, CSRF, sid rotate |

## OWASP API Security Top 10

| Item | How addressed |
|---|---|
| API1 Broken Object AuthZ | Scope checks on `/loans` |
| API2 Broken Auth | Hardened JWT + sessions; attack suite |
| API3 Broken Object Property AuthZ | Minimal claims |
| API4 Unrestricted Resource Consumption | Short TTL; gate benchmarks only |
| API5 Broken Function AuthZ | Role/scope gates; high-risk approvals |
| API6 Unrestricted Access to Sensitive Business Flows | Human approval for `loans:decide` |
| API7 SSRF | No jku/x5u fetch |
| API8 Security Misconfiguration | Cookie flags; CI workflow hardening |
| API9 Improper Inventory | Company principals + Entra app docs |
| API10 Unsafe Consumption of APIs | No token passthrough |

## OWASP ASVS (session / token themes)

V3 session: HttpOnly Secure SameSite, idle/absolute timeout, fixation defence, CSRF. V5 tokens: alg allowlist, iss/aud/exp, revocation, refresh rotation.

## OWASP LLM Top 10 (agent parts)

| Item | How addressed |
|---|---|
| LLM01 Prompt injection | Agent plans tools in code; tokens from exchange not from model text |
| LLM06 Excessive agency | Scope intersection + high-risk approval |
| LLM07 System prompt leakage | N/A offline stub |
| LLM08 Vector / embedding weak spots | N/A |

## ATT&CK / ATLAS

Auth failures map to T1606, T1550.001, T1078.004 in `soc.py` for the companion SOC repo.

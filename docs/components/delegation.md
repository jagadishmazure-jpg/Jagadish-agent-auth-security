# Agent delegation (OBO)

Scope intersection and act claim Module: `src/aauth/delegation.py`.

## 1. Purpose

Scope intersection and act claim Built for Northglass Financial Services (fictional).

## 2. Architecture

```mermaid
flowchart LR
  C[Client] --> M[Agent delegation (OBO)]
  M --> S[Auth store / JWKS]
```

## 3. How it works

See `src/aauth/delegation.py` and the tests under `tests/`.

## 4. Key files

| File | Role |
|---|---|
| `src/aauth/delegation.py` | Implementation |
| `tests/` | Behaviour and attack coverage |

## 5. Code excerpts

<!-- code: src/aauth/delegation.py::DelegationService -->
```python
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
```
<!-- /code -->

## 6. Configuration

Defaults live in the module and in `config/policy.yaml`.

## 7. Commands

```bash
aauth gate
```

## 8. Real output

<!-- output: gate -->
```text
Auth security release gate

PASS  jwks_active_key: 1 keys
PASS  attack_suite_hardened: 14/14 blocked
PASS  delegation_blocks_overreach: no_overlapping_scopes
PASS  delegation_subset: exceeded=[]
PASS  benchmark_runs: measured ok
PASS  naive_not_in_default_paths: offenders=[]

6/6 checks passed
```
<!-- /output -->

## 9. Tests and gates

Covered by pytest and `aauth gate`. CI runs both.

## 10. Guardrails

Fail closed on validation errors. Naive paths are never default.

## 11. Security and governance

Mapped in [threat-model.md](../threat-model.md). Keys are runtime-only.

## 12. Observability

Failures emit audit events; see [observability.md](../observability.md).

## 13. Failure modes

See [failure-modes.md](../failure-modes.md).

## 14. Mapping to cloud services

| Azure | Google Cloud | AWS |
|---|---|---|
| Entra ID | Identity Platform | IAM Identity Center |
| API Management | Apigee | API Gateway |
| Key Vault | Cloud KMS | KMS |
| Log Analytics | Cloud Logging | CloudWatch |

Also referenced: Entra ID, API Management, Key Vault, Log Analytics, Microsoft Fabric (N/A here), BigQuery (N/A), S3 (N/A).

## 15. Limitations

Offline demo; Entra path written not run; nothing deployed.

## 16. Interview talking points

Explain how agent delegation (obo) fits the end-to-end agent auth story and cite a real number from `aauth benchmark` or `aauth attacks`.

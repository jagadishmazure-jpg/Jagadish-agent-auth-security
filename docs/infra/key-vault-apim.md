# Key Vault and APIM

Signing-key vault and validate-jwt / validate-azure-ad-token Module: `src/aauth/iac.py`.

## 1. Purpose

Signing-key vault and validate-jwt / validate-azure-ad-token Built for Northglass Financial Services (fictional).

## 2. Architecture

```mermaid
flowchart LR
  C[Client] --> M[Key Vault and APIM]
  M --> S[Auth store / JWKS]
```

## 3. How it works

See `src/aauth/iac.py` and the tests under `tests/`.

## 4. Key files

| File | Role |
|---|---|
| `src/aauth/iac.py` | Implementation |
| `tests/` | Behaviour and attack coverage |

## 5. Code excerpts

<!-- code: src/aauth/iac.py::terraform -->
```python
def terraform() -> dict:
    text = "\n".join(p.read_text() for p in sorted(TF.glob("*.tf"))) if TF.exists() else ""
    return {
        "resources": len(re.findall(r'^resource\s+"', text, re.M)),
        "controls": {
            "key_vault": "azurerm_key_vault" in text,
            "entra_apps": "azuread_application" in text,
            "apim": "azurerm_api_management" in text,
            "log_analytics": "azurerm_log_analytics_workspace" in text,
            "no_secrets": "client_secret" not in text.lower() and "account_key" not in text.lower(),
            "rbac_kv": "rbac_authorization_enabled" in text or "rbac_authorization_enabled  = true" in text,
        },
        "test_runs": (TF / "tests" / "plan.tftest.hcl").read_text().count('run "') if (TF / "tests" / "plan.tftest.hcl").exists() else 0,
    }
```
<!-- /code -->

## 6. Configuration

Defaults live in the module and in `config/policy.yaml`.

## 7. Commands

```bash
aauth iac
```

## 8. Real output

<!-- output: iac -->
```text
terraform resources: 9; controls: {'key_vault': True, 'entra_apps': True, 'apim': True, 'log_analytics': True, 'no_secrets': True, 'rbac_kv': True}; test runs: 3
bicep files: 2; controls: {'key_vault': True, 'apim': True, 'log_analytics': True, 'validate_token': True}
workflow ci.yml: read_only=True pinned=8/8 gated=0
workflow codeql.yml: read_only=True pinned=3/3 gated=0
workflow deploy.yml: read_only=True pinned=6/6 gated=5
workflow infra.yml: read_only=True pinned=9/9 gated=0
workflow teardown.yml: read_only=True pinned=3/3 gated=1
controls_ok: True
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

Explain how key vault and apim fits the end-to-end agent auth story and cite a real number from `aauth benchmark` or `aauth attacks`.

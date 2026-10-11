# Observability

`AuditLog` records `login`, `token_issue`, `token_refresh`, `refresh_reuse`, `revoke`, `validate_fail`, `exchange`, `approval` with outcome and reason.

Failures export to the SecurityAlert shape used by [Jagadish-azure-ai-soc](https://github.com/jagadishmazure-jpg/Jagadish-azure-ai-soc). See [soc-integration.md](soc-integration.md).

On Azure, the same events would land in Log Analytics via diagnostic settings on APIM and Entra sign-in / token logs (documented in IaC; not deployed).

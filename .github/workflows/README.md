# Workflows

| File | What it does |
|---|---|
| `ci.yml` | Lint, tests, gate, doc drift, Bicep, SBOM, gitleaks |
| `codeql.yml` | CodeQL for Python and Actions |
| `infra.yml` | Terraform fmt/validate/test, tflint, checkov, optional plan |
| `deploy.yml` | Gated deploy (needs DEPLOY_ENABLED) |
| `teardown.yml` | Gated teardown with confirmation |

# Implementation guide

1. Install: `pip install -e ".[dev]"`
2. Meet the company: `aauth company`
3. Run the comparison: `aauth benchmark`
4. Run the attack matrix: `aauth attacks`
5. Exercise OAuth PKCE and delegation via pytest
6. Read [decision-guide.md](decision-guide.md) and [threat-model.md](threat-model.md)
7. Skim Terraform / Bicep under `infra/` (never apply unless you set `DEPLOY_ENABLED`)

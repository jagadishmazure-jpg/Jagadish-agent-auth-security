# Security policy

This is a portfolio project. Nothing in it is deployed, and it holds no real customer data: every person and organisation is fictional.

## Supported versions

Only the `main` branch is maintained.

## Report a vulnerability

Please report privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**. Private vulnerability reporting is switched on. Please do not open a public issue for a security problem.

Useful details:

- the file and line, or the command that shows the problem
- what an attacker could do with it
- a suggested fix, if you have one

You should get a first reply within a week.

## Security contact request

If private reporting does not work for you, open a public issue titled **Security contact request** with no details of the problem. A private channel will be arranged from there.

## What is in scope

- JWT and session validation (`src/aauth/jwt_tokens.py`, `sessions.py`)
- Refresh rotation and reuse detection (`refresh.py`)
- DPoP and mTLS binding (`dpop.py`, `mtls.py`)
- Delegation / OBO (`delegation.py`): any way for an agent to exceed the user
- MCP and A2A auth (`mcp_auth.py`, `a2a_auth.py`): token passthrough, wrong audience
- The deliberately vulnerable `naive.py` module is labelled and never used by default; finding that it is vulnerable is expected
- Infrastructure and workflows (`infra/`, `.github/`)

The threat model is in [docs/threat-model.md](docs/threat-model.md).

## Controls already in place

- Secret scanning with push protection, Dependabot alerts and security updates, CodeQL, gitleaks in CI
- Every GitHub Action pinned to a commit SHA; workflows read-only by default; cloud access only through OIDC
- checkov and tflint on the Terraform stack; skipped checks are listed with a reason in `.checkov.yaml`
- Signing keys are generated at runtime; none are committed

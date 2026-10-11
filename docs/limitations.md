# Limitations

- Benchmark numbers are from a single-process microbench on one host; they are not a capacity plan.
- The OAuth server is a teaching mock, not a certified OIDC provider.
- Entra / MSAL paths are written and documented, never run against a tenant from this repo.
- JWE (encrypted claims) is planned, not built; today we keep PII out of claims instead.
- PII detection is not applied; principals are synthetic.
- APIM and Key Vault exist only as IaC.
- The Agent Framework agent uses a deterministic mock chat client.

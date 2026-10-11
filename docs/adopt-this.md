# Adopt this

## When it fits

You need a reference for hardening tokens and sessions, teaching JWT attacks safely, or wiring agent delegation with audience-per-tool rules on Azure.

## Adopt

1. Copy `jwt_tokens`, `sessions`, `refresh`, `dpop` and the store into your service
2. Keep the attack tests; point them at your verifier
3. Replace the local AS with Entra ID using `entra.py` notes
4. Put APIM `validate-jwt` in front of public APIs
5. Emit audit events into your SIEM using `soc.py` as a template

## Do not adopt blindly

- Do not deploy the sample APIM Developer SKU without a budget
- Do not use `naive.py` outside tests
- Do not store access tokens in `localStorage`

# ADR 0006: Deploy is gated off

**Status:** Accepted

## Context

Past practice resources on a learning subscription produced unexpected bills. Portfolio IaC must never apply by surprise.

## Decision

`DEPLOY_ENABLED` must equal `true` for deploy and teardown jobs. Default is unset. OIDC only; no client secrets. Docs say nothing is deployed.

## Consequences

CI still validates, plans (when credentials exist), and builds Bicep. Apply never runs from this repository as published.

# ADR 0002: Short-lived access tokens with a version claim

**Status:** Accepted

## Context

Stateless JWTs cannot be revoked instantly without shared state. Role changes leave stale claims until expiry.

## Decision

Access tokens live five minutes. A `tv` (token version) claim must match the store; bumping the version rejects outstanding tokens. A denylist covers explicit revocation by `jti`. Refresh tokens rotate with reuse detection (OAuth 2.1).

## Consequences

We are not purely stateless. The store is small (versions + denylist + refresh), not full session blobs.

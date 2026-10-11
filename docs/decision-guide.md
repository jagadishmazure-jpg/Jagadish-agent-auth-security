# Which one should I use?

## JWT vs server sessions vs opaque tokens

| Need | Prefer |
|---|---|
| Many resource servers, local verify | JWT (with denylist/version for revoke) |
| Instant revoke and server-rendered HTML | Server session |
| Hide all claims from the client | Opaque token + introspection (RFC 7662) |
| SPA in the browser | BFF pattern: session cookie to BFF, JWT from BFF to APIs |
| Service to service | Managed identity / client credentials JWT |
| Agent calling a tool | Delegated JWT with tool audience (no passthrough) |

## BFF for SPAs

Storing access tokens in `localStorage` loses to XSS. Prefer a backend-for-frontend that holds the session in an HttpOnly cookie and attaches tokens server-side. The attack matrix row "JWT in localStorage" records that design choice.

## Sender-constrained tokens

Use DPoP (RFC 9449) for public clients and mTLS-bound tokens (RFC 8705) for confidential services when bearer theft is in scope.

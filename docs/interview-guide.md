# Interview talking points

- Measured JWT vs sessions instead of repeating the article table; on an in-memory store, session lookup was faster than RS256 verify — an honest caveat about "JWT is always faster".
- Revocation and stale claims need shared state even with JWTs (`jti` denylist + `tv` version).
- Classic JWT attacks are tests; the naive module is isolated and gated out of default paths.
- Agents get `user ∩ agent ∩ requested` scopes with `act` claims; high-risk scopes need a human.
- MCP: no token passthrough; audience per resource (RFC 8707 / 9728).
- Deploy is gated; nothing is deployed; keys are generated at runtime.

# ADR 0001: JWT and sessions side by side

**Status:** Accepted

## Context

An article table compared JWTs with server sessions across scalability, performance, revocation, updates, data security, complexity, best-for and avoid-if. Recruiters see JWT-only demos often; measuring both is more honest.

## Decision

Implement the same Loan API behind both a hardened JWT path and a hardened session path, and ship a benchmark that fills every row of the comparison from a real local run.

## Consequences

Docs show numbers from this host, with caveats. Neither path is declared universally better.

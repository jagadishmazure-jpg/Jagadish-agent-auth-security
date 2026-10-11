# ADR 0005: Isolate the deliberately vulnerable module

**Status:** Accepted

## Context

Attack demos need a path where classic JWT bugs still succeed, so the matrix can show blocked vs accepted.

## Decision

Put vulnerable helpers in `aauth.naive`, labelled DELIBERATELY VULNERABLE / NEVER USED BY DEFAULT. The release gate fails if `api`, `oauth_server`, `delegation`, `mcp_auth` or `a2a_auth` import it.

## Consequences

Readers can see both sides of each attack without risking a default insecure path.

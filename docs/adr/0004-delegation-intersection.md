# ADR 0004: Delegation is the intersection of scopes

**Status:** Accepted

## Context

Agents acting for users must not gain power the user lacks, nor keep power the agent was not granted.

## Decision

Downstream tokens receive `user_scopes ∩ agent_scopes ∩ requested_scopes`. High-risk scopes need a recorded human approval. The `act` claim identifies the agent (RFC 8693).

## Consequences

Tests assert `agent_exceeds_user` is always empty for successful exchanges.

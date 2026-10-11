# ADR 0003: No token passthrough for MCP

**Status:** Accepted

## Context

The MCP authorization guidance forbids forwarding a caller's token to a downstream API. Passthrough makes audience and consent meaningless.

## Decision

The MCP resource accepts only tokens whose `aud` is the MCP audience. Agents obtain a new token via exchange (RFC 8693) per tool audience. Resource indicators (RFC 8707) and protected resource metadata (RFC 9728) are published.

## Consequences

Every hop has its own audience. Tests fail if an API-audience token reaches an MCP tool.

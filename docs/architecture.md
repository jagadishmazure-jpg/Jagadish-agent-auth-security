# Architecture

End-to-end auth for users and AI agents at **Northglass Financial Services** (fictional).

```mermaid
flowchart TB
  subgraph clients [Clients]
    SPA[Loan portal SPA / BFF]
    Agent[Loan Assistant agent]
    Svc[Batch service]
  end
  subgraph as [Authorization]
    LocalAS[Local OAuth 2.1 AS]
    Entra[Entra ID adapter]
    Keys[JWKS key ring]
  end
  subgraph rs [Resource servers]
    API[Loan API JWT + sessions]
    MCP[MCP server]
    A2A[A2A peer]
  end
  subgraph shared [Shared state]
    Store[Versions denylist refresh sessions]
  end
  SPA --> LocalAS
  SPA --> API
  Agent --> LocalAS
  Agent -->|RFC 8693 exchange| API
  Agent --> MCP
  Svc -->|client credentials| LocalAS
  LocalAS --> Keys
  API --> Keys
  API --> Store
  MCP --> Keys
  Entra -.->|written not run| LocalAS
```

See [components](components/) for per-piece detail and [decision-guide.md](decision-guide.md) for when to pick JWT, sessions or opaque tokens.

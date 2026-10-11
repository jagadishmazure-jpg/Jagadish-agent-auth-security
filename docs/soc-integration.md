# SOC integration

Auth failures export to the SecurityAlert shape consumed by [Jagadish-azure-ai-soc](https://github.com/jagadishmazure-jpg/Jagadish-azure-ai-soc). Companion posture findings come from [Jagadish-agent-identity-security](https://github.com/jagadishmazure-jpg/Jagadish-agent-identity-security).

```mermaid
sequenceDiagram
  participant API as aauth API
  participant L as AuditLog
  participant E as aauth soc-export
  participant S as azure-ai-soc
  API->>L: validate_fail
  L->>E: failures()
  E->>E: map technique severity entity
  E->>S: SecurityAlert rows
```

## Try it

```bash
aauth soc-export
```

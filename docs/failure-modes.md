# Failure modes

| Failure | What the user sees | System behaviour |
|---|---|---|
| Expired access token | 401 `expired` | Refresh with rotated refresh token |
| Refresh reuse | 401; family revoked | Re-login required |
| Role change mid-flight | 401 `stale_token_version` | New login or silent re-issue |
| Missing DPoP proof | 401 `dpop_*` | Retry with proof |
| Agent asks for user-only scope | exchange error `no_overlapping_scopes` | Narrow the request |
| High-risk without approval | `approval_required` | Human approves, then retry |
| CSRF mismatch | 401 | Reload form to get new CSRF |
| Absolute session timeout | 401 | Login again |

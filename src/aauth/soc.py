"""Export auth audit failures as SOC alerts for Jagadish-azure-ai-soc.

Rows follow the SecurityAlert shape that `aisoc.detections.product_alerts` reads.
"""

from __future__ import annotations

from datetime import UTC, datetime

from aauth.audit import AuditLog

PRODUCT = "Agent Auth Security"
# Map auth failure reasons to ATT&CK techniques where the fit is honest.
TECHNIQUES = {
    "alg_not_allowed": ["T1606.002"],  # Forge web credentials: SAML/token (closest)
    "bad_signature": ["T1606"],
    "expired": [],
    "wrong_audience": ["T1606"],
    "revoked": ["T1550.001"],  # Use Alternate Authentication Material: Application Access Token
    "reuse_detected": ["T1550.001"],
    "csrf_mismatch": ["T1185"],
    "missing_bearer": ["T1078"],
    "dpop_jkt_mismatch": ["T1550.001"],
    "peer_not_allowed": ["T1078.004"],
    "no_overlapping_scopes": [],
    "approval_required": [],
    "stale_token_version": ["T1550.001"],
    "insufficient_scope": ["T1078"],
}
TACTICS = {
    "T1606": ["CredentialAccess"],
    "T1606.002": ["CredentialAccess"],
    "T1550.001": ["DefenseEvasion", "LateralMovement"],
    "T1185": ["Collection"],
    "T1078": ["DefenseEvasion", "Persistence", "PrivilegeEscalation", "InitialAccess"],
    "T1078.004": ["DefenseEvasion", "Persistence", "PrivilegeEscalation", "InitialAccess"],
}
SEVERITY = {
    "alg_not_allowed": "High",
    "bad_signature": "High",
    "reuse_detected": "High",
    "dpop_jkt_mismatch": "High",
    "csrf_mismatch": "Medium",
    "wrong_audience": "Medium",
    "revoked": "Medium",
    "stale_token_version": "Medium",
    "peer_not_allowed": "Medium",
    "insufficient_scope": "Low",
    "missing_bearer": "Low",
    "expired": "Low",
}
REQUIRED = (
    "TimeGenerated",
    "SystemAlertId",
    "AlertName",
    "ProductName",
    "ProviderName",
    "AlertSeverity",
    "Techniques",
    "Tactics",
    "Entities",
    "Description",
    "EventIds",
)


def export(log: AuditLog, now: datetime | None = None) -> list[dict]:
    ts = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = []
    for i, e in enumerate(log.failures()):
        reason = e.reason or e.event
        techniques = list(TECHNIQUES.get(reason.split(":")[0], []))
        tactics = sorted({t for tech in techniques for t in TACTICS.get(tech, [])})
        rows.append(
            {
                "TimeGenerated": ts,
                "SystemAlertId": f"aauth-{i:04d}-{e.token_id or e.subject or 'anon'}"[:64],
                "AlertName": f"Auth failure: {e.event} ({reason})",
                "ProductName": PRODUCT,
                "ProviderName": PRODUCT,
                "AlertSeverity": SEVERITY.get(reason.split(":")[0], "Low"),
                "Techniques": techniques,
                "Tactics": tactics,
                "Entities": [{"Type": "account", "Name": e.subject or "unknown"}],
                "Description": f"Auth event {e.event} failed: {reason}. client={e.client_id or '-'}",
                "EventIds": [],
                "ExtendedProperties": {"event": e.event, "reason": reason, "scopes": e.scopes},
            }
        )
    return rows


def validate(rows: list[dict]) -> list[str]:
    problems = []
    for r in rows:
        missing = [k for k in REQUIRED if k not in r]
        if missing:
            problems.append(f"{r.get('SystemAlertId')}: missing {missing}")
        if r.get("AlertSeverity") not in ("Low", "Medium", "High"):
            problems.append(f"{r.get('SystemAlertId')}: severity")
    return problems

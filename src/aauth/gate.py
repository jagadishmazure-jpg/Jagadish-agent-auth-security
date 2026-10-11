"""Release gate: offline checks that must all pass before a release is honest."""

from __future__ import annotations

from aauth import attacks, benchmark, jwt_tokens
from aauth.company import COMPANY
from aauth.delegation import DelegationService
from aauth.keys import KeyRing
from aauth.store import AuthStore


def run() -> list[tuple[str, bool, str]]:
    checks: list[tuple[str, bool, str]] = []
    ring = KeyRing.create(COMPANY.issuer, seed=3)
    store = AuthStore.memory()

    # 1. JWKS has an active key
    jwks = ring.jwks()
    checks.append(("jwks_active_key", len(jwks["keys"]) >= 1, f"{len(jwks['keys'])} keys"))

    # 2. Attack suite: every hardened result starts with blocked
    results = attacks.run_all()
    bad = [r for r in results if not r.hardened.startswith("blocked")]
    checks.append(("attack_suite_hardened", not bad, f"{len(results) - len(bad)}/{len(results)} blocked"))

    # 3. Delegation never exceeds user
    user = COMPANY.principals["u-ava"]
    agent = COMPANY.principals["a-loan"]
    user_tok = jwt_tokens.issue(ring, sub=user.id, audience=COMPANY.audience_api, scopes=list(user.scopes), roles=list(user.roles), store=store)
    dele = DelegationService(ring=ring, store=store, tool_audiences={"summarize_loan": COMPANY.audience_mcp})
    try:
        # Agent asks for loans:decide which user doesn't have and agent doesn't have
        dele.exchange(
            subject_token=user_tok.token,
            agent=agent,
            requested_scopes=["loans:decide"],
            target_audience=COMPANY.audience_mcp,
        )
        checks.append(("delegation_blocks_overreach", False, "should have raised"))
    except jwt_tokens.TokenError as e:
        checks.append(("delegation_blocks_overreach", e.reason == "no_overlapping_scopes", e.reason))

    at = dele.exchange(
        subject_token=user_tok.token,
        agent=agent,
        requested_scopes=["loans:read", "tools:summarize"],
        target_audience=COMPANY.audience_mcp,
        tool_id="summarize_loan",
    )
    exceeded = dele.agent_exceeds_user(user_tok.token, at.token, COMPANY.audience_mcp)
    checks.append(("delegation_subset", exceeded == [], f"exceeded={exceeded}"))

    # 4. Benchmark runs and JWT p50 is finite
    m = benchmark.measure(iterations=50)
    checks.append(("benchmark_runs", m["jwt_verify_p50_ms"] >= 0 and m["session_lookup_p50_ms"] >= 0, "measured ok"))

    # 5. Naive module is not imported by api/oauth/delegation
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parent
    offenders = []
    for name in ("api.py", "oauth_server.py", "delegation.py", "mcp_auth.py", "a2a_auth.py"):
        tree = ast.parse((root / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "naive" in node.module:
                offenders.append(name)
            if isinstance(node, ast.Import):
                for a in node.names:
                    if "naive" in a.name:
                        offenders.append(name)
    checks.append(("naive_not_in_default_paths", not offenders, f"offenders={offenders}"))

    return checks


def render(checks: list[tuple[str, bool, str]]) -> str:
    lines = ["Auth security release gate", ""]
    for name, ok, detail in checks:
        lines.append(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")
    passed = sum(1 for _, ok, _ in checks if ok)
    lines.append("")
    lines.append(f"{passed}/{len(checks)} checks passed")
    return "\n".join(lines)

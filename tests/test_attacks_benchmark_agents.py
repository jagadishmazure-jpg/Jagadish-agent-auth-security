"""Attack matrix, benchmark, agent delegation, SOC export, gate."""

from aauth import attacks, benchmark, gate, jwt_tokens, soc
from aauth.agents import approve_high_risk, run_loan_assistant
from aauth.audit import AuditLog
from aauth.company import COMPANY
from aauth.delegation import DelegationService


def test_attack_matrix_all_hardened_blocked():
    results = attacks.run_all()
    assert len(results) == 14
    for r in results:
        assert r.hardened.startswith("blocked"), r
    # Classic bugs accepted on naive path
    by_name = {r.attack: r for r in results}
    assert by_name["alg=none"].naive == "accepted"
    assert by_name["RS256-to-HS256 key confusion"].naive == "accepted"
    assert "password" in by_name["weak HMAC brute force"].naive


def test_benchmark_produces_comparison_rows():
    m = benchmark.measure(iterations=30)
    rows = benchmark.comparison_table(m)
    assert len(rows) == 8
    md = benchmark.render_markdown(m)
    assert "Performance" in md and "Revocation" in md
    assert m["jwt_verify_p50_ms"] > 0


def test_agent_never_exceeds_user(ring, store):
    user = COMPANY.principals["u-ava"]
    agent = COMPANY.principals["a-loan"]
    user_tok = jwt_tokens.issue(ring, sub=user.id, audience=COMPANY.audience_api, scopes=list(user.scopes), roles=list(user.roles), store=store)
    dele = DelegationService(ring=ring, store=store, tool_audiences={"summarize_loan": COMPANY.audience_mcp})
    result = run_loan_assistant(dele, user_token=user_tok.token, agent=agent, user_text="Please summarize loan L-1001")
    assert result.exceeded_user == []
    assert "loans:read" in result.scopes_used
    assert result.tool == "summarize_loan"


def test_high_risk_approval_helper(ring, store):
    dele = DelegationService(ring=ring, store=store)
    ap = approve_high_risk(dele, user_sub="u-ben", agent_id="a-tmp", scopes=["loans:decide"], approver="u-cara")
    assert ap.approval_id in dele.approvals


def test_soc_export_schema():
    log = AuditLog()
    log.emit("validate_fail", "failure", subject="u-ava", reason="alg_not_allowed:none", token_id="t1")
    log.emit("validate_fail", "failure", subject="u-ava", reason="wrong_audience", token_id="t2")
    rows = soc.export(log)
    assert soc.validate(rows) == []
    assert rows[0]["ProductName"] == "Agent Auth Security"
    assert rows[0]["AlertSeverity"] == "High"


def test_gate_passes():
    checks = gate.run()
    assert all(ok for _, ok, _ in checks), gate.render(checks)

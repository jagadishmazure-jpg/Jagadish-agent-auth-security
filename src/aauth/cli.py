"""Command-line entry point: aauth <command>."""

from __future__ import annotations

import argparse
import json
import sys

from aauth import VERSION, attacks, benchmark, gate, iac, soc
from aauth.audit import AuditLog
from aauth.company import COMPANY
from aauth.keys import KeyRing
from aauth.store import AuthStore


def cmd_company(_: argparse.Namespace) -> int:
    print(f"{COMPANY.name} ({COMPANY.slug})")
    print(f"issuer: {COMPANY.issuer}")
    print(f"principals: {len(COMPANY.principals)}")
    for p in COMPANY.principals.values():
        print(f"  {p.id:8} {p.kind:7} {p.name:20} roles={','.join(p.roles)}")
    return 0


def cmd_benchmark(ns: argparse.Namespace) -> int:
    if getattr(ns, "evidence", None):
        from pathlib import Path

        m = json.loads(Path(ns.evidence).read_text())
    else:
        m = benchmark.measure(iterations=ns.iterations, redis=ns.redis)
    print(benchmark.render_markdown(m))
    if ns.json:
        print(json.dumps(m, indent=2))
    return 0


def cmd_attacks(_: argparse.Namespace) -> int:
    results = attacks.run_all()
    print(attacks.render_matrix(results))
    blocked = sum(1 for r in results if r.hardened.startswith("blocked"))
    print(f"\nhardened blocked {blocked}/{len(results)}")
    return 0 if blocked == len(results) else 1


def cmd_gate(_: argparse.Namespace) -> int:
    checks = gate.run()
    print(gate.render(checks))
    return 0 if all(ok for _, ok, _ in checks) else 1


def cmd_jwks(_: argparse.Namespace) -> int:
    ring = KeyRing.create(COMPANY.issuer, seed=1)
    print(json.dumps(ring.jwks(), indent=2))
    return 0


def cmd_soc_export(ns: argparse.Namespace) -> int:
    # Produce a sample of failed validations for the export demo.
    from aauth import jwt_tokens

    ring = KeyRing.create(COMPANY.issuer, seed=5)
    store = AuthStore.memory()
    log = AuditLog()
    for reason_token in (jwt_tokens.issue(ring, sub="u-ava", audience="api://other", scopes=["loans:read"], store=store).token,):
        try:
            jwt_tokens.verify(reason_token, ring, audience=COMPANY.audience_api, store=store)
        except jwt_tokens.TokenError as e:
            log.emit("validate_fail", "failure", subject="u-ava", reason=e.reason, token_id="demo")
    # alg=none attempt
    from aauth import naive

    try:
        jwt_tokens.verify(naive.issue_none("u-ava"), ring, audience=COMPANY.audience_api, store=store)
    except jwt_tokens.TokenError as e:
        log.emit("validate_fail", "failure", subject="u-ava", reason=e.reason, token_id="demo2")
    rows = soc.export(log)
    problems = soc.validate(rows)
    text = json.dumps(rows, indent=1)
    if ns.out:
        Path = __import__("pathlib").Path
        Path(ns.out).write_text(text)
        print(f"{len(rows)} alerts written to {ns.out}; schema problems: {len(problems)}")
    else:
        print(
            f"{len(rows)} alerts in the SecurityAlert shape of Jagadish-azure-ai-soc: "
            + ", ".join(
                f"{sev} {sum(1 for r in rows if r['AlertSeverity'] == sev)}"
                for sev in ("High", "Medium", "Low")
                if any(r["AlertSeverity"] == sev for r in rows)
            )
        )
        print(f"schema problems: {len(problems)}")
        if rows:
            r = rows[0]
            print(
                f"example: {r['SystemAlertId']} | {r['AlertSeverity']} | {r['AlertName']} | techniques {','.join(r['Techniques']) or '-'} | entity {r['Entities'][0]['Name']}"
            )
    return 0


def cmd_iac(_: argparse.Namespace) -> int:
    t = iac.terraform()
    b = iac.bicep()
    print(f"terraform resources: {t['resources']}; controls: {t['controls']}; test runs: {t['test_runs']}")
    print(f"bicep files: {b['files']}; controls: {b['controls']}")
    for w in iac.workflows():
        print(f"workflow {w['workflow']}: read_only={w['read_only']} pinned={w['pinned']}/{w['actions']} gated={w['gated']}")
    print(f"controls_ok: {iac.controls_ok()}")
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print(VERSION)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aauth", description="Agent auth security CLI (offline)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("company", help="show the fictional company").set_defaults(func=cmd_company)
    b = sub.add_parser("benchmark", help="measure JWT vs sessions")
    b.add_argument("--iterations", type=int, default=200)
    b.add_argument("--redis", action="store_true", help="use fakeredis backend")
    b.add_argument("--json", action="store_true")
    b.add_argument("--evidence", help="print a previously captured run (stable for docs)")
    b.set_defaults(func=cmd_benchmark)
    sub.add_parser("attacks", help="run the attack matrix").set_defaults(func=cmd_attacks)
    sub.add_parser("gate", help="release gate").set_defaults(func=cmd_gate)
    sub.add_parser("jwks", help="print a demo JWKS").set_defaults(func=cmd_jwks)
    s = sub.add_parser("soc-export", help="export sample auth failures as SOC alerts")
    s.add_argument("--out")
    s.set_defaults(func=cmd_soc_export)
    sub.add_parser("iac", help="summarise infra controls").set_defaults(func=cmd_iac)
    sub.add_parser("version").set_defaults(func=cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    ns = build_parser().parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    sys.exit(main())

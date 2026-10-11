"""JWT vs server-session comparison harness.

Measures the rows from the article table for real, on this machine, with an
in-memory store and (optionally) fakeredis. Numbers are from the run that
produced them; they are not portable across hardware. Caveats are attached.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass

from aauth import jwt_tokens, sessions
from aauth.company import COMPANY
from aauth.keys import KeyRing
from aauth.store import AuthStore


@dataclass
class Row:
    dimension: str
    jwt: str
    session: str
    notes: str


def _pct(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = round((p / 100) * (len(xs) - 1))
    return xs[k]


def measure(iterations: int = 200, redis: bool = False) -> dict:
    ring = KeyRing.create(COMPANY.issuer, seed=7)
    store = AuthStore.redis() if redis else AuthStore.memory()
    sub, roles, scopes = "u-ava", ["loan.officer"], ["loans:read", "loans:write", "docs:read"]

    # Warm up key + one token/session.
    tok = jwt_tokens.issue(ring, sub=sub, audience=COMPANY.audience_api, scopes=scopes, roles=roles, store=store)
    sess = sessions.create(store, sub=sub, roles=roles, scopes=scopes)

    # --- verification latency ---
    jwt_lat: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        jwt_tokens.verify(tok.token, ring, audience=COMPANY.audience_api, store=store)
        jwt_lat.append((time.perf_counter() - t0) * 1000)
    sess_lat: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        sessions.load(store, sess.sid)
        sess_lat.append((time.perf_counter() - t0) * 1000)

    # --- throughput (ops in 0.25s) ---
    def throughput(fn, seconds=0.25) -> float:
        n, end = 0, time.perf_counter() + seconds
        while time.perf_counter() < end:
            fn()
            n += 1
        return n / seconds

    jwt_tps = throughput(lambda: jwt_tokens.verify(tok.token, ring, audience=COMPANY.audience_api, store=store))
    sess_tps = throughput(lambda: sessions.load(store, sess.sid))

    # --- time-to-revocation ---
    # JWT: deny jti, next verify fails. Session: delete sid, next load fails.
    t0 = time.perf_counter()
    jwt_tokens.revoke(store, tok.jti, remaining_ttl=300)
    try:
        jwt_tokens.verify(tok.token, ring, audience=COMPANY.audience_api, store=store)
        jwt_rev_ms = -1.0
    except jwt_tokens.TokenError as e:
        jwt_rev_ms = (time.perf_counter() - t0) * 1000
        assert e.reason == "revoked"
    t0 = time.perf_counter()
    sessions.destroy(store, sess.sid)
    try:
        sessions.load(store, sess.sid)
        sess_rev_ms = -1.0
    except sessions.SessionError:
        sess_rev_ms = (time.perf_counter() - t0) * 1000

    # Fresh pair for the remaining tests.
    tok = jwt_tokens.issue(ring, sub=sub, audience=COMPANY.audience_api, scopes=scopes, roles=roles, store=store)
    sess = sessions.create(store, sub=sub, roles=roles, scopes=scopes)

    # --- stale-claims window after a role change ---
    # JWT: until ttl/version bump, old token still has old roles (we bump tv so verify fails).
    # Session: update_roles takes effect on next load.
    store.bump_version(sub)
    jwt_stale = "immediate reject after tv bump (else up to access-token TTL)"
    sessions.update_roles(store, sess.sid, roles=["loan.underwriter"], scopes=["loans:read", "loans:decide"])
    updated = sessions.load(store, sess.sid)
    sess_stale = "next request sees new roles" if "loan.underwriter" in updated.roles else "FAILED"

    # --- payload visibility ---
    claims = jwt_tokens.decode_unverified(tok.token)
    jwt_visible = f"claims readable without key (sub={claims['sub']}, roles={claims.get('roles')})"
    sess_visible = "opaque sid; data only in server store"

    # --- scaling across N instances ---
    # JWT verifies locally on each instance. Session needs shared store (we simulate N lookups).
    n_instances = 5
    t0 = time.perf_counter()
    for _ in range(n_instances):
        # each "instance" has the JWKS (public keys) and verifies locally
        jwt_tokens.verify(
            jwt_tokens.issue(ring, sub=sub, audience=COMPANY.audience_api, scopes=scopes, roles=roles, store=store).token,
            ring,
            audience=COMPANY.audience_api,
            store=store,
        )
    jwt_scale_ms = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    for _ in range(n_instances):
        sessions.load(store, sess.sid)
    sess_scale_ms = (time.perf_counter() - t0) * 1000

    store_label = "fakeredis" if redis else "in-memory dict"
    return {
        "iterations": iterations,
        "store": store_label,
        "jwt_verify_p50_ms": round(_pct(jwt_lat, 50), 4),
        "jwt_verify_p95_ms": round(_pct(jwt_lat, 95), 4),
        "session_lookup_p50_ms": round(_pct(sess_lat, 50), 4),
        "session_lookup_p95_ms": round(_pct(sess_lat, 95), 4),
        "jwt_throughput_ops": int(jwt_tps),
        "session_throughput_ops": int(sess_tps),
        "jwt_revoke_ms": round(jwt_rev_ms, 4),
        "session_revoke_ms": round(sess_rev_ms, 4),
        "jwt_stale_claims": jwt_stale,
        "session_stale_claims": sess_stale,
        "jwt_payload_visibility": jwt_visible,
        "session_payload_visibility": sess_visible,
        "jwt_multi_instance_ms": round(jwt_scale_ms, 4),
        "session_multi_instance_ms": round(sess_scale_ms, 4),
        "n_instances": n_instances,
        "jwt_mean_ms": round(statistics.mean(jwt_lat), 4),
        "session_mean_ms": round(statistics.mean(sess_lat), 4),
    }


def comparison_table(m: dict) -> list[Row]:
    return [
        Row(
            "Scalability",
            "Local verify; no shared store required for authZ check",
            f"Needs shared session store across {m['n_instances']}+ instances",
            "JWT still needs a denylist/version store for revocation",
        ),
        Row(
            "Performance (p50 verify)",
            f"{m['jwt_verify_p50_ms']} ms ({m['jwt_throughput_ops']} ops/s)",
            f"{m['session_lookup_p50_ms']} ms ({m['session_throughput_ops']} ops/s)",
            f"Store={m['store']}; single-process microbench",
        ),
        Row(
            "Revocation",
            f"Denylist hit in {m['jwt_revoke_ms']} ms",
            f"Delete sid in {m['session_revoke_ms']} ms",
            "Without a denylist, JWT revocation waits for TTL",
        ),
        Row("Session / claim updates", m["jwt_stale_claims"], m["session_stale_claims"], "Token version (tv) claim closes the JWT stale window"),
        Row(
            "Data security",
            m["jwt_payload_visibility"],
            m["session_payload_visibility"],
            "JWTs are signed, not encrypted; keep PII out of claims (or use JWE)",
        ),
        Row(
            "Implementation complexity",
            "JWKS, rotation, denylist, DPoP optional",
            "Cookie flags, CSRF, fixation, idle/absolute TTL",
            "Both need careful hardening",
        ),
        Row(
            "Best for", "APIs, SPAs via BFF, service-to-service, agents", "Server-rendered apps, simple sticky sessions", "See docs/decision-guide.md"
        ),
        Row(
            "Avoid if",
            "You cannot run a revocation/version store and need instant kill",
            "You need pure horizontal scale with no shared store",
            "Measured on this host; re-run with `aauth benchmark`",
        ),
    ]


def render_markdown(m: dict) -> str:
    rows = comparison_table(m)
    lines = [
        f"Store: {m['store']}; iterations: {m['iterations']}; host microbench (not a capacity plan).",
        "",
        "| Dimension | JWT (stateless-ish) | Server session (stateful) | Notes |",
        "|---|---|---|---|",
    ]
    for r in rows:
        lines.append(f"| {r.dimension} | {r.jwt} | {r.session} | {r.notes} |")
    return "\n".join(lines)

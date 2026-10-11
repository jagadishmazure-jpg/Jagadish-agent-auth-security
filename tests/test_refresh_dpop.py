"""Refresh rotation and DPoP / mTLS binding."""

import pytest

from aauth import dpop, jwt_tokens, mtls, refresh
from aauth.company import COMPANY


def test_refresh_rotation_and_reuse(store):
    rt = refresh.issue(store, sub="u-ava", scopes=["loans:read"])
    nxt = refresh.rotate(store, rt.token)
    assert nxt.family == rt.family and nxt.jti != rt.jti
    with pytest.raises(refresh.RefreshError, match="reuse"):
        refresh.rotate(store, rt.token)
    assert refresh.family_revoked(store, rt.family)


def test_dpop_roundtrip(ring, store):
    key = dpop.generate_key()
    tok = jwt_tokens.issue(ring, sub="u-ava", audience=COMPANY.audience_api, scopes=["loans:read"], store=store, cnf={"jkt": key.jkt})
    claims = jwt_tokens.verify(tok.token, ring, audience=COMPANY.audience_api, store=store, require_cnf="jkt")
    proof = dpop.proof(key, method="GET", url="https://api.northglass.example/loans", access_token=tok.token)
    dpop.verify_proof(proof, method="GET", url="https://api.northglass.example/loans", expected_jkt=claims["cnf"]["jkt"], access_token=tok.token)


def test_dpop_rejects_stolen_bearer(ring, store):
    key = dpop.generate_key()
    other = dpop.generate_key()
    tok = jwt_tokens.issue(ring, sub="u-ava", audience=COMPANY.audience_api, scopes=["loans:read"], store=store, cnf={"jkt": key.jkt})
    claims = jwt_tokens.verify(tok.token, ring, audience=COMPANY.audience_api, store=store, require_cnf="jkt")
    bad = dpop.proof(other, method="GET", url="https://api.northglass.example/loans", access_token=tok.token)
    with pytest.raises(jwt_tokens.TokenError, match="jkt_mismatch"):
        dpop.verify_proof(bad, method="GET", url="https://api.northglass.example/loans", expected_jkt=claims["cnf"]["jkt"], access_token=tok.token)


def test_mtls_binding(ring, store):
    cert = b"fake-der-cert-for-northglass-demo"
    tok = jwt_tokens.issue(ring, sub="u-ava", audience=COMPANY.audience_api, scopes=["loans:read"], store=store, cnf=mtls.cnf_claim(cert))
    claims = jwt_tokens.verify(tok.token, ring, audience=COMPANY.audience_api, store=store, require_cnf="x5t#S256")
    mtls.verify_binding(claims, mtls.thumbprint(cert))
    with pytest.raises(jwt_tokens.TokenError, match="thumbprint"):
        mtls.verify_binding(claims, "AAAA")

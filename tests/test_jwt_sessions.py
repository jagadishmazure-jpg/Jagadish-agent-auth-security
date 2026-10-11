"""JWT and session hardening."""

import time

import pytest

from aauth import jwt_tokens, sessions
from aauth.company import COMPANY


def test_issue_and_verify(ring, store):
    tok = jwt_tokens.issue(ring, sub="u-ava", audience=COMPANY.audience_api, scopes=["loans:read"], roles=["loan.officer"], store=store)
    claims = jwt_tokens.verify(tok.token, ring, audience=COMPANY.audience_api, store=store)
    assert claims["sub"] == "u-ava" and "loans:read" in claims["scope"]


def test_rejects_wrong_audience(ring, store):
    tok = jwt_tokens.issue(ring, sub="u-ava", audience="api://other", scopes=["loans:read"], store=store)
    with pytest.raises(jwt_tokens.TokenError, match="wrong_audience"):
        jwt_tokens.verify(tok.token, ring, audience=COMPANY.audience_api, store=store)


def test_rejects_expired(ring, store):
    import jwt as pyjwt

    tok = pyjwt.encode(
        {
            "sub": "u-ava",
            "aud": COMPANY.audience_api,
            "iss": COMPANY.issuer,
            "exp": int(time.time()) - 50,
            "iat": int(time.time()) - 100,
            "nbf": int(time.time()) - 100,
            "jti": "e",
            "tv": 0,
            "scope": "loans:read",
            "roles": [],
        },
        ring.active_key().private_pem,
        algorithm="RS256",
        headers={"kid": ring.active_key().kid},
    )
    with pytest.raises(jwt_tokens.TokenError, match="expired"):
        jwt_tokens.verify(tok, ring, audience=COMPANY.audience_api, store=store)


def test_revocation(ring, store):
    tok = jwt_tokens.issue(ring, sub="u-ava", audience=COMPANY.audience_api, scopes=["loans:read"], store=store)
    jwt_tokens.revoke(store, tok.jti, 300)
    with pytest.raises(jwt_tokens.TokenError, match="revoked"):
        jwt_tokens.verify(tok.token, ring, audience=COMPANY.audience_api, store=store)


def test_token_version_stale_claims(ring, store):
    tok = jwt_tokens.issue(ring, sub="u-ava", audience=COMPANY.audience_api, scopes=["loans:read"], store=store)
    store.bump_version("u-ava")
    with pytest.raises(jwt_tokens.TokenError, match="stale_token_version"):
        jwt_tokens.verify(tok.token, ring, audience=COMPANY.audience_api, store=store)


def test_jwks_rotation_keeps_old_kid(ring, store):
    tok = jwt_tokens.issue(ring, sub="u-ava", audience=COMPANY.audience_api, scopes=["loans:read"], store=store)
    old_kid = ring.active_key().kid
    ring.rotate()
    assert ring.active_key().kid != old_kid
    assert len(ring.jwks()["keys"]) == 2
    claims = jwt_tokens.verify(tok.token, ring, audience=COMPANY.audience_api, store=store)
    assert claims["sub"] == "u-ava"


def test_decode_unverified_shows_claims(ring, store):
    tok = jwt_tokens.issue(ring, sub="u-ava", audience=COMPANY.audience_api, scopes=["loans:read"], roles=["loan.officer"], store=store)
    raw = jwt_tokens.decode_unverified(tok.token)
    assert raw["roles"] == ["loan.officer"]


def test_session_create_load_destroy(store):
    sess = sessions.create(store, sub="u-ava", roles=["loan.officer"], scopes=["loans:read"])
    loaded = sessions.load(store, sess.sid)
    assert loaded.sub == "u-ava"
    sessions.destroy(store, sess.sid)
    with pytest.raises(sessions.SessionError):
        sessions.load(store, sess.sid)


def test_session_csrf_and_cookie_flags(store):
    sess = sessions.create(store, sub="u-ava", roles=["loan.officer"], scopes=["loans:read"])
    with pytest.raises(sessions.SessionError, match="csrf"):
        sessions.check_csrf(sess, "nope")
    sessions.check_csrf(sess, sess.csrf)
    hdr = sessions.cookie_header(sess.sid)
    assert "HttpOnly" in hdr and "Secure" in hdr and "SameSite=Lax" in hdr


def test_session_fixation_defence(store):
    a = sessions.create(store, sub="anon", roles=[], scopes=[])
    b = sessions.create(store, sub="u-ava", roles=["loan.officer"], scopes=["loans:read"])
    assert a.sid != b.sid


def test_session_role_update_immediate(store):
    sess = sessions.create(store, sub="u-ava", roles=["loan.officer"], scopes=["loans:read"])
    sessions.update_roles(store, sess.sid, roles=["loan.underwriter"], scopes=["loans:decide"])
    assert "loan.underwriter" in sessions.load(store, sess.sid).roles


def test_absolute_timeout(store):
    sess = sessions.create(store, sub="u-ava", roles=[], scopes=[], now=time.time() - sessions.ABSOLUTE_TTL - 10)
    # rewrite absolute_exp into the past via store
    data = store.get_session(sess.sid)
    data["absolute_exp"] = time.time() - 1
    store.put_session(sess.sid, data, ttl=60)
    with pytest.raises(sessions.SessionError, match="absolute"):
        sessions.load(store, sess.sid)

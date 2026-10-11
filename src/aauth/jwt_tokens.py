"""Hardened JWT access tokens (RFC 7519) with strict validation.

Rules enforced on every verify:
- alg allowlist (RS256 only; never none, never HS*)
- iss, aud, exp, nbf, iat with small clock skew
- kid must resolve in JWKS
- jti checked against denylist
- tv (token version) must match the subject's current version
- optional cnf (confirmation) for DPoP or x5t#S256 mTLS binding
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

import jwt

from aauth.keys import KeyRing
from aauth.store import AuthStore

ALLOWED_ALGS = ("RS256",)
CLOCK_SKEW = 30  # seconds
DEFAULT_TTL = 300  # 5 minutes


@dataclass
class AccessToken:
    token: str
    jti: str
    expires_at: float
    claims: dict


class TokenError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def issue(
    ring: KeyRing,
    *,
    sub: str,
    audience: str,
    scopes: list[str],
    roles: list[str] | None = None,
    ttl: int = DEFAULT_TTL,
    store: AuthStore | None = None,
    extra: dict | None = None,
    cnf: dict | None = None,
    act: dict | None = None,
) -> AccessToken:
    """Issue a short-lived RS256 access token. Sensitive PII stays out of claims."""
    key = ring.active_key()
    now = int(time.time())
    jti = uuid.uuid4().hex
    claims: dict[str, Any] = {
        "iss": ring.issuer,
        "sub": sub,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": jti,
        "scope": " ".join(scopes),
        "roles": list(roles or []),
        "tv": store.version(sub) if store else 0,
    }
    if cnf:
        claims["cnf"] = cnf
    if act:
        claims["act"] = act  # RFC 8693 actor claim
    if extra:
        # Never put passwords, SSNs or full addresses in claims.
        forbidden = {"password", "ssn", "secret", "credit_card"}
        claims.update({k: v for k, v in extra.items() if k.lower() not in forbidden})
    token = jwt.encode(claims, key.private_pem, algorithm="RS256", headers={"kid": key.kid, "typ": "at+jwt"})
    return AccessToken(token=token, jti=jti, expires_at=float(claims["exp"]), claims=claims)


def verify(
    token: str,
    ring: KeyRing,
    *,
    audience: str,
    store: AuthStore | None = None,
    require_cnf: str | None = None,
) -> dict:
    """Strict verification. Raises TokenError with a machine-readable reason."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as e:
        raise TokenError("malformed_header") from e
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise TokenError(f"alg_not_allowed:{alg}")
    kid = header.get("kid")
    if not kid:
        raise TokenError("missing_kid")
    key = ring.by_kid(kid)
    if key is None:
        raise TokenError("unknown_kid")
    try:
        claims = jwt.decode(
            token,
            key.public_pem,
            algorithms=list(ALLOWED_ALGS),
            audience=audience,
            issuer=ring.issuer,
            leeway=CLOCK_SKEW,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]},
        )
    except jwt.ExpiredSignatureError as e:
        raise TokenError("expired") from e
    except jwt.InvalidAudienceError as e:
        raise TokenError("wrong_audience") from e
    except jwt.InvalidIssuerError as e:
        raise TokenError("wrong_issuer") from e
    except jwt.ImmatureSignatureError as e:
        raise TokenError("not_yet_valid") from e
    except jwt.InvalidSignatureError as e:
        raise TokenError("bad_signature") from e
    except jwt.PyJWTError as e:
        raise TokenError(f"invalid:{type(e).__name__}") from e
    if store is not None:
        if store.is_denied(claims["jti"]):
            raise TokenError("revoked")
        expected_tv = store.version(claims["sub"])
        if int(claims.get("tv", -1)) != expected_tv:
            raise TokenError("stale_token_version")
    if require_cnf:
        cnf = claims.get("cnf") or {}
        if require_cnf not in cnf:
            raise TokenError(f"missing_cnf:{require_cnf}")
    return claims


def decode_unverified(token: str) -> dict:
    """Decode without verifying. Used to demonstrate that JWTs are signed, not encrypted."""
    return jwt.decode(token, options={"verify_signature": False})


def revoke(store: AuthStore, jti: str, remaining_ttl: int) -> None:
    store.deny(jti, remaining_ttl)

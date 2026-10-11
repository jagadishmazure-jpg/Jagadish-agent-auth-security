"""Refresh tokens with rotation and reuse detection (OAuth 2.1).

Each refresh token is opaque (random jti). On use it is rotated: the old jti is
denied and a new one is issued. Presenting a denied (already used) refresh token
revokes the whole family, which stops an attacker who stole a prior refresh.
"""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass

from aauth.store import AuthStore

REFRESH_TTL = 7 * 24 * 3600  # 7 days


@dataclass
class RefreshToken:
    token: str  # opaque: family_id.jti
    family: str
    jti: str
    sub: str
    scopes: list[str]
    expires_at: float


class RefreshError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def issue(store: AuthStore, *, sub: str, scopes: list[str], family: str | None = None, ttl: int = REFRESH_TTL) -> RefreshToken:
    fam = family or uuid.uuid4().hex
    jti = secrets.token_urlsafe(24)
    exp = time.time() + ttl
    store.put_refresh(jti, {"family": fam, "sub": sub, "scopes": scopes, "exp": exp, "used": False}, ttl=ttl)
    return RefreshToken(token=f"{fam}.{jti}", family=fam, jti=jti, sub=sub, scopes=scopes, expires_at=exp)


def rotate(store: AuthStore, presented: str, *, ttl: int = REFRESH_TTL) -> RefreshToken:
    """Consume `presented` and return a new refresh token in the same family.

    Reuse of an already-rotated token revokes the family and raises RefreshError.
    """
    try:
        family, jti = presented.split(".", 1)
    except ValueError as e:
        raise RefreshError("malformed") from e
    data = store.get_refresh(jti)
    if data is None:
        # Unknown or expired. If the jti is on the denylist, this is reuse.
        if store.is_denied(jti):
            _revoke_family(store, family)
            raise RefreshError("reuse_detected")
        raise RefreshError("unknown_or_expired")
    if data.get("used"):
        _revoke_family(store, data["family"])
        raise RefreshError("reuse_detected")
    if time.time() > data["exp"]:
        store.delete_refresh(jti)
        raise RefreshError("expired")
    # Mark used and deny the old jti for the rest of its life.
    data["used"] = True
    store.put_refresh(jti, data, ttl=max(int(data["exp"] - time.time()), 1))
    store.deny(jti, max(int(data["exp"] - time.time()), 1))
    return issue(store, sub=data["sub"], scopes=list(data["scopes"]), family=data["family"], ttl=ttl)


def _revoke_family(store: AuthStore, family: str) -> None:
    # Family revocation marker: any later rotate of this family fails fast.
    store.deny(f"family:{family}", REFRESH_TTL)


def family_revoked(store: AuthStore, family: str) -> bool:
    return store.is_denied(f"family:{family}")

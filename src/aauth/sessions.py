"""Server-side sessions (stateful).

Sid is a high-entropy opaque cookie value. Session data (user, roles, csrf) lives
in the store. Hardening: HttpOnly + Secure + SameSite=Lax cookies, CSRF double
submit, session fixation defence (rotate sid on login), idle and absolute timeouts.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from aauth.store import AuthStore

IDLE_TTL = 1800  # 30 minutes
ABSOLUTE_TTL = 28800  # 8 hours
COOKIE_NAME = "ngfs_sid"
CSRF_HEADER = "X-CSRF-Token"


@dataclass
class Session:
    sid: str
    sub: str
    roles: list[str]
    scopes: list[str]
    csrf: str
    created_at: float
    last_seen: float
    absolute_exp: float

    def to_dict(self) -> dict:
        return {
            "sub": self.sub,
            "roles": self.roles,
            "scopes": self.scopes,
            "csrf": self.csrf,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "absolute_exp": self.absolute_exp,
        }

    @classmethod
    def from_dict(cls, sid: str, d: dict) -> Session:
        return cls(
            sid=sid,
            sub=d["sub"],
            roles=list(d["roles"]),
            scopes=list(d["scopes"]),
            csrf=d["csrf"],
            created_at=d["created_at"],
            last_seen=d["last_seen"],
            absolute_exp=d["absolute_exp"],
        )


class SessionError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def create(store: AuthStore, *, sub: str, roles: list[str], scopes: list[str], now: float | None = None) -> Session:
    """Create a new session. Always generates a fresh sid (fixation defence)."""
    ts = now if now is not None else time.time()
    sid = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    sess = Session(sid=sid, sub=sub, roles=roles, scopes=scopes, csrf=csrf, created_at=ts, last_seen=ts, absolute_exp=ts + ABSOLUTE_TTL)
    store.put_session(sid, sess.to_dict(), ttl=IDLE_TTL)
    return sess


def rotate(store: AuthStore, old: Session, *, now: float | None = None) -> Session:
    """Rotate the sid (e.g. on privilege change or re-auth). Old sid is deleted."""
    store.delete_session(old.sid)
    return create(store, sub=old.sub, roles=old.roles, scopes=old.scopes, now=now)


def load(store: AuthStore, sid: str, *, now: float | None = None) -> Session:
    ts = now if now is not None else time.time()
    data = store.get_session(sid)
    if data is None:
        raise SessionError("unknown_or_expired")
    sess = Session.from_dict(sid, data)
    if ts > sess.absolute_exp:
        store.delete_session(sid)
        raise SessionError("absolute_timeout")
    # Sliding idle window.
    sess.last_seen = ts
    remaining = int(sess.absolute_exp - ts)
    store.put_session(sid, sess.to_dict(), ttl=min(IDLE_TTL, max(remaining, 1)))
    return sess


def destroy(store: AuthStore, sid: str) -> None:
    store.delete_session(sid)


def check_csrf(sess: Session, provided: str | None) -> None:
    if not provided or not secrets.compare_digest(sess.csrf, provided):
        raise SessionError("csrf_mismatch")


def cookie_header(sid: str) -> str:
    """Set-Cookie value with Secure, HttpOnly, SameSite=Lax."""
    return f"{COOKIE_NAME}={sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={IDLE_TTL}"


def clear_cookie_header() -> str:
    return f"{COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"


def update_roles(store: AuthStore, sid: str, roles: list[str], scopes: list[str]) -> Session:
    """Update roles in the live session (the JWT equivalent needs a new token / version bump)."""
    sess = load(store, sid)
    sess.roles = list(roles)
    sess.scopes = list(scopes)
    remaining = int(sess.absolute_exp - time.time())
    store.put_session(sid, sess.to_dict(), ttl=min(IDLE_TTL, max(remaining, 1)))
    return sess

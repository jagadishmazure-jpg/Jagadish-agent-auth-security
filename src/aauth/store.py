"""Shared stores for sessions, refresh tokens, revocation and token versions.

Uses an in-memory dict by default, or fakeredis when `use_redis=True`, so the
benchmark can contrast local JWT verify with a networked (faked) session lookup.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any


class MemoryBackend:
    def __init__(self) -> None:
        self._data: dict[str, str] = {}
        self._ttl: dict[str, float] = {}

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._data[key] = value
        if ex is not None:
            self._ttl[key] = time.time() + ex
        elif key in self._ttl:
            del self._ttl[key]

    def get(self, key: str) -> str | None:
        exp = self._ttl.get(key)
        if exp is not None and time.time() > exp:
            self._data.pop(key, None)
            self._ttl.pop(key, None)
            return None
        return self._data.get(key)

    def delete(self, key: str) -> None:
        self._data.pop(key, None)
        self._ttl.pop(key, None)

    def exists(self, key: str) -> bool:
        return self.get(key) is not None


class RedisBackend:
    """Thin wrapper over fakeredis so the call shape matches MemoryBackend."""

    def __init__(self) -> None:
        import fakeredis

        self._r = fakeredis.FakeRedis(decode_responses=True)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._r.set(key, value, ex=ex)

    def get(self, key: str) -> str | None:
        return self._r.get(key)

    def delete(self, key: str) -> None:
        self._r.delete(key)

    def exists(self, key: str) -> bool:
        return bool(self._r.exists(key))


@dataclass
class AuthStore:
    backend: Any
    # token_version[sub] increments on role change / forced logout; JWT carries `tv`.
    token_versions: dict[str, int] = field(default_factory=dict)

    @classmethod
    def memory(cls) -> AuthStore:
        return cls(backend=MemoryBackend())

    @classmethod
    def redis(cls) -> AuthStore:
        return cls(backend=RedisBackend())

    # --- sessions ---
    def put_session(self, sid: str, data: dict, ttl: int) -> None:
        self.backend.set(f"sess:{sid}", json.dumps(data), ex=ttl)

    def get_session(self, sid: str) -> dict | None:
        raw = self.backend.get(f"sess:{sid}")
        return json.loads(raw) if raw else None

    def delete_session(self, sid: str) -> None:
        self.backend.delete(f"sess:{sid}")

    # --- refresh tokens (opaque ids) ---
    def put_refresh(self, jti: str, data: dict, ttl: int) -> None:
        self.backend.set(f"rt:{jti}", json.dumps(data), ex=ttl)

    def get_refresh(self, jti: str) -> dict | None:
        raw = self.backend.get(f"rt:{jti}")
        return json.loads(raw) if raw else None

    def delete_refresh(self, jti: str) -> None:
        self.backend.delete(f"rt:{jti}")

    # --- denylist (revoked access JTIs and used refresh JTIs) ---
    def deny(self, jti: str, ttl: int) -> None:
        self.backend.set(f"deny:{jti}", "1", ex=max(ttl, 1))

    def is_denied(self, jti: str) -> bool:
        return self.backend.exists(f"deny:{jti}")

    # --- token version (stale-claims defence) ---
    def version(self, sub: str) -> int:
        return self.token_versions.get(sub, 0)

    def bump_version(self, sub: str) -> int:
        self.token_versions[sub] = self.version(sub) + 1
        return self.token_versions[sub]

"""Signing keys and JWKS with rotation (kid).

RSA keys are generated at runtime. No private key is ever committed. The active
kid signs new tokens; previous kids stay in JWKS so in-flight tokens still verify
until they expire. See RFC 7517.
"""

from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class Key:
    kid: str
    private_pem: bytes
    public_pem: bytes
    created_at: float
    retired_at: float | None = None

    @property
    def active(self) -> bool:
        return self.retired_at is None


@dataclass
class KeyRing:
    """In-memory JWKS with rotation. Deterministic only when `seed` is set (tests)."""

    issuer: str
    keys: list[Key] = field(default_factory=list)
    _counter: int = 0
    _seed: int | None = None

    @classmethod
    def create(cls, issuer: str, seed: int | None = None) -> KeyRing:
        ring = cls(issuer=issuer, _seed=seed)
        ring.rotate()
        return ring

    def rotate(self) -> Key:
        self._counter += 1
        if self._seed is not None:
            # Deterministic key material for tests: cryptography accepts no seed, so we
            # still generate a fresh key, but kid is stable for a given counter.
            kid = f"ngfs-test-{self._seed}-{self._counter}"
        else:
            kid = f"ngfs-{secrets.token_hex(4)}-{self._counter}"
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        public_pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        now = time.time()
        for k in self.keys:
            if k.active:
                k.retired_at = now
        key = Key(kid=kid, private_pem=private_pem, public_pem=public_pem, created_at=now)
        self.keys.append(key)
        return key

    def active_key(self) -> Key:
        for k in reversed(self.keys):
            if k.active:
                return k
        raise RuntimeError("no active signing key")

    def by_kid(self, kid: str) -> Key | None:
        for k in self.keys:
            if k.kid == kid:
                return k
        return None

    def jwks(self) -> dict:
        """Public JWKS document (RFC 7517). Retains retired keys so clients can verify in-flight tokens."""
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        keys = []
        for k in self.keys:
            pub = load_pem_public_key(k.public_pem)
            nums = pub.public_numbers()
            n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
            e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
            keys.append({"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.kid, "n": _b64u(n), "e": _b64u(e)})
        return {"keys": keys}

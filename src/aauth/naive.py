"""DELIBERATELY VULNERABLE JWT helpers.

*** NEVER USED BY DEFAULT. *** Labelled so attack tests can show each attack
succeeding against the naive path and failing against the hardened path.
Do not import from production code paths (api.py, oauth_server.py, delegation.py).
"""

from __future__ import annotations

import time
import uuid

import jwt

# Weak HMAC secret on purpose. Attack tests use a tiny wordlist that includes it.
WEAK_SECRET = "passwordpasswordpasswordpassword"
ALG_NONE_ALLOWED = True  # the bug


def issue_hs256(sub: str, secret: str = WEAK_SECRET, **extra) -> str:
    now = int(time.time())
    claims = {"sub": sub, "iat": now, "exp": now + 3600, "jti": uuid.uuid4().hex, **extra}
    return jwt.encode(claims, secret, algorithm="HS256")


def issue_none(sub: str, **extra) -> str:
    """alg=none token: unsigned. PyJWT refuses to encode alg=none, so we hand-build it."""
    import base64
    import json

    def b64(obj: dict | bytes) -> str:
        raw = obj if isinstance(obj, bytes) else json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    now = int(time.time())
    header = {"alg": "none", "typ": "JWT"}
    claims = {"sub": sub, "iat": now, "exp": now + 3600, "jti": uuid.uuid4().hex, **extra}
    return f"{b64(header)}.{b64(claims)}."


def _b64u_decode(s: str) -> bytes:
    import base64

    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64u(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def issue_hs256_with_key_bytes(sub: str, key_bytes: bytes, **extra) -> str:
    """Sign HS256 with raw key bytes (used to simulate key-confusion tokens)."""
    import hashlib
    import hmac as hm
    import json
    import time as _t
    import uuid as _u

    header = {"alg": "HS256", "typ": "JWT"}
    now = int(_t.time())
    claims = {"sub": sub, "iat": now, "exp": now + 3600, "jti": _u.uuid4().hex, **extra}
    h = _b64u(json.dumps(header, separators=(",", ":")).encode())
    p = _b64u(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64u(hm.new(key_bytes, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def verify_naive(token: str, *, hmac_secret: str | bytes = WEAK_SECRET, rsa_public_pem: bytes | None = None) -> dict:
    """Accepts alg=none, and will verify an HS256 token with the RSA public key as the HMAC secret
    when the token says alg=HS256 (classic key-confusion). Also does not check aud/iss.
    """
    import hashlib
    import hmac as hm
    import json

    header = jwt.get_unverified_header(token)
    alg = header.get("alg", "HS256")
    if alg == "none" and ALG_NONE_ALLOWED:
        return jwt.decode(token, options={"verify_signature": False, "verify_exp": True})
    if alg == "HS256":
        # KEY CONFUSION: naive code uses the RSA public PEM as the HMAC secret.
        key: bytes = rsa_public_pem if rsa_public_pem is not None else (hmac_secret.encode() if isinstance(hmac_secret, str) else hmac_secret)
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("malformed")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected = hm.new(key, signing_input, hashlib.sha256).digest()
        actual = _b64u_decode(parts[2])
        if not hm.compare_digest(expected, actual):
            raise ValueError("bad_signature")
        return json.loads(_b64u_decode(parts[1]))
    if alg == "RS256" and rsa_public_pem is not None:
        return jwt.decode(token, rsa_public_pem, algorithms=["RS256"], options={"verify_aud": False})
    raise ValueError(f"unsupported alg {alg}")

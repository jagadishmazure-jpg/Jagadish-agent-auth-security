"""Certificate-bound access tokens (RFC 8705 OAuth 2.0 Mutual-TLS).

The access token carries `cnf.x5t#S256`, the SHA-256 thumbprint of the client's
certificate. The resource server compares that to the cert presented on the TLS
connection. Offline we simulate the presented thumbprint as a function argument.
"""

from __future__ import annotations

import hashlib

from aauth.jwt_tokens import TokenError


def thumbprint(cert_der: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(hashlib.sha256(cert_der).digest()).rstrip(b"=").decode()


def cnf_claim(cert_der: bytes) -> dict:
    return {"x5t#S256": thumbprint(cert_der)}


def verify_binding(claims: dict, presented_thumbprint: str) -> None:
    cnf = claims.get("cnf") or {}
    expected = cnf.get("x5t#S256")
    if not expected:
        raise TokenError("missing_cnf:x5t#S256")
    if expected != presented_thumbprint:
        raise TokenError("mtls_thumbprint_mismatch")

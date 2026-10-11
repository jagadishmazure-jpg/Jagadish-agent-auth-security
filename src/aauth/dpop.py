"""Demonstrating Proof-of-Possession at the Application Layer (DPoP), RFC 9449.

A DPoP proof is a JWT signed by the client's ephemeral key, bound to the HTTP
method and URL. The access token carries `cnf.jkt` equal to the JWK thumbprint
of that key. A stolen bearer token without a matching proof is rejected.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aauth.jwt_tokens import TokenError


def _b64u(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class DPoPKey:
    private_pem: bytes
    public_jwk: dict
    jkt: str  # JWK SHA-256 thumbprint (RFC 7638)


def generate_key() -> DPoPKey:
    private = ec.generate_private_key(ec.SECP256R1())
    private_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub = private.public_key().public_numbers()
    x = pub.x.to_bytes(32, "big")
    y = pub.y.to_bytes(32, "big")
    jwk = {"kty": "EC", "crv": "P-256", "x": _b64u(x), "y": _b64u(y)}
    # RFC 7638 thumbprint over the required members, sorted.
    thumb_input = json.dumps({"crv": "P-256", "kty": "EC", "x": jwk["x"], "y": jwk["y"]}, separators=(",", ":"), sort_keys=True)
    jkt = _b64u(hashlib.sha256(thumb_input.encode()).digest())
    return DPoPKey(private_pem=private_pem, public_jwk=jwk, jkt=jkt)


def proof(key: DPoPKey, *, method: str, url: str, access_token: str | None = None, now: int | None = None) -> str:
    """Build a DPoP proof JWT for the given request."""
    ts = now if now is not None else int(time.time())
    claims = {"htu": url, "htm": method.upper(), "iat": ts, "jti": uuid.uuid4().hex}
    if access_token is not None:
        claims["ath"] = _b64u(hashlib.sha256(access_token.encode()).digest())
    headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk}
    return jwt.encode(claims, key.private_pem, algorithm="ES256", headers=headers)


def verify_proof(proof_jwt: str, *, method: str, url: str, expected_jkt: str, access_token: str | None = None, max_age: int = 60) -> dict:
    """Verify a DPoP proof and that its JWK thumbprint matches the token's cnf.jkt."""
    try:
        header = jwt.get_unverified_header(proof_jwt)
    except jwt.PyJWTError as e:
        raise TokenError("dpop_malformed") from e
    if header.get("typ") != "dpop+jwt":
        raise TokenError("dpop_bad_typ")
    if header.get("alg") != "ES256":
        raise TokenError("dpop_bad_alg")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise TokenError("dpop_missing_jwk")
    thumb_input = json.dumps(
        {"crv": jwk.get("crv"), "kty": jwk.get("kty"), "x": jwk.get("x"), "y": jwk.get("y")}, separators=(",", ":"), sort_keys=True
    )
    jkt = _b64u(hashlib.sha256(thumb_input.encode()).digest())
    if jkt != expected_jkt:
        raise TokenError("dpop_jkt_mismatch")
    # Rebuild a PEM from the JWK for verification.
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers

    def _b64d(s: str) -> bytes:
        import base64

        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad)

    numbers = EllipticCurvePublicNumbers(int.from_bytes(_b64d(jwk["x"]), "big"), int.from_bytes(_b64d(jwk["y"]), "big"), ec_mod.SECP256R1())
    pem = numbers.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    try:
        claims = jwt.decode(proof_jwt, pem, algorithms=["ES256"], options={"require": ["iat", "jti", "htm", "htu"]})
    except jwt.PyJWTError as e:
        raise TokenError("dpop_bad_signature") from e
    if claims["htm"].upper() != method.upper():
        raise TokenError("dpop_method_mismatch")
    if claims["htu"].rstrip("/") != url.rstrip("/"):
        raise TokenError("dpop_url_mismatch")
    if abs(time.time() - claims["iat"]) > max_age:
        raise TokenError("dpop_stale")
    if access_token is not None:
        expected_ath = _b64u(hashlib.sha256(access_token.encode()).digest())
        if claims.get("ath") != expected_ath:
            raise TokenError("dpop_ath_mismatch")
    return claims

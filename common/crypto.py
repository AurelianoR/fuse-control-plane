"""
Shared cryptographic core for the Fuse demo.

Everything here is real, standards-based crypto:
  - EC P-256 keys (ES256 signatures)
  - RFC 7638 JWK thumbprints (the `jkt` used to bind a token to a key)
  - RFC 9449 DPoP proofs (the freshly-signed proof sent on every request)
  - Fuse-issued access tokens are standard JWTs carrying a `cnf.jkt` claim

No mock crypto. The only demo shortcut lives in the vendor service, which
keeps its private key locally (as it would in production) but lets Fuse drive
it for the demo. The verification path is the genuine article.
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Optional, Tuple

import jwt  # PyJWT, used for the Fuse access token (a normal JWT)
from jwcrypto import jwk, jws


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------
def generate_keypair() -> jwk.JWK:
    """Generate an EC P-256 keypair as a JWK."""
    return jwk.JWK.generate(kty="EC", crv="P-256")


def public_jwk_dict(key: jwk.JWK) -> dict:
    """Public half of a JWK, as a plain dict (safe to share)."""
    return json.loads(key.export_public())


def thumbprint(key: jwk.JWK) -> str:
    """RFC 7638 SHA-256 JWK thumbprint, base64url. This is the `jkt`."""
    return key.thumbprint()  # jwcrypto returns SHA-256 base64url by default


def private_pem(key: jwk.JWK) -> bytes:
    return key.export_to_pem(private_key=True, password=None)


def public_pem(key: jwk.JWK) -> bytes:
    return key.export_to_pem(private_key=False, password=None)


# --------------------------------------------------------------------------
# Fuse access token (a normal JWT, signed by Fuse, bound via cnf.jkt)
# --------------------------------------------------------------------------
def issue_access_token(
    fuse_private_pem: bytes,
    kid: str,
    *,
    connection_id: str,
    vendor: str,
    scope: str,
    bound_jkt: Optional[str],
    lifetime_seconds: int,
) -> Tuple[str, dict]:
    """
    Mint a short-lived access token. If bound_jkt is set, the token is
    sender-constrained: only the holder of the matching private key can use it.
    """
    now = int(time.time())
    jti = uuid.uuid4().hex
    claims = {
        "iss": "fuse",
        "sub": connection_id,
        "vendor": vendor,
        "scope": scope,
        "iat": now,
        "exp": now + lifetime_seconds,
        "jti": jti,
    }
    if bound_jkt:
        claims["cnf"] = {"jkt": bound_jkt}  # the binding lives here
    token = jwt.encode(
        claims, fuse_private_pem, algorithm="ES256", headers={"kid": kid}
    )
    return token, claims


def verify_access_token(fuse_public_pem: bytes, token: str) -> dict:
    """Verify signature + expiry. Raises jwt exceptions on failure."""
    return jwt.decode(token, fuse_public_pem, algorithms=["ES256"])


# --------------------------------------------------------------------------
# DPoP proof (RFC 9449) - created by the vendor on every request
# --------------------------------------------------------------------------
def create_dpop_proof(
    signing_key: jwk.JWK,
    htm: str,
    htu: str,
    access_token: Optional[str] = None,
) -> str:
    """
    Build a DPoP proof JWT. The public key travels in the header (`jwk`);
    the resource server thumbprints it and checks it against the token's jkt.
    """
    now = int(time.time())
    payload = {
        "htm": htm,                 # HTTP method this proof is good for
        "htu": htu,                 # exact URL this proof is good for
        "iat": now,                 # freshness
        "jti": uuid.uuid4().hex,    # one-time id, stops replay
    }
    if access_token is not None:
        payload["ath"] = _ath(access_token)  # binds proof to this token

    protected = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": public_jwk_dict(signing_key),
    }
    sig = jws.JWS(json.dumps(payload).encode())
    sig.add_signature(signing_key, alg="ES256", protected=json.dumps(protected))
    return sig.serialize(compact=True)


def verify_dpop_proof(
    proof: str,
    *,
    htm: str,
    htu: str,
    expected_jkt: str,
    seen_jti: set,
    access_token: Optional[str] = None,
    max_age_seconds: int = 120,
) -> Tuple[bool, str, list]:
    """
    Run the four binding checks. Returns (ok, summary, detailed_checks).
    `detailed_checks` is a list of {name, ok, detail} so the UI can show each
    one lighting up green or red.
    """
    checks: list = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    # Parse the header without trusting it yet, to read the embedded key.
    try:
        header_b64 = proof.split(".")[0]
        header = json.loads(_b64url_decode(header_b64))
        embedded = jwk.JWK(**header["jwk"])
    except Exception:
        record("proof structure", False, "malformed DPoP proof")
        return False, "malformed DPoP proof", checks

    # Check 2 (load-bearing): the proof key must match the bound key.
    actual_jkt = embedded.thumbprint()
    if actual_jkt != expected_jkt:
        record(
            "key binding",
            False,
            f"proof key {actual_jkt[:10]}... does not match bound key {expected_jkt[:10]}...",
        )
        # Still try to verify the signature so the UI shows the proof was
        # genuinely signed - just by the WRONG key. This is the forged-proof case.
        try:
            v = jws.JWS()
            v.deserialize(proof)
            v.verify(embedded)
            record("signature", True, "validly signed, but by an attacker key")
        except Exception:
            record("signature", False, "signature did not verify")
        return False, "proof key does not match the bound key", checks

    record("key binding", True, "proof key matches the token's bound key")

    # Verify the signature with the embedded (and now trusted) key.
    try:
        v = jws.JWS()
        v.deserialize(proof)
        v.verify(embedded)
        payload = json.loads(v.payload)
    except Exception:
        record("signature", False, "signature did not verify")
        return False, "proof signature invalid", checks
    record("signature", True, "proof is correctly signed by the bound key")

    # Check 3: method + URL must match this exact request.
    if payload.get("htm") != htm or payload.get("htu") != htu:
        record(
            "request match",
            False,
            f"proof was made for {payload.get('htm')} {payload.get('htu')}",
        )
        return False, "proof does not match this request", checks
    record("request match", True, f"{htm} {htu}")

    # Check 4a: freshness.
    iat = payload.get("iat", 0)
    age = int(time.time()) - int(iat)
    if age > max_age_seconds or age < -30:
        record("freshness", False, f"proof is {age}s old")
        return False, "proof is stale", checks
    record("freshness", True, f"{age}s old")

    # Check 4b: one-time use.
    jti = payload.get("jti")
    if not jti or jti in seen_jti:
        record("replay", False, "this proof was already used (jti seen)")
        return False, "proof replay detected", checks
    seen_jti.add(jti)
    record("replay", True, "fresh one-time proof id")

    # Optional: ath ties the proof to this specific token.
    if access_token is not None and "ath" in payload:
        if payload["ath"] != _ath(access_token):
            record("token hash", False, "proof not bound to this token")
            return False, "proof token hash mismatch", checks
        record("token hash", True, "proof is bound to this access token")

    return True, "all checks passed", checks


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _ath(access_token: str) -> str:
    import hashlib

    digest = hashlib.sha256(access_token.encode()).digest()
    return _b64url_encode(digest)


# --------------------------------------------------------------------------
# private_key_jwt client assertion (RFC 7523) - vendor authenticates to Fuse's
# token endpoint by signing a JWT with its own key. Real asymmetric client auth.
# --------------------------------------------------------------------------
def make_client_assertion(signing_key: jwk.JWK, *, client_id: str, audience: str,
                          lifetime_seconds: int = 120) -> str:
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + lifetime_seconds,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, private_pem(signing_key), algorithm="ES256")


def verify_client_assertion(public_jwk_dict: dict, assertion: str, *, audience: str,
                            client_id: str) -> dict:
    """Verify a vendor's client_assertion against its REGISTERED public key.
    Raises on failure."""
    pub_pem = jwk.JWK(**public_jwk_dict).export_to_pem(private_key=False, password=None)
    claims = jwt.decode(assertion, pub_pem, algorithms=["ES256"], audience=audience)
    if claims.get("sub") != client_id or claims.get("iss") != client_id:
        raise ValueError("client_assertion sub/iss does not match client_id")
    return claims


# --------------------------------------------------------------------------
# GitHub App JWT (RS256) - authenticate AS the app to mint an installation token.
# This is how a real product integrates with GitHub.
# --------------------------------------------------------------------------
def github_app_jwt(app_id: str, private_key_pem: str) -> str:
    now = int(time.time())
    claims = {"iat": now - 60, "exp": now + 9 * 60, "iss": str(app_id)}
    return jwt.encode(claims, private_key_pem, algorithm="RS256")


def sign_fuse_jwt(private_pem: bytes, kid: str, claims: dict) -> str:
    """Sign a short JWT with Fuse's key (used for the gateway assertion that the
    company trusts when Fuse forwards a verified request inline)."""
    return jwt.encode(claims, private_pem, algorithm="ES256", headers={"kid": kid})

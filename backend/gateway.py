import jwt
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models import UsedJTI, Route

def verify_dpop_proof(
    db: Session,
    dpop_proof: str,
    request_method: str,
    request_uri: str,
    vendor_name: str
) -> tuple[bool, str]:
    """
    Verifies a DPoP proof token.
    Returns (success, message/error).
    """
    try:
        # 1. Decode header without validation to get JWK and alg
        unverified_header = jwt.get_unverified_header(dpop_proof)
        if not unverified_header:
            return False, "Invalid JWT header format."

        # Check 'typ' in header
        typ = unverified_header.get("typ")
        if typ != "dpop+jwt":
            return False, f"Invalid token type (typ). Expected 'dpop+jwt', got '{typ}'."

        # Check 'alg' in header
        alg = unverified_header.get("alg")
        if not alg or alg == "none":
            return False, "DPoP signature algorithm (alg) cannot be empty or 'none'."

        # Extract JWK
        jwk_dict = unverified_header.get("jwk")
        if not jwk_dict:
            return False, "Missing JSON Web Key (jwk) in DPoP header."

        # Load public key from JWK using PyJWT
        try:
            jwk_obj = jwt.PyJWK.from_dict(jwk_dict)
            public_key = jwk_obj.key
        except Exception as e:
            return False, f"Failed to parse public key from JWK: {str(e)}"

        # 2. Decode and verify JWT signature and basic validation
        # We do not use standard iat/exp validations in jwt.decode directly if we want
        # to custom-check them or let PyJWT do it. Let's do it manually for custom messages.
        try:
            payload = jwt.decode(
                dpop_proof,
                public_key,
                algorithms=[alg],
                options={"verify_signature": True, "verify_iat": False, "verify_exp": False}
            )
        except jwt.PyJWTError as e:
            return False, f"Signature verification failed: {str(e)}"

        # 3. Verify DPoP Claims
        # HTM: HTTP Method
        htm = payload.get("htm")
        if not htm or htm.upper() != request_method.upper():
            return False, f"HTTP Method mismatch. Claim: '{htm}', Request: '{request_method}'."

        # HTU: HTTP URI
        htu = payload.get("htu")
        if not htu:
            return False, "Missing HTTP URI (htu) claim."
            
        # Strip query parameters/fragments from request_uri for proper comparison
        clean_request_uri = request_uri.split('?')[0].split('#')[0]
        clean_htu = htu.split('?')[0].split('#')[0]
        
        if clean_htu != clean_request_uri:
            return False, f"HTTP URI mismatch. Claim: '{clean_htu}', Request: '{clean_request_uri}'."

        # IAT: Issued At (Must be recent, within 5 minutes / 300s window)
        iat = payload.get("iat")
        if not iat:
            return False, "Missing Issued At (iat) claim."
            
        now = datetime.utcnow()
        try:
            iat_dt = datetime.utcfromtimestamp(iat)
        except Exception:
            return False, "Invalid 'iat' timestamp format."

        # Support a 5-minute clock skew drift
        if abs((now - iat_dt).total_seconds()) > 300:
            return False, f"DPoP proof expired or timestamp in the future. iat: {iat_dt} UTC, current time: {now} UTC."

        # JTI: JWT ID (Unique, replay protection)
        jti = payload.get("jti")
        if not jti:
            return False, "Missing JWT ID (jti) claim."

        # Check if JTI exists in UsedJTI table
        existing_jti = db.query(UsedJTI).filter(UsedJTI.jti == jti).first()
        if existing_jti:
            # Check if it has expired (can be pruned). If expired, we could delete it, but since it's in the DB, it's a replay.
            return False, f"Replay attack detected: jti '{jti}' has already been used."

        # Save JTI to database
        # JTI entries are kept until they are past the 5-minute validity window
        expiry_time = iat_dt + timedelta(minutes=5)
        new_jti = UsedJTI(jti=jti, expires_at=expiry_time)
        db.add(new_jti)
        
        # Check dynamic routing for target
        route = db.query(Route).filter(Route.vendor == vendor_name, Route.active == True).first()
        target_message = f"and routed to {route.target_url}" if route else "with no active endpoint route found"
        
        # Commit JTI write
        db.commit()

        return True, f"DPoP proof verified successfully for {vendor_name} {target_message}."

    except Exception as e:
        return False, f"Unexpected DPoP verification error: {str(e)}"

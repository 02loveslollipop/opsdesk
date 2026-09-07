import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from fastapi import HTTPException, Header, Request, status
from app.config import settings

logger = logging.getLogger(__name__)

class RedirectToLoginException(Exception):
    """Signal that an unauthenticated browser request should redirect to /login."""
    pass

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
) -> str:
    """
    Creates a signed JWT with standard claims:
    - sub: user ID
    - username: login name
    - role: user | admin
    - iss: opsdesk
    - aud: opsdesk-web
    - exp: expiration timestamp
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "iss": issuer or settings.JWT_ISSUER,
        "aud": audience or settings.JWT_AUDIENCE,
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp()),
    })
    
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def decode_token_vulnerable(token: str) -> dict:
    """
    VULNERABLE JWT VALIDATION (Kept for educational reference)
    Omits verify_exp, verify_iss, and verify_aud.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={
            "verify_signature": True,
            "verify_exp": False,
            "verify_iss": False,
            "verify_aud": False,
        },
    )

def decode_token_secure(token: str) -> dict:
    """
    SECURE JWT VALIDATION (Remediated)
    
    Enforces defense-in-depth:
      1. Cryptographic HMAC signature check using server SECRET_KEY.
      2. Pinned algorithm whitelist [settings.JWT_ALGORITHM] ('HS256') - prevents algorithm confusion.
      3. Expiration verification ('exp'): Expired tokens are rejected.
      4. Issuer verification ('iss'): Rejects tokens issued by third parties.
      5. Audience verification ('aud'): Rejects tokens targeted for other client applications.
      6. Required claims: Rejects tokens missing essential fields.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        issuer=settings.JWT_ISSUER,
        audience=settings.JWT_AUDIENCE,
        options={
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": True,
            "verify_aud": True,
            "require": ["exp", "iss", "aud", "sub", "username", "role"],
        },
    )

# ACTIVE IMPLEMENTATION: Strict validation
decode_token = decode_token_secure

def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> dict:
    """
    Authentication dependency.
    Extracts token from 'Authorization: Bearer <token>' header or 'access_token' cookie.
    Decodes and validates token.
    """
    token = None
    
    # 1. Check Authorization header
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
        
    # 2. Check Cookie
    if not token and "access_token" in request.cookies:
        cookie_val = request.cookies.get("access_token", "")
        if cookie_val.startswith("Bearer "):
            token = cookie_val.split(" ", 1)[1].strip()
        else:
            token = cookie_val

    is_html_client = "text/html" in request.headers.get("accept", "")

    if not token:
        if is_html_client:
            raise RedirectToLoginException()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(token)
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token rejected: signature has expired")
        if is_html_client:
            raise RedirectToLoginException()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (jwt.InvalidTokenError, Exception) as exc:
        logger.warning("Token validation failed: %s", exc)
        if is_html_client:
            raise RedirectToLoginException()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

def require_admin(current_user: dict = None) -> dict:
    """
    Authorization dependency.
    Enforces Role-Based Access Control (RBAC).
    """
    if not current_user or current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Administrator privileges required"
        )
    return current_user

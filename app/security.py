import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from fastapi import HTTPException, Header, Request, status
from fastapi.responses import RedirectResponse
from app.config import settings

logger = logging.getLogger(__name__)

class RedirectToLoginException(Exception):
    """Signal that an unauthenticated browser request should redirect to /login."""
    pass

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
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
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp()),
    })
    
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def decode_token_vulnerable(token: str) -> dict:
    """
    VULNERABLE JWT VALIDATION (Pedagogical demonstration)
    
    This function verifies the cryptographic HMAC signature, but deliberately
    omits expiration ('exp'), audience ('aud'), and issuer ('iss') checks.
    
    Flaw:
      A validly signed token that expired 1 hour, 1 week, or 1 year ago is STILL ACCEPTED!
      This demonstrates that 'signature valid != token valid'.
    """
    logger.info("Executing decode_token_vulnerable: verify_exp=False")
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={
            "verify_signature": True,
            "verify_exp": False,  # <--- DELIBERATE FLAW: Ignores expiration!
            "verify_iss": False,  # <--- Ignores issuer!
            "verify_aud": False,  # <--- Ignores audience!
        },
    )

def decode_token_secure(token: str) -> dict:
    """
    SECURE JWT VALIDATION
    
    Strictly validates:
      1. Cryptographic signature with trusted SECRET_KEY
      2. Pinned algorithm (HS256) - prevents algorithm switching attacks
      3. Token expiration timestamp ('exp')
      4. Expected issuer ('iss')
      5. Expected audience ('aud')
      6. Required presence of essential claims
    """
    logger.info("Executing decode_token_secure: full claims and exp validation")
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

# Active decoder in vulnerable version
decode_token = decode_token_vulnerable

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
    Separates Authentication (who you are) from Authorization (what you are allowed to do).
    """
    if not current_user or current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Administrator privileges required"
        )
    return current_user

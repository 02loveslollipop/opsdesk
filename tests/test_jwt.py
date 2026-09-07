from datetime import datetime, timedelta, timezone
import pytest
import jwt
from app.config import settings
from app.security import (
    create_access_token,
    decode_token_vulnerable,
    decode_token_secure,
)

def test_valid_jwt(client, user_headers):
    response = client.get("/profile", headers=user_headers)
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "alice"

def test_expired_jwt_rejected_in_secure_mode(client):
    """
    Verifies that an expired token is strictly rejected with 401 Unauthorized.
    """
    expired_time = datetime.now(timezone.utc) - timedelta(hours=2)
    payload = {
        "sub": "1",
        "username": "alice",
        "role": "user",
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": int(expired_time.timestamp()),
    }
    expired_token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    response = client.get("/profile", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()

def test_invalid_issuer_rejected(client):
    """
    Verifies that a token from an unexpected issuer is rejected with 401.
    """
    token = create_access_token(
        data={"sub": "1", "username": "alice", "role": "user"},
        issuer="untrusted-issuer-service",
    )
    response = client.get("/profile", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()

def test_invalid_audience_rejected(client):
    """
    Verifies that a token intended for another audience is rejected with 401.
    """
    token = create_access_token(
        data={"sub": "1", "username": "alice", "role": "user"},
        audience="mobile-app-client",
    )
    response = client.get("/profile", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()

def test_vulnerable_vs_secure_decoder_comparison():
    """
    Side-by-side unit test comparing both decoders:
    - decode_token_vulnerable accepts expired token.
    - decode_token_secure raises jwt.ExpiredSignatureError.
    """
    expired_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    payload = {
        "sub": "1",
        "username": "alice",
        "role": "user",
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": int(expired_time.timestamp()),
    }
    expired_token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    # Vulnerable accepts
    vulnerable_claims = decode_token_vulnerable(expired_token)
    assert vulnerable_claims["username"] == "alice"

    # Secure rejects with ExpiredSignatureError
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_token_secure(expired_token)

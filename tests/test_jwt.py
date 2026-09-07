from datetime import datetime, timedelta, timezone
import jwt
from app.config import settings
from app.security import decode_token_vulnerable

def test_valid_jwt(client, user_headers):
    response = client.get("/profile", headers=user_headers)
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "alice"

def test_expired_jwt_vulnerable_acceptance(client):
    """
    Demonstrates JWT vulnerability:
    Token was created in the past and is strictly expired.
    In vulnerable mode, decode_token_vulnerable does not verify 'exp'.
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

    # Directly verify decode_token_vulnerable accepts the expired token
    decoded = decode_token_vulnerable(expired_token)
    assert decoded["username"] == "alice"

    # Verify endpoint also accepts expired token in vulnerable mode
    response = client.get("/profile", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "alice"

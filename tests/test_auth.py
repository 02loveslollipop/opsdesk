from app.auth import authenticate_user_vulnerable, authenticate_user_secure

def test_legitimate_login(client):
    response = client.post(
        "/login",
        data={"username": "alice", "password": "alice123"},
        headers={"Accept": "application/json"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["username"] == "alice"
    assert data["user"]["role"] == "user"

def test_invalid_credentials(client):
    response = client.post(
        "/login",
        data={"username": "alice", "password": "wrongpassword"},
        headers={"Accept": "application/json"}
    )
    assert response.status_code == 401

def test_sqli_blocked_by_parameterization(client):
    """
    Verifies that SQL Injection attempt is completely neutralized
    by parameterized query execution. The input 'admin' --' is treated
    strictly as a literal username string.
    """
    response = client.post(
        "/login",
        data={"username": "admin' --", "password": "doesnotmatter"},
        headers={"Accept": "application/json"}
    )
    assert response.status_code == 401

def test_vulnerable_vs_secure_implementation_comparison(db_session):
    """
    Side-by-side unit test comparing both implementations:
    - Vulnerable function accepts SQL injection bypass.
    - Secure function safely rejects it.
    """
    # Vulnerable implementation accepts SQLi
    vulnerable_res = authenticate_user_vulnerable(db_session, "admin' --", "wrong")
    assert vulnerable_res is not None
    assert vulnerable_res["username"] == "admin"

    # Secure parameterized implementation rejects SQLi
    secure_res = authenticate_user_secure(db_session, "admin' --", "wrong")
    assert secure_res is None

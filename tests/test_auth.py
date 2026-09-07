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

def test_vulnerable_sqli_bypass(client):
    """
    Demonstrates SQL Injection vulnerability.
    Using username: admin' --
    The trailing comment disables the password check in the raw SQL query.
    """
    response = client.post(
        "/login",
        data={"username": "admin' --", "password": "doesnotmatter"},
        headers={"Accept": "application/json"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"

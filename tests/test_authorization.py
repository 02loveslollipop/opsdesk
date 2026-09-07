from pathlib import Path

def test_unauthenticated_cannot_access_admin(client):
    response = client.get("/admin", headers={"Accept": "application/json"})
    assert response.status_code == 401

def test_regular_user_forbidden_on_admin(client, user_headers):
    """
    Demonstrates Authorization != Authentication.
    A validly authenticated user with role 'user' receives 403 Forbidden.
    """
    response = client.get("/admin", headers={**user_headers, "Accept": "application/json"})
    assert response.status_code == 403

def test_regular_user_forbidden_on_diagnostics(client, user_headers):
    response = client.get("/admin/diagnostics", headers={**user_headers, "Accept": "application/json"})
    assert response.status_code == 403

def test_admin_user_allowed_on_admin(client, admin_headers):
    response = client.get("/admin", headers={**admin_headers, "Accept": "text/html"})
    assert response.status_code == 200
    assert "OpsDesk Administration Console" in response.text

def test_dockerfile_runs_as_non_root():
    """
    Pedagogical test: Verifies that the fixed Dockerfile enforces
    the Principle of Least Privilege by declaring a dedicated non-root USER.
    """
    dockerfile_path = Path("Dockerfile")
    assert dockerfile_path.exists()
    content = dockerfile_path.read_text()
    
    user_lines = [line.strip() for line in content.splitlines() if line.strip().startswith("USER ")]
    assert len(user_lines) == 1, "Dockerfile must declare exactly one USER directive"
    assert "appuser" in user_lines[0], f"USER directive should specify unprivileged user 'appuser', found: {user_lines[0]}"
    assert "10001" in content, "Dockerfile should assign non-root UID 10001 to appuser"

def test_security_headers_present(client):
    """
    Verifies that defense-in-depth HTTP security headers are injected
    on all HTTP responses.
    """
    response = client.get("/login")
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert "strict-origin" in response.headers.get("Referrer-Policy", "")
    assert "default-src 'self'" in response.headers.get("Content-Security-Policy", "")
    assert "server" not in response.headers

def test_healthcheck_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_oversized_payload_rejected_with_413(client):
    """
    Verifies that request bodies exceeding the maximum limit are rejected with 413.
    """
    large_payload = "a" * (1024 * 1024 + 100)
    response = client.post(
        "/login",
        content=large_payload,
        headers={"Content-Length": str(len(large_payload)), "Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 413

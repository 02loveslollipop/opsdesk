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

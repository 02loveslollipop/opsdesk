import pytest
from app.diagnostics import (
    is_valid_target,
    run_diagnostics_vulnerable,
    run_diagnostics_secure,
)

def test_legitimate_ping(client, admin_headers):
    response = client.post(
        "/admin/diagnostics",
        data={"host": "127.0.0.1"},
        headers={**admin_headers, "Accept": "application/json"}
    )
    assert response.status_code == 200
    assert "127.0.0.1" in response.json()["output"]

def test_command_injection_blocked_with_400(client, admin_headers):
    """
    Verifies that command injection payloads containing ';' are
    strictly rejected with HTTP 400 Bad Request before execution.
    """
    response = client.post(
        "/admin/diagnostics",
        data={"host": "127.0.0.1; id"},
        headers={**admin_headers, "Accept": "application/json"}
    )
    assert response.status_code == 400
    assert "invalid host" in response.json()["detail"].lower()

def test_additional_metacharacters_rejected(client, admin_headers):
    """
    Verifies various command injection techniques are rejected:
    &&, |, $(), ``, newlines.
    """
    payloads = [
        "127.0.0.1 && id",
        "127.0.0.1 | whoami",
        "127.0.0.1 $(pwd)",
        "127.0.0.1 `id`",
        "127.0.0.1\nid",
    ]
    for p in payloads:
        response = client.post(
            "/admin/diagnostics",
            data={"host": p},
            headers={**admin_headers, "Accept": "application/json"}
        )
        assert response.status_code == 400

def test_target_validation_logic():
    assert is_valid_target("127.0.0.1") is True
    assert is_valid_target("::1") is True
    assert is_valid_target("localhost") is True
    assert is_valid_target("gateway.internal") is True
    
    # Invalid / Metacharacters
    assert is_valid_target("127.0.0.1; id") is False
    assert is_valid_target("127.0.0.1 && whoami") is False
    assert is_valid_target("$(id)") is False
    assert is_valid_target("") is False

def test_vulnerable_vs_secure_diagnostics_comparison():
    """
    Side-by-side unit test comparing both runners:
    - Vulnerable runner executes 'id' (output contains 'uid=').
    - Secure runner raises ValueError.
    """
    # Vulnerable executes injected command
    vulnerable_out = run_diagnostics_vulnerable("127.0.0.1; id")
    assert "uid=" in vulnerable_out

    # Secure rejects
    with pytest.raises(ValueError) as exc:
        run_diagnostics_secure("127.0.0.1; id")
    assert "shell metacharacters" in str(exc.value).lower()

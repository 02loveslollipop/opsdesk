# OpsDesk Secure Coding Lab

> [!CAUTION]
> **WARNING: DELIBERATELY VULNERABLE APPLICATION**
>
> This application contains deliberate security vulnerabilities for educational and demonstration purposes.
>
> **DO NOT:**
> - Expose it to the Internet or untrusted networks
> - Deploy it in production environments
> - Use real credentials or sensitive personal information
> - Connect it to real enterprise systems or databases

---

## Overview & Architecture

**OpsDesk** is an internal operations and ticketing portal built to demonstrate real-world web application vulnerabilities and their corresponding defensive mitigations:

```text
Browser / Client (127.0.0.1:8000)
       |
       v
FastAPI (Python 3.13)
       |
       +-- Authentication (Session / JWT)
       |      |-- SQL Injection (Vulnerable query concatenation)
       |      \-- JWT Validation (Skipped expiration / claim checks)
       |
       +-- Tickets & Dashboard
       |
       \-- Admin Console
              |-- Authorization (Role-Based Access Control)
              \-- Network Diagnostics
                     \-- Command Injection (Shell execution of user input)
FastAPI
       |
       v
PostgreSQL 16 (Isolated container network, no host port exposure)
```

---

## Security Guardrails of the Lab

To keep this educational lab strictly safe and contained:
- **Localhost Only**: The web interface binds exclusively to `127.0.0.1:8000`.
- **Database Isolation**: PostgreSQL's port (`5432`) is not published to the host machine.
- **No Privileged Containers**: Container runs without `--privileged` and without Docker socket mounts (`/var/run/docker.sock`).
- **No Sensitive Mounts**: Host filesystems are not mounted into the container.
- **Innocuous Demonstrations Only**: Command execution examples are strictly limited to safe commands like `id`, `whoami`, `pwd`, or files in `/tmp`.

---

## Requirements

- Docker and Docker Compose v2+
- Python 3.13+ (optional, for local `pytest` execution)
- `make` (optional convenience runner)

---

## Running the Lab

Start the entire environment locally:

```bash
docker compose up --build
```

Access the application in your browser:
**[http://127.0.0.1:8000](http://127.0.0.1:8000)**

To reset the database and state at any time:
```bash
docker compose down -v
docker compose up --build
```

---

## Demo Accounts

Pre-seeded credentials available on startup:

| Username | Password | Role | Description |
| :--- | :--- | :--- | :--- |
| `alice` | `alice123` | `user` | Standard operations user |
| `bob` | `bob123` | `user` | Standard operations user |
| `admin` | `admin123` | `admin` | Administrator with diagnostic tool access |

---

## Lab Versions & Git Branches

This repository is organized into three clean states accessible via git branches or tags:

- **`01-vulnerable`**: The baseline vulnerable state (SQLi, unvalidated JWT, Command Injection, Root container).
- **`02-fixed`**: Every vulnerability remediated with clean, readable code diffs.
- **`03-hardened`**: Defense-in-depth controls applied (Security headers, non-root, read-only FS, rate/size limits).

Switch branches:
```bash
git checkout 01-vulnerable
# or
git checkout 02-fixed
# or
git checkout 03-hardened
```

---

## Vulnerabilities Demonstrated

### 1. SQL Injection (Authentication Bypass)
- **Location**: `app/auth.py`
- **Root Cause**: Constructing SQL query via Python f-string interpolation:
  ```python
  raw_query = f"SELECT id, username, password, role FROM users WHERE username = '{username}' AND password = '{password}'"
  ```
- **Exploit**:
  - Username: `admin' --`
  - Password: `anypassword`
  - Result: Bypasses password check entirely and logs in as `admin`.

### 2. Improper JWT Validation (Expired Tokens Accepted)
- **Location**: `app/security.py`
- **Root Cause**: Skipping `verify_exp`, `verify_iss`, and `verify_aud` in `jwt.decode()`.
  ```python
  jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_exp": False})
  ```
- **Exploit**: A cryptographic signature is valid, but an expired token remains valid forever.

### 3. Command Injection (Controlled RCE)
- **Location**: `app/diagnostics.py`
- **Root Cause**: Combining user input with `shell=True`:
  ```python
  cmd = f"ping -c 1 {host}"
  subprocess.run(cmd, shell=True, ...)
  ```
- **Exploit**:
  - Target: `127.0.0.1; id`
  - Result: Executes `ping` followed by the `id` command.

### 4. Container Running as Root
- **Location**: `Dockerfile`
- **Root Cause**: No `USER` directive in `Dockerfile`.
- **Impact**: Output of injected `id` command displays:
  ```text
  uid=0(root) gid=0(root) groups=0(root)
  ```
  *Key Takeaway*: Root execution does not cause the vulnerability, but amplifies attacker blast radius.

---

## Presentation Walkthrough

### Scene 1: SQL Injection
1. Open `http://127.0.0.1:8000/login`.
2. Inspect `app/auth.py` and explain string interpolation.
3. Login using `admin' --` with any password.
4. You are immediately authenticated into the dashboard as `admin`!

### Scene 2: JWT Claims & Expiration
1. On `/dashboard`, view the **JWT Claims Inspector**.
2. Explain the difference between signature validity and claim validity.
3. Run `make demo-jwt` or pytest: an expired token from hours ago is accepted.

### Scene 3: Command Injection
1. Navigate to `/admin/diagnostics`.
2. Ping legitimate host `127.0.0.1`.
3. Enter payload: `127.0.0.1; id`
4. The output shows system user information executed by the shell.

### Scene 4: Root Container Impact
1. Notice the output of `id` shows `uid=0(root)`.
2. Show `Dockerfile` and explain how lack of non-root user exacerbates the compromise.

### Scene 5: Remediation & Defense in Depth
1. Checkout the fixed branch:
   ```bash
   git checkout 02-fixed
   docker compose down -v && docker compose up --build
   ```
2. Repeat all previous exploits:
   - SQLi `admin' --` fails (parameterized query + Argon2).
   - Expired token returns `401 Unauthorized`.
   - `127.0.0.1; id` returns `400 Bad Request` (input validation + `shell=False`).
   - Container process runs as non-root `appuser` (`uid=10001`).

---

## Testing

Run the automated test suite:
```bash
pytest -v tests/
```

# OpsDesk Secure Coding Lab

> [!CAUTION]
> ### ⚠️ WARNING: DELIBERATELY VULNERABLE APPLICATION
> This application intentionally contains critical security vulnerabilities designed exclusively for local security training and live secure coding demonstrations.
>
> **STRICT SAFETY RULES:**
> - **DO NOT** expose this application to the Internet or untrusted networks.
> - **DO NOT** deploy this repository to production or cloud environments.
> - **DO NOT** use real credentials, passwords, API keys, or private data.
> - **DO NOT** connect this containerized setup to real systems or internal production databases.

---

## Architecture

**OpsDesk** is a lightweight operations and internal support ticket management portal built with **Python 3.13**, **FastAPI**, **Jinja2**, and **PostgreSQL**.

```text
Browser / Client (127.0.0.1:8000)
       |
       v
FastAPI (Python 3.13)
       |
       +-- [Authentication]
       |      |-- SQL Injection (Vulnerable query interpolation)
       |      \-- JWT Validation (Skipped expiration / claim validation)
       |
       +-- [Tickets & Dashboard]
       |      \-- Internal operations tickets & claim inspector
       |
       \-- [Admin Console]
              |-- Authorization Check (`require_admin`)
              \-- Network Diagnostics Tool
                     \-- Command Injection (`shell=True` with user input)
FastAPI
       |
       v
PostgreSQL 16 (Isolated internal network, port NOT published to host)
```

---

## Laboratory Safety Constraints

To guarantee a safe local testing environment:
1. **Localhost Binding**: In `docker-compose.yml`, the web port binds strictly to `127.0.0.1:8000:8000`.
2. **Database Isolation**: PostgreSQL does not publish port `5432` to the host machine.
3. **No Docker Socket**: `/var/run/docker.sock` is never mounted.
4. **No Privileged Mode**: Containers run without `--privileged`.
5. **No Host Directory Mounts**: No sensitive host directories are mapped.
6. **No Host Network**: Docker uses standard bridge networks (`network_mode: host` is forbidden).
7. **Safe Payloads Only**: Demonstrations are limited to innocuous commands: `id`, `whoami`, `pwd`, or files in `/tmp`. No reverse shells or persistence mechanisms.

---

## Requirements

- **Docker** and **Docker Compose** (v2+)
- **Python 3.13+** (optional, for local `pytest` execution without Docker)
- **Make** (optional, for demo shortcuts)

---

## Running the Lab

Build and start the application locally with a single command:

```bash
docker compose up --build
```

Access the web interface in your browser:
**[http://127.0.0.1:8000](http://127.0.0.1:8000)**

To reset the database and volume state cleanly at any time:
```bash
docker compose down -v
docker compose up --build
```

---

## Demo Accounts

The database is pre-seeded on startup with these demo accounts:

| Username | Password | Role | Description |
| :--- | :--- | :--- | :--- |
| `alice` | `alice123` | `user` | Standard operations user (can view tickets & profile) |
| `bob` | `bob123` | `user` | Standard operations user |
| `admin` | `admin123` | `admin` | Administrator (access to `/admin` and Network Diagnostics) |

---

## Lab Versions (Git Branches & Tags)

The repository provides three self-contained versions accessible via Git branches and tags:

```text
01-vulnerable  ──>  02-fixed  ──>  03-hardened
```

Switch between them during your demonstration:

```bash
# 1. Baseline vulnerable lab:
git checkout 01-vulnerable
docker compose down -v && docker compose up --build

# 2. Remediated application:
git checkout 02-fixed
docker compose down -v && docker compose up --build

# 3. Hardened defense-in-depth application:
git checkout 03-hardened
docker compose down -v && docker compose up --build
```

You can inspect the exact diffs with:
```bash
git diff 01-vulnerable 02-fixed
git diff 02-fixed 03-hardened
```

---

## Vulnerabilities (in `01-vulnerable`)

### 1. SQL Injection (Authentication Bypass)
- **Location**: [`app/auth.py`](file:///home/zerotwo/security_presentation_example/app/auth.py)
- **Problem**: Constructing raw SQL queries by concatenating untrusted user input using Python f-strings:
  ```python
  raw_query = f"SELECT id, username, password, role FROM users WHERE username = '{username}' AND password = '{password}'"
  ```
- **Exploit**:
  - Username: `admin' --`
  - Password: `anything`
  - Result: The single-line SQL comment (`--`) discards the password check, authenticating the attacker as `admin`.

### 2. Improper JWT Validation (Expired Signature Acceptance)
- **Location**: [`app/security.py`](file:///home/zerotwo/security_presentation_example/app/security.py)
- **Problem**: Verifying the cryptographic signature while explicitly disabling expiration and audience checks:
  ```python
  jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_exp": False})
  ```
- **Exploit**: An old, expired token (e.g. leaked from logs or backups) remains valid indefinitely.

### 3. Command Injection (Controlled RCE)
- **Location**: [`app/diagnostics.py`](file:///home/zerotwo/security_presentation_example/app/diagnostics.py)
- **Problem**: Concatenating user input into a shell command executed with `shell=True`:
  ```python
  cmd = f"ping -c 1 {host}"
  subprocess.run(cmd, shell=True, capture_output=True, text=True)
  ```
- **Exploit**:
  - Target input: `127.0.0.1; id`
  - Result: Shell executes `ping` and then executes `id`.

### 4. Container Running as Root
- **Location**: [`Dockerfile`](file:///home/zerotwo/security_presentation_example/Dockerfile)
- **Problem**: Absence of a `USER` directive causes FastAPI to run as `root` (UID 0) inside the container.
- **Key Takeaway**:
  > *Running as root does NOT cause the RCE. The command injection vulnerability in code causes execution. However, running as root amplifies the impact by giving an attacker full root privileges inside the container.*

---

## Fixed Version (`02-fixed`)

Remediates all four vulnerabilities:
1. **Parameterized Queries**: Uses SQLAlchemy `text("SELECT ... WHERE username = :username")` with bound parameters and **Argon2id** password hashing.
2. **Strict JWT Claim Validation**: Validates `exp`, `iss` (`opsdesk`), `aud` (`opsdesk-web`), and pins the expected algorithm (`HS256`).
3. **Safe Command Execution**: Replaces `shell=True` with `shell=False` and a vector list `["ping", "-c", "1", "-W", "2", target]`, combined with strict IP address/hostname regex validation.
4. **Dedicated Non-Root User**: Declares an unprivileged user `appuser` (UID 10001, GID 10001) in `Dockerfile` with restricted filesystem ownership.

---

## Hardened Version (`03-hardened`)

Applies Defense-in-Depth layers:
- **Defensive HTTP Headers**: Enforces `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and suppresses server identification.
- **Strict Environment Secrets**: Validates secret length (minimum 32 characters) and halts startup if default secrets are used in production.
- **Security Event Logging**: Structured logging of authentication failures, 401s, 403 authorization rejections, and malicious input probes.
- **Request Size Limiting**: Middleware rejects request bodies larger than 1MB with `413 Request Entity Too Large` to mitigate buffer and resource exhaustion.
- **Read-Only Root Filesystem**: In `docker-compose.yml`, the application container runs with `read_only: true`, mounting only `/tmp` as a restricted `tmpfs` with `noexec,nosuid`.
- **Process Security**: Enforces `security_opt: [no-new-privileges:true]`, drops all capabilities (`cap_drop: [ALL]`), and adds only `NET_RAW` for ping.
- **Healthchecks**: Built-in healthchecks for PostgreSQL (`pg_isready`) and FastAPI (`/health`).
- **Clean Error Handling**: All 500 errors log tracebacks internally while returning a safe reference ID without exposing stack traces.

---

## Presentation Walkthrough (Step-by-Step Script)

Follow this 5-scene script during your live presentation:

### Scene 1: SQL Injection
1. Ensure you are on the vulnerable branch:
   ```bash
   git checkout 01-vulnerable
   docker compose down -v && docker compose up -d
   ```
2. Open `http://127.0.0.1:8000/login`.
3. Open [`app/auth.py`](file:///home/zerotwo/security_presentation_example/app/auth.py) and show the audience:
   ```python
   raw_query = f"SELECT id, username, password, role FROM users WHERE username = '{username}' AND password = '{password}'"
   ```
4. Demonstrate bypass:
   - Username: `admin' --`
   - Password: `wrongpassword`
   - Click **Sign In**.
5. **Audience Takeaway**: You are logged in as `admin` without knowing the password because `--` commented out the password clause.

---

### Scene 2: JWT Validation Flaw
1. Once logged in, show the **JWT Claims Inspector** card on `/dashboard`.
2. Explain the JWT structure (`header.payload.signature`).
3. Open [`app/security.py`](file:///home/zerotwo/security_presentation_example/app/security.py) and point out:
   ```python
   options={"verify_exp": False}
   ```
4. Send an expired token:
   ```bash
   python3 -c "
   import jwt, urllib.request, json
   token = jwt.encode({'sub': '1', 'username': 'alice', 'role': 'user', 'iss': 'opsdesk', 'aud': 'opsdesk-web', 'exp': 1000000000}, 'opsdesk-insecure-presentation-secret-key-2026', algorithm='HS256')
   req = urllib.request.Request('http://127.0.0.1:8000/profile', headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'})
   print(json.loads(urllib.request.urlopen(req).read()))
   "
   ```
5. **Audience Takeaway**: The server accepts an expired token from 2001! Signature valid does not equal claim valid.

---

### Scene 3: Command Injection
1. Navigate to `/admin/diagnostics`.
2. First, demonstrate normal usage: enter `127.0.0.1` and click **Ping**.
3. Open [`app/diagnostics.py`](file:///home/zerotwo/security_presentation_example/app/diagnostics.py) and explain:
   - User input is interpolated: `f"ping -c 1 {host}"`
   - Executed through shell: `shell=True`
4. In the target box, enter:
   ```text
   127.0.0.1; id
   ```
5. Click **Ping**.
6. **Audience Takeaway**: The output shows both ping results AND the output of the `id` command!

---

### Scene 4: Root Container Impact
1. Direct the audience's attention to the output from Scene 3:
   ```text
   uid=0(root) gid=0(root) groups=0(root)
   ```
2. Open [`Dockerfile`](file:///home/zerotwo/security_presentation_example/Dockerfile) and show that `USER` is missing.
3. **Pedagogical Discussion**:
   - Did Docker running as root cause the RCE? **No**, the vulnerable Python code caused it.
   - Did running as root make it worse? **Yes**, it turned a limited application exploit into full container root compromise.

---

### Scene 5: Remediation & Defense in Depth
1. Switch to the fixed version:
   ```bash
   git checkout 02-fixed
   docker compose down -v && docker compose up -d
   ```
2. Repeat each test:
   - **SQL Injection**: Try `admin' --` &rarr; Returns **401 Invalid username or password**.
   - **Expired JWT**: Try the expired token script &rarr; Returns **401 Token has expired**.
   - **Command Injection**: Try `127.0.0.1; id` &rarr; Returns **400 Invalid host or IP address format**.
3. Next, demonstrate the hardened version:
   ```bash
   git checkout 03-hardened
   docker compose down -v && docker compose up -d
   ```
4. Show that the container runs with `read_only: true`, `security_opt: [no-new-privileges:true]`, and all defensive HTTP headers.

---

## Running the Automated Test Suite

Run pytest locally:
```bash
pytest -v tests/
```

Or run inside Docker:
```bash
docker compose run --rm web pytest -v tests/
```

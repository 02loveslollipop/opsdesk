import ipaddress
import logging
import re
import subprocess

logger = logging.getLogger(__name__)

# RFC 1123 compliant hostname pattern (letters, numbers, hyphens, dots)
HOSTNAME_REGEX = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

def is_valid_target(target: str) -> bool:
    """
    Validates that target is strictly an IPv4/IPv6 address or valid hostname.
    Strictly forbids shell metacharacters (; & | ` $ > < \n etc.).
    """
    target = target.strip()
    if not target or len(target) > 253:
        return False
    
    # 1. Check IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # 2. Check Hostname
    if HOSTNAME_REGEX.match(target):
        return True

    return False

def run_diagnostics_vulnerable(host: str) -> str:
    """
    VULNERABLE COMMAND EXECUTION (Kept for educational reference)
    String interpolation + shell=True allows command chaining.
    """
    cmd = f"ping -c 1 {host}"
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = proc.stdout if proc.stdout else proc.stderr
        return output.strip() if output else f"Command completed with exit code {proc.returncode}"
    except subprocess.TimeoutExpired:
        return "Command execution timed out after 5 seconds."
    except Exception as exc:
        return f"Execution error: {str(exc)}"

def run_diagnostics_secure(host: str) -> str:
    """
    SECURE COMMAND EXECUTION (Remediated)

    Defense-in-depth controls:
      1. Strict Input Validation (Allowlist of IP/hostname characters).
         Rejects command separators like ';', '&&', '|', '$', '`', etc.
      2. No Shell Invocation (shell=False):
         Process arguments are passed as a discrete vector/list. The OS execve
         system call invokes the binary directly without a shell interpreter.
      3. Strict Execution Timeout (3 seconds):
         Prevents resource exhaustion / hanging worker threads.
    """
    target = host.strip()
    if not is_valid_target(target):
        logger.warning("Rejected malicious or malformed diagnostic target: %r", target)
        raise ValueError(
            f"Invalid host or IP address format: '{target}'. Shell metacharacters and multiple targets are rejected."
        )

    logger.info("Executing safe ping for target: %s", target)
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "2", target],
            shell=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
        output = proc.stdout if proc.stdout else proc.stderr
        return output.strip() if output else f"Ping completed with exit code {proc.returncode}"
    except subprocess.TimeoutExpired:
        logger.warning("Ping to target %s timed out", target)
        return "Diagnostic check timed out after 3 seconds."
    except Exception as exc:
        logger.error("Diagnostic execution error: %s", exc)
        return f"Diagnostic service error: {str(exc)}"

# ACTIVE IMPLEMENTATION: Validated & shell=False
run_diagnostics = run_diagnostics_secure

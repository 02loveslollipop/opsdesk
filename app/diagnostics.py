import logging
import subprocess

logger = logging.getLogger(__name__)

def run_diagnostics_vulnerable(host: str) -> str:
    """
    VULNERABLE COMMAND EXECUTION (Pedagogical demonstration of Command Injection)

    The Three Ingredients of the Flaw:
      1. Untrusted user input: 'host'
      2. String interpolation into a shell command: f"ping -c 1 {host}"
      3. Execution through the system shell: shell=True

    Consequence:
      An attacker providing '127.0.0.1; id' causes the shell to execute both the ping
      and the 'id' command in sequence!
    """
    cmd = f"ping -c 1 {host}"
    logger.info("Executing vulnerable command with shell=True: %s", cmd)

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

# Active runner in vulnerable version
run_diagnostics = run_diagnostics_vulnerable

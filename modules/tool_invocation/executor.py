"""
SubprocessExecutor - safe shell runner for security tools.
Handles timeout, stderr capture, exception wrapping.
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass


@dataclass
class RawOutput:
    stdout: str
    stderr: str
    returncode: int
    elapsed_seconds: float
    timed_out: bool = False


class SubprocessExecutor:
    """
    Runs external commands in a subprocess with timeout and error handling.
    All commands are run without shell=True to prevent injection.
    """

    @staticmethod
    def run(
        cmd: list[str],
        timeout: int = 120,
        cwd: str | None = None,
        env: dict | None = None,
    ) -> RawOutput:
        start = time.monotonic()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
            )
            elapsed = time.monotonic() - start
            return RawOutput(
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                elapsed_seconds=elapsed,
            )
        except subprocess.TimeoutExpired as e:
            elapsed = time.monotonic() - start
            stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
            return RawOutput(
                stdout=stdout,
                stderr=stderr,
                returncode=-1,
                elapsed_seconds=elapsed,
                timed_out=True,
            )
        except FileNotFoundError:
            elapsed = time.monotonic() - start
            tool_name = cmd[0] if cmd else "unknown"
            return RawOutput(
                stdout="",
                stderr=f"Tool not found: '{tool_name}'. Ensure it is installed and in PATH.",
                returncode=-2,
                elapsed_seconds=elapsed,
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            return RawOutput(
                stdout="",
                stderr=f"Unexpected error executing command: {e}",
                returncode=-3,
                elapsed_seconds=elapsed,
            )

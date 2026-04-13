"""ghr-bin — Install tools from GitHub releases."""

from __future__ import annotations

import os
import sys


def find_ghr_bin() -> str:
    """Return the ghr binary path."""
    exe = "ghr.exe" if sys.platform == "win32" else "ghr"
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), exe)
    if os.path.isfile(path):
        return path
    raise FileNotFoundError(f"Could not find ghr binary at {path}")


def main() -> None:
    """Entry point for the ``ghr`` console script."""
    ghr = find_ghr_bin()

    # Ensure the binary is executable (pip may not preserve the bit).
    if sys.platform != "win32" and not os.access(ghr, os.X_OK):
        try:
            os.chmod(ghr, os.stat(ghr).st_mode | 0o111)
        except OSError:
            raise SystemExit(
                f"ghr binary is not executable and cannot be repaired:\n"
                f"  {ghr}\n"
                f"Run: chmod +x '{ghr}'"
            )

    args = [ghr, *sys.argv[1:]]
    if sys.platform == "win32":
        import subprocess

        raise SystemExit(subprocess.call(args))
    os.execv(ghr, args)

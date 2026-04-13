"""ghr-bin — Install tools from GitHub releases."""

import os
import subprocess
import sys
from pathlib import Path


def _get_version() -> str:
    try:
        from importlib.metadata import version

        return version("ghr-bin")
    except Exception:
        return "0.0.0"


_EXT = ".exe" if sys.platform == "win32" else ""


def _binary_path() -> Path:
    """Return the path to the ghr binary."""
    return Path(__file__).parent / f"ghr{_EXT}"


def main() -> None:
    """Run the ghr binary, replacing the current process on Unix."""
    binary = _binary_path()
    if not binary.exists():
        print(f"ghr binary not found at {binary}", file=sys.stderr)
        sys.exit(1)
    args = [str(binary), *sys.argv[1:]]
    if sys.platform != "win32":
        os.execv(args[0], args)
    else:
        raise SystemExit(subprocess.call(args))

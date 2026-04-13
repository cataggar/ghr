"""ghr-bin — Install tools from GitHub releases."""

from __future__ import annotations

import os
import sys
import sysconfig


def find_ghr_bin() -> str:
    """Return the ghr binary path."""
    exe = "ghr.exe" if sys.platform == "win32" else "ghr"

    targets = [
        sysconfig.get_path("scripts"),
        sysconfig.get_path("scripts", vars={"base": sys.base_prefix}),
    ]

    # User scheme
    if sys.version_info >= (3, 10):
        user_scheme = sysconfig.get_preferred_scheme("user")
    elif os.name == "nt":
        user_scheme = "nt_user"
    else:
        user_scheme = "posix_user"
    targets.append(sysconfig.get_path("scripts", scheme=user_scheme))

    seen: list[str] = []
    for target in targets:
        if not target or target in seen:
            continue
        seen.append(target)
        path = os.path.join(target, exe)
        if os.path.isfile(path):
            return path

    locations = "\n".join(f" - {t}" for t in seen)
    raise FileNotFoundError(
        f"Could not find ghr binary in:\n{locations}\n"
    )

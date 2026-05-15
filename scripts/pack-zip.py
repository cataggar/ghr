#!/usr/bin/env python3
"""
Deterministic-as-possible zip packager for ghr Windows release archives.

The bundled `.exe` is Authenticode-signed at release time and therefore
not byte-reproducible. The zip envelope itself, however, is built to
be deterministic and spec-compliant:

* entries are emitted in sorted order (directories before their contents);
* every entry's date_time is derived from `SOURCE_DATE_EPOCH`;
* every entry is stored with forward-slash paths (ZIP APPNOTE §4.4.17.1).
  Git for Windows' `zip` writes backslashes here, which makes InfoZIP
  `unzip` warn `appears to use backslashes as path separators` and
  exit 1 — that breaks `set -e` pipelines (e.g. our Windows
  reproducibility job) even though the files extract correctly;
* `create_system = 3` (UNIX) regardless of host OS, so external attrs
  carry POSIX modes (0o755 for directories, 0o644 for files);
* `ZIP_DEFLATED` at a fixed compression level.

Also writes a `<archive>.sha256` sidecar in the `sha256sum`-compatible
`HEX  FILENAME\n` format.

Usage: pack-zip.py <pkgdir> <archive.zip>

`SOURCE_DATE_EPOCH` is read from the environment (decimal seconds since
the Unix epoch). Required.
"""
from __future__ import annotations

import datetime
import hashlib
import os
import sys
import zipfile


def _walk_sorted(root: str):
    """Yield (path, is_dir) under root in stable lexicographic order,
    directories before their contents."""
    yield (root, True)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        for name in dirnames:
            yield (os.path.join(dirpath, name), True)
        for name in filenames:
            yield (os.path.join(dirpath, name), False)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: pack-zip.py <pkgdir> <archive.zip>", file=sys.stderr)
        return 2
    pkgdir, archive = argv[1], argv[2]

    sde = os.environ.get("SOURCE_DATE_EPOCH")
    if not sde:
        print("error: SOURCE_DATE_EPOCH env var is required", file=sys.stderr)
        return 2
    dt = datetime.datetime.fromtimestamp(int(sde), datetime.timezone.utc)
    date_time = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

    with zipfile.ZipFile(
        archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as zf:
        for path, is_dir in _walk_sorted(pkgdir):
            arc = path.replace(os.sep, "/")
            if is_dir:
                info = zipfile.ZipInfo(arc + "/", date_time=date_time)
                info.external_attr = (0o755 << 16) | 0x10  # MS-DOS DIR bit
                info.create_system = 3  # UNIX
                zf.writestr(info, b"")
            else:
                with open(path, "rb") as fh:
                    data = fh.read()
                info = zipfile.ZipInfo(arc, date_time=date_time)
                info.external_attr = 0o644 << 16
                info.create_system = 3  # UNIX
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, data)

    with open(archive, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    sidecar = archive + ".sha256"
    with open(sidecar, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{digest}  {os.path.basename(archive)}\n")

    print(f"{digest}  {os.path.basename(archive)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

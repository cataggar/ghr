#!/usr/bin/env python3
"""
Deterministic tar.gz packager for ghr release archives.

Builds a gzipped tarball of the directory ``pkgdir`` in a way that is
byte-reproducible across runs and runners:

* entries are emitted in sorted order;
* every entry has mtime ``SOURCE_DATE_EPOCH``;
* every entry has uid/gid 0 and empty uname/gname;
* file modes are normalized (files 0o644, directories 0o755);
* the gzip header carries ``mtime=0`` and no original filename;
* gzip compression level is fixed (level 9).

Also writes a ``<archive>.sha256`` sidecar in the ``sha256sum``-compatible
``HEX  FILENAME\n`` format.

Usage: pack.py <pkgdir> <archive.tar.gz>

``SOURCE_DATE_EPOCH`` is read from the environment (decimal seconds since
the Unix epoch). Required.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import os
import sys
import tarfile


def _walk_sorted(root: str):
    """Yield paths under ``root`` (including ``root`` itself) in a stable
    lexicographic order, directories before their contents."""
    yield root
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        for name in dirnames:
            yield os.path.join(dirpath, name)
        for name in filenames:
            yield os.path.join(dirpath, name)


def _normalize(info: tarfile.TarInfo, mtime: int) -> tarfile.TarInfo:
    info.mtime = mtime
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    if info.isdir():
        info.mode = 0o755
    elif info.isfile():
        info.mode = 0o755 if (info.mode & 0o111) else 0o644
    return info


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: pack.py <pkgdir> <archive.tar.gz>", file=sys.stderr)
        return 2
    pkgdir, archive = argv[1], argv[2]

    sde = os.environ.get("SOURCE_DATE_EPOCH")
    if not sde:
        print("error: SOURCE_DATE_EPOCH env var is required", file=sys.stderr)
        return 2
    mtime = int(sde)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for path in _walk_sorted(pkgdir):
            info = tar.gettarinfo(path, arcname=path)
            info = _normalize(info, mtime)
            if info.isfile():
                with open(path, "rb") as fh:
                    tar.addfile(info, fh)
            else:
                tar.addfile(info)

    with open(archive, "wb") as out:
        # mtime=0 and no filename => reproducible gzip header
        with gzip.GzipFile(
            filename="", fileobj=out, mode="wb", mtime=0, compresslevel=9
        ) as gz:
            gz.write(buf.getvalue())

    with open(archive, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    sidecar = archive + ".sha256"
    with open(sidecar, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{digest}  {os.path.basename(archive)}\n")

    print(f"{digest}  {os.path.basename(archive)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

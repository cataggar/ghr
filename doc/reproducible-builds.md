# Reproducible builds

Linux and macOS release archives (`.tar.gz`) are produced deterministically:
the gzip header carries `mtime=0` and no filename, and every tar entry has
sorted order, fixed uid/gid 0, empty owner/group names, and `mtime` set to
`SOURCE_DATE_EPOCH` derived from the tagged commit. Packaging is performed
by [`scripts/pack.py`](../scripts/pack.py), and the same script is used
both at release time and during validation, so each archive's SHA-256 can
be reproduced bit-for-bit from source.

Windows `.zip` archives **cannot** be byte-reproduced at the archive level
— the `.exe` inside is Authenticode-signed by Azure Trusted Signing and
the signing key is, deliberately, not available to rebuilders. Instead,
the reproducibility workflow verifies Windows builds at the `.exe` level
(issue #78, Option E): it strips the Authenticode signature off the
published `.exe` and compares its sha256 against a locally-rebuilt
unsigned `.exe`. The stripping is performed by
[`ghr validate strip-authenticode`](../src/validate.zig) — a small
subcommand that reverses exactly what Trusted Signing appends
(the certificate table at end of file, the `IMAGE_DIRECTORY_ENTRY_SECURITY`
entry, and `OptionalHeader.CheckSum`).

The [`Reproducibility` workflow](../.github/workflows/reproducibility.yml)
runs automatically after each successful `Release` workflow and can also be
triggered manually with `workflow_dispatch` (provide the tag, e.g. `v0.3.0`).
For every release target it:

1. checks out the source at the tag,
2. installs the pinned Zig version,
3. rebuilds with the same flags as `release.yml`,
4. **for non-Windows targets**: repackages with `scripts/pack.py`,
   downloads the published `.tar.gz`, verifies it against GitHub's
   published asset digest, and fails on hash mismatch against the rebuild
   (with `tar tvf` and `cmp` diffs as a diagnostic artifact),
5. **for Windows targets**: also builds a host-native `ghr.exe` as the
   stripper, downloads the published `.zip`, extracts `bin/ghr.exe`,
   strips its Authenticode signature, and fails if the stripped sha256
   doesn't match the locally-rebuilt unsigned `.exe`. Diagnostics
   include `cmp -l` byte differences and side-by-side header dumps.

Releases tagged at or before `v0.2.1` predate deterministic packaging and
the Authenticode signing pipeline; they will not reproduce.

## Running the strip locally

`ghr validate strip-authenticode <input.exe> <output.exe>` reads a
signed PE, removes the embedded `WIN_CERTIFICATE` table at end of file,
zeroes the security data-directory entry, and zeroes
`OptionalHeader.CheckSum`. Given a deterministic Zig-built unsigned
`.exe`, signing-then-stripping returns the exact bytes the compiler
emitted — the foundation of Option E.

```
$ ghr validate strip-authenticode published/ghr.exe stripped.exe
stripped published/ghr.exe -> stripped.exe: dropped 15672 bytes (cert table at offset 0x238be00)
$ sha256sum stripped.exe locally-rebuilt-ghr.exe
```

# Authenticode test fixtures

## `git-lfs-windows-v3.7.1.pkcs7.der`

The `WIN_CERTIFICATE.bCertificate` payload (a PKCS#7 `ContentInfo`
carrying Authenticode `SignedData`) extracted from the certificate
table of `git-lfs-windows-v3.7.1.exe`, published at
<https://github.com/git-lfs/git-lfs/releases/tag/v3.7.1>.

Signed by GitHub, Inc. and chaining to Microsoft Identity Verification
Root Certificate Authority 2020. The signer leaf is one of Microsoft's
short-lived EOC code-signing certificates (valid 2025-10-16 to
2025-10-19), so the fixture is only used for **parsing** coverage —
tests must not validate it against the wall clock.

Regenerate with:

```sh
ghr download --skip-verify git-lfs/git-lfs/git-lfs-windows-v3.7.1.exe
python3 - <<'PY'
import struct
b = open('git-lfs-windows-v3.7.1.exe', 'rb').read()
e_lfanew = struct.unpack_from('<I', b, 0x3C)[0]
opt_off = e_lfanew + 24
plus = struct.unpack_from('<H', b, opt_off)[0] == 0x20b
sec = opt_off + (112 if plus else 96) + 4 * 8
off, size = struct.unpack_from('<II', b, sec)
dwlen = struct.unpack_from('<I', b, off)[0]
open('git-lfs-windows-v3.7.1.pkcs7.der', 'wb').write(b[off + 8:off + dwlen])
PY
```

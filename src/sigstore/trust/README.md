# Embedded Sigstore trust

`ghr` embeds trust material at build time. Updating any file in this
directory requires a new `ghr` release.

## Public Good instance

- `fulcio_v1.crt.pem`
- `fulcio_intermediate_v1.crt.pem`
- `rekor.pub`

These are sourced from
<https://github.com/sigstore/root-signing/tree/main/targets>.

## GitHub Sigstore instance

The files under `github/` were extracted from the GitHub TUF target returned
by `gh attestation trusted-root`.

Source target:

```text
https://tuf-repo.github.com/targets/484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7.trusted_root.json
length: 31645 bytes
sha256: 484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7
```

Refresh and authenticate the target before extracting certificates:

```sh
gh attestation trusted-root > trusted_root.jsonl
curl -fsSLo github-trusted-root.json \
  https://tuf-repo.github.com/targets/484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7.trusted_root.json
test "$(wc -c < github-trusted-root.json)" = 31645
printf '%s  %s\n' \
  484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7 \
  github-trusted-root.json | shasum -a 256 -c -
```

The trusted-root intervals overlap during rotation. Verification selects the
certificate whose interval contains the signed RFC 3161 `genTime`, then
validates the complete X.509 chain at that time.

| Valid from | Valid through | Fulcio l2 SHA-256 | TSA leaf SHA-256 |
|---|---|---|---|
| 2023-10-27 | 2024-05-25 | `F2:FD:DC:A7:5F:A1:33:8A:86:05:9E:DC:B4:DB:13:D1:A8:DC:41:17:03:3C:63:69:08:02:0A:1C:C5:BC:2F:70` | `2E:17:EB:B7:B3:57:8A:B4:38:57:9C:9E:44:54:03:1E:AC:55:18:DB:FD:0E:A7:65:8C:B4:71:F3:1F:1C:A8:01` |
| 2024-05-13 | 2024-10-25 | `79:5E:AD:B8:6C:F9:ED:CE:37:1B:AC:F7:08:48:94:BC:82:A3:A3:3D:DE:FE:63:47:9B:12:24:83:7D:63:FE:1F` | `79:48:F2:26:A9:7E:C3:D3:36:FC:02:A1:06:E9:D5:16:AA:9A:E7:D4:34:7A:BB:31:B2:74:09:19:59:09:1B:07` |
| 2024-10-07 | 2025-06-19 | `D3:F5:1B:27:12:02:A6:79:66:86:AF:11:76:23:C4:93:F8:3B:C5:78:E3:E9:E9:30:29:5C:0E:15:19:A1:1B:7C` | `7B:88:4A:C2:92:CA:22:6D:96:11:A3:4F:E4:72:4B:EB:58:43:B8:B0:08:CB:0C:09:31:A6:CF:63:4A:DC:3E:C3` |
| 2025-05-27 | 2025-12-09 | `4E:16:50:9E:3D:D3:A6:D2:2C:78:24:50:9C:8C:47:A6:8F:54:6A:87:4F:98:06:29:26:92:DF:CE:4E:7C:1C:1F` | `AF:77:7E:73:00:E3:5F:62:35:8A:5C:09:2F:04:B4:88:DE:7A:F3:05:E8:6F:77:6F:28:29:B6:F5:CC:09:92:65` |
| 2025-11-13 | 2026-07-13 | `C3:44:4F:18:FB:B1:A2:81:1D:8F:A4:94:20:8D:C7:C1:61:2F:78:C1:93:28:41:25:B8:6A:04:73:0E:31:BC:CE` | `AC:F3:E6:C8:3C:16:52:14:34:8A:79:F7:FD:81:C4:7F:8F:F0:16:5C:B1:A9:23:BF:78:EF:B3:80:28:1C:7A:69` |
| 2026-06-12 | open | `5E:32:FC:62:25:43:A4:D4:B9:DB:64:BB:C5:8F:C6:A6:7E:67:E4:BB:D0:9E:D3:2C:19:A0:80:EF:21:3F:09:AF` | `44:16:C8:AE:73:14:6A:63:A1:37:C2:E5:5B:E8:DE:70:E3:C9:AF:30:73:BF:39:8B:AA:BA:A8:DB:08:17:CE:D7` |

Common chain fingerprints:

- Fulcio l1: `B4:FB:ED:28:59:CB:16:CE:AF:3A:41:F0:55:31:9F:4E:D2:44:6E:1A:B8:5F:45:D0:80:D4:58:0A:56:43:A3:24`
- TSA intermediate: `4E:0F:06:4A:5F:AF:69:BF:1E:46:72:CE:94:7B:D4:25:B5:AC:89:99:85:AD:B8:01:3E:A4:49:81:4C:C7:CB:02`
- Internal Services Root: `DC:64:D3:AF:9F:D4:6D:D8:40:48:69:35:C9:03:98:6D:06:ED:D3:57:88:76:96:96:D2:F1:45:D3:8B:7F:78:87`

# Embedded Authenticode + RFC 3161 trust roots

Vendored at fixture-capture time from the sources listed below.
Rotation: refresh this directory + bump ghr's version when a CA
rotates or adds an Authenticode-trusted root.

Most roots were extracted from `/etc/ssl/certs/ca-bundle.crt` on a
Microsoft Azure Linux 3 host (the same Mozilla CCADB snapshot most
Linux distros ship). The Microsoft Identity Verification Root 2020
and GlobalSign Code Signing Root R45 were fetched directly from
their issuing CAs because they aren't yet in Mozilla's TLS bundle.

## Provenance

| File | Subject CN | SHA-256 fingerprint | Validity |
|---|---|---|---|
| `digicert_assured_id_root_g3.crt.pem` | DigiCert Assured ID Root G3 | `7E:37:CB:8B:4C:47:09:0C:AB:36:55:1B:A6:F4:5D:B8:40:68:0F:BA:16:6A:95:2D:B1:00:71:7F:43:05:3F:C2` | Aug  1 12:00:00 2013 GMT → Jan 15 12:00:00 2038 GMT |
| `digicert_global_root_ca.crt.pem` | DigiCert Global Root CA | `43:48:A0:E9:44:4C:78:CB:26:5E:05:8D:5E:89:44:B4:D8:4F:96:62:BD:26:DB:25:7F:89:34:A4:43:C7:01:61` | Nov 10 00:00:00 2006 GMT → Nov 10 00:00:00 2031 GMT |
| `digicert_global_root_g3.crt.pem` | DigiCert Global Root G3 | `31:AD:66:48:F8:10:41:38:C7:38:F3:9E:A4:32:01:33:39:3E:3A:18:CC:02:29:6E:F9:7C:2A:C9:EF:67:31:D0` | Aug  1 12:00:00 2013 GMT → Jan 15 12:00:00 2038 GMT |
| `digicert_high_assurance_ev_root_ca.crt.pem` | DigiCert High Assurance EV Root CA | `74:31:E5:F4:C3:C1:CE:46:90:77:4F:0B:61:E0:54:40:88:3B:A9:A0:1E:D0:0B:A6:AB:D7:80:6E:D3:B1:18:CF` | Nov 10 00:00:00 2006 GMT → Nov 10 00:00:00 2031 GMT |
| `digicert_trusted_root_g4.crt.pem` | DigiCert Trusted Root G4 | `55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88` | Aug  1 12:00:00 2013 GMT → Jan 15 12:00:00 2038 GMT |
| `entrust_root_ca_ec1.crt.pem` | Entrust Root Certification Authority - EC1 | `02:ED:0E:B2:8C:14:DA:45:16:5C:56:67:91:70:0D:64:51:D7:FB:56:F0:B2:AB:1D:3B:8E:B0:70:E5:6E:DF:F5` | Dec 18 15:25:36 2012 GMT → Dec 18 15:55:36 2037 GMT |
| `entrust_root_ca_g2.crt.pem` | Entrust Root Certification Authority - G2 | `43:DF:57:74:B0:3E:7F:EF:5F:E4:0D:93:1A:7B:ED:F1:BB:2E:6B:42:73:8C:4E:6D:38:41:10:3D:3A:A7:F3:39` | Jul  7 17:25:54 2009 GMT → Dec  7 17:55:54 2030 GMT |
| `globalsign_code_signing_root_r45.crt.pem` | GlobalSign Code Signing Root R45 | `7B:9D:55:3E:1C:92:CB:6E:88:03:E1:37:F4:F2:87:D4:36:37:57:F5:D4:4B:37:D5:2F:9F:CA:22:FB:97:DF:86` | Mar 18 00:00:00 2020 GMT → Mar 18 00:00:00 2045 GMT |
| `globalsign_root_ca_r3.crt.pem` | GlobalSign Root CA - R3 | `CB:B5:22:D7:B7:F1:27:AD:6A:01:13:86:5B:DF:1C:D4:10:2E:7D:07:59:AF:63:5A:7C:F4:72:0D:C9:63:C5:3B` | Mar 18 10:00:00 2009 GMT → Mar 18 10:00:00 2029 GMT |
| `globalsign_root_ca_r6.crt.pem` | GlobalSign Root CA - R6 | `2C:AB:EA:FE:37:D0:6C:A2:2A:BA:73:91:C0:03:3D:25:98:29:52:C4:53:64:73:49:76:3A:3A:B5:AD:6C:CF:69` | Dec 10 00:00:00 2014 GMT → Dec 10 00:00:00 2034 GMT |
| `microsoft_identity_verification_root_2020.crt.pem` | Microsoft Identity Verification Root Certificate Authority 2020 | `53:67:F2:0C:7A:DE:0E:2B:CA:79:09:15:05:6D:08:6B:72:0C:33:C1:FA:2A:26:61:AC:F7:87:E3:29:2E:12:70` | Apr 16 18:36:16 2020 GMT → Apr 16 18:44:40 2045 GMT |
| `microsoft_root_ca_2011.crt.pem` | Microsoft Root Certificate Authority 2011 | `84:7D:F6:A7:84:97:94:3F:27:FC:72:EB:93:F9:A6:37:32:0A:02:B5:61:D0:A9:1B:09:E8:7A:78:07:ED:7C:61` | Mar 22 22:05:28 2011 GMT → Mar 22 22:13:04 2036 GMT |
| `usertrust_ecc_ca.crt.pem` | USERTrust ECC Certification Authority | `4F:F4:60:D5:4B:9C:86:DA:BF:BC:FC:57:12:E0:40:0D:2B:ED:3F:BC:4D:4F:BD:AA:86:E0:6A:DC:D2:A9:AD:7A` | Feb  1 00:00:00 2010 GMT → Jan 18 23:59:59 2038 GMT |
| `usertrust_rsa_ca.crt.pem` | USERTrust RSA Certification Authority | `E7:93:C9:B0:2F:D8:AA:13:E2:1C:31:22:8A:CC:B0:81:19:64:3B:74:9C:89:89:64:B1:74:6D:46:C3:D4:CB:D2` | Feb  1 00:00:00 2010 GMT → Jan 18 23:59:59 2038 GMT |

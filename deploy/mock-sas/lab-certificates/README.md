# LAB test certificate catalog

This is the reference area for the simulator's test certificates. Only this
README is versioned. Specific certificates, keys, P12/PFX and generated output
are ignored by Git and excluded from the build context. The fork does not ship
operational credentials. Old upstream certificate/key files are historical
fixtures and must not be reused as operational credentials.

No commercial PKI, CPI registry, revocation framework or accreditation is
simulated. The Mock SAS checks the JWS signature, schema, configured identity and
validity of its pinned public CPI certificate. mTLS client trust is separate.

## Populate a private local catalog

The following are example paths relative to the checkout root. Use your actual
verified private locations. This document does not generate, download, rotate or
copy any material automatically.

| Material | Example path | Purpose |
|---|---|---|
| Public LAB server CA | `deploy\mock-sas\lab-certificates\existing\radio-server-ca.pem` | Radio trust in the HTTPS server; not the incoming mTLS client CA |
| Public CPI certificate | `deploy\mock-sas\lab-certificates\existing\cpi-cert.pem` | Matches the verifier pin and signer key; cannot sign |
| Complete radio + LAB CA bundle | `mock-sas-deploy-output\lab-server\radio-trust-bundle-with-lab.pem` | Retain ALL original CAs; never overwrite the truststore with only the LAB CA |
| PRIVATE CPI signing key | `mock-sas-lab\signer\cpi-key.pem` | Signing software only, never service/public package/Git; prefer its existing protected location without duplication |
| Signer PKCS#12, if needed | Your private signer directory | P12 and password stay outside Git/logs/public packages; no automatic duplicate |

Automatic deployment downloads are public-only. A previously transferred or
locally generated signer key remains at its existing private operator location;
the catalog does not export another one. No P12/password is supplied publicly.

If you want local copies of the two public LAB certificates in `existing`,
protect the directory first: Windows noninherited DACL for current user + SYSTEM
only, or Linux 0700. Copy only verified public LAB files and compare their
checksums with the originals. Do not copy private server/CA/CBSD keys or
radio-specific client root inputs into this directory. Original files and
permissions remain unchanged.

Preserve the radio's existing TLS alias/key; never replace it with synthetic
client credentials. Do not export the private CBSD, CA or HTTPS server key.
The CPI key belongs to the signer and is distinct from radio TLS.
Check `notBefore`/`notAfter` and private deployment metadata: organizing files does
not renew them or authorize RF.

## Fresh offline LAB, not rotation of an existing deployment

Reuse `deploy\mock-sas\generate_lab.py` only for a new separate LAB.
First create an empty private directory. On Windows use a protected
current-user/SYSTEM DACL as in the launcher's `Protect-Output`; Python `chmod`
does not guarantee Windows ACLs. Do not run the deployment launcher to organize
files. On Linux use 0700 and `umask 077`.

From the checkout root, after protecting the empty directory:

```powershell
.\.venv\Scripts\python.exe .\deploy\mock-sas\generate_lab.py `
  --out .\deploy\mock-sas\lab-certificates\fresh-offline `
  --ip ACTUAL_SERVER_IP --dns ACTUAL_SERVER_DNS_NAME
```

The helper refuses nonempty output and generates 30-day test certificates
(RS256 default, or `--cpi-alg ES256`). Review private `config\device.json`:
default FCC ID/serial are fictional. `runtime`/`config` are for the service;
`signer` stays private and its CA/TLS private keys are not exported.
There is no certificate autorenewal.

A new CPI pair requires a deliberate verifier-pin change and a new signature.
A new TLS CA requires a deliberate radio trust import preserving all original
CAs. State binding changes fail closed, never transferring old authorization
automatically. For PKCS#12 conversion use only an already protected destination
and an interactive password, never one stored in Git or this README.

Use this simulator only for tests with a radio in a properly RF-shielded
anechoic chamber. Anechoic treatment alone does not guarantee RF containment;
verify isolation before positive-mode activation.

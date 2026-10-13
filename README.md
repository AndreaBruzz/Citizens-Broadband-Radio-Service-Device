# CBSD Mock SAS laboratory container

A test-only Linux container based on the original
[Wireless Innovation Forum CBSD Testing and Interoperability repository](https://github.com/Wireless-Innovation-Forum/Citizens-Broadband-Radio-Service-Device).
The starting point was its historical Python 2, interactive, scenario-driven Mock
SAS harness. This fork reuses the original CPI signature verification and JSON
schema machinery, adapting only the required handler/utilities to a headless
Python 3.13 Flask/Gunicorn runtime. It does **not** migrate the entire legacy
project or provide a certified/commercial SAS.

**Default: single-step registration/CPI only.** Validated registration is a
LAB result, not permission to transmit. An explicitly acknowledged positive LAB
profile adds a bounded simulated lifecycle; ordinary startup does not enable it.

Use radios only in a **properly RF-shielded anechoic test chamber**.
An anechoic chamber alone does not guarantee RF isolation: verify containment
before positive-mode activation or any simulated AUTHORIZED response. There is
no authorization here for real/public-network transmission.

## Quickstart: registration-only isolated LAB

Requires Linux Docker Engine/Compose v2 and a reviewed server DNS/IP.
The following non-root example generates **new test credentials**, never replaces
existing material, and leaves positive mode disabled:

```sh
docker build -f Dockerfile.mock-sas -t winnf-mock-sas-lab:local .
export SAS_RUN_UID="$(id -u)"
export SAS_RUN_GID="$(id -g)"
umask 077
mkdir -m 700 mock-sas-lab
docker run --rm --user "$SAS_RUN_UID:$SAS_RUN_GID" \
  --mount "type=bind,src=$(pwd)/mock-sas-lab,dst=/lab" \
  winnf-mock-sas-lab:local \
  python generate_lab.py --out /lab --dns ACTUAL_SERVER_DNS_NAME
```

Replace the DNS placeholder with the name the client will actually verify.
Review the private `mock-sas-lab/config/device.json`: generated FCC ID/serial are
fictional. Then start only the default registration profile:

```sh
docker compose -f compose.mock-sas.yml config
docker compose -f compose.mock-sas.yml up -d --no-build
```

HTTPS is published on 8443 by default. mTLS is required; generated trust accepts
only the synthetic test client. For a radio, independently verify its existing
client CA chain and prepare matching private configuration before registration.
Do not substitute a synthetic key for the radio's client identity.
Root/UID 10001 setup, real client trust, SANs, ports and separately approved
positive-mode ownership are described in the [deployment guide](deploy/mock-sas/README.md).

## What changed

| Area | Scope |
|---|---|
| Original handler/utilities | Minimal Python 3 adaptation, safe parameter diagnostics, modern RS256/ES256 verification, preserved schema/device checks |
| LAB adapter/container | Noninteractive single-step CPI scenario, Category A NR compatibility, optional/empty measurement capability, JSON slash variants, HTTPS/mTLS |
| Deployment | Explicit host/IP/root-fingerprint inputs, pinned SSH support, public-only packages, coexistence/ownership checks, non-root hardened service |
| Opt-in positive mode | GAA policy/lease bounds, one configured device, original deadline persistence, schema/ID/response contracts |
| Explicit operator controls | Default-disabled local private Unix commands for suspension/resume, termination and targeted deregistration; no public admin API/scheduler |

The positive example policy is disabled until the operator reviews both
LAB-only/RF-containment acknowledgments. Private state is atomic, bounded and
single-writer; restart does not renew leases or resurrect expired grants.
There is no unconditional success for stale/unknown IDs and no automatic
credential rotation or negative event.

## Where keys and certificates are

All generated/specific material is local and ignored by Git/build context.
The repository does not ship operational credentials.

| Local generation output | Use |
|---|---|
| `mock-sas-lab/runtime/server-cert.pem`, `server-key.pem` | Service HTTPS, read-only runtime |
| `mock-sas-lab/runtime/client-ca.pem` | Incoming client TLS trust, distinct from the server CA |
| `mock-sas-lab/runtime/cpi-cert.pem` | Public certificate pinned for CPI verification |
| `mock-sas-lab/signer/cpi-key.pem` | Private CPI key for the signing software only |
| `mock-sas-lab/signer/server-ca.pem` | Public LAB CA for client/server-trust setup |
| Existing signer PKCS#12, if used | Keep in protected operator storage with a private password; not generated/exported automatically |

The SSH launcher downloads **public exports only**, not signer/private keys.
Existing private signer material stays at its operator-controlled location.
Do not regenerate it to publish the fork or sign another payload. Generated
test certificates expire after 30 days; renewal/pin/trust changes are deliberate.
Keep every original radio CA when adding LAB trust, never replace its bundle with
the bare LAB CA. Never export the private radio, server or CA key.
See the [English certificate catalog](deploy/mock-sas/lab-certificates/README.md)
for detailed roles, private directory permissions and separate offline generation.

## Validation and limitations

An earlier LAB lifecycle version was exercised with **one 5G small cell only**,
including CPI-verified registration and successful persisted heartbeats after
restart. This is not general radio/vendor interoperability or RF proof.
The newer response-contract/operator-control changes have local synthetic
regression coverage; this public snapshot's Linux image/Gunicorn/UID 10001 IPC
checks have not yet been run. See the guide for the runners and skipped-check
interpretation; local tests do not authorize deployment or live negative events.
The sanitized Windows suite ran 156 tests: 152 passed and four Linux-only checks
were skipped. Shipped Python/PowerShell/Bash syntax and public-only package checks
also passed.

This is not a commercial SAS, a spectrum-availability determination, real CPI
accreditation or proof of latest WInnForum certification. It does not implement
incumbent/ESC/DPA/PAL or SAS-SAS coordination, physical RF enforcement, HA,
multi-CBSD/Domain Proxy scheduling or multi-step registration. Positive mode is
one configured Category A NR device and one worker. Historical Python 2 GUI/
interactive launchers and the complete original certification suite are not
migrated. The guide cites the exact reviewed normative revision, not universal
current compliance.

## Documentation and upstream attribution

- [Build, Windows/Linux setup, CPI workflow, lifecycle and contracts](deploy/mock-sas/README.md)
- [Certificate/key catalog](deploy/mock-sas/lab-certificates/README.md)
- [Original upstream harness instructions](https://github.com/Wireless-Innovation-Forum/Citizens-Broadband-Radio-Service-Device/blob/774165ec7d846239aa049e56bd5d09b60a369d1c/README.md)
- [Apache License 2.0](LICENSE), with original copyright/attribution preserved

Old upstream certificate/key fixtures remain part of upstream history; they are
not operator credentials and are excluded from this container. The public fork
contains no added deployment diary, live device IDs, operator private material
or local credential paths.

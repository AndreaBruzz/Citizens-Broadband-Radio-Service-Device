# Mock SAS laboratory container

This Python 3 Linux container calls this repository's original
`model/CBRSRequestHandler.py` and single-step CPI scenario. It is not a substitute
emulator, certified SAS, commercial CPI service or current certification harness.
Only the handler/direct utilities were adapted; historical Python 2 GUI and
interactive controllers are not supported by this profile.

**Default: `registration-cpi-only`.** Registration/CPI is checked; inquiry,
grant, heartbeat, relinquishment and deregistration return JSON HTTP 404.
Registration acceptance is not permission to transmit. Keep RF disabled.

An optional, separately acknowledged `lab-positive` profile implements a bounded
single-device Category A NR lifecycle. It can return simulated `AUTHORIZED` and
therefore cause a radio to transmit. Activate it only after explicit operator
approval and verified RF containment in a properly RF-shielded anechoic chamber.
An anechoic chamber alone does not guarantee RF shielding; verify containment
before any simulated AUTHORIZED response. No example authorizes radio apply/reboot,
RF enablement, trust rotation, firewall changes or changes to unrelated services.

The root Apache-2.0 license and upstream copyright notices are retained.
Modified handler/utilities/schema have modification notices. Original upstream
test certificates/keys are historical fixtures, never operational credentials:
they and generated credentials are excluded from the container build context.

## Build and generate a separate LAB

Build natively for the target server's architecture:

```sh
docker build -f Dockerfile.mock-sas -t winnf-mock-sas-lab:local .
```

The server needs Linux, Docker Engine and Compose v2. The deployment tools do not
install them or guess the server's OS/architecture. Use the dedicated
`deploy/mock-sas/requirements.txt`, not the historical root requirements.

Generate **new** test credentials only for a new LAB. Never regenerate over
existing credentials to sign another payload, organize certificates or renew a
deployment. The helper refuses a nonempty output directory. Use the real server
DNS/IP in the SAN; the documentation address `192.0.2.10` and `lab-sas.example`
are reserved examples, not deployment targets.

For a non-root Linux login:

```sh
export SAS_RUN_UID="$(id -u)"
export SAS_RUN_GID="$(id -g)"
umask 077
mkdir -m 700 mock-sas-lab
docker run --rm --user "$SAS_RUN_UID:$SAS_RUN_GID" \
  --mount "type=bind,src=$(pwd)/mock-sas-lab,dst=/lab" \
  winnf-mock-sas-lab:local \
  python generate_lab.py --out /lab --dns ACTUAL_SERVER_DNS_NAME --cpi-alg RS256
```

The non-root UID override is for the registration-only quickstart. Positive-mode
state ownership and private operator controls use the default UID/GID 10001.
When administering as root, keep runtime non-root: prepare the empty directory
for UID/GID 10001 and generate using that identity. Persist the same UID/GID in a
private Compose env file. The SSH launcher uses UID/GID 10001 with root-owned
signer material. On Windows, protect the output DACL for current user + SYSTEM
before generation; Python `chmod` does not guarantee private Windows ACLs.

| Material | Purpose |
|---|---|
| `runtime/server-cert.pem`, `server-key.pem` | HTTPS certificate/key, read-only in the service |
| `runtime/client-ca.pem` | Trust for incoming client TLS certificates |
| `runtime/cpi-cert.pem` | Public pinned CPI certificate |
| `config/device.json` | Expected FCC ID, serial, category and technology |
| `signer/cpi-key.pem` | Private CPI signing key, never mounted in the service |
| `signer/server-ca.pem` | Public LAB server CA |
| `signer/test-client-cert.pem`, `test-client-key.pem` | Synthetic offline/curl client, not radio credentials |
| `signer/ca-key.pem` | Private LAB CA key, never exported or mounted in the service |

Generated credentials are explicitly test-only and valid for 30 days.
RS256/RSA >= 2048 is the default; `--cpi-alg ES256` uses P-256.
Keys are unencrypted PEM 0600 in private directories. Keep keys and PKCS#12
passwords outside Git, public bundles, logs and image layers.
The [certificate catalog](lab-certificates/README.md) describes their roles.

The generated device is deliberately fictional:

```json
{
  "fccId": "LABFCC001",
  "cbsdSerialNumber": "LAB-CBSD-0001",
  "cbsdCategory": "A",
  "radioTechnology": "NR"
}
```

Review and edit the private `config/device.json` to the intended LAB device
**before startup/registration**. The radio, signed CPI payload and configuration
must match. The service does not discover a radio, provision its credentials or
request its password/private key. Existing configurations are never overwritten.

## HTTPS and mTLS

```sh
docker compose -f compose.mock-sas.yml config
docker compose -f compose.mock-sas.yml up -d --no-build
docker compose -f compose.mock-sas.yml logs --tail=100 mock-sas
```

Gunicorn listens on 0.0.0.0:8443 inside the container; the default host publication
is 8443. `SAS_BIND_ADDRESS` restricts the interface, `SAS_HTTPS_PORT` changes the
published port. Configure the radio with the actual verified endpoint:

```text
https://ACTUAL_SERVER_DNS_NAME:ACTUAL_PUBLISHED_PORT/v1.2/
```

Limit reachability to the LAB network. TLS >= 1.2 is required, TLS 1.3 is allowed;
the original RSA/AES-GCM cipher compatibility is retained.

**mTLS is required by default.** Generated client trust initially accepts only
the synthetic test client. For a radio, supply the actual issuing CA chain/root
for its existing CBSD TLS certificate, verified independently. Do not replace its
private key with the test client's key. Untrusted/missing clients fail TLS before
registration/CPI. A successful CA import is not proof that the radio uses it.

For deliberately isolated registration-only testing,
`SAS_REQUIRE_CLIENT_CERT=false` disables client authentication, not HTTPS server
verification or CPI checks. Only literal `true`/`false` are accepted. This mode
cannot enable `lab-positive` and is not equivalent to WInnForum mTLS testing.

## Windows deployment launcher

### Interactive deployment: Windows and Linux

The two operator-side entry points share one English prompt/validation flow and
the same allowlisted package manifest. PowerShell delegates the confirmed inputs
to `Deploy-MockSas.ps1`; native Linux transport sends the **same**
`deploy-server.sh` payload. No alternate Docker/Compose ownership, port-selection
or credential pipeline is introduced.

Local prerequisites: supported Python 3 with the existing pinned
`deploy/mock-sas/requirements.txt`, Windows PowerShell 5.1+ or Linux Bash,
and OpenSSH `ssh`, `scp`, `ssh-keygen` for deployment. The Windows backend also
requires `tar`. No Docker daemon is needed on the operator machine. Create the
local environment once, then start the appropriate wizard from any directory:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\deploy\mock-sas\requirements.txt
.\deploy\mock-sas\Deploy-MockSas-Wizard.ps1
.\deploy\mock-sas\Deploy-MockSas-Wizard.ps1 -Help
```

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r deploy/mock-sas/requirements.txt
bash deploy/mock-sas/deploy-mock-sas-wizard.sh
bash deploy/mock-sas/deploy-mock-sas-wizard.sh --help
```

Setup commands are from the checkout root; entry points resolve their own
location. Override the interpreter with PowerShell `-Python PATH_TO_PYTHON`, or
Linux `PYTHON=/path/to/venv/bin/python`. Help requires no dependency environment or
SSH connection. Never put SSH/CPI/P12 passwords in environment overrides.

The wizard collects an actual **IPv4** HTTPS SAN/address (the existing SSH
pipeline does not provision DNS/IPv6 SANs), `root@HOST` SSH destination and port,
an optional existing private identity file or agent, and a previously verified
`known_hosts` file. DNS names are supported for the SSH target, not automatically
resolved into an invented HTTPS address. Paths with spaces are supported.
The known-host entry must match the exact SSH host/port, including hashed entries;
the operator must independently confirm its provenance. No unverified
`ssh-keyscan`, disabled host checking or automatic trust enrollment occurs.
OpenSSH itself handles any private-key passphrase; the wizard never asks for,
stores or prints it.

Client CA inputs must contain only public CA certificates and include the
**explicit independently verified root SHA256**. mTLS is mandatory in both
wizards. An optional original radio CA bundle is preserved in the merged public
export; keep every original CA. No private radio/server/CA key is requested.
The advanced launcher retains its separately acknowledged registration-only
no-client-certificate mode; the wizard deliberately does not offer it.

Blank HTTPS port preserves an owned deployment's port, or initially searches
8443-8542. An entered port is strict; nothing occupying it is stopped.
The default installation directory is `/opt/winnf-mock-sas-lab`; a dedicated
validated `/opt` or `/srv` path determines the existing project scope.
The default profile is implicit registration-only: existing positive deployments
cannot be silently downgraded. Select the actual existing profile when rerunning.
Keys, settings and durable state are preserved; differing inputs fail rather
than trigger regeneration, lease extension or silent migration.

For explicit `lab-positive`, the entire policy schema and both acknowledgments
are checked, its bounds are displayed, and the operator must type `RF-CONTAINED`.
Simulated AUTHORIZED responses **may cause radio transmission**: require verified
isolation in a properly RF-shielded anechoic chamber. Anechoic treatment alone
is not shielding or SAS authority. State version must match existing state;
v1-to-v2 migration remains separate stopped-worker maintenance.
Operator controls default to disabled and require separate explicit v2 consent;
enabling the socket fires no event.

All inputs are validated before the final summary. Type `PACKAGE` for an
offline public-input package, or `DEPLOY` for actual server preflight/upload/start.
Blank/decline, `cancel`, EOF or Ctrl+C **before confirmation** yields cancellation
and no deployment/upload/output changes. Interruption **after confirmation**
cannot undo an already started deployment: inspect the owned service/settings
before retrying. Backend failure is nonzero and never reported as success.

Deployment requires the already working rootful local Linux Docker/Compose v2
host described below. It builds natively on that server and starts only the
owned service with `--no-deps`; no dependency installation, firewall change,
other-stack restart, private credential download or radio/RF action is built in.
Outputs use a protected dedicated local directory and are public-only:
server CA, CPI certificate, optional complete radio+LAB bundle and public
device/deployment metadata. **Public does not mean publish your device metadata
to GitHub**; these operator-specific files remain ignored/private locally.

New deployment signer material resides in the server's root-only
`INSTALL_DIRECTORY/mock-sas-lab/signer/cpi-key.pem`; the matching pinned public
certificate is under `runtime/cpi-cert.pem`. Use the existing signer key when
signing again. Any deliberate secure CPI-key transfer to protected signer
storage is separate approved operator work, never automatic wizard/export
behavior. Do not transfer radio, server TLS or CA private keys.
See the [certificate catalog](lab-certificates/README.md).

Only local synthetic input, package and mocked-transport tests have exercised
these new wizards. They and the newer Linux image have **not** been deployed by
this feature; earlier evidence with one 5G small cell does not verify them.

### Advanced noninteractive Windows launcher

`Deploy-MockSas.ps1` uses Windows PowerShell 5.1+, OpenSSH and tar.
**Running it without `-PackageOnly` performs deployment.** It requires an
explicit `-ServerIp`; mTLS also requires an explicit verified
`-ClientCa` and `-ClientRootSha256`. Deployment requires `-SshTarget root@HOST`.
No server, radio CA fingerprint or real device is selected by a published
default. The following examples require your actual values:

```powershell
.\deploy\mock-sas\Deploy-MockSas.ps1 `
  -PackageOnly -ServerIp '192.0.2.10' `
  -ClientCa C:\Lab\radio-client-ca.pem `
  -ClientRootSha256 'REPLACE_WITH_VERIFIED_ROOT_SHA256' `
  -RadioTrustBundle C:\Lab\original-radio-trust-bundle.pem `
  -OutputDirectory C:\Lab\mock-sas-package
```

Replace the reserved IP and fingerprint placeholder. Packaging validates
public-only CA inputs and the exact root fingerprint, builds a per-file SHA256
manifest and makes **no SSH connection**. A deployment, after separate approval:

```powershell
.\deploy\mock-sas\Deploy-MockSas.ps1 `
  -ServerIp '192.0.2.10' -SshTarget 'root@lab-sas.example' `
  -ClientCa C:\Lab\radio-client-ca.pem `
  -ClientRootSha256 'REPLACE_WITH_VERIFIED_ROOT_SHA256' `
  -RadioTrustBundle C:\Lab\original-radio-trust-bundle.pem `
  -IdentityFile C:\Keys\lab-server-identity `
  -KnownHostsFile C:\Lab\verified-known-hosts
```

Use independently verified host pins and private SSH identity files.
`-KnownHostsFile` enforces `StrictHostKeyChecking=yes`; checking is never disabled.
Neither SSH keys nor host-key files are packaged. No passwords are embedded.
The execution-policy option, if needed, should be process-scoped only.

Defaults retained: SSH 22, deploy directory `/opt/winnf-mock-sas-lab`, preferred
HTTPS 8443, registration-only, state version 1 and controls off. A fresh deployment
uses 8443 if free, otherwise searches 8444-8542; an explicit `-HttpsPort` must be
free. Repeated deployment preserves the stored port and credentials. Outputs
default to private `mock-sas-deploy-output\lab-server`, or `lab-positive` for that
explicit profile; `-OutputDirectory` overrides this.

Before upload/writes, bounded coexistence checks identify the host/runtime,
existing containers/projects, listeners, Docker publications and directory
ownership. An owned, path-derived Compose project has protected markers/labels.
Unmarked/manual/foreign deployments are not adopted; ancestor symlinks, unsafe
ownership and ambiguous listener ownership fail. Checks repeat before startup.
Only the owned `mock-sas` service is started with `--no-deps`; no prune, other-stack
restart, global package install or firewall changes occur.

Remote requirements: rootful local Docker without user-namespace remapping,
Compose v2, root, Bash, tar, SHA256, flock, `ss` and GNU filesystem utilities.
Missing dependencies stop deployment; install them separately for the actual OS.
Content-addressed releases/images preserve earlier releases and existing keys.
Mismatched CA/key/SAN/settings, partial/expired credentials and unsafe ownership
fail rather than triggering silent regeneration or no-client-cert fallback.

Runtime/config/policy/rootfs are read-only; runtime UID/GID 10001 has one worker,
four threads, dropped capabilities and private `/tmp`. Only the dedicated
positive-profile state directory is persistent/writable. Preflight checks these
assumptions; do not mount the repository or a general-purpose directory writable.

The server-local probe verifies the configured IP/SAN and missing-client
rejection. It does not possess a radio private key or add the synthetic client's
CA to real trust. It is not authenticated radio HTTP health, external/firewall
reachability or proof of RF state.

Public exports: `radio-server-ca.pem`, optional complete
`radio-trust-bundle-with-lab.pem`, `cpi-cert.pem`, `device.json`, `deployment.json`.
Private keys are excluded from automatic downloads. Retain all original radio
CAs when adding the LAB CA; never overwrite the truststore with only the LAB root.
Keep private signer keys separate; any transfer requires deliberate approval.

## Registration/CPI workflow

Your signing software -> upload three CPI JWS fields through the vendor's normal
procedure -> radio sends its own `registrationRequest` -> original Mock SAS
verifies cryptography, signed schema and configured identity. No radio command,
certificate import, apply/reboot or RF action is performed by this guide.

Use a private signing directory and meaningful LAB-only installer identifiers.
The signed object contains `fccId`, `cbsdSerialNumber`, `installationParam` and
`professionalInstallerData`. Installation values must be operator-verified, not
invented to satisfy the schema. Category A still requires signed antennaGain;
Category B additionally requires antenna azimuth/downtilt/beamwidth.
Do not add unsigned installationParam alongside the CPI signature.

```python
payload = {
    "fccId": device["fccId"],
    "cbsdSerialNumber": device["cbsdSerialNumber"],
    "installationParam": installer_verified,
    "professionalInstallerData": {
        "cpiId": "LAB-ONLY-CPI",
        "cpiName": "LAB ONLY - not accredited",
        "installCertificationTime": intended_utc_time,
    },
}
token = jwt.encode(payload, matching_private_cpi_key, algorithm="RS256", headers={"typ": "JWT"})
fields = dict(zip(("protectedHeader", "encodedCpiSignedData", "digitalSignature"), token.split(".")))
```

Use the algorithm of the existing matching key (ES256 for P-256).
JWS segments are base64url without padding. Changing installation bytes requires
regenerating all three segments with the same intended matching signer key, not
patching a segment or rotating TLS/CPI certificates. Keep output/payload private.
The mock does not accredit a CPI from its name/public key or provide a signing CLI.

Every REG uses a fresh original scenario, not an after-test canned success.
It checks envelope/types, configured identity, CPI signature and signed schema.
Unsigned/HMAC signatures are rejected; RS256/RSA >= 2048 and ES256/P-256 are allowed.
Canonical/trailing/double-slash URLs return JSON directly without redirects.
NR is adapted only in the temporary scenario/config; historic scenarios remain.
Optional/empty `measCapability` is accepted; invalid values are rejected without
inventing measurements or weakening CPI.

The adapter checks pinned CPI validity at startup/on requests and rejects missing,
changed, expired or not-yet-valid certificates with visible service errors.
Preflight checks key matching and SAN/client trust. The actual verified Gunicorn
peer certificate, not headers, can further limit leases by validity.
No issuer-role, registry, CRL/OCSP or commercial PKI framework is simulated.

## Optional positive lifecycle and explicit controls

`lab-positive` requires mTLS, explicit profile/policy and both
`labOnlyAcknowledged`/`rfContainmentAcknowledged=true`. The committed
`lab-positive.example.json` deliberately has both false and cannot start it.
Copy it into private operator storage and review it before approving activation.

| Example policy | Limit |
|---|---|
| Band/tier | n48 3550-3700 MHz, GAA only |
| Bandwidths | 10/20/30/40/60/80/100 MHz |
| EIRP ceiling | 16 dBm/MHz, reject rather than clamp |
| Heartbeat | 60 seconds |
| Grant | 600 seconds, renewal only when `grantRenew=true` |
| Transmit | At most 180 seconds and never past grant expiry |

Signed `eirpCapability` can only narrow the approved ceiling. It does not widen
frequency/tier/policy or establish physically verified antenna/RF conditions.
The model does not choose the radio's channel, synthesize measurements or
implement ESC/DPA/PAL/multi-CBSD scheduling.

To package the explicitly reviewed positive profile, add
`-Profile lab-positive -LabPositiveConfig C:\Lab\reviewed-policy.json` to the
offline launcher command. Actual rollout is a separate operator decision.
The launcher selects `compose.mock-sas.lab-positive.yml` only for that profile.
For manual Compose, prepare private policy and state ownership first:

```sh
install -d -m 700 -o 10001 -g 10001 lab-state
docker compose -f compose.mock-sas.yml -f compose.mock-sas.lab-positive.yml config
```

One registered device, at most 15 disjoint grants and a 64 KiB snapshot are retained.
Atomic private JSON, fsync-before-success, one writer/process lock and shared
thread lock prevent concurrent HTTP/control writers. State binds device/profile/
exact policy/CPI certificate hashes; it contains no JWS, installation payload,
coordinates, installer details or private keys.

Restart preserves only still-valid IDs/parameters/original absolute deadlines
and remaining lifetimes. It never renews or produces a positive authorization
by itself. Expired grants are not resurrected; expired transmit state is not
restored as AUTHORIZED. New verified REG/deregistration/relinquishment durably
invalidate the corresponding old state before success.

Schema/version/binding/corruption/permission/storage/clock errors fail closed,
including health. Missing snapshots with existing lock metadata are not silently
reinitialized. Accurate trusted UTC is required; backwards time faults the
worker. Restored remaining time cannot exceed original UTC expiry or monotonic
remainder minus elapsed UTC. Whole-second advertised deadlines are authoritative.
Back up the complete private directory with its ownership/bindings during
reviewed maintenance; never edit IDs/expiry/checksums or force recovery by deleting
the lock. Already-lost memory-only sessions cannot be rebuilt from retries.
Persistence is a simulator robustness choice, not a WInnForum storage mandate.

A first valid GRANTED heartbeat may authorize an active grant. Inconsistent
AUTHORIZED state returns 502; repeated/unknown IDs fail rather than receiving
idempotent success. Renewal cannot revive expired grants. HTTP 200 is not protocol
success; failed heartbeats never include a future transmit lease.

Operator controls are default-disabled, require `lab-positive` plus explicit
`SAS_STATE_VERSION=2` and `SAS_OPERATOR_CONTROL_ENABLED=true`, and use no public
admin API/scheduler/extra service. Set these only after approved migration or
creation of a fresh v2 state directory; neither setting fires an event.
The UID 10001 worker owns a Linux Unix socket in private `/tmp` (0700/0600,
`SO_PEERCRED` UID 10001). Obtain IDs/generation privately only in an approved run:

```text
docker exec --user 10001:10001 OWNED_CONTAINER python operator_control.py status
docker exec --user 10001:10001 OWNED_CONTAINER python operator_control.py suspend --cbsd-id ID --generation GENERATION --grant-id GRANT --command-id 32_HEX_ID
```

Replace command placeholders with privately obtained IDs, the actual integer
generation and a unique 32-character lowercase hexadecimal command ID.
Explicit actions: suspend 501 retains the original grant deadline, resume itself
does not grant transmit permission (fresh GRANTED HB required), terminate 500
invalidates the grant, force-deregister 105 clears registration/all grants before
acknowledgment and targets only the former session. Unknown IDs still get 103.
No alternate frequency or blanket reset is invented. At most 16 command-dedup
records are retained 600 seconds; identical retries never extend deadlines.
Operator acknowledgment is not proof of immediate physical RF shutdown.

State version 1 remains default. To enable controls, explicitly migrate with the owned
worker stopped, private backup and reviewed existing checksum:

```text
python lab_state.py migrate --directory /state --device /config/device.json --policy /lab-policy.json --cpi-cert /credentials/cpi-cert.pem --expected-checksum REVIEWED_SHA256 --dry-run
```

Omit dry-run only after review. Migration preserves IDs/parameters/deadlines and
creates a private backup under the single-writer lock. There is no silent v1/v2
conversion, trust migration, backup restoration or authorized-state transfer to
new bindings. Incompatible experimental snapshots are rejected. Keeping controls
off after migration still requires the corresponding v2 reader.

## Scoped normative contracts

Reviewed [WINNF-TS-0016 V1.2.7, 21 March 2022](https://winnforum.org/wp-content/uploads/WInnForum/CBRS/WINNF-TS-0016.pdf),
SHA256 `4d651ecc8efdb3f6d3f945c18a6e262127a2b29cf7589967668ae78b36473e4f`.
This precise accessible revision is not a claim of latest-release certification.

| Contract | LAB behavior |
|---|---|
| 8.3.2/Table 13; Tables 39/40 | Failed REG omits cbsdId. Missing normative Required userId/fccId/serial gives 102 with parameter names; invalid values give 103. LAB-required category/air-interface/CPI are documented 103 restrictions, not universally normative 102. |
| 8.4.2 | Any partially/completely out-of-CBRS inquiry gives 300, without channels/responseData. Malformed/reversed ranges give 103. Narrower LAB policy inside CBRS does not automatically mean 300; batch entries are independent. |
| Tables 39/40 | Grant 401 returns all active conflicting grantIDs, including suspended ones; no success-only fields. |
| 8.6.1/Table 30 | Failed HB has nonfuture transmit expiry. Suspended 501 retains valid IDs/original grant expiry only for `grantRenew=true`; terminated 500 omits invalid grantID. |
| 8.7.2/8.8.2 | Unknown/repeated RLQ and invalid deregistration give 103/invalid-parameter names and omit invalid IDs; no fake 0 workaround. |
| Table 39 | Explicit targeted 105 recovery is durable and bounded, not generic success for arbitrary IDs. |

Public response schemas/tests are pinned to
[WInnForum/Spectrum-Access-System](https://github.com/Wireless-Innovation-Forum/Spectrum-Access-System/tree/928c3150adf7b31e53a96b695bf1fbdd3284ecb2).
They retain source attribution in `response_contracts.json`. Historical inquiry
spelling `FCC Part 96` is adapted only in the test validator; output follows
`FCC_PART_96`. Tests check conditional IDs/responseData/expiry beyond schema alone.
The historic mock uses v1.2/harness 1.0.0.3 and a WINNF v1.1 CPI schema with original
protected-header 128 and payload/signature 1024 limits; no full current SAS
certification, commercial authorization or real CPI accreditation is claimed.

## Checks and interpretation

Use a supported Python 3 environment and the dedicated pinned dependencies.
On Windows, create a local environment before the catalog's offline generation
command or the tests:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\deploy\mock-sas\requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s .\deploy\mock-sas -p 'test*.py'
```

On Linux, use `python3 -m venv .venv` and `.venv/bin/python` for the equivalent
installation/test commands, or use the existing built image runner:

```sh
python -m unittest discover -s deploy/mock-sas -p 'test*.py'
bash deploy/mock-sas/offline-image-check.sh EXISTING_LOCAL_IMAGE
```

The Linux image runner checks exact image/source hashes and uses `--network none`,
UID 10001, read-only root/source and private tmpfs, with no published ports.
Fixtures are synthetic and never replace operator keys. It includes actual LAB
Gunicorn mTLS/CPI and private IPC checks when supported. A Windows test run does
not verify a Linux image, UID ownership or actual IPC; report skipped checks.
No deployment/radio/RF claim is derived from local tests.

An earlier LAB lifecycle version has been exercised with **one 5G small cell
only**, including CPI-verified registration and successful heartbeats with
persisted state after restart. This is not evidence of interoperability with
other radios/vendors or real SAS authorization. The newer response-contract and
operator-control changes have local synthetic regression coverage only; this
public snapshot's Linux image/Gunicorn/UID 10001 IPC checks have not yet been run.
No dated installation diary, device identifier or operator trust material is
distributed with this fork.

Additional limitations: one configured device/one worker, no HA/replicas,
multi-CBSD/Domain Proxy/multi-step registration, commercial SAS/SAS-SAS,
incumbent/ESC/DPA/PAL coordination, real spectrum-availability assessment,
physical RF enforcement or CPI accreditation. Historical Python 2 launchers are
not migrated and current certification/full-harness compatibility is not claimed.

Use actual SAN/port and a synthetic client only in its isolated test deployment:

```sh
curl --cacert mock-sas-lab/signer/server-ca.pem \
  --cert mock-sas-lab/signer/test-client-cert.pem \
  --key mock-sas-lab/signer/test-client-key.pem \
  https://ACTUAL_SERVER_DNS_NAME:ACTUAL_PUBLISHED_PORT/healthz
```

Health is not a CPI test. Submit your signed single-step request via the normal
LAB workflow; inspect cryptographic/schema/identity acceptance and protocol 0.
Invalid signature/payload/identity/schema gives 103 without cbsdId; missing
normative Required parameters gives 102. Malformed envelopes give HTTP 400;
credential/storage service faults give HTTP 503, never success fallbacks.
Logs contain operation/result/state and parameter names, not payloads/JWS/keys.

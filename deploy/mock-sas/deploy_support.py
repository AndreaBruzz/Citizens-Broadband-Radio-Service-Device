"""Validation, public radio bundle export and TLS-only deployment probes."""

import argparse
import datetime
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import ssl
import tarfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import jsonschema

from lab_protocol import DEFAULT_PROFILE, POSITIVE_PROFILE, PROFILES, read_policy
from lab_state import StateStoreError, read_snapshot


def ca_certificates(path):
    data = Path(path).read_bytes()
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
    remainder = re.sub(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", b"", data, flags=re.S)
    if not blocks or remainder.strip():
        raise ValueError(f"{path}: expected only public PEM certificates, no keys or other content")
    certificates = [x509.load_pem_x509_certificate(block) for block in blocks]
    for cert in certificates:
        try:
            is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound as error:
            raise ValueError(f"{path}: CA certificate is missing BasicConstraints") from error
        if not is_ca:
            raise ValueError(f"{path}: bundle contains a non-CA certificate")
    return certificates


def fingerprints(certificates):
    return {cert.fingerprint(hashes.SHA256()).hex() for cert in certificates}


def write_preserving(path, data):
    path = Path(path)
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError(f"Refusing to overwrite different existing file: {path}")
        return
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o600)


def package_files(root):
    files = json.loads((Path(root) / "deploy/mock-sas/package-files.json").read_text())
    if (not isinstance(files, list) or not files or
            not all(isinstance(name, str) for name in files) or len(set(files)) != len(files)):
        raise ValueError("Package allowlist must be a nonempty unique list")
    for name in files:
        if (not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_./-]+", name) or
                PurePosixPath(name).is_absolute() or
                any(part in ("", ".", "..") for part in name.split("/"))):
            raise ValueError("Unsafe package allowlist path")
        source = Path(root) / name
        if not source.is_file() or source.is_symlink():
            raise ValueError("Package source is missing or a symlink: " + name)
    return files


def build_package(root, directory, client_ca, expected_root, radio_bundle=None, lab_policy=None):
    """Use the same source allowlist and content manifest as the Windows launcher."""
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected_root or ""):
        raise ValueError("An explicit verified root SHA256 is required")
    if expected_root.lower() not in fingerprints(ca_certificates(client_ca)):
        raise ValueError("Client CA does not contain the expected radio root SHA256 fingerprint")
    if radio_bundle:
        ca_certificates(radio_bundle)
    if lab_policy:
        read_policy(lab_policy)
    files = package_files(root)
    stage = Path(directory) / "source"
    stage.mkdir(mode=0o700)
    for name in files:
        destination = stage / name
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(Path(root) / name, destination)
    inputs = stage / "inputs"
    inputs.mkdir(mode=0o700)
    for name, source in (("client-ca.pem", client_ca), ("radio-trust-bundle.pem", radio_bundle),
                         ("lab-policy.json", lab_policy)):
        if source:
            shutil.copyfile(source, inputs / name)
    entries = sorted(path for path in stage.rglob("*") if path.is_file())
    manifest = "".join(hashlib.sha256(path.read_bytes()).hexdigest() + "  " +
                       path.relative_to(stage).as_posix() + "\n" for path in entries).encode()
    (stage / "package.sha256").write_bytes(manifest)
    archive = Path(directory) / "package.tar"
    with tarfile.open(archive, "w") as output:
        for path in sorted(stage.rglob("*")):
            output.add(path, arcname="./" + path.relative_to(stage).as_posix(), recursive=False)
    return archive, hashlib.sha256(archive.read_bytes()).hexdigest(), hashlib.sha256(manifest).hexdigest()


def validate_pair(cert_path, key_path):
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    encoding = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert.public_key().public_bytes(*encoding) != key.public_key().public_bytes(*encoding):
        raise ValueError(f"Certificate/private key mismatch: {cert_path}")
    now = datetime.datetime.now(datetime.timezone.utc)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError(f"Certificate not currently valid: {cert_path}; renew manually, do not overwrite existing keys")
    return cert


def prepare(credentials, settings_path, output, server_ip, port, mutual_tls,
            client_ca=None, expected_root=None, radio_trust_bundle=None, fresh=False,
            check_permissions=False, profile=DEFAULT_PROFILE, lab_policy=None,
            state_version=1, operator_control=False, state_directory=None):
    from app import DEVICE_SCHEMA

    credentials, output = Path(credentials), Path(output)
    if profile not in PROFILES:
        raise ValueError("Unsupported deployment profile")
    if state_version not in (1, 2):
        raise ValueError("Unsupported state configuration")
    if operator_control and (profile != POSITIVE_PROFILE or state_version != 2):
        raise ValueError("Operator controls require positive profile and explicit version2 migration")
    policy_digest = None
    if profile == POSITIVE_PROFILE:
        if not mutual_tls or lab_policy is None:
            raise ValueError("lab-positive deployment requires mTLS and explicit LAB policy")
        _, policy_digest = read_policy(lab_policy)
    elif lab_policy is not None:
        raise ValueError("LAB policy must not be supplied to registration-only deployment")
    settings = {
        "serverIp": server_ip, "httpsPort": port, "mutualTls": mutual_tls,
        "runtimeUid": 10001, "runtimeGid": 10001,
    }
    if Path(settings_path).exists() and json.loads(Path(settings_path).read_text()) != settings:
        raise ValueError("Existing deployment settings differ; preserve them or reconfigure explicitly by hand")
    if check_permissions:
        folders = [("runtime", 0 if fresh else 10001), ("config", 0 if fresh else 10001), ("signer", 0)]
        for folder, owner in folders:
            directory = credentials / folder
            if directory.is_symlink() or directory.stat().st_uid != owner or directory.stat().st_mode & 0o077:
                raise ValueError(f"Unexpected credentials directory ownership/mode: {directory}; correct manually")
        for key_path in [credentials / "runtime/server-key.pem", *(credentials / "signer").glob("*-key.pem")]:
            if key_path.is_symlink() or key_path.stat().st_mode & 0o077:
                raise ValueError(f"Private key permissions are not private: {key_path}")
    server_cert = validate_pair(credentials / "runtime/server-cert.pem", credentials / "runtime/server-key.pem")
    sans = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if ipaddress.ip_address(server_ip) not in sans.get_values_for_type(x509.IPAddress):
        raise ValueError("Existing server certificate does not include the requested IP SAN; no automatic regeneration")
    cpi_cert = validate_pair(credentials / "runtime/cpi-cert.pem", credentials / "signer/cpi-key.pem")
    key = cpi_cert.public_key()
    if not ((isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048) or
            (isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1))):
        raise ValueError("CPI key is not supported by this RS256/ES256 profile")
    device = json.loads((credentials / "config/device.json").read_text())
    jsonschema.validate(device, DEVICE_SCHEMA)
    if profile == POSITIVE_PROFILE and (device["cbsdCategory"] != "A" or device["radioTechnology"] != "NR"):
        raise ValueError("lab-positive deployment requires the verified Category A NR device")
    server_ca = credentials / "signer/server-ca.pem"
    ca_certificates(server_ca)
    if mutual_tls:
        if client_ca is None:
            raise ValueError("A real radio client CA is required for mTLS")
        incoming = ca_certificates(client_ca)
        if expected_root and expected_root.lower() not in fingerprints(incoming):
            raise ValueError("Client CA bundle does not contain the expected radio root SHA256 fingerprint")
        existing_path = credentials / "runtime/client-ca.pem"
        if fresh:
            existing_path.write_bytes(Path(client_ca).read_bytes())
        elif fingerprints(ca_certificates(existing_path)) != fingerprints(incoming):
            raise ValueError("Existing client CA differs from the supplied CA; refusing automatic trust replacement")
    if state_directory and profile == POSITIVE_PROFILE:
        directory = Path(state_directory)
        if (directory / "session.json").exists() or (directory / "session.json").is_symlink():
            bindings = {
                "device": hashlib.sha256(json.dumps(device, sort_keys=True).encode()).hexdigest(),
                "policy": policy_digest, "profile": profile,
                "cpiCertificate": hashlib.sha256((credentials / "runtime/cpi-cert.pem").read_bytes()).hexdigest(),
            }
            read_snapshot(directory, bindings, state_version, owner=10001 if check_permissions else None)
        elif (directory / "session.lock").exists():
            raise StateStoreError("Existing durable snapshot missing; no reinitialization")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_preserving(output / "radio-server-ca.pem", server_ca.read_bytes())
    write_preserving(output / "cpi-cert.pem", (credentials / "runtime/cpi-cert.pem").read_bytes())
    write_preserving(output / "device.json", (credentials / "config/device.json").read_bytes())
    if radio_trust_bundle:
        certificates = ca_certificates(radio_trust_bundle) + ca_certificates(server_ca)
        unique = {}
        for cert in certificates:
            unique.setdefault(cert.fingerprint(hashes.SHA256()), cert)
        bundle = b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in unique.values())
        write_preserving(output / "radio-trust-bundle-with-lab.pem", bundle)
    write_preserving(settings_path, (json.dumps(settings, indent=2) + "\n").encode())
    result = {
        "endpoint": f"https://{server_ip}:{port}/v1.2/",
        "serverCertificateSha256": server_cert.fingerprint(hashes.SHA256()).hex(),
        "cpiCertificateSha256": cpi_cert.fingerprint(hashes.SHA256()).hex(),
        "cpiAlgorithm": "RS256" if isinstance(key, rsa.RSAPublicKey) else "ES256",
        "serverCertificateExpires": server_cert.not_valid_after_utc.isoformat(),
        "mutualTls": mutual_tls, "radioEndToEndVerified": False,
    }
    if profile == POSITIVE_PROFILE:
        result.update(profile=profile, labPolicySha256=policy_digest,
                      labOnly=True, statePersistence="atomic-json")
    result.update(cpiCertificateExpires=cpi_cert.not_valid_after_utc.isoformat(),
                  stateVersion=state_version, operatorControlEnabled=operator_control)
    write_preserving(output / "deployment.json", (json.dumps(result, indent=2) + "\n").encode())
    return result


def probe_once(ca_path, server_ip, port, mutual_tls, connect_host=None):
    if connect_host is None:
        connect_host = server_ip
    context = ssl.create_default_context(cafile=str(ca_path))
    verified_server = False
    connection = http.client.HTTPConnection(connect_host, port, timeout=5)
    try:
        raw = socket.create_connection((connect_host, port), timeout=5)
        try:
            connection.sock = context.wrap_socket(raw, server_hostname=server_ip)
        except BaseException:
            raw.close()
            raise
        verified_server = True
        if mutual_tls:
            connection.sock.settimeout(1)
            try:
                data = connection.sock.recv(1)
            except TimeoutError:
                data = None
            if data is not None:
                raise ValueError("Server closed/sent application data without a verifiable client-certificate TLS alert")
            connection.sock.settimeout(5)
        connection.request("GET", "/healthz")
        response = connection.getresponse()
        body = response.read()
    except ssl.SSLError as error:
        if (mutual_tls and verified_server and
                error.reason in ("TLSV13_ALERT_CERTIFICATE_REQUIRED", "SSLV3_ALERT_HANDSHAKE_FAILURE")):
            return {
                "serverTlsAndSanVerified": True,
                "missingClientCertificateRejected": True,
                "httpsApplicationHealthVerified": False,
                "radioEndToEndVerified": False,
            }
        raise
    finally:
        connection.close()
    if mutual_tls:
        raise ValueError("mTLS policy failure: server answered HTTP without a client certificate")
    expected = {"status": "ready", "profile": "registration-cpi-only", "protocol": "v1.2"}
    document = json.loads(body)
    if (response.status != 200 or not isinstance(document, dict) or
            any(document.get(name) != value for name, value in expected.items())):
        raise ValueError("HTTPS application health failed")
    return {"serverTlsAndSanVerified": True, "httpsApplicationHealthVerified": True,
            "mutualTls": False, "radioEndToEndVerified": False}


def probe(ca_path, server_ip, port, mutual_tls, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        try:
            return probe_once(ca_path, server_ip, port, mutual_tls)
        except ssl.SSLError:
            raise
        except (ConnectionError, TimeoutError, OSError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("prepare")
    setup.add_argument("--credentials", required=True, type=Path)
    setup.add_argument("--settings", required=True, type=Path)
    setup.add_argument("--output", required=True, type=Path)
    setup.add_argument("--client-ca", type=Path)
    setup.add_argument("--expected-root")
    setup.add_argument("--radio-trust-bundle", type=Path)
    setup.add_argument("--fresh", action="store_true")
    setup.add_argument("--check-permissions", action="store_true")
    setup.add_argument("--profile", choices=PROFILES, default=DEFAULT_PROFILE)
    setup.add_argument("--lab-policy", type=Path)
    setup.add_argument("--state-version", type=int, choices=(1, 2), default=1)
    setup.add_argument("--operator-control", choices=("true", "false"), default="false")
    setup.add_argument("--state-directory", type=Path)
    check = commands.add_parser("probe")
    check.add_argument("--ca", required=True, type=Path)
    check.add_argument("--timeout", type=int, default=60)
    for command in (setup, check):
        command.add_argument("--server-ip", required=True)
        command.add_argument("--port", required=True, type=int)
        command.add_argument("--mutual-tls", choices=["true", "false"], required=True)
    args = parser.parse_args()
    mutual_tls = args.mutual_tls == "true"
    if args.command == "prepare":
        result = prepare(args.credentials, args.settings, args.output, args.server_ip,
                         args.port, mutual_tls, args.client_ca, args.expected_root,
                         args.radio_trust_bundle, args.fresh, args.check_permissions,
                         args.profile, args.lab_policy, args.state_version,
                         args.operator_control == "true",
                         args.state_directory)
    else:
        result = probe(args.ca, args.server_ip, args.port, mutual_tls, args.timeout)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

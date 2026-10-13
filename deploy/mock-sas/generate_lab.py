"""Generate new, explicitly LAB-only TLS and CPI credentials; never overwrite."""

import argparse
import datetime
import ipaddress
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def certificate(name, key, issuer_cert=None, issuer_key=None, ca=False, san=None, eku=None):
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mock SAS LAB ONLY"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_cert.public_key() if issuer_cert else key.public_key(),
        ), critical=False)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=not ca, content_commitment=False,
            key_encipherment=not ca and isinstance(key, rsa.RSAPrivateKey),
            data_encipherment=False, key_agreement=False,
            key_cert_sign=ca, crl_sign=ca,
            encipher_only=False, decipher_only=False,
        ), critical=True)
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(issuer_key or key, hashes.SHA256())


def write_key(path, key):
    with path.open("xb") as stream:
        path.chmod(0o600)
        stream.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))


def write_cert(path, cert):
    with path.open("xb") as stream:
        stream.write(cert.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o644)


def generate(output, dns_names, ip_addresses, cpi_algorithm="RS256"):
    san = [x509.DNSName(name) for name in dns_names]
    san.extend(x509.IPAddress(ipaddress.ip_address(address)) for address in ip_addresses)
    if not san:
        raise ValueError("Specify at least one real server DNS name or IP address")
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("Output directory must be empty; refusing to overwrite credentials")
    output.mkdir(parents=True, exist_ok=True)
    for folder in ("runtime", "signer", "config"):
        (output / folder).mkdir(mode=0o700)

    ca_key = private_key()
    ca_cert = certificate("LAB ONLY root CA", ca_key, ca=True)
    server_key = private_key()
    server_cert = certificate("LAB ONLY Mock SAS", server_key, ca_cert, ca_key,
                              san=san, eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    client_key = private_key()
    client_cert = certificate("LAB ONLY test client (not a real CBSD)", client_key,
                              ca_cert, ca_key, eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
    cpi_key = ec.generate_private_key(ec.SECP256R1()) if cpi_algorithm == "ES256" else private_key()
    cpi_cert = certificate("LAB ONLY CPI (no accreditation)", cpi_key, ca_cert, ca_key)

    write_key(output / "runtime" / "server-key.pem", server_key)
    write_cert(output / "runtime" / "server-cert.pem", server_cert)
    write_cert(output / "runtime" / "client-ca.pem", ca_cert)
    write_cert(output / "runtime" / "cpi-cert.pem", cpi_cert)
    write_key(output / "signer" / "ca-key.pem", ca_key)
    write_key(output / "signer" / "cpi-key.pem", cpi_key)
    write_key(output / "signer" / "test-client-key.pem", client_key)
    write_cert(output / "signer" / "test-client-cert.pem", client_cert)
    write_cert(output / "signer" / "server-ca.pem", ca_cert)
    (output / "config" / "device.json").write_text(json.dumps({
        "fccId": "LABFCC001",
        "cbsdSerialNumber": "LAB-CBSD-0001",
        "cbsdCategory": "A",
        "radioTechnology": "NR",
    }, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--dns", action="append", default=[], help="Actual server hostname; repeat for additional SANs")
    parser.add_argument("--ip", action="append", default=[], help="Actual server IP; repeat for additional SANs")
    parser.add_argument("--cpi-alg", choices=["RS256", "ES256"], default="RS256")
    args = parser.parse_args()
    generate(args.out, args.dns, args.ip, args.cpi_alg)
    print("Fresh LAB-only credentials created; valid for 30 days.")
    print("Mount runtime/ and config/ only; keep signer/ private and outside the server container.")


if __name__ == "__main__":
    main()

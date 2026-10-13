"""Shared interactive deployment inputs and native Linux transport; no automatic trust or installation."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = Path(__file__).parent
OUTPUT_NAMES = r"(radio-server-ca\.pem|radio-trust-bundle-with-lab\.pem|cpi-key\.pem|cpi-cert\.pem|device\.json|deployment\.json|package-[a-f0-9]{64}\.tar)"


class Cancelled(Exception):
    pass


def say(message):
    print(message, file=sys.stderr)


def ask(label, validate=str, default=""):
    while True:
        say(label + (f" [{default}]" if default else "") + ":")
        value = input().strip()
        if value.lower() == "cancel":
            raise Cancelled
        try:
            return validate(value or default)
        except (ValueError, OSError) as error:
            say("Invalid input: " + str(error))


def choice(*values):
    def validate(value):
        if value not in values:
            raise ValueError("Choose " + " / ".join(values) + ", or cancel")
        return value
    return validate


def ipv4(value):
    address = ipaddress.ip_address(value)
    if address.version != 4:
        raise ValueError("The existing deployment pipeline supports IPv4 SANs only; no DNS/IPv6 guessing")
    return str(address)


def port(value):
    if not re.fullmatch(r"[0-9]{1,5}", value) or not 1 <= int(value) <= 65535:
        raise ValueError("Port must be an integer from 1 to 65535")
    return int(value)


def target(value):
    if not re.fullmatch(r"root@[a-zA-Z0-9][a-zA-Z0-9.-]*", value):
        raise ValueError("Use root@HOST with an IPv4 address or DNS hostname; no whitespace/shell syntax/IPv6")
    return value


def remote_directory(value):
    if not re.fullmatch(r"/(opt|srv)/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*", value):
        raise ValueError("Use a dedicated /opt or /srv path with letters, digits, underscores or hyphens")
    return value


def file_path(value):
    if not value or any(character in value for character in ('"', "\r", "\n", "\x00")):
        raise ValueError("Supply a file path without double quotes or control characters; spaces are supported")
    path = Path(value).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError("File missing or symlink; supply an existing regular file")
    return str(path.resolve())


def output_directory(value):
    if not value or any(character in value for character in ("\r", "\n", "\x00")):
        raise ValueError("Supply a dedicated output directory")
    original = Path(value).expanduser().absolute()
    if any(path.is_symlink() for path in (original, *original.parents)):
        raise ValueError("Output directory/ancestors must not be symlinks")
    path = original.resolve()
    if path in (ROOT, Path.home().resolve(), Path(path.anchor)):
        raise ValueError("Output must not be the repository, home or filesystem root")
    if path.exists():
        if not path.is_dir():
            raise ValueError("Output is not a directory")
        for child in path.iterdir():
            if child.is_symlink() or not child.is_file() or not re.fullmatch(OUTPUT_NAMES, child.name):
                raise ValueError("Output contains unrelated/unsafe entries; choose a dedicated directory")
        if os.name == "posix" and (path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077):
            raise ValueError("Existing output must belong to this user with mode 0700")
        if os.name == "posix" and any(child.stat().st_uid != os.getuid() or
                                     child.stat().st_mode & 0o077 for child in path.iterdir()):
            raise ValueError("Existing output files must belong to this user with private permissions")
    return str(path)


def tool(name):
    executable = shutil.which(name)
    if not executable:
        raise ValueError(f"{name} missing; install prerequisites separately, no automatic installation")
    return executable


def known_hosts(value, ssh_target, ssh_port):
    path = file_path(value)
    if "%" in path or "$" in path:
        raise ValueError("known_hosts paths must not contain OpenSSH percent/environment expansion tokens")
    host = ssh_target.split("@", 1)[1]
    query = host if ssh_port == 22 else f"[{host}]:{ssh_port}"
    result = subprocess.run([tool("ssh-keygen"), "-F", query, "-f", path],
                            capture_output=True, text=True, check=False)
    if result.returncode != 0 or not result.stdout.strip():
        raise ValueError("known_hosts has no entry for this exact SSH host/port; verify it independently")
    return path


def collect(plan_only=False):
    from deploy_support import ca_certificates, fingerprints, package_files
    from lab_protocol import read_policy

    say("TEST-ONLY Mock SAS wizard. Type cancel or press Ctrl+C to cancel.")
    say("No SSH, uploads or deployment before the final explicit confirmation.")
    action = ask("Action: package (offline), deploy, or cancel", choice("package", "deploy"), "package")
    if plan_only:
        tool("tar")
    request = {"ServerIp": ask("Actual server IPv4 SAN/address (not a guessed DNS address)", ipv4)}
    if action == "deploy":
        tool("ssh")
        tool("scp")
        tool("ssh-keygen")
        request["SshTarget"] = ask("SSH destination (server preflight requires root)", target)
        request["SshPort"] = ask("SSH port", port, "22")
        identity = ask("Existing private SSH key file; blank uses the existing agent",
                       lambda value: file_path(value) if value else "")
        if identity:
            request["IdentityFile"] = identity
        request["KnownHostsFile"] = ask(
            "Independently verified known_hosts file",
            lambda value: known_hosts(value, request["SshTarget"], request["SshPort"]))
        if ask("Confirm the SSH host key was independently verified; type VERIFIED") != "VERIFIED":
            raise Cancelled
    while True:
        request["ClientCa"] = ask("Public CA PEM bundle issuing the radio's existing TLS certificate", file_path)
        fingerprint = ask("Independently verified client root SHA256 (64 hex characters)")
        if not re.fullmatch(r"[a-fA-F0-9]{64}", fingerprint):
            say("Invalid input: root SHA256 must have exactly 64 hexadecimal characters")
            continue
        try:
            if fingerprint.lower() not in fingerprints(ca_certificates(request["ClientCa"])):
                raise ValueError("Client CA does not contain the expected radio root SHA256 fingerprint")
        except (ValueError, OSError) as error:
            say("Invalid input: " + str(error))
            continue
        request["ClientRootSha256"] = fingerprint.lower()
        break

    def radio_bundle(value):
        if not value:
            return ""
        path = file_path(value)
        ca_certificates(path)
        return path

    bundle = ask("Existing complete public radio CA bundle (optional; NEVER replace it with only the LAB CA)",
                 radio_bundle)
    if bundle:
        request["RadioTrustBundle"] = bundle
    https = ask("HTTPS port; blank preserves an owned port or searches 8443-8542",
                lambda value: port(value) if value else None)
    if https is not None:
        request["HttpsPort"] = https
    request["RemoteDirectory"] = ask("Dedicated server installation directory",
                                     remote_directory, "/opt/winnf-mock-sas-lab")
    profile = ask("Profile: registration-cpi-only (default), or lab-positive",
                  lambda value: choice("registration-cpi-only", "lab-positive")(value) if value else "")
    if profile:
        request["Profile"] = profile
    if profile == "lab-positive":
        def policy_file(value):
            path = file_path(value)
            policy, _ = read_policy(path)
            say("Reviewed policy: " + json.dumps(policy, sort_keys=True))
            return path

        request["LabPositiveConfig"] = ask("Explicit reviewed positive LAB policy JSON", policy_file)
        say("WARNING: simulated AUTHORIZED responses MAY CAUSE RADIO TRANSMISSION.")
        say("Require a properly RF-SHIELDED anechoic chamber; anechoic treatment alone is NOT RF shielding.")
        if ask("Confirm verified RF containment and LAB-only use; type RF-CONTAINED") != "RF-CONTAINED":
            raise Cancelled
        request["StateVersion"] = ask("State version; must match existing state, NO automatic migration",
                                       choice("1", "2"), "1")
        controls = ask("Local operator controls (no events are fired)", choice("disabled", "enabled"), "disabled")
        if controls == "enabled":
            if request["StateVersion"] != "2":
                raise ValueError("Local operator controls require explicit v2 state; migrate offline first")
            if ask("Confirm local controls are deliberately enabled; type ENABLE-CONTROLS") != "ENABLE-CONTROLS":
                raise Cancelled
            request["EnableOperatorControl"] = True
    request["CpiAlgorithm"] = ask("CPI algorithm for a NEW LAB only; existing keys are preserved",
                                  choice("RS256", "ES256"), "RS256")
    request["OutputDirectory"] = ask("Dedicated private local output directory (public artifacts only)",
                                     output_directory, str(ROOT / "mock-sas-deploy-output" /
                                                           ("lab-positive" if profile == "lab-positive" else "lab-server")))
    package_files(ROOT)
    request["PackageOnly"] = action == "package"
    say("Final summary: " + json.dumps({
        "action": action, "target": request.get("SshTarget", "none - offline"),
        "directory": request["RemoteDirectory"], "profile": profile or "registration-cpi-only (implicit)",
        "port": request.get("HttpsPort", "preserve/select free port"), "mTLS": "required",
        "stateVersion": request.get("StateVersion", "1"),
        "operatorControls": request.get("EnableOperatorControl", False),
        "privateKeyDownloads": False,
    }, sort_keys=True))
    say("Existing credentials/settings/state are preserved or mismatches fail; no rotation/migration/firewall/install.")
    if ask(f"Type {action.upper()} to confirm, anything else cancels") != action.upper():
        raise Cancelled
    return request


def protect_output(path):
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_directory(str(directory))


def native_deploy(request):
    from deploy_support import build_package, write_preserving

    if sys.platform != "linux":
        raise ValueError("The native Bash backend requires Linux; use the PowerShell wizard on Windows")
    os.umask(0o077)
    protect_output(request["OutputDirectory"])
    output = Path(request["OutputDirectory"])
    with tempfile.TemporaryDirectory(prefix="winnf-mock-sas-package-") as temporary:
        archive, archive_sha, release = build_package(
            ROOT, temporary, request["ClientCa"], request["ClientRootSha256"],
            request.get("RadioTrustBundle"), request.get("LabPositiveConfig"))
        if request["PackageOnly"]:
            destination = output / f"package-{release}.tar"
            if destination.exists():
                raise ValueError("Package output already exists; choose a new output directory")
            write_preserving(destination, archive.read_bytes())
            say("Offline package created: " + str(destination))
            say("No SSH connection, credential generation or deployment performed.")
            return
        options = ["-o", "StrictHostKeyChecking=yes",
                   "-o", 'UserKnownHostsFile="' + request["KnownHostsFile"] + '"']
        if request.get("IdentityFile"):
            options += ["-i", request["IdentityFile"]]
        ssh = [tool("ssh"), "-p", str(request["SshPort"]), *options]
        scp = [tool("scp"), "-P", str(request["SshPort"]), *options]
        destination = request["SshTarget"]
        payload = (DEPLOY / "deploy-server.sh").read_text().replace("\r", "")
        explicit_profile = "true" if "Profile" in request else "false"
        profile = request.get("Profile", "registration-cpi-only")
        preflight = shlex.join(["bash", "-s", "--", "--preflight", request["RemoteDirectory"],
                               str(request.get("HttpsPort", 8443)),
                               "true" if "HttpsPort" in request else "false", profile, explicit_profile])
        result = subprocess.run([*ssh, "-T", destination, preflight], input=payload + "\n",
                                text=True, stdout=subprocess.PIPE, check=True)
        say(result.stdout.rstrip())
        selected = re.findall(r"^SELECTED_HTTPS_PORT=([0-9]+)$", result.stdout, re.M)
        if len(selected) != 1:
            raise ValueError("Unexpected preflight port-selection output; refusing upload")
        selected_port = port(selected[0])
        upload = subprocess.check_output(
            [*ssh, destination, "umask 077; mktemp -d /tmp/winnf-mock-sas-upload.XXXXXXXX"], text=True).strip()
        if not re.fullmatch(r"/tmp/winnf-mock-sas-upload\.[a-zA-Z0-9]+", upload):
            raise ValueError("Unexpected upload directory; refusing upload")
        try:
            subprocess.run([*scp, str(archive), f"{destination}:{upload}/package.tar"], check=True)
            command = shlex.join(["bash", "-s", "--", upload, request["RemoteDirectory"],
                                  request["ServerIp"], str(selected_port), "true", archive_sha,
                                  request["CpiAlgorithm"], request["ClientRootSha256"], profile,
                                  explicit_profile, request.get("StateVersion", "1"),
                                  "true" if request.get("EnableOperatorControl") else "false"])
            subprocess.run([*ssh, "-T", destination, command], input=payload + "\n", text=True, check=True)
            exports = request["RemoteDirectory"] + "/releases/" + release + "/exports"
            downloads = ["radio-server-ca.pem", "cpi-cert.pem", "device.json", "deployment.json"]
            if request.get("RadioTrustBundle"):
                downloads.append("radio-trust-bundle-with-lab.pem")
            for name in downloads:
                local = Path(temporary) / name
                subprocess.run([*scp, f"{destination}:{exports}/{name}", str(local)], check=True)
                write_preserving(output / name, local.read_bytes())
        finally:
            cleanup = subprocess.run([*ssh, destination, shlex.join(["rm", "-rf", "--", upload])], check=False)
            if cleanup.returncode != 0:
                say("WARNING: Could not remove the exact temporary remote upload directory: " + upload)
        say(f"Deployment checks completed: https://{request['ServerIp']}:{selected_port}/v1.2/ ({profile})")
        say("Public artifacts only: " + str(output) + "; no private keys downloaded.")
        say("Radio registration/RF not verified. Preserve every original radio CA and existing TLS identity.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true", help="Validated confirmed JSON request for the PowerShell wrapper")
    args = parser.parse_args(argv)
    confirmed = False
    try:
        request = collect(args.plan)
        confirmed = True
        if args.plan:
            print(json.dumps(request))
        else:
            native_deploy(request)
        return 0
    except (Cancelled, KeyboardInterrupt, EOFError):
        if confirmed:
            say("Interrupted after confirmation. Deployment may have started; inspect the owned deployment before retrying.")
        else:
            say("Cancelled. No deployment was requested by the wizard.")
        return 2
    except subprocess.CalledProcessError as error:
        say(f"ERROR: Deployment command failed (exit code {error.returncode}); inspect preceding output. No success claimed.")
        return 1
    except (ValueError, OSError, ImportError) as error:
        say("ERROR: " + str(error) + ". See the documented prerequisites; no fallback or automatic installation.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

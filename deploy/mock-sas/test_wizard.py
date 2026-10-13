"""Local wizard/packaging tests: synthetic inputs and mocked transport only."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import deployment_wizard as wizard
from deploy_support import build_package, ca_certificates, fingerprints, package_files
from generate_lab import generate

HERE = Path(__file__).parent
ROOT = HERE.parents[1]


class WizardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="mock-sas-wizard-")
        cls.directory = Path(cls.temporary.name)
        generate(cls.directory / "fixture with spaces", [], ["192.0.2.10"])
        cls.ca = cls.directory / "fixture with spaces/signer/server-ca.pem"
        cls.fingerprint = next(iter(fingerprints(ca_certificates(cls.ca))))
        cls.hosts = cls.directory / "verified hosts"
        cls.hosts.write_text("synthetic local test input\n")
        policy = json.loads((HERE / "lab-positive.example.json").read_text())
        policy.update(labOnlyAcknowledged=True, rfContainmentAcknowledged=True)
        cls.policy = cls.directory / "reviewed policy.json"
        cls.policy.write_text(json.dumps(policy))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def package_answers(self, confirmation="PACKAGE"):
        return ["package", "192.0.2.10", str(self.ca), self.fingerprint,
                "", "", "", "", "", str(self.directory / "public output"), confirmation]

    def deploy_answers(self, confirmation="DEPLOY"):
        return ["deploy", "192.0.2.10", "root@lab-sas.example", "", "", str(self.hosts),
                "VERIFIED", str(self.ca), self.fingerprint, "", "", "", "", "",
                str(self.directory / "public output"), confirmation]

    def collect(self, answers, plan_only=False):
        with mock.patch("builtins.input", side_effect=answers), \
                mock.patch.object(wizard, "tool", side_effect=lambda name: name), \
                mock.patch.object(wizard, "known_hosts", return_value=str(self.hosts)), \
                contextlib.redirect_stderr(io.StringIO()):
            return wizard.collect(plan_only)

    def test_package_defaults_are_mtls_offline_and_no_implicit_profile_port_change(self):
        request = self.collect(self.package_answers())
        self.assertTrue(request["PackageOnly"])
        for name in ("SshTarget", "HttpsPort", "Profile", "EnableOperatorControl", "IdentityFile"):
            self.assertNotIn(name, request)
        self.assertEqual(request["ClientRootSha256"], self.fingerprint)
        self.assertFalse((self.directory / "public output").exists())

    def test_deployment_inputs_are_forwarded_without_private_key_contents(self):
        request = self.collect(self.deploy_answers(), True)
        self.assertEqual(request["SshTarget"], "root@lab-sas.example")
        self.assertEqual(request["SshPort"], 22)
        self.assertEqual(request["KnownHostsFile"], str(self.hosts))
        self.assertFalse(request["PackageOnly"])
        self.assertNotIn("IdentityFile", request)

    def test_invalid_address_and_fingerprint_reprompt_before_any_action(self):
        answers = self.package_answers()
        answers[1:2] = ["::1", "lab-sas.example", "192.0.2.10"]
        answers[5:6] = ["0" * 64, str(self.ca), self.fingerprint]
        request = self.collect(answers)
        self.assertEqual(request["ServerIp"], "192.0.2.10")
        self.assertEqual(request["ClientRootSha256"], self.fingerprint)

    def test_declined_confirmation_and_eof_do_not_invoke_backend(self):
        for answers in (self.package_answers(""), ["cancel"]):
            with self.subTest(answers=len(answers)), mock.patch.object(wizard, "native_deploy") as backend, \
                    mock.patch("builtins.input", side_effect=answers), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(wizard.main([]), 2)
                backend.assert_not_called()
        with mock.patch("builtins.input", side_effect=EOFError), \
                mock.patch.object(wizard, "native_deploy") as backend, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(wizard.main([]), 2)
            backend.assert_not_called()

    def test_cancelled_positive_confirmation_does_not_enable_rf_profile(self):
        answers = ["package", "192.0.2.10", str(self.ca), self.fingerprint, "", "", "",
                   "lab-positive", str(self.policy), ""]
        with self.assertRaises(wizard.Cancelled):
            self.collect(answers)

    def test_positive_policy_and_explicit_v2_controls_require_both_acknowledgments(self):
        answers = ["package", "192.0.2.10", str(self.ca), self.fingerprint, "", "", "",
                   "lab-positive", str(self.policy), "RF-CONTAINED", "2", "enabled",
                   "ENABLE-CONTROLS", "", str(self.directory / "positive output"), "PACKAGE"]
        request = self.collect(answers)
        self.assertEqual(request["Profile"], "lab-positive")
        self.assertEqual(request["StateVersion"], "2")
        self.assertTrue(request["EnableOperatorControl"])
        invalid = answers[:]
        invalid[10] = "1"
        with self.assertRaisesRegex(ValueError, "v2"):
            self.collect(invalid)
        policy = json.loads(self.policy.read_text())
        policy["rfContainmentAcknowledged"] = False
        invalid_policy = self.directory / "unapproved policy.json"
        invalid_policy.write_text(json.dumps(policy))
        answers[8:9] = [str(invalid_policy), str(self.policy)]
        self.assertEqual(self.collect(answers)["LabPositiveConfig"], str(self.policy))

    def test_positive_controls_remain_disabled_by_default(self):
        answers = ["package", "192.0.2.10", str(self.ca), self.fingerprint, "", "", "",
                   "lab-positive", str(self.policy), "RF-CONTAINED", "", "", "",
                   str(self.directory / "positive output"), "PACKAGE"]
        request = self.collect(answers)
        self.assertEqual(request["StateVersion"], "1")
        self.assertNotIn("EnableOperatorControl", request)

    def test_public_ca_validation_rejects_private_key_and_wrong_fingerprint(self):
        with tempfile.TemporaryDirectory() as temporary:
            for ca, root in ((self.directory / "fixture with spaces/signer/cpi-key.pem", self.fingerprint),
                             (self.ca, "0" * 64)):
                with self.subTest(ca=ca.name), self.assertRaises(ValueError):
                    build_package(ROOT, temporary, ca, root)
            self.assertFalse((Path(temporary) / "source").exists())

    def test_missing_files_root_output_and_shell_target_are_rejected(self):
        with self.assertRaises(ValueError):
            wizard.file_path(str(self.directory / "missing"))
        for value in ("root@lab;echo", "other@lab", "root@-bad", "root@::1", "root@lab host"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                wizard.target(value)
        for value in (str(ROOT), str(Path.home()), str(Path(ROOT.anchor))):
            with self.subTest(value=value), self.assertRaises(ValueError):
                wizard.output_directory(value)
        for value in ("/", "/opt/../srv/other", "/opt/lab;echo"):
            with self.assertRaises(ValueError):
                wizard.remote_directory(value)
        for value in ("0", "65536", "01;echo"):
            with self.assertRaises(ValueError):
                wizard.port(value)

    def test_known_hosts_must_match_the_exact_host_port(self):
        expanded = self.directory / "host-%h"
        expanded.write_text("synthetic public host entry\n")
        with self.assertRaisesRegex(ValueError, "expansion tokens"):
            wizard.known_hosts(str(expanded), "root@lab-sas.example", 22)
        with mock.patch.object(wizard, "tool", return_value="ssh-keygen"), \
                mock.patch.object(subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 1, stdout="", stderr="")
            with self.assertRaisesRegex(ValueError, "exact SSH host/port"):
                wizard.known_hosts(str(self.hosts), "root@lab-sas.example", 2222)
            self.assertEqual(run.call_args.args[0][1:],
                             ["-F", "[lab-sas.example]:2222", "-f", str(self.hosts)])
            run.return_value = subprocess.CompletedProcess([], 0, stdout="matching synthetic entry\n")
            self.assertEqual(wizard.known_hosts(str(self.hosts), "root@lab-sas.example", 22), str(self.hosts))
            self.assertNotIn("ssh-keyscan", run.call_args.args[0])

    def test_missing_tools_and_backend_failures_are_nonzero_without_success(self):
        with mock.patch.object(shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "missing"):
                wizard.tool("ssh")
        for error in (ValueError("Docker preflight refused"), subprocess.CalledProcessError(9, ["synthetic-command"])):
            stream = io.StringIO()
            with mock.patch.object(wizard, "collect", return_value={}), \
                    mock.patch.object(wizard, "native_deploy", side_effect=error), \
                    contextlib.redirect_stderr(stream):
                self.assertEqual(wizard.main([]), 1)
                self.assertNotIn("completed", stream.getvalue())

    def test_interrupt_before_and_after_confirmation_is_reported_honestly(self):
        for confirmed in (False, True):
            stream = io.StringIO()
            with mock.patch.object(wizard, "collect", side_effect=None if confirmed else KeyboardInterrupt,
                                   return_value={}), \
                    mock.patch.object(wizard, "native_deploy", side_effect=KeyboardInterrupt) as backend, \
                    contextlib.redirect_stderr(stream):
                self.assertEqual(wizard.main([]), 2)
                if not confirmed:
                    backend.assert_not_called()
                    self.assertIn("No deployment was requested", stream.getvalue())
                else:
                    self.assertIn("may have started", stream.getvalue())

    def test_shared_package_manifest_has_only_allowlisted_public_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive, archive_hash, release = build_package(
                ROOT, temporary, self.ca, self.fingerprint, self.ca, self.policy)
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), archive_hash)
            with tarfile.open(archive) as package:
                members = {item.name.removeprefix("./"): item for item in package.getmembers() if item.isfile()}
                expected = set(package_files(ROOT)) | {
                    "inputs/client-ca.pem", "inputs/radio-trust-bundle.pem", "inputs/lab-policy.json", "package.sha256"}
                self.assertEqual(set(members), expected)
                for name in members:
                    self.assertNotIn("signer/", name)
                    self.assertFalse(name.endswith((".key", ".p12", ".pfx")))
                manifest = package.extractfile(members["package.sha256"]).read()
                self.assertEqual(hashlib.sha256(manifest).hexdigest(), release)
                for line in manifest.decode().splitlines():
                    digest, name = line.split("  ", 1)
                    self.assertEqual(hashlib.sha256(package.extractfile(members[name]).read()).hexdigest(), digest)

    def test_native_transport_reuses_server_payload_preflight_and_public_only_downloads(self):
        request = self.collect(self.deploy_answers(), True)
        with tempfile.TemporaryDirectory() as temporary:
            request["OutputDirectory"] = str(Path(temporary) / "output")
            calls = []
            payloads = []

            def run(command, **kwargs):
                calls.append(command)
                if "input" in kwargs:
                    payloads.append(kwargs["input"])
                if "--preflight" in command[-1]:
                    return subprocess.CompletedProcess(command, 0, stdout="SELECTED_HTTPS_PORT=8444\n")
                if command[0] == "scp" and ":/opt/" in command[-2]:
                    Path(command[-1]).write_bytes(b"synthetic public export")
                return subprocess.CompletedProcess(command, 0, stdout="")

            with mock.patch.object(sys, "platform", "linux"), \
                    mock.patch.object(wizard, "protect_output", side_effect=lambda path: Path(path).mkdir()), \
                    mock.patch.object(wizard, "tool", side_effect=lambda name: name), \
                    mock.patch.object(subprocess, "run", side_effect=run), \
                    mock.patch.object(subprocess, "check_output", return_value="/tmp/winnf-mock-sas-upload.FIXTURE\n"), \
                    mock.patch.dict(os.environ, {"SAS_WIZARD_SENTINEL": "not-a-credential"}), \
                    contextlib.redirect_stderr(io.StringIO()) as messages:
                wizard.native_deploy(request)
            self.assertTrue(all("StrictHostKeyChecking=yes" in command for command in calls))
            self.assertIn("false", calls[0][-1])
            self.assertEqual(payloads, [(HERE / "deploy-server.sh").read_text().replace("\r", "") + "\n"] * 2)
            downloads = [command[-2] for command in calls if command[0] == "scp" and ":/opt/" in command[-2]]
            self.assertEqual(len(downloads), 4)
            self.assertFalse(any("-key.pem" in name or ".p12" in name for name in downloads))
            self.assertNotIn("not-a-credential", messages.getvalue())
            self.assertIn("rm -rf -- /tmp/winnf-mock-sas-upload.FIXTURE", calls[-1][-1])

    def test_failed_preflight_does_not_upload_or_create_remote_directory(self):
        request = self.collect(self.deploy_answers(), True)
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(sys, "platform", "linux"), \
                mock.patch.object(wizard, "protect_output"), \
                mock.patch.object(wizard, "tool", side_effect=lambda name: name), \
                mock.patch.object(subprocess, "run", side_effect=subprocess.CalledProcessError(8, ["ssh"])) as run, \
                mock.patch.object(subprocess, "check_output") as create:
            request["OutputDirectory"] = temporary
            with self.assertRaises(subprocess.CalledProcessError):
                wizard.native_deploy(request)
            self.assertEqual(run.call_count, 1)
            create.assert_not_called()


class WrapperTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "PowerShell Windows interactive input")
    def test_real_shared_prompts_reach_windows_backend_only_after_confirmation(self):
        with tempfile.TemporaryDirectory(prefix="wizard prompt integration-") as temporary:
            root = Path(temporary)
            generate(root / "fixture", [], ["192.0.2.10"])
            ca = root / "fixture/signer/server-ca.pem"
            fingerprint = next(iter(fingerprints(ca_certificates(ca))))
            shutil.copyfile(HERE / "Deploy-MockSas-Wizard.ps1", root / "wizard.ps1")
            result_path = root / "forwarded.json"
            backend = root / "Deploy-MockSas.ps1"
            backend.write_text(
                "param([string]$ServerIp,[string]$ClientCa,[string]$ClientRootSha256,"
                "[string]$RemoteDirectory,[string]$CpiAlgorithm,[string]$OutputDirectory,[switch]$PackageOnly)\n"
                "$PSBoundParameters | ConvertTo-Json | Set-Content -LiteralPath '" +
                str(result_path).replace("'", "''") + "'\n")
            (root / "deployment_wizard.py").write_text(
                "import sys\nsys.path.insert(0, " + repr(str(HERE)) + ")\n"
                "import deployment_wizard\nraise SystemExit(deployment_wizard.main(['--plan']))\n")
            command = ["powershell", "-NoProfile", "-NonInteractive", "-File",
                       str(root / "wizard.ps1"), "-Python", sys.executable]
            answers = ["package", "192.0.2.10", str(ca), fingerprint, "", "", "", "", "",
                       str(root / "public output"), "PACKAGE"]
            result = subprocess.run(command, input="\n".join(answers) + "\n",
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(json.loads(result_path.read_text(encoding="utf-8-sig"))["PackageOnly"])
            self.assertIn("Final summary", result.stderr)
            result_path.unlink()
            answers[-1] = ""
            result = subprocess.run(command, input="\n".join(answers) + "\n",
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertFalse(result_path.exists())

    @unittest.skipUnless(os.name == "nt", "PowerShell Windows wrapper")
    def test_windows_wrapper_forwards_plan_once_and_propagates_errors(self):
        with tempfile.TemporaryDirectory(prefix="wizard wrappers with spaces-") as temporary:
            root = Path(temporary)
            shutil.copyfile(HERE / "Deploy-MockSas-Wizard.ps1", root / "Deploy-MockSas-Wizard.ps1")
            backend = root / "Deploy-MockSas.ps1"
            result_path = root / "result.json"
            backend.write_text("param([string]$ServerIp,[switch]$PackageOnly)\n"
                               "$PSBoundParameters | ConvertTo-Json | Set-Content -LiteralPath '" +
                               str(result_path).replace("'", "''") + "'\n")
            helper = root / "deployment_wizard.py"
            helper.write_text('print(\'{"ServerIp":"192.0.2.10","PackageOnly":true}\')\n')
            command = ["powershell", "-NoProfile", "-NonInteractive", "-File",
                       str(root / "Deploy-MockSas-Wizard.ps1"), "-Python", sys.executable]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30, cwd=root.parent)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result_path.read_text(encoding="utf-8-sig"))["ServerIp"], "192.0.2.10")
            result_path.unlink()
            helper.write_text("raise SystemExit(2)\n")
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(result_path.exists())
            helper.write_text('print(\'{"ServerIp":"192.0.2.10","PackageOnly":true}\')\n')
            backend.write_text("throw 'Synthetic backend failure'\n")
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Synthetic backend failure", result.stderr)

    def test_bash_wrapper_delegates_to_its_own_helper_with_spaces_and_propagates_failure(self):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("Bash unavailable")
        with tempfile.TemporaryDirectory(prefix="wizard bash with spaces-") as temporary:
            directory = Path(temporary)
            shutil.copyfile(HERE / "deploy-mock-sas-wizard.sh", directory / "wizard.sh")
            helper = directory / "deployment_wizard.py"
            helper.write_text("import pathlib\nprint(pathlib.Path(__file__).name)\n")
            env = os.environ.copy()
            env["PYTHON"] = sys.executable
            result = subprocess.run([bash, str(directory / "wizard.sh")], env=env, cwd=directory.parent,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("deployment_wizard.py", result.stdout)
            helper.write_text("raise SystemExit(7)\n")
            result = subprocess.run([bash, str(directory / "wizard.sh")], env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 7)
            env["PYTHON"] = str(directory / "missing-python")
            result = subprocess.run([bash, str(directory / "wizard.sh")], env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Python missing", result.stderr)

    def test_help_requires_no_runtime_dependencies_or_connections(self):
        result = subprocess.run([sys.executable, "-S", str(HERE / "deployment_wizard.py"), "--help"],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        bash = shutil.which("bash")
        if bash:
            result = subprocess.run([bash, str(HERE / "deploy-mock-sas-wizard.sh"), "--help"],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
        if os.name == "nt":
            result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-File",
                                     str(HERE / "Deploy-MockSas-Wizard.ps1"), "-Help"],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

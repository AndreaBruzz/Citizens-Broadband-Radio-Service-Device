import base64
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import datetime
from contextlib import nullcontext
import http.client
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import shlex
import shutil
import subprocess
import tarfile
import ssl
import stat
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
import jwt
import jsonschema
from referencing import Registry, Resource
from werkzeug.serving import make_server

from app import create_app, SOURCE
from generate_lab import generate, private_key
from deploy_support import ca_certificates, fingerprints, prepare, probe, probe_once
from lab_protocol import CredentialError, DEFAULT_PROFILE, LabSession, POSITIVE_PROFILE, read_policy
from lab_state import StateStore, StateStoreError
from lab_state import migrate_v1
from operator_control import ControlError, ControlServer, request_command

CONTRACT_SCHEMAS = json.loads(Path(__file__).with_name("response_contracts.json").read_text())["schemas"]
CONTRACT_REGISTRY = Registry().with_resources(
    ("file:" + name, Resource.from_contents(schema)) for name, schema in CONTRACT_SCHEMAS.items())
RESPONSE_VALIDATORS = {}
for operation in ("registration", "spectrumInquiry", "grant", "heartbeat", "relinquishment", "deregistration"):
    schema = deepcopy(CONTRACT_SCHEMAS[operation[0].upper() + operation[1:] + "Response.schema.json"])
    if operation == "spectrumInquiry":
        # The pinned SIQ tests require this spelling; the older public schema uses "FCC Part 96".
        schema["availableChannelObject"]["properties"]["ruleApplied"]["enum"] = ["FCC_PART_96"]
    RESPONSE_VALIDATORS[operation] = jsonschema.Draft4Validator(schema, registry=CONTRACT_REGISTRY)


def cleanup_app(app):
    control = app.extensions.get("lab_control")
    if control:
        control.close()
    store = app.extensions.get("lab_store")
    if store:
        store.close()
    app.extensions["lab_workspace"].cleanup()


def tls_config(required="true"):
    spec = importlib.util.spec_from_file_location("lab_tls_config", Path(__file__).with_name("gunicorn.conf.py"))
    config = importlib.util.module_from_spec(spec)
    with patch.dict(os.environ, {"SAS_REQUIRE_CLIENT_CERT": required}):
        spec.loader.exec_module(config)
    return config


def signature_data(payload, key, algorithm):
    token = jwt.encode(payload, key, algorithm=algorithm, headers={"typ": "JWT"})
    return dict(zip(
        ("protectedHeader", "encodedCpiSignedData", "digitalSignature"),
        token.split("."),
    ))


class RegistrationTests(unittest.TestCase):
    algorithm = "RS256"

    @classmethod
    def setUpClass(cls):
        cls.credentials = tempfile.TemporaryDirectory(prefix="mock-sas-tests-")
        cls.directory = Path(cls.credentials.name)
        generate(cls.directory, ["localhost"], ["127.0.0.1"], cls.algorithm)
        cls.app = create_app(cls.directory / "config" / "device.json",
                             cls.directory / "runtime" / "cpi-cert.pem")
        cls.key = serialization.load_pem_private_key(
            (cls.directory / "signer" / "cpi-key.pem").read_bytes(), password=None,
        )

    @classmethod
    def tearDownClass(cls):
        cls.app.extensions["lab_workspace"].cleanup()
        cls.credentials.cleanup()

    def payload(self):
        return {
            "fccId": "LABFCC001",
            "cbsdSerialNumber": "LAB-CBSD-0001",
            "installationParam": {
                "latitude": 0, "longitude": 0, "height": 1,
                "heightType": "AGL", "indoorDeployment": True, "antennaGain": 0,
            },
            "professionalInstallerData": {
                "cpiId": "LAB-ONLY-CPI", "cpiName": "LAB ONLY - not accredited",
                "installCertificationTime": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        }

    def registration(self, payload=None):
        return {
            "userId": "LAB-ONLY-USER", "fccId": "LABFCC001",
            "cbsdSerialNumber": "LAB-CBSD-0001", "cbsdCategory": "A",
            "airInterface": {"radioTechnology": "NR"},
            "measCapability": ["RECEIVED_POWER_WITHOUT_GRANT"],
            "cpiSignatureData": signature_data(payload or self.payload(), self.key, self.algorithm),
        }

    def post(self, registration, path="/v1.2/registration"):
        response = self.app.test_client().post(path, json={"registrationRequest": [registration]})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.is_json)
        self.assertNotIn("Location", response.headers)
        result = response.json["registrationResponse"][0]
        RESPONSE_VALIDATORS["registration"].validate(result)
        return result

    def rejected(self, registration, path="/v1.2/registration", code=103):
        response = self.post(registration, path)
        self.assertEqual(response["response"]["responseCode"], code)
        self.assertNotIn("cbsdId", response)
        return response

    def test_valid_nr_signature_and_trailing_slash(self):
        for path in ("/v1.2/registration", "/v1.2/registration/",
                     "/v1.2//registration", "/v1.2//registration/"):
            response = self.post(self.registration(), path)
            self.assertEqual(response["response"]["responseCode"], 0)
            self.assertIn("cbsdId", response)

    def test_double_slash_preserves_cpi_schema_and_identity_checks(self):
        for path in ("/v1.2//registration", "/v1.2//registration/"):
            with self.subTest(path=path):
                self.assertEqual(self.post(self.registration(), path)["response"]["responseCode"], 0)
                registration = self.registration()
                signature = registration["cpiSignatureData"]["digitalSignature"]
                registration["cpiSignatureData"]["digitalSignature"] = (
                    "A" if signature[0] != "A" else "B") + signature[1:]
                self.rejected(registration, path)
                payload = self.payload()
                payload["installationParam"]["height"] = 2
                registration = self.registration()
                registration["cpiSignatureData"]["encodedCpiSignedData"] = base64.urlsafe_b64encode(
                    json.dumps(payload).encode()).rstrip(b"=").decode()
                self.rejected(registration, path)
                payload = self.payload()
                del payload["professionalInstallerData"]
                self.rejected(self.registration(payload), path)
                payload = self.payload()
                payload["fccId"] = "OTHER-DEVICE"
                self.rejected(self.registration(payload), path)
                registration = self.registration()
                registration["fccId"] = "OTHER-DEVICE"
                self.rejected(registration, path)

    def test_required_property_diagnostics_log_only_missing_names(self):
        required = ("userId", "fccId", "cbsdSerialNumber", "cbsdCategory",
                    "airInterface", "cpiSignatureData")
        for path in ("/v1.2/registration", "/v1.2//registration"):
            for name in required:
                with self.subTest(path=path, missing=name):
                    registration = self.registration()
                    registration["userId"] = "DO-NOT-LOG-USER-VALUE"
                    signature_values = list(registration["cpiSignatureData"].values())
                    del registration[name]
                    with self.assertLogs("mock_sas_lab", level="WARNING") as captured:
                        result = self.rejected(
                            registration, path, 102 if name in required[:3] else 103)
                    self.assertEqual(result["response"]["responseData"], [name])
                    self.assertEqual(captured.output, [
                        "WARNING:mock_sas_lab:Registration schema rejected at $ (required); "
                        f"missing required properties: {name}",
                    ])
                    for sensitive in ("DO-NOT-LOG-USER-VALUE", "LAB-CBSD-0001",
                                      "LABFCC001", "LAB ONLY - not accredited", *signature_values):
                        self.assertNotIn(sensitive, captured.output[0])
        registration = self.registration()
        registration["airInterface"] = {}
        with self.assertLogs("mock_sas_lab", level="WARNING") as captured:
            self.rejected(registration, "/v1.2//registration")
        self.assertEqual(captured.output, [
            "WARNING:mock_sas_lab:Registration schema rejected at $.airInterface (required); "
            "missing required properties: radioTechnology",
        ])

    def test_registration_fault_lists_and_no_failed_identity(self):
        self.post(self.registration())
        item = self.registration()
        for name in ("userId", "fccId", "cbsdSerialNumber", "cpiSignatureData"):
            del item[name]
        result = self.rejected(item, code=102)
        self.assertEqual(result["response"]["responseData"], ["userId", "fccId", "cbsdSerialNumber"])
        for name, value in (("fccId", ""), ("airInterface", {}),
                            ("cbsdCategory", "B"), ("measCapability", "invalid")):
            with self.subTest(parameter=name):
                item = self.registration()
                item[name] = value
                result = self.rejected(item)
                self.assertEqual(result["response"]["responseData"], [name])
        item = self.registration()
        item["cpiSignatureData"]["digitalSignature"] = "AAAA"
        self.assertEqual(self.rejected(item)["response"]["responseData"], ["cpiSignatureData"])
        payload = self.payload()
        del payload["professionalInstallerData"]
        self.assertEqual(self.rejected(self.registration(payload))["response"]["responseData"],
                         ["cpiSignatureData"])

    def test_measurement_capability_optional_empty_and_supported_values(self):
        capabilities = (None, [], ["RECEIVED_POWER_WITHOUT_GRANT"],
                        ["RECEIVED_POWER_WITH_GRANT"],
                        ["RECEIVED_POWER_WITHOUT_GRANT", "RECEIVED_POWER_WITH_GRANT"],
                        ["RECEIVED_POWER_WITH_GRANT", "RECEIVED_POWER_WITHOUT_GRANT"])
        for path in ("/v1.2/registration", "/v1.2//registration"):
            for capability in capabilities:
                with self.subTest(path=path, capability=capability):
                    registration = self.registration()
                    if capability is None:
                        del registration["measCapability"]
                    else:
                        registration["measCapability"] = capability
                    original = json.dumps(registration, sort_keys=True)
                    response = self.post(registration, path)
                    self.assertEqual(response["response"]["responseCode"], 0)
                    self.assertIn("cbsdId", response)
                    self.assertEqual(json.dumps(registration, sort_keys=True), original)

    def test_measurement_scenario_adjustment_is_confined_to_temporary_copy(self):
        relative = Path("jsonExpectedFolder/REG_SingleStep_CPI_Success_cbsd1.json")
        original = json.loads((SOURCE / relative).read_text())
        expected = json.loads(json.dumps(original))
        self.assertIn("measCapability", original["registrationRequest"][0])
        del expected["registrationRequest"][0]["measCapability"]
        expected["registrationRequest"][0]["airInterface"]["radioTechnology"]["$or"].append("NR")
        copied = Path(self.app.extensions["lab_workspace"].name) / relative
        self.assertEqual(json.loads(copied.read_text()), expected)

    def test_optional_or_empty_measurement_does_not_bypass_cpi(self):
        for path in ("/v1.2/registration", "/v1.2//registration"):
            for capability in (None, []):
                for altered in ("signature", "payload"):
                    with self.subTest(path=path, capability=capability, altered=altered):
                        registration = self.registration()
                        if capability is None:
                            del registration["measCapability"]
                        else:
                            registration["measCapability"] = capability
                        if altered == "signature":
                            signature = registration["cpiSignatureData"]["digitalSignature"]
                            registration["cpiSignatureData"]["digitalSignature"] = (
                                "A" if signature[0] != "A" else "B") + signature[1:]
                        else:
                            payload = self.payload()
                            payload["installationParam"]["height"] = 2
                            registration["cpiSignatureData"]["encodedCpiSignedData"] = base64.urlsafe_b64encode(
                                json.dumps(payload).encode()).rstrip(b"=").decode()
                        self.rejected(registration, path)

    def test_invalid_measurement_types_and_enum_remain_rejected(self):
        for capability in ("", "RECEIVED_POWER_WITHOUT_GRANT", None, 1, {},
                           [""], ["INVALID"], [1],
                           ["RECEIVED_POWER_WITHOUT_GRANT", "INVALID"]):
            with self.subTest(capability=capability):
                registration = self.registration()
                registration["measCapability"] = capability
                self.rejected(registration, "/v1.2//registration")

    def test_altered_signature_rejected_even_after_success(self):
        self.assertEqual(self.post(self.registration())["response"]["responseCode"], 0)
        registration = self.registration()
        segment = registration["cpiSignatureData"]["digitalSignature"]
        registration["cpiSignatureData"]["digitalSignature"] = ("A" if segment[0] != "A" else "B") + segment[1:]
        self.rejected(registration)

    def test_altered_payload_rejected(self):
        registration = self.registration()
        payload = self.payload()
        payload["installationParam"]["height"] = 2
        registration["cpiSignatureData"]["encodedCpiSignedData"] = base64.urlsafe_b64encode(
            json.dumps(payload).encode()).rstrip(b"=").decode()
        self.rejected(registration)

    def test_signed_identity_mismatch_rejected(self):
        for field in ("fccId", "cbsdSerialNumber"):
            payload = self.payload()
            payload[field] = "OTHER-DEVICE"
            self.rejected(self.registration(payload))

    def test_invalid_signed_schema_rejected(self):
        payload = self.payload()
        payload["installationParam"]["latitude"] = 91
        self.rejected(self.registration(payload))
        payload = self.payload()
        del payload["professionalInstallerData"]
        self.rejected(self.registration(payload))

    def test_missing_cpi_and_unsigned_installation_rejected(self):
        registration = self.registration()
        del registration["cpiSignatureData"]
        registration["installationParam"] = self.payload()["installationParam"]
        self.rejected(registration)

    def test_both_installation_and_cpi_rejected(self):
        registration = self.registration()
        registration["installationParam"] = self.payload()["installationParam"]
        self.rejected(registration)

    def test_malformed_jws_and_none_algorithm_rejected(self):
        registration = self.registration()
        registration["cpiSignatureData"]["protectedHeader"] = "%%%"
        self.rejected(registration)
        registration = self.registration()
        registration["cpiSignatureData"] = signature_data(self.payload(), "", "none")
        self.rejected(registration)

    def test_wrong_cpi_key_rejected(self):
        key = private_key()
        registration = self.registration()
        registration["cpiSignatureData"] = signature_data(self.payload(), key, "RS256")
        self.rejected(registration)

    def test_optional_cbsd_info_and_unknown_technology(self):
        registration = self.registration()
        registration["cbsdInfo"] = {"vendor": "BLiNQ", "model": "PCW-400i", "firmwareVersion": "4.3.5_1"}
        self.assertEqual(self.post(registration)["response"]["responseCode"], 0)
        registration["airInterface"]["radioTechnology"] = "UNSUPPORTED"
        self.rejected(registration)

    def test_legacy_radio_technologies_preserved(self):
        for technology in ("E_UTRA", "CAMBIUM_NETWORKS"):
            config = json.loads((self.directory / "config" / "device.json").read_text())
            config["radioTechnology"] = technology
            path = self.directory / "config" / (technology + ".json")
            path.write_text(json.dumps(config))
            app = create_app(path, self.directory / "runtime" / "cpi-cert.pem")
            try:
                registration = self.registration()
                registration["airInterface"]["radioTechnology"] = technology
                response = app.test_client().post("/v1.2/registration", json={"registrationRequest": [registration]})
                self.assertEqual(response.json["registrationResponse"][0]["response"]["responseCode"], 0)
            finally:
                app.extensions["lab_workspace"].cleanup()

    def test_category_b_requires_original_antenna_parameters(self):
        config = json.loads((self.directory / "config" / "device.json").read_text())
        config["cbsdCategory"] = "B"
        path = self.directory / "config" / "category-b.json"
        path.write_text(json.dumps(config))
        app = create_app(path, self.directory / "runtime" / "cpi-cert.pem")
        try:
            registration = self.registration()
            registration["cbsdCategory"] = "B"
            client = app.test_client()
            response = client.post("/v1.2/registration", json={"registrationRequest": [registration]})
            self.assertEqual(response.json["registrationResponse"][0]["response"]["responseCode"], 103)
            payload = self.payload()
            payload["installationParam"].update(antennaAzimuth=0, antennaDowntilt=0, antennaBeamwidth=360)
            registration["cpiSignatureData"] = signature_data(payload, self.key, self.algorithm)
            response = client.post("/v1.2/registration", json={"registrationRequest": [registration]})
            self.assertEqual(response.json["registrationResponse"][0]["response"]["responseCode"], 0)
        finally:
            app.extensions["lab_workspace"].cleanup()

    def test_outer_identity_and_schema_rejected(self):
        for name, value in (("fccId", "OTHER"), ("cbsdSerialNumber", "OTHER"),
                            ("fccId", '"LABFCC001"'),
                            ("cbsdCategory", "B"), ("userId", 10),
                            ("cpiSignatureData", None)):
            registration = self.registration()
            registration[name] = value
            self.rejected(registration)

    def test_batch_has_independent_validation(self):
        invalid = self.registration()
        invalid["cpiSignatureData"]["digitalSignature"] = "AAAA"
        response = self.app.test_client().post("/v1.2/registration", json={
            "registrationRequest": [self.registration(), invalid],
        })
        self.assertEqual([item["response"]["responseCode"]
                          for item in response.json["registrationResponse"]], [0, 103])

    def test_envelope_and_unsupported_operations(self):
        client = self.app.test_client()
        for prefix in ("/v1.2/", "/v1.2//"):
            for suffix in ("", "/"):
                for envelope in ({}, {"registrationRequest": []}, {"registrationRequest": "bad"}):
                    response = client.post(prefix + "registration" + suffix, json=envelope)
                    self.assertEqual(response.status_code, 400)
                    self.assertTrue(response.is_json)
                    self.assertNotIn("Location", response.headers)
                for operation in ("grant", "heartbeat"):
                    response = client.post(prefix + operation + suffix, json={})
                    self.assertEqual(response.status_code, 404)
                    self.assertTrue(response.is_json)
                    self.assertNotIn("Location", response.headers)
                    self.assertEqual(response.json, {
                        "error": "LAB profile supports registration/CPI only; no grants or heartbeats",
                    })

    def test_https_mtls_network_and_hostname(self):
        config = tls_config()
        self.assertEqual(config.bind, "0.0.0.0:8443")
        self.assertEqual(config.cert_reqs, ssl.CERT_REQUIRED)

        def factory():
            context = ssl.create_default_context(
                ssl.Purpose.CLIENT_AUTH, cafile=str(self.directory / "runtime" / "client-ca.pem"),
            )
            context.load_cert_chain(str(self.directory / "runtime" / "server-cert.pem"),
                                    str(self.directory / "runtime" / "server-key.pem"))
            context.load_verify_locations(str(self.directory / "runtime" / "client-ca.pem"))
            context.verify_mode = config.cert_reqs
            context.set_ciphers(config.ciphers)
            return context

        context = config.ssl_context(None, factory)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        server = make_server("127.0.0.1", 0, self.app, ssl_context=context)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            client_context = ssl.create_default_context(cafile=str(self.directory / "signer" / "server-ca.pem"))
            connection = http.client.HTTPSConnection("127.0.0.1", server.server_port, context=client_context, timeout=5)
            with self.assertRaises((ssl.SSLError, ConnectionError)):
                connection.request("GET", "/healthz")
                connection.getresponse()
            connection.close()
            result = probe(self.directory / "signer/server-ca.pem", "127.0.0.1",
                           server.server_port, True, timeout=10)
            self.assertTrue(result["missingClientCertificateRejected"])
            self.assertFalse(result["httpsApplicationHealthVerified"])
            self.assertFalse(result["radioEndToEndVerified"])
            untrusted = self.directory / "untrusted-client"
            generate(untrusted, ["localhost"], [], self.algorithm)
            untrusted_context = ssl.create_default_context(cafile=str(self.directory / "signer" / "server-ca.pem"))
            untrusted_context.load_cert_chain(str(untrusted / "signer" / "test-client-cert.pem"),
                                              str(untrusted / "signer" / "test-client-key.pem"))
            connection = http.client.HTTPSConnection("127.0.0.1", server.server_port, context=untrusted_context, timeout=5)
            with self.assertRaises((ssl.SSLError, ConnectionError)):
                connection.request("GET", "/healthz")
                connection.getresponse()
            connection.close()
            client_context.load_cert_chain(str(self.directory / "signer" / "test-client-cert.pem"),
                                           str(self.directory / "signer" / "test-client-key.pem"))
            with socket.create_connection(("127.0.0.1", server.server_port), timeout=5) as raw_socket:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    client_context.wrap_socket(raw_socket, server_hostname="wrong-host.invalid")
            connection = http.client.HTTPSConnection("127.0.0.1", server.server_port, context=client_context, timeout=5)
            connection.request("GET", "/healthz")
            self.assertEqual(connection.getresponse().status, 200)
            connection.close()
            client_context.maximum_version = ssl.TLSVersion.TLSv1_2
            for valid in (True, False):
                registration = self.registration()
                if not valid:
                    registration["cpiSignatureData"]["digitalSignature"] = "AAAA"
                connection = http.client.HTTPSConnection("localhost", server.server_port, context=client_context, timeout=5)
                connection.request("POST", "/v1.2/registration",
                                   json.dumps({"registrationRequest": [registration]}),
                                   {"Content-Type": "application/json"})
                response = json.loads(connection.getresponse().read())
                self.assertEqual(response["registrationResponse"][0]["response"]["responseCode"], 0 if valid else 103)
                connection.close()
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_explicit_optional_mtls_and_invalid_setting(self):
        self.assertEqual(tls_config("false").cert_reqs, ssl.CERT_NONE)
        self.assertIsNone(tls_config("false").ca_certs)
        with self.assertRaises(ValueError):
            tls_config("False")

    def test_startup_rejects_missing_cpi_certificate(self):
        with self.assertRaises(FileNotFoundError):
            create_app(self.directory / "config" / "device.json",
                       self.directory / "runtime" / "missing-cpi-cert.pem")

    def test_pinned_cpi_validity_boundaries_fail_closed_without_renewal(self):
        certificate = x509.load_pem_x509_certificate((self.directory / "runtime/cpi-cert.pem").read_bytes())
        clock = TestClock()
        clock.utc = certificate.not_valid_before_utc
        app = create_app(self.directory / "config/device.json", self.directory / "runtime/cpi-cert.pem",
                         credential_clock=clock)
        try:
            health = app.test_client().get("/healthz")
            self.assertEqual(health.status_code, 200)
            self.assertNotIn("pkiMode", health.json)
            self.assertEqual(health.json["cpiCertificateExpires"], certificate.not_valid_after_utc.isoformat())
            for invalid in (certificate.not_valid_before_utc - datetime.timedelta(seconds=1),
                            certificate.not_valid_after_utc):
                clock.utc = invalid
                for path, method, body in (("/healthz", "get", None),
                                          ("/v1.2/registration", "post",
                                           {"registrationRequest": [self.registration()]})):
                    response = getattr(app.test_client(), method)(path, json=body)
                    self.assertEqual(response.status_code, 503)
                    self.assertNotIn("registrationResponse", response.json)
                with self.assertRaises(CredentialError):
                    create_app(self.directory / "config/device.json", self.directory / "runtime/cpi-cert.pem",
                               credential_clock=clock)
        finally:
            cleanup_app(app)

    def test_missing_changed_pin_and_verifier_io_are_sanitized_failures(self):
        with tempfile.TemporaryDirectory(prefix="mock-sas-pin-tests-") as temporary:
            pin = Path(temporary) / "cpi-cert.pem"
            original = (self.directory / "runtime/cpi-cert.pem").read_bytes()
            pin.write_bytes(original)
            app = create_app(self.directory / "config/device.json", pin)
            try:
                with patch("app.CBRSRequestHandler.handle_Http_Req",
                           side_effect=OSError("fixture-private-detail")):
                    with self.assertLogs("mock_sas_lab", level="ERROR") as logs:
                        response = app.test_client().post("/v1.2/registration",
                                                         json={"registrationRequest": [self.registration()]})
                self.assertEqual(response.status_code, 503)
                self.assertNotIn("registrationResponse", response.json)
                self.assertNotIn("fixture-private-detail", "\n".join(logs.output))
                self.assertNotIn("fixture-private-detail", response.get_data(as_text=True))
                pin.write_bytes(original + b"\n")
                self.assertEqual(app.test_client().get("/healthz").status_code, 503)
                pin.unlink()
                self.assertEqual(app.test_client().get("/healthz").status_code, 503)
                self.assertEqual((self.directory / "runtime/cpi-cert.pem").read_bytes(), original)
            finally:
                cleanup_app(app)

    def test_generator_refuses_overwrite(self):
        with self.assertRaises(FileExistsError):
            generate(self.directory, ["localhost"], [], self.algorithm)


class ES256RegistrationTests(RegistrationTests):
    algorithm = "ES256"


@unittest.skipUnless(sys.platform == "linux" and importlib.util.find_spec("gunicorn"),
                     "Actual Gunicorn runtime requires Linux")
class LinuxGunicornTests(unittest.TestCase):
    algorithm = "ES256"
    payload = RegistrationTests.payload
    registration = RegistrationTests.registration

    def test_actual_lab_mtls_worker_factory_and_cpi(self):
        runtime = Path(create_app.__code__.co_filename).resolve().parent
        with tempfile.TemporaryDirectory(prefix="mock-sas-gunicorn-lab-") as temporary:
            directory = Path(temporary)
            generate(directory, ["localhost"], ["127.0.0.1"], self.algorithm)
            self.key = serialization.load_pem_private_key(
                (directory / "signer/cpi-key.pem").read_bytes(), password=None)
            environment = os.environ.copy()
            environment.update(
                SAS_PROFILE=DEFAULT_PROFILE, SAS_STATE_VERSION="1", SAS_OPERATOR_CONTROL_ENABLED="false",
                SAS_REQUIRE_CLIENT_CERT="true", SAS_DEVICE_CONFIG=str(directory / "config/device.json"),
                SAS_CPI_CERT=str(directory / "runtime/cpi-cert.pem"),
                SAS_TLS_CERT=str(directory / "runtime/server-cert.pem"),
                SAS_TLS_KEY=str(directory / "runtime/server-key.pem"),
                SAS_CLIENT_CA=str(directory / "runtime/client-ca.pem"))
            client = ssl.create_default_context(cafile=str(directory / "signer/server-ca.pem"))
            client.load_cert_chain(str(directory / "signer/test-client-cert.pem"),
                                   str(directory / "signer/test-client-key.pem"))
            with socket.socket() as listener, (directory / "worker.log").open("wb") as log:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                port = listener.getsockname()[1]
                process = subprocess.Popen(
                    [sys.executable, "-m", "gunicorn", "--config", str(runtime / "gunicorn.conf.py"),
                     "--bind", "fd://" + str(listener.fileno()), "app:create_app()"],
                    cwd=runtime, env=environment, pass_fds=(listener.fileno(),), stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        self.assertIsNone(process.poll(), "LAB worker failed startup; see temporary test log")
                        connection = http.client.HTTPSConnection("127.0.0.1", port, context=client, timeout=0.5)
                        try:
                            connection.request("GET", "/healthz")
                            response = connection.getresponse()
                            self.assertEqual(response.status, 200)
                            self.assertEqual(json.loads(response.read())["profile"], DEFAULT_PROFILE)
                            break
                        except (OSError, http.client.HTTPException):
                            time.sleep(0.05)
                        finally:
                            connection.close()
                    else:
                        self.fail("LAB worker did not become ready within the bounded local check")
                    result = probe(directory / "signer/server-ca.pem", "127.0.0.1", port, True, timeout=5)
                    self.assertTrue(result["missingClientCertificateRejected"])
                    for valid in (True, False):
                        item = self.registration()
                        if not valid:
                            item["cpiSignatureData"]["digitalSignature"] = "AAAA"
                        connection = http.client.HTTPSConnection("127.0.0.1", port, context=client, timeout=5)
                        try:
                            connection.request("POST", "/v1.2//registration",
                                               json.dumps({"registrationRequest": [item]}),
                                               {"Content-Type": "application/json"})
                            response = connection.getresponse()
                            self.assertEqual(response.status, 200)
                            body = json.loads(response.read())["registrationResponse"][0]
                            RESPONSE_VALIDATORS["registration"].validate(body)
                            self.assertEqual(body["response"]["responseCode"], 0 if valid else 103)
                            self.assertEqual("cbsdId" in body, valid)
                        finally:
                            connection.close()
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


class TestClock:
    def __init__(self):
        self.utc = datetime.datetime(2026, 10, 9, 10, 0, tzinfo=datetime.timezone.utc)
        self.tick = 1000

    def now(self):
        return self.utc

    def monotonic(self):
        return self.tick

    def advance(self, seconds):
        self.utc += datetime.timedelta(seconds=seconds)
        self.tick += seconds


class PositiveTests(unittest.TestCase):
    algorithm = "RS256"
    payload = RegistrationTests.payload
    registration = RegistrationTests.registration
    post = RegistrationTests.post
    rejected = RegistrationTests.rejected

    @classmethod
    def setUpClass(cls):
        cls.test_apps = []
        cls.credentials = tempfile.TemporaryDirectory(prefix="mock-sas-positive-tests-")
        cls.directory = Path(cls.credentials.name)
        generate(cls.directory, ["localhost"], ["127.0.0.1"], cls.algorithm)
        cls.key = serialization.load_pem_private_key(
            (cls.directory / "signer/cpi-key.pem").read_bytes(), password=None)
        cls.policy = json.loads(Path(__file__).with_name("lab-positive.example.json").read_text())
        cls.policy.update(labOnlyAcknowledged=True, rfContainmentAcknowledged=True)
        cls.policy_path = cls.directory / "policy.json"
        cls.policy_path.write_text(json.dumps(cls.policy))
        cls.configure_response_contracts()

    @classmethod
    def configure_response_contracts(cls):
        cls.response_validators = RESPONSE_VALIDATORS

    @classmethod
    def tearDownClass(cls):
        for app in cls.test_apps:
            cleanup_app(app)
        cls.credentials.cleanup()

    def setUp(self):
        self.clock = TestClock()
        self.app = self.new_app()
        self.cbsd_id = None

    def tearDown(self):
        cleanup_app(self.app)

    def new_app(self, profile=POSITIVE_PROFILE, policy_path=None, state_directory=None,
                state_version=1, operator_control=False):
        state_directory = state_directory or tempfile.mkdtemp(prefix="state-", dir=self.directory)
        app = create_app(self.directory / "config/device.json",
                         self.directory / "runtime/cpi-cert.pem",
                         profile, policy_path or self.policy_path, self.clock, state_directory,
                         state_version=state_version, operator_control=operator_control)
        self.test_apps.append(app)
        return app

    def register(self):
        self.cbsd_id = self.post(self.registration())["cbsdId"]
        return self.cbsd_id

    def operation(self, operation, item, prefix="/v1.2/", suffix=""):
        response = self.app.test_client().post(
            prefix + operation + suffix, json={operation + "Request": [item]})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.is_json)
        self.assertNotIn("Location", response.headers)
        self.assertEqual(set(response.json), {operation + "Response"})
        self.assertEqual(len(response.json[operation + "Response"]), 1)
        result = response.json[operation + "Response"][0]
        self.assertIsInstance(result["response"]["responseCode"], int)
        if operation in self.response_validators:
            self.response_validators[operation].validate(result)
        if result["response"]["responseCode"] == 0:
            self.assertEqual(result["cbsdId"], self.cbsd_id)
            if operation == "grant":
                self.assertEqual(set(result), {
                    "cbsdId", "grantId", "operationParam", "heartbeatInterval",
                    "grantExpireTime", "channelType", "response",
                })
                self.assertIsInstance(result["grantId"], str)
                self.assertTrue(result["grantId"])
                self.parsed_time(result["grantExpireTime"])
            elif operation == "spectrumInquiry":
                self.assertEqual(set(result), {"cbsdId", "availableChannel", "response"})
                for channel in result["availableChannel"]:
                    self.assertEqual(set(channel), {"frequencyRange", "channelType", "ruleApplied", "maxEirp"})
            elif operation in ("heartbeat", "relinquishment"):
                self.assertEqual(result["grantId"], item["grantId"])
        elif operation == "grant":
            self.assertNotIn("grantId", result)
            self.assertNotIn("grantExpireTime", result)
            self.assertNotIn("operationParam", result)
        if operation == "heartbeat":
            self.parsed_time(result["transmitExpireTime"])
        return result

    def test_verified_signed_capability_can_only_narrow_policy(self):
        payload = self.payload()
        payload["installationParam"]["eirpCapability"] = 10
        self.cbsd_id = self.post(self.registration(payload))["cbsdId"]
        inquiry = self.operation("spectrumInquiry", {
            "cbsdId": self.cbsd_id,
            "inquiredSpectrum": [{"lowFrequency": 3550000000, "highFrequency": 3570000000}],
        })
        self.assertEqual(inquiry["availableChannel"][0]["maxEirp"], 0)
        self.assertEqual(self.grant()["response"]["responseCode"], 103)
        self.assertEqual(self.operation("grant", self.grant_request(power=0))["response"]["responseCode"], 0)

    def grant_request(self, low=3550000000, width=20000000, power=16):
        return {
            "cbsdId": self.cbsd_id,
            "operationParam": {
                "maxEirp": power,
                "operationFrequencyRange": {"lowFrequency": low, "highFrequency": low + width},
            },
        }

    def heartbeat_request(self, grant_id, state="GRANTED", renew=None):
        item = {"cbsdId": self.cbsd_id, "grantId": grant_id, "operationState": state}
        if renew is not None:
            item["grantRenew"] = renew
        return item

    def grant(self):
        return self.operation("grant", self.grant_request())

    def parsed_time(self, text):
        return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)

    def test_complete_flow_on_all_radio_url_variants(self):
        for prefix in ("/v1.2/", "/v1.2//"):
            for suffix in ("", "/"):
                self.register()
                inquiry = self.operation("spectrumInquiry", {
                    "cbsdId": self.cbsd_id,
                    "inquiredSpectrum": [{"lowFrequency": 3550000000, "highFrequency": 3700000000}],
                }, prefix, suffix)
                self.assertEqual(inquiry["response"]["responseCode"], 0)
                self.assertEqual(inquiry["availableChannel"], [{
                    "frequencyRange": {"lowFrequency": 3550000000, "highFrequency": 3700000000},
                    "channelType": "GAA", "ruleApplied": "FCC_PART_96", "maxEirp": 16,
                }])
                grant = self.operation("grant", self.grant_request(), prefix, suffix)
                self.assertEqual(grant["response"]["responseCode"], 0)
                self.assertEqual(grant["operationParam"], self.grant_request()["operationParam"])
                self.assertEqual(grant["heartbeatInterval"], 60)
                self.assertEqual(self.parsed_time(grant["grantExpireTime"]),
                                 self.clock.now() + datetime.timedelta(seconds=600))
                heartbeat = self.operation("heartbeat", self.heartbeat_request(grant["grantId"]), prefix, suffix)
                self.assertEqual(heartbeat["response"]["responseCode"], 0)
                self.assertEqual(self.parsed_time(heartbeat["transmitExpireTime"]),
                                 self.clock.now() + datetime.timedelta(seconds=180))
                self.clock.advance(60)
                renewal = self.operation("heartbeat", self.heartbeat_request(
                    grant["grantId"], "AUTHORIZED", True), prefix, suffix)
                self.assertEqual(renewal["response"]["responseCode"], 0)
                self.assertEqual(self.parsed_time(renewal["grantExpireTime"]),
                                 self.clock.now() + datetime.timedelta(seconds=600))
                identifiers = {"cbsdId": self.cbsd_id, "grantId": grant["grantId"]}
                self.assertEqual(self.operation("relinquishment", identifiers, prefix, suffix)
                                 ["response"]["responseCode"], 0)
                denied = self.operation("heartbeat", self.heartbeat_request(grant["grantId"]), prefix, suffix)
                self.assertEqual(denied["response"]["responseCode"], 103)
                self.assertLessEqual(self.parsed_time(denied["transmitExpireTime"]), self.clock.now())
                self.assertEqual(self.operation("deregistration", {"cbsdId": self.cbsd_id}, prefix, suffix)
                                 ["response"]["responseCode"], 0)

    def test_registration_and_cpi_failures_cannot_create_state_or_log_values(self):
        for capability in (None, []):
            for failure in ("signature", "signed-schema", "signed-identity", "nonfinite"):
                registration = self.registration()
                if capability is None:
                    del registration["measCapability"]
                else:
                    registration["measCapability"] = capability
                payload = self.payload()
                if failure == "signature":
                    registration["cpiSignatureData"]["digitalSignature"] = "DO-NOT-LOG"
                elif failure == "signed-schema":
                    payload["installationParam"]["latitude"] = 987654321
                    registration["cpiSignatureData"] = signature_data(payload, self.key, self.algorithm)
                elif failure == "signed-identity":
                    payload["fccId"] = "DO-NOT-LOG-OTHER"
                    registration["cpiSignatureData"] = signature_data(payload, self.key, self.algorithm)
                else:
                    payload["installationParam"]["antennaGain"] = float("nan")
                    registration["cpiSignatureData"] = signature_data(payload, self.key, self.algorithm)
                with self.assertLogs("mock_sas_lab", level="INFO") as captured:
                    self.rejected(registration)
                for value in ("987654321", "DO-NOT-LOG", "LABFCC001", "LAB-CBSD-0001",
                              *registration["cpiSignatureData"].values()):
                    self.assertNotIn(value, "\n".join(captured.output))
                self.assertIsNone(self.app.extensions["lab_session"].cbsd_id)
        payload = self.payload()
        del payload["installationParam"]["antennaGain"]
        with self.assertLogs("mock_sas_lab", level="WARNING") as captured:
            self.rejected(self.registration(payload))
        self.assertIn("at $.installationParam (required); missing required properties: antennaGain",
                      "\n".join(captured.output))

    def test_absent_empty_measurement_and_envelope_schema(self):
        for capability in (None, [], ["RECEIVED_POWER_WITH_GRANT"]):
            registration = self.registration()
            if capability is None:
                del registration["measCapability"]
            else:
                registration["measCapability"] = capability
            self.assertEqual(self.post(registration)["response"]["responseCode"], 0)
        for invalid in ("", [""], ["UNSUPPORTED"], None):
            registration = self.registration()
            registration["measCapability"] = invalid
            self.rejected(registration)

    def test_missing_required_fields_and_invalid_types_are_safe_errors(self):
        self.register()
        items = {
            "spectrumInquiry": {"cbsdId": self.cbsd_id, "inquiredSpectrum": [
                {"lowFrequency": 3550000000, "highFrequency": 3570000000}]},
            "grant": self.grant_request(),
            "heartbeat": self.heartbeat_request("UNKNOWN"),
            "relinquishment": {"cbsdId": self.cbsd_id, "grantId": "UNKNOWN"},
            "deregistration": {"cbsdId": self.cbsd_id},
        }
        for operation, item in items.items():
            for field in item:
                omitted = deepcopy(item)
                del omitted[field]
                with self.assertLogs("mock_sas_lab", level="WARNING") as captured:
                    result = self.operation(operation, omitted)
                self.assertEqual(result["response"]["responseCode"], 102)
                self.assertIn("missing required properties: " + field, "\n".join(captured.output))
            for bad in (None, [], 7, "DO-NOT-LOG-REQUEST"):
                result = self.operation(operation, bad)
                self.assertEqual(result["response"]["responseCode"], 103)
        for bad_id in (None, {}, [], 7):
            self.assertEqual(self.operation("heartbeat", self.heartbeat_request(bad_id))
                             ["response"]["responseCode"], 103)

    def test_unknown_state_ids_and_operation_states_never_authorize(self):
        self.cbsd_id = "UNKNOWN"
        self.assertEqual(self.grant()["response"]["responseCode"], 103)
        self.register()
        self.assertEqual(self.operation("heartbeat", self.heartbeat_request("UNKNOWN"))
                         ["response"]["responseCode"], 103)
        grant = self.grant()
        for state, code in (("AUTHORIZED", 502), ("INVALID", 103)):
            failed = self.operation("heartbeat", self.heartbeat_request(grant["grantId"], state))
            self.assertEqual(failed["response"]["responseCode"], code)
            self.assertLessEqual(self.parsed_time(failed["transmitExpireTime"]), self.clock.now())
        self.assertIsNone(self.app.extensions["lab_session"].grants[grant["grantId"]].transmit_expires)

    def test_grant_policy_bounds_bandwidth_power_overlap_and_nonfinite(self):
        self.register()
        for low, width, power in (
                (3540000000, 20000000, 16), (3690000000, 20000000, 16),
                (3570000000, -20000000, 16), (3550000000, 50000000, 16),
                (3550000000, 20000000, 16.01), (3550000000, 20000000, True),
                (3550000000, 20000000, float("nan")), (float("inf"), 20000000, 16)):
            result = self.operation("grant", self.grant_request(low, width, power))
            self.assertEqual(result["response"]["responseCode"], 103)
            for field in ("grantId", "grantExpireTime", "operationParam"):
                self.assertNotIn(field, result)
        for width in (10, 20, 30, 40, 60, 80, 100):
            self.register()
            result = self.operation("grant", self.grant_request(width=width * 1000000))
            self.assertEqual(result["response"]["responseCode"], 0)
            overlap = self.operation("grant", self.grant_request(width=width * 1000000))
            self.assertEqual(overlap["response"]["responseCode"], 401)
            self.assertNotIn("grantId", overlap)
        self.register()
        self.assertEqual(self.grant()["response"]["responseCode"], 0)
        self.assertEqual(self.operation("grant", self.grant_request(low=3570000000))
                         ["response"]["responseCode"], 0)

    def test_inquiry_no_intersection_and_invalid_ranges(self):
        self.register()
        for ranges, code, channels in (
                ([{"lowFrequency": 3300000000, "highFrequency": 3400000000}], 300, None),
                ([{"lowFrequency": 3560000000, "highFrequency": 3565000000}], 0, []),
                ([{"lowFrequency": 3570000000, "highFrequency": 3560000000}], 103, None),
                ([], 103, None)):
            response = self.operation("spectrumInquiry", {"cbsdId": self.cbsd_id, "inquiredSpectrum": ranges})
            self.assertEqual(response["response"]["responseCode"], code)
            if channels is not None:
                self.assertEqual(response["availableChannel"], channels)

    def test_inquiry_outside_cbrs_rejects_entire_object_and_preserves_batch(self):
        self.register()
        good = {"lowFrequency": 3550000000, "highFrequency": 3570000000}
        outside = [
            {"lowFrequency": 3540000000, "highFrequency": 3560000000},
            {"lowFrequency": 3690000000, "highFrequency": 3710000000},
            {"lowFrequency": 3300000000, "highFrequency": 3400000000},
        ]
        for bad in outside:
            for ranges in ([bad], [good, bad], [bad, good]):
                result = self.operation("spectrumInquiry", {
                    "cbsdId": self.cbsd_id, "inquiredSpectrum": ranges})
                self.assertEqual(result["response"]["responseCode"], 300)
                self.assertEqual(set(result), {"cbsdId", "response"})
                self.assertNotIn("responseData", result["response"])
        items = [{"cbsdId": self.cbsd_id, "inquiredSpectrum": [item]}
                 for item in (good, outside[0], good)]
        response = self.app.test_client().post("/v1.2//spectrumInquiry",
                                              json={"spectrumInquiryRequest": items})
        results = response.json["spectrumInquiryResponse"]
        self.assertEqual([item["response"]["responseCode"] for item in results], [0, 300, 0])
        for item in results:
            RESPONSE_VALIDATORS["spectrumInquiry"].validate(item)

    def test_inside_cbrs_outside_narrow_lab_policy_is_not_unsupported(self):
        policy = deepcopy(self.policy)
        policy["frequencyRange"] = {"lowFrequency": 3550000000, "highFrequency": 3570000000}
        path = self.directory / "narrow-policy.json"
        path.write_text(json.dumps(policy))
        cleanup_app(self.app)
        self.app = self.new_app(policy_path=path)
        self.register()
        result = self.operation("spectrumInquiry", {
            "cbsdId": self.cbsd_id,
            "inquiredSpectrum": [{"lowFrequency": 3600000000, "highFrequency": 3620000000}]})
        self.assertEqual(result["response"]["responseCode"], 0)
        self.assertEqual(result["availableChannel"], [])

    def test_conflict_data_lists_all_and_only_matching_active_grants(self):
        self.register()
        first = self.grant()
        second = self.operation("grant", self.grant_request(low=3570000000))
        other = self.operation("grant", self.grant_request(low=3650000000))
        conflict = self.operation("grant", self.grant_request(width=40000000))
        self.assertEqual(conflict["response"]["responseCode"], 401)
        self.assertEqual(conflict["response"]["responseData"],
                         sorted([first["grantId"], second["grantId"]]))
        self.assertNotIn(other["grantId"], conflict["response"]["responseData"])
        self.assertEqual(set(conflict), {"cbsdId", "response"})
        for _ in range(2):
            self.assertEqual(self.operation("grant", self.grant_request(width=40000000)), conflict)
        self.operation("relinquishment", {"cbsdId": self.cbsd_id, "grantId": first["grantId"]})
        self.assertEqual(self.operation("grant", self.grant_request(width=40000000))
                         ["response"]["responseData"], [second["grantId"]])

    def test_renewal_expiry_and_recovery_boundaries_without_real_waits(self):
        self.register()
        grant = self.grant()
        identifier = grant["grantId"]
        for renew in (None, False):
            response = self.operation("heartbeat", self.heartbeat_request(identifier, renew=renew))
            self.assertEqual(response["response"]["responseCode"], 0)
            self.assertNotIn("grantExpireTime", response)
            self.clock.advance(60)
        self.clock.advance(120)
        expired_tx = self.operation("heartbeat", self.heartbeat_request(identifier, "AUTHORIZED"))
        self.assertEqual(expired_tx["response"]["responseCode"], 502)
        recovery = self.operation("heartbeat", self.heartbeat_request(identifier))
        self.assertEqual(recovery["response"]["responseCode"], 0)
        self.clock.advance(359)
        near_expiry = self.operation("heartbeat", self.heartbeat_request(identifier))
        self.assertEqual(self.parsed_time(near_expiry["transmitExpireTime"]),
                         self.parsed_time(grant["grantExpireTime"]))
        self.clock.advance(1)
        expired = self.operation("heartbeat", self.heartbeat_request(identifier, renew=True))
        self.assertEqual(expired["response"]["responseCode"], 500)
        self.assertLessEqual(self.parsed_time(expired["transmitExpireTime"]), self.clock.now())

    def test_new_registration_deregistration_restart_and_backwards_clock(self):
        self.register()
        first = self.grant()["grantId"]
        self.register()
        self.assertEqual(self.operation("heartbeat", self.heartbeat_request(first))
                         ["response"]["responseCode"], 103)
        second = self.grant()["grantId"]
        self.assertNotEqual(first, second)
        restarted = self.new_app()
        try:
            self.assertIsNone(restarted.extensions["lab_session"].cbsd_id)
        finally:
            cleanup_app(restarted)
        self.clock.advance(-1)
        result = self.app.test_client().post("/v1.2/heartbeat", json={
            "heartbeatRequest": [self.heartbeat_request(second)]})
        self.assertEqual(result.status_code, 503)
        self.assertNotIn("heartbeatResponse", result.json)
        self.assertIsNone(self.app.extensions["lab_session"].cbsd_id)
        cleanup_app(self.app)
        self.app = self.new_app()
        self.register()
        grant = self.grant()["grantId"]
        self.assertEqual(self.operation("deregistration", {"cbsdId": self.cbsd_id})
                         ["response"]["responseCode"], 0)
        self.assertEqual(self.operation("heartbeat", self.heartbeat_request(grant))
                         ["response"]["responseCode"], 103)

    def test_restart_stale_requests_cannot_skip_new_cpi_registration(self):
        self.register()
        old_grant = self.grant()
        identifier = old_grant["grantId"]
        self.assertEqual(self.operation("heartbeat", self.heartbeat_request(identifier))
                         ["response"]["responseCode"], 0)
        self.clock.advance(220)
        cleanup_app(self.app)
        self.app = self.new_app()
        session = self.app.extensions["lab_session"]
        for operation, request in (
                ("heartbeat", self.heartbeat_request(identifier, "AUTHORIZED", True)),
                ("relinquishment", {"cbsdId": self.cbsd_id, "grantId": identifier}),
                ("relinquishment", {"cbsdId": self.cbsd_id, "grantId": identifier}),
                ("deregistration", {"cbsdId": self.cbsd_id})):
            result = self.operation(operation, request, "/v1.2//", "/")
            self.assertEqual(result["response"]["responseCode"], 103)
            self.assertEqual(result["response"]["responseData"], ["cbsdId"])
            self.assertNotIn("cbsdId", result)
            self.assertNotIn("grantId", result)
            self.assertNotIn("grantExpireTime", result)
            self.assertNotIn("operationParam", result)
            if operation == "heartbeat":
                self.assertLessEqual(self.parsed_time(result["transmitExpireTime"]), self.clock.now())
            self.assertIsNone(session.cbsd_id)
            self.assertFalse(session.grants)
        altered = self.registration()
        altered["cpiSignatureData"]["digitalSignature"] = "INVALID"
        self.rejected(altered)
        self.assertIsNone(session.cbsd_id)
        self.register()
        denied_old = self.operation("heartbeat", self.heartbeat_request(identifier))
        self.assertEqual(denied_old["response"]["responseCode"], 103)
        self.assertEqual(denied_old["response"]["responseData"], ["grantId"])
        self.assertEqual(denied_old["cbsdId"], self.cbsd_id)
        self.assertNotIn("grantId", denied_old)
        new_grant = self.grant()
        self.assertNotEqual(new_grant["grantId"], identifier)
        self.assertEqual(self.parsed_time(new_grant["grantExpireTime"]),
                         self.clock.now() + datetime.timedelta(seconds=600))
        denied = self.operation("heartbeat", self.heartbeat_request(new_grant["grantId"], "AUTHORIZED"))
        self.assertEqual(denied["response"]["responseCode"], 502)
        self.assertLessEqual(self.parsed_time(denied["transmitExpireTime"]), self.clock.now())
        allowed = self.operation("heartbeat", self.heartbeat_request(new_grant["grantId"]))
        self.assertEqual(allowed["response"]["responseCode"], 0)
        self.assertEqual(self.parsed_time(allowed["transmitExpireTime"]),
                         self.clock.now() + datetime.timedelta(seconds=180))
        self.assertLessEqual(self.parsed_time(allowed["transmitExpireTime"]),
                             self.parsed_time(new_grant["grantExpireTime"]))

    def restart_persisted(self):
        directory = self.app.extensions["lab_store"].directory
        cleanup_app(self.app)
        self.app = self.new_app(state_directory=directory)
        return self.app.extensions["lab_session"]

    def snapshot(self):
        return json.loads(self.app.extensions["lab_store"].path.read_text())

    def test_durable_restart_preserves_ids_cap_and_original_remaining_deadlines(self):
        payload = self.payload()
        payload["installationParam"]["eirpCapability"] = 24
        self.cbsd_id = self.post(self.registration(payload))["cbsdId"]
        granted = self.operation("grant", self.grant_request(power=14))
        identifier = granted["grantId"]
        authorized = self.operation("heartbeat", self.heartbeat_request(identifier))
        before = deepcopy(self.app.extensions["lab_session"].grants[identifier])
        self.clock.advance(37)
        session = self.restart_persisted()
        restored = session.grants[identifier]
        self.assertEqual(session.cbsd_id, self.cbsd_id)
        self.assertEqual(session.max_eirp, 14)
        self.assertEqual(restored.parameters, before.parameters)
        self.assertEqual(restored.expires, before.expires)
        self.assertEqual(restored.transmit_expires, before.transmit_expires)
        self.assertEqual(restored.deadline - self.clock.monotonic(), 563)
        self.assertEqual(restored.transmit_deadline - self.clock.monotonic(), 143)
        self.assertTrue(session._authorized(restored, self.clock.now(), self.clock.monotonic()))
        self.assertEqual(self.snapshot()["grants"][identifier]["grantExpireTime"], before.expires.isoformat())
        conflict = self.operation("grant", self.grant_request(power=14))
        self.assertEqual(conflict["response"]["responseCode"], 401)
        self.assertEqual(conflict["cbsdId"], self.cbsd_id)
        self.assertNotIn("grantId", conflict)
        heartbeat = self.operation("heartbeat", self.heartbeat_request(identifier, "AUTHORIZED"))
        self.assertEqual(heartbeat["response"]["responseCode"], 0)
        self.assertEqual(heartbeat["grantId"], identifier)
        self.assertNotIn("grantExpireTime", heartbeat)
        self.assertEqual(session.grants[identifier].expires, self.parsed_time(granted["grantExpireTime"]))
        self.assertLessEqual(self.parsed_time(heartbeat["transmitExpireTime"]), before.expires)
        self.assertEqual(self.parsed_time(authorized["transmitExpireTime"]), before.transmit_expires)

    def test_expired_transmit_is_not_restored_as_authorized_or_extended_on_restart(self):
        self.register()
        identifier = self.operation("grant", self.grant_request())["grantId"]
        self.operation("heartbeat", self.heartbeat_request(identifier))
        self.clock.advance(180)
        session = self.restart_persisted()
        grant = session.grants[identifier]
        self.assertIsNone(grant.transmit_expires)
        self.assertIsNone(self.snapshot()["grants"][identifier]["transmitExpireTime"])
        denied = self.operation("heartbeat", self.heartbeat_request(identifier, "AUTHORIZED"))
        self.assertEqual(denied["response"]["responseCode"], 502)
        self.assertEqual(denied["cbsdId"], self.cbsd_id)
        self.assertEqual(denied["grantId"], identifier)
        self.assertLessEqual(self.parsed_time(denied["transmitExpireTime"]), self.clock.now())
        self.assertIsNone(session.grants[identifier].transmit_expires)
        approved = self.operation("heartbeat", self.heartbeat_request(identifier, "GRANTED"))
        self.assertEqual(approved["response"]["responseCode"], 0)
        self.assertLessEqual(self.parsed_time(approved["transmitExpireTime"]), grant.expires)
        self.clock.advance(420)
        session = self.restart_persisted()
        self.assertFalse(session.grants)
        self.assertFalse(self.snapshot()["grants"])
        for operation, item in (
                ("heartbeat", self.heartbeat_request(identifier, renew=True)),
                ("relinquishment", {"cbsdId": self.cbsd_id, "grantId": identifier})):
            denied = self.operation(operation, item)
            self.assertEqual(denied["response"]["responseCode"], 103)
            self.assertEqual(denied["response"]["responseData"], ["grantId"])
            self.assertEqual(denied["cbsdId"], self.cbsd_id)
            self.assertNotIn("grantId", denied)
            if operation == "heartbeat":
                self.assertLessEqual(self.parsed_time(denied["transmitExpireTime"]), self.clock.now())

    def test_fractional_clock_never_extends_the_advertised_protocol_deadlines(self):
        fraction = datetime.timedelta(microseconds=567891)
        self.clock.utc += fraction
        self.clock.tick += fraction.total_seconds()
        self.register()
        granted = self.operation("grant", self.grant_request())
        identifier = granted["grantId"]
        authorized = self.operation("heartbeat", self.heartbeat_request(identifier))
        session = self.app.extensions["lab_session"]
        grant_expiry = self.parsed_time(granted["grantExpireTime"])
        transmit_expiry = self.parsed_time(authorized["transmitExpireTime"])
        self.assertEqual(session.grants[identifier].expires, grant_expiry)
        self.assertEqual(session.grants[identifier].transmit_expires, transmit_expiry)
        store = self.app.extensions["lab_store"]
        snapshot = self.snapshot()
        # Older snapshots stored internal fractions although the protocol advertised floored seconds.
        legacy = snapshot["grants"][identifier]
        legacy["grantExpireTime"] = (grant_expiry + fraction).isoformat()
        legacy["transmitExpireTime"] = (transmit_expiry + fraction).isoformat()
        legacy["grantRemainingSeconds"] += fraction.total_seconds()
        legacy["transmitRemainingSeconds"] += fraction.total_seconds()
        snapshot["checksum"] = store.checksum(snapshot)
        cleanup_app(self.app)
        store.path.write_text(json.dumps(snapshot))
        self.app = self.new_app(state_directory=store.directory)
        restored = self.app.extensions["lab_session"].grants[identifier]
        self.assertEqual(restored.expires, grant_expiry)
        self.assertEqual(restored.transmit_expires, transmit_expiry)
        self.assertAlmostEqual(restored.deadline - self.clock.monotonic(),
                               (grant_expiry - self.clock.now()).total_seconds())
        self.clock.advance((transmit_expiry - self.clock.now()).total_seconds())
        denied = self.operation("heartbeat", self.heartbeat_request(identifier, "AUTHORIZED"))
        self.assertEqual(denied["response"]["responseCode"], 502)
        self.assertLessEqual(self.parsed_time(denied["transmitExpireTime"]), transmit_expiry)
        self.clock.advance((grant_expiry - self.clock.now()).total_seconds())
        self.restart_persisted()
        denied = self.operation("heartbeat", self.heartbeat_request(identifier, renew=True))
        self.assertEqual(denied["response"]["responseCode"], 103)
        self.assertEqual(denied["response"]["responseData"], ["grantId"])
        self.assertNotIn("grantId", denied)
        self.assertLessEqual(self.parsed_time(denied["transmitExpireTime"]), grant_expiry)

    def test_persisted_relinquishment_deregistration_and_registration_invalidate_before_success(self):
        self.register()
        identifier = self.operation("grant", self.grant_request())["grantId"]
        released = self.operation("relinquishment", {"cbsdId": self.cbsd_id, "grantId": identifier})
        self.assertEqual(released["response"]["responseCode"], 0)
        self.assertEqual(released["grantId"], identifier)
        self.assertFalse(self.snapshot()["grants"])
        self.restart_persisted()
        repeated = self.operation("relinquishment", {"cbsdId": self.cbsd_id, "grantId": identifier})
        self.assertEqual(repeated["response"]["responseData"], ["grantId"])
        self.assertNotIn("grantId", repeated)
        identifier = self.operation("grant", self.grant_request())["grantId"]
        self.register()
        self.assertFalse(self.snapshot()["grants"])
        self.restart_persisted()
        old = self.operation("heartbeat", self.heartbeat_request(identifier))
        self.assertEqual(old["response"]["responseCode"], 103)
        self.assertNotIn("grantId", old)
        removed = self.operation("deregistration", {"cbsdId": self.cbsd_id})
        self.assertEqual(removed["response"]["responseCode"], 0)
        self.assertEqual(removed["cbsdId"], self.cbsd_id)
        self.assertIsNone(self.snapshot()["cbsdId"])
        self.restart_persisted()
        repeated = self.operation("deregistration", {"cbsdId": self.cbsd_id})
        self.assertEqual(repeated["response"]["responseData"], ["cbsdId"])
        self.assertNotIn("cbsdId", repeated)

    def test_explicit_renewal_is_persisted_but_restart_itself_never_renews(self):
        self.register()
        identifier = self.operation("grant", self.grant_request())["grantId"]
        self.clock.advance(100)
        renewed = self.operation("heartbeat", self.heartbeat_request(identifier, renew=True))
        original_expiry = self.parsed_time(renewed["grantExpireTime"])
        original_transmit = self.parsed_time(renewed["transmitExpireTime"])
        self.clock.advance(59)
        session = self.restart_persisted()
        self.assertEqual(session.grants[identifier].expires, original_expiry)
        self.assertEqual(session.grants[identifier].transmit_expires, original_transmit)
        self.assertEqual(session.grants[identifier].deadline - self.clock.monotonic(), 541)
        self.assertEqual(session.grants[identifier].transmit_deadline - self.clock.monotonic(), 121)
        unknown = self.operation("heartbeat", {**self.heartbeat_request(identifier), "cbsdId": "wrong"})
        self.assertEqual(unknown["response"]["responseData"], ["cbsdId"])
        self.assertNotIn("cbsdId", unknown)
        self.assertNotIn("grantId", unknown)
        self.assertEqual(self.snapshot()["grants"][identifier]["grantExpireTime"], original_expiry.isoformat())

    def test_storage_failure_never_returns_or_logs_success_and_health_fails_closed(self):
        self.register()
        store = self.app.extensions["lab_store"]
        original = store.path.read_bytes()
        with patch("lab_state.os.replace", side_effect=OSError("fixture IO failure")), \
                self.assertLogs("mock_sas_lab", level="INFO") as captured:
            response = self.app.test_client().post("/v1.2/grant", json={"grantRequest": [self.grant_request()]})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("grantResponse", response.json)
        self.assertNotIn("responseCode=0", "\n".join(captured.output))
        self.assertNotIn("GRANTED", "\n".join(captured.output))
        self.assertEqual(store.path.read_bytes(), original)
        self.assertFalse(list(store.directory.glob(".session-*.tmp")))
        self.assertTrue(self.app.extensions["lab_session"].faulted)
        self.assertEqual(self.app.test_client().get("/healthz").status_code, 503)
        self.assertEqual(self.app.test_client().post("/v1.2/registration", json={
            "registrationRequest": [self.registration()]}).status_code, 503)
        self.restart_persisted()
        self.assertEqual(self.app.extensions["lab_session"].cbsd_id, self.cbsd_id)
        self.assertFalse(self.app.extensions["lab_session"].grants)

    def test_invalid_snapshots_binding_clock_bounds_and_missing_state_fail_startup(self):
        self.register()
        identifier = self.operation("grant", self.grant_request())["grantId"]
        self.operation("heartbeat", self.heartbeat_request(identifier))
        store = self.app.extensions["lab_store"]
        snapshot = self.snapshot()
        cleanup_app(self.app)
        mutations = [
            {"version": 2}, {"savedAt": (self.clock.now() + datetime.timedelta(seconds=1)).isoformat()},
            {"cbsdId": None}, {"maxEirp": 17},
            {"grants": {identifier: {**snapshot["grants"][identifier], "grantRemainingSeconds": 601}}},
            {"grants": {identifier: {**snapshot["grants"][identifier], "grantRemainingSeconds": 1}}},
            {"grants": {identifier: {**snapshot["grants"][identifier],
                                    "transmitExpireTime": (self.clock.now() + datetime.timedelta(seconds=601)).isoformat()}}},
            {"grants": {identifier: {**snapshot["grants"][identifier], "operationParam": {
                **snapshot["grants"][identifier]["operationParam"],
                "operationFrequencyRange": {"lowFrequency": 3550000000, "highFrequency": 3555000000}}}}},
        ]
        mutations += [{"bindings": {**snapshot["bindings"], name: (
            "registration-cpi-only" if name == "profile" else "0" * 64)}}
                      for name in snapshot["bindings"]]
        for mutation in mutations:
            with self.subTest(keys=list(mutation)):
                invalid = {**snapshot, **mutation}
                invalid["checksum"] = store.checksum(invalid)
                store.path.write_text(json.dumps(invalid))
                with self.assertRaises(StateStoreError):
                    self.new_app(state_directory=store.directory)
        for data in (b"{corrupt", b"x" * 65537):
            store.path.write_bytes(data)
            with self.assertRaises(StateStoreError):
                self.new_app(state_directory=store.directory)
        store.path.unlink()
        with self.assertRaisesRegex(StateStoreError, "snapshot missing"):
            self.new_app(state_directory=store.directory)
        store.path.write_text(json.dumps(snapshot))
        store.path.chmod(0o600)
        self.app = self.new_app(state_directory=store.directory)

    def test_invalidation_and_registration_io_failures_preserve_prior_durable_state(self):
        self.register()
        identifier = self.operation("grant", self.grant_request())["grantId"]
        cases = [
            ("relinquishment", {"cbsdId": self.cbsd_id, "grantId": identifier}),
            ("deregistration", {"cbsdId": self.cbsd_id}),
            ("registration", self.registration()),
        ]
        for operation, item in cases:
            with self.subTest(operation=operation):
                original = self.app.extensions["lab_store"].path.read_bytes()
                with patch("lab_state.os.fsync", side_effect=OSError("fixture disk error")), \
                        self.assertLogs("mock_sas_lab", level="INFO") as captured:
                    response = self.app.test_client().post("/v1.2/" + operation, json={
                        operation + "Request": [item]})
                self.assertEqual(response.status_code, 503)
                self.assertNotIn(operation + "Response", response.json)
                self.assertNotIn("responseCode=0", "\n".join(captured.output))
                self.assertNotIn("Registration accepted", "\n".join(captured.output))
                self.assertEqual(self.app.extensions["lab_store"].path.read_bytes(), original)
                session = self.restart_persisted()
                self.assertEqual(session.cbsd_id, self.cbsd_id)
                self.assertIn(identifier, session.grants)

    @unittest.skipIf(os.name == "nt", "POSIX ownership/mode checks run against the Linux image")
    def test_state_permissions_and_symlinks_fail_closed(self):
        store = self.app.extensions["lab_store"]
        original = store.path.read_bytes()
        store.path.chmod(0o644)
        response = self.app.test_client().post("/v1.2/grant", json={
            "grantRequest": [self.grant_request()]})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(store.path.read_bytes(), original)
        cleanup_app(self.app)
        with self.assertRaisesRegex(StateStoreError, "ownership/permissions"):
            self.new_app(state_directory=store.directory)
        store.path.chmod(0o600)
        store.directory.chmod(0o755)
        with self.assertRaisesRegex(StateStoreError, "ownership/permissions"):
            self.new_app(state_directory=store.directory)
        store.directory.chmod(0o700)
        link = self.directory / ("symlink-" + store.directory.name)
        link.symlink_to(store.directory, target_is_directory=True)
        with self.assertRaises(StateStoreError):
            self.new_app(state_directory=link)
        link.unlink()
        self.app = self.new_app(state_directory=store.directory)

    def test_single_writer_lock_and_clock_rollback_fail_closed(self):
        directory = self.app.extensions["lab_store"].directory
        with self.assertRaisesRegex(StateStoreError, "lock unavailable"):
            self.new_app(state_directory=directory)
        self.register()
        self.operation("grant", self.grant_request())
        original = self.app.extensions["lab_store"].path.read_bytes()
        self.clock.advance(-1)
        response = self.app.test_client().post("/v1.2/heartbeat", json={
            "heartbeatRequest": [self.heartbeat_request("unknown")]})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.app.extensions["lab_store"].path.read_bytes(), original)
        cleanup_app(self.app)
        with self.assertRaisesRegex(StateStoreError, "clock predates"):
            self.new_app(state_directory=directory)
        self.clock.advance(1)
        self.app = self.new_app(state_directory=directory)
        self.clock.tick -= 1
        response = self.app.test_client().post("/v1.2/spectrumInquiry", json={
            "spectrumInquiryRequest": [{"cbsdId": self.cbsd_id, "inquiredSpectrum": [
                {"lowFrequency": 3550000000, "highFrequency": 3700000000}]}]})
        self.assertEqual(response.status_code, 503)

    def test_concurrent_atomic_snapshots_are_bounded_and_schema_valid(self):
        self.register()
        store = self.app.extensions["lab_store"]
        stopped = threading.Event()
        errors = []
        observed = []

        def observe():
            while not stopped.is_set():
                try:
                    # Windows file readers serialize replacement; deployed Linux reads the atomic snapshot unlocked.
                    with self.app.extensions["lab_session"].lock if os.name == "nt" else nullcontext():
                        snapshot = json.loads(store.path.read_bytes())
                    store.validate(snapshot)
                    observed.append(len(snapshot["grants"]))
                except (OSError, ValueError, StateStoreError) as error:
                    errors.append(type(error).__name__)
                stopped.wait(0.001)

        thread = threading.Thread(target=observe)
        thread.start()
        try:
            requests = [self.grant_request(low=3550000000 + index * 10000000, width=10000000)
                        for index in range(15)]
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda item: self.operation("grant", item), requests))
        finally:
            stopped.set()
            thread.join(timeout=5)
        self.assertFalse(errors)
        self.assertTrue(observed)
        self.assertEqual(len({item["grantId"] for item in results}), 15)
        self.assertEqual(len(self.snapshot()["grants"]), 15)
        self.assertLessEqual(store.path.stat().st_size, 65536)
        self.assertEqual(self.operation("grant", requests[0])["response"]["responseCode"], 401)
        self.restart_persisted()
        self.assertEqual(len(self.app.extensions["lab_session"].grants), 15)

    def test_negative_response_ids_follow_valid_identity_contract(self):
        self.register()
        identifier = self.grant()["grantId"]
        session = self.app.extensions["lab_session"]
        original = deepcopy(session.grants)
        for operation in ("heartbeat", "relinquishment"):
            base = (self.heartbeat_request(identifier) if operation == "heartbeat"
                    else {"cbsdId": self.cbsd_id, "grantId": identifier})
            for changes, code, fields, cbsd_present, grant_present in (
                    ({"cbsdId": "OTHER-DEVICE"}, 103, ["cbsdId"], False, False),
                    ({"grantId": "UNKNOWN"}, 103, ["grantId"], True, False),
                    ({"grantId": []}, 103, ["grantId"], True, False),
                    ({"cbsdId": None}, 103, ["cbsdId"], False, False),
                    ({"grantId": ""}, 103, ["grantId"], True, False)):
                result = self.operation(operation, dict(base, **changes))
                self.assertEqual(result["response"]["responseCode"], code)
                self.assertEqual(result["response"]["responseData"], fields)
                self.assertEqual("cbsdId" in result, cbsd_present)
                self.assertEqual("grantId" in result, grant_present)
                if cbsd_present:
                    self.assertEqual(result["cbsdId"], self.cbsd_id)
                self.assertNotIn("grantExpireTime", result)
                if operation == "heartbeat":
                    self.assertLessEqual(self.parsed_time(result["transmitExpireTime"]), self.clock.now())
                self.assertEqual(session.grants, original)
        for state, code in ((None, 102), ("INVALID", 103)):
            request = self.heartbeat_request(identifier)
            if state is None:
                del request["operationState"]
            else:
                request["operationState"] = state
            result = self.operation("heartbeat", request)
            self.assertEqual(result["response"]["responseCode"], code)
            self.assertEqual(result["response"]["responseData"], ["operationState"])
            self.assertEqual(result["cbsdId"], self.cbsd_id)
            self.assertEqual(result["grantId"], identifier)
        self.assertEqual(session.grants, original)

    def test_expired_identity_cannot_be_relinquished_or_renewed(self):
        self.register()
        grant = self.grant()
        identifier = grant["grantId"]
        session = self.app.extensions["lab_session"]
        self.clock.advance(601)
        original = deepcopy(session.grants)
        heartbeat = self.operation("heartbeat", self.heartbeat_request(identifier, renew=True))
        self.assertEqual(heartbeat["response"]["responseCode"], 500)
        self.assertEqual(heartbeat["cbsdId"], self.cbsd_id)
        self.assertNotIn("grantId", heartbeat)
        self.assertNotIn("grantExpireTime", heartbeat)
        self.assertLessEqual(self.parsed_time(heartbeat["transmitExpireTime"]),
                             self.parsed_time(grant["grantExpireTime"]))
        for _ in range(2):
            released = self.operation("relinquishment", {"cbsdId": self.cbsd_id, "grantId": identifier})
            self.assertEqual(released["response"]["responseCode"], 103)
            self.assertEqual(released["response"]["responseData"], ["grantId"])
            self.assertEqual(released["cbsdId"], self.cbsd_id)
            self.assertNotIn("grantId", released)
        self.assertEqual(session.grants, original)
        new = self.grant()
        self.assertEqual(new["response"]["responseCode"], 0)
        self.assertNotEqual(new["grantId"], identifier)
        self.assertNotIn(identifier, session.grants)
        self.clock.advance(-1)
        stale = self.app.test_client().post("/v1.2/heartbeat", json={
            "heartbeatRequest": [self.heartbeat_request(new["grantId"])]})
        self.assertEqual(stale.status_code, 503)
        self.assertNotIn("heartbeatResponse", stale.json)
        self.assertIsNone(session.cbsd_id)
        self.assertFalse(session.grants)

    def test_repeated_batch_release_and_deregistration_are_not_fake_success(self):
        self.register()
        first = self.grant()["grantId"]
        second = self.operation("grant", self.grant_request(low=3570000000))["grantId"]
        requests = [
            {"cbsdId": self.cbsd_id, "grantId": first},
            {"cbsdId": self.cbsd_id, "grantId": first},
            {"cbsdId": "OTHER-DEVICE", "grantId": second},
            {"cbsdId": self.cbsd_id, "grantId": second},
        ]
        response = self.app.test_client().post("/v1.2//relinquishment",
                                               json={"relinquishmentRequest": requests})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Location", response.headers)
        results = response.json["relinquishmentResponse"]
        self.assertEqual([item["response"]["responseCode"] for item in results], [0, 103, 103, 0])
        for item in results:
            self.response_validators["relinquishment"].validate(item)
        for index in (0, 3):
            self.assertEqual(results[index]["cbsdId"], self.cbsd_id)
            self.assertEqual(results[index]["grantId"], requests[index]["grantId"])
        self.assertEqual(results[1]["cbsdId"], self.cbsd_id)
        self.assertEqual(results[1]["response"]["responseData"], ["grantId"])
        self.assertNotIn("grantId", results[1])
        self.assertEqual(results[2]["response"]["responseData"], ["cbsdId"])
        self.assertNotIn("cbsdId", results[2])
        self.assertNotIn("grantId", results[2])
        self.assertFalse(self.app.extensions["lab_session"].grants)
        response = self.app.test_client().post("/v1.2/deregistration", json={
            "deregistrationRequest": [{"cbsdId": self.cbsd_id}, {"cbsdId": self.cbsd_id}],
        })
        results = response.json["deregistrationResponse"]
        self.assertEqual([item["response"]["responseCode"] for item in results], [0, 103])
        for item in results:
            self.response_validators["deregistration"].validate(item)
        self.assertEqual(results[0]["cbsdId"], self.cbsd_id)
        self.assertNotIn("cbsdId", results[1])
        self.assertEqual(results[1]["response"]["responseData"], ["cbsdId"])
        self.assertIsNone(self.app.extensions["lab_session"].cbsd_id)

    def test_invalid_release_parameters_report_names_without_logging_values(self):
        self.register()
        identifier = self.grant()["grantId"]
        for field, value in (("grantId", 123456789), ("grantId", float("nan")),
                             ("cbsdId", ["DO-NOT-LOG-DEVICE"]), ("DO-NOT-LOG-EXTRA", "PRIVATE-VALUE")):
            request = {"cbsdId": self.cbsd_id, "grantId": identifier}
            request[field] = value
            with self.assertLogs("mock_sas_lab", level="WARNING") as captured:
                result = self.operation("relinquishment", request)
            self.assertEqual(result["response"]["responseCode"], 103)
            self.assertEqual(result["response"]["responseData"], [field])
            for secret in (self.cbsd_id, identifier, "123456789", "DO-NOT-LOG-DEVICE",
                           "DO-NOT-LOG-EXTRA", "PRIVATE-VALUE"):
                self.assertNotIn(secret, "\n".join(captured.output))

    def test_concurrent_grants_and_invalidation(self):
        self.register()
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: self.grant(), range(2)))
        self.assertEqual(sorted(item["response"]["responseCode"] for item in results), [0, 401])
        identifier = next(item["grantId"] for item in results if item["response"]["responseCode"] == 0)
        with ThreadPoolExecutor(max_workers=2) as executor:
            jobs = [
                executor.submit(self.operation, "heartbeat", self.heartbeat_request(identifier)),
                executor.submit(self.operation, "relinquishment",
                                {"cbsdId": self.cbsd_id, "grantId": identifier}),
            ]
            for job in jobs:
                self.assertIn(job.result()["response"]["responseCode"], (0, 103))
        self.assertNotIn(identifier, self.app.extensions["lab_session"].grants)
        self.register()
        identifier = self.grant()["grantId"]
        with ThreadPoolExecutor(max_workers=2) as executor:
            jobs = [executor.submit(self.post, self.registration()),
                    executor.submit(self.operation, "deregistration", {"cbsdId": self.cbsd_id})]
            for job in jobs:
                job.result()
        self.assertFalse(self.app.extensions["lab_session"].grants)
        self.assertEqual(self.operation("heartbeat", self.heartbeat_request(identifier))
                         ["response"]["responseCode"], 103)

    def test_batch_results_keep_request_order_and_do_not_create_invalid_grants(self):
        self.register()
        invalid = self.grant_request(low=3580000000, power=17)
        response = self.app.test_client().post("/v1.2//grant", json={
            "grantRequest": [invalid, self.grant_request(), self.grant_request()],
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual([item["response"]["responseCode"] for item in response.json["grantResponse"]],
                         [103, 0, 401])
        self.assertEqual(len(self.app.extensions["lab_session"].grants), 1)

    def test_positive_https_flow_requires_a_trusted_client_certificate(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(str(self.directory / "runtime/server-cert.pem"),
                                str(self.directory / "runtime/server-key.pem"))
        context.load_verify_locations(str(self.directory / "runtime/client-ca.pem"))
        server = make_server("127.0.0.1", 0, self.app, ssl_context=context)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            client = ssl.create_default_context(cafile=str(self.directory / "signer/server-ca.pem"))
            connection = http.client.HTTPSConnection("localhost", server.server_port, context=client, timeout=5)
            with self.assertRaises((ssl.SSLError, ConnectionError)):
                connection.request("GET", "/healthz")
                connection.getresponse()
            connection.close()
            client.load_cert_chain(str(self.directory / "signer/test-client-cert.pem"),
                                   str(self.directory / "signer/test-client-key.pem"))
            connection = http.client.HTTPSConnection("localhost", server.server_port, context=client, timeout=5)
            connection.request("POST", "/v1.2//registration",
                               json.dumps({"registrationRequest": [self.registration()]}),
                               {"Content-Type": "application/json"})
            result = json.loads(connection.getresponse().read())["registrationResponse"][0]
            self.assertEqual(result["response"]["responseCode"], 0)
            self.cbsd_id = result["cbsdId"]
            connection.close()
            connection = http.client.HTTPSConnection("localhost", server.server_port, context=client, timeout=5)
            connection.request("POST", "/v1.2//grant",
                               json.dumps({"grantRequest": [self.grant_request()]}),
                               {"Content-Type": "application/json"})
            result = json.loads(connection.getresponse().read())["grantResponse"][0]
            self.assertEqual(result["response"]["responseCode"], 0)
            connection.close()
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_opt_in_policy_and_mtls_are_mandatory_default_unchanged(self):
        default = self.new_app(DEFAULT_PROFILE)
        try:
            self.assertEqual(default.test_client().post("/v1.2/spectrumInquiry", json={}).status_code, 404)
            self.assertEqual(default.test_client().get("/healthz").json["profile"], DEFAULT_PROFILE)
        finally:
            cleanup_app(default)
        health = self.app.test_client().get("/healthz").json
        self.assertEqual(health["profile"], POSITIVE_PROFILE)
        self.assertTrue(health["labOnly"])
        self.assertEqual(health["statePersistence"], "atomic-json")
        self.assertEqual(health["policySha256"], hashlib.sha256(self.policy_path.read_bytes()).hexdigest())
        with patch.dict(os.environ, {"SAS_REQUIRE_CLIENT_CERT": "false"}):
            with self.assertRaisesRegex(ValueError, "requires mTLS"):
                self.new_app()
        with self.assertRaisesRegex(ValueError, "Unknown SAS_PROFILE"):
            self.new_app("unexpected")
        example = Path(__file__).with_name("lab-positive.example.json")
        with self.assertRaisesRegex(ValueError, "Invalid LAB policy"):
            self.new_app(policy_path=example)
        with self.assertRaises(FileNotFoundError):
            self.new_app(policy_path=self.directory / "missing.json")
        for field, value in (("maxEirpDbmMHz", 17), ("channelType", "PAL"),
                             ("allowedBandwidthsMHz", [50]), ("heartbeatInterval", 300),
                             ("labOnlyAcknowledged", 1), ("maxEirpDbmMHz", float("nan"))):
            policy = deepcopy(self.policy)
            policy[field] = value
            path = self.directory / "invalid-policy.json"
            path.write_text(json.dumps(policy))
            with self.assertRaises(ValueError):
                read_policy(path)

    def test_shorter_credential_deadline_clips_nonrenew_hb_and_restored_authorization(self):
        self.register()
        grant = self.grant()
        self.operation("heartbeat", self.heartbeat_request(grant["grantId"]))
        session = self.app.extensions["lab_session"]
        limit = self.clock.now() + datetime.timedelta(seconds=30)
        session.authorization_limit = limit
        response = session.handle("heartbeat", self.heartbeat_request(grant["grantId"], "AUTHORIZED"))
        self.response_validators["heartbeat"].validate(response)
        self.assertEqual(response["response"]["responseCode"], 0)
        self.assertEqual(response["cbsdId"], self.cbsd_id)
        self.assertEqual(response["grantId"], grant["grantId"])
        self.assertEqual(self.parsed_time(response["transmitExpireTime"]), limit)
        self.assertNotIn("grantExpireTime", response)
        self.assertEqual(session.grants[grant["grantId"]].expires, self.parsed_time(grant["grantExpireTime"]))
        directory, bindings = session.store.directory, session.store.bindings
        cleanup_app(self.app)
        store = StateStore(directory, bindings)
        try:
            earlier = self.clock.now() + datetime.timedelta(seconds=15)
            restored = LabSession(SOURCE, self.policy, self.clock, store, earlier)
            self.assertEqual(restored.grants[grant["grantId"]].transmit_expires, earlier)
            self.assertEqual(restored.grants[grant["grantId"]].expires,
                             self.parsed_time(grant["grantExpireTime"]))
            self.clock.advance(15)
            with self.assertRaises(CredentialError):
                restored.handle("heartbeat", self.heartbeat_request(grant["grantId"], "AUTHORIZED"))
        finally:
            store.close()

    def test_malformed_json_envelopes_and_unknown_routes_are_json(self):
        for operation in ("registration", "spectrumInquiry", "grant", "heartbeat",
                          "relinquishment", "deregistration"):
            for envelope in ({}, {operation + "Request": []}, {operation + "Request": "bad"}):
                response = self.app.test_client().post("/v1.2//" + operation + "/", json=envelope)
                self.assertEqual(response.status_code, 400)
                self.assertTrue(response.is_json)
                self.assertNotIn("Location", response.headers)
            response = self.app.test_client().post("/v1.2/" + operation,
                                                   data="{invalid", content_type="application/json")
            self.assertEqual(response.status_code, 400)
            self.assertTrue(response.is_json)
        response = self.app.test_client().post("/v1.2//unsupported", json={})
        self.assertEqual(response.status_code, 404)
        self.assertTrue(response.is_json)


class OperatorTests(unittest.TestCase):
    algorithm = "RS256"
    setUpClass = classmethod(PositiveTests.setUpClass.__func__)
    configure_response_contracts = classmethod(PositiveTests.configure_response_contracts.__func__)
    tearDownClass = classmethod(PositiveTests.tearDownClass.__func__)
    setUp = PositiveTests.setUp
    tearDown = PositiveTests.tearDown
    payload = RegistrationTests.payload
    registration = RegistrationTests.registration
    post = RegistrationTests.post
    register = PositiveTests.register
    operation = PositiveTests.operation
    grant_request = PositiveTests.grant_request
    grant = PositiveTests.grant
    heartbeat_request = PositiveTests.heartbeat_request
    parsed_time = PositiveTests.parsed_time

    @staticmethod
    def state_contents(directory):
        return {path.name: (path.stat().st_size, path.stat().st_mtime_ns,
                            path.read_bytes() if path.name != "session.lock" else None)
                for path in directory.iterdir()}

    def new_app(self, **kwargs):
        return PositiveTests.new_app(self, state_version=2, operator_control=True, **kwargs)

    def command(self, action, grant_id=None, command_id=None):
        session = self.app.extensions["lab_session"]
        result = {"action": action, "commandId": command_id or uuid.uuid4().hex,
                  "cbsdId": self.cbsd_id, "generation": session.generation}
        if action != "force-deregister":
            result["grantId"] = grant_id
        return result

    def restart(self):
        directory = self.app.extensions["lab_store"].directory
        cleanup_app(self.app)
        self.app = self.new_app(state_directory=directory)
        return self.app.extensions["lab_session"]

    def test_suspend_resume_restart_and_original_conditional_deadline(self):
        self.register()
        grant = self.grant()
        identifier = grant["grantId"]
        self.operation("heartbeat", self.heartbeat_request(identifier))
        command = self.command("suspend", identifier)
        session = self.app.extensions["lab_session"]
        self.assertEqual(session.control(command)["status"], "applied")
        snapshot = json.loads(session.store.path.read_bytes())
        self.assertEqual(snapshot["grants"][identifier]["status"], "SUSPENDED")
        self.assertIsNone(snapshot["grants"][identifier]["transmitExpireTime"])
        self.clock.advance(60)
        session = self.restart()
        result = self.operation("heartbeat", self.heartbeat_request(identifier, "AUTHORIZED", True))
        self.assertEqual(result["response"]["responseCode"], 501)
        self.assertEqual(result["cbsdId"], self.cbsd_id)
        self.assertEqual(result["grantId"], identifier)
        self.assertEqual(result["grantExpireTime"], grant["grantExpireTime"])
        self.assertLessEqual(self.parsed_time(result["transmitExpireTime"]), self.clock.now())
        self.assertEqual(session.control(command)["status"], "already-applied")
        self.assertEqual(self.operation("grant", self.grant_request())["response"]["responseData"], [identifier])
        session.control(self.command("resume", identifier))
        self.assertFalse(session._authorized(session.grants[identifier], self.clock.now(), self.clock.monotonic()))
        session = self.restart()
        result = self.operation("heartbeat", self.heartbeat_request(identifier, "AUTHORIZED"))
        self.assertEqual(result["response"]["responseCode"], 502)
        result = self.operation("heartbeat", self.heartbeat_request(identifier))
        self.assertEqual(result["response"]["responseCode"], 0)
        self.assertEqual(session.grants[identifier].expires, self.parsed_time(grant["grantExpireTime"]))

    def test_termination_reset_and_fresh_registration_never_resurrect(self):
        self.register()
        first = self.grant()
        identifier = first["grantId"]
        self.operation("heartbeat", self.heartbeat_request(identifier))
        self.app.extensions["lab_session"].control(self.command("terminate", identifier))
        session = self.restart()
        result = self.operation("heartbeat", self.heartbeat_request(identifier, "AUTHORIZED", True))
        self.assertEqual(result["response"]["responseCode"], 500)
        self.assertNotIn("grantId", result)
        self.assertNotIn("grantExpireTime", result)
        self.assertLessEqual(self.parsed_time(result["transmitExpireTime"]), self.clock.now())
        for _ in range(2):
            result = self.operation("relinquishment", {"cbsdId": self.cbsd_id, "grantId": identifier})
            self.assertEqual(result["response"]["responseCode"], 103)
            self.assertEqual(result["response"]["responseData"], ["grantId"])
            self.assertNotIn("grantId", result)
        replacement = self.grant()
        self.assertNotEqual(identifier, replacement["grantId"])
        old_command = self.command("force-deregister")
        session.control(old_command)
        session = self.restart()
        result = self.operation("heartbeat", self.heartbeat_request(replacement["grantId"]))
        self.assertEqual(result["response"]["responseCode"], 105)
        self.assertNotIn("cbsdId", result)
        self.assertNotIn("grantId", result)
        self.assertFalse(session.grants)
        result = self.operation("deregistration", {"cbsdId": self.cbsd_id})
        self.assertEqual(result["response"]["responseCode"], 105)
        result = self.operation("heartbeat", {"cbsdId": "UNKNOWN", "grantId": identifier,
                                              "operationState": "GRANTED"})
        self.assertEqual(result["response"]["responseCode"], 103)
        self.register()
        with self.assertRaises(ControlError):
            session.control(old_command)
        self.assertIsNone(session.forced_reset)
        third = self.grant()
        self.assertEqual(self.operation("heartbeat", self.heartbeat_request(third["grantId"]))
                         ["response"]["responseCode"], 0)

    def test_command_target_replay_schema_io_and_clock_failures(self):
        self.register()
        grant = self.grant()
        session = self.app.extensions["lab_session"]
        for action in ("resume", "suspend"):
            command = self.command(action, "f" * 32)
            with self.assertRaises(ControlError):
                session.control(command)
        command = self.command("suspend", grant["grantId"])
        session.control(command)
        changed = deepcopy(command)
        changed["action"] = "terminate"
        with self.assertRaises(ControlError):
            session.control(changed)
        for invalid in ({}, {"action": "scheduled"}, {**command, "extra": True}):
            with self.assertRaises(ControlError):
                session.control(invalid)
        with patch("lab_state.os.replace", side_effect=OSError("fixture IO failure")):
            with self.assertRaises(StateStoreError):
                session.control(self.command("resume", grant["grantId"]))
        self.assertTrue(session.faulted)
        with self.assertRaises(StateStoreError):
            session.control({"action": "status"})

    def test_marker_expiry_and_concurrent_single_application(self):
        self.register()
        grant = self.grant()
        session = self.app.extensions["lab_session"]
        command = self.command("suspend", grant["grantId"])
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(session.control, [command] * 4))
        self.assertEqual(sum(item["status"] == "applied" for item in results), 1)
        self.assertEqual(len(session.applied_commands), 1)
        session.control(self.command("force-deregister"))
        self.clock.advance(600)
        session = self.restart()
        self.assertIsNone(session.forced_reset)
        result = self.operation("heartbeat", self.heartbeat_request(grant["grantId"]))
        self.assertEqual(result["response"]["responseCode"], 103)
        self.assertNotIn("grantId", result)

    def test_explicit_migration_preserves_original_state_and_private_backup(self):
        cleanup_app(self.app)
        self.app = PositiveTests.new_app(self)
        self.register()
        grant = self.grant()
        self.operation("heartbeat", self.heartbeat_request(grant["grantId"]))
        store = self.app.extensions["lab_store"]
        directory, bindings = store.directory, store.bindings
        original = store.path.read_bytes()
        previous = json.loads(original)
        contents = self.state_contents(directory)
        migrate_v1(directory, bindings, previous["checksum"], dry_run=True)
        self.assertEqual(contents, self.state_contents(directory))
        with self.assertRaises(StateStoreError):
            migrate_v1(directory, bindings, previous["checksum"])
        cleanup_app(self.app)
        with self.assertRaises(StateStoreError):
            self.new_app(state_directory=directory)
        backup = migrate_v1(directory, bindings, previous["checksum"])
        self.assertEqual((directory / backup).read_bytes(), original)
        migrated = json.loads((directory / "session.json").read_bytes())
        self.assertEqual(migrated["version"], 2)
        self.assertEqual(migrated["cbsdId"], previous["cbsdId"])
        self.assertEqual(migrated["savedAt"], previous["savedAt"])
        for name, value in previous["grants"][grant["grantId"]].items():
            self.assertEqual(migrated["grants"][grant["grantId"]][name], value)
        self.assertNotIn("peerCertificate", migrated)
        self.app = self.new_app(state_directory=directory)
        restored = self.app.extensions["lab_session"].grants[grant["grantId"]]
        self.assertEqual(restored.expires, self.parsed_time(grant["grantExpireTime"]))

    def test_removed_experimental_fields_are_not_silently_downgraded(self):
        self.register()
        store = self.app.extensions["lab_store"]
        directory, bindings = store.directory, store.bindings
        snapshot = json.loads(store.path.read_bytes())
        cleanup_app(self.app)
        for extra in ("peerCertificate", "pkiPolicy"):
            incompatible = deepcopy(snapshot)
            if extra == "peerCertificate":
                incompatible[extra] = None
            else:
                incompatible["bindings"][extra] = "f" * 64
            incompatible["checksum"] = StateStore.checksum(incompatible)
            original = json.dumps(incompatible).encode()
            (directory / "session.json").write_bytes(original)
            with self.assertRaises(StateStoreError):
                self.new_app(state_directory=directory)
            self.assertEqual((directory / "session.json").read_bytes(), original)
        self.assertNotIn("pkiPolicy", bindings)

    def test_suspended_without_renew_expiry_invalid_ids_and_clock_rollback(self):
        self.register()
        grant = self.grant()
        session = self.app.extensions["lab_session"]
        session.control(self.command("suspend", grant["grantId"]))
        result = self.operation("heartbeat", self.heartbeat_request(grant["grantId"]))
        self.assertEqual(result["response"]["responseCode"], 501)
        self.assertNotIn("grantExpireTime", result)
        self.assertNotIn("operationParam", result)
        self.assertEqual(result["grantId"], grant["grantId"])
        self.clock.advance(600)
        session = self.restart()
        self.assertNotIn(grant["grantId"], session.grants)
        result = self.operation("heartbeat", self.heartbeat_request(grant["grantId"]))
        self.assertEqual(result["response"]["responseData"], ["grantId"])
        self.assertNotIn("grantId", result)
        with self.assertRaises(ControlError):
            session.control(self.command("resume", grant["grantId"]))
        self.clock.advance(-1)
        with self.assertRaises(StateStoreError):
            session.control({"action": "status"})
        self.assertTrue(session.faulted)

    def test_control_default_disabled_and_state_version_never_auto_downgrades(self):
        cleanup_app(self.app)
        self.app = PositiveTests.new_app(self)
        self.assertIsNone(self.app.extensions["lab_control"])
        self.assertEqual(self.app.test_client().get("/healthz").json["stateVersion"], 1)
        with self.assertRaisesRegex(ValueError, "explicitly migrated"):
            PositiveTests.new_app(self, operator_control=True)
        cleanup_app(self.app)
        self.app = self.new_app()
        directory = self.app.extensions["lab_store"].directory
        cleanup_app(self.app)
        with self.assertRaises(StateStoreError):
            PositiveTests.new_app(self, state_directory=directory)
        self.app = self.new_app(state_directory=directory)

    def test_command_retention_bound_and_semantic_corruption_fail_startup(self):
        self.register()
        grant = self.grant()
        session = self.app.extensions["lab_session"]
        for index in range(16):
            action = "suspend" if index % 2 == 0 else "resume"
            session.control(self.command(action, grant["grantId"]))
        with self.assertRaises(ControlError):
            session.control(self.command("suspend", grant["grantId"]))
        self.assertEqual(len(session.applied_commands), 16)
        directory = session.store.directory
        original = session.store.path.read_bytes()
        snapshot = json.loads(original)
        cleanup_app(self.app)
        duplicate = deepcopy(snapshot)
        duplicate["appliedCommands"][1] = deepcopy(duplicate["appliedCommands"][0])
        inactive = deepcopy(snapshot)
        inactive["grants"][grant["grantId"]].update(
            status="SUSPENDED", transmitExpireTime=(self.clock.now() + datetime.timedelta(seconds=180)).isoformat(),
            transmitRemainingSeconds=180)
        for corrupted in (duplicate, inactive):
            corrupted["checksum"] = StateStore.checksum(corrupted)
            (directory / "session.json").write_text(json.dumps(corrupted))
            with self.assertRaises(StateStoreError):
                self.new_app(state_directory=directory)
        (directory / "session.json").write_bytes(original)
        self.app = self.new_app(state_directory=directory)

    @unittest.skipUnless(os.name == "posix" and hasattr(socket, "SO_PEERCRED") and
                         getattr(os, "geteuid", lambda: -1)() == 10001,
                         "Real private IPC requires Linux UID10001; covered by offline image runner")
    def test_real_private_socket_and_verified_uid(self):
        self.register()
        grant = self.grant()
        path = str(Path(tempfile.mkdtemp(dir=self.directory)) / "control.sock")
        server = ControlServer(self.app.extensions["lab_session"], path)
        server.path.parent.chmod(0o700)
        server.start()
        try:
            self.assertEqual(stat.S_IMODE(server.path.stat().st_mode), 0o600)
            self.assertEqual(request_command({"action": "status"}, path)["cbsdId"], self.cbsd_id)
            result = request_command(self.command("suspend", grant["grantId"]), path)
            self.assertEqual(result["status"], "applied")
            with self.assertRaises(ControlError):
                ControlServer(self.app.extensions["lab_session"], path).start()
        finally:
            server.close()


class ES256PositiveTests(PositiveTests):
    algorithm = "ES256"


class PackagingTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "PowerShell Windows launcher test")
    def test_positive_package_has_explicit_policy_and_no_client_cert_fallback(self):
        with tempfile.TemporaryDirectory(prefix="mock-sas-positive-package-") as temporary:
            directory = Path(temporary)
            generate(directory / "fixture", [], ["127.0.0.1"])
            ca = directory / "fixture/signer/server-ca.pem"
            policy = json.loads(Path(__file__).with_name("lab-positive.example.json").read_text())
            path = directory / "policy.json"
            path.write_text(json.dumps(policy))
            command = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                       str(Path(__file__).with_name("Deploy-MockSas.ps1")),
                       "-PackageOnly", "-ServerIp", "127.0.0.1", "-Profile", POSITIVE_PROFILE,
                       "-LabPositiveConfig", str(path), "-ClientCa", str(ca),
                       "-ClientRootSha256", next(iter(fingerprints(ca_certificates(ca)))),
                       "-OutputDirectory", str(directory / "output")]
            denied = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("acknowledgments", denied.stderr)
            policy.update(labOnlyAcknowledged=True, rfContainmentAcknowledged=True)
            path.write_text(json.dumps(policy))
            accepted = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
            self.assertIn("no SSH connection", accepted.stdout)
            with tarfile.open(next((directory / "output").glob("*.tar"))) as archive:
                names = {name.removeprefix("./") for name in archive.getnames()}
                for expected in ("inputs/lab-policy.json", "compose.mock-sas.lab-positive.yml",
                                 "deploy/mock-sas/lab_protocol.py"):
                    self.assertIn(expected, names)
                for operation in ("spectrumInquiry", "grant", "heartbeat", "relinquishment", "deregistration"):
                    self.assertIn("CBRS_Mock_SAS_Python_Master/cbrsPython-master/jsonExpectedFolder/"
                                  f"OptionalParams/{operation}Optional.json", names)
            no_client = command[:]
            index = no_client.index("-ClientCa")
            del no_client[index:index + 2]
            index = no_client.index("-ClientRootSha256")
            del no_client[index:index + 2]
            no_client.append("-AllowNoClientCertificate")
            denied = subprocess.run(no_client, capture_output=True, text=True, timeout=60)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("requires mTLS", denied.stderr)
    @unittest.skipUnless(os.name == "nt", "PowerShell Windows transport test")
    def test_windows_payload_transport_has_valid_bash_syntax(self):
        bash = Path(os.environ["ProgramFiles"]) / "Git/bin/bash.exe"
        if not bash.exists():
            self.skipTest("Git Bash unavailable")
        script = Path(__file__).with_name("deploy-server.sh")
        command = (
            f"$payload = [IO.File]::ReadAllText('{script}').Replace(\"`r\", ''); "
            f"($payload + \"`n# End of payload\") | & '{bash}' -n; exit $LASTEXITCODE"
        )
        result = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_image_copy_sources_exist_and_do_not_include_old_credentials(self):
        root = Path(__file__).resolve().parents[2]
        files = []
        for line in (root / "Dockerfile.mock-sas").read_text().splitlines():
            if not line.startswith("COPY "):
                continue
            for source in shlex.split(line)[1:-1]:
                path = root / source
                self.assertTrue(path.exists(), source)
                files.extend(path.rglob("*") if path.is_dir() else [path])
        for path in files:
            self.assertNotIn("certificates", path.parts)
            self.assertNotIn(path.suffix.lower(), (".key", ".pem", ".cer", ".p12", ".pfx"))
        self.assertIn(root / "deploy" / "mock-sas" / "generate_lab.py", files)
        self.assertIn(root / "deploy" / "mock-sas" / "app.py", files)

    def test_certificate_catalog_excludes_specific_materials_from_git_and_build(self):
        root = Path(__file__).resolve().parents[2]
        catalog = "deploy/mock-sas/lab-certificates"
        self.assertIn(catalog + "/**", (root / ".gitignore").read_text().splitlines())
        self.assertIn("!" + catalog + "/README.md", (root / ".gitignore").read_text().splitlines())
        ignored = (root / ".dockerignore").read_text().splitlines()
        for pattern in (catalog, "**/*.p12", "**/*.pfx"):
            self.assertIn(pattern, ignored)
        self.assertNotIn("PRIVATE KEY", (root / catalog / "README.md").read_text())

    @unittest.skipUnless(os.name == "nt", "PowerShell Windows launcher test")
    def test_windows_offline_package_allowlist_and_manifest(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix="mock-sas-offline-package-") as temporary:
            directory = Path(temporary)
            fixture = directory / "fixture"
            generate(fixture, [], ["127.0.0.1"])
            ca = fixture / "signer/server-ca.pem"
            fingerprint = next(iter(fingerprints(ca_certificates(ca))))
            command = [
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                str(root / "deploy/mock-sas/Deploy-MockSas.ps1"),
                "-PackageOnly", "-ServerIp", "127.0.0.1", "-ClientCa", str(ca),
                "-ClientRootSha256", fingerprint, "-RadioTrustBundle", str(ca),
                "-OutputDirectory", str(directory / "output"),
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("no SSH connection", result.stdout)
            shutil.copyfile(fixture / "signer/cpi-key.pem", directory / "output/cpi-key.pem")
            repeated = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertIn("Package output already exists", repeated.stderr)
            self.assertNotIn("SeSecurityPrivilege", repeated.stderr)
            with tarfile.open(next((directory / "output").glob("*.tar"))) as archive:
                members = {item.name.removeprefix("./"): item for item in archive.getmembers() if item.isfile()}
                self.assertIn("inputs/client-ca.pem", members)
                self.assertIn("deploy/mock-sas/deploy_support.py", members)
                self.assertIn("deploy/mock-sas/lab-certificates/README.md", members)
                for name in members:
                    if "certificates/" in name:
                        self.assertEqual(name, "deploy/mock-sas/lab-certificates/README.md")
                    self.assertNotIn("signer/", name)
                    self.assertFalse(name.endswith((".key", ".p12", ".pfx")) or "private" in name.lower())
                manifest = archive.extractfile(members["package.sha256"]).read().decode()
                for line in manifest.splitlines():
                    expected, name = line.split("  ", 1)
                    self.assertEqual(hashlib.sha256(archive.extractfile(members[name]).read()).hexdigest(), expected)
            command[command.index("-ClientRootSha256") + 1] = "0" * 64
            failed = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("expected radio root", failed.stderr)
            command[command.index("-ClientCa") + 1] = str(fixture / "signer/cpi-key.pem")
            failed = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("not private keys", failed.stderr)
            isolated = [
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                str(root / "deploy/mock-sas/Deploy-MockSas.ps1"),
                "-PackageOnly", "-ServerIp", "127.0.0.1", "-AllowNoClientCertificate",
                "-OutputDirectory", str(directory / "isolated-output"),
            ]
            result = subprocess.run(isolated, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("no SSH connection", result.stdout)

    @unittest.skipUnless(os.name == "nt", "PowerShell Windows launcher test")
    def test_deployment_without_explicit_ssh_target_fails_before_any_remote_action(self):
        command = [
            "powershell", "-NoProfile", "-NonInteractive", "-File",
            str(Path(__file__).with_name("Deploy-MockSas.ps1")),
            "-ServerIp", "127.0.0.1", "-AllowNoClientCertificate",
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires explicit -SshTarget", result.stderr)
        self.assertNotIn("PREFLIGHT", result.stdout)
        self.assertNotIn("Upload", result.stdout)


class CoexistenceTests(unittest.TestCase):
    def run_preflight(self, mode="free", explicit=False, owned=False, port=8443, requested=8443,
                      profile=DEFAULT_PROFILE, explicit_profile=False):
        bash = (str(Path(os.environ["ProgramFiles"]) / "Git/bin/bash.exe")
                if os.name == "nt" else shutil.which("bash"))
        if not bash or not Path(bash).exists():
            self.skipTest("Bash unavailable")
        with tempfile.TemporaryDirectory(prefix="mock-sas-preflight-") as temporary:
            directory = Path(temporary)
            deployment = directory / "deployment"
            identity = hashlib.sha256(deployment.as_posix().encode()).hexdigest()
            if owned or mode == "unrelated-directory":
                deployment.mkdir()
                (deployment / "preserve.txt").write_text("unrelated data")
            if owned:
                (deployment / ".deployment-owner").write_text(identity + "\n")
                (deployment / "deploy.env").write_text(f"SAS_HTTPS_PORT={port}\n")
                if mode in ("stored-positive", "invalid-stored-profile", "public-profile"):
                    (deployment / ".active-profile").write_text(
                        ("INVALID" if mode == "invalid-stored-profile" else POSITIVE_PROFILE) + "\n")
            if mode == "wrong-marker":
                (deployment / ".deployment-owner").write_text("0" * 64 + "\n")
            proc = directory / "proc" / "123"
            proc.mkdir(parents=True)
            arguments = ["docker-proxy", "-proto", "tcp", "-host-ip", "0.0.0.0",
                         "-host-port", str(port), "-container-ip", "172.19.0.2",
                         "-container-port", "8443"]
            if mode == "wrong-proxy":
                arguments[arguments.index("-container-ip") + 1] = "172.19.0.99"
            (proc / "cmdline").write_bytes(b"\0".join(value.encode() for value in arguments) + b"\0")
            source = Path(__file__).with_name("deploy-server.sh").read_text()
            # Redirect only absolute deployment/proc paths into the fixture.
            source = source.replace(
                "^/(opt|srv)/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$", "^${TEST_DIRECTORY}$")
            source = source.replace("/proc/$pid/cmdline", "$PROC_FIXTURE/$pid/cmdline")
            script = directory / "payload.sh"
            script.write_text(source, newline="\n")
            wrapper = directory / "wrapper.sh"
            wrapper.write_text(r"""
set -euo pipefail
uname() { echo Linux; }
id() { echo 0; }
flock() { echo 'Forbidden preflight write/lock operation' >&2; return 1; }
realpath() {
    if [[ $MODE == ancestor-symlink ]]; then echo /unrelated; else echo "$TEST_DIRECTORY"; fi
}
stat() {
    if [[ $* == *%u* ]]; then
        if [[ $MODE == foreign-directory-owner ]]; then echo 1000; else echo 0; fi
    elif [[ $* == *active-profile* && $MODE == public-profile ]]; then echo 644
    elif [[ $* == *deployment-owner* ]]; then
        if [[ $MODE == public-marker ]]; then echo 644; else echo 600; fi
    else echo 700; fi
}
docker() {
    case "$*" in
        info) return 0 ;;
        "info --format "*) echo linux/amd64 ;;
        "compose version") echo 'Docker Compose v2 fixture' ;;
        "context show") echo default ;;
        "context inspect "*) echo unix:///var/run/docker.sock ;;
        "ps -a --format "*) echo 'foreign-service foreign-project 0.0.0.0:8080' ;;
        "ps -aq --filter "*)
            if [[ $MODE == project-collision ]]; then echo foreign; elif [[ $OWNED == true ]]; then echo own; fi ;;
        "ps -q") echo foreign; if [[ $OWNED == true ]]; then echo own; fi ;;
        *NetworkSettings.Ports*own)
            printf '0.0.0.0|%s|8443/tcp\n' "$STORED_PORT" ;;
        *NetworkSettings.Ports*foreign)
            if [[ $MODE == docker-port ]]; then echo '0.0.0.0|8443|443/tcp'; else echo '0.0.0.0|8080|80/tcp'; fi ;;
        *NetworkSettings.Networks*own) echo 172.19.0.2 ;;
        *Config.Labels*own) printf 'winnf-mock-sas-%s|%s|%s\n' "${IDENTITY:0:12}" "$IDENTITY" "$PROFILE_LABEL" ;;
        *Config.Labels*foreign) echo 'foreign-project|other|unrelated' ;;
        *) echo "Forbidden/unexpected Docker operation: $*" >&2; return 1 ;;
    esac
}
ss() {
    if [[ $# == 2 ]]; then return; fi
    case "$MODE:$*" in
        ipv4:*ltnp4*8443*|all-busy:*ltnp4*)
            echo 'LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:(("unrelated",pid=999,fd=3))' ;;
        ipv6:*ltnp6*8443*|own-with-foreign-ipv6:*ltnp6*8443*)
            echo 'LISTEN 0 128 [::]:8443 [::]:* users:(("unrelated",pid=999,fd=3))' ;;
        own-proxy:*ltnp4*8443*|wrong-proxy:*ltnp4*8443*)
            echo 'LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:(("docker-proxy",pid=123,fd=3))' ;;
        own-with-foreign-ipv4:*ltnp4*8443*)
            echo 'LISTEN 0 128 127.0.0.1:8443 0.0.0.0:* users:(("unrelated",pid=999,fd=3))' ;;
    esac
}
source "$1" --preflight "$TEST_DIRECTORY" "$REQUESTED_PORT" "$EXPLICIT_PORT" "$REQUESTED_PROFILE" "$PROFILE_EXPLICIT"
""", newline="\n")
            before = {path.name: path.read_bytes() for path in deployment.glob("*")}
            environment = dict(os.environ, MODE=mode, TEST_DIRECTORY=deployment.as_posix(),
                               PROC_FIXTURE=(directory / "proc").as_posix(),
                               OWNED=str(owned).lower(), STORED_PORT=str(port), IDENTITY=identity,
                               PROFILE_LABEL=POSITIVE_PROFILE if mode == "own-positive" else DEFAULT_PROFILE,
                               REQUESTED_PROFILE=profile, PROFILE_EXPLICIT=str(explicit_profile).lower(),
                               EXPLICIT_PORT=str(explicit).lower(), REQUESTED_PORT=str(requested))
            result = subprocess.run([bash, wrapper.as_posix(), script.as_posix()],
                                    env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual({path.name: path.read_bytes() for path in deployment.glob("*")}, before)
            if not owned and mode != "unrelated-directory":
                self.assertFalse(deployment.exists(), "Preflight must not create the deployment")
            return result

    def test_free_port_and_ipv4_ipv6_docker_nat_fallback(self):
        for mode, port in [("free", 8443), ("ipv4", 8444), ("ipv6", 8444), ("docker-port", 8444)]:
            with self.subTest(mode=mode):
                result = self.run_preflight(mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"SELECTED_HTTPS_PORT={port}", result.stdout)

    def test_profile_changes_require_explicit_choice_and_do_not_adopt_foreign_containers(self):
        result = self.run_preflight("own-positive", owned=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Profile changes require explicit", result.stderr)
        for mode, profile in (("own-positive", POSITIVE_PROFILE),
                              ("own-positive", DEFAULT_PROFILE), ("free", POSITIVE_PROFILE)):
            result = self.run_preflight(mode, owned=True, profile=profile, explicit_profile=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.run_preflight("project-collision", owned=True,
                                    profile=POSITIVE_PROFILE, explicit_profile=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrelated container", result.stderr)
        result = self.run_preflight(profile=POSITIVE_PROFILE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected explicitly", result.stderr)
        result = self.run_preflight("stored-positive", owned=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Profile changes require explicit", result.stderr)
        for mode in ("invalid-stored-profile", "public-profile"):
            result = self.run_preflight(mode, owned=True, explicit_profile=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("profile", result.stderr.lower())

    def test_explicit_or_exhausted_port_conflicts_do_not_displace_services(self):
        for mode, explicit in [("docker-port", True), ("ipv6", True), ("all-busy", False)]:
            with self.subTest(mode=mode):
                result = self.run_preflight(mode, explicit=explicit,
                                            requested=65535 if mode == "all-busy" else 8443)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("SELECTED_HTTPS_PORT=", result.stdout)

    def test_owned_deployment_preserves_port_and_allows_only_its_proxy(self):
        for mode, port in [("free", 9443), ("own-proxy", 8443)]:
            with self.subTest(mode=mode):
                result = self.run_preflight(mode, owned=True, port=port)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"SELECTED_HTTPS_PORT={port}", result.stdout)
        result = self.run_preflight(owned=True, explicit=True, port=9443)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Existing port is 9443", result.stderr)

    def test_owned_binding_does_not_hide_foreign_listener_or_proxy(self):
        for mode in ("own-with-foreign-ipv4", "own-with-foreign-ipv6", "wrong-proxy"):
            with self.subTest(mode=mode):
                result = self.run_preflight(mode, owned=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("overlaps another listener/container", result.stderr)

    def test_unrelated_directory_project_and_marker_are_not_adopted(self):
        for mode, owned in [("unrelated-directory", False), ("project-collision", False),
                            ("project-collision", True), ("wrong-marker", True),
                            ("public-marker", True), ("foreign-directory-owner", True),
                            ("ancestor-symlink", False)]:
            with self.subTest(mode=mode, owned=owned):
                result = self.run_preflight(mode, owned=owned)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ERROR:", result.stderr)
                self.assertNotIn("SELECTED_HTTPS_PORT=", result.stdout)


class DeploymentTests(unittest.TestCase):
    def test_cpi_key_mismatch_is_rejected_without_writing_exports(self):
        with tempfile.TemporaryDirectory(prefix="mock-sas-key-match-") as temporary:
            directory = Path(temporary)
            credentials = directory / "credentials"
            generate(credentials, [], ["127.0.0.1"])
            (credentials / "signer/cpi-key.pem").write_bytes((credentials / "runtime/server-key.pem").read_bytes())
            before = {str(path.relative_to(credentials)): path.read_bytes()
                      for path in credentials.rglob("*") if path.is_file()}
            with self.assertRaisesRegex(ValueError, "Certificate/private key mismatch"):
                prepare(credentials, directory / "settings.json", directory / "exports",
                        "127.0.0.1", 8444, False)
            self.assertFalse((directory / "settings.json").exists())
            self.assertFalse((directory / "exports").exists())
            self.assertEqual(before, {str(path.relative_to(credentials)): path.read_bytes()
                                     for path in credentials.rglob("*") if path.is_file()})

    def test_positive_prepare_preserves_credentials_settings_and_is_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="mock-sas-positive-prepare-") as temporary:
            directory = Path(temporary)
            credentials = directory / "credentials"
            generate(credentials, [], ["127.0.0.1"])
            ca = credentials / "signer/server-ca.pem"
            policy = json.loads(Path(__file__).with_name("lab-positive.example.json").read_text())
            policy.update(labOnlyAcknowledged=True, rfContainmentAcknowledged=True)
            path = directory / "policy.json"
            path.write_text(json.dumps(policy))
            settings = directory / "settings.json"
            arguments = (credentials, settings, directory / "registration-exports", "127.0.0.1", 8444, True, ca)
            prepare(*arguments)
            before = {str(item.relative_to(credentials)): item.read_bytes()
                      for item in credentials.rglob("*") if item.is_file()}
            settings_before = settings.read_bytes()
            arguments = (credentials, settings, directory / "positive-exports", "127.0.0.1", 8444, True, ca)
            result = prepare(*arguments, profile=POSITIVE_PROFILE, lab_policy=path)
            self.assertEqual(result, prepare(*arguments, profile=POSITIVE_PROFILE, lab_policy=path))
            self.assertEqual(result["profile"], POSITIVE_PROFILE)
            self.assertFalse(result["radioEndToEndVerified"])
            self.assertEqual(settings.read_bytes(), settings_before)
            self.assertEqual(before, {str(item.relative_to(credentials)): item.read_bytes()
                                     for item in credentials.rglob("*") if item.is_file()})
            changed = deepcopy(policy)
            changed["maxEirpDbmMHz"] = 15
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "Refusing to overwrite"):
                prepare(*arguments, profile=POSITIVE_PROFILE, lab_policy=path)
            self.assertEqual(settings.read_bytes(), settings_before)
            with self.assertRaisesRegex(ValueError, "requires mTLS"):
                prepare(credentials, settings, directory / "denied", "127.0.0.1", 8444,
                        False, profile=POSITIVE_PROFILE, lab_policy=path)
            self.assertFalse((directory / "denied").exists())
    def test_probe_connects_to_configured_lan_address_not_loopback(self):
        with patch("deploy_support.ssl.create_default_context"), \
                patch("deploy_support.socket.create_connection",
                      side_effect=RuntimeError("connection target checked")) as connect:
            with self.assertRaisesRegex(RuntimeError, "connection target checked"):
                probe_once("unused.pem", "192.0.2.10", 8444, True)
            connect.assert_called_once_with(("192.0.2.10", 8444), timeout=5)

    def test_unclassified_connection_reset_is_not_a_successful_mtls_probe(self):
        with patch("deploy_support.probe_once", side_effect=ConnectionResetError("closed")), \
                patch("deploy_support.time.monotonic", side_effect=[0, 2]):
            with self.assertRaises(ConnectionResetError):
                probe("unused.pem", "192.0.2.10", 8443, True, timeout=1)

    def test_explicit_no_client_cert_https_health_and_wrong_mtls_policy(self):
        with tempfile.TemporaryDirectory(prefix="mock-sas-deployment-tests-") as temporary:
            directory = Path(temporary)
            generate(directory, [], ["127.0.0.1"])
            app = create_app(directory / "config/device.json", directory / "runtime/cpi-cert.pem")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(directory / "runtime/server-cert.pem"),
                                    str(directory / "runtime/server-key.pem"))
            server = make_server("127.0.0.1", 0, app, ssl_context=context)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                result = probe_once(directory / "signer/server-ca.pem", "127.0.0.1", server.server_port, False)
                self.assertTrue(result["httpsApplicationHealthVerified"])
                self.assertFalse(result["radioEndToEndVerified"])
                with self.assertRaisesRegex(ValueError, "mTLS policy failure"):
                    probe_once(directory / "signer/server-ca.pem", "127.0.0.1", server.server_port, True)
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()
                app.extensions["lab_workspace"].cleanup()

    def test_prepare_preserves_keys_config_settings_and_radio_ca_bundle(self):
        with tempfile.TemporaryDirectory(prefix="mock-sas-deployment-tests-") as temporary:
            directory = Path(temporary)
            credentials = directory / "credentials"
            radio = directory / "radio-fixture"
            generate(credentials, [], ["192.0.2.10"])
            generate(radio, [], ["127.0.0.1"])
            client_ca = radio / "signer/server-ca.pem"
            fingerprint = next(iter(fingerprints(ca_certificates(client_ca))))
            original_key = (credentials / "signer/cpi-key.pem").read_bytes()
            original_device = (credentials / "config/device.json").read_bytes()
            bundle = directory / "radio-bundle.pem"
            bundle.write_bytes(client_ca.read_bytes() * 2)
            settings = directory / "settings.json"
            outputs = directory / "exports"
            arguments = (credentials, settings, outputs, "192.0.2.10",
                         8443, True, client_ca, fingerprint, bundle)
            prepare(*arguments, fresh=True)
            prepare(*arguments)
            self.assertEqual((credentials / "signer/cpi-key.pem").read_bytes(), original_key)
            self.assertEqual((credentials / "config/device.json").read_bytes(), original_device)
            merged = ca_certificates(outputs / "radio-trust-bundle-with-lab.pem")
            self.assertEqual(len(merged), 2)
            self.assertIn(fingerprint, fingerprints(merged))
            with self.assertRaisesRegex(ValueError, "does not include"):
                prepare(credentials, directory / "other-settings.json", outputs,
                        "127.0.0.2", 8443, True, client_ca)
            # A changed setting is blocked before any credential mutation.
            with self.assertRaisesRegex(ValueError, "settings differ"):
                prepare(credentials, settings, outputs, "192.0.2.10", 9443, True, client_ca)
            with self.assertRaisesRegex(ValueError, "trust replacement"):
                prepare(credentials, settings, outputs, "192.0.2.10", 8443, True,
                        credentials / "signer/server-ca.pem")

    def test_wrong_san_and_missing_or_wrong_client_ca_are_blocked(self):
        with tempfile.TemporaryDirectory(prefix="mock-sas-deployment-tests-") as temporary:
            directory = Path(temporary)
            credentials = directory / "credentials"
            generate(credentials, [], ["127.0.0.1"])
            arguments = (credentials, directory / "settings.json", directory / "exports")
            with self.assertRaisesRegex(ValueError, "does not include"):
                prepare(*arguments, "192.0.2.10", 8443, False)
            with self.assertRaisesRegex(ValueError, "real radio client CA"):
                prepare(*arguments, "127.0.0.1", 8443, True)
            with self.assertRaisesRegex(ValueError, "expected radio root"):
                prepare(*arguments, "127.0.0.1", 8443, True,
                        credentials / "signer/server-ca.pem", "0" * 64)


if __name__ == "__main__":
    unittest.main()

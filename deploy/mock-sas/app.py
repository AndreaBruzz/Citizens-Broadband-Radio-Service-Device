"""Headless registration profile using the repository's original Mock SAS handler."""

import datetime
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from types import SimpleNamespace
from xml.dom import minidom
import xml.etree.ElementTree as ET

from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from flask import Flask, g, jsonify, request
import jsonschema
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, UnsupportedMediaType

from lab_protocol import (
    DEFAULT_PROFILE, POSITIVE_PROFILE, PROFILES, REQUIRED, LabSession,
    Clock, CredentialError, finite_json, log_validation, parameter_faults, read_policy,
)
from lab_state import StateStore, StateStoreError
from operator_control import ControlServer

SOURCE = Path(os.environ.get(
    "SAS_SOURCE",
    str(Path(__file__).resolve().parents[2] /
        "CBRS_Mock_SAS_Python_Master" / "cbrsPython-master"),
))
sys.path.insert(0, str(SOURCE / "cbrsPython"))
from model.CBRSRequestHandler import CBRSRequestHandler

LOG = logging.getLogger("mock_sas_lab")
SCENARIO = "REG_SingleStep_CPI_Success_cbsd1.json"
DEVICE_SCHEMA = {
    "type": "object",
    "required": ["fccId", "cbsdSerialNumber", "cbsdCategory", "radioTechnology"],
    "additionalProperties": False,
    "properties": {
        "fccId": {"type": "string", "minLength": 1, "maxLength": 128},
        "cbsdSerialNumber": {"type": "string", "minLength": 1, "maxLength": 128},
        "cbsdCategory": {"enum": ["A", "B"]},
        "radioTechnology": {"enum": ["NR", "E_UTRA", "CAMBIUM_NETWORKS"]},
    },
}


class LabLogger:
    def print_to_Logs_Files(self, message, important):
        safe_messages = {
            "Registration message contains cpiSignatureData",
            "Invalid CPI JWS segments",
            "Signed CPI payload contains nonfinite numbers",
            "verified signature on cpiSignatureData",
            "cbsdCategory= 'A', removing optional param from cpi_schema",
            "cpiSignatureData data successfully validated against jsonschema ",
            "Signed CPI identity differs from registration: fccId",
            "Signed CPI identity differs from registration: cbsdSerialNumber",
            "ERROR: cpiSignatureData and installationParam exist in same registration message ",
        }
        if not isinstance(message, str) or message not in safe_messages:
            if (isinstance(message, str) and re.fullmatch(
                    r"cpiSignature decoded json schema rejected at "
                    r"\$(?:\.[A-Za-z][A-Za-z0-9_]*|\[\d+\])* \([A-Za-z]+\)"
                    r"(?:; missing required properties: [A-Za-z0-9_, ]+)?", message)):
                pass
            elif isinstance(message, str) and message.startswith("cpiSignatureData signature error"):
                message = "cpiSignatureData signature error (details suppressed)"
            else:
                message = "Original scenario validation event (details suppressed)"
        (LOG.warning if important else LOG.info)("%s", message)


class ScenarioError(RuntimeError):
    pass


def valid_now(certificate, now):
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise CredentialError("LAB certificate is expired or not yet valid")


def read_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def write_xml(path, values, registration=False):
    root = ET.Element("cbrsParams")
    parent = ET.SubElement(root, "registrationParams") if registration else root
    for name, value in values.items():
        ET.SubElement(parent, name).text = value
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def create_app(device_path=None, cpi_cert_path=None, profile=None, lab_policy_path=None, clock=None,
               state_directory=None, state_version=None, operator_control=None,
               credential_clock=None):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    profile = profile or os.environ.get("SAS_PROFILE", DEFAULT_PROFILE)
    if profile not in PROFILES:
        raise ValueError("Unknown SAS_PROFILE; no fallback profile is permitted")
    credential_clock = credential_clock or Clock()
    policy = None
    policy_digest = None
    state_version = str(state_version or os.environ.get("SAS_STATE_VERSION", "1"))
    if state_version not in ("1", "2"):
        raise ValueError("SAS_STATE_VERSION must be 1 or 2; migration is explicit")
    control_setting = (str(operator_control).lower() if operator_control is not None else
                       os.environ.get("SAS_OPERATOR_CONTROL_ENABLED", "false"))
    if control_setting not in ("true", "false"):
        raise ValueError("SAS_OPERATOR_CONTROL_ENABLED must be true or false")
    control_enabled = control_setting == "true"
    if control_enabled and (profile != POSITIVE_PROFILE or state_version != "2"):
        raise ValueError("Operator control requires lab-positive and explicitly migrated state version 2")
    if profile == POSITIVE_PROFILE:
        if os.environ.get("SAS_REQUIRE_CLIENT_CERT", "true") != "true":
            raise ValueError("lab-positive requires mTLS; no no-client-certificate mode")
        policy, policy_digest = read_policy(
            lab_policy_path or os.environ.get("SAS_LAB_POLICY", "/lab-policy.json"))
    device = read_json(device_path or os.environ.get("SAS_DEVICE_CONFIG", "/config/device.json"))
    jsonschema.validate(device, DEVICE_SCHEMA)
    if policy and (device["cbsdCategory"] != "A" or device["radioTechnology"] != "NR"):
        raise ValueError("This lab-positive policy supports the verified Category A NR device only")
    cpi_cert = Path(cpi_cert_path or os.environ.get("SAS_CPI_CERT", "/credentials/cpi-cert.pem")).resolve()
    cpi_bytes = cpi_cert.read_bytes()
    cpi_certificate = load_pem_x509_certificate(cpi_bytes)
    valid_now(cpi_certificate, credential_clock.now())

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
    workspace = tempfile.TemporaryDirectory(prefix="mock-sas-lab-")
    app.extensions["lab_workspace"] = workspace
    directory = Path(workspace.name)
    for folder in ("Configuration", "jsonExpectedFolder"):
        shutil.copytree(SOURCE / folder, directory / folder)

    scenario_path = directory / "jsonExpectedFolder" / SCENARIO
    scenario = read_json(scenario_path)
    scenario["registrationRequest"][0]["airInterface"]["radioTechnology"]["$or"].append("NR")
    # Measurement capability is optional; validate present values with the original schema.
    del scenario["registrationRequest"][0]["measCapability"]
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")
    write_xml(directory / "Configuration" / "CBSDconfig" / "cbsdc1.xml", {
        name: device[name] for name in ("cbsdSerialNumber", "fccId", "cbsdCategory")
    }, registration=True)

    optional_path = directory / "Configuration" / "ObjectListConfig" / "laterDefindedOptional.json"
    optional = read_json(optional_path)
    optional["properties"]["airInterface"]["properties"]["radioTechnology"]["enum"].append("NR")
    optional_path.write_text(json.dumps(optional), encoding="utf-8")
    write_xml(directory / "Configuration" / "conf.xml", {
        "jsonsRepoPath": "jsonExpectedFolder",
        "heartbeatLimit": "30",
        "cpiCert": str(cpi_cert),
    })
    configuration = minidom.parse(str(directory / "Configuration" / "conf.xml"))

    schema = read_json(directory / "jsonExpectedFolder" / "OptionalParams" /
                       "registrationOptional.json")["registrationOptionalParams"][0]
    schema["properties"].update(optional["properties"])
    schema["required"] = [
        "userId", "fccId", "cbsdSerialNumber", "cbsdCategory",
        "airInterface", "cpiSignatureData",
    ]
    schema["additionalProperties"] = False
    for name in ("userId", "fccId", "cbsdSerialNumber"):
        schema["properties"][name]["minLength"] = 1
    for name in ("fccId", "cbsdSerialNumber", "cbsdCategory"):
        schema["properties"][name]["enum"] = [device[name]]
    schema["properties"]["airInterface"]["properties"]["radioTechnology"]["enum"] = [device["radioTechnology"]]
    jsonschema.Draft4Validator.check_schema(schema)
    validator = jsonschema.Draft4Validator(schema)
    store = None
    try:
        if policy:
            bindings = {
                "device": hashlib.sha256(json.dumps(device, sort_keys=True).encode()).hexdigest(),
                "policy": policy_digest, "cpiCertificate": hashlib.sha256(cpi_cert.read_bytes()).hexdigest(),
                "profile": profile,
            }
            store = StateStore(state_directory or os.environ.get("SAS_STATE_DIRECTORY", "/state"),
                               bindings, version=int(state_version))
        authorization_limit = cpi_certificate.not_valid_after_utc
        session = LabSession(directory, policy, clock, store, authorization_limit) if policy else None
    except BaseException:
        if store:
            store.close()
        workspace.cleanup()
        raise
    app.extensions["lab_session"] = session
    app.extensions["lab_store"] = store
    control = ControlServer(session) if control_enabled else None
    app.extensions["lab_control"] = control

    @app.before_request
    def authenticate():
        now = credential_clock.now()
        try:
            current_cpi = cpi_cert.read_bytes()
        except OSError:
            raise CredentialError("Pinned CPI certificate unavailable; no fallback") from None
        if current_cpi != cpi_bytes:
            raise CredentialError("Pinned CPI certificate changed; explicit maintenance required")
        valid_now(cpi_certificate, now)
        g.credential_limit = cpi_certificate.not_valid_after_utc
        peer_socket = request.environ.get("gunicorn.socket")
        if peer_socket:
            data = peer_socket.getpeercert(binary_form=True)
            if data:
                peer = load_der_x509_certificate(data)
                valid_now(peer, now)
                g.credential_limit = min(g.credential_limit, peer.not_valid_after_utc)

    def register(registration):
        def rejected(code, fields, message):
            result = {"response": {"responseCode": code, "responseMessage": message}}
            if fields:
                result["response"]["responseData"] = fields
            return result

        if not finite_json(registration):
            LOG.warning("Registration schema rejected at $ (nonfinite number)")
            fields = ([name for name, value in registration.items() if not finite_json(value)]
                      if isinstance(registration, dict) else [])
            return rejected(103, fields, "LAB registration schema rejected")
        try:
            validator.validate(registration)
        except jsonschema.ValidationError as error:
            log_validation(error, "Registration schema")
            code, fields = parameter_faults(
                validator, registration, ("userId", "fccId", "cbsdSerialNumber"))
            return rejected(code, fields, "LAB registration schema rejected")

        # A new scenario instance for every attempt: no after-test canned success.
        handler = CBRSRequestHandler(
            device["cbsdSerialNumber"],
            SimpleNamespace(jsonNamesOfSteps=[[SCENARIO]]),
            configuration, directory, LabLogger(),
        )
        try:
            response = handler.handle_Http_Req(
                registration, "registration",
                datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
            )
        except OSError:
            if not handler.validationErrorAccuredInEngine or not handler.validationErrorFields:
                raise ScenarioError("Original registration verifier unavailable; details suppressed") from None
            LOG.warning("Registration/CPI rejected after original scenario/CPI validation")
            return rejected(103, handler.validationErrorFields, "LAB registration/CPI rejected")
        result = response["registrationResponse"][0]
        if result["response"]["responseCode"] != 0 or not result.get("cbsdId"):
            raise RuntimeError("Original registration success scenario did not return a valid success")
        if session:
            session.authorization_limit = g.credential_limit
            session.registered(result["cbsdId"], handler.verifiedEirpCapability)
        LOG.info("Registration accepted after scenario, CPI signature, schema and identity checks")
        return result

    @app.get("/healthz")
    def health():
        body = {"status": "ready", "profile": profile, "protocol": "v1.2",
                "cpiCertificateExpires": cpi_certificate.not_valid_after_utc.isoformat()}
        if policy:
            session._available()
            if control and not control.running:
                return jsonify(error="LAB operator worker not ready"), 503
            body.update(labOnly=True, policySha256=policy_digest, statePersistence="atomic-json",
                        stateVersion=store.version, operatorControlEnabled=control_enabled)
        return jsonify(body)

    @app.errorhandler(StateStoreError)
    def state_failure(error):
        LOG.error("LAB durable state unavailable; no successful response")
        return jsonify(error="LAB durable state unavailable"), 503

    @app.errorhandler(CredentialError)
    def credential_failure(error):
        LOG.error("LAB credential authorization unavailable: %s", error)
        return jsonify(error="LAB credential authorization unavailable"), 503

    @app.errorhandler(ScenarioError)
    def scenario_failure(error):
        LOG.error("Original registration verifier unavailable; no successful response")
        return jsonify(error="LAB registration verifier unavailable"), 503

    def envelope(operation):
        body = request.get_json()
        name = operation + "Request"
        if (not isinstance(body, dict) or set(body) != {name} or
                not isinstance(body[name], list) or not 1 <= len(body[name]) <= 16):
            LOG.warning("Invalid %s envelope", name)
            return None
        return body[name]

    for error_type in (BadRequest, UnsupportedMediaType, RequestEntityTooLarge):
        app.register_error_handler(
            error_type, lambda error: (jsonify(error="Invalid LAB JSON request"), error.code))

    # Some radios concatenate a trailing-slash base URL with "/registration".
    @app.post("/v1.2//registration", strict_slashes=False, merge_slashes=False)
    @app.post("/v1.2/registration", strict_slashes=False)
    def registration():
        registrations = envelope("registration")
        if registrations is None:
            return jsonify(error="Expected registrationRequest array with 1-16 entries"), 400
        if session:
            with session.lock:
                return jsonify(registrationResponse=[register(item) for item in registrations])
        return jsonify(registrationResponse=[register(item) for item in registrations])

    @app.post("/v1.2//<operation>", strict_slashes=False, merge_slashes=False)
    @app.post("/v1.2/<operation>", strict_slashes=False)
    def unsupported(operation):
        if session and operation in REQUIRED:
            entries = envelope(operation)
            if entries is None:
                return jsonify(error=f"Expected {operation}Request array with 1-16 entries"), 400
            with session.lock:
                session.authorization_limit = g.credential_limit
                return jsonify({operation + "Response": [session.handle(operation, entry) for entry in entries]})
        if session:
            LOG.warning("Unsupported operation in lab-positive profile")
            return jsonify(error="Unsupported LAB simulation operation"), 404
        LOG.warning("Unsupported operation in registration-only profile: %s",
                    operation if operation in REQUIRED else "unknown")
        return jsonify(error="LAB profile supports registration/CPI only; no grants or heartbeats"), 404

    LOG.info("LAB profile active: %s; policy SHA256: %s", profile, policy_digest or "none")
    if store:
        LOG.info("LAB state persistence active: atomic-json")
    LOG.info("LAB settings active: stateVersion=%s; operatorControlEnabled=%s",
             state_version, str(control_enabled).lower())
    return app

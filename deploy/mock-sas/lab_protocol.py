"""Bounded, opt-in LAB lifecycle using the original Mock SAS schemas/templates."""

from copy import deepcopy
from dataclasses import dataclass
import datetime
import hashlib
import json
import logging
import math
from pathlib import Path
import threading
import time
import uuid

import jsonschema
from lab_state import StateStoreError, utc_time

LOG = logging.getLogger("mock_sas_lab")
DEFAULT_PROFILE = "registration-cpi-only"
POSITIVE_PROFILE = "lab-positive"
PROFILES = (DEFAULT_PROFILE, POSITIVE_PROFILE)
BANDWIDTHS = (10, 20, 30, 40, 60, 80, 100)
POLICY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "labOnlyAcknowledged", "rfContainmentAcknowledged", "band",
        "channelType", "frequencyRange", "allowedBandwidthsMHz",
        "maxEirpDbmMHz", "heartbeatInterval", "grantDurationSeconds",
        "transmitLifetimeSeconds",
    ],
    "properties": {
        "labOnlyAcknowledged": {"type": "boolean", "enum": [True]},
        "rfContainmentAcknowledged": {"type": "boolean", "enum": [True]},
        "band": {"enum": ["N48"]},
        "channelType": {"enum": ["GAA"]},
        "frequencyRange": {
            "type": "object", "additionalProperties": False,
            "required": ["lowFrequency", "highFrequency"],
            "properties": {
                name: {"type": "integer", "minimum": 3550000000, "maximum": 3700000000}
                for name in ("lowFrequency", "highFrequency")
            },
        },
        "allowedBandwidthsMHz": {
            "type": "array", "minItems": 1, "uniqueItems": True,
            "items": {"type": "integer", "enum": list(BANDWIDTHS)},
        },
        "maxEirpDbmMHz": {"type": "number", "minimum": -137, "maximum": 16},
        "heartbeatInterval": {"enum": [60]},
        "grantDurationSeconds": {"enum": [600]},
        "transmitLifetimeSeconds": {"enum": [180]},
    },
}
REQUIRED = {
    "spectrumInquiry": ["cbsdId", "inquiredSpectrum"],
    "grant": ["cbsdId", "operationParam"],
    "heartbeat": ["cbsdId", "grantId", "operationState"],
    "relinquishment": ["cbsdId", "grantId"],
    "deregistration": ["cbsdId"],
}
TEMPLATES = {
    "spectrumInquiry": "HBT_spectrumInquiry_Cbsd.json",
    "grant": "HBT_grant_Cbsd.json",
    "heartbeat": "HBT_heartbeat_GrantedState.json",
    "relinquishment": "RLQ_relinquish_success.json",
    "deregistration": "DRG_Success.json",
}


def finite_json(value):
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, float) and not math.isfinite(item):
            return False
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return True


def log_validation(error, label):
    if error.validator == "required" and isinstance(error.instance, dict):
        missing = [name for name in error.validator_value if name not in error.instance]
        LOG.warning("%s rejected at %s (%s); missing required properties: %s",
                    label, error.json_path, error.validator, ", ".join(missing))
    else:
        LOG.warning("%s rejected at %s (%s)", label, error.json_path, error.validator)


def parameter_faults(validator, value, normative_required):
    if isinstance(value, dict):
        missing = [name for name in normative_required if name not in value]
        if missing:
            return 102, missing
    errors = list(validator.iter_errors(value))
    fields = set()
    for error in errors:
        if error.path:
            fields.add(str(error.path[0]))
        elif error.validator == "required" and isinstance(error.instance, dict):
            fields.update(name for name in error.validator_value if name not in error.instance)
        elif error.validator == "additionalProperties" and isinstance(error.instance, dict):
            fields.update(name for name in error.instance if name not in error.schema["properties"])
    return 103, sorted(fields)


def read_policy(path):
    data = Path(path).read_bytes()
    policy = json.loads(data)
    error = next(jsonschema.Draft4Validator(POLICY_SCHEMA).iter_errors(policy), None)
    if error is not None:
        raise ValueError(f"Invalid LAB policy at {error.json_path} ({error.validator})")
    frequencies = policy["frequencyRange"]
    if (not finite_json(policy) or
            frequencies["lowFrequency"] >= frequencies["highFrequency"] or
            min(policy["allowedBandwidthsMHz"]) * 1000000 >
            frequencies["highFrequency"] - frequencies["lowFrequency"]):
        raise ValueError("LAB policy has nonfinite values or no usable frequency range")
    return policy, hashlib.sha256(data).hexdigest()


class Clock:
    def now(self):
        return datetime.datetime.now(datetime.timezone.utc)

    def monotonic(self):
        return time.monotonic()


def timestamp(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Grant:
    parameters: dict
    expires: datetime.datetime
    deadline: float
    transmit_expires: datetime.datetime | None = None
    transmit_deadline: float | None = None
    status: str = "ACTIVE"


class CredentialError(RuntimeError):
    pass


class LabSession:
    def __init__(self, directory, policy, clock=None, store=None, authorization_limit=None):
        self.policy = policy
        self.clock = clock or Clock()
        self.lock = threading.RLock()
        self.cbsd_id = None
        self.grants = {}
        self.max_eirp = policy["maxEirpDbmMHz"]
        self.last_time = None
        self.last_tick = None
        self.validators = {}
        self.templates = {}
        self.store = store
        self.faulted = False
        self.generation = None
        self.forced_reset = None
        self.applied_commands = []
        self.authorization_limit = authorization_limit
        for operation, required in REQUIRED.items():
            with open(directory / "jsonExpectedFolder" / "OptionalParams" /
                      f"{operation}Optional.json", encoding="utf-8") as stream:
                schema = json.load(stream)[f"{operation}OptionalParams"][0]
            schema["required"] = required
            schema["additionalProperties"] = False
            for name in ("cbsdId", "grantId"):
                if name in schema["properties"]:
                    schema["properties"][name].update(minLength=1, maxLength=128)
            if operation == "spectrumInquiry":
                ranges = schema["properties"]["inquiredSpectrum"]
                ranges["minItems"] = 1
                ranges["items"]["additionalProperties"] = False
                # The public FrequencyRange schema permits inquiries beyond the LAB policy.
                for descriptor in ranges["items"]["properties"].values():
                    descriptor["minimum"] = 0
                    descriptor.pop("maximum", None)
            if operation == "grant":
                schema["operationParam"]["additionalProperties"] = False
                schema["operationParam"]["properties"]["operationFrequencyRange"]["additionalProperties"] = False
            jsonschema.Draft4Validator.check_schema(schema)
            self.validators[operation] = jsonschema.Draft4Validator(schema)
            with open(directory / "jsonExpectedFolder" / TEMPLATES[operation],
                      encoding="utf-8") as stream:
                self.templates[operation] = json.load(stream)["response"][f"{operation}Response"][0]
        if self.store:
            snapshot = self.store.load()
            now, tick = self._time()
            if snapshot is not None:
                self._restore(snapshot, now, tick)
            self._commit(now, tick)

    def _restore(self, snapshot, now, tick):
        saved = utc_time(snapshot["savedAt"])
        if now < saved:
            raise StateStoreError("LAB clock predates durable state; restart refused")
        if snapshot["maxEirp"] > self.policy["maxEirpDbmMHz"]:
            raise StateStoreError("LAB state exceeds approved power policy")
        if snapshot["cbsdId"] is None and (snapshot["grants"] or
                                           snapshot["maxEirp"] != self.policy["maxEirpDbmMHz"]):
            raise StateStoreError("Unregistered LAB state contains grants/capability")
        self.cbsd_id = snapshot["cbsdId"]
        self.max_eirp = snapshot["maxEirp"]
        elapsed = (now - saved).total_seconds()
        if snapshot["version"] == 2:
            self.generation = snapshot["generation"]
            if bool(self.generation) != bool(self.cbsd_id):
                raise StateStoreError("LAB state session generation invalid")
            reset = snapshot["forcedReset"]
            if reset:
                expiry = utc_time(reset["expires"])
                if self.cbsd_id or not 0 < (expiry - saved).total_seconds() <= self.policy["grantDurationSeconds"]:
                    raise StateStoreError("LAB reset marker violates session/deadline")
                if any(utc_time(value) > expiry for value in reset["grantExpiries"].values()):
                    raise StateStoreError("LAB reset grant deadline exceeds original retention")
                if now < expiry:
                    self.forced_reset = deepcopy(reset)
            self.applied_commands = [
                deepcopy(item) for item in snapshot["appliedCommands"] if now < utc_time(item["expires"])]
            if len({item["commandId"] for item in snapshot["appliedCommands"]}) != len(snapshot["appliedCommands"]):
                raise StateStoreError("LAB duplicate command retention invalid")
            if any(not 0 < (utc_time(item["expires"]) - saved).total_seconds() <=
                   self.policy["grantDurationSeconds"] for item in snapshot["appliedCommands"]):
                raise StateStoreError("LAB command retention invalid")
        occupied = []
        for identifier, record in snapshot["grants"].items():
            expires = utc_time(record["grantExpireTime"])
            frequencies = record["operationParam"]["operationFrequencyRange"]
            low, high = frequencies["lowFrequency"], frequencies["highFrequency"]
            policy_range = self.policy["frequencyRange"]
            remaining = record["grantRemainingSeconds"]
            status = record.get("status", "ACTIVE")
            if (not policy_range["lowFrequency"] <= low < high <= policy_range["highFrequency"] or
                    high - low not in [width * 1000000 for width in self.policy["allowedBandwidthsMHz"]] or
                    record["operationParam"]["maxEirp"] > self.max_eirp or
                    not 0 < (expires - saved).total_seconds() <= self.policy["grantDurationSeconds"] or
                    remaining > (expires - saved).total_seconds() or
                    (status != "TERMINATED" and
                     any(low < other_high and high > other_low for other_low, other_high in occupied))):
                raise StateStoreError("LAB grant snapshot violates policy/deadlines/ownership")
            if status != "TERMINATED":
                occupied.append((low, high))
            tx_time, tx_remaining = record["transmitExpireTime"], record["transmitRemainingSeconds"]
            if (tx_time is None) != (tx_remaining is None):
                raise StateStoreError("LAB transmit snapshot is incomplete")
            tx_expires = utc_time(tx_time) if tx_time else None
            if status != "ACTIVE" and tx_expires is not None:
                raise StateStoreError("Inactive LAB grant retains transmission permission")
            if tx_expires is not None and (
                    not 0 < (tx_expires - saved).total_seconds() <= self.policy["transmitLifetimeSeconds"] or
                    tx_expires > expires or tx_remaining > remaining or
                    tx_remaining > (tx_expires - saved).total_seconds()):
                raise StateStoreError("LAB transmit snapshot violates original deadlines")
            # Legacy internal fractions cannot exceed the whole-second deadline advertised to the CBSD.
            expires = expires.replace(microsecond=0)
            lifetime = min((expires - now).total_seconds(), remaining - elapsed)
            if lifetime <= 0:
                continue
            grant = Grant(deepcopy(record["operationParam"]), expires, tick + lifetime)
            grant.status = status
            if tx_expires is not None:
                tx_expires = tx_expires.replace(microsecond=0)
                if self.authorization_limit is not None:
                    tx_expires = min(tx_expires, self.authorization_limit.replace(microsecond=0))
                tx_lifetime = min((tx_expires - now).total_seconds(), tx_remaining - elapsed, lifetime)
                if tx_lifetime > 0:
                    grant.transmit_expires = tx_expires
                    grant.transmit_deadline = tick + tx_lifetime
            self.grants[identifier] = grant
        LOG.info("LAB durable state restored; only original unexpired deadlines retained")

    def _commit(self, now, tick):
        if not self.store:
            return
        records = {}
        for identifier, grant in self.grants.items():
            if not self._retained(grant, now, tick):
                continue
            authorized = self._authorized(grant, now, tick)
            records[identifier] = {
                "operationParam": grant.parameters, "grantExpireTime": grant.expires.isoformat(),
                "grantRemainingSeconds": min(grant.deadline - tick, (grant.expires - now).total_seconds()),
                "transmitExpireTime": grant.transmit_expires.isoformat() if authorized else None,
                "transmitRemainingSeconds": min(
                    grant.transmit_deadline - tick, (grant.transmit_expires - now).total_seconds()
                ) if authorized else None,
            }
            if self.store.version == 2:
                records[identifier]["status"] = grant.status
        snapshot = {
            "version": self.store.version, "bindings": self.store.bindings, "savedAt": now.isoformat(),
            "cbsdId": self.cbsd_id, "maxEirp": self.max_eirp, "grants": records,
        }
        if self.store.version == 2:
            self._prune_commands(now)
            snapshot.update(generation=self.generation,
                            forcedReset=self.forced_reset, appliedCommands=self.applied_commands)
        try:
            self.store.save(snapshot)
        except (OSError, StateStoreError):
            self.faulted = True
            self.cbsd_id = None
            self.grants.clear()
            self.max_eirp = self.policy["maxEirpDbmMHz"]
            LOG.error("LAB state persistence failed; session unavailable until restart")
            raise StateStoreError("LAB state persistence unavailable; no successful response") from None

    def _available(self):
        if self.faulted:
            raise StateStoreError("LAB state persistence unavailable; restart required")

    def _time(self):
        now, tick = self.clock.now(), self.clock.monotonic()
        if self.authorization_limit is not None and now >= self.authorization_limit.replace(microsecond=0):
            raise CredentialError("LAB credential authorization deadline elapsed")
        if ((self.last_time is not None and now < self.last_time) or
                (self.last_tick is not None and tick < self.last_tick)):
            self.cbsd_id = None
            self.grants.clear()
            LOG.error("LAB clock moved backwards; registration and grants invalidated")
            self.max_eirp = self.policy["maxEirpDbmMHz"]
            if self.store:
                self.faulted = True
                raise StateStoreError("LAB clock moved backwards; restart/review required")
        self.last_time, self.last_tick = now, tick
        return now, tick

    def registered(self, cbsd_id, signed_eirp_capability=None):
        with self.lock:
            self._available()
            now, tick = self._time()
            self.cbsd_id = cbsd_id
            self.generation = uuid.uuid4().hex
            self.forced_reset = None
            self.applied_commands.clear()
            self.grants.clear()
            self.max_eirp = self.policy["maxEirpDbmMHz"]
            if signed_eirp_capability is not None:
                self.max_eirp = min(self.max_eirp, signed_eirp_capability - 10)
            self._commit(now, tick)
            LOG.info("LAB state: REGISTERED; previous grants invalidated")

    def _response(self, operation, request, code=0, fields=None):
        response = deepcopy(self.templates[operation]) if code == 0 else {}
        response.pop("availableChannel", None)
        response["response"] = {
            "responseCode": code,
            "responseMessage": "LAB simulation only; no real spectrum authority",
        }
        if fields:
            response["response"]["responseData"] = fields
        now, tick = self.clock.now(), self.clock.monotonic()
        grant = None
        if isinstance(request, dict) and self.cbsd_id and request.get("cbsdId") == self.cbsd_id:
            response["cbsdId"] = self.cbsd_id
            if operation in ("heartbeat", "relinquishment") and isinstance(request.get("grantId"), str):
                grant = self.grants.get(request["grantId"])
                if grant is not None and self._active(grant, now, tick):
                    response["grantId"] = request["grantId"]
        if operation == "heartbeat":
            expires = grant.expires if grant else None
            if expires is None and self.forced_reset and isinstance(request, dict):
                previous = self.forced_reset["grantExpiries"].get(request.get("grantId"))
                expires = utc_time(previous) if previous else None
            response["transmitExpireTime"] = timestamp(min(now, expires) if expires else now)
        return response

    @staticmethod
    def _active(grant, now, tick):
        return grant.status != "TERMINATED" and LabSession._retained(grant, now, tick)

    @staticmethod
    def _retained(grant, now, tick):
        return now < grant.expires and tick < grant.deadline

    @staticmethod
    def _authorized(grant, now, tick):
        return (grant.status == "ACTIVE" and grant.transmit_expires is not None and
                now < grant.transmit_expires and tick < grant.transmit_deadline)

    def handle(self, operation, request):
        with self.lock:
            self._available()
            now, tick = self._time()
            response = self._handle(operation, request, now, tick)
            self._commit(now, tick)
            code = response["response"]["responseCode"]
            LOG.log(logging.INFO if code == 0 else logging.WARNING,
                    "LAB %s responseCode=%s", operation, code)
            if code == 0:
                state = {
                    "grant": "GRANTED (not yet AUTHORIZED)",
                    "heartbeat": "AUTHORIZED (simulated)",
                    "deregistration": "UNREGISTERED; all grants invalidated",
                }.get(operation)
                if state:
                    LOG.info("LAB state: %s", state)
                elif operation == "relinquishment":
                    LOG.info("LAB grant relinquished")
            return response

    def _handle(self, operation, request, now, tick):
        if not finite_json(request):
            LOG.warning("LAB %s rejected at $ (nonfinite number)", operation)
            fields = ([name for name, value in request.items() if not finite_json(value)]
                      if isinstance(request, dict) else None)
            return self._response(operation, request, 103, fields)
        error = next(self.validators[operation].iter_errors(request), None)
        if error is not None:
            log_validation(error, f"LAB {operation} schema")
            fields = ([name for name in error.validator_value if name not in error.instance]
                      if error.validator == "required" and isinstance(error.instance, dict)
                      else None)
            code = 102 if fields else 103
            if not fields and error.path:
                fields = [str(error.path[0])]
            elif error.validator == "additionalProperties" and isinstance(error.instance, dict):
                fields = [name for name in error.instance if name not in error.schema["properties"]]
            return self._response(operation, request, code, fields)
        if not self.cbsd_id or request["cbsdId"] != self.cbsd_id:
            self._prune_commands(now)
            if self.forced_reset and request["cbsdId"] == self.forced_reset["cbsdId"]:
                return self._response(operation, request, 105)
            return self._response(operation, request, 103, ["cbsdId"])
        if operation == "spectrumInquiry":
            return self._inquiry(request)
        if operation == "grant":
            return self._grant(request, now, tick)
        if operation == "deregistration":
            response = self._response(operation, request)
            self.cbsd_id = None
            self.generation = None
            self.grants.clear()
            self.max_eirp = self.policy["maxEirpDbmMHz"]
            return response
        grant = self.grants.get(request["grantId"])
        if grant is None:
            return self._response(operation, request, 103, ["grantId"])
        if operation == "relinquishment":
            if not self._active(grant, now, tick):
                return self._response(operation, request, 103, ["grantId"])
            response = self._response(operation, request)
            del self.grants[request["grantId"]]
            return response
        if not self._active(grant, now, tick):
            return self._response(operation, request, 500)
        if grant.status == "SUSPENDED":
            response = self._response(operation, request, 501)
            if request.get("grantRenew", False):
                response["grantExpireTime"] = timestamp(grant.expires)
            return response
        if (request["operationState"] == "AUTHORIZED" and
                not self._authorized(grant, now, tick)):
            return self._response(operation, request, 502)
        if request.get("grantRenew", False):
            grant.expires = (
                now + datetime.timedelta(seconds=self.policy["grantDurationSeconds"])
            ).replace(microsecond=0)
            if self.authorization_limit is not None:
                grant.expires = min(grant.expires, self.authorization_limit.replace(microsecond=0))
            grant.deadline = tick + (grant.expires - now).total_seconds()
        grant.transmit_expires = min(
            grant.expires,
            (now + datetime.timedelta(seconds=self.policy["transmitLifetimeSeconds"])).replace(microsecond=0),
        )
        if self.authorization_limit is not None:
            grant.transmit_expires = min(grant.transmit_expires, self.authorization_limit.replace(microsecond=0))
        grant.transmit_deadline = min(
            grant.deadline, tick + (grant.transmit_expires - now).total_seconds(),
        )
        response = self._response(operation, request)
        response["transmitExpireTime"] = timestamp(grant.transmit_expires)
        if request.get("grantRenew", False):
            response["grantExpireTime"] = timestamp(grant.expires)
        return response

    def _inquiry(self, request):
        policy_range = self.policy["frequencyRange"]
        channels = []
        ranges = request["inquiredSpectrum"]
        if any(item["lowFrequency"] >= item["highFrequency"] for item in ranges):
            return self._response("spectrumInquiry", request, 103, ["inquiredSpectrum"])
        if any(item["lowFrequency"] < 3550000000 or item["highFrequency"] > 3700000000
               for item in ranges):
            return self._response("spectrumInquiry", request, 300)
        for frequency_range in request["inquiredSpectrum"]:
            low = max(policy_range["lowFrequency"], frequency_range["lowFrequency"])
            high = min(policy_range["highFrequency"], frequency_range["highFrequency"])
            if high - low >= min(self.policy["allowedBandwidthsMHz"]) * 1000000:
                channel = {
                    "frequencyRange": {"lowFrequency": low, "highFrequency": high},
                    "channelType": "GAA", "ruleApplied": "FCC_PART_96",
                    "maxEirp": self.max_eirp,
                }
                if channel not in channels:
                    channels.append(channel)
        response = self._response("spectrumInquiry", request)
        response["availableChannel"] = channels
        return response

    def _grant(self, request, now, tick):
        parameters = request["operationParam"]
        frequencies = parameters["operationFrequencyRange"]
        low, high = frequencies["lowFrequency"], frequencies["highFrequency"]
        policy_range = self.policy["frequencyRange"]
        if (not policy_range["lowFrequency"] <= low < high <= policy_range["highFrequency"] or
                high - low not in [value * 1000000 for value in self.policy["allowedBandwidthsMHz"]]):
            LOG.warning("LAB grant rejected at $.operationParam.operationFrequencyRange (frequency/bandwidth policy)")
            return self._response("grant", request, 103, ["operationParam"])
        if parameters["maxEirp"] > self.max_eirp:
            LOG.warning("LAB grant rejected at $.operationParam.maxEirp (EIRP ceiling)")
            return self._response("grant", request, 103, ["operationParam"])
        self.grants = {identifier: grant for identifier, grant in self.grants.items()
                       if self._retained(grant, now, tick)}
        conflicts = []
        for identifier, grant in self.grants.items():
            if not self._active(grant, now, tick):
                continue
            other = grant.parameters["operationFrequencyRange"]
            if low < other["highFrequency"] and high > other["lowFrequency"]:
                conflicts.append(identifier)
        if conflicts:
            return self._response("grant", request, 401, sorted(conflicts))
        if len(self.grants) >= 15:
            return self._response("grant", request, 400)
        identifier = uuid.uuid4().hex
        expires = (now + datetime.timedelta(seconds=self.policy["grantDurationSeconds"])).replace(microsecond=0)
        if self.authorization_limit is not None:
            expires = min(expires, self.authorization_limit.replace(microsecond=0))
        grant = Grant(deepcopy(parameters), expires, tick + (expires - now).total_seconds())
        self.grants[identifier] = grant
        response = self._response("grant", request)
        response.update(
            grantId=identifier, grantExpireTime=timestamp(grant.expires),
            heartbeatInterval=self.policy["heartbeatInterval"], channelType="GAA",
            operationParam=deepcopy(grant.parameters),
        )
        return response

    def _prune_commands(self, now):
        self.applied_commands = [item for item in self.applied_commands if now < utc_time(item["expires"])]
        if self.forced_reset and now >= utc_time(self.forced_reset["expires"]):
            self.forced_reset = None

    def control(self, command):
        from operator_control import COMMAND_VALIDATOR, ControlError

        with self.lock:
            self._available()
            if not self.store or self.store.version != 2:
                raise ControlError("Operator control requires explicitly migrated state version 2")
            if not finite_json(command) or not COMMAND_VALIDATOR.is_valid(command):
                raise ControlError("Invalid operator command schema")
            now, tick = self._time()
            self._prune_commands(now)
            if command["action"] == "status":
                return {
                    "cbsdId": self.cbsd_id, "generation": self.generation,
                    "grants": {identifier: {"status": grant.status, "grantExpireTime": timestamp(grant.expires)}
                               for identifier, grant in self.grants.items() if self._retained(grant, now, tick)},
                }
            digest = hashlib.sha256(json.dumps(command, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            for previous in self.applied_commands:
                if previous["commandId"] == command["commandId"]:
                    if digest != previous["requestSha256"]:
                        raise ControlError("Command ID already used for another request")
                    return {"status": "already-applied", "commandId": command["commandId"]}
            if command["cbsdId"] != self.cbsd_id or command["generation"] != self.generation:
                raise ControlError("Operator target/session generation is not current")
            if len(self.applied_commands) >= 16:
                raise ControlError("Operator command retention bound reached")
            action = command["action"]
            if action == "force-deregister":
                self.forced_reset = {
                    "cbsdId": self.cbsd_id, "generation": self.generation,
                    "expires": (now + datetime.timedelta(seconds=self.policy["grantDurationSeconds"])).isoformat(),
                    "grantExpiries": {identifier: grant.expires.isoformat()
                                     for identifier, grant in self.grants.items()},
                }
                self.cbsd_id = None
                self.generation = None
                self.grants.clear()
                self.max_eirp = self.policy["maxEirpDbmMHz"]
            else:
                grant = self.grants.get(command["grantId"])
                if grant is None or not self._active(grant, now, tick):
                    raise ControlError("Operator grant target is not valid")
                if action == "resume" and grant.status != "SUSPENDED":
                    raise ControlError("Only a suspended grant can resume")
                if action == "suspend" and grant.status != "ACTIVE":
                    raise ControlError("Grant is already suspended")
                grant.status = {"suspend": "SUSPENDED", "resume": "ACTIVE", "terminate": "TERMINATED"}[action]
                grant.transmit_expires = None
                grant.transmit_deadline = None
            self.applied_commands.append({
                "commandId": command["commandId"], "requestSha256": digest, "action": action,
                "expires": (now + datetime.timedelta(seconds=self.policy["grantDurationSeconds"])).isoformat(),
            })
            self._commit(now, tick)
            LOG.warning("LAB explicit operator event applied: %s", action)
            return {"status": "applied", "commandId": command["commandId"]}

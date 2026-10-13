"""Private, bounded, single-writer LAB snapshots; never recover by guessing IDs."""

import datetime
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import uuid
import re

import jsonschema

MAX_BYTES = 65536
MAX_GRANTS = 15
TIME = {"type": "string", "format": "date-time"}
SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["version", "bindings", "savedAt", "cbsdId", "maxEirp", "grants", "checksum"],
    "properties": {
        "version": {"enum": [1]},
        "checksum": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "bindings": {
            "type": "object", "additionalProperties": False,
            "required": ["device", "policy", "cpiCertificate", "profile"],
            "properties": {
                **{name: {"type": "string", "pattern": "^[a-f0-9]{64}$"}
                   for name in ("device", "policy", "cpiCertificate")},
                "profile": {"enum": ["lab-positive"]},
            },
        },
        "savedAt": TIME,
        "cbsdId": {"type": ["string", "null"], "minLength": 1, "maxLength": 128},
        "maxEirp": {"type": "number", "minimum": -137, "maximum": 16},
        "grants": {
            "type": "object", "maxProperties": MAX_GRANTS, "additionalProperties": False,
            "patternProperties": {
                "^[a-f0-9]{32}$": {
                    "type": "object", "additionalProperties": False,
                    "required": ["operationParam", "grantExpireTime", "grantRemainingSeconds",
                                 "transmitExpireTime", "transmitRemainingSeconds"],
                    "properties": {
                        "operationParam": {
                            "type": "object", "additionalProperties": False,
                            "required": ["maxEirp", "operationFrequencyRange"],
                            "properties": {
                                "maxEirp": {"type": "number", "minimum": -137, "maximum": 16},
                                "operationFrequencyRange": {
                                    "type": "object", "additionalProperties": False,
                                    "required": ["lowFrequency", "highFrequency"],
                                    "properties": {
                                        name: {"type": "number", "minimum": 3550000000,
                                               "maximum": 3700000000}
                                        for name in ("lowFrequency", "highFrequency")
                                    },
                                },
                            },
                        },
                        "grantExpireTime": TIME,
                        "grantRemainingSeconds": {"type": "number", "minimum": 0, "maximum": 600},
                        "transmitExpireTime": {"type": ["string", "null"], "format": "date-time"},
                        "transmitRemainingSeconds": {"type": ["number", "null"], "minimum": 0, "maximum": 180},
                    },
                },
            },
        },
    },
}
VALIDATOR = jsonschema.Draft4Validator(SCHEMA, format_checker=jsonschema.FormatChecker())
SCHEMA_V2 = deepcopy(SCHEMA)
SCHEMA_V2["properties"]["version"] = {"enum": [2]}
SCHEMA_V2["required"] += ["generation", "forcedReset", "appliedCommands"]
IDENTIFIER = {"type": "string", "pattern": "^[a-f0-9]{32}$"}
DIGEST = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
SCHEMA_V2["properties"].update({
    "generation": {"anyOf": [IDENTIFIER, {"type": "null"}]},
    "forcedReset": {
        "anyOf": [{"type": "null"}, {
            "type": "object", "additionalProperties": False,
            "required": ["cbsdId", "generation", "expires", "grantExpiries"],
            "properties": {
                "cbsdId": {"type": "string", "minLength": 1, "maxLength": 128},
                "generation": IDENTIFIER, "expires": TIME,
                "grantExpiries": {
                    "type": "object", "maxProperties": MAX_GRANTS, "additionalProperties": False,
                    "patternProperties": {"^[a-f0-9]{32}$": TIME},
                },
            },
        }],
    },
    "appliedCommands": {
        "type": "array", "maxItems": 16,
        "items": {
            "type": "object", "additionalProperties": False,
            "required": ["commandId", "requestSha256", "expires", "action"],
            "properties": {
                "commandId": IDENTIFIER, "requestSha256": DIGEST, "expires": TIME,
                "action": {"enum": ["suspend", "resume", "terminate", "force-deregister"]},
            },
        },
    },
})
V2_GRANT = SCHEMA_V2["properties"]["grants"]["patternProperties"]["^[a-f0-9]{32}$"]
V2_GRANT["required"].append("status")
V2_GRANT["properties"]["status"] = {"enum": ["ACTIVE", "SUSPENDED", "TERMINATED"]}
VALIDATOR_V2 = jsonschema.Draft4Validator(SCHEMA_V2, format_checker=jsonschema.FormatChecker())


class StateStoreError(RuntimeError):
    pass


def utc_time(value):
    if not isinstance(value, str):
        raise StateStoreError("LAB state requires explicit UTC timestamps")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise StateStoreError("LAB state requires valid UTC timestamps") from None
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise StateStoreError("LAB state requires explicit UTC timestamps")
    return parsed


class StateStore:
    def __init__(self, directory, bindings, version=1):
        if version not in (1, 2):
            raise StateStoreError("Unsupported LAB state version")
        self.version = version
        self.directory = Path(directory)
        self.bindings = bindings
        self.path = self.directory / "session.json"
        self.lock_fd = None
        self.watermark = None
        self._check(self.directory.stat(follow_symlinks=False), True)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            self.lock_fd = os.open(self.directory / "session.lock",
                                   os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
            self.fresh = True
            if os.name == "nt":
                os.write(self.lock_fd, b"\0")
        except FileExistsError:
            self.lock_fd = os.open(self.directory / "session.lock", os.O_RDWR | nofollow)
            self.fresh = False
        try:
            self._check(os.fstat(self.lock_fd))
            if os.name == "nt":
                import msvcrt
                os.lseek(self.lock_fd, 0, os.SEEK_SET)
                msvcrt.locking(self.lock_fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for entry in self.directory.iterdir():
                if entry.name in ("session.json", "session.lock"):
                    continue
                if re.fullmatch(r"\.backup-[a-f0-9]{64}\.json", entry.name):
                    self._check(entry.stat(follow_symlinks=False))
                    continue
                if not (entry.name.startswith(".session-") and entry.name.endswith(".tmp")):
                    raise StateStoreError("Unexpected LAB state directory content")
                self._check(entry.stat(follow_symlinks=False))
                entry.unlink()
        except (OSError, StateStoreError):
            self.close()
            raise StateStoreError("LAB state lock unavailable or unsafe") from None

    @staticmethod
    def _check(info, directory=False, owner=None):
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected_type(info.st_mode):
            raise StateStoreError("LAB state path must be a regular private directory/file")
        if os.name != "nt" and (info.st_uid != (os.geteuid() if owner is None else owner) or
                               stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)):
            raise StateStoreError("LAB state ownership/permissions are not private")

    def validate(self, snapshot):
        return validate_snapshot(snapshot, self.bindings, self.version)

    @staticmethod
    def checksum(snapshot):
        contents = {name: value for name, value in snapshot.items() if name != "checksum"}
        try:
            data = json.dumps(contents, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
        except (ValueError, TypeError):
            raise StateStoreError("LAB state contains invalid/nonfinite JSON data") from None
        return hashlib.sha256(data).hexdigest()

    def load(self):
        try:
            info = self.path.stat(follow_symlinks=False)
        except FileNotFoundError:
            if self.fresh:
                return None
            raise StateStoreError("Existing LAB state snapshot missing; no memory fallback") from None
        snapshot = read_snapshot(self.directory, self.bindings, self.version)
        self.watermark = utc_time(snapshot["savedAt"])
        return snapshot

    def save(self, snapshot):
        if self.lock_fd is None:
            raise StateStoreError("LAB state store is closed")
        self._check(self.directory.stat(follow_symlinks=False), True)
        try:
            self._check(self.path.stat(follow_symlinks=False))
        except FileNotFoundError:
            if self.watermark is not None:
                raise StateStoreError("Existing LAB state snapshot missing; no memory fallback") from None
        snapshot = {**snapshot, "checksum": self.checksum(snapshot)}
        data = self.validate(snapshot)
        observed = utc_time(snapshot["savedAt"])
        if self.watermark is not None and observed < self.watermark:
            raise StateStoreError("LAB clock predates durable state; no recovery or lease extension")
        descriptor, temporary = tempfile.mkstemp(prefix=".session-", suffix=".tmp", dir=self.directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name != "nt":
                directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            self.watermark = observed
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def close(self):
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None


def validate_snapshot(snapshot, bindings, version):
    if version not in (1, 2):
        raise StateStoreError("Unsupported LAB state version")
    validator = VALIDATOR_V2 if version == 2 else VALIDATOR
    error = next(validator.iter_errors(snapshot), None)
    if error is not None:
        raise StateStoreError("LAB state schema/version invalid")
    if snapshot["bindings"] != bindings:
        raise StateStoreError("LAB state device/profile/policy/CPI binding mismatch")
    try:
        data = json.dumps(snapshot, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    except ValueError:
        raise StateStoreError("LAB state contains nonfinite numbers") from None
    if snapshot["checksum"] != StateStore.checksum(snapshot):
        raise StateStoreError("LAB state checksum mismatch")
    if len(data) > MAX_BYTES:
        raise StateStoreError("LAB state exceeds size limit")
    return data


def read_snapshot(directory, bindings, version, owner=None):
    directory = Path(directory)
    StateStore._check(directory.stat(follow_symlinks=False), True, owner)
    path = directory / "session.json"
    info = path.stat(follow_symlinks=False)
    StateStore._check(info, owner=owner)
    if info.st_size > MAX_BYTES:
        raise StateStoreError("LAB state exceeds size limit")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        StateStore._check(os.fstat(stream.fileno()), owner=owner)
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise StateStoreError("LAB state exceeds size limit")
    try:
        snapshot = json.loads(data)
    except (ValueError, UnicodeError):
        raise StateStoreError("LAB state JSON is corrupt") from None
    validate_snapshot(snapshot, bindings, version)
    return snapshot


def private_backup(store, expected_checksum):
    original = store.path.read_bytes()
    store.validate(json.loads(original))
    if json.loads(original)["checksum"] != expected_checksum:
        raise StateStoreError("Explicit maintenance requires the expected checksum")
    backup = store.directory / (".backup-" + expected_checksum + ".json")
    try:
        descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        store._check(backup.stat(follow_symlinks=False))
        if backup.read_bytes() != original:
            raise StateStoreError("Existing maintenance backup differs")
    else:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
    return backup.name


def migrate_v1(directory, bindings, expected_checksum, dry_run=False):
    if dry_run:
        snapshot = read_snapshot(directory, bindings, 1)
        if snapshot["checksum"] != expected_checksum:
            raise StateStoreError("Explicit migration requires the expected v1 checksum")
        return ".backup-" + expected_checksum + ".json"
    store = StateStore(directory, bindings)
    try:
        snapshot = store.load()
        if snapshot is None or snapshot["checksum"] != expected_checksum:
            raise StateStoreError("Explicit migration requires the expected v1 checksum")
        backup = private_backup(store, expected_checksum)
        migrated = deepcopy(snapshot)
        migrated.update(version=2, generation=uuid.uuid4().hex if snapshot["cbsdId"] else None,
                        forcedReset=None, appliedCommands=[])
        for grant in migrated["grants"].values():
            grant["status"] = "ACTIVE"
        store.version = 2
        store.save(migrated)
        return backup
    finally:
        store.close()


def main():
    import argparse
    from lab_protocol import read_policy

    parser = argparse.ArgumentParser(description="Explicit offline state maintenance; stop the worker first")
    parser.add_argument("action", nargs="?", choices=("migrate",), default="migrate")
    parser.add_argument("--directory", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--cpi-cert", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--expected-checksum", required=True)
    args = parser.parse_args()
    try:
        device = json.loads(Path(args.device).read_bytes())
        _, policy_digest = read_policy(args.policy)
        bindings = {
            "device": hashlib.sha256(json.dumps(device, sort_keys=True).encode()).hexdigest(),
            "policy": policy_digest, "profile": "lab-positive",
            "cpiCertificate": hashlib.sha256(Path(args.cpi_cert).read_bytes()).hexdigest(),
        }
        backup = migrate_v1(args.directory, bindings, args.expected_checksum, args.dry_run)
    except (OSError, StateStoreError, ValueError):
        print("State maintenance failed; no successful transition acknowledged. Inspect private state/backup.")
        raise SystemExit(1) from None
    if args.dry_run:
        print("Dry-run validated; no files written; prospective private backup: " + backup)
    else:
        print("State maintenance complete; private backup: " + backup)


if __name__ == "__main__":
    main()

"""Explicit local-only LAB commands; the existing worker remains the sole writer."""

import argparse
import json
import logging
import os
from pathlib import Path
import socket
import stat
import struct
import threading

import jsonschema
from lab_state import StateStore, StateStoreError
from lab_protocol import CredentialError

LOG = logging.getLogger("mock_sas_lab")
SOCKET_PATH = "/tmp/mock-sas-control/control.sock"
MAX_COMMAND = 4096
COMMAND_SCHEMA = {
    "oneOf": [
        {"type": "object", "additionalProperties": False, "required": ["action"],
         "properties": {"action": {"enum": ["status"]}}},
        {
            "type": "object", "additionalProperties": False,
            "required": ["action", "commandId", "cbsdId", "generation", "grantId"],
            "properties": {
                "action": {"enum": ["suspend", "resume", "terminate"]},
                "commandId": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
                "cbsdId": {"type": "string", "minLength": 1, "maxLength": 128},
                "generation": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
                "grantId": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
            },
        },
        {
            "type": "object", "additionalProperties": False,
            "required": ["action", "commandId", "cbsdId", "generation"],
            "properties": {
                "action": {"enum": ["force-deregister"]},
                "commandId": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
                "cbsdId": {"type": "string", "minLength": 1, "maxLength": 128},
                "generation": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
            },
        },
    ],
}
COMMAND_VALIDATOR = jsonschema.Draft4Validator(COMMAND_SCHEMA)


class ControlError(RuntimeError):
    pass


class ControlServer:
    def __init__(self, session, path=SOCKET_PATH):
        self.session = session
        self.path = Path(path)
        self.listener = None
        self.thread = None
        self.inode = None
        self.stopped = threading.Event()

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive() and not self.stopped.is_set()

    def start(self):
        if os.name != "posix" or not hasattr(socket, "SO_PEERCRED"):
            raise ControlError("Operator IPC requires Linux Unix sockets with verified peer UID")
        if os.geteuid() != 10001:
            raise ControlError("Operator IPC worker must run as UID 10001")
        self.path.parent.mkdir(mode=0o700, exist_ok=True)
        StateStore._check(self.path.parent.stat(follow_symlinks=False), True)
        if self.path.exists() or self.path.is_symlink():
            info = self.path.stat(follow_symlinks=False)
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                raise ControlError("Unsafe operator socket path")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                try:
                    probe.connect(str(self.path))
                except ConnectionRefusedError:
                    self.path.unlink()
                else:
                    raise ControlError("Operator socket already active")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.path))
            self.inode = self.path.stat().st_ino
            self.path.chmod(0o600)
            listener.listen(4)
            listener.settimeout(0.5)
            self.listener = listener
            self.thread = threading.Thread(target=self._serve, args=(listener,), daemon=True)
            self.thread.start()
        except OSError:
            listener.close()
            raise
        LOG.info("LAB operator control ready: private Unix socket; explicit commands only")

    def _serve(self, listener):
        while not self.stopped.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self.stopped.is_set():
                    LOG.error("LAB operator listener failed")
                    with self.session.lock:
                        self.session.faulted = True
                return
            with connection:
                connection.settimeout(5)
                try:
                    _, uid, _ = struct.unpack("3i", connection.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                    if uid != os.geteuid():
                        raise ControlError("Operator peer UID rejected")
                    with connection.makefile("rb") as stream:
                        data = stream.readline(MAX_COMMAND + 1)
                    if len(data) > MAX_COMMAND or not data.endswith(b"\n"):
                        raise ControlError("Operator command size/framing rejected")
                    try:
                        command = json.loads(data)
                    except (ValueError, UnicodeError):
                        raise ControlError("Invalid operator JSON") from None
                    reply = self.session.control(command)
                    connection.sendall(json.dumps({"result": reply}).encode() + b"\n")
                except (ControlError, StateStoreError, CredentialError) as error:
                    LOG.warning("LAB operator command rejected: %s", error)
                    try:
                        connection.sendall(json.dumps({"error": str(error)}).encode() + b"\n")
                    except OSError:
                        LOG.warning("LAB operator error acknowledgment unavailable")
                except OSError:
                    LOG.warning("LAB operator connection/acknowledgment unavailable")

    def close(self):
        self.stopped.set()
        if self.listener:
            self.listener.close()
            self.listener = None
        if self.thread:
            self.thread.join(timeout=6)
        if self.inode is not None and self.path.exists():
            info = self.path.stat(follow_symlinks=False)
            if stat.S_ISSOCK(info.st_mode) and info.st_ino == self.inode and info.st_uid == os.geteuid():
                self.path.unlink()


def request_command(command, path=SOCKET_PATH):
    if not COMMAND_VALIDATOR.is_valid(command):
        raise ControlError("Invalid operator command schema")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(path)
        connection.sendall(json.dumps(command).encode() + b"\n")
        with connection.makefile("rb") as stream:
            data = stream.readline(16385)
    if len(data) > 16384 or not data.endswith(b"\n"):
        raise ControlError("Invalid operator acknowledgment framing")
    reply = json.loads(data)
    if "error" in reply:
        raise ControlError(reply["error"])
    if set(reply) != {"result"}:
        raise ControlError("Invalid operator acknowledgment")
    return reply["result"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["status", "suspend", "resume", "terminate", "force-deregister"])
    parser.add_argument("--cbsd-id")
    parser.add_argument("--generation")
    parser.add_argument("--grant-id")
    parser.add_argument("--command-id")
    args = parser.parse_args()
    command = {"action": args.action}
    if args.action != "status":
        if not args.command_id:
            parser.error("Explicit events require --command-id; retain it for an unacknowledged retry")
        command.update(cbsdId=args.cbsd_id, generation=args.generation,
                       commandId=args.command_id)
        if args.action != "force-deregister":
            command["grantId"] = args.grant_id
    try:
        print(json.dumps(request_command(command), sort_keys=True))
    except (ControlError, OSError, ValueError):
        LOG.error("Operator command failed; no acknowledged transition; preserve command ID for retry")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()

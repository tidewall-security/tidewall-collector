"""Pinned-origin collector enrollment, credential storage and bounded writes."""

from __future__ import annotations

import contextlib
import fcntl
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID, uuid4

# The single-request subprocess below runs this file in stdlib-only script
# mode. It needs neither the application's import path nor access to its queue.
if __name__ != "__main__":
    from . import admission
    from .reader import read_fixture
    from .state import InvalidHead, Owner, QueueState


class BackendError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


DEADLINE = 5.0
OBSERVATIONS = "/v1/collector/observations"
HEARTBEAT = "/v1/collector/heartbeat"
REGISTRATION = "/v1/devices/enrol"
CREDENTIALS = "credentials.json"
LOCK = "credential.lock"
TEMP = "credentials.next"
SUSPENDED = frozenset(
    {
        "scope_denied",
        "device_revoked",
        "credential_unknown",
        "credential_expired",
        "unauthorized",
        "row_too_large",
        "offboarding",
    }
)
RECOVERY_WARNING = "Successful recovery deletes the old device’s server-side collection history. The replacement starts empty and requires new approval."


def canonical_origin(value: str, *, fixture_loopback: bool) -> str:
    try:
        if (
            not isinstance(value, str)
            or not value.isascii()
            or len(value) > 512
            or re.search(r"[\x00-\x20\x7f\\?#@%]", value)
        ):
            raise ValueError
        u = urlsplit(value)
        if (
            u.path not in ("", "/")
            or not u.hostname
            or u.port == 0
            or u.netloc.endswith(":")
        ):
            raise ValueError
        host = u.hostname.lower()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                for part in host.split(".")
            ):
                raise ValueError from None
            if "[" in u.netloc or "]" in u.netloc:
                raise ValueError from None
        else:
            host = (
                f"[{address.compressed}]"
                if address.version == 6
                else address.compressed
            )
            if u.netloc.startswith("[") and not re.fullmatch(
                r"\[[a-fA-F0-9:]+\](?::[0-9]+)?", u.netloc
            ):
                raise ValueError
        if u.scheme != "https" and not (
            fixture_loopback and u.scheme == "http" and host in ("127.0.0.1", "[::1]")
        ):
            raise ValueError
        port = (
            "" if u.port in (None, 443 if u.scheme == "https" else 80) else f":{u.port}"
        )
        return f"{u.scheme}://{host}{port}"
    except (ValueError, AttributeError):
        raise BackendError("invalid_origin") from None


def _wire_worker() -> int:
    """One connection without proxy discovery, redirect handling or retry."""
    try:
        origin, path, token, body, limit = json.loads(sys.stdin.buffer.read(150000))
        target = urlsplit(origin)
        if target.scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                target.hostname or "",
                target.port,
                timeout=DEADLINE,
                context=ssl.create_default_context(),
            )
        else:
            conn = http.client.HTTPConnection(
                target.hostname or "", target.port, timeout=DEADLINE
            )
        with contextlib.closing(conn):
            conn.request(
                "POST",
                path,
                body.encode("ascii"),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Authorization": "Bearer " + token,
                    "Connection": "close",
                },
            )
            with conn.getresponse() as response:
                status = response.status
                # Preserve a completed refusal header even if the peer never
                # finishes its bounded refusal body before the parent deadline.
                sys.stdout.buffer.write(str(status).encode() + b"\n")
                sys.stdout.buffer.flush()
                if status == 422:
                    limit = 128
                media = response.headers.get_all("Content-Type", [])
                encoding = response.headers.get_all("Content-Encoding", [])
                lengths = response.headers.get_all("Content-Length", [])
                transfer = response.headers.get_all("Transfer-Encoding", [])
                length = None
                if lengths:
                    if (
                        len(lengths) != 1
                        or transfer
                        or not re.fullmatch(r"[0-9]{1,10}", lengths[0].strip())
                    ):
                        return 0
                    length = int(lengths[0])
                    if length > limit:
                        return 0
                if transfer and [v.strip().lower() for v in transfer] != ["chunked"]:
                    return 0
                data = b""
                if (
                    len(media) == 1
                    and re.fullmatch(
                        r'application/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?',
                        media[0].strip(),
                        re.I,
                    )
                    and (
                        not encoding
                        or len(encoding) == 1
                        and encoding[0].strip().lower() == "identity"
                    )
                ):
                    try:
                        data = response.read(limit + 1)
                    except (http.client.IncompleteRead, OSError):
                        if status != 422:
                            raise
                    if len(data) > limit or (
                        length is not None and len(data) != length
                    ):
                        data = b""
                sys.stdout.buffer.write(data)
        return 0
    except (socket.timeout, TimeoutError):
        return 2
    except (OSError, ValueError, http.client.HTTPException):
        return 1


def _post(
    origin: str, path: str, token: str, body: bytes, limit: int
) -> tuple[int, bytes]:
    # libc name resolution and HTTP header parsing may both block beyond an
    # individual socket timeout. Kill/reap the entire single-request child at
    # the wall-clock deadline. Only its private stdin carries credentials.
    deadline = time.monotonic() + DEADLINE
    request = json.dumps([origin, path, token, body.decode("ascii"), limit]).encode()
    with subprocess.Popen(
        [sys.executable, "-I", "-S", str(Path(__file__).resolve())],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={},
    ) as worker:
        try:
            output, _ = worker.communicate(
                request, timeout=max(0, deadline - time.monotonic())
            )
        except subprocess.TimeoutExpired:
            worker.kill()
            output, _ = worker.communicate()
            if output.startswith(b"422\n"):
                return 422, b""
            raise BackendError("timeout") from None
    if output.startswith(b"422\n") and (
        worker.returncode or time.monotonic() > deadline
    ):
        return 422, b""
    if worker.returncode == 2 or time.monotonic() > deadline:
        raise BackendError("timeout")
    if worker.returncode:
        raise BackendError("offline")
    status, _, payload = output.partition(b"\n")
    return int(status), payload


def _private(fd: int, *, directory: bool = False) -> os.stat_result:
    info = os.fstat(fd)
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not kind(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
        or not directory
        and info.st_nlink != 1
    ):
        raise BackendError("unsafe_state")
    return info


class _LockedState:
    def __init__(self, path: Path, root: int, lock: int):
        self.path, self.root, self.lock = path, root, lock
        info = _private(root, directory=True)
        key = _private(lock)
        self.location = [str(path), info.st_dev, info.st_ino, key.st_dev, key.st_ino]

    def check(self) -> None:
        if (
            self.path.resolve(strict=True) != self.path
            or not os.path.samestat(
                os.lstat(self.path), _private(self.root, directory=True)
            )
            or not os.path.samestat(
                os.stat(LOCK, dir_fd=self.root, follow_symlinks=False),
                _private(self.lock),
            )
        ):
            raise BackendError("unsafe_state")

    def read(self) -> dict:
        self.check()
        with os.fdopen(
            os.open(
                CREDENTIALS,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                dir_fd=self.root,
            ),
            "rb",
        ) as f:
            _private(f.fileno())
            data = admission.wire_json(f.read(8193), 8192)
        if not isinstance(data, dict) or data.get("location") != self.location:
            raise BackendError("unsafe_state")
        return data

    def discard_temp(self) -> None:
        try:
            fd = os.open(
                TEMP, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.root
            )
        except FileNotFoundError:
            return
        with os.fdopen(fd, "rb"):
            _private(fd)
            os.unlink(TEMP, dir_fd=self.root)

    def write(self, data: dict) -> None:
        self.check()
        self.discard_temp()
        data["location"] = self.location
        fd = os.open(
            TEMP,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.root,
        )
        with os.fdopen(fd, "wb") as f:
            f.write(admission.canonical(data))
            f.flush()
            os.fsync(fd)
        self.check()
        os.replace(TEMP, CREDENTIALS, src_dir_fd=self.root, dst_dir_fd=self.root)
        os.fsync(self.root)


def _secret(value: object, prefix: str = "") -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", value)
        or not value.startswith(prefix)
    ):
        raise BackendError("invalid_credential")
    return value


def _failure(status: int) -> BackendError:
    if status == 429 or 500 <= status < 600:
        return BackendError("retry_later")
    if 300 <= status < 400:
        return BackendError("redirect_refused")
    return BackendError("request_refused")


def _device_reply(body: bytes, enrol: bool) -> tuple[UUID, str, str, str]:
    try:
        message = admission.wire_json(body, 8192)
        r = message["result"]
        if (
            message["status"] != ("Success" if enrol else "ok")
            or r["device_status"] != ("pending" if enrol else "active")
            or r["config"] != {"sites": {}}
        ):
            raise ValueError
        device = UUID(r["device_id"])
        if device.version != 4 or str(device) != r["device_id"]:
            raise ValueError
        access = _secret(r["access_token"]["token"], "at_")
        refresh = _secret(r["refresh_token"]["token"], "dr_") if enrol else ""
        code = r["confirmation_code"] if enrol else ""
        if enrol and (
            not isinstance(code, str)
            or not re.fullmatch("[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}", code)
        ):
            raise ValueError
        return device, access, refresh, code
    except (AttributeError, ValueError, TypeError, KeyError):
        raise BackendError("invalid_device_reply") from None


class TidewallBackend:
    def __init__(
        self, state_root: Path | None = None, *, fixture_loopback: bool = False
    ):
        self.root = Path(state_root).absolute() if state_root is not None else None
        self.fixture_loopback = fixture_loopback
        self.confirmation_code = ""
        self.installation_id: UUID | None = None
        self._post = _post

    @contextlib.contextmanager
    def _locked(self, *, create: bool = False) -> Iterator[_LockedState]:
        path = self.root
        if path is None or ".." in path.parts or path.resolve() != path:
            raise BackendError("unsafe_state")
        try:
            if create:
                path.mkdir(mode=0o700, exist_ok=True)
            with contextlib.ExitStack() as stack:
                root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                stack.callback(os.close, root)
                _private(root, directory=True)
                flags = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_RDWR
                lock = os.open(
                    LOCK, flags | (os.O_CREAT if create else 0), 0o600, dir_fd=root
                )
                stack.callback(os.close, lock)
                _private(lock)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise BackendError("busy") from None
                state = _LockedState(path, root, lock)
                state.check()
                yield state
        except FileNotFoundError:
            raise BackendError("state_missing") from None
        except (OSError, admission.Invalid):
            raise BackendError("state_unavailable") from None

    def _bound(
        self, state: _LockedState, owner: Owner | None = None
    ) -> tuple[Owner, dict]:
        data = state.read()
        try:
            current = Owner(
                canonical_origin(
                    data["origin"], fixture_loopback=self.fixture_loopback
                ),
                UUID(data["device_id"]),
            )
            if (
                current.origin != data["origin"]
                or owner is not None
                and current != owner
            ):
                raise BackendError("owner_mismatch")
            _secret(data["access"], "at_")
            _secret(data["refresh"], "dr_")
            if data["status"] not in SUSPENDED | {"active", "device_pending"}:
                raise BackendError("unsafe_state")
        except (KeyError, TypeError, AttributeError):
            raise BackendError("unsafe_state") from None
        return current, data

    def owner(self) -> Owner:
        with self._locked() as state:
            return self._bound(state)[0]

    def enrol(self, origin: str, registration_secret: str, state_root: Path) -> Owner:
        return self._enrol(origin, uuid4(), registration_secret, None, state_root)

    def recover(
        self,
        origin: str,
        installation_id: UUID,
        registration_secret: str,
        recovery_secret: str,
        state_root: Path,
    ) -> Owner:
        if not isinstance(installation_id, UUID) or installation_id.int == 0:
            raise BackendError("invalid_installation")
        print(RECOVERY_WARNING, file=sys.stderr, flush=True)
        return self._enrol(
            origin,
            installation_id,
            registration_secret,
            _secret(recovery_secret),
            state_root,
        )

    def _enrol(
        self,
        origin: str,
        installation: UUID,
        registration: str,
        recovery: str | None,
        state_root: Path,
    ) -> Owner:
        origin = canonical_origin(origin, fixture_loopback=self.fixture_loopback)
        registration = _secret(registration, "rt_")
        root = Path(state_root).absolute()
        if self.root is not None and self.root != root:
            raise BackendError("owner_mismatch")
        self.root = root
        with self._locked(create=True) as state:
            if set(os.listdir(state.root)) != {LOCK}:
                raise BackendError("state_exists")
            request = dict(
                installation_id=str(installation),
                device_name="Tidewall fixture collector",
                user_name="",
                user_email="",
            )
            if recovery is not None:
                request["recovery_secret"] = recovery
            status, body = self._post(
                origin, REGISTRATION, registration, admission.canonical(request), 8192
            )
            if status != 201:
                raise _failure(status)
            device, access, refresh, code = _device_reply(body, True)
            owner = Owner(origin, device)
            state.write(
                dict(
                    device_id=str(device),
                    origin=origin,
                    access=access,
                    refresh=refresh,
                    installation_id=str(installation),
                    status="device_pending",
                )
            )
            with QueueState.create(root / "queue", owner):
                pass
            self.installation_id = installation
            self.confirmation_code = code
            return owner

    def _check_reply(
        self,
        state: _LockedState,
        owner: Owner,
        data: dict,
        queue: QueueState | None = None,
    ) -> None:
        try:
            if self._bound(state, owner)[1] != data:
                raise BackendError("stale_authority")
        except (OSError, ValueError):
            if queue is not None:
                queue.cancel_flight(owner)
            raise

    def _refresh(
        self, state: _LockedState, owner: Owner, data: dict, queue: QueueState
    ) -> None:
        if data["status"] in SUSPENDED:
            raise BackendError(data["status"])
        queue.cancel_flight(owner)
        status, body = self._post(
            owner.origin,
            f"/v1/devices/{owner.device_id}/refresh",
            data["refresh"],
            b"{}",
            8192,
        )
        self._check_reply(state, owner, data, queue)
        if status == 200:
            device, access, _, _ = _device_reply(body, False)
            if device != owner.device_id:
                raise BackendError("owner_mismatch")
            data.update(access=access, status="active")
            state.write(data)
            return
        if status in (401, 403, 202):
            expected = {
                202: ("device_pending",),
                403: ("device_revoked",),
                401: ("credential_unknown", "credential_expired"),
            }
            try:
                result = admission.wire_json(body, 8192)
                reason = result["reason"]
                if reason not in expected[status] or result != {
                    "status": reason,
                    "reason": reason,
                    "result": None,
                }:
                    raise ValueError
            except (TypeError, ValueError, KeyError):
                reason = "unauthorized"
            data["status"] = reason
            state.write(data)
            raise BackendError(reason)
        raise _failure(status)

    def refresh(self, owner: Owner) -> None:
        with self._locked() as state:
            _, data = self._bound(state, owner)
            with QueueState.open(state.path / "queue", owner) as queue:
                self._refresh(state, owner, data, queue)

    def _queue(self, state: _LockedState, owner: Owner, queue: QueueState) -> dict:
        _, data = self._bound(state, owner)
        if queue.owner != owner or queue.path != state.path / "queue":
            raise BackendError("owner_mismatch")
        if data["status"] in SUSPENDED:
            raise BackendError(data["status"])
        return data

    def _authorization(
        self,
        state: _LockedState,
        owner: Owner,
        data: dict,
        queue: QueueState,
        status: int,
        refreshed: bool,
    ) -> None:
        queue.cancel_flight(owner)
        if status == 401 and not refreshed:
            self._refresh(state, owner, data, queue)
            return
        reason = "scope_denied" if status == 403 else "unauthorized"
        data["status"] = reason
        state.write(data)
        raise BackendError(reason)

    def ship_once(self, owner: Owner, queue: QueueState) -> int:
        with self._locked() as state:
            data = self._queue(state, owner, queue)
            refreshed = data["status"] == "device_pending"
            if refreshed:
                self._refresh(state, owner, data, queue)
            limit = 32
            disposed = False
            while True:
                try:
                    pending = queue.next_batch(owner, limit)
                except InvalidHead as invalid:
                    if disposed:
                        return 0
                    queue.finalize_invalid_head(
                        owner, invalid.ordinal, invalid.admission_digest
                    )
                    disposed = True
                    continue
                if pending is None:
                    return 0
                status, body = self._post(
                    owner.origin,
                    OBSERVATIONS,
                    data["access"],
                    pending.body,
                    admission.MAX_BATCH,
                )
                self._check_reply(state, owner, data, queue)
                if status == 200:
                    return queue.apply_receipt(owner, pending, body)
                if status in (401, 403):
                    self._authorization(state, owner, data, queue, status, refreshed)
                    refreshed = True
                elif status == 413:
                    if len(pending.rows) == 1:
                        queue.cancel_flight(owner)
                        data["status"] = "row_too_large"
                        state.write(data)
                        raise BackendError("row_too_large")
                    limit = len(pending.rows) // 2
                elif status == 422:
                    try:
                        invalid_row = admission.wire_json(body, 128) == {
                            "code": "invalid_row"
                        }
                    except admission.Invalid:
                        invalid_row = False
                    if invalid_row and queue.invalid_rows(owner, pending):
                        # Reselect only a freshly preflighted prefix. The refusal
                        # itself can never advance a position.
                        queue.cancel_flight(owner)
                        return 0
                    queue.set_contract_mismatch(owner)
                    raise BackendError("contract_mismatch")
                else:
                    raise _failure(status)

    def send_heartbeat(self, owner: Owner, queue: QueueState) -> None:
        with self._locked() as state:
            data = self._queue(state, owner, queue)
            refreshed = data["status"] == "device_pending"
            if refreshed:
                self._refresh(state, owner, data, queue)
            while True:
                snapshot = queue.heartbeat(owner)
                status, body = self._post(
                    owner.origin,
                    HEARTBEAT,
                    data["access"],
                    admission.canonical(snapshot),
                    2048,
                )
                self._check_reply(state, owner, data, queue)
                if status in (401, 403):
                    self._authorization(state, owner, data, queue, status, refreshed)
                    refreshed = True
                    continue
                if status == 422:
                    queue.set_contract_mismatch(owner)
                    raise BackendError("contract_mismatch")
                if status != 200:
                    raise _failure(status)
                expected = dict(
                    version=1,
                    enrollment_id=str(owner.device_id),
                    revision=snapshot["revision"],
                    capture="metadata_only",
                    retain_content=False,
                )
                try:
                    if admission.canonical(
                        admission.wire_json(body, 2048)
                    ) != admission.canonical(expected) or snapshot != queue.heartbeat(
                        owner
                    ):
                        raise ValueError
                except ValueError:
                    raise BackendError("invalid_heartbeat") from None
                return

    def ingest_fixture(
        self,
        owner: Owner,
        queue: QueueState,
        directory: Path,
        independent: frozenset[str],
    ) -> None:
        with self._locked() as state:
            self._queue(state, owner, queue)
            read_fixture(directory, owner, queue, independent=independent)

    def status(self, owner: Owner, queue: QueueState) -> dict:
        with self._locked() as state:
            _, data = self._bound(state, owner)
            return dict(
                device_id=str(owner.device_id),
                installation_id=data["installation_id"],
                status=data["status"],
                heartbeat=queue.heartbeat(owner),
            )

    def resume_contract(self, owner: Owner, queue: QueueState) -> None:
        with self._locked() as state:
            _, data = self._bound(state, owner)
            if queue.path != state.path / "queue" or queue.owner != owner:
                raise BackendError("owner_mismatch")
            queue.set_contract_mismatch(owner, False)
            if data["status"] == "row_too_large":
                data["status"] = "active"
                state.write(data)

    def offboard(self, device_id: UUID) -> None:
        with self._locked() as state:
            owner, data = self._bound(state)
            if owner.device_id != device_id:
                raise BackendError("owner_mismatch")
            queue_path = state.path / "queue"
            resuming = data["status"] == "offboarding"
            if not resuming:
                data["status"] = "offboarding"
                state.write(data)
            resumed = QueueState.resume_offboard(queue_path, owner)
            if not resumed and (os.path.lexists(queue_path) or not resuming):
                with QueueState.open(queue_path, owner) as queue:
                    queue.offboard(owner)
            self._check_reply(state, owner, data)
            if set(os.listdir(state.root)) - {CREDENTIALS, LOCK, TEMP}:
                raise BackendError("unsafe_state")
            state.discard_temp()
            os.unlink(CREDENTIALS, dir_fd=state.root)
            os.fsync(state.root)


if __name__ == "__main__":
    sys.exit(_wire_worker())

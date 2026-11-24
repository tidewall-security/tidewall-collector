"""Private, enrollment-bound native configuration and metadata journal."""

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hmac
import os
from pathlib import Path
import stat
import time
from uuid import uuid4

from openaidr.sensor.collectors import native_id

from . import admission, native_contract as wire
from .projection import _token
from .state import (
    Owner,
    QueueState,
    _create_file,
    _manifest_bytes,
    _private_file,
    _read,
)
from .tidewall_backend import BackendError

CONFIG = "native-session.json"
JOURNAL = "native-journal.json"
MAX_ENTRIES = 256
# An atomic replacement may temporarily coexist with the previous journal.
MAX_JOURNAL = 512 * 1024
TTL = 7 * 86400


@dataclass(frozen=True)
class Authority:
    owner: Owner
    generation: str
    revision: str
    access: str = field(repr=False)
    grant: dict = field(repr=False)
    capture: bool
    session_token: str
    selected_session: str | None


def cwd_token(key, cwd):
    cwd = Path(cwd)
    if not cwd.is_absolute() or cwd.resolve(strict=True) != cwd:
        raise BackendError("cwd_mismatch")
    info = cwd.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o022
    ):
        raise BackendError("cwd_mismatch")
    return _token(
        key,
        "native_cwd",
        admission.canonical([str(cwd), info.st_dev, info.st_ino]).decode(),
    )


def _enrollment_key(root, owner, generation):
    queue = root / "queue"
    info = queue.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise BackendError("unsafe_state")
    key = _read(queue / "key", 32)
    location = admission.digest(
        admission.canonical([str(queue), info.st_dev, info.st_ino])
    )
    expected = _manifest_bytes(owner, generation, location, key)
    if len(key) != 32 or not hmac.compare_digest(
        _read(queue / "manifest.json", 1536), expected
    ):
        raise BackendError("owner_mismatch")
    return key


def _tag(key, binding, path, value):
    return hmac.digest(
        key,
        admission.canonical(["native-state-v1", binding, path.name, value]),
        "sha256",
    ).hex()


def _load(key, binding, path, limit, *, staged=False):
    try:
        tag, obj = admission.wire_json(
            _read(path.with_suffix(".next") if staged else path, limit), limit
        )
        if not hmac.compare_digest(_tag(key, binding, path, obj), tag):
            raise ValueError
        return obj
    except (KeyError, TypeError, ValueError, OSError):
        raise BackendError("native_state_invalid") from None


def _save(key, binding, path, value, limit, *, commit=None):
    data = admission.canonical([_tag(key, binding, path, value), value])
    if len(data) > limit:
        raise BackendError("native_capacity")
    tmp = path.with_suffix(".next")
    if os.path.lexists(tmp):
        _private_file(tmp)
        tmp.unlink()
    _create_file(tmp, data)
    if commit is not None:
        # Durable staging must precede the credential revision pointer.
        from openaidr.core.files import sync_directory

        sync_directory(path.parent)
        commit()
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class NativeState:
    def __init__(self, backend, path):
        if backend.root is None or Path(path) != backend.root / CONFIG:
            raise BackendError("config_mismatch")
        self.backend = backend
        self.path = Path(path)
        self.journal = backend.root / JOURNAL

    def _current_config(self, key, bound, data, locked):
        revision = data.get("native_revision")
        if not wire.uuid4_text(revision):
            raise BackendError("native_state_invalid")
        if os.path.lexists(self.path):
            config = _load(key, bound, self.path, 8192)
            if config["revision"] == revision:
                return config
        # A committed revision can be waiting for its final rename after a
        # crash. An older signed config by itself can never restore consent.
        config = _load(key, bound, self.path, 8192, staged=True)
        if config["revision"] != revision:
            raise BackendError("native_state_invalid")
        os.replace(self.path.with_suffix(".next"), self.path)
        os.fsync(locked.root)
        return config

    def _records(self, key, bound, config):
        records = _load(key, bound, self.journal, MAX_JOURNAL)
        if records["selection"] == config["selection"]:
            return records
        if records["selection"] != config["previous_selection"]:
            raise BackendError("native_state_invalid")
        # Finish the explicit switch even if its process died immediately
        # after publishing B. Never expose A's receipts under B.
        retired = records["rows"]
        records["lost"] = min(2**31 - 1, records["lost"] + _unreported(retired))
        records["discarded"] = min(2**31 - 1, records["discarded"] + len(retired))
        records["rows"] = []
        records.pop("selected_session", None)
        records["selection"] = config["selection"]
        _save(key, bound, self.journal, records, MAX_JOURNAL)
        return records

    @contextmanager
    def open(self, owner=None, generation=None):
        with self.backend._locked() as locked:
            actual, data = self.backend._bound(locked, owner)
            if data["status"] != "active":
                raise BackendError("native_inactive")
            current = data.get("queue_generation")
            if (
                not wire.uuid4_text(current)
                or generation is not None
                and str(generation) != current
            ):
                raise BackendError("owner_mismatch")
            key = _enrollment_key(locked.path, actual, current)
            anchor = data.get("native_state")
            if not wire.uuid4_text(anchor):
                raise BackendError("native_unprepared")
            bound = [actual.origin, str(actual.device_id), current, anchor]
            config = self._current_config(key, bound, data, locked)
            records = self._records(key, bound, config)
            session = _Session(
                self,
                locked,
                actual,
                current,
                data["access"],
                key,
                bound,
                config,
                records,
            )
            session.expire()
            yield session

    def prepare(self, session_id, cwd, version, capture, grant, *, new_session=False):
        if (
            native_id(session_id) is None
            or version != wire.VERSION
            or type(capture) is not bool
            or new_session
            and (capture or grant is not None)
        ):
            raise BackendError("invalid_session")
        if grant is not None:
            grant = wire.parse("NativeGrantIssued", wire.encode(grant))
        with self.backend._locked() as locked:
            owner, data = self.backend._bound(locked)
            if data["status"] != "active":
                raise BackendError("native_inactive")
            generation = data.get("queue_generation")
            if generation is None and "native_state" not in data:
                # Pre-generation credentials can bind only their authenticated
                # existing queue, under the same lock as enrollment setup.
                with QueueState.open(locked.path / "queue", owner) as queue:
                    generation = data["queue_generation"] = str(queue.generation)
            if not wire.uuid4_text(generation):
                raise BackendError("owner_mismatch")
            key = _enrollment_key(locked.path, owner, generation)
            token = _token(key, "session", session_id)
            directory = cwd_token(key, cwd)
            if grant and (
                grant["device_id"] != str(owner.device_id)
                or grant["session_token"] != token
                or datetime.fromisoformat(grant["expires_at"]) <= datetime.now(UTC)
            ):
                raise BackendError("grant_mismatch")
            anchor = data.get("native_state")
            initial = anchor is None
            if initial:
                if any(
                    os.path.lexists(p)
                    for p in (
                        self.path,
                        self.journal,
                        self.path.with_suffix(".next"),
                        self.journal.with_suffix(".next"),
                    )
                ):
                    raise BackendError("native_state_invalid")
                anchor = str(uuid4())
            elif not wire.uuid4_text(anchor):
                raise BackendError("native_state_invalid")
            bound = [owner.origin, str(owner.device_id), generation, anchor]
            selection = str(uuid4())
            previous_selection = None
            bootstrap_required = new_session
            if "native_revision" not in data:
                # Before the first committed config no invocation can reserve.
                # Resume only a private, authenticated empty birth journal.
                if os.path.lexists(self.path):
                    raise BackendError("native_state_invalid")
                if initial:
                    data["native_state"] = anchor
                    locked.write(data)
                if os.path.lexists(self.journal):
                    records = _load(key, bound, self.journal, MAX_JOURNAL)
                    selection = records.get("selection")
                    if not wire.uuid4_text(selection) or records != dict(
                        rows=[],
                        lost=0,
                        pressure=0,
                        expired=0,
                        discarded=0,
                        selection=selection,
                    ):
                        raise BackendError("native_state_invalid")
                else:
                    records = dict(
                        rows=[],
                        lost=0,
                        pressure=0,
                        expired=0,
                        discarded=0,
                        selection=selection,
                    )
                    _save(key, bound, self.journal, records, MAX_JOURNAL)
            else:
                previous = self._current_config(key, bound, data, locked)
                records = self._records(key, bound, previous)
                if new_session:
                    if previous["session_token"] == token:
                        if (
                            previous["bootstrap_required"]
                            and previous["grant"] is None
                            and previous["cwd_token"] == directory
                            and not previous["capture"]
                        ):
                            return token
                        raise BackendError("session_mismatch")
                    previous_selection = previous["selection"]
                else:
                    if (
                        previous["session_token"] != token
                        or previous["cwd_token"] != directory
                    ):
                        raise BackendError("session_mismatch")
                    selection = previous["selection"]
                    bootstrap_required = previous["bootstrap_required"]
                    old = previous["grant"]
                    if old and grant is None:
                        if capture:
                            raise BackendError("grant_required")
                        # Turning off local consent never requires a second copy
                        # of the secret, and preserves generation high water.
                        grant = old
                    if (
                        old
                        and grant
                        and old != grant
                        and (
                            old["grant_generation"] >= grant["grant_generation"]
                            or old["policy_id"] != grant["policy_id"]
                            or old["policy_generation"] > grant["policy_generation"]
                        )
                    ):
                        raise BackendError("grant_mismatch")
                    if (
                        grant
                        and grant["capture_allowed"]
                        and (bootstrap_required or old and old != grant)
                    ):
                        # An imported enabled grant already binds the selected
                        # server session even before its first local callback.
                        bound_session = old["session_id"] if old else None
                        selected = records.get("selected_session", bound_session)
                        if selected != grant["session_id"] or bound_session not in (
                            None,
                            selected,
                        ):
                            raise BackendError("session_mismatch")
            config = dict(
                version=1,
                selection=selection,
                previous_selection=previous_selection,
                bootstrap_required=bootstrap_required,
                revision=str(uuid4()),
                session_token=token,
                cwd_token=directory,
                native_profile=wire.PROFILE,
                agent_version=version,
                capture=capture,
                grant=grant,
            )

            def commit_revision():
                data["native_revision"] = config["revision"]
                locked.write(data)

            _save(key, bound, self.path, config, 8192, commit=commit_revision)
            if new_session:
                self._records(key, bound, config)
        return token

    @staticmethod
    def offboard(locked, data, owner):
        if "native_state" not in data:
            return
        paths = [locked.path / n for n in (CONFIG, JOURNAL)]
        if any(os.path.lexists(p) for p in paths):
            generation = data["queue_generation"]
            key = _enrollment_key(locked.path, owner, generation)
            bound = [
                owner.origin,
                str(owner.device_id),
                generation,
                data["native_state"],
            ]
            for p, limit in zip(paths, (8192, MAX_JOURNAL), strict=True):
                if os.path.lexists(p):
                    _load(key, bound, p, limit)
        for p in paths:
            for member in (p.with_suffix(".next"), p):
                if os.path.lexists(member):
                    _private_file(member)
                    member.unlink()
        os.fsync(locked.root)


def _unreported(rows):
    # A discarded row without any observer report loses one unknown outcome.
    # If reports exist, count only the reports still awaiting acknowledgement.
    return sum(
        sum(not r["ack"] for r in row["reports"]) if row["reports"] else 1
        for row in rows
    )


class _Session:
    """A short operation under the enrollment lock. No network calls belong here."""

    def __init__(
        self, state, locked, owner, generation, access, key, binding, config, records
    ):
        self.locked = locked
        self.state, self.owner, self.generation = state, owner, generation
        self.access, self.key, self.binding = access, key, binding
        self.config, self.records = config, records

    def _save(self):
        _save(self.key, self.binding, self.state.journal, self.records, MAX_JOURNAL)

    def expire(self):
        current = int(time.time())
        rows = self.records["rows"]
        retired = [r for r in rows if r["created"] <= current - TTL]
        if retired:
            self.records["lost"] = min(
                2**31 - 1, self.records["lost"] + _unreported(retired)
            )
            self.records["expired"] = min(
                2**31 - 1, self.records["expired"] + len(retired)
            )
            self.records["rows"] = [r for r in rows if r["created"] > current - TTL]
            self._save()

    def authority(self):
        grant = self.config["grant"]
        if not grant:
            raise BackendError("grant_missing")
        if datetime.fromisoformat(grant["expires_at"]) <= datetime.now(UTC):
            raise BackendError("grant_expired")
        return Authority(
            self.owner,
            self.generation,
            self.config["revision"],
            self.access,
            grant,
            self.config["capture"],
            self.config["session_token"],
            grant["session_id"] or self.records.get("selected_session"),
        )

    def output_authority(self):
        # A process respecting our file lock cannot rotate these while stdout
        # waits. Detect pathname replacement and stale signed state as well.
        _, data = self.state.backend._bound(self.locked, self.owner)
        if (
            data["status"] != "active"
            or data["access"] != self.access
            or data.get("queue_generation") != self.generation
            or data.get("native_state") != self.binding[-1]
            or data.get("native_revision") != self.config["revision"]
            or _enrollment_key(self.locked.path, self.owner, self.generation)
            != self.key
            or self.state._current_config(self.key, self.binding, data, self.locked)
            != self.config
        ):
            raise BackendError("stale_authority")
        if cwd_token(self.key, Path.cwd()) != self.config["cwd_token"]:
            raise BackendError("cwd_mismatch")
        return self.authority()

    def check_event(self, event):
        if (
            not isinstance(event, dict)
            or event.get("hook_event_name") != "UserPromptSubmit"
        ):
            raise BackendError("unsupported_event")
        if (
            event.get("agent_version", wire.VERSION) != wire.VERSION
            or event.get("native_profile", wire.PROFILE) != wire.PROFILE
            or event.get("agent", "claude-code") != "claude-code"
        ):
            raise BackendError("profile_mismatch")
        sid = native_id(event.get("session_id"))
        if (
            sid is None
            or _token(self.key, "session", sid) != self.config["session_token"]
        ):
            raise BackendError("session_mismatch")
        if (
            event.get("cwd") != str(Path.cwd())
            or cwd_token(self.key, Path.cwd()) != self.config["cwd_token"]
        ):
            raise BackendError("cwd_mismatch")

    def _capacity(self):
        if sum(1 + len(r["reports"]) for r in self.records["rows"]) >= MAX_ENTRIES:
            self.records["lost"] = min(2**31 - 1, self.records["lost"] + 1)
            self.records["pressure"] = min(2**31 - 1, self.records["pressure"] + 1)
            self._save()
            raise BackendError("native_capacity")

    def reserve_invocation(self):
        self._capacity()
        row = dict(
            request_id=str(uuid4()),
            occurrence_id=str(uuid4()),
            created=int(time.time()),
            revision=self.config["revision"],
            outcome="reserved_unknown",
            reports=[],
        )
        self.records["rows"].append(row)
        self._save()
        return row

    def row(self, request_id):
        for row in self.records["rows"]:
            if row["request_id"] == request_id:
                return row
        raise BackendError("invocation_missing")

    def unavailable(self, request_id, code):
        row = self.row(request_id)
        if row["outcome"] == "reserved_unknown" and code in LOCAL_CODES:
            row["outcome"] = code
            self._save()

    def select_session(self, session_id):
        if not wire.uuid4_text(session_id) or self.records.get(
            "selected_session"
        ) not in (None, session_id):
            raise BackendError("session_mismatch")
        self.records["selected_session"] = session_id
        self._save()

    def prepared(self, request_id, reply, auth):
        row = self.row(request_id)
        if row["revision"] != auth.revision or row["outcome"] != "reserved_unknown":
            raise BackendError("stale_authority")
        self.records["selected_session"] = reply["session_id"]
        row.update(
            outcome="response_prepared",
            decision_id=reply["decision_id"],
            session_id=reply["session_id"],
            grant_id=auth.grant["grant_id"],
            grant_generation=auth.grant["grant_generation"],
        )
        self._save()

    def record_emission(self, report):
        wire.validate("NativeDeliveryReport", report)
        row = self.row(report["request_id"])
        auth = self.authority()
        if (
            row["outcome"] != "response_prepared"
            or row["occurrence_id"] != report["occurrence_id"]
            or row["decision_id"] != report["decision_id"]
            or row["grant_id"] != auth.grant["grant_id"]
            or row["grant_generation"] != auth.grant["grant_generation"]
            or report["evidence_source"] != "controlled_observer"
        ):
            raise BackendError("evidence_mismatch")
        for r in self.records["rows"]:
            for saved in r["reports"]:
                if saved["body"]["report_id"] == report["report_id"]:
                    if saved["body"] != report:
                        raise BackendError("evidence_mismatch")
                    return
        self._capacity()
        row["reports"].append(dict(body=report, ack=False))
        self._save()

    def pending_reports(self):
        auth = self.authority()
        return [
            s["body"]
            for r in self.records["rows"]
            if r.get("grant_id") == auth.grant["grant_id"]
            and r.get("grant_generation") == auth.grant["grant_generation"]
            for s in r["reports"]
            if not s["ack"]
        ]

    def ack_report(self, ack):
        wire.validate("NativeDeliveryAck", ack)
        for row in self.records["rows"]:
            for saved in row["reports"]:
                body = saved["body"]
                if (body["report_id"], body["decision_id"]) == (
                    ack["report_id"],
                    ack["decision_id"],
                ):
                    saved["ack"] = True
                    self._save()
                    return
        raise BackendError("evidence_mismatch")


LOCAL_CODES = wire.REFUSALS | frozenset(
    (
        "grant_missing native_inactive profile_mismatch session_mismatch cwd_mismatch "
        "unsupported_event invalid_input input_limit timeout busy offline invalid_reply stale_authority "
        "native_capacity storage_unavailable native_unprepared native_state_invalid owner_mismatch"
    ).split()
)

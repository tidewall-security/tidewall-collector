"""Client decisions at the HTTP boundary, with the real owned queue."""

import json
from uuid import uuid4

import pytest

from tidewall_collector import admission
from tidewall_collector.state import QueueState
from tidewall_collector.tidewall_backend import (
    BackendError,
    TidewallBackend,
    canonical_origin,
)
from test_queue_ownership import STREAM, obs

ORIGIN = "https://example.invalid"
DEVICE = uuid4()
ACCESS = "at_" + "1" * 32
REFRESH = "dr_" + "2" * 32
REG = "rt_" + "3" * 32
EVENTS = "/v1/collector/observations"
HEALTH = "/v1/collector/heartbeat"


@pytest.mark.parametrize(
    "value",
    [
        "https://a.invalid/path",
        "https://u@a.invalid",
        "https://a.invalid#x",
        "https://a.invalid?x",
        "https://a.invalid\\evil",
        "https://a.invalid:0",
        "http://localhost",
        "http://127.1",
        "http://192.0.2.4",
        "https://a.invalid\n",
    ],
)
def test_reject_ambiguous_origins(value):
    with pytest.raises(BackendError):
        canonical_origin(value, fixture_loopback=True)


def test_loopback_requires_explicit_opt_in():
    with pytest.raises(BackendError):
        canonical_origin("http://127.0.0.1:5000", fixture_loopback=False)
    assert (
        canonical_origin("https://EXAMPLE.invalid:443/", fixture_loopback=False)
        == ORIGIN
    )


def device_reply(enrol):
    result: dict = dict(
        device_id=str(DEVICE),
        device_status="pending" if enrol else "active",
        access_token=dict(token=ACCESS, expires_in=3600),
        config={"sites": {}},
    )
    if enrol:
        result.update(
            refresh_token=dict(token=REFRESH, expires_in=86400),
            confirmation_code="ABCDEFGH",
        )
    return admission.canonical(dict(status="Success" if enrol else "ok", result=result))


class Receiver:
    def __init__(self):
        self.calls = []
        self.answers = []
        self.refresh_failure = None

    def __call__(self, origin, path, token, body, limit):
        self.calls.append((origin, path, json.loads(body)))
        if path.endswith("/enrol"):
            assert token == REG
            return 201, device_reply(True)
        if path.endswith("/refresh"):
            assert token == REFRESH
            return self.refresh_failure or (200, device_reply(False))
        assert path in (EVENTS, HEALTH) and token == ACCESS
        obj = json.loads(body)
        if self.answers:
            answer = self.answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer
        if path == HEALTH:
            return 200, admission.canonical(
                dict(
                    version=1,
                    enrollment_id=str(DEVICE),
                    revision=obj["revision"],
                    capture="metadata_only",
                    retain_content=False,
                )
            )
        return 200, admission.canonical(
            dict(
                version=1,
                enrollment_id=obj["enrollment_id"],
                batch_id=obj["batch_id"],
                results=[
                    dict(
                        ordinal=r["ordinal"],
                        outcome="accepted",
                        digest=admission.digest(admission.canonical(r["observation"])),
                        event_id=str(uuid4()),
                    )
                    for r in obj["rows"]
                ],
            )
        )


@pytest.fixture
def client(tmp_path, monkeypatch):
    root = tmp_path / "device"
    back = TidewallBackend(root)
    receiver = Receiver()
    monkeypatch.setattr(back, "_post", receiver)
    owner = back.enrol(ORIGIN, REG, root)
    back.refresh(owner)
    with QueueState.open(root / "queue", owner) as q:
        yield back, owner, q, receiver


def three(q, owner, monkeypatch, invalid=False):
    # Start at the published vector's ordinal 40. A historical defect can admit
    # malformed metadata, while the current sender always runs the real preflight.
    with q._operation(owner) as journal:
        journal["next_ordinal"] = 40
        q._save(journal)
    rows = [obs(i) for i in (40, 41, 42)]
    if invalid:
        rows[1]["kind"] = "tool.call"
    with monkeypatch.context() as patch:
        if invalid:
            patch.setattr(admission, "validate_observation", lambda _: None)
        q.admit_record(owner, STREAM, 0, 1, rows)
    return rows


@pytest.mark.parametrize(
    "reply",
    [
        (422, b'{"code":"invalid_row"}'),
        (422, b'{"code":"unsupported_version"}'),
        (422, b'{"code":"invalid_envelope"}'),
        (422, b""),
        (422, b'{"code":"secret"}'),
    ],
)
def test_422_contract_mismatch_holds_queue(client, monkeypatch, reply):
    back, owner, q, receiver = client
    three(q, owner, monkeypatch)
    original = q.next_batch(owner).rows
    receiver.answers.append(reply)
    with pytest.raises(BackendError, match="contract_mismatch"):
        back.ship_once(owner, q)
    assert q.heartbeat(owner)["pending"] == 3 and not any(
        q.heartbeat(owner)["totals"].values()
    )
    assert q.heartbeat(owner)["state"] == "contract_mismatch"
    q.set_contract_mismatch(owner, False)
    assert q.next_batch(owner).rows == original
    assert back.ship_once(owner, q) == 3


@pytest.mark.parametrize("cut", ["before_terminal", "after_terminal"])
def test_422_local_disposition_and_suffix(client, monkeypatch, cut):
    from tidewall_collector.state import QueueError

    back, owner, q, receiver = client
    rows = three(q, owner, monkeypatch, True)
    assert back.ship_once(owner, q) == 1
    q.close()
    with QueueState.open(q.path, owner) as restarted:

        def fail(phase):
            if phase == cut:
                raise OSError

        monkeypatch.setattr(restarted, "_boundary", fail)
        with pytest.raises(QueueError, match="blocked_storage"):
            back.ship_once(owner, restarted)
    with QueueState.open(q.path, owner) as restarted:
        assert restarted.heartbeat(owner)["totals"]["row_schema_invalid"] == int(
            cut == "after_terminal"
        )
        assert back.ship_once(owner, restarted) == 1
        assert restarted.heartbeat(owner)["totals"]["row_schema_invalid"] == 1
        assert restarted.heartbeat(owner)["pending"] == 0
    assert [
        r for _, path, data in receiver.calls if path == EVENTS for r in data["rows"]
    ] == [
        {"ordinal": 40, "observation": rows[0]},
        {"ordinal": 42, "observation": rows[2]},
    ]


@pytest.mark.parametrize(
    "answer,code",
    [
        (429, "retry_later"),
        (503, "retry_later"),
        (302, "redirect_refused"),
        (403, "scope_denied"),
    ],
)
def test_failed_send_preserves_rows(client, answer, code):
    back, owner, q, receiver = client
    q.admit_record(owner, STREAM, 0, 1, [obs(1)])
    before = q.next_batch(owner).rows
    receiver.answers.append((answer, b""))
    with pytest.raises(BackendError, match=code):
        back.ship_once(owner, q)
    assert q.next_batch(owner).rows == before
    if answer == 403:
        with pytest.raises(BackendError, match=code):
            back.ship_once(owner, q)
        assert len([1 for _, p, _ in receiver.calls if p == EVENTS]) == 1


@pytest.mark.parametrize(
    "status,reason",
    [
        (403, "device_revoked"),
        (401, "credential_expired"),
        (401, "credential_unknown"),
        (202, "device_pending"),
    ],
)
def test_one_refresh_and_closed_taxonomy(client, status, reason):
    back, owner, q, receiver = client
    q.admit_record(owner, STREAM, 0, 1, [obs(1)])
    receiver.answers.append((401, b""))
    receiver.refresh_failure = (
        status,
        admission.canonical(dict(status=reason, reason=reason, result=None)),
    )
    with pytest.raises(BackendError, match=reason):
        back.ship_once(owner, q)
    assert q.heartbeat(owner)["pending"] == 1
    assert [p for _, p, _ in receiver.calls[2:]] == [
        EVENTS,
        f"/v1/devices/{DEVICE}/refresh",
    ]
    assert all(origin == ORIGIN for origin, _, _ in receiver.calls)


def test_413_shrinks_and_holds_irreducible(client, monkeypatch):
    back, owner, q, receiver = client
    three(q, owner, monkeypatch)
    receiver.answers.append((413, b""))
    assert back.ship_once(owner, q) == 1
    receiver.answers.extend([(413, b""), (413, b"")])
    with pytest.raises(BackendError, match="row_too_large"):
        back.ship_once(owner, q)
    before = len(receiver.calls)
    with pytest.raises(BackendError, match="row_too_large"):
        back.ship_once(owner, q)
    assert len(receiver.calls) == before and q.heartbeat(owner)["pending"] == 2


def test_stale_or_command_heartbeat_is_ignored(client):
    back, owner, q, receiver = client
    snapshot = q.heartbeat(owner)
    for change in (
        dict(revision=snapshot["revision"] - 1),
        dict(command="run"),
        dict(version=True),
    ):
        ack = dict(
            version=1,
            enrollment_id=str(DEVICE),
            revision=snapshot["revision"],
            capture="metadata_only",
            retain_content=False,
        )
        receiver.answers.append((200, admission.canonical({**ack, **change})))
        with pytest.raises(BackendError, match="invalid_heartbeat"):
            back.send_heartbeat(owner, q)
        assert q.heartbeat(owner) == snapshot


def test_unknown_heartbeat_replays_immutable_snapshot_after_local_changes(
    client, monkeypatch
):
    back, owner, q, receiver = client
    receiver.answers.append(BackendError("offline"))
    with pytest.raises(BackendError, match="offline"):
        back.send_heartbeat(owner, q)
    first = receiver.calls[-1][2]
    q.admit_record(owner, STREAM, 0, 1, [obs(1)])
    assert back.status(owner, q)["heartbeat"]["pending"] == 1
    q.close()
    assert back.root is not None
    restarted = TidewallBackend(back.root)
    monkeypatch.setattr(restarted, "_post", receiver)
    with QueueState.open(back.root / "queue", owner) as reopened:
        restarted.send_heartbeat(owner, reopened)
        assert receiver.calls[-1][2] == first
        restarted.send_heartbeat(owner, reopened)
        second = receiver.calls[-1][2]
        assert second["pending"] == 1 and second["revision"] > first["revision"]
        restarted.send_heartbeat(owner, reopened)
        third = receiver.calls[-1][2]
        assert third["revision"] > second["revision"]
        assert {**third, "revision": second["revision"]} == second


def test_heartbeat_commit_failure_keeps_same_delivery(client, monkeypatch):
    from tidewall_collector.state import QueueError

    back, owner, q, receiver = client
    save = q._save

    def no_space(journal):
        if journal.get("acked_heartbeat"):
            raise OSError("fixture full disk")
        save(journal)

    with monkeypatch.context() as patch:
        patch.setattr(q, "_save", no_space)
        with pytest.raises(QueueError, match="blocked_storage"):
            back.send_heartbeat(owner, q)
    first = receiver.calls[-1][2]
    q.close()
    assert back.root is not None
    with QueueState.open(back.root / "queue", owner) as reopened:
        back.send_heartbeat(owner, reopened)
        assert receiver.calls[-1][2] == first
        # Inspecting live status after a completed ACK must not queue a delivery.
        assert back.status(owner, reopened)["heartbeat"] == first
        reopened.admit_record(owner, STREAM, 0, 1, [obs(1)])
        back.send_heartbeat(owner, reopened)
        fresh = receiver.calls[-1][2]
        assert fresh["pending"] == 1 and fresh["revision"] > first["revision"]


def disable_sqlite_serialize(patch):
    import sqlite3
    from functools import partial

    class WithoutSerialize(sqlite3.Connection):
        def __getattribute__(self, name):
            if name == "serialize":
                raise AttributeError("sensitive_fixture")
            return super().__getattribute__(name)

    patch.setattr(
        sqlite3, "connect", partial(sqlite3.connect, factory=WithoutSerialize)
    )


@pytest.mark.parametrize("recovery", [False, True])
def test_sqlite_capability_before_registration(tmp_path, monkeypatch, recovery):
    from tidewall_collector.state import QueueError

    root = tmp_path / "device"
    back = TidewallBackend(root)
    receiver = Receiver()
    monkeypatch.setattr(back, "_post", receiver)
    installation = uuid4()

    def register():
        if recovery:
            return back.recover(ORIGIN, installation, REG, "fixture_grant", root)
        return back.enrol(ORIGIN, REG, root)

    with monkeypatch.context() as patch:
        disable_sqlite_serialize(patch)
        with pytest.raises(
            (QueueError, BackendError), match="^sqlite_serialize_required$"
        ):
            register()
    assert receiver.calls == []
    assert not (root / "credentials.json").exists()
    assert register().device_id == DEVICE
    assert len(receiver.calls) == 1


def test_late_reply_cannot_advance_replaced_credentials(client, monkeypatch):
    back, owner, queue, receiver = client
    queue.admit_record(owner, STREAM, 0, 1, [obs(7)])
    original = queue.next_batch(owner).rows
    replies = []
    selected = []
    select = queue.next_batch

    def remember(*args):
        pending = select(*args)
        selected.append(pending)
        return pending

    monkeypatch.setattr(queue, "next_batch", remember)

    def late(*args):
        response = receiver(*args)
        replies.append(response[1])
        # Simulate an old process receiving a reply after local authority changed.
        path = queue.path.parent / "credentials.json"
        data = json.loads(path.read_bytes())
        data["status"] = "device_revoked"
        path.write_bytes(admission.canonical(data))
        return response

    monkeypatch.setattr(back, "_post", late)
    with pytest.raises(BackendError, match="stale_authority"):
        back.ship_once(owner, queue)
    from tidewall_collector.state import QueueError

    with pytest.raises(QueueError, match="stale_receipt"):
        queue.apply_receipt(owner, selected[0], replies[0])
    assert queue.next_batch(owner).rows == original


def test_one_refresh_never_reenrols_after_second_401(client):
    back, owner, q, receiver = client
    q.admit_record(owner, STREAM, 0, 1, [obs(7)])
    receiver.answers.extend([(401, b""), (401, b"")])
    with pytest.raises(BackendError, match="unauthorized"):
        back.ship_once(owner, q)
    assert [p for _, p, _ in receiver.calls[2:]] == [
        EVENTS,
        f"/v1/devices/{DEVICE}/refresh",
        EVENTS,
    ]
    first, _, second = receiver.calls[2:]
    assert first[2]["batch_id"] != second[2]["batch_id"]
    assert first[2]["rows"] == second[2]["rows"]
    assert q.heartbeat(owner)["pending"] == 1


def test_protected_inputs_and_local_offboard_handoff(client, tmp_path, monkeypatch):
    from tidewall_collector.cli import _secret_fd
    from tidewall_collector.state import QueueError

    back, owner, q, _ = client
    cred = q.path.parent / "credentials.json"
    assert cred.stat().st_mode & 0o777 == 0o600
    assert (
        REG.encode() not in cred.read_bytes() and b"ABCDEFGH" not in cred.read_bytes()
    )
    p = tmp_path / "input"
    p.write_bytes(REG.encode())
    p.chmod(0o644)
    with p.open("rb") as f, pytest.raises(BackendError, match="unprotected_input"):
        _secret_fd(f.fileno())
    p.chmod(0o600)
    with p.open("rb") as f:
        assert _secret_fd(f.fileno()) == REG
    with pytest.raises(BackendError, match="owner_mismatch"):
        back.offboard(uuid4())
    with pytest.raises(QueueError, match="busy"):
        back.offboard(owner.device_id)
    assert cred.exists() and q.path.exists()
    q.close()
    original = QueueState.offboard

    def interrupted(self, owner):
        original(self, owner)
        raise OSError("test cut after queue erasure")

    with monkeypatch.context() as patch:
        patch.setattr(QueueState, "offboard", interrupted)
        with pytest.raises(BackendError, match="state_unavailable"):
            back.offboard(owner.device_id)
    assert cred.exists() and not q.path.exists()
    back.offboard(owner.device_id)
    assert not cred.exists() and [p.name for p in q.path.parent.iterdir()] == [
        "credential.lock"
    ]


def test_secret_values_never_echoed_on_parse_error(capsys):
    from tidewall_collector.cli import main

    assert main(["ship", "--state-root", "/tmp/absent", "--" + REG]) == 2
    assert capsys.readouterr().err == "invalid_arguments\n"


def test_recovery_uses_original_nonnil_uuid(tmp_path, monkeypatch):
    from uuid import UUID

    original = UUID("77777777-8888-1111-8222-333333333333")
    back = TidewallBackend(tmp_path / "B")
    receiver = Receiver()
    monkeypatch.setattr(back, "_post", receiver)
    back.recover(ORIGIN, original, REG, "fixture_grant", tmp_path / "B")
    assert receiver.calls[0][2]["installation_id"] == str(original)


def test_stalled_resolver_is_reaped_at_total_deadline(tmp_path, monkeypatch):
    """A resolver that never completes cannot leave a background sender alive."""
    import os
    import sys
    import time
    from tidewall_collector import tidewall_backend as backend

    pid_file = tmp_path / "resolver.pid"
    driver = tmp_path / "stuck-resolver"
    driver.write_text(
        f"#!{sys.executable}\n"
        "import os,runpy,socket,sys,time\n"
        "def stalled(*args):\n"
        f"    with open({str(pid_file)!r}, 'w') as f: print(os.getpid(),file=f)\n"
        "    time.sleep(300)\n"
        "socket.getaddrinfo = stalled\n"
        "runpy.run_path(sys.argv[-1], run_name='__main__')\n"
    )
    driver.chmod(0o700)
    monkeypatch.setattr(sys, "executable", str(driver))
    start = time.monotonic()
    with pytest.raises(BackendError, match="timeout"):
        backend._post(ORIGIN, HEALTH, ACCESS, b"{}", 2048)
    assert 4.8 < time.monotonic() - start < 6.2
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text()), 0)


def test_incompatible_heartbeat_holds_pending_observations(client):
    back, owner, q, receiver = client
    q.admit_record(owner, STREAM, 0, 1, [obs(9)])
    original = q.next_batch(owner).rows
    receiver.answers.append((422, b'{"code":"unsupported_version"}'))
    with pytest.raises(BackendError, match="contract_mismatch"):
        back.send_heartbeat(owner, q)
    assert q.heartbeat(owner)["pending"] == 1
    assert q.heartbeat(owner)["state"] == "contract_mismatch"
    back.resume_contract(owner, q)
    assert q.next_batch(owner).rows == original


@pytest.mark.parametrize("target", ["queue", "queue/B", "B", "unrelated", "ancestor"])
def test_disjoint_recovery_state_selection(client, tmp_path, monkeypatch, target):
    back, owner, q, receiver = client
    q.admit_record(owner, STREAM, 0, 1, [obs(75)])
    original = q.next_batch(owner)
    root = q.path.parent
    if target == "unrelated":
        dest = tmp_path / "other"
        dest.mkdir(mode=0o700)
        (dest / "preserve").touch()
    elif target == "ancestor":
        dest = tmp_path
    else:
        dest = root / target
    before = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    calls = len(receiver.calls)
    candidate = TidewallBackend(dest)
    monkeypatch.setattr(candidate, "_post", receiver)
    with pytest.raises(BackendError, match="state_exists"):
        candidate.recover(ORIGIN, uuid4(), REG, "out_of_band", dest)
    assert {p.relative_to(tmp_path) for p in tmp_path.rglob("*")} == before
    assert len(receiver.calls) == calls
    current = q.next_batch(owner)
    assert (
        current.rows == original.rows
        and current.expected_cursor == original.expected_cursor
    )
    q.close()
    back.offboard(owner.device_id)
    assert not (root / "credentials.json").exists() and not (root / "queue").exists()


def test_known_enrolment_reopens_completed_queue_without_rekey(tmp_path, monkeypatch):
    from tidewall_collector.state import QueueError

    root = tmp_path / "A"
    receiver = Receiver()
    back = TidewallBackend(root)
    monkeypatch.setattr(back, "_post", receiver)
    from tidewall_collector import tidewall_backend as backend

    real_prepare = backend.prepare_queue
    saved = []

    def interrupt(path, owner, birth, persist):
        real_prepare(path, owner, birth, persist)
        with QueueState.open(path, owner) as q:
            q.admit_record(owner, STREAM, 0, 1, [obs(50)])
            saved.append((q.generation, q.projection_key(owner), q.next_batch(owner)))
        raise QueueError("busy")

    with monkeypatch.context() as patch:
        patch.setattr(backend, "prepare_queue", interrupt)
        with pytest.raises(QueueError, match="busy"):
            back.enrol(ORIGIN, REG, root)
    retry = TidewallBackend(root)
    monkeypatch.setattr(retry, "_post", receiver)
    with pytest.raises(BackendError):
        retry.enrol(ORIGIN, "rt_wrong", root)
    owner = retry.enrol(ORIGIN, REG, root)
    assert retry.confirmation_code == "ABCDEFGH" and len(receiver.calls) == 1
    with QueueState.open(root / "queue", owner) as queue:
        batch = queue.next_batch(owner)
        generation, key, previous = saved[0]
        assert batch is not None and previous is not None
        assert queue.generation == generation and queue.projection_key(owner) == key
        assert (
            batch.rows == previous.rows
            and batch.expected_cursor == previous.expected_cursor
        )
    (root / "queue").rename(tmp_path / "missing")
    with pytest.raises((BackendError, QueueError)):
        retry.enrol(ORIGIN, REG, root)
    assert not (root / "queue").exists() and len(receiver.calls) == 1


@pytest.mark.parametrize("boundary", ["first_file", "ready_write"])
def test_new_process_resumes_confirmed_queue_birth(tmp_path, monkeypatch, boundary):
    """After a known 201 a separate CLI needs only the original local handoff."""
    import errno
    import os
    from pathlib import Path
    import shutil
    import subprocess
    import sys
    import tempfile
    from tidewall_collector import state, tidewall_backend as backend

    root = tmp_path / "A"
    sources = tmp_path / "inputs"
    sources.mkdir()
    for name in ("claude-session.jsonl", "claude-hooks.json"):
        shutil.copyfile(Path(__file__).parent / "fixtures" / name, sources / name)
    receiver = Receiver()
    first = TidewallBackend(root)
    monkeypatch.setattr(first, "_post", receiver)
    save = backend._LockedState.write

    def fail_save(self, data):
        if (data.get("setup") or {}).get("ready") is True:
            raise OSError(errno.ENOSPC, "fixture storage interruption")
        return save(self, data)

    def fail_file(path, data):
        raise OSError(errno.ENOSPC, "fixture storage interruption")

    with monkeypatch.context() as cut:
        if boundary == "first_file":
            cut.setattr(state, "_create_file", fail_file)
        else:
            cut.setattr(backend._LockedState, "write", fail_save)
        with pytest.raises((BackendError, state.QueueError)):
            first.enrol(ORIGIN, REG, root)
    owner = state.Owner(ORIGIN, DEVICE)
    args = [sys.executable, "-m", "tidewall_collector.cli"]
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(
            map(
                str,
                [
                    Path(__file__).resolve().parents[1] / p
                    for p in (
                        "src",
                        "vendor/openaidr/src",
                        "vendor/openaidr/packages/common/src",
                    )
                ],
            )
        ),
    }

    def invoke(command, *extra):
        with tempfile.TemporaryFile(dir=tmp_path) as fd:
            fd.write(REG.encode())
            fd.seek(0)
            options = (
                ["--registration-fd", str(fd.fileno()), "--origin", ORIGIN]
                if command == "enrol"
                else []
            )
            return subprocess.run(
                [*args, command, "--state-root", str(root), *options, *extra],
                capture_output=True,
                text=True,
                cwd=tmp_path,
                env=env,
                pass_fds=[fd.fileno()],
                timeout=10,
            )

    if boundary == "first_file":
        assert list((root / "queue").iterdir()) == []
        # A known remote success may have been created by an earlier release.
        with monkeypatch.context() as patch:
            disable_sqlite_serialize(patch)
            with pytest.raises(state.QueueError, match="^sqlite_serialize_required$"):
                first.enrol(ORIGIN, REG, root)
        assert len(receiver.calls) == 1
    else:
        result = invoke("fixture", "--fixture-dir", str(sources))
        assert result.returncode != 0 and result.stderr.strip() == "setup_incomplete"
        with QueueState.open(root / "queue", owner) as q:
            assert q.heartbeat(owner)["pending"] == 0
            prior = (q.generation, q.projection_key(owner))
            for write in (first.ship_once, first.send_heartbeat):
                with pytest.raises(BackendError, match="setup_incomplete"):
                    write(owner, q)
            with pytest.raises(BackendError, match="setup_incomplete"):
                first.refresh(owner)
        (root / "queue").rename(tmp_path / "held")
        assert invoke("enrol").returncode != 0
        assert not (root / "queue").exists()
        (tmp_path / "held").rename(root / "queue")
    completed = invoke("enrol")
    assert completed.returncode == 0
    assert json.loads(completed.stdout)["device_id"] == str(DEVICE)
    assert json.loads(completed.stdout)["confirmation_code"] == "ABCDEFGH"
    with QueueState.open(root / "queue", owner) as q:
        if boundary == "ready_write":
            assert (q.generation, q.projection_key(owner)) == prior
        assert q.heartbeat(owner)["pending"] == 0
    first.refresh(owner)
    # Once approval has been confirmed, the separate CLI can capture offline.
    assert invoke("fixture", "--fixture-dir", str(sources)).returncode == 0
    with QueueState.open(root / "queue", owner) as q:
        assert q.heartbeat(owner)["pending"] == 11
    assert len(receiver.calls) == 2


def test_unpublished_readiness_never_recreates_lost_initialized_queue(
    tmp_path, monkeypatch
):
    from tidewall_collector import tidewall_backend as backend
    from tidewall_collector.state import QueueError, Owner

    root = tmp_path / "A"
    back = TidewallBackend(root)
    wire = Receiver()
    monkeypatch.setattr(back, "_post", wire)
    write = backend._LockedState.write

    def failed_ready(self, data):
        if data.get("setup", {}).get("ready"):
            raise OSError("readiness write failed")
        return write(self, data)

    with monkeypatch.context() as cut:
        cut.setattr(backend._LockedState, "write", failed_ready)
        with pytest.raises(BackendError):
            back.enrol(ORIGIN, REG, root)
    owner = Owner(ORIGIN, DEVICE)
    with QueueState.open(root / "queue", owner) as q:
        # Exercise the lower-level queue separately from the gated CLI.
        q.admit_record(owner, STREAM, 0, 1, [obs(84)])
        pending = q.next_batch(owner)
        key = q.projection_key(owner)
        generation = q.generation
    (root / "queue").rename(tmp_path / "held")
    with pytest.raises((BackendError, QueueError)):
        back.enrol(ORIGIN, REG, root)
    assert not (root / "queue").exists() and len(wire.calls) == 1
    (tmp_path / "held").rename(root / "queue")
    back.enrol(ORIGIN, REG, root)
    with QueueState.open(root / "queue", owner) as q:
        current = q.next_batch(owner)
        assert current is not None and pending is not None
        assert q.projection_key(owner) == key and q.generation == generation
        assert (
            current.rows == pending.rows
            and current.expected_cursor == pending.expected_cursor
        )


@pytest.mark.parametrize(
    "cut",
    [
        "directory_proof",
        "partial_key",
        "partial_manifest",
        "partial_journal",
        "prepared_proof",
        "journal_publish",
    ],
)
def test_interrupted_queue_publication_preserves_planned_generation(
    tmp_path, monkeypatch, cut
):
    import errno
    from tidewall_collector import state, tidewall_backend as backend

    root = tmp_path / "A"
    back = TidewallBackend(root)
    wire = Receiver()
    monkeypatch.setattr(back, "_post", wire)
    create = state._create_file
    write = backend._LockedState.write
    rename = state.os.rename

    def interrupt():
        raise OSError(errno.ENOSPC, "fixture storage interruption")

    def partial(path, content):
        matches = (
            (cut == "partial_key" and len(content) == 32)
            or (cut == "partial_manifest" and content.startswith(b"["))
            or (cut == "partial_journal" and content.startswith(b"SQLite"))
        )
        if matches:
            create(path, content[:7])
            interrupt()
        return create(path, content)

    def checkpoint(self, data):
        plan = data.get("setup", {}).get("birth", {})
        if (
            cut == "directory_proof"
            and "directory" in plan
            or cut == "prepared_proof"
            and "prepared" in plan
        ):
            interrupt()
        return write(self, data)

    def publish(source, dest, *args, **kwargs):
        if (
            cut == "journal_publish"
            and str(source).endswith("/initial.db")
            and str(dest).endswith("/state.db")
        ):
            interrupt()
        return rename(source, dest, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(state, "_create_file", partial)
        patch.setattr(backend._LockedState, "write", checkpoint)
        patch.setattr(state.os, "rename", publish)
        with pytest.raises((state.QueueError, BackendError)):
            back.enrol(ORIGIN, REG, root)
    plan = json.loads((root / "credentials.json").read_bytes())["setup"]["birth"]
    keyfile = root / "queue/key"
    old_key = keyfile.read_bytes() if keyfile.exists() else None
    owner = back.enrol(ORIGIN, REG, root)
    with QueueState.open(root / "queue", owner) as q:
        assert str(q.generation) == plan["generation"]
        if old_key is not None:
            assert q.projection_key(owner) == old_key
        assert q.heartbeat(owner)["pending"] == 0
    assert len(wire.calls) == 1


def test_explicit_offboard_after_failed_readiness(tmp_path, monkeypatch):
    from tidewall_collector import tidewall_backend as backend

    root = tmp_path / "A"
    back = TidewallBackend(root)
    wire = Receiver()
    monkeypatch.setattr(back, "_post", wire)
    write = backend._LockedState.write

    def cut(self, data):
        if data.get("setup", {}).get("ready"):
            raise OSError("failed readiness")
        return write(self, data)

    with monkeypatch.context() as patch:
        patch.setattr(backend._LockedState, "write", cut)
        with pytest.raises(BackendError):
            back.enrol(ORIGIN, REG, root)
    with pytest.raises(BackendError, match="owner_mismatch"):
        back.offboard(uuid4())
    back.offboard(DEVICE)
    assert not (root / "queue").exists() and not (root / "credentials.json").exists()
    assert back.confirmation_code == "" and len(wire.calls) == 1

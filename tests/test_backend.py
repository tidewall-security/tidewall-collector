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

"""Native state uses the actual enrolled owner and generation."""

from datetime import UTC, datetime, timedelta
import os
from uuid import uuid4

import pytest

from test_backend import ORIGIN, REG, Receiver
from tidewall_collector.native_state import NativeState
from tidewall_collector.tidewall_backend import BackendError, TidewallBackend


@pytest.fixture
def native(tmp_path):
    root = tmp_path / "A"
    work = tmp_path / "controlled"
    work.mkdir(mode=0o700)
    back = TidewallBackend(root)
    back._post = Receiver()
    owner = back.enrol(ORIGIN, REG, root)
    back.refresh(owner)
    state = NativeState(back, root / "native-session.json")
    token = state.prepare("synthetic-session", work, "2.1.330", False, None)
    return back, state, owner, token, work


def grant(owner, token, *, capture=True):
    return dict(
        device_id=str(owner.device_id),
        policy_id="fixture",
        policy_generation=1,
        grant_id=str(uuid4()),
        grant_generation=2,
        capability="g" * 43,
        session_token=token,
        session_id=str(uuid4()) if capture else None,
        native_profile="claude-code.user-prompt-submit.1",
        capture_allowed=capture,
        expires_at=(datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
    )


def test_a_journal_and_secret_cannot_move_or_survive_offboard(native, tmp_path):
    back, state, owner, token, work = native
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    with state.open(owner) as session:
        session.reserve_invocation()
    for path in (state.path, state.journal):
        assert path.stat().st_mode & 0o777 == 0o600
        assert b"synthetic-session" not in path.read_bytes()
        assert os.fsencode(work) not in path.read_bytes()
    assert g["capability"].encode() not in state.journal.read_bytes()
    other = TidewallBackend(tmp_path / "B")
    other._post = Receiver()
    b = other.enrol(ORIGIN, REG, other.root)
    other.refresh(b)
    bstate = NativeState(other, other.root / state.path.name)
    bstate.prepare("synthetic-session", work, "2.1.330", False, None)
    bstate.journal.write_bytes(state.journal.read_bytes())
    with pytest.raises(ValueError):
        with bstate.open(b):
            pass
    back.offboard(owner.device_id)
    assert not state.journal.exists() and not state.path.exists()


def test_corruption_and_missing_journal_refused_without_reset(native):
    _, state, owner, _, work = native
    state.journal.write_bytes(b"{}")
    with pytest.raises(ValueError):
        state.prepare("synthetic-session", work, "2.1.330", False, None)
    assert state.journal.read_bytes() == b"{}"
    state.journal.unlink()
    with pytest.raises(ValueError):
        with state.open(owner):
            pass


def test_journal_pressure_ttl_and_separate_report_ack(native, monkeypatch):
    from tidewall_collector import native_state as store
    from test_native_hook import reply

    back, state, owner, token, work = native
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    with state.open(owner) as session:
        row = session.reserve_invocation()
        result = reply(dict(request_id=row["request_id"], observation=row), g)
        session.prepared(row["request_id"], result, session.authority())
        report = {k: result[k] for k in ("decision_id", "request_id", "occurrence_id")}
        report.update(
            report_id=str(uuid4()),
            evidence_source="controlled_observer",
            stage="stdout_flushed",
        )
        assert not session.pending_reports()
        session.record_emission(report)
        session.record_emission(report)
        assert session.pending_reports() == [report]
        with pytest.raises(BackendError, match="evidence_mismatch"):
            session.record_emission(dict(report, stage="unknown"))
        with pytest.raises(BackendError, match="evidence_mismatch"):
            session.ack_report(
                dict(version=1, report_id=report["report_id"], decision_id=str(uuid4()))
            )
        session.ack_report(
            dict(
                version=1,
                report_id=report["report_id"],
                decision_id=report["decision_id"],
            )
        )
        assert not session.pending_reports()
    monkeypatch.setattr(store, "MAX_ENTRIES", 3)
    with state.open(owner) as session:
        session.reserve_invocation()
        with pytest.raises(BackendError, match="native_capacity"):
            session.reserve_invocation()
        assert session.records["lost"] == 1
    assert state.journal.stat().st_size < 1 << 20
    now = store.time.time()
    monkeypatch.setattr(store.time, "time", lambda: now + store.TTL)
    with state.open(owner) as session:
        assert (
            session.records["rows"] == []
            and session.records["lost"] == 2
            and session.records["expired"] == 2
        )


def test_config_and_state_are_authenticated_and_private(native):
    back, state, owner, token, work = native
    with pytest.raises(BackendError, match="owner_mismatch"):
        with state.open(owner, uuid4()):
            pass
    for file in (state.journal, state.path):
        os.chmod(file, 0o644)
        with pytest.raises(ValueError):
            with state.open(owner):
                pass
        os.chmod(file, 0o600)
    with pytest.raises(BackendError, match="grant_mismatch"):
        state.prepare(
            "synthetic-session", work, "2.1.330", True, grant(owner, "0" * 64)
        )
    with pytest.raises(BackendError, match="invalid_session"):
        state.prepare("synthetic-session", work, "2.1.329", False, None)


def test_explicit_fresh_selection_drops_old_grant_and_unreported_metadata(native):
    from test_native_hook import reply

    back, state, owner, token, work = native
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    with state.open(owner) as session:
        row = session.reserve_invocation()
        answer = reply(dict(request_id=row["request_id"], observation=row), g)
        session.prepared(row["request_id"], answer, session.authority())
        report = {k: answer[k] for k in ("decision_id", "request_id", "occurrence_id")}
        report.update(
            report_id=str(uuid4()),
            stage="stdout_flushed",
            evidence_source="controlled_observer",
        )
        session.record_emission(report)
    with pytest.raises(BackendError, match="session_mismatch"):
        state.prepare("second-synthetic", work, "2.1.330", False, None)
    second = state.prepare(
        "second-synthetic", work, "2.1.330", False, None, new_session=True
    )
    assert second != token
    for path in (state.path, state.journal):
        data = path.read_bytes()
        assert (
            g["capability"].encode() not in data
            and row["request_id"].encode() not in data
        )
    with state.open(owner) as session:
        assert session.records["rows"] == [] and session.records["lost"] >= 1
        assert session.config["capture"] is False
        with pytest.raises(BackendError, match="grant_missing"):
            session.authority()
    with pytest.raises(BackendError, match="session_mismatch"):
        state.prepare("second-synthetic", work, "2.1.330", True, grant(owner, second))
    fresh = grant(owner, second, capture=False)
    state.prepare("second-synthetic", work, "2.1.330", False, fresh)
    with state.open(owner) as session:
        assert not session.pending_reports()
        with pytest.raises(BackendError, match="invocation_missing"):
            session.record_emission(report)


def test_replaced_previous_consent_config_cannot_revive_capture(native):
    _, state, owner, token, work = native
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    old = state.path.read_bytes()
    state.prepare("synthetic-session", work, "2.1.330", False, g)
    state.path.write_bytes(old)
    with pytest.raises(BackendError, match="native_state_invalid"):
        with state.open(owner):
            pass


def test_config_rotation_interrupted_after_credential_commit_resumes(
    native, monkeypatch
):
    import errno
    from tidewall_collector import native_state as store

    _, state, owner, token, work = native
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    replace = store.os.replace

    def interrupt(src, dst, *args, **kwargs):
        if dst == state.path:
            raise OSError(errno.ENOSPC, "synthetic")
        return replace(src, dst, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(store.os, "replace", interrupt)
        with pytest.raises(ValueError):
            state.prepare("synthetic-session", work, "2.1.330", False, None)
    with state.open(owner) as session:
        assert not session.authority().capture and session.authority().grant == g
    assert not state.path.with_suffix(".next").exists()


def test_expired_grant_local_authority(native, monkeypatch):
    from datetime import datetime, timedelta
    from tidewall_collector import native_state as store

    back, state, owner, token, work = native
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(hours=1)

    monkeypatch.setattr(store, "datetime", Later)
    with (
        state.open(owner) as session,
        pytest.raises(BackendError, match="grant_expired"),
    ):
        session.authority()


def test_reporting_never_holds_enrollment_lock_while_reading_or_printing(
    native, monkeypatch
):
    from tidewall_collector import cli

    back, state, owner, _, _ = native
    argv = [
        "report-native",
        "--state-root",
        str(back.root),
        "--session-config",
        str(state.path),
    ]
    checks = []

    def unlocked(*args, **kwargs):
        with state.open(owner):
            checks.append(True)
        return b"{}"

    monkeypatch.setattr(cli, "_protected_fd", unlocked)
    monkeypatch.setattr("builtins.print", unlocked)
    assert cli.main([*argv, "--evidence-fd", "9"]) == 2
    assert cli.main([*argv, "--list"]) == 0
    assert len(checks) == 3


@pytest.mark.parametrize("local_observation", [False, True])
def test_policy_regrant_preserves_session_and_both_generation_fences(
    native, local_observation
):
    _, state, owner, token, work = native
    old = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, old)
    if local_observation:
        with state.open(owner) as session:
            session.select_session(old["session_id"])
    newer = dict(
        old,
        policy_generation=2,
        grant_generation=3,
        grant_id=str(uuid4()),
        capability="n" * 43,
    )
    state.prepare("synthetic-session", work, "2.1.330", False, newer)
    for supplied in (
        old,
        dict(newer, grant_generation=4, policy_generation=1),
        dict(newer, grant_generation=3, policy_generation=3),
        dict(newer, grant_generation=4, policy_id="other"),
        dict(newer, grant_generation=4, session_id=str(uuid4())),
    ):
        with pytest.raises(BackendError):
            state.prepare("synthetic-session", work, "2.1.330", True, supplied)
    with state.open(owner) as session:
        assert not session.authority().capture
        assert session.authority().grant["grant_id"] == newer["grant_id"]


@pytest.mark.parametrize(
    "code", ["owner_mismatch", "native_state_invalid", "native_unprepared"]
)
def test_reserved_row_records_local_binding_errors_when_storage_recovers(native, code):
    _, state, owner, _, _ = native
    with state.open(owner) as session:
        request_id = session.reserve_invocation()["request_id"]
    with state.open(owner) as session:
        session.unavailable(request_id, code)
    with state.open(owner) as session:
        assert session.row(request_id)["outcome"] == code
        assert session.row(request_id)["reports"] == []

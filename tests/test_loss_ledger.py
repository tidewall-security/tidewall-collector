import json

import pytest
from test_queue_ownership import A, STREAM, obs, queue, receipt

from tidewall_collector import admission, state as state_module
from tidewall_collector.state import InvalidHead, QueueError, QueueState


def test_capacity_and_loss_commit_are_bounded_and_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(state_module, "DATA_LIMIT", 2400)
    monkeypatch.setattr(state_module, "SEGMENT_LIMIT", 1200)
    with queue(tmp_path, 0) as q:
        q.admit_record(A, STREAM, 10, 11, [obs(i) for i in range(40)])
        events = q.next_batch(A).rows
        assert 0 < len(events) < 40
        hb = q.heartbeat(A)
        assert hb["totals"]["capacity_rejected"] == 40 - len(events)
        assert hb["pending"] == len(events) and hb["queue_bytes"] <= 2400
        assert all(p.stat().st_size <= 1200 for p in q._spool.segments())
        assert q.checkpoint(A, STREAM) == 11
    with QueueState.open(tmp_path / "queue", A) as q:
        q.admit_record(A, STREAM, 10, 11, [obs(i) for i in range(40)])
        assert q.heartbeat(A) == hb and q.next_batch(A).rows == events


@pytest.mark.parametrize(
    "phase",
    [
        "before_terminal",
        "after_terminal",
        "before_cursor",
        "after_cursor",
        "before_unlink",
        "after_unlink",
    ],
)
def test_rejection_journal_precedes_cursor_and_unlink(tmp_path, phase):
    with queue(tmp_path, 1) as q:
        p = q.next_batch(A)
        body = receipt(p)
        row = body["results"][0]
        row.update(outcome="rejected", reason="identity_conflict")
        del row["event_id"]
        data = json.dumps(body).encode()

        def cut(name):
            if phase == name:
                raise OSError("synthetic")

        q._boundary = cut
        with pytest.raises(QueueError):
            q.apply_receipt(A, p, data)
    with QueueState.open(tmp_path / "queue", A) as q:
        if phase == "before_terminal":
            assert q.heartbeat(A)["totals"]["server_conflict"] == 0
            q.apply_receipt(A, p, data)
        assert q.next_batch(A) is None
        hb = q.heartbeat(A)
        assert hb["totals"]["server_conflict"] == 1 and hb["queue_bytes"] == 0
        assert q.apply_receipt(A, p, data) == 0


def test_clock_regression_does_not_extend_expiry(tmp_path, monkeypatch):
    now = 1_000_000
    monkeypatch.setattr(state_module.time, "time", lambda: now)
    with queue(tmp_path, 1) as q:
        now -= 1000
        q.admit_record(A, STREAM, 10, 11, [obs(2)])
        assert len(q.next_batch(A).rows) == 2
        now += 1000 + 604800
        assert q.next_batch(A) is None
        hb = q.heartbeat(A)
        assert hb["totals"]["expired"] == 2 and hb["pending"] == 0
    with QueueState.open(tmp_path / "queue", A) as q:
        assert q.heartbeat(A) == hb


def test_invalid_head_requires_admission_evidence_and_preserves_suffix(
    tmp_path, monkeypatch
):
    # Simulate an old validator defect, keeping owner, index and original digest authentic.
    invalid = obs(2)
    invalid["kind"] = "tool.call"
    with QueueState.create(tmp_path / "q", A) as q:
        with monkeypatch.context() as m:
            m.setattr(admission, "validate_observation", lambda o: None)
            q.admit_record(A, STREAM, 0, 1, [obs(1), invalid, obs(3)])
        p = q.next_batch(A)
        assert len(p.rows) == 1
        with pytest.raises(QueueError):
            q.finalize_invalid_head(A, p.rows[0].ordinal, p.rows[0].digest)
        q.apply_receipt(A, p, json.dumps(receipt(p)).encode())
    with QueueState.open(tmp_path / "q", A) as q:
        with pytest.raises(InvalidHead) as exc:
            q.next_batch(A)
        assert exc.value.ordinal == 2
        q.finalize_invalid_head(A, 2, exc.value.admission_digest)
        assert q.heartbeat(A)["totals"]["row_schema_invalid"] == 1
        assert [r.ordinal for r in q.next_batch(A).rows] == [3]


def test_failed_loss_commit_holds_checkpoint(tmp_path):
    with queue(tmp_path, 0) as q:

        def cut(name):
            if name == "before_intent":
                raise OSError("sensitive path")

        q._boundary = cut
        with pytest.raises(QueueError, match="^blocked_storage$"):
            q.admit_record(A, STREAM, 10, 11, [{"raw": "secret"}])
        assert q.checkpoint(A, STREAM) == 10
        assert q.heartbeat(A)["state"] == "blocked_storage"
    with QueueState.open(tmp_path / "queue", A) as q:
        q.admit_record(A, STREAM, 10, 11, [{"raw": "secret"}])
        assert (
            q.checkpoint(A, STREAM) == 11
            and q.heartbeat(A)["totals"]["invalid_shape"] == 1
        )
        assert all(
            b'"raw"' not in p.read_bytes() for p in (tmp_path / "queue").iterdir()
        )


def test_real_default_budget_rotation_and_bounded_rollback_journal(
    tmp_path, monkeypatch
):
    # Exercise default limits at actual sizes with 8 MiB of distinct projected rows.
    peak = 0
    first = None
    with QueueState.create(tmp_path / "q", A) as q:

        def observe(name):
            nonlocal peak
            files = [tmp_path / "q" / "state.db", tmp_path / "q" / "state.db-journal"]
            peak = max(peak, sum(p.stat().st_size for p in files if p.exists()))

        q._db.set_trace_callback(observe)
        template = obs()
        for i in range(200):
            observations = [
                dict(
                    template,
                    source=dict(
                        template["source"], parser_observation_token=f"{i*64+k:064x}"
                    ),
                )
                for k in range(64)
            ]
            q.admit_record(A, STREAM, i, i + 1, observations)
            if i == 0:
                first = q.next_batch(A).rows
            if q.heartbeat(A)["totals"]["capacity_rejected"]:
                break
        hb = q.heartbeat(A)
        assert (8 << 20) - 1500 < hb["queue_bytes"] <= 8 << 20
        assert hb["totals"]["capacity_rejected"] == ((i + 1) * 64 - hb["pending"]) > 0
        assert all(p.stat().st_size <= 256 << 10 for p in q._spool.segments())
        assert len(q._spool.segments()) >= 32 and q.next_batch(A).rows == first
        assert 0 < peak < 1 << 20
        assert q.checkpoint(A, STREAM) == i + 1


@pytest.mark.parametrize("where", ["before_terminal", "after_terminal"])
def test_restart_invalid_local_disposition_without_receipt(
    tmp_path, monkeypatch, where
):
    invalid = obs(1)
    invalid["kind"] = "tool.call"
    with QueueState.create(tmp_path / "q", A) as q:
        with monkeypatch.context() as m:
            m.setattr(admission, "validate_observation", lambda _: None)
            q.admit_record(A, STREAM, 0, 1, [invalid, obs(2)])
        with pytest.raises(InvalidHead) as exc:
            q.next_batch(A)
        sha = exc.value.admission_digest

        def cut(phase):
            if phase == where:
                raise OSError

        q._boundary = cut
        with pytest.raises(QueueError, match="blocked_storage"):
            q.finalize_invalid_head(A, 1, sha)
    with QueueState.open(tmp_path / "q", A) as q:
        if where == "before_terminal":
            assert q.heartbeat(A)["totals"]["row_schema_invalid"] == 0
            q.finalize_invalid_head(A, 1, sha)
        assert q.heartbeat(A)["totals"]["row_schema_invalid"] == 1
        assert [r.ordinal for r in q.next_batch(A).rows] == [2]
        with pytest.raises(QueueError):
            q.finalize_invalid_head(A, 1, sha)


def test_short_segment_prefix_recovered_and_alien_bytes_quarantined(tmp_path):
    with queue(tmp_path, 0) as q:

        def cut(phase):
            if phase == "after_intent":
                raise OSError

        q._boundary = cut
        with pytest.raises(QueueError):
            q.admit_record(A, STREAM, 10, 12, [obs(1), obs(2)])
        import sqlite3

        with sqlite3.connect(tmp_path / "queue" / "state.db") as db:
            journal = json.loads(
                db.execute("select payload from journal").fetchone()[0]
            )
        seg, offset, row = journal["intent"]["rows"][0]
        path = tmp_path / "queue" / f"{seg:020d}.jsonl"
        path.touch(mode=0o600)
        path.write_bytes(
            json.dumps(row, sort_keys=True, separators=(",", ":")).encode()[:87]
        )
    with QueueState.open(tmp_path / "queue", A) as q:
        assert [r.ordinal for r in q.next_batch(A).rows] == [1, 2]
    with path.open("r+b") as f:
        f.seek(10)
        f.write(b"XX")
    with QueueState.open(tmp_path / "queue", A) as q:
        with pytest.raises(QueueError, match="quarantined"):
            q.next_batch(A)


def test_expired_rows_reclaim_space_before_capacity_disposition(tmp_path, monkeypatch):
    monkeypatch.setattr(state_module, "DATA_LIMIT", 1600)
    now = 1_000_000
    monkeypatch.setattr(state_module.time, "time", lambda: now)
    with queue(tmp_path, 1) as q:
        now += 604800
        q.admit_record(A, STREAM, 10, 11, [obs(2)])
        assert [r.ordinal for r in q.next_batch(A).rows] == [2]
        assert q.heartbeat(A)["totals"]["expired"] == 1
        assert q.heartbeat(A)["totals"]["capacity_rejected"] == 0


def test_unknown_admission_contract_holds_prepared_rows_without_advancing(
    tmp_path, monkeypatch
):
    with queue(tmp_path, 0) as q:

        def cut(name):
            if name == "after_intent":
                raise OSError()

        q._boundary = cut
        with pytest.raises(QueueError):
            q.admit_record(A, STREAM, 10, 11, [obs(2)])
    with monkeypatch.context() as m:
        m.setattr(admission, "CONTRACT", "unrecognized")
        with QueueState.open(tmp_path / "queue", A) as q:
            assert q.checkpoint(A, STREAM) == 10
            assert q.heartbeat(A)["state"] == "contract_mismatch"
            with pytest.raises(QueueError, match="contract_mismatch"):
                q.next_batch(A)
    with QueueState.open(tmp_path / "queue", A) as q:
        assert q.checkpoint(A, STREAM) == 11 and len(q.next_batch(A).rows) == 1


@pytest.mark.parametrize("cut", ["after_terminal", "after_unlink"])
def test_process_death_preserves_committed_rejection(tmp_path, cut):
    import os
    import subprocess
    import sys

    with queue(tmp_path, 1):
        pass
    script = """
from test_queue_ownership import A,QueueState,receipt
from pathlib import Path
import sys,os,json
q=QueueState.open(Path(sys.argv[1]),A)
p=q.next_batch(A)
body=receipt(p)
r=body["results"][0]
del r["event_id"]
r.update(outcome="rejected",reason="retired_ordinal")
def crash(phase):
    if phase==sys.argv[2]: os._exit(84)
q._boundary=crash
q.apply_receipt(A,p,json.dumps(body).encode())
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path / "queue"), cut],
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
    )
    assert result.returncode == 84
    with QueueState.open(tmp_path / "queue", A) as q:
        assert q.next_batch(A) is None
        hb = q.heartbeat(A)
        assert hb["queue_bytes"] == 0 and hb["totals"]["retired_ordinal"] == 1


def test_canonical_size_boundary():
    admission.check_observation_size(b"x" * 4096)
    with pytest.raises(admission.Invalid):
        admission.check_observation_size(b"x" * 4097)


def test_heartbeat_expiry_preserves_quarantined_suffix(tmp_path, monkeypatch):
    clock = [1_000_000]
    monkeypatch.setattr(state_module.time, "time", lambda: clock[0])
    with queue(tmp_path, 1) as q:
        segment = q._spool.segments()[0]
        with segment.open("ab") as f:
            f.write(b"unexpected")
        damaged = segment.read_bytes()
        before = q._load()
        with pytest.raises(QueueError, match="quarantined"):
            q.next_batch(A)
        clock[0] += 604800
        with pytest.raises(QueueError, match="quarantined"):
            q.heartbeat(A)
        after = q._load()
        for field in ("cursor", "totals", "pending", "segments", "clock"):
            assert after[field] == before[field]
        assert segment.read_bytes() == damaged


@pytest.mark.parametrize(
    "cut",
    [
        "compact_intent",
        "compact_write",
        "compact_progress",
        "compact_truncate",
        "compact_commit",
    ],
)
def test_mixed_age_expiry_reclaims_bytes_across_process_death(
    tmp_path, cut, monkeypatch
):
    import os
    import sys
    import subprocess

    clock = [1_000_000]
    monkeypatch.setattr(state_module.time, "time", lambda: clock[0])
    with QueueState.create(tmp_path / "q", A) as q:
        q.admit_record(A, STREAM, 0, 1, [obs(111)])
        clock[0] += 86400
        q.admit_record(A, STREAM, 1, 2, [obs(i) for i in range(220, 226)])
        original = q.next_batch(A).rows
        seg = q._spool.segments()[0]
        old_size = seg.stat().st_size
    script = """
from test_queue_ownership import A,QueueState
from tidewall_collector import state
from pathlib import Path
import os,sys
state.time.time=lambda:1000000+604800
q=QueueState.open(Path(sys.argv[1]),A)
def cut(name):
    if name==sys.argv[2]: os._exit(71)
q._boundary=cut
q.heartbeat(A)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path / "q"), cut],
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
    )
    assert result.returncode == 71
    clock[0] = 1_604_800
    with QueueState.open(tmp_path / "q", A) as q:
        p = q.next_batch(A)
        assert p.rows == original[1:]
        assert (
            original[0].data not in seg.read_bytes()
            and len(seg.read_bytes()) < old_size
        )
        hb = q.heartbeat(A)
        assert hb["totals"]["expired"] == 1 and hb["queue_bytes"] == seg.stat().st_size
        assert q.apply_receipt(A, p, json.dumps(receipt(p)).encode()) == 6


def test_acknowledged_prefix_expires_during_newer_inflight_receipt(
    tmp_path, monkeypatch
):
    clock = [1_000_000]
    monkeypatch.setattr(state_module.time, "time", lambda: clock[0])
    with queue(tmp_path, 1) as q:
        clock[0] += 1000
        q.admit_record(A, STREAM, 10, 11, [obs(99)])
        original = q.next_batch(A)
        q.apply_receipt(A, original, json.dumps(receipt(original, 1)).encode())
        p = q.next_batch(A)
        clock[0] = 1_604_800
        assert q.heartbeat(A)["totals"]["expired"] == 0
        assert original.rows[0].data not in q._spool.segments()[0].read_bytes()
        assert q.apply_receipt(A, p, json.dumps(receipt(p)).encode()) == 1


@pytest.mark.parametrize("failure", ["short_write", "post_truncate"])
def test_real_file_reclamation_errors_retry_same_logical_cursor(
    tmp_path, monkeypatch, failure
):
    import os

    clock = [1_000_000]
    monkeypatch.setattr(state_module.time, "time", lambda: clock[0])
    with queue(tmp_path, 1) as q:
        clock[0] += 10
        q.admit_record(A, STREAM, 10, 11, [obs(501), obs(502)])
        before = q.next_batch(A)
        segment = q._spool.segments()[0]
        peak = segment.stat().st_size
        clock[0] = 1_604_800
        with monkeypatch.context() as m:
            if failure == "short_write":
                real = os.pwrite

                def short(fd, data, offset):
                    return real(fd, data[: len(data) // 2], offset)

                m.setattr(os, "pwrite", short)
            else:
                truncate = os.ftruncate

                def fail(fd, size):
                    truncate(fd, size)
                    raise OSError("synthetic fault")

                m.setattr(os, "ftruncate", fail)
            with pytest.raises(QueueError, match="blocked_storage"):
                q.heartbeat(A)
        assert sum(p.stat().st_size for p in q._spool.segments()) <= peak
    with QueueState.open(tmp_path / "queue", A) as q:
        p = q.next_batch(A)
        assert p.rows == before.rows[1:] and q.heartbeat(A)["totals"]["expired"] == 1
        assert before.rows[0].data not in segment.read_bytes()
        q.admit_record(A, STREAM, 11, 12, [obs(503)])
        assert q.apply_receipt(A, p, json.dumps(receipt(p)).encode()) == 2
        assert q.next_batch(A).rows[0].ordinal == 4


def test_restart_between_expiry_cursor_and_compaction_purges_mixed_prefix(
    tmp_path, monkeypatch
):
    clock = [1_000_000]
    monkeypatch.setattr(state_module.time, "time", lambda: clock[0])
    with queue(tmp_path, 1) as q:
        clock[0] += 10
        q.admit_record(A, STREAM, 10, 11, [obs(104)])
        original = q.next_batch(A).rows
        seg = q._spool.segments()[0]
        clock[0] = 1_604_800

        def cut(phase):
            if phase == "after_cursor":
                raise OSError()

        q._boundary = cut
        with pytest.raises(QueueError):
            q.heartbeat(A)
    with QueueState.open(tmp_path / "queue", A) as q:
        assert original[0].data not in seg.read_bytes()
        assert q.next_batch(A).rows == original[1:]


def test_reopen_preserves_unexplained_bytes_after_pending_unlink(tmp_path):
    with queue(tmp_path, 1) as q:
        p = q.next_batch(A)
        seg = q._spool.segments()[0]

        def cut(name):
            if name == "before_unlink":
                raise OSError()

        q._boundary = cut
        with pytest.raises(QueueError):
            q.apply_receipt(A, p, json.dumps(receipt(p)).encode())
    with seg.open("ab") as f:
        f.write(b"unexplained")
    original = seg.read_bytes()
    with pytest.raises(QueueError, match="quarantined"):
        QueueState.open(tmp_path / "queue", A)
    assert seg.read_bytes() == original

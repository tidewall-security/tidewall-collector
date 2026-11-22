import json
import os
import shutil
import subprocess
import sys

import pytest
from test_queue_ownership import A, FIX, STREAM, obs

from tidewall_collector.reader import read_fixture
from tidewall_collector.state import QueueError, QueueState


@pytest.mark.parametrize(
    "phase",
    [
        "before_intent",
        "after_intent",
        "before_append",
        "after_append",
        "after_first_row",
        "before_fsync",
        "after_fsync",
        "before_append_2",
        "after_append_2",
        "before_fsync_2",
        "after_fsync_2",
        "before_checkpoint",
        "after_checkpoint",
    ],
)
def test_process_crash_replays_whole_framed_record(tmp_path, phase):
    with QueueState.create(tmp_path / "q", A):
        pass
    script = """
import os,sys
from pathlib import Path
from test_queue_ownership import A,STREAM,obs
from tidewall_collector.state import QueueState
from collections import Counter
seen=Counter()
q=QueueState.open(Path(sys.argv[1]),A)
def cut(name):
    seen[name]+=1
    if name == sys.argv[2] or f"{name}_{seen[name]}"==sys.argv[2]: os._exit(77)
q._boundary=cut
q._spool._boundary=cut
q.admit_record(A,STREAM,0,15,[obs(201),obs(202)])
"""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    assert (
        subprocess.run(
            [sys.executable, "-c", script, str(tmp_path / "q"), phase], env=env
        ).returncode
        == 77
    )
    import sqlite3

    with sqlite3.connect(tmp_path / "q" / "state.db") as db:
        j = json.loads(db.execute("select payload from journal").fetchone()[0])
        assert j["streams"].get(str(STREAM), 0) == (
            15 if phase == "after_checkpoint" else 0
        )
    with QueueState.open(tmp_path / "q", A) as state:
        state.admit_record(A, STREAM, 0, 15, [obs(201), obs(202)])
        assert state.checkpoint(A, STREAM) == 15
        assert [
            (r.ordinal, json.loads(r.data)["source"]["parser_observation_token"])
            for r in state.next_batch(A).rows
        ] == [(1, f"{201:064x}"), (2, f"{202:064x}")]


def fixtures(root):
    root.mkdir()
    for name in ("claude-session.jsonl", "claude-hooks.json"):
        shutil.copyfile(FIX / name, root / name)
    return root


def test_frozen_reader_restarts_context_and_never_persists_source(tmp_path):
    root = fixtures(tmp_path / "fixture")
    path = root / "claude-session.jsonl"
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:2]))
    with QueueState.create(tmp_path / "q", A) as state:
        read_fixture(root, A, state)
        first = state.next_batch(A)
        assert len(first.rows) == 8
    with path.open("ab") as f:
        f.write(b"".join(lines[2:]))
    with QueueState.open(tmp_path / "q", A) as state:
        read_fixture(root, A, state)
        batch = state.next_batch(A)
        assert len(batch.rows) == 11
        assert first.rows == batch.rows[:8]
        obs3 = json.loads(batch.rows[8].data)
        assert obs3["tool_name"] == "Read" and "missing_tool_call" not in obs3["gaps"]
        hb = state.heartbeat(A)
        assert hb["state"] == "source_incomplete" and hb["totals"]["invalid_json"] == 1
        assert (
            hb["totals"]["unsupported_record"] == 1
            and hb["totals"]["incomplete_tail"] == 0
        )
        read_fixture(root, A, state)
        assert state.next_batch(A).rows == batch.rows and state.heartbeat(A) == hb
    for p in (tmp_path / "q").iterdir():
        assert (
            b"FIXTURE_" not in p.read_bytes()
            and str(root).encode() not in p.read_bytes()
        )


@pytest.mark.parametrize("change", ["replace", "truncate"])
def test_seal_partial_tail_and_read_new_generation(tmp_path, change):
    root = fixtures(tmp_path / "fixture")
    p = root / "claude-session.jsonl"
    with QueueState.create(tmp_path / "q", A) as state:
        read_fixture(root, A, state)
        if change == "replace":
            p.rename(tmp_path / "sealed")
        p.write_bytes(b"23\n")
        for _ in range(2):
            with pytest.raises(QueueError, match="source_changed"):
                read_fixture(root, A, state)
        assert state.heartbeat(A)["pending"] == 11
        read_fixture(root, A, state, independent=frozenset({"transcript"}))
        read_fixture(root, A, state)
        totals = state.heartbeat(A)["totals"]
        assert totals["incomplete_tail"] == 1 and totals["invalid_shape"] == 1


def test_reader_bounds_and_does_not_follow_links(tmp_path):
    root = fixtures(tmp_path / "fixture")
    p = root / "claude-session.jsonl"
    p.write_bytes(b"x" * 65537 + b"\n23\n")
    (root / "claude-hooks.json").write_bytes(b" " * 262145)
    with QueueState.create(tmp_path / "q", A) as state:
        read_fixture(root, A, state)
        read_fixture(root, A, state)
        totals = state.heartbeat(A)["totals"]
        assert totals["oversized_input"] == 2 and totals["invalid_shape"] == 1
        p.unlink()
        p.symlink_to(FIX / "claude-session.jsonl")
        with pytest.raises(QueueError):
            read_fixture(root, A, state)


def test_hook_uuid_recovered_exactly_and_fresh_invocation_distinct(tmp_path):
    root = fixtures(tmp_path / "fixture")
    (root / "claude-session.jsonl").write_bytes(b"")
    with QueueState.create(tmp_path / "q", A) as q:

        def cut(phase):
            if phase == "after_intent":
                raise OSError()

        q._boundary = cut
        with pytest.raises(QueueError):
            read_fixture(root, A, q)
        import sqlite3

        with sqlite3.connect(tmp_path / "q" / "state.db") as db:
            j = json.loads(db.execute("select payload from journal").fetchone()[0])
        expected = j["intent"]["rows"][0][2][4]["source"]["collector_observation_id"]
    with QueueState.open(tmp_path / "q", A) as q:
        read_fixture(root, A, q)
        hb = q.heartbeat(A)
        rows = q.next_batch(A).rows
        assert (
            len(rows) == 4
            and json.loads(rows[0].data)["source"]["collector_observation_id"]
            == expected
        )
        existing = json.loads((root / "claude-hooks.json").read_bytes())
        existing.append(existing[0])
        (root / "claude-hooks.json").write_text(json.dumps(existing, indent=2))
        read_fixture(root, A, q)
        updated = q.next_batch(A).rows
        assert len(updated) == 5 and updated[:4] == rows
        assert (
            json.loads(updated[4].data)["source"]["collector_observation_id"]
            != expected
        )
        assert q.heartbeat(A)["revision"] > hb["revision"]


def test_missing_or_unrecognized_and_nested_symlink_fixture_paths(tmp_path):
    root = fixtures(tmp_path / "fixture")
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    with QueueState.create(tmp_path / "q", A) as q:
        with pytest.raises(QueueError, match="invalid_fixture"):
            read_fixture(alias / "fixture", A, q)
        (root / "extra").touch()
        with pytest.raises(QueueError, match="invalid_fixture"):
            read_fixture(root, A, q)
        assert q.heartbeat(A)["pending"] == 0


def test_stream_seal_after_crash_before_tail_marker(tmp_path):
    root = fixtures(tmp_path / "fixture")
    p = root / "claude-session.jsonl"
    with QueueState.create(tmp_path / "q", A) as q:

        def cut(owner, stream, pending):
            assert pending
            raise QueueError("blocked_storage")

        q.fixture_tail = cut
        with pytest.raises(QueueError):
            read_fixture(root, A, q)
    p.rename(tmp_path / "old")
    p.write_bytes(b"")
    with QueueState.open(tmp_path / "q", A) as q:
        with pytest.raises(QueueError, match="source_changed"):
            read_fixture(root, A, q)
        assert q.heartbeat(A)["totals"]["incomplete_tail"] == 1


def test_oversized_hook_container_after_previous_checkpoint_records_one_loss(tmp_path):
    root = fixtures(tmp_path / "fixture")
    with QueueState.create(tmp_path / "q", A) as q:
        read_fixture(root, A, q)
        with (root / "claude-hooks.json").open("ab") as f:
            f.write(b" " * (256 << 10))
        read_fixture(root, A, q)
        read_fixture(root, A, q)
        assert (
            q.heartbeat(A)["totals"]["oversized_input"] == 1
            and q.heartbeat(A)["pending"] == 11
        )


@pytest.mark.parametrize("failure", ["data_fsync", "directory_fsync", "sqlite_write"])
def test_storage_error_holds_durable_source_position_and_retry_keeps_rows(
    tmp_path, monkeypatch, failure
):
    import sqlite3
    import openaidr.sensor.spool as spool
    from test_queue_ownership import queue

    with queue(tmp_path, 0) as q:
        with monkeypatch.context() as m:

            def fail(*args):
                raise OSError("private sentinel")

            if failure == "data_fsync":
                m.setattr(spool.os, "fsync", fail)
            elif failure == "directory_fsync":
                m.setattr(spool, "sync_directory", fail)
            else:

                def deny(action, *args):
                    return (
                        sqlite3.SQLITE_DENY
                        if action == sqlite3.SQLITE_INSERT
                        else sqlite3.SQLITE_OK
                    )

                q._db.set_authorizer(deny)
            with pytest.raises(QueueError, match="^blocked_storage$"):
                q.admit_record(A, STREAM, 10, 11, [obs(10), obs(11)])
            assert q.checkpoint(A, STREAM) == 10
        q._db.set_authorizer(None)
        assert q.heartbeat(A)["state"] == "blocked_storage"
    with QueueState.open(tmp_path / "queue", A) as q:
        q.admit_record(A, STREAM, 10, 11, [obs(10), obs(11)])
        assert q.checkpoint(A, STREAM) == 11
        assert [r.ordinal for r in q.next_batch(A).rows] == [1, 2]


@pytest.mark.parametrize(
    "channel,name",
    [("transcript", "claude-session.jsonl"), ("hook", "claude-hooks.json")],
)
def test_observe_replacement_then_restore_original_never_relabels(
    tmp_path, channel, name
):
    root = fixtures(tmp_path / "fixture")
    with QueueState.create(tmp_path / "q", A) as q:
        read_fixture(root, A, q)
        rows = q.next_batch(A).rows
        old = tmp_path / "original"
        (root / name).rename(old)
        replacement = b"[]" if channel == "hook" else b"{}\n"
        (root / name).write_bytes(replacement)
        with pytest.raises(QueueError, match="source_changed"):
            read_fixture(root, A, q)
        (root / name).rename(tmp_path / "replacement")
        old.rename(root / name)
        with pytest.raises(QueueError, match="stale_fixture"):
            read_fixture(root, A, q, independent=frozenset({channel}))
        assert q.next_batch(A).rows == rows
        (root / name).rename(old)
        (tmp_path / "replacement").rename(root / name)
        read_fixture(root, A, q, independent=frozenset({channel}))
        assert q.next_batch(A).rows[: len(rows)] == rows


def test_restored_same_inode_generation_after_confirmed_truncation_stays_sealed(
    tmp_path,
):
    root = fixtures(tmp_path / "fixture")
    p = root / "claude-session.jsonl"
    original = p.read_bytes()
    old_time = p.stat().st_mtime_ns
    with QueueState.create(tmp_path / "q", A) as q:
        read_fixture(root, A, q)
        p.write_bytes(b"{}\n")
        read_fixture(root, A, q, independent=frozenset({"transcript"}))
        previous = q.next_batch(A).rows
        p.write_bytes(original)
        os.utime(p, ns=(old_time, old_time))
        with pytest.raises(QueueError, match="stale_fixture"):
            read_fixture(root, A, q, independent=frozenset({"transcript"}))
        assert q.next_batch(A).rows == previous

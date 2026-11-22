import copy
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from tidewall_collector.state import Owner, QueueError, QueueState

FIX = Path(__file__).parent / "fixtures"
BINDINGS = json.loads((FIX / "re-enrollment.json").read_bytes())
A, B = [
    Owner(enrollment["server_origin"], UUID(enrollment["device_id"]))
    for enrollment in (BINDINGS["queued_enrollment"], BINDINGS["proposed_enrollment"])
]
STREAM = UUID("00000000-0000-4000-8000-000000000001")


def obs(i=1):
    row = json.loads(
        json.loads((FIX / "collector_v1.json").read_bytes())["observation_vectors"][0][
            "canonical"
        ]
    )
    row["source"]["parser_observation_token"] = f"{i:064x}"
    return row


def receipt(batch, count=None):
    return dict(
        version=1,
        enrollment_id=str(A.device_id),
        batch_id=str(batch.batch_id),
        results=[
            dict(
                ordinal=r.ordinal,
                digest=r.digest,
                outcome="accepted",
                event_id=str(uuid4()),
            )
            for r in batch.rows[:count]
        ],
    )


def queue(tmp_path, count=3):
    state = QueueState.create(tmp_path / "queue", A)
    state.admit_record(A, STREAM, 0, 10, [obs(i) for i in range(count)])
    return state


def test_enrollment_authority_and_inflight_generation(tmp_path):
    with queue(tmp_path) as state:
        p = state.next_batch(A)
        first_key = state.projection_key(A)
        for wrong in (B, Owner("https://other.invalid", A.device_id)):
            for op in (
                lambda: state.next_batch(wrong),
                lambda: state.admit_record(wrong, STREAM, 10, 11, [obs()]),
                lambda: state.apply_receipt(wrong, p, json.dumps(receipt(p)).encode()),
                lambda: state.projection_key(wrong),
            ):
                with pytest.raises(QueueError, match="owner_mismatch"):
                    op()
        q = state.next_batch(A)
        assert q.body != p.body and q.rows == p.rows
        with pytest.raises(QueueError):
            state.apply_receipt(A, p, json.dumps(receipt(p)).encode())
        data = json.dumps(receipt(q, 1)).encode()
        assert state.apply_receipt(A, q, data) == 1
        assert state.apply_receipt(A, q, data) == 0
    with pytest.raises(QueueError, match="owner_mismatch"):
        QueueState.open(tmp_path / "queue", B)
    with QueueState.open(tmp_path / "queue", A) as state:
        assert first_key == state.projection_key(A)
        assert state.next_batch(A).rows == q.rows[1:]
    shutil.move(tmp_path / "queue", tmp_path / "moved")
    with pytest.raises(QueueError, match="quarantined"):
        QueueState.open(tmp_path / "moved", A)


@pytest.mark.parametrize(
    "mutation",
    [
        "gap",
        "reverse",
        "duplicate",
        "extra",
        "digest",
        "ordinal",
        "unknown",
        "missing_id",
        "foreign",
        "wrong_batch",
        "wrong_type",
        "unknown_field",
        "false_rejection",
        "size",
        "deep",
        "duplicate_key",
        "invalid_utf8",
        "forged_cursor",
    ],
)
def test_bad_receipt_never_moves_cursor(tmp_path, mutation):
    with queue(tmp_path) as state:
        p = state.next_batch(A)
        body = receipt(p)
        rows = body["results"]
        raw = None
        if mutation == "gap":
            del rows[1]
        elif mutation == "reverse":
            rows.reverse()
        elif mutation == "duplicate":
            rows[1] = rows[0]
        elif mutation == "extra":
            rows.append(copy.copy(rows[-1]))
        elif mutation == "digest":
            rows[-1]["digest"] = "a" * 64
        elif mutation == "ordinal":
            rows[-1]["ordinal"] += 1
        elif mutation == "unknown":
            rows[-1]["outcome"] = "success"
        elif mutation == "missing_id":
            del rows[0]["event_id"]
        elif mutation == "foreign":
            body["enrollment_id"] = str(B.device_id)
        elif mutation == "wrong_batch":
            body["batch_id"] = str(uuid4())
        elif mutation == "wrong_type":
            rows[0]["ordinal"] = True
        elif mutation == "unknown_field":
            rows[0]["cursor"] = 911
        elif mutation == "false_rejection":
            rows[0].update(reason="transient", outcome="rejected")
        elif mutation == "size":
            raw = b" " * 65537
        elif mutation == "deep":
            raw = b"[" * 1500 + b"]" * 1500
        elif mutation == "duplicate_key":
            raw = (
                json.dumps(body)
                .replace('"version": 1', '"version": 0, "version": 1')
                .encode()
            )
        elif mutation == "invalid_utf8":
            raw = b"\xff"
        elif mutation == "forged_cursor":
            p = replace(p, rows=(replace(p.rows[0], end=(99, 99)), *p.rows[1:]))
        with pytest.raises(QueueError):
            state.apply_receipt(A, p, raw or json.dumps(body).encode())
        assert json.loads(state.next_batch(A).body)["rows"][0]["ordinal"] == 1


@pytest.mark.parametrize(
    "damage",
    [
        "missing_key",
        "different_key",
        "missing_db",
        "manifest",
        "cursor",
        "unknown_segment",
    ],
)
def test_damaged_state_never_adopts_rows(tmp_path, damage):
    with queue(tmp_path):
        pass
    path = tmp_path / "queue"
    if damage == "missing_key":
        (path / "key").unlink()
    elif damage == "different_key":
        (path / "key").write_bytes(os.urandom(32))
    elif damage == "missing_db":
        (path / "state.db").unlink()
    elif damage == "manifest":
        (path / "manifest.json").write_bytes(b"{}")
    elif damage == "cursor":
        import sqlite3

        with sqlite3.connect(path / "state.db") as db:
            db.execute(
                "update journal set payload = replace(cast(payload as text), '\"cursor\":[0,0]', '\"cursor\":[0,42]')"
            )
    elif damage == "unknown_segment":
        (path / "00000000000000000999.jsonl").touch(mode=0o600)
    with pytest.raises(QueueError, match="quarantined"):
        QueueState.open(path, A)
    with pytest.raises(QueueError):
        QueueState.create(path, A)
    assert list(path.glob("*.jsonl"))


def test_second_process_excluded_and_offboard_erases_owned_files(tmp_path):
    with queue(tmp_path) as state:
        path = tmp_path / "queue"
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
        script = "from tidewall_collector.state import *\nfrom pathlib import Path\nfrom uuid import UUID\nimport sys\ntry: QueueState.open(Path(sys.argv[1]), Owner(sys.argv[2],UUID(sys.argv[3])))\nexcept QueueError as exc: print(exc.code)"
        r = subprocess.run(
            [sys.executable, "-c", script, str(path), A.origin, str(A.device_id)],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        assert r.stdout.strip() == "busy"
        assert path.stat().st_mode & 0o777 == 0o700
        assert all(p.stat().st_mode & 0o777 == 0o600 for p in path.iterdir())
        with pytest.raises(QueueError):
            state.offboard(B)
        state.offboard(A)
        assert not path.exists()


def test_refusal_revalidation_and_revoke_inflight_are_bound_to_saved_batch(
    tmp_path, monkeypatch
):
    from tidewall_collector import admission

    with queue(tmp_path) as q:
        p = q.next_batch(A)
        assert q.invalid_rows(A, p) == ()
        original = admission.validate_observation

        def narrowed(o):
            if o["source"]["parser_observation_token"] == f"{1:064x}":
                raise admission.Invalid()
            original(o)

        with monkeypatch.context() as m:
            m.setattr(admission, "validate_observation", narrowed)
            assert q.invalid_rows(A, p) == ((2, p.rows[1].digest),)
        q.cancel_flight(A)
        with pytest.raises(QueueError):
            q.apply_receipt(A, p, json.dumps(receipt(p)).encode())
        q.set_contract_mismatch(A)
        with pytest.raises(QueueError, match="contract_mismatch"):
            q.next_batch(A)
        assert q.heartbeat(A)["pending"] == 3
    with QueueState.open(tmp_path / "queue", A) as q:
        assert q.heartbeat(A)["state"] == "contract_mismatch"
        q.set_contract_mismatch(A, False)
        assert q.next_batch(A).rows == p.rows


def test_offboard_recreate_same_owner_cannot_use_old_receipt(tmp_path):
    with queue(tmp_path, 1) as q:
        p = q.next_batch(A)
        key = q.projection_key(A)
        q.offboard(A)
    with queue(tmp_path, 1) as q:
        fresh = q.next_batch(A)
        assert fresh.generation != p.generation and key != q.projection_key(A)
        with pytest.raises(QueueError):
            q.apply_receipt(A, p, json.dumps(receipt(p)).encode())
        assert q.heartbeat(A)["pending"] == 1

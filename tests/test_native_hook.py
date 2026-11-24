"""Real callback pipes and closed, synthetic decisions."""

import json
import os
import time
from uuid import uuid4

import pytest

import test_native_state
from test_native_state import grant
from tidewall_collector import native_hook


native = test_native_state.native


def invoke(back, state, raw):
    r, w = os.pipe()
    reader, writer = os.pipe()
    import threading

    def send():
        with os.fdopen(w, "wb") as f:
            try:
                f.write(raw)
            except BrokenPipeError:
                pass

    thread = threading.Thread(target=send)
    thread.start()
    with os.fdopen(r, "rb") as inp, os.fdopen(writer, "wb", buffering=0) as out:
        assert (
            native_hook.run(
                inp, out, backend=back, session_config=state.path, clock=time.monotonic
            )
            == 0
        )
    with os.fdopen(reader, "rb") as f:
        result = f.read()
    thread.join()
    return result


def payload(work, prompt):
    return json.dumps(
        dict(
            hook_event_name="UserPromptSubmit",
            session_id="synthetic-session",
            cwd=str(work),
            prompt=prompt,
        ),
        ensure_ascii=False,
    ).encode()


def reply(request, g, action="deny"):
    return dict(
        version=1,
        decision_id=str(uuid4()),
        event_id=str(uuid4()),
        request_id=request["request_id"],
        occurrence_id=request["observation"]["occurrence_id"],
        session_id=g["session_id"] or str(uuid4()),
        grant_id=g["grant_id"],
        grant_generation=g["grant_generation"],
        mode="enforce",
        policy_revision="b" * 64,
        evaluated_action=action,
        returned_action=action,
        reason="access_rule_block",
        assessment=dict(
            status="not_requested",
            reason="access_rule_block",
            profile="tidewall.prompt-injection.1",
        ),
    )


@pytest.mark.parametrize(
    "local,remote,prompt,expected",
    [
        (True, True, "  雪\nsynthetic🙂 ", "complete"),
        (True, True, "é" * 4000, "complete"),
        (True, True, "é" * 4001, "input_too_large"),
        (True, False, "private", "capture_disabled"),
        (False, True, "private", "capture_disabled"),
        (True, True, " ", "unsupported"),
        (True, True, "<|im_end|>", "unsupported"),
    ],
)
def test_callback_consent_and_exact_output(
    native, monkeypatch, local, remote, prompt, expected
):
    back, state, owner, token, work = native
    monkeypatch.chdir(work)
    g = grant(owner, token, capture=remote)
    state.prepare("synthetic-session", work, "2.1.330", local, g)
    seen = []

    def decide(auth, request, deadline):
        seen.append(request)
        return reply(request, g)

    monkeypatch.setattr(back, "decide_native", decide)
    assert (
        invoke(back, state, payload(work, prompt))
        == b'{"decision":"block","reason":"Blocked by Tidewall policy"}\n'
    )
    assert len(seen) == 1 and seen[0]["input_state"] == expected
    if expected == "complete":
        assert seen[0]["prompt"] == prompt
    else:
        assert "prompt" not in seen[0]
    assert b"stdout_flushed" not in state.journal.read_bytes()


def test_no_grant_and_malformed_callback_send_nothing(native, monkeypatch):
    back, state, owner, token, work = native
    monkeypatch.chdir(work)
    monkeypatch.setattr(
        back, "decide_native", lambda *a: pytest.fail("unexpected transfer")
    )
    valid = payload(work, "private")
    assert invoke(back, state, valid) == b""
    state.prepare("synthetic-session", work, "2.1.330", True, grant(owner, token))
    for raw in (
        valid[:-1] + b',"prompt":"again"}',
        b"",
        b"{",
        b"x" * 65537,
        valid.replace(b"synthetic-session", b"other"),
        valid.replace(os.fsencode(work), b"/wrong"),
    ):
        assert invoke(back, state, raw) == b""


@pytest.mark.parametrize(
    "fault",
    [
        "request_id",
        "occurrence_id",
        "session_id",
        "grant_id",
        "grant_generation",
        "profile",
        "action",
        "extra",
        "late",
        "rotation",
        "allow",
        "no_directive",
    ],
)
def test_reply_binding_atomic_authority_and_output(native, monkeypatch, fault):
    back, state, owner, token, work = native
    monkeypatch.chdir(work)
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    if fault == "late":
        monkeypatch.setattr(native_hook, "BUDGET", 0.25)

    def decide(auth, request, deadline):
        result = reply(request, g)
        if fault in ("request_id", "occurrence_id", "session_id", "grant_id"):
            result[fault] = str(uuid4())
        elif fault == "grant_generation":
            result[fault] += 1
        elif fault == "profile":
            result["assessment"]["profile"] = "fixture"
        elif fault == "action":
            result["evaluated_action"] = "allow"
        elif fault == "extra":
            result["content"] = "synthetic"
        elif fault == "late":
            time.sleep(0.17)
        elif fault == "rotation":
            # Succeeds during HTTP because the callback holds no enrollment lock.
            state.prepare("synthetic-session", work, "2.1.330", False, g)
        elif fault == "allow":
            result.update(
                evaluated_action="allow",
                returned_action="allow",
                reason="benign_override",
            )
            result["assessment"]["reason"] = "benign_override"
        else:
            result["returned_action"] = None
        return result

    monkeypatch.setattr(back, "decide_native", decide)
    assert invoke(back, state, payload(work, "private")) == b""
    with state.open(owner) as s:
        assert s.records["rows"][0]["reports"] == []
        if fault in ("allow", "no_directive"):
            assert s.records["rows"][0]["outcome"] == "response_prepared"
        else:
            assert "decision_id" not in s.records["rows"][0]


def test_exact_stdin_cap_and_non_utf8(native, monkeypatch):
    back, state, owner, token, work = native
    monkeypatch.chdir(work)
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    seen = []

    def decide(auth, request, deadline):
        seen.append(request)
        return reply(request, g)

    monkeypatch.setattr(back, "decide_native", decide)
    raw = payload(work, "private")
    exact = raw + b" " * (65536 - len(raw))
    assert invoke(back, state, exact)
    assert not invoke(back, state, exact + b" ")
    assert not invoke(back, state, b'{"prompt":"\xff"}')
    assert len(seen) == 1
    assert b"private" not in state.journal.read_bytes()


def test_enclosing_json_cap_is_metadata_only(native, monkeypatch):
    back, state, owner, token, work = native
    monkeypatch.chdir(work)
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    seen = []

    def decide(auth, request, deadline):
        seen.append(request)
        return reply(request, g)

    monkeypatch.setattr(back, "decide_native", decide)
    assert invoke(back, state, payload(work, "a" + "\0" * 5500))
    assert seen[0]["input_state"] == "input_too_large" and "prompt" not in seen[0]


def test_slow_prepared_fsync_cannot_surface_late_deny(native, monkeypatch):
    from tidewall_collector import native_state as store

    back, state, owner, token, work = native
    monkeypatch.chdir(work)
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    monkeypatch.setattr(native_hook, "BUDGET", 0.34)

    def decide(auth, request, deadline):
        # Simulate a stalled pre-output local storage operation after HTTP.
        monkeypatch.setattr(store.os, "fsync", lambda fd: time.sleep(1.3))
        return reply(request, g)

    monkeypatch.setattr(back, "decide_native", decide)
    started = time.monotonic()
    assert not invoke(back, state, payload(work, "private"))
    assert time.monotonic() - started < 0.7
    assert b"stdout_flushed" not in state.journal.read_bytes()


def test_last_output_gate_rechecks_enrollment_and_config(native, monkeypatch):
    back, state, owner, token, work = native
    monkeypatch.chdir(work)
    g = grant(owner, token)
    original = state.path.read_bytes()
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    monkeypatch.setattr(
        back, "decide_native", lambda auth, req, deadline: reply(req, g)
    )
    write = native_hook._emit

    def replace_before_output(*args):
        # Uncooperative replacement while the callback already holds the lock.
        state.path.write_bytes(original)
        return write(*args)

    monkeypatch.setattr(native_hook, "_emit", replace_before_output)
    assert not invoke(back, state, payload(work, "private"))


def test_full_stdout_pipe_cannot_extend_original_callback_budget(native, monkeypatch):
    back, state, owner, token, work = native
    monkeypatch.chdir(work)
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    monkeypatch.setattr(native_hook, "BUDGET", 0.35)
    monkeypatch.setattr(
        back, "decide_native", lambda auth, req, deadline: reply(req, g)
    )
    r, w = os.pipe()
    read_out, write_out = os.pipe()
    with os.fdopen(w, "wb") as source:
        source.write(payload(work, "synthetic"))
    with os.fdopen(r, "rb") as inp, os.fdopen(write_out, "wb", buffering=0) as out:
        os.set_blocking(out.fileno(), False)
        while True:
            try:
                os.write(out.fileno(), b"x" * 4096)
            except BlockingIOError:
                break
        started = time.monotonic()
        assert (
            native_hook.run(
                inp, out, backend=back, session_config=state.path, clock=time.monotonic
            )
            == 0
        )
        assert time.monotonic() - started < 0.67
    with os.fdopen(read_out, "rb") as filled:
        assert filled.read().strip(b"x") == b""
    with state.open(owner) as session:
        assert not session.pending_reports()


def test_trickled_stdin_shares_original_deadline(native, monkeypatch):
    import threading

    back, state, owner, token, work = native
    monkeypatch.chdir(work)
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    monkeypatch.setattr(native_hook, "BUDGET", 0.4)
    monkeypatch.setattr(
        back, "decide_native", lambda *args: pytest.fail("late transfer")
    )
    r, w = os.pipe()
    read_out, write_out = os.pipe()

    def trickle():
        with os.fdopen(w, "wb", buffering=0) as source:
            try:
                for b in payload(work, "synthetic"):
                    source.write(bytes([b]))
                    time.sleep(0.045)
            except BrokenPipeError:
                pass

    thread = threading.Thread(target=trickle)
    thread.start()
    started = time.monotonic()
    with os.fdopen(r, "rb") as inp, os.fdopen(write_out, "wb", buffering=0) as out:
        assert (
            native_hook.run(
                inp, out, backend=back, session_config=state.path, clock=time.monotonic
            )
            == 0
        )
    assert time.monotonic() - started < 0.65
    thread.join(1)
    with os.fdopen(read_out, "rb") as f:
        assert f.read() == b""


@pytest.mark.parametrize(
    "fault",
    [
        "native_unprepared",
        "native_state_invalid",
        "owner_mismatch",
        "after_reservation",
    ],
)
def test_local_binding_errors_retain_their_code_without_transport(
    tmp_path, monkeypatch, capfd, fault
):
    from test_backend import Receiver, REG, ORIGIN
    from tidewall_collector.native_state import NativeState
    from tidewall_collector.tidewall_backend import TidewallBackend

    root = tmp_path / "active"
    back = TidewallBackend(root)
    back._post = Receiver()
    owner = back.enrol(ORIGIN, REG, root)
    back.refresh(owner)
    monkeypatch.chdir(tmp_path)
    state = NativeState(back, root / "native-session.json")

    def corrupt():
        tag, body = json.loads(state.path.read_bytes())
        state.path.write_text(json.dumps(["0" * 64, body]))

    if fault != "native_unprepared":
        token = state.prepare("synthetic-session", tmp_path, "2.1.330", False, None)
        state.prepare(
            "synthetic-session",
            tmp_path,
            "2.1.330",
            False,
            grant(owner, token, capture=False),
        )
        if fault == "native_state_invalid":
            corrupt()
        elif fault == "owner_mismatch":
            with back._locked() as locked:
                _, data = back._bound(locked)
                data["queue_generation"] = str(uuid4())
                locked.write(data)
        else:
            read = native_hook._read

            def corrupt_after_read(*args):
                event = read(*args)
                corrupt()
                return event

            monkeypatch.setattr(native_hook, "_read", corrupt_after_read)
    monkeypatch.setattr(
        back, "_post", lambda *a, **k: pytest.fail("unexpected HTTP attempt")
    )
    assert invoke(back, state, payload(tmp_path, "synthetic")) == b""
    expected = "native_state_invalid" if fault == "after_reservation" else fault
    assert capfd.readouterr().err.strip() == expected


@pytest.mark.parametrize("legacy", [False, True])
def test_access_expiry_prevents_content_until_explicit_refresh(
    native, monkeypatch, legacy
):
    back, state, owner, token, work = native
    monkeypatch.chdir(work)
    g = grant(owner, token)
    state.prepare("synthetic-session", work, "2.1.330", True, g)
    with back._locked() as locked:
        data = locked.read()
        if legacy:
            data.pop("access_expires_at", None)
        else:
            data["access_expires_at"] = int(time.time()) - 1
        locked.write(data)
    with monkeypatch.context() as patch:
        patch.setattr(
            native_hook.wire,
            "input_state",
            lambda _: pytest.fail("content constructed"),
        )
        patch.setattr(
            back, "_post", lambda *_a, **_k: pytest.fail("unexpected network transfer")
        )
        assert invoke(back, state, payload(work, "synthetic")) == b""
    with state.open(owner) as session:
        assert session.records["rows"][-1]["outcome"] == "access_refresh_required"
    back.refresh(owner)
    seen = []

    def decide(auth, request, deadline):
        seen.append(request["prompt"])
        return reply(request, g)

    monkeypatch.setattr(back, "decide_native", decide)
    assert invoke(back, state, payload(work, "synthetic")) and seen == ["synthetic"]

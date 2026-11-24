"""Installed simulation. The classifier and the Claude stdin envelope are fixtures."""

import hashlib
import http.server
import importlib.util
import json
from pathlib import Path
import secrets
import tempfile
import threading
from uuid import uuid4

import pytest
from test_foundation_roundtrip import Fleet, ROOT, SERVER, installed  # noqa: F401


def load_demo():
    spec = importlib.util.spec_from_file_location(
        "native_prompt_demo", ROOT / "scripts/native_prompt_demo.py"
    )
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    return demo


@pytest.fixture
def paired(tmp_path, installed, request):  # noqa: F811 - shared wheel fixture
    if not SERVER:
        pytest.skip("requires the paired Server environment")
    case = request.param
    demo = load_demo()
    spec = importlib.util.spec_from_file_location(
        "native_prompt_receiver", ROOT / "scripts/native_prompt_receiver.py"
    )
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    with tempfile.TemporaryDirectory(dir=tmp_path) as tmp:
        root = Path(tmp).resolve()
        token, tenant = secrets.token_urlsafe(32), str(uuid4())
        key = root / "classifier.key"
        key.touch(mode=0o600)
        key.write_text(token)
        calls = []
        identity = json.loads(
            (ROOT / "tests/fixtures/native_prompt_v1_vectors.json").read_text()
        )
        # Pin the HTTP fixture to the reviewed response identity.
        identity = json.loads(
            bytes.fromhex(
                next(
                    v["hex"]
                    for v in identity
                    if v["name"] == "valid NativeDecisionReply"
                )
            )
        )["assessment"]["model_identity"]

        class Model(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                messages = data["messages"]
                assert self.path == "/v1/classify"
                assert self.headers["Authorization"] == "Bearer " + token
                assert self.headers["X-Tidewall-Tenant-ID"] == tenant
                assert set(data) == {
                    "schema_version",
                    "request_id",
                    "profile",
                    "event_kind",
                    "messages",
                    "timeout_ms",
                }
                assert data["event_kind"] == "prompt" and data["schema_version"] == 1
                assert (
                    data["profile"] == "tidewall.prompt-injection.1"
                    and 0 < data["timeout_ms"] <= 1200
                )
                assert messages == [{"role": "user", "content": demo.prompts(case)}]
                calls.append(data["request_id"])
                if case in ("outage", "rule-outage"):
                    self.connection.close()
                    return
                body = json.dumps(
                    dict(
                        schema_version=1,
                        profile=data["profile"],
                        request_id=data["request_id"],
                        status="classified",
                        model=identity,
                        unsafe_score=0.1 if case == "benign" else 0.9,
                        score_kind="two_class_softmax_uncalibrated",
                        input_tokens=41,
                        inference_ms=1,
                    )
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Model) as model:
            worker = threading.Thread(target=model.serve_forever, daemon=True)
            worker.start()
            try:
                with helper.receiver(
                    Path(SERVER),
                    root,
                    case,
                    {"tenant_id": tenant, "api_key_file": str(key)},
                    model.server_port,
                ) as (port, admin, fault):
                    fleet = Fleet(root, installed, port)
                    fleet.admin = admin
                    yield demo, case, fleet, calls, fault
            finally:
                model.shutdown()
                worker.join()


@pytest.mark.parametrize(
    "paired",
    ["benign", "denied", "report", "outage", "rule-outage", "disabled"],
    indirect=True,
)
def test_installed_complete_simulated_exchange(paired):
    demo, case, fleet, calls, _ = paired
    result = demo.run_case(
        fleet.root, fleet.cli, fleet.port, fleet.admin, "fixture-policy", case
    )
    assert (
        result["source"] == "simulated_callback"
        and result["native_effect"] == "unknown"
    )
    d = result["decision"]
    status, action = {
        "benign": ("assessed", "allow"),
        "denied": ("assessed", "deny"),
        "report": ("assessed", "allow"),
        "outage": ("unavailable", "allow"),
        "rule-outage": ("not_requested", "deny"),
        "disabled": ("not_requested", "allow"),
    }[case]
    assert (d["assessment"]["status"], d["prepared_action"]) == (status, action)
    assert len(calls) == int(case in {"benign", "denied", "report"})
    assert d["delivery_reports"][0]["stage"] == (
        "stdout_flushed" if action == "deny" else "allow_no_output"
    )
    assert (
        len(d["delivery_reports"]) == 1
        and d["delivery_reports"][0]["report_count"] == 1
    )
    assert d["input_state"] == (
        "capture_disabled" if case == "disabled" else "complete"
    )
    if case == "report":
        assert d["evaluated_action"] == "deny" and d["mode"] == "report"
    assert fleet.sql("select count(*) from native_prompt_observations") == [(2,)]
    values = (fleet.root / "fixture.db").read_bytes()
    prompt = demo.prompts(case).encode()
    assert (
        prompt not in values
        and hashlib.sha256(prompt).hexdigest().encode() not in values
    )


@pytest.mark.parametrize("paired", ["transport-outage", "late-reply"], indirect=True)
def test_transport_fallback_has_no_native_prevention_receipt(paired):
    demo, case, fleet, calls, fault = paired
    result = demo.run_case(
        fleet.root,
        fleet.cli,
        fleet.port,
        fleet.admin,
        "fixture-policy",
        case,
        before_submit=fault,
    )
    assert (
        result["native_effect"] == "unknown" and result["stdout"] == "allow_no_output"
    )
    assert "decision" not in result
    assert result["local_outcome"] in {"offline", "timeout", "reserved_unknown"}
    assert len(calls) == int(case == "late-reply")
    if case == "late-reply":
        assert fleet.sql(
            "select count(*) from native_prompt_decisions where returned_action='deny'"
        ) == [(1,)]
    assert fleet.sql("select count(*) from native_prompt_deliveries") == [(0,)]


def fixture_trace(demo, sid, *, denied=False):
    init = {
        "type": "system",
        "subtype": "init",
        "tools": ["Bash"],
        "mcp_servers": [],
        "session_id": sid,
    }
    final = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "session_id": sid,
        "usage": dict.fromkeys(demo.COUNTERS, 0 if denied else 1),
    }
    if denied:
        ack = {
            "type": "system",
            "subtype": "informational",
            "uuid": str(uuid4()),
            "session_id": sid,
            "prevent_continuation": True,
            "prompt_submit_outcome": {
                "kind": "blocked_by_hook",
                "prompt_kept": False,
                "reason": "Blocked by Tidewall policy",
            },
        }
        return [init, ack, final]
    tool = {
        "type": "tool_use",
        "id": "marker-tool",
        "name": "Bash",
        "input": {"command": demo.COMMAND},
    }
    completed = {
        "type": "tool_result",
        "tool_use_id": "marker-tool",
        "content": "",
        "is_error": False,
    }
    return [
        init,
        {"type": "assistant", "session_id": sid, "message": {"content": [tool]}},
        {"type": "user", "session_id": sid, "message": {"content": [completed]}},
        final,
    ]


def framed(demo, events, sid, marker):
    events[0]["cwd"] = str(marker.parent)
    hook = {
        "type": "system",
        "hook_event": "UserPromptSubmit",
        "hook_id": "fixture-hook",
        "session_id": sid,
    }
    events[1:1] = [
        {**hook, "subtype": "hook_started"},
        {
            **hook,
            "subtype": "hook_response",
            "stdout": demo.BLOCK.decode()
            if any("prompt_submit_outcome" in e for e in events)
            else "",
        },
    ]
    return b"\n".join(demo.compact(e) for e in events)


@pytest.mark.parametrize(
    "change",
    [
        "none",
        "other-session",
        "missing-counter",
        "missing-ack",
        "extra-tool",
        "marker",
        "late-result",
    ],
)
def test_native_negative_trace_requires_complete_correlated_receipts(tmp_path, change):
    demo = load_demo()
    sid = str(uuid4())
    marker = tmp_path / demo.MARKER
    events = fixture_trace(demo, sid, denied=True)
    final = events[-1]
    if change == "other-session":
        events[0]["session_id"] = str(uuid4())
    if change == "missing-counter":
        final["usage"].pop("input_tokens")
    if change == "missing-ack":
        events.pop(1)
    if change == "extra-tool":
        events.insert(1, fixture_trace(demo, sid)[1])
    if change == "marker":
        marker.touch()
    if change == "late-result":
        events.append(
            {"type": "assistant", "session_id": sid, "message": {"content": []}}
        )
    raw = framed(demo, events, sid, marker)
    if change in ("other-session", "missing-counter", "late-result"):
        with pytest.raises(demo.QualificationError):
            demo.trace(raw, sid, marker)
    else:
        assert demo.trace(raw, sid, marker)["blocked"] == (change == "none")


@pytest.mark.parametrize(
    "change",
    [
        "none",
        "wrong-tool-id",
        "error",
        "missing-marker",
        "extra-command",
        "reversed",
        "nonempty",
        "missing-completion",
        "effect-before-hook",
        "contradictory-stdout",
    ],
)
def test_native_positive_requires_exact_action_and_successful_tool_result(
    tmp_path, change
):
    demo = load_demo()
    sid = str(uuid4())
    marker = tmp_path / demo.MARKER
    if change != "missing-marker":
        marker.touch()
    events = fixture_trace(demo, sid)
    tool = events[1]["message"]["content"][0]
    result = events[2]["message"]["content"][0]
    if change == "wrong-tool-id":
        result["tool_use_id"] = "other"
    if change == "error":
        result["is_error"] = True
    if change == "extra-command":
        tool["input"]["command"] += "; true"
    if change == "reversed":
        events[1], events[2] = events[2], events[1]
    if change == "nonempty":
        marker.write_text("unexpected")
    if change == "missing-completion":
        result.pop("content")
    raw = framed(demo, events, sid, marker)
    if change == "effect-before-hook":
        raw = b"\n".join(
            demo.compact(e) for e in [events[i] for i in (0, 3, 4, 1, 2, 5)]
        )
    if change == "contradictory-stdout":
        events[2]["stdout"] = demo.BLOCK.decode()
        raw = b"\n".join(demo.compact(e) for e in events)
    if change == "nonempty":
        with pytest.raises(demo.QualificationError):
            demo.trace(raw, sid, marker)
    else:
        assert demo.trace(raw, sid, marker)["positive"] == (change == "none")


def test_ambiguous_trace_cannot_establish_observed_effect(tmp_path):
    demo = load_demo()
    sid = str(uuid4())
    marker = tmp_path / demo.MARKER
    events = fixture_trace(demo, sid, denied=True)
    events.insert(
        1,
        {
            "type": "assistant",
            "session_id": sid,
            "message": {"content": [{"type": "server_tool_use", "name": "unexpected"}]},
        },
    )
    with pytest.raises(demo.QualificationError):
        demo.trace(framed(demo, events, sid, marker), sid, marker)
    events = fixture_trace(demo, sid)
    events[-1]["prompt_submit_outcome"] = {"kind": "blocked_by_hook"}
    marker.touch()
    assert not demo.trace(framed(demo, events, sid, marker), sid, marker)["positive"]


@pytest.mark.parametrize(
    "change",
    [
        "sessionless",
        "wrong-type",
        "wrong-subtype",
        "after-final",
        "not-prevented",
        "kept",
        "dangling-marker",
        "wrong-reason",
        "no-hook-session",
    ],
)
def test_review_ack_and_marker_require_attribution(tmp_path, change):
    demo = load_demo()
    sid = str(uuid4())
    marker = tmp_path / demo.MARKER
    events = fixture_trace(demo, sid, denied=True)
    ack = events[1]
    if change == "sessionless":
        ack.pop("session_id")
    if change == "wrong-type":
        ack["type"] = "unrelated"
    if change == "wrong-subtype":
        ack["subtype"] = "other"
    if change == "after-final":
        events[1:] = events[:0:-1]
    if change == "not-prevented":
        ack["prevent_continuation"] = False
    if change == "kept":
        ack["prompt_submit_outcome"]["prompt_kept"] = True
    if change == "dangling-marker":
        marker.symlink_to(tmp_path / "missing")
    if change == "wrong-reason":
        ack["prompt_submit_outcome"]["reason"] = "unrelated"
    records = [
        json.loads(line) for line in framed(demo, events, sid, marker).splitlines()
    ]
    if change == "no-hook-session":
        records[1].pop("session_id")
    try:
        result = demo.trace(b"\n".join(demo.compact(r) for r in records), sid, marker)
    except demo.QualificationError:
        return
    assert not result["blocked"]


@pytest.mark.parametrize(
    "call_id,content,error",
    [
        (1, "", False),
        (" ", "", False),
        ("tool", None, False),
        ("tool", {}, False),
        ("tool", 17, False),
        ("tool", [], False),
        ("tool", "", None),
        ("tool", "", 0),
        ("tool", "", ""),
    ],
)
def test_review_incomplete_native_tool_receipt(tmp_path, call_id, content, error):
    demo = load_demo()
    sid = str(uuid4())
    marker = tmp_path / demo.MARKER
    marker.touch()
    events = fixture_trace(demo, sid)
    events[1]["message"]["content"][0]["id"] = call_id
    events[2]["message"]["content"][0].update(
        tool_use_id=call_id, content=content, is_error=error
    )
    assert not demo.trace(framed(demo, events, sid, marker), sid, marker)["positive"]


@pytest.mark.parametrize("paired", ["transport-outage"], indirect=True)
@pytest.mark.parametrize(
    "mutation", ["local-refusal", "unknown", "stale-revision", "duplicate-identity"]
)
def test_review_outage_rejects_unrelated_fallback_with_marker(
    paired, monkeypatch, mutation
):
    demo, case, fleet, _, fault = paired

    original = demo.command

    def observed(args, work, **kwargs):
        r = original(args, work, **kwargs)
        if "--list" in args:
            j = json.loads(r.stdout)
            if len(j["rows"]) == 2:
                before, after = j["rows"]
                if mutation == "local-refusal":
                    after["outcome"] = "cwd_mismatch"
                if mutation == "unknown":
                    after["outcome"] = "reserved_unknown"
                if mutation == "stale-revision":
                    after["revision"] = before["revision"]
                if mutation == "duplicate-identity":
                    after["occurrence_id"] = before["occurrence_id"]
                r.stdout = demo.compact(j)
        return r

    def simulated_agent(binary, context, work, sid, text, args, receipt, selection):
        r = original(
            args,
            work,
            data=demo.compact(
                dict(
                    hook_event_name="UserPromptSubmit",
                    cwd=str(work),
                    session_id=sid,
                    prompt=text,
                )
            ),
        )
        assert r.stdout == b""
        (work / demo.MARKER).touch()
        return "allow_no_output", dict(
            positive=True,
            blocked=False,
            tool_count=1,
            marker_present=True,
            token_count=4,
        )

    monkeypatch.setattr(demo, "command", observed)
    monkeypatch.setattr(demo, "agent_run", simulated_agent)
    with pytest.raises(demo.QualificationError):
        demo.run_case(
            fleet.root,
            fleet.cli,
            fleet.port,
            fleet.admin,
            "fixture-policy",
            case,
            binary="fixture",
            before_submit=fault,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "duplicate",
        "wrong-source",
        "wrong-count",
        "wrong-effect",
        "swapped-effect",
        "bool-count",
    ],
)
def test_review_delivery_verifies_all_observed_stages(mutation):
    demo = load_demo()
    effects = {"marker_present": False, "token_count": 0, "tool_count": 0}
    expected = [
        ("stdout_flushed", {}),
        ("native_ack_blocked", {}),
        ("effect_deny_no_effect_verified", effects),
    ]
    rows = [
        dict(
            evidence_source="controlled_observer",
            stage=stage,
            report_count=1,
            received_at="2026-11-24T12:00:00Z",
            **{k: fields.get(k) for k in effects},
        )
        for stage, fields in expected
    ]
    demo.verify_delivery(rows, expected)
    if mutation == "missing":
        rows.pop()
    if mutation == "duplicate":
        rows.append(rows[1])
    if mutation == "wrong-source":
        rows[0]["evidence_source"] = "hook"
    if mutation == "wrong-count":
        rows[0]["report_count"] = 2
    if mutation == "wrong-effect":
        rows[2]["marker_present"] = True
    if mutation == "swapped-effect":
        rows[0]["stage"], rows[2]["stage"] = rows[2]["stage"], rows[0]["stage"]
    if mutation == "bool-count":
        rows[2]["tool_count"] = False
    with pytest.raises(demo.QualificationError):
        demo.verify_delivery(rows, expected)


@pytest.mark.parametrize(
    "guard",
    [
        "wrong-tmpdir",
        "wrong-db-url",
        "wrong-mode",
        "wrong-argc",
        "invalid-fd",
        "udp",
        "bound-stream",
        "existing-db",
    ],
)
def test_review_receiver_preconditions_independently(tmp_path, guard):
    import socket
    import subprocess
    import sys

    root = tmp_path.resolve()
    root.chmod(0o700)
    db = root / "fixture.db"
    helper = ROOT / "scripts/native_prompt_receiver.py"
    env = {"HOME": str(root), "TMPDIR": str(root), "DB_URL": "sqlite:///" + str(db)}
    with socket.socket(
        type=socket.SOCK_DGRAM if guard == "udp" else socket.SOCK_STREAM
    ) as sock:
        sock.bind(("127.0.0.1", 0))
        if guard not in ("udp", "bound-stream"):
            sock.listen()
        args = [str(sock.fileno()), "benign"]
        if guard == "wrong-tmpdir":
            env["TMPDIR"] = "/tmp"
        if guard == "wrong-db-url":
            env["DB_URL"] = "sqlite:///" + str(root / "other.db")
        if guard == "wrong-mode":
            root.chmod(0o755)
        if guard == "wrong-argc":
            args = []
        if guard == "invalid-fd":
            args[0] = "9999"
        if guard == "existing-db":
            db.write_bytes(b"owned-test-sentinel")
        run = subprocess.run(
            [sys.executable, "-I", helper, *args],
            cwd=root,
            env=env,
            pass_fds=[sock.fileno()],
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
    assert run.returncode and run.stderr == b"isolated_receiver_required\n"
    if guard == "existing-db":
        assert db.read_bytes() == b"owned-test-sentinel"
    else:
        assert not db.exists()


def test_review_relocated_actual_launcher_rejected_before_server(tmp_path, installed):  # noqa: F811
    import shutil

    demo = load_demo()
    # Copy a real pipless runtime. Its Python sees only its own installed modules,
    # while pip's launcher keeps the old absolute shebang.
    dest = tmp_path / "relocated"
    shutil.copytree(installed.parents[1], dest, symlinks=True)
    wheel = next(installed.parents[2].glob("*.whl"))
    with pytest.raises(demo.QualificationError, match="launcher"):
        demo.collector_provenance(dest / "bin/tidewall-collector", wheel)


@pytest.mark.parametrize("paired", ["denied"], indirect=True)
def test_review_submitted_delivery_ack_cannot_substitute_for_readback(
    paired, monkeypatch
):
    demo, case, fleet, _, fault = paired
    original_get = demo.get

    def simulated_agent(binary, context, work, sid, text, args, receipt, selection):
        result = demo.command(
            args,
            work,
            data=demo.compact(
                dict(
                    hook_event_name="UserPromptSubmit",
                    cwd=str(work),
                    session_id=sid,
                    prompt=text,
                )
            ),
        )
        if result.stdout == demo.BLOCK:
            return "stdout_flushed", dict(
                blocked=True,
                positive=False,
                marker_present=False,
                token_count=0,
                tool_count=0,
            )
        assert result.stdout == b""
        (work / demo.MARKER).touch()
        return "allow_no_output", dict(
            blocked=False,
            positive=True,
            marker_present=True,
            token_count=4,
            tool_count=1,
        )

    omitted = []

    def omit_committed_stage(*args):
        response = original_get(*args)
        if isinstance(response, dict) and "items" in response:
            for item in response["items"]:
                reports = item["decision"]["delivery_reports"]
                if len(reports) == 3:
                    omitted.append(reports.pop()["stage"])
        return response

    monkeypatch.setattr(demo, "agent_run", simulated_agent)
    monkeypatch.setattr(demo, "get", omit_committed_stage)
    with pytest.raises(demo.QualificationError, match="delivery_readback_mismatch"):
        demo.run_case(
            fleet.root,
            fleet.cli,
            fleet.port,
            fleet.admin,
            "fixture-policy",
            case,
            binary="fixture",
            before_submit=fault,
        )
    assert len(omitted) == 1 and fleet.sql(
        "select count(*) from native_prompt_deliveries"
    ) == [(3,)]


def test_agent_witness_must_match_hook_response(tmp_path, monkeypatch):
    from types import SimpleNamespace

    demo = load_demo()
    work = tmp_path.resolve()
    sid = str(uuid4())
    receipt = work / "output-witness"
    marker = work / demo.MARKER
    monkeypatch.setattr(demo, "owned", lambda _: None)
    monkeypatch.setattr(demo, "verify_binary", lambda *_: None)

    def fake_process(*_args, **_kwargs):
        marker.touch()
        receipt.write_text("stdout_flushed")
        return SimpleNamespace(
            returncode=0, stdout=framed(demo, fixture_trace(demo, sid), sid, marker)
        )

    monkeypatch.setattr(demo.subprocess, "run", fake_process)
    with pytest.raises(demo.QualificationError, match="hook_stdout_witness_mismatch"):
        demo.agent_run(
            work / "synthetic", work, work, sid, "test", [], receipt, "metadata"
        )

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
        final["prompt_submit_outcome"] = {"kind": "blocked_by_hook"}
        return [init, final]
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
        {**hook, "subtype": "hook_response"},
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
        final.pop("prompt_submit_outcome")
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


def test_receiver_refuses_existing_or_unselected_state_before_any_server_import(
    tmp_path,
):
    import subprocess
    import sys

    helper = ROOT / "scripts/native_prompt_receiver.py"
    existing = tmp_path / "fixture.db"
    existing.write_bytes(b"owned-test-sentinel")
    for argv in ([], ["9999", "benign"]):
        run = subprocess.run(
            [sys.executable, "-I", helper, *argv],
            cwd=tmp_path,
            stdin=subprocess.DEVNULL,
            env={"HOME": str(tmp_path), "DB_URL": "sqlite:///" + str(existing)},
            capture_output=True,
        )
        assert run.returncode and run.stderr == b"isolated_receiver_required\n"
        assert existing.read_bytes() == b"owned-test-sentinel"

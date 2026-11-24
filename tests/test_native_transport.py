"""Paired strict Collector vectors and a single, real HTTP handoff."""

import hashlib
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time

import pytest
import test_foundation_roundtrip

from tidewall_collector import native_contract as wire
from tidewall_collector.tidewall_backend import _post, BackendError

installed = test_foundation_roundtrip.installed
FILES = Path(__file__).parent / "fixtures"


def test_paired_contract_and_all_client_vectors():
    for name, expected in [
        (
            "native_prompt_v1.json",
            "dac0f1b196fe3e873aaa3ac224216a92e292b93025deb0a369cc34ecedd77374",
        ),
        (
            "native_prompt_v1_vectors.json",
            "614ae134bf19ddf65a5fc655a651830d0f3a158ffd27ccf4a28293d6d4ce0214",
        ),
    ]:
        assert hashlib.sha256((FILES / name).read_bytes()).hexdigest() == expected
    for case in json.loads((FILES / name).read_bytes()):
        if case["type"] in {
            "NativePolicySettings",
            "NativeConfigAck",
            "NativeGrantRequest",
        }:
            continue  # Administrator-side types are outside the endpoint.
        raw = bytes.fromhex(case["hex"])
        if case["valid"]:
            wire.parse(case["type"], raw)
        else:
            with pytest.raises(ValueError):
                wire.parse(case["type"], raw)


@pytest.fixture
def receiver():
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            data = self.rfile.read(int(self.headers["Content-Length"]))
            self.server.seen.append((self.path, dict(self.headers), data))
            body = self.server.reply(data)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                self.wfile.write(
                    f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
                )
            except OSError:
                pass

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.seen = []
        server.reply = lambda data: b"{}"
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server
        finally:
            server.shutdown()
            worker.join()


def test_native_transport_original_deadline_and_identity_body(receiver, monkeypatch):
    import subprocess

    spawn = subprocess.Popen
    workers = []

    def inspect_worker(argv, **kwargs):
        assert kwargs["env"] == {}
        assert all(
            "at_fixture" not in arg and "a" * 43 not in arg and "雪" not in arg
            for arg in argv
        )
        workers.append(1)
        return spawn(argv, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", inspect_worker)
    origin = f"http://127.0.0.1:{receiver.server_port}"
    path = "/v1/native-prompt/decisions"

    def post(body, budget):
        return _post(
            origin,
            path,
            "at_fixture",
            body,
            8192,
            capability="a" * 43,
            deadline=time.monotonic() + budget,
        )

    assert post('{"prompt":"雪"}'.encode(), 1) == (200, b"{}")
    _, headers, body = receiver.seen[-1]
    assert headers["X-Tidewall-Inline-Capability"] == "a" * 43
    assert headers["Authorization"] == "Bearer at_fixture"
    assert body == '{"prompt":"雪"}'.encode()
    receiver.reply = lambda data: b"x" * 8193
    assert post(b"{}", 1) == (200, b"")
    receiver.reply = lambda data: (time.sleep(0.7), b"{}")[1]
    started = time.monotonic()
    with pytest.raises(BackendError, match="timeout"):
        post(b"{}", 0.22)
    assert time.monotonic() - started < 0.6
    assert len(receiver.seen) == len(workers) == 3


def _installed_call(cli, state, work, command, *args, streams=(), data=b""):
    import contextlib
    import os
    import subprocess

    from test_foundation_roundtrip import env

    argv = [
        str(cli),
        command,
        "--state-root",
        str(state),
        "--session-config",
        str(state / "native-session.json"),
        "--fixture-loopback-http",
        *args,
    ]
    with contextlib.ExitStack() as stack:
        fds = []
        for option, content in streams:
            r, w = os.pipe()
            stack.callback(os.close, r)
            with os.fdopen(w, "wb") as output:
                output.write(content)
            argv += [option, str(r)]
            fds.append(r)
        return subprocess.run(
            argv,
            pass_fds=fds,
            input=data,
            capture_output=True,
            cwd=work,
            env=env(work),
            timeout=4,
        )


def test_installed_metadata_bootstrap_rotation_and_later_observed_report(
    installed, tmp_path, receiver
):
    from test_backend import Receiver, REG
    from test_native_state import grant
    from test_native_hook import payload, reply
    from tidewall_collector.tidewall_backend import TidewallBackend
    from uuid import uuid4

    root = tmp_path / "A"
    work = tmp_path / "controlled"
    work.mkdir(mode=0o700)
    client = TidewallBackend(root, fixture_loopback=True)
    client._post = Receiver()
    owner = client.enrol(f"http://127.0.0.1:{receiver.server_port}", REG, root)
    client.refresh(owner)

    def call(command, *args, **kwargs):
        result = _installed_call(installed, root, work, command, *args, **kwargs)
        assert (
            b"synthetic-session" not in result.stderr
            and b"g" * 43 not in result.stdout + result.stderr
        )
        return result

    def prepare(g=None, local=False):
        streams = [("--session-id-fd", b"synthetic-session")]
        if g:
            streams.append(("--grant-fd", wire.encode(g)))
        args = ["--cwd", str(work), "--agent-version", "2.1.330"]
        if local:
            args.append("--capture")
        return call("prepare-native-session", *args, streams=streams)

    token = json.loads(prepare().stdout)["session_token"]
    private = "  synthetic metadata-only sentinel 雪"
    raw = payload(work, private)
    no_grant = call("claude-hook", data=raw)
    assert no_grant.returncode == 0 and no_grant.stdout == b"" and receiver.seen == []
    g = grant(owner, token, capture=False)
    assert prepare(g).returncode == 0
    chosen = str(uuid4())

    def decide(data):
        body = json.loads(data)
        result = reply(body, g)
        result["session_id"] = chosen
        if body["input_state"] == "capture_disabled":
            result.update(
                evaluated_action="allow",
                returned_action="allow",
                reason="capture_disabled",
            )
            result["assessment"]["reason"] = "capture_disabled"
        return wire.encode(result)

    receiver.reply = decide
    allowed = call("claude-hook", data=raw)
    assert allowed.returncode == 0 and allowed.stdout == allowed.stderr == b""
    assert (
        json.loads(receiver.seen[-1][2])["input_state"] == "capture_disabled"
        and private.encode() not in receiver.seen[-1][2]
    )
    first = g
    g = dict(
        grant(owner, token),
        grant_generation=first["grant_generation"] + 1,
        session_id=chosen,
        capability="h" * 43,
    )
    assert prepare(dict(g, session_id=str(uuid4())), True).returncode != 0
    assert prepare(g, True).returncode == 0
    assert prepare(first, True).returncode != 0
    blocked = call("claude-hook", data=raw)
    assert (
        blocked.returncode == 0
        and blocked.stderr == b""
        and json.loads(blocked.stdout)
        == {"decision": "block", "reason": "Blocked by Tidewall policy"}
    )
    assert json.loads(receiver.seen[-1][2])["prompt"] == private
    assert [p for p, _, _ in receiver.seen] == ["/v1/native-prompt/decisions"] * 2
    for f in root.rglob("*"):
        if f.is_file():
            content = f.read_bytes()
            assert (
                private.encode() not in content and b"synthetic-session" not in content
            )
            if f.name != "native-session.json":
                assert b"h" * 43 not in content
    status = json.loads(call("report-native", "--list").stdout)
    row = status["rows"][-1]
    assert row["reports"] == [] and row["outcome"] == "response_prepared"
    observed = {k: row[k] for k in ("decision_id", "request_id", "occurrence_id")}
    observed.update(
        stage="stdout_flushed",
        evidence_source="controlled_observer",
        report_id=str(uuid4()),
    )
    receiver.reply = lambda data: wire.encode(
        dict(version=1, report_id=observed["report_id"], decision_id=row["decision_id"])
    )
    for count in (1, 0):
        result = call(
            "report-native", streams=[("--evidence-fd", wire.encode(observed))]
        )
        assert result.returncode == 0 and json.loads(result.stdout) == {
            "acknowledged": count
        }
    assert [p for p, _, _ in receiver.seen] == ["/v1/native-prompt/decisions"] * 2 + [
        "/v1/native-prompt/deliveries"
    ]
    assert json.loads(receiver.seen[-1][2]) == observed
    assert b"returned_action" not in (root / "native-journal.json").read_bytes()


def test_installed_stalls_kill_busy_and_broken_pipe(installed, tmp_path, receiver):
    import fcntl
    import subprocess
    from test_backend import REG, Receiver
    from test_foundation_roundtrip import env
    from test_native_state import grant
    from test_native_hook import payload, reply
    from tidewall_collector.native_state import NativeState
    from tidewall_collector.tidewall_backend import TidewallBackend

    root = tmp_path / "A"
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    client = TidewallBackend(root, fixture_loopback=True)
    client._post = Receiver()
    owner = client.enrol(f"http://127.0.0.1:{receiver.server_port}", REG, root)
    client.refresh(owner)
    native = NativeState(client, root / "native-session.json")
    token = native.prepare("synthetic-session", work, "2.1.330", False, None)
    g = grant(owner, token)
    native.prepare("synthetic-session", work, "2.1.330", True, g)
    data = payload(work, "synthetic")
    argv = [
        str(installed),
        "claude-hook",
        "--state-root",
        str(root),
        "--session-config",
        str(native.path),
        "--fixture-loopback-http",
    ]

    def process():
        return subprocess.Popen(
            argv,
            cwd=work,
            env=env(work),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    # Deliberately never close stdin while waiting for the callback.
    with process() as child:
        child.stdin.write(data[:3])
        child.stdin.flush()
        start = time.monotonic()
        assert child.wait(timeout=2.4) == 0 and time.monotonic() - start < 2.25
        assert child.stdout.read() == b"" and b"timeout" in child.stderr.read()
    assert not receiver.seen
    with (root / "credential.lock").open("r+b") as lock, process() as child:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stdout, stderr = child.communicate(data, timeout=2)
        assert child.returncode == 0 and not stdout and b"busy" in stderr
    assert not receiver.seen
    entered = threading.Event()
    release = threading.Event()

    def delayed(body):
        entered.set()
        release.wait(2)
        return wire.encode(reply(json.loads(body), g))

    receiver.reply = delayed
    with process() as child:
        child.stdin.write(data)
        child.stdin.close()
        assert entered.wait(2)
        child.kill()
        child.wait(timeout=1)
        release.set()
        assert child.stdout.read() == b""
    with native.open(owner) as session:
        assert session.records["rows"][-1]["outcome"] == "reserved_unknown"
    receiver.reply = lambda body: wire.encode(reply(json.loads(body), g))
    with process() as child:
        child.stdout.close()
        child.stdin.write(data)
        child.stdin.close()
        assert (
            child.wait(timeout=2.3) == 0 and child.stderr.read() == b"stdout_failed\n"
        )
    with native.open(owner) as session:
        assert session.records["rows"][-1]["outcome"] == "response_prepared"
        assert not session.pending_reports()


def test_wheel_native_import_closure(installed, tmp_path):
    """Exercise wheel imports with an empty home and a read-only import audit."""
    import subprocess
    from zipfile import ZipFile
    from test_foundation_roundtrip import env

    runtime = installed.parent.parent
    (wheel,) = runtime.parent.glob("*.whl")
    with ZipFile(wheel) as z:
        names = set(z.namelist())
        vendor = {
            name for name in names if name.startswith(("openaidr/", "openaidr_common/"))
        }
        assert vendor == {
            "openaidr/__init__.py",
            "openaidr/core/__init__.py",
            "openaidr/sensor/__init__.py",
            "openaidr_common/__init__.py",
            "openaidr/core/event.py",
            "openaidr/core/files.py",
            "openaidr/core/hook_protocol.py",
            "openaidr/core/toolmap.py",
            "openaidr/sensor/collectors.py",
            "openaidr/sensor/spool.py",
            "openaidr_common/event.py",
            "openaidr/guardrail/__init__.py",
            "openaidr/guardrail/hooks.py",
        }
        assert not any(
            "Requires-Dist:" in z.read(n).decode()
            for n in names
            if n.endswith("/METADATA")
        )
        for name, digest in (
            (
                "__init__.py",
                "1ddc371d85568838c47f0014f935138d44469158108c1b1d41f2f5762a3e0a83",
            ),
            (
                "hooks.py",
                "77aaaba0045b1d605bbb8e050eb308ed1dd2796a90af8b3d7d7a6616d3e86dbb",
            ),
        ):
            assert (
                hashlib.sha256(z.read("openaidr/guardrail/" + name)).hexdigest()
                == digest
            )
    (purelib,) = (runtime / "lib").glob("python*/site-packages")
    script = """
import os,sys,threading
purelib=sys.argv[1]
sys.path.insert(0,purelib)
def audit(event,args):
    if event.startswith(("socket.","subprocess.","os.exec","os.spawn","os.posix_spawn")):
        raise AssertionError(event)
    if event in ("open","os.listdir","os.scandir") and isinstance(args[0],(str,bytes)):
        p=os.path.realpath(os.fsdecode(args[0]))
        assert any(p==r or p.startswith(r+os.sep) for r in (os.path.realpath(purelib),os.path.realpath(sys.base_prefix))), (event,p)
        if event=="open":
            assert not args[2] & (os.O_WRONLY|os.O_RDWR|os.O_CREAT)
sys.addaudithook(audit)
from tidewall_collector import native_hook,cli
from openaidr.guardrail.hooks import native_response
assert native_response("claude-code","UserPromptSubmit","deny","Blocked by Tidewall policy",{})[1]["decision"]=="block"
for name,module in sys.modules.copy().items():
    if name.split(".")[0] not in sys.stdlib_module_names:
        assert name.split(".")[0] in {"openaidr","openaidr_common","tidewall_collector","__main__"},name
    if name.startswith(("openaidr","tidewall_collector")) and getattr(module,"__file__",None):
        assert module.__file__.startswith(purelib+os.sep)
assert len(threading.enumerate())==1
print(" ".join(sorted(n for n in sys.modules if n.startswith(("openaidr","tidewall_collector")))))
"""
    result = subprocess.run(
        [runtime / "bin/python", "-I", "-B", "-S", "-c", script, str(purelib)],
        cwd=tmp_path,
        env=env(tmp_path),
        capture_output=True,
        text=True,
        timeout=8,
    )
    assert result.returncode == 0, result.stderr
    assert "openaidr.guardrail.hooks" in result.stdout
    assert not list(tmp_path.iterdir())
    print(
        "wheel",
        wheel.name,
        hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "modules",
        result.stdout.strip(),
    )


def test_observe_native_checks_owner_and_scoped_ack_before_selecting_session(
    tmp_path, receiver
):
    import time
    from test_backend import REG, Receiver
    from test_native_state import grant
    from tidewall_collector.native_state import NativeState
    from tidewall_collector.tidewall_backend import TidewallBackend
    from uuid import uuid4

    root = tmp_path / "A"
    back = TidewallBackend(root, fixture_loopback=True)
    real = back._post
    back._post = Receiver()
    owner = back.enrol(f"http://127.0.0.1:{receiver.server_port}", REG, root)
    back.refresh(owner)
    back._post = real
    native = NativeState(back, root / "native-session.json")
    token = native.prepare("scope", tmp_path, "2.1.330", False, None)
    g = grant(owner, token, capture=False)
    native.prepare("scope", tmp_path, "2.1.330", False, g)
    with native.open(owner) as session:
        auth = session.authority()
    obs = dict(
        version=1,
        occurrence_id=str(uuid4()),
        agent="claude-code",
        agent_version="2.1.330",
        native_profile=wire.PROFILE,
        session_token=token,
    )
    ack = dict(
        version=1,
        occurrence_id=obs["occurrence_id"],
        event_id=str(uuid4()),
        session_id=str(uuid4()),
    )
    receiver.reply = lambda data: wire.encode(dict(ack, occurrence_id=str(uuid4())))
    with pytest.raises(BackendError, match="invalid_reply"):
        back.observe_native(auth, obs, time.monotonic() + 1)
    receiver.reply = lambda data: wire.encode(ack)
    assert back.observe_native(auth, obs, time.monotonic() + 1) == ack
    assert all(
        path == "/v1/native-prompt/observations" and json.loads(body) == obs
        for path, _, body in receiver.seen
    )
    with native.open(owner) as session:
        assert session.authority().selected_session == ack["session_id"]

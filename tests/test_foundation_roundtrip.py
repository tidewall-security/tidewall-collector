"""Installed, dependency-free collector and the migrated receiver in separate processes."""

import contextlib
import http.client
import inspect
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from tidewall_collector.state import QueueState, Owner
from tidewall_collector.tidewall_backend import TidewallBackend
from test_queue_ownership import obs, STREAM

ROOT = Path(__file__).resolve().parents[1]
SERVER = os.environ.get("TIDEWALL_SERVER_ROOT")
pytestmark = pytest.mark.skipif(
    not SERVER, reason="requires a Tidewall Server checkout and native .venv"
)


# The fixture controls the socket and lifespan only. Every application request
# passes through production auth, route, validation and database transaction.
def serve_fixture():
    import asyncio
    import json
    import os
    import socket
    import sys
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from app.auth.key_utils import hash_key
    from app.db.engine import get_engine, get_session_factory
    from app.db.models import Policy, APIKey
    from app.main import create_app
    import uvicorn

    work = Path(sys.argv[1])
    command.upgrade(Config("alembic.ini"), "head")
    sessions = get_session_factory(get_engine(os.environ["DB_URL"]))
    with sessions.begin() as session:
        session.add(Policy(id="fixture-policy", name="fixture", type="application"))
        session.flush()
        session.add(
            APIKey(
                name="fixture admin",
                role="admin",
                policy_id="fixture-policy",
                key_hash=hash_key(input()),
                key_prefix="fixture",
            )
        )
    app = create_app()
    app.state.session_factory = sessions

    async def boundary(scope, receive, send):
        path = scope["path"]
        with (work / "arrivals.jsonl").open("a") as f:
            print(json.dumps([scope["server"], scope["method"], path]), file=f)
        if path.endswith("/observations") and (work / "pause").exists():
            (work / "waiting").touch()
            for _ in range(300):
                if not (work / "pause").exists():
                    break
                await asyncio.sleep(0.01)
        status = 0
        reported = False

        async def observe(message):
            nonlocal status, reported
            if message["type"] == "http.response.start":
                status = message["status"]
                if (
                    path.endswith("/enrol")
                    and status == 201
                    and (work / "pause-201").exists()
                ):
                    (work / "confirmed-201").touch()
                    while (work / "pause-201").exists():
                        await asyncio.sleep(0.01)
                if (
                    path.endswith("/observations")
                    and status == 200
                    and (work / "drop").exists()
                ):
                    (work / "drop").unlink()
                    send.__self__.transport.abort()
                    raise ConnectionResetError("fixture response interruption")
            if message["type"] == "http.response.body" and status == 403:
                while (work / "stall-403-body").exists():
                    await asyncio.sleep(0.01)
            if message["type"] == "http.response.body" and not reported:
                reported = True
                outcomes = []
                if status == 200 and path.endswith("/observations"):
                    outcomes = [
                        r["outcome"] for r in json.loads(message["body"])["results"]
                    ]
                with (work / "routes.jsonl").open("a") as f:
                    print(
                        json.dumps(
                            [scope["server"], scope["method"], path, status, outcomes]
                        ),
                        file=f,
                    )
            await send(message)

        await app(scope, receive, observe)

    listener = socket.socket(fileno=int(sys.argv[2]))
    (work / "ready").touch()
    uvicorn.Server(
        uvicorn.Config(boundary, lifespan="off", access_log=False, log_level="critical")
    ).run(sockets=[listener])


def env(root):
    return dict(
        PATH=os.defpath,
        HOME=str(root),
        TMPDIR=str(root),
        HF_HUB_OFFLINE="1",
        TRANSFORMERS_OFFLINE="1",
        PIP_NO_INDEX="1",
        PIP_DISABLE_PIP_VERSION_CHECK="1",
    )


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    root = tmp_path_factory.mktemp("installed").resolve()
    src = root / "src"
    for name in ("src", "vendor"):
        shutil.copytree(
            ROOT / name,
            src / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"),
        )
    for name in ("pyproject.toml", "LICENSE", "NOTICE", "README.md"):
        shutil.copy(ROOT / name, src / name)

    def run(*args):
        subprocess.run(
            args,
            env=env(root),
            cwd=root,
            check=True,
            stdout=subprocess.DEVNULL,
            timeout=90,
        )

    run(
        sys.executable,
        "-m",
        "pip",
        "wheel",
        "--no-build-isolation",
        "--no-deps",
        "-w",
        str(root),
        str(src),
    )
    runtime = root / "runtime"
    run(sys.executable, "-m", "venv", "--without-pip", str(runtime))
    py = runtime / "bin/python"
    run(
        sys.executable,
        "-m",
        "pip",
        "--python",
        str(py),
        "install",
        "--no-deps",
        str(next(root.glob("*.whl"))),
    )
    packages = subprocess.check_output(
        [
            py,
            "-I",
            "-c",
            "from importlib.metadata import distributions;print(','.join(d.metadata['Name'] for d in distributions()))",
        ],
        cwd=root,
        env=env(root),
        text=True,
    )
    assert packages.strip() == "tidewall-collector"
    print(
        f"Installed wheel {next(root.glob('*.whl')).name}, distributions {packages.strip()}"
    )
    return runtime / "bin/tidewall-collector"


class Fleet:
    def __init__(self, root, cli, port):
        self.root, self.cli, self.port = root, cli, port
        self.origin = f"http://127.0.0.1:{port}"
        self.admin = "ak_" + uuid4().hex

    def request(self, method, path, token=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            conn.request(
                method, path, None if body is None else json.dumps(body), headers
            )
            response = conn.getresponse()
            data = response.read()
            return response.status, json.loads(data) if data else None
        finally:
            conn.close()

    def register(self):
        status, result = self.request(
            "POST",
            "/v1/registration-tokens",
            self.admin,
            dict(
                name="fixture",
                purpose="collector_write",
                policy_id="fixture-policy",
                expires_at=(datetime.now(UTC) + timedelta(days=1)).isoformat(),
            ),
        )
        assert status == 201
        return result["token"]

    def args(self, command, state):
        return [
            str(self.cli),
            command,
            "--state-root",
            str(self.root / state),
            "--fixture-loopback-http",
        ]

    def call(self, command, state, *extra, secrets=(), success=True):
        with contextlib.ExitStack() as files:
            args = self.args(command, state) + list(extra)
            fds = []
            for flag, secret in secrets:
                f = files.enter_context(tempfile.TemporaryFile(dir=self.root))
                f.write(secret.encode())
                f.seek(0)
                fds.append(f.fileno())
                args.extend([flag, str(f.fileno())])
            result = subprocess.run(
                args,
                cwd=self.root,
                env=env(self.root),
                pass_fds=fds,
                capture_output=True,
                text=True,
                timeout=25,
            )
        if success and result.returncode:
            pytest.fail(
                f"{command} failed with {result.returncode}: {result.stderr}"
                if result.stderr.strip().isidentifier()
                else f"{command} failed with {result.returncode}"
            )
        for _, secret in secrets:
            if secret in (result.stdout + result.stderr):
                pytest.fail("credential present in CLI output")
        return result

    def enrol(self):
        entry = self.call(
            "enrol",
            "A",
            "--origin",
            self.origin,
            secrets=[("--registration-fd", self.register())],
        )
        return json.loads(entry.stdout)

    def approve(self, device):
        status, _ = self.request(
            "POST",
            f"/v1/devices/{device['device_id']}/approve",
            self.admin,
            {"confirmation_code": device["confirmation_code"]},
        )
        assert status == 200

    def sql(self, sql, *params):
        with contextlib.closing(sqlite3.connect(self.root / "fixture.db")) as conn:
            return conn.execute(sql, params).fetchall()

    def routes(self):
        return [
            json.loads(line)
            for line in (self.root / "routes.jsonl").read_text().splitlines()
        ]


@pytest.fixture
def fleet(tmp_path, installed):
    scratch = tempfile.TemporaryDirectory(dir=tmp_path)
    root = Path(scratch.name).resolve()
    for name in ("claude-session.jsonl", "claude-hooks.json"):
        (root / "sources").mkdir(exist_ok=True)
        shutil.copyfile(ROOT / "tests/fixtures" / name, root / "sources" / name)
    assert SERVER is not None
    server = Path(SERVER)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        result = Fleet(root, installed, listener.getsockname()[1])
        proc = subprocess.Popen(
            [
                server / ".venv/bin/python",
                "-c",
                inspect.getsource(serve_fixture) + "\nserve_fixture()",
                str(root),
                str(listener.fileno()),
            ],
            cwd=server,
            env={**env(root), "DB_URL": f"sqlite:///{root}/fixture.db"},
            pass_fds=[listener.fileno()],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            assert proc.stdin is not None
            proc.stdin.write((result.admin + "\n").encode())
            proc.stdin.close()
            deadline = time.monotonic() + 35
            while not (root / "ready").exists():
                if proc.poll() is not None or time.monotonic() > deadline:
                    pytest.fail("fixture receiver startup failed")
                time.sleep(0.05)
            yield result
        finally:
            proc.terminate()
            proc.wait(timeout=10)
            scratch.cleanup()


def fixture(f):
    f.call("fixture", "A", "--fixture-dir", str(f.root / "sources"))


def test_foundation_roundtrip(fleet):
    f = fleet
    a = f.enrol()
    f.approve(a)
    source = f.root / "sources"
    extra = source / "unrecognized"
    extra.touch()
    assert (
        f.call(
            "fixture", "A", "--fixture-dir", str(source), success=False
        ).stderr.strip()
        == "invalid_fixture"
    )
    extra.unlink()
    alias = f.root / "alias"
    alias.symlink_to(source, target_is_directory=True)
    assert (
        f.call(
            "fixture", "A", "--fixture-dir", str(alias), success=False
        ).stderr.strip()
        == "invalid_fixture"
    )
    fixture(f)
    (f.root / "drop").touch()
    lost = f.call("ship", "A", success=False)
    assert lost.returncode == 75 and lost.stderr.strip() == "offline"
    events = f.sql(
        "select event_id, source_key from agent_observations order by event_id"
    )
    assert len(events) == 11
    assert json.loads(f.call("status", "A").stdout)["heartbeat"]["pending"] == 11
    f.call("ship", "A")
    assert (
        f.sql("select event_id,source_key from agent_observations order by event_id")
        == events
    )
    assert any(r[-1] == ["duplicate"] * 11 for r in f.routes())
    fixture(f)
    f.call("ship", "A")
    assert f.sql(
        "select channel,count(*) from agent_observations group by channel order by channel"
    ) == [("hook", 4), ("transcript", 7)]
    assert f.sql("select count(*) from agent_sessions") == [(1,)]
    assert f.sql(
        "select channel from agent_observations where session_id is null order by channel"
    ) == [("hook",), ("transcript",)]
    health = json.loads(f.sql("select heartbeat_json from collector_progress")[0][0])
    assert health["pending"] == 0 and health["state"] == "source_incomplete"
    assert (
        health["totals"]["invalid_json"] == health["totals"]["unsupported_record"] == 1
    )
    observations = [
        json.loads(r[0])
        for r in f.sql("select observation_json from agent_observations")
    ]
    gaps = {g for o in observations for g in o["gaps"]}
    assert {"missing_native_session_id", "malformed_record"} <= gaps
    for table in ("interactions", "interaction_contents", "vaults", "activity_log"):
        assert f.sql(f"select count(*) from {table}") == [(0,)]
    assert not f.sql(
        "select name from sqlite_master where type='table' and (name like '%assessment%' or name like '%delivery%')"
    )
    # A deliberately malformed receiver probe uses the fixture admin harness's
    # direct HTTP client and a synthetic enrolled access token, never ship_once.
    cred = json.loads((f.root / "A/credentials.json").read_bytes())

    def counts():
        return [
            f.sql("select count(*) from " + table)[0][0]
            for table in (
                "agent_observations",
                "agent_sessions",
                "collector_outcomes",
                "collector_progress",
            )
        ]

    before = counts()
    rows = [dict(ordinal=n, observation=obs(n)) for n in (40, 41, 42)]
    rows[1]["observation"]["kind"] = "tool.call"
    assert f.request(
        "POST",
        "/v1/collector/observations",
        cred["access"],
        dict(version=1, enrollment_id=a["device_id"], batch_id=str(uuid4()), rows=rows),
    ) == (422, {"code": "invalid_row"})
    assert counts() == before and f.sql(
        "select high_water from collector_progress"
    ) == [(11,)]
    hooks = f.root / "sources/claude-hooks.json"
    original = json.loads(hooks.read_bytes())
    old = hooks.with_suffix(".old")
    hooks.rename(old)
    hooks.write_text(json.dumps([original[0]]))
    old.unlink()
    f.call("fixture", "A", "--fixture-dir", str(hooks.parent), "--independent", "hook")
    f.call("ship", "A")
    assert f.sql(
        "select count(*),count(distinct event_id) from agent_observations"
    ) == [(12, 12)]
    print(f"Fixture roundtrip origin {f.origin}")
    assert all(
        route[0] == ["127.0.0.1", f.port] and route[1] == "POST" for route in f.routes()
    )


def test_same_installation_recovery(fleet):
    f = fleet
    a = f.enrol()
    f.approve(a)
    fixture(f)
    f.call("ship", "A")
    owner = Owner(f.origin, UUID(a["device_id"]))
    cred = json.loads((f.root / "A/credentials.json").read_bytes())
    # A real semantic conflict commits a rejection without storing new detail.
    request = dict(
        version=1,
        enrollment_id=a["device_id"],
        batch_id=str(uuid4()),
        rows=[dict(ordinal=1, observation=obs(987))],
    )
    assert (
        f.request("POST", "/v1/collector/observations", cred["access"], request)[1][
            "results"
        ][0]["outcome"]
        == "rejected"
    )
    with QueueState.open(f.root / "A/queue", owner) as q:
        q.admit_record(owner, STREAM, 0, 1, [obs(987)])
        pending = q.next_batch(owner)
    # Freeze a real A request at the receiver before authorization, then commit
    # revocation from a separate scoped administrator connection.
    (f.root / "pause").touch()
    sender = subprocess.Popen(
        f.args("ship", "A"),
        cwd=f.root,
        env=env(f.root),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        until = time.monotonic() + 4
        while not (f.root / "waiting").exists():
            assert time.monotonic() < until
            time.sleep(0.02)
        path = "/v1/devices/" + a["device_id"]
        assert f.request("PATCH", path, f.admin, {"status": "revoked"})[0] == 200
        (f.root / "pause").unlink()
        assert sender.wait(timeout=10) != 0
    finally:
        if sender.poll() is None:
            sender.kill()
            sender.wait()
    assert json.loads(f.call("status", "A").stdout)["status"] == "device_revoked"
    print(f"Recovery origin {f.origin}")
    grant = f.request("POST", path + "/authorise-recovery", f.admin)[1][
        "recovery_secret"
    ]
    inputs = [("--registration-fd", f.register()), ("--recovery-fd", grant)]
    recover = ("--origin", f.origin, "--installation-id", a["installation_id"])
    arrivals = f.root / "arrivals.jsonl"
    before = arrivals.read_bytes()
    assert f.call("recover", "A", *recover, secrets=inputs, success=False).returncode
    assert arrivals.read_bytes() == before
    inventory = {p.relative_to(f.root / "A") for p in (f.root / "A").rglob("*")}
    for target in ("A/queue", "A/queue/B", "A/B"):
        assert (
            f.call(
                "recover", target, *recover, secrets=inputs, success=False
            ).returncode
            == 2
        )
        assert arrivals.read_bytes() == before
        assert {
            p.relative_to(f.root / "A") for p in (f.root / "A").rglob("*")
        } == inventory
    from concurrent.futures import ThreadPoolExecutor
    import fcntl

    (f.root / "pause-201").touch()
    with ThreadPoolExecutor(max_workers=1) as pool:
        attempt = pool.submit(
            f.call, "recover", "B", *recover, secrets=inputs, success=False
        )
        until = time.monotonic() + 4
        while not (f.root / "confirmed-201").exists():
            assert time.monotonic() < until
            time.sleep(0.01)
        directory = os.open(f.root / "B", os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
            (f.root / "pause-201").unlink()
            busy = attempt.result(timeout=6)
            assert busy.returncode == 75 and "busy" in busy.stderr
        finally:
            os.close(directory)
    after = arrivals.read_bytes()
    assert len(after.splitlines()) == len(before.splitlines()) + 1
    wrong_inputs = [inputs[0], ("--recovery-fd", "wrong_fixture_grant")]
    assert (
        f.call("recover", "B", *recover, secrets=wrong_inputs, success=False).returncode
        == 2
    )
    result = f.call("recover", "B", *recover, secrets=inputs)
    assert arrivals.read_bytes() == after
    assert "deletes" in result.stderr and "approval" in result.stderr
    b = json.loads(result.stdout)
    assert (
        b["device_id"] != a["device_id"]
        and b["installation_id"] == a["installation_id"]
    )
    assert f.sql(
        "select status,installation_id from devices where id=?", b["device_id"]
    ) == [("pending", a["installation_id"])]
    assert f.sql(
        "select consumed_at is not null from device_tombstones where device_id=?",
        a["device_id"],
    ) == [(1,)]
    assert f.call("recover", "C", *recover, secrets=inputs, success=False).returncode
    assert f.routes()[-1][3] == 409
    assert f.call("ship", "B", success=False).returncode
    assert (
        f.request(
            "POST",
            "/v1/devices/" + b["device_id"] + "/approve",
            f.admin,
            {"confirmation_code": a["confirmation_code"]},
        )[0]
        == 403
    )
    f.approve(b)
    f.call("ship", "B")
    with QueueState.open(f.root / "A/queue", owner) as q:
        current = q.next_batch(owner)
        assert current is not None and pending is not None
        assert (
            current.rows == pending.rows
            and current.expected_cursor == pending.expected_cursor
        )
        from tidewall_collector.state import QueueError
        from tidewall_collector.tidewall_backend import BackendError

        back = TidewallBackend(f.root / "B", fixture_loopback=True)
        with pytest.raises((QueueError, BackendError), match="owner_mismatch"):
            back.ship_once(back.owner(), q)
    assert f.sql(
        "select count(*) from agent_observations where device_id=?", b["device_id"]
    ) == [(0,)]
    assert json.loads(f.call("status", "B").stdout)["heartbeat"]["pending"] == 0
    assert all(route[0] == ["127.0.0.1", f.port] for route in f.routes())
    assert (
        f.request("POST", path + "/refresh", cred["refresh"], {})[1]["reason"]
        == "device_revoked"
    )
    f.call("fixture", "B", "--fixture-dir", str(f.root / "sources"))
    f.call("ship", "B")
    assert f.sql(
        "select count(*) from agent_observations where device_id=?", b["device_id"]
    ) == [(11,)]
    assert not f.sql(
        "select event_id from agent_observations where source_key=?",
        obs(987)["source"]["parser_observation_token"],
    )
    assert not f.call("offboard", "A", "--device-id", a["device_id"]).returncode
    assert (
        not (f.root / "A/queue").exists()
        and not (f.root / "A/credentials.json").exists()
    )


@pytest.mark.parametrize(
    "fault",
    [
        "drip_header",
        "drip_body",
        "drip_refusal",
        "drip_401",
        "drip_413",
        "short_body",
        "bad_media",
        "large_body",
        "redirect",
        "proxy",
        "tls_required",
    ],
)
def test_real_wire_bounds_and_destination(tmp_path, monkeypatch, fault):
    import threading
    from tidewall_collector import tidewall_backend as backend
    from contextlib import closing

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(2)
    origin = "http://127.0.0.1:" + str(listener.getsockname()[1])
    # Any attempted proxy or redirect would reach this independently recorded
    # listener. The real HTTP implementation never trusts environment routing.
    with listener, socket.socket() as sink:
        sink.bind(("127.0.0.1", 0))
        sink.listen()
        sink.settimeout(0.05)
        alternate = "http://127.0.0.1:" + str(sink.getsockname()[1])
        for key in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ):
            monkeypatch.setenv(key, alternate)
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setattr(backend, "DEADLINE", 0.75)
        received = []

        def serve():
            try:
                with closing(listener.accept()[0]) as peer:
                    if fault == "tls_required":
                        received.append(peer.recv(1))
                        return
                    received.append(peer.recv(8192).split(b"\r\n", 1)[0])
                    codes = {
                        "redirect": b"302 Found",
                        "drip_refusal": b"422 Unprocessable Entity",
                        "drip_401": b"401 Unauthorized",
                        "drip_413": b"413 Content Too Large",
                    }
                    status = b"HTTP/1.1 " + codes.get(fault, b"200 OK") + b"\r\n"
                    header = b"Content-Type: application/json\r\n"
                    if fault == "redirect":
                        header += b"Location: " + alternate.encode() + b"/second\r\n"
                    if fault == "bad_media":
                        header = b"Content-Type: text/plain\r\n"
                    if fault == "drip_header":
                        peer.sendall(status + b"X-Fixture: ")
                    elif fault in ("drip_body", "drip_refusal", "drip_401", "drip_413"):
                        peer.sendall(
                            status
                            + header
                            + b"Transfer-Encoding: chunked\r\n\r\n40\r\n"
                        )
                    else:
                        body = b"x" * 2049 if fault == "large_body" else b"{}"
                        length = len(body) + (50 if fault == "short_body" else 0)
                        peer.sendall(
                            status
                            + header
                            + b"Content-Length: "
                            + str(length).encode()
                            + b"\r\n\r\n"
                            + body
                        )
                        return
                    for _ in range(40):
                        peer.sendall(b"x")
                        time.sleep(0.08)
            except OSError:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        start = time.monotonic()
        if fault == "tls_required":
            with pytest.raises(backend.BackendError, match="offline"):
                backend._post(
                    origin.replace("http:", "https:"),
                    "/v1/collector/heartbeat",
                    "at_fixture",
                    b"{}",
                    2048,
                )
        elif fault in ("drip_header", "drip_body"):
            with pytest.raises(backend.BackendError, match="timeout"):
                backend._post(
                    origin, "/v1/collector/heartbeat", "at_fixture", b"{}", 2048
                )
            assert 0.6 < time.monotonic() - start < 1.4
        else:
            status, body = backend._post(
                origin, "/v1/collector/heartbeat", "at_fixture", b"{}", 2048
            )
            if fault == "drip_refusal":
                assert (status, body) == (422, b"")
            elif fault in ("drip_401", "drip_413"):
                assert (status, body) == (int(fault[-3:]), b"")
                assert time.monotonic() - start < 0.7
            elif fault == "redirect":
                assert status == 302
            elif fault == "proxy":
                assert (status, body) == (200, b"{}")
            else:
                assert body == b""
        thread.join(2)
        assert received == (
            [b"\x16"]
            if fault == "tls_required"
            else [b"POST /v1/collector/heartbeat HTTP/1.1"]
        )
        with pytest.raises(socket.timeout):
            sink.accept()


def test_real_prefix_local_loss_and_suffix(fleet, monkeypatch):
    """The installed client sends the valid prefix/suffix in different processes."""
    from test_backend import three
    from tidewall_collector import admission

    f = fleet
    a = f.enrol()
    f.approve(a)
    owner = Owner(f.origin, UUID(a["device_id"]))
    with QueueState.open(f.root / "A/queue", owner) as queue:
        rows = three(queue, owner, monkeypatch, invalid=True)
    assert json.loads(f.call("ship", "A").stdout) == {"acknowledged": 1}
    assert f.sql("select ordinal,digest from collector_outcomes") == [
        (40, admission.digest(admission.canonical(rows[0])))
    ]
    snapshot = json.loads(f.call("status", "A").stdout)["heartbeat"]
    assert snapshot["pending"] == 2 and snapshot["totals"]["row_schema_invalid"] == 0
    assert json.loads(f.call("ship", "A").stdout) == {"acknowledged": 1}
    assert f.sql("select ordinal,digest from collector_outcomes order by ordinal") == [
        (n, admission.digest(admission.canonical(row)))
        for n, row in [(40, rows[0]), (42, rows[2])]
    ]
    persisted = [
        json.loads(r[0])
        for r in f.sql(
            "select observation_json from agent_observations order by source_key"
        )
    ]
    assert persisted == [rows[0], rows[2]]
    health = json.loads(f.sql("select heartbeat_json from collector_progress")[0][0])
    assert health["totals"]["row_schema_invalid"] == 1 and health["pending"] == 0
    print(f"Ordered disposition origin {f.origin}")


def test_untrusted_tls_certificate_sends_no_http_request(tmp_path, monkeypatch):
    import ssl
    import threading
    from tidewall_collector import tidewall_backend as backend

    key, cert = tmp_path / "server.key", tmp_path / "server.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    alerts: list[str | bytes] = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(3)

        def serve():
            with contextlib.closing(listener.accept()[0]) as connection:
                try:
                    with context.wrap_socket(connection, server_side=True) as tls:
                        alerts.append(tls.recv(1))
                except ssl.SSLError:
                    alerts.append("certificate_refused")

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        monkeypatch.setenv("SSL_CERT_FILE", str(cert))
        origin = "https://127.0.0.1:" + str(listener.getsockname()[1])
        with pytest.raises(backend.BackendError, match="offline"):
            backend._post(origin, "/v1/collector/heartbeat", "at_fixture", b"{}", 2048)
        worker.join(3)
        assert alerts == ["certificate_refused"]


@pytest.mark.parametrize("operation", ["observations", "heartbeat"])
def test_completed_scope_refusal_stops_writes(fleet, monkeypatch, operation):
    from tidewall_collector import tidewall_backend as backend

    f = fleet
    a = f.enrol()
    f.approve(a)
    owner = Owner(f.origin, UUID(a["device_id"]))
    client = TidewallBackend(f.root / "A", fixture_loopback=True)
    client.refresh(owner)
    # The real middleware refuses a credential with a missing policy binding.
    # Hold only its response body at the fixture socket, after the final headers.
    with contextlib.closing(sqlite3.connect(f.root / "fixture.db")) as db, db:
        db.execute("update devices set policy_id=NULL where id=?", (a["device_id"],))
    barrier = f.root / "stall-403-body"
    barrier.touch()
    arrivals = f.root / "arrivals.jsonl"
    before = len(arrivals.read_text().splitlines())
    monkeypatch.setattr(backend, "DEADLINE", 0.8)
    try:
        with QueueState.open(f.root / "A/queue", owner) as q:
            q.admit_record(owner, STREAM, 0, 1, [obs(9)])
            write = (
                client.ship_once
                if operation == "observations"
                else client.send_heartbeat
            )
            start = time.monotonic()
            with pytest.raises(backend.BackendError, match="scope_denied"):
                write(owner, q)
            assert time.monotonic() - start < 0.7
            assert client.status(owner, q)["status"] == "scope_denied"
            assert q.heartbeat(owner)["pending"] == 1
    finally:
        barrier.unlink()
    restarted = TidewallBackend(f.root / "A", fixture_loopback=True)
    with QueueState.open(f.root / "A/queue", owner) as q:
        for write in (restarted.ship_once, restarted.send_heartbeat):
            with pytest.raises(backend.BackendError, match="scope_denied"):
                write(owner, q)
    assert [
        json.loads(line)[1:] for line in arrivals.read_text().splitlines()[before:]
    ] == [["POST", f"/v1/collector/{operation}"]]


@pytest.mark.parametrize("cut", ["first_file", "ready_write"])
def test_installed_cli_finishes_known_enrolment_after_storage_failure(
    fleet, monkeypatch, cut
):
    import errno
    from tidewall_collector import state, tidewall_backend as backend

    f = fleet
    root = f.root / "B"
    registration = f.register()
    direct = TidewallBackend(root, fixture_loopback=True)
    write = backend._LockedState.write

    def failed_file(path, data):
        raise OSError(errno.ENOSPC, "fixture storage interruption")

    def failed_ready(self, data):
        if data.get("setup", {}).get("ready") is True:
            raise OSError(errno.ENOSPC, "fixture storage interruption")
        return write(self, data)

    before = f.root / "arrivals.jsonl"
    count = len(before.read_text().splitlines())
    with monkeypatch.context() as patch:
        if cut == "first_file":
            patch.setattr(state, "_create_file", failed_file)
        else:
            patch.setattr(backend._LockedState, "write", failed_ready)
        with pytest.raises((backend.BackendError, state.QueueError)):
            direct.enrol(f.origin, registration, root)
    arrivals = before.read_bytes()
    assert len(arrivals.splitlines()) == count + 1
    assert (
        f.call(
            "fixture", "B", "--fixture-dir", str(f.root / "sources"), success=False
        ).stderr.strip()
        == "setup_incomplete"
    )
    inputs = [("--registration-fd", registration)]
    if cut == "ready_write":
        (root / "queue").rename(f.root / "original")
        assert f.call(
            "enrol", "B", "--origin", f.origin, secrets=inputs, success=False
        ).returncode
        assert not (root / "queue").exists()
        (f.root / "original").rename(root / "queue")
    result = f.call("enrol", "B", "--origin", f.origin, secrets=inputs)
    assert before.read_bytes() == arrivals
    b = json.loads(result.stdout)
    f.approve(b)
    f.call("fixture", "B", "--fixture-dir", str(f.root / "sources"))
    f.call("ship", "B")
    assert f.sql(
        "select count(*) from agent_observations where device_id=?", b["device_id"]
    ) == [(11,)]

"""Disposable, migrated Tidewall Server for the isolated native acceptance workflow."""

import contextlib
import http.client
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time


def serve():
    import os
    import sys
    from alembic import command
    from alembic.config import Config
    from app.auth.key_utils import hash_key
    from app.db.engine import get_engine, get_session_factory
    from app.db.models import AccessRule, APIKey, Policy, RuleSet
    import uvicorn

    command.upgrade(Config("alembic.ini"), "head")
    sessions = get_session_factory(get_engine(os.environ["DB_URL"]))
    with sessions.begin() as db:
        db.add(
            Policy(
                id="fixture-policy",
                name="isolated",
                report_only=sys.argv[2] == "report",
            )
        )
        db.flush()
        rules = RuleSet(
            policy_id="fixture-policy",
            event_type="input",
            detectors={"malicious_prompt": {"action": "block"}},
        )
        db.add(rules)
        db.flush()
        if sys.argv[2] == "rule-outage":
            db.add(
                AccessRule(
                    rule_set_id=rules.id,
                    name="synthetic rule",
                    conditions={"field": "app_id", "value": "claude-code"},
                    then_action="block_and_stop",
                )
            )
        db.add(
            APIKey(
                name="isolated admin",
                role="admin",
                policy_id="fixture-policy",
                key_prefix="isolated",
                key_hash=hash_key(input()),
            )
        )
    from app.main import app
    import asyncio
    from pathlib import Path

    async def boundary(scope, receive, send):
        async def deliver(message):
            if (
                scope["type"] == "http"
                and scope["path"] == "/v1/native-prompt/decisions"
                and message["type"] == "http.response.start"
                and Path(os.environ["DB_URL"].removeprefix("sqlite:///"))
                .with_name("delay-native")
                .is_file()
            ):
                await asyncio.sleep(2.1)
            await send(message)

        await app(scope, receive, deliver)

    uvicorn.run(boundary, fd=int(sys.argv[1]), access_log=False, log_level="critical")


@contextlib.contextmanager
def disconnected_provider():
    """Own the selected fault endpoint and close every connection without a reply."""
    stop = threading.Event()
    with socket.socket() as endpoint:
        endpoint.bind(("127.0.0.1", 0))
        endpoint.listen()
        endpoint.settimeout(0.1)

        def disconnect():
            while not stop.is_set():
                try:
                    peer, _ = endpoint.accept()
                except TimeoutError:
                    continue
                with peer:
                    peer.shutdown(socket.SHUT_RDWR)

        worker = threading.Thread(target=disconnect)
        worker.start()
        try:
            yield endpoint.getsockname()[1]
        finally:
            stop.set()
            worker.join()


@contextlib.contextmanager
def receiver(server, root, case, config, classifier_port):
    """Run only the chosen Server checkout, on a private ephemeral loopback port."""
    key = "ak_" + secrets.token_hex(32)
    with socket.socket() as listener, contextlib.ExitStack() as faults:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        if case in ("outage", "rule-outage"):
            classifier_port = faults.enter_context(disconnected_provider())
        env = {
            "PATH": os.defpath,
            "HOME": str(root),
            "TMPDIR": str(root),
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "TOKENIZERS_PARALLELISM": "false",
            "DB_URL": f"sqlite:///{root}/fixture.db",
            "NATIVE_CLASSIFIER_ORIGIN": f"http://127.0.0.1:{classifier_port}",
            "NATIVE_CLASSIFIER_TENANT_ID": config["tenant_id"],
            "NATIVE_CLASSIFIER_KEY_FILE": config["api_key_file"],
            "NATIVE_CLASSIFIER_ALLOW_LOOPBACK_HTTP": "true",
        }
        # -c makes the selected Server cwd the import root, including alembic.ini.
        runner = "import runpy,sys; script=sys.argv.pop(1); runpy.run_path(script,run_name='__main__')"
        p = subprocess.Popen(
            [
                server / ".venv/bin/python",
                "-c",
                runner,
                str(Path(__file__).resolve()),
                str(listener.fileno()),
                case,
            ],
            cwd=server,
            env=env,
            pass_fds=[listener.fileno()],
            stdin=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
        )
        try:
            listener.close()
            p.stdin.write((key + "\n").encode())
            p.stdin.close()
            end = time.monotonic() + 30
            while time.monotonic() < end and p.poll() is None:
                with contextlib.closing(
                    http.client.HTTPConnection("127.0.0.1", port, timeout=0.4)
                ) as connection:
                    try:
                        connection.request("GET", "/health")
                        if connection.getresponse().status == 200:
                            break
                    except OSError:
                        pass
                time.sleep(0.05)
            else:
                raise RuntimeError("isolated_server_not_ready")

            def fault():
                if case == "transport-outage":
                    p.terminate()
                    p.wait(timeout=15)
                elif case == "late-reply":
                    (root / "delay-native").touch()

            yield port, key, fault
        finally:
            if p.poll() is None:
                p.terminate()
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()


if __name__ == "__main__":
    serve()

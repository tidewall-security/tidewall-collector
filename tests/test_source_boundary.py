import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = "7ec2891b0904dad621bb13f24312121d05d4ca03"
VENDOR_FILES = {
    "LICENSE",
    "src/openaidr/__init__.py",
    "src/openaidr/core/__init__.py",
    "src/openaidr/core/event.py",
    "src/openaidr/core/files.py",
    "src/openaidr/core/hook_protocol.py",
    "src/openaidr/core/toolmap.py",
    "src/openaidr/guardrail/__init__.py",
    "src/openaidr/guardrail/hooks.py",
    "src/openaidr/sensor/__init__.py",
    "src/openaidr/sensor/collectors.py",
    "src/openaidr/sensor/spool.py",
    "packages/common/src/openaidr_common/__init__.py",
    "packages/common/src/openaidr_common/event.py",
}
PHASE0_FIXTURE_HASHES = {
    "claude-hooks.json": "7cd504b740c6749d14c698983e8aecd9be7b382d7e95be92da6608042acc8853",
    "claude-session.jsonl": "b5ecc86941ae6ed63b90f67b722ae0e2fb57073adc41ea5f63afe24502af3e14",
    "expected-metadata.json": "a46203db3ce3334b5c33da2ffaf766377ca8f522287e8aab5f40ddaf0d395946",
    "re-enrollment.json": "7807fac0159e894a9ff4613a3451b2f5583caf74e2574189509175fd292a3c3b",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_phase_zero_fixtures_are_copied_byte_for_byte():
    assert {
        name: sha(ROOT / "tests" / "fixtures" / name) for name in PHASE0_FIXTURE_HASHES
    } == PHASE0_FIXTURE_HASHES


def test_vendored_paths_are_pinned_with_reusable_change_ancestry():
    vendor = ROOT / "vendor" / "openaidr"
    assert (
        vendor / "source-lock.json"
    ).is_file(), "selected OpenAIDR source lock is missing"
    lock = json.loads((vendor / "source-lock.json").read_bytes())
    assert lock["commit"] == PIN
    assert set(lock["files"]) == VENDOR_FILES
    actual_paths = {
        path.relative_to(vendor).as_posix()
        for path in vendor.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    assert actual_paths == VENDOR_FILES | {"source-lock.json"}
    assert lock["files"]["src/openaidr/sensor/collectors.py"]["upstream_sha256"] == (
        "d3b44aef9dac7862a527ba2f2d5c327fb1d2d2b49cc406ba543729d86238414e"
    )
    assert lock["files"]["src/openaidr/sensor/spool.py"]["upstream_sha256"] == (
        "0318c76986fb05328f32ad750bd82991fcd66406264a6b6f9fe1d8796b811c0c"
    )
    for path, entry in lock["files"].items():
        assert sha(vendor / path) == entry["redistributed_sha256"]
        if entry["upstream_sha256"] != entry["redistributed_sha256"]:
            assert entry["change"]
            assert b"Tidewall" in (vendor / path).read_bytes()
    assert "7ec2891b0904dad621bb13f24312121d05d4ca03" in (ROOT / "NOTICE").read_text()


def test_fixture_projection_imports_and_runs_without_external_activity(tmp_path):
    assert (
        importlib.util.find_spec("tidewall_collector") is not None
    ), "projection package is missing"
    paths = [
        ROOT / "src",
        ROOT / "vendor" / "openaidr" / "src",
        ROOT / "vendor" / "openaidr" / "packages" / "common" / "src",
    ]
    script = """
import os
import sys
import threading
from uuid import UUID

paths = tuple(sys.argv[1:])
prefixes = paths + (sys.base_prefix,)
sys.path[:0] = paths


def audit(event, args):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn", "os.posix_spawn")):
        raise AssertionError(event)
    if event in {"os.scandir", "os.listdir", "open"} and isinstance(args[0], (str, bytes)):
        path = os.fsdecode(args[0])
        if not any(path == root or path.startswith(root + os.sep) for root in prefixes):
            raise AssertionError(event)
        if event == "open" and args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
            raise AssertionError("unexpected write")


sys.addaudithook(audit)
from openaidr.sensor.collectors import Parser
from tidewall_collector.projection import project_hook, project_transcript

key = bytes(32)
record = {"type": "user", "sessionId": "scope", "message": {"content": "synthetic"}}
parser = Parser(stream_id="opaque")
assert [
    project_transcript(record, event, stream_id="opaque", key=key, adapter_version="1.0.0")["kind"]
    for event in parser.parse(record, position=1)
] == ["session.start", "prompt"]
assert project_hook(
    {"hook_event_name": "PostToolUse"}, observation_id=UUID("12345678-abcd-4000-8000-000000000003"),
    key=key, adapter_version="1.0.0",
)["kind"] == "tool.result"
assert len(threading.enumerate()) == 1
modules = {name for name in sys.modules if name.startswith(("openaidr", "tidewall_collector"))}
assert modules == {
    "openaidr", "openaidr.core", "openaidr.core.hook_protocol", "openaidr.core.toolmap",
    "openaidr.sensor", "openaidr.sensor.collectors", "tidewall_collector",
    "tidewall_collector.projection",
}, modules
for module in tuple(sys.modules):
    if module.split(".")[0] not in sys.stdlib_module_names:
        assert module.split(".")[0] in {"openaidr", "tidewall_collector", "__main__"}, module
print("\\n".join(sorted(modules)))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-S", "-c", script, *map(str, paths)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert "openaidr.sensor.collectors" in result.stdout
    assert not list(tmp_path.iterdir())

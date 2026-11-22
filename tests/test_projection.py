import hashlib
import hmac
import json
import re
from pathlib import Path
from uuid import UUID

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
STREAM = "fixture-claude-stream-01"
KEY = bytes(32)
VERSION = "1.0.0"
HOOK_ID = UUID("12345678-abcd-4000-8000-000000000003")
HEX = re.compile(r"[0-9a-f]{64}")
COMMON_FIELDS = {
    "agent",
    "fixture_profile",
    "upstream_sha",
    "adapter_version",
    "kind",
    "source",
    "availability",
    "gaps",
}
OPTIONAL_FIELDS = {
    "native_session_token",
    "native_tool_call_token",
    "tool_name",
    "source_at",
}
TRANSCRIPT_FIELDS = {
    "channel",
    "parser_observation_token",
    "parser_logical_token",
    "parser_evidence_version",
    "stream_token",
    "byte_position",
    "part",
    "record_token",
    "record_origin",
}
HOOK_FIELDS = {"channel", "collector_observation_id", "native_event"}


def fixture(name):
    return json.loads((FIXTURES / name).read_bytes())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def transcript_inputs(stream=STREAM, *, omit_timestamp=False):
    from openaidr.sensor.collectors import Parser

    parser = Parser(stream_id=stream)
    omitted = []
    rows = []
    position = 1
    for line, raw in enumerate(
        (FIXTURES / "claude-session.jsonl").read_bytes().splitlines(True), 1
    ):
        if not raw.endswith(b"\n"):
            omitted.append({"line": line, "reason": "unterminated_jsonl_record"})
            break
        try:
            record = json.loads(raw)
        except ValueError:
            record = {}
            events = parser.gap("malformed_record", line=line, position=position)
        else:
            if omit_timestamp:
                record.pop("timestamp", None)
            events = parser.parse(record, line=line, position=position)
        if not events:
            omitted.append({"line": line, "reason": "parser_emitted_no_observation"})
        rows.extend((line, record, event) for event in events)
        position += len(raw)
    return rows, omitted


def project_rows(key=KEY):
    from tidewall_collector.projection import project_hook, project_transcript

    inputs, omitted = transcript_inputs()
    transcripts = [
        project_transcript(
            record, event, stream_id=STREAM, key=key, adapter_version=VERSION
        )
        for _, record, event in inputs
    ]
    hooks = [
        project_hook(
            hook,
            observation_id=UUID(f"12345678-abcd-4000-8000-{index:012}"),
            key=key,
            adapter_version=VERSION,
        )
        for index, hook in enumerate(fixture("claude-hooks.json"), 1)
    ]
    return inputs, transcripts, hooks, omitted


def test_pinned_fixture_produces_measured_observations_and_omissions():
    inputs, transcripts, hooks, omitted = project_rows()
    expected = fixture("expected-metadata.json")
    assert len(transcripts) == len(expected["transcript"]) == 7
    assert len(hooks) == len(expected["hooks"]) == 4
    assert omitted == expected["discarded_transcript_records"]

    for (line, _, event), actual, spec in zip(
        inputs, transcripts, expected["transcript"], strict=True
    ):
        source = actual["source"]
        assert line == spec["line"]
        assert source.keys() == TRANSCRIPT_FIELDS
        assert source["channel"] == "transcript"
        assert source["parser_evidence_version"] == 1
        assert source["byte_position"] == spec["sequence"]
        assert source["part"] == spec["part"]
        assert actual["kind"] == spec["kind"]
        assert actual.get("tool_name") == spec.get("tool_name")
        assert ("native_session_token" in actual) == ("native_session_id" in spec)
        assert ("native_tool_call_token" in actual) == ("native_tool_call_id" in spec)
        assert event["evidence"]["gaps"] == spec["gaps"]
        if actual["kind"] == "sensor":
            assert actual["gaps"] == ["malformed_record", "missing_native_session_id"]
            assert actual["availability"] == "source_unavailable"
            assert "source_at" not in actual
        else:
            assert actual["gaps"] == spec["gaps"]
            assert actual["source_at"] == f"2026-11-22T09:00:0{line}Z"
            assert actual["availability"] == (
                "truncated" if "content_truncated" in spec["gaps"] else "metadata_only"
            )
        assert source["record_origin"] == (
            "parser_generated"
            if actual["kind"] in {"session.start", "sensor"}
            else "native"
        )
        assert COMMON_FIELDS <= actual.keys() <= COMMON_FIELDS | OPTIONAL_FIELDS
        for field in (
            "record_token",
            "stream_token",
            "parser_observation_token",
            "parser_logical_token",
        ):
            assert HEX.fullmatch(source[field])

    for actual, spec in zip(hooks, expected["hooks"], strict=True):
        assert actual["source"].keys() == HOOK_FIELDS
        assert actual["source"]["channel"] == "hook"
        assert actual["source"]["native_event"] == spec["native_hook_event"]
        assert actual["kind"] == spec["kind"]
        assert actual["availability"] == "metadata_only"
        assert actual["gaps"] == spec["gaps"]
        assert actual.get("tool_name") == spec.get("tool_name")
        assert ("native_session_token" in actual) == ("native_session_id" in spec)
        assert ("native_tool_call_token" in actual) == ("native_tool_call_id" in spec)
        assert COMMON_FIELDS <= actual.keys() <= COMMON_FIELDS | OPTIONAL_FIELDS
        assert "source_at" not in actual
    assert len({hook["source"]["collector_observation_id"] for hook in hooks}) == 4
    assert (
        transcripts[0]["source"]["record_token"]
        != transcripts[1]["source"]["record_token"]
    )
    assert (
        transcripts[2]["source"]["record_token"]
        == transcripts[3]["source"]["record_token"]
    )


def test_cross_channel_linkage_changes_with_enrollment_key():
    _, transcripts_a, hooks_a, _ = project_rows()
    _, transcripts_b, hooks_b, _ = project_rows(bytes([1]) * 32)
    for transcripts, hooks in [(transcripts_a, hooks_a), (transcripts_b, hooks_b)]:
        assert (
            transcripts[0]["native_session_token"] == hooks[0]["native_session_token"]
        )
        assert (
            transcripts[2]["native_tool_call_token"]
            == hooks[1]["native_tool_call_token"]
        )
        assert (
            transcripts[4]["native_tool_call_token"]
            == hooks[2]["native_tool_call_token"]
        )
        assert (
            transcripts[2]["source"]["parser_observation_token"]
            != (transcripts[4]["source"]["parser_observation_token"])
        )
    for left, right in [(transcripts_a[2], transcripts_b[2]), (hooks_a[1], hooks_b[1])]:
        assert left["native_session_token"] != right["native_session_token"]
        assert left["native_tool_call_token"] != right["native_tool_call_token"]


def test_full_frozen_wire_vectors_reconstruct_from_parser_and_native_inputs():
    from tidewall_collector.projection import project_hook, project_transcript

    wire = fixture("collector_v1.json")
    input_spec = fixture("projection-inputs.json")
    read = input_spec["read_case"]
    domains = input_spec["hmac"]["domains"]
    vectors = {v["name"]: v for v in wire["observation_vectors"]}
    assert (
        hashlib.sha256((FIXTURES / "collector_v1.json").read_bytes()).hexdigest()
        == (input_spec["server_vectors_sha256"])
    )
    assert read["native_inputs"]["stream"] == wire["fixture_stream_id"] == STREAM

    def read_observation(key):
        inputs, _ = transcript_inputs(omit_timestamp=True)
        [(line, record, event)] = [
            row for row in inputs if row[2]["kind"] == "file.read"
        ]
        assert (line, event["evidence"]["sequence"], event["evidence"]["part"]) == (
            read["line"],
            read["byte_position"],
            read["part"],
        )
        values = read["native_inputs"]
        assert record["sessionId"] == values["session"]
        assert event["tool"]["call_id"] == values["tool_call"]
        assert record["uuid"] == values["native_record"]
        assert (
            event["evidence"]["logical_id"]
            == wire["projection"]["parser_inputs"]["parser_logical"]
        )
        assert (
            event["evidence"]["observation_id"]
            == wire["projection"]["parser_inputs"]["parser_observation"]
        )
        return project_transcript(
            record,
            event,
            stream_id=values["stream"],
            key=key,
            adapter_version=read["adapter_version"],
        )

    results = {}
    for name, key_hex in wire["projection"]["test_keys_hex"].items():
        key = bytes.fromhex(key_hex)
        observation = read_observation(key)
        results[name] = observation
        vector = vectors[f"transcript_file_read_{name}"]
        assert canonical(observation) == vector["canonical"].encode()
        assert hashlib.sha256(canonical(observation)).hexdigest() == vector["sha256"]
        source = observation["source"]
        token_fields = {
            "native_session_token": observation["native_session_token"],
            "native_tool_call_token": observation["native_tool_call_token"],
            "source.record_token.native": source["record_token"],
            "source.stream_token": source["stream_token"],
            "source.parser_logical_token": source["parser_logical_token"],
            "source.parser_observation_token": source["parser_observation_token"],
        }
        values = read["native_inputs"] | wire["projection"]["parser_inputs"]
        for field, token in token_fields.items():
            domain = domains[field]
            assert (
                token
                == hmac.digest(
                    key, (domain + "\0" + values[domain]).encode(), "sha256"
                ).hex()
            )
        assert all(
            source[field] == token
            for field, token in wire["projection"]["expected_tokens"][name].items()
        )
        assert read_observation(key) == observation

    enrollment = fixture("re-enrollment.json")
    assert (
        enrollment["queued_enrollment"]["device_id"]
        != enrollment["proposed_enrollment"]["device_id"]
    )
    assert enrollment["expected"]["same_identity_refresh"].startswith("allow_replay")
    refreshed_a_uses_existing_key = bytes.fromhex(
        wire["projection"]["test_keys_hex"]["A"]
    )
    assert canonical(read_observation(refreshed_a_uses_existing_key)) == canonical(
        results["A"]
    )
    assert (
        results["A"]["source"]["parser_logical_token"]
        != results["B"]["source"]["parser_logical_token"]
    )
    assert (
        results["A"]["source"]["parser_observation_token"]
        != results["B"]["source"]["parser_observation_token"]
    )

    actual = project_hook(
        fixture("claude-hooks.json")[3],
        observation_id=HOOK_ID,
        key=KEY,
        adapter_version=VERSION,
    )
    assert canonical(actual) == vectors["hook_orphan_result"]["canonical"].encode()
    assert (
        hashlib.sha256(canonical(actual)).hexdigest()
        == vectors["hook_orphan_result"]["sha256"]
    )


def test_private_source_data_stays_out_of_wire_logs_and_spool(tmp_path, caplog, capsys):
    from openaidr.sensor.collectors import Parser
    from openaidr.sensor.spool import Spool
    from tidewall_collector.projection import project_hook, project_transcript

    inputs, transcripts, hooks, _ = project_rows()
    parser = Parser(stream_id=STREAM)
    hostile = "SENTINEL_HOSTILE_ID"
    invalid = "/tmp/SENTINEL_INVALID_ID\u0000"
    unknown_tool = "SENTINEL_UNVERIFIED_TOOL"
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": hostile,
        "tool_use_id": invalid,
        "tool_name": unknown_tool,
        "tool_input": {"cmd": "SENTINEL_ARGUMENT"},
        "tool_response": "SENTINEL_RESULT",
        "cwd": "/tmp/SENTINEL_CWD",
        "timestamp": "2024-02-29T23:59:59Z",
        "prompt": "SENTINEL_BODY",
        "url": "https://sentinel-host.invalid",
        "capture": "capture_disabled",
        "redacted": True,
        "native_session_token": "SENTINEL_FORGED_TOKEN",
    }
    row = project_hook(
        payload, observation_id=HOOK_ID, key=KEY, adapter_version=VERSION
    )
    assert (
        row["native_session_token"]
        == hmac.digest(KEY, f"session\0{hostile}".encode(), "sha256").hex()
    )
    assert row["gaps"] == ["missing_native_tool_call_id"]
    assert row["availability"] == "metadata_only"
    assert row.keys() == COMMON_FIELDS | {"native_session_token"}

    record = {
        "type": "assistant",
        "uuid": invalid,
        "sessionId": hostile,
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": invalid,
                    "name": "Read",
                    "input": {"file_path": "/tmp/SENTINEL_FILE"},
                }
            ]
        },
    }
    events = parser.parse(record, position=55)
    read_event = next(event for event in events if event["kind"] == "file.read")
    read = project_transcript(
        record, read_event, stream_id=STREAM, key=KEY, adapter_version=VERSION
    )
    assert read["native_session_token"] == row["native_session_token"]
    assert "native_tool_call_token" not in read
    assert read["gaps"] == ["missing_native_tool_call_id"]
    assert read["source"]["record_origin"] == "parser_generated"
    assert read["tool_name"] == "Read"

    record["sessionId"] = invalid
    [malformed] = parser.parse(record, position=56)
    gap = project_transcript(
        record, malformed, stream_id=STREAM, key=KEY, adapter_version=VERSION
    )
    assert gap["kind"] == "sensor"
    assert gap["gaps"] == ["malformed_record", "missing_native_session_id"]
    assert "native_session_token" not in gap

    spool = Spool(tmp_path / "spool")
    observations = [*transcripts, *hooks, row, read, gap]
    for observation in observations:
        spool.append(observation)
    assert spool.read(limit=len(observations))["events"] == observations
    persisted = b"".join(path.read_bytes() for path in spool.segments())
    raw_parser_ids = [
        event["evidence"][field]
        for _, _, event in inputs
        for field in ("logical_id", "observation_id", "stream_id")
    ]
    raw_parser_ids += [event["source"]["record_id"] for _, _, event in inputs]
    output = capsys.readouterr()
    for material in (
        canonical(observations),
        persisted,
        (output.out + output.err + caplog.text).encode(),
    ):
        for forbidden in [
            *raw_parser_ids,
            hostile,
            "SENTINEL_",
            "fixture-url-sentinel",
            "sentinel-host.invalid",
            "/Users/",
            "fixture-claude-session-01",
            "fixture-call-read",
            "fixture-call-web",
            "fixture-call-unseen",
            "fixture-version",
        ]:
            assert forbidden.encode() not in material


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        ("2024-02-29T18:59:59.12-05:00", "2024-02-29T23:59:59.120000Z"),
        ("2024-02-29T23:59:59Z", "2024-02-29T23:59:59Z"),
        ("2024-02-30T23:59:59Z", None),
        ("2024-02-29T23:59:59", None),
        ("2024-02-29T23:59:59+01:60", None),
        ("2024-02-29T23:59:59.1234567Z", None),
        ("2024-02-29T23:59:59-00:00", None),
        ("0001-01-01T00:00:00+01:00", None),
        ("SENTINEL_TIME", None),
        (False, None),
        (None, None),
    ],
)
def test_only_valid_native_transcript_time_is_projected(timestamp, expected):
    from openaidr.sensor.collectors import Parser
    from tidewall_collector.projection import project_transcript

    parser = Parser(stream_id=STREAM, started=True)
    record = {
        "type": "user",
        "sessionId": "synthetic",
        "message": {"content": "synthetic"},
    }
    if timestamp is not None:
        record["timestamp"] = timestamp
    [event] = parser.parse(record, position=1)
    observation = project_transcript(
        record, event, stream_id=STREAM, key=KEY, adapter_version=VERSION
    )
    if expected is None:
        assert "source_at" not in observation
    else:
        assert observation["source_at"] == expected


def test_gaps_are_independent_mapped_sorted_and_deduplicated():
    from openaidr.sensor.collectors import Parser
    from tidewall_collector.projection import project_transcript

    parser = Parser(stream_id=STREAM, started=True)
    record = {
        "type": "user",
        "sessionId": "test",
        "message": {"content": [{"type": "image"}]},
    }
    [event] = parser.parse(record, position=10)
    event["evidence"]["gaps"].extend(
        ["unsupported_content", "unmapped_SENSITIVE_REASON"]
    )
    row = project_transcript(
        record, event, stream_id=STREAM, key=KEY, adapter_version=VERSION
    )
    assert row["kind"] == "sensor"
    assert row["gaps"] == ["other_parser_gap", "unsupported_content"]
    assert row["availability"] == "unsupported"

    event["evidence"]["gaps"].extend(
        ["malformed_record", "content_truncated", "skipped_content"]
    )
    row = project_transcript(
        record, event, stream_id=STREAM, key=KEY, adapter_version=VERSION
    )
    assert row["gaps"] == [
        "content_truncated",
        "malformed_record",
        "other_parser_gap",
        "skipped_content",
        "unsupported_content",
    ]
    assert row["availability"] == "truncated"


def test_unmeasured_or_invalid_input_has_only_sanitized_error_codes(caplog, capsys):
    from openaidr.sensor.collectors import Parser
    from tidewall_collector.projection import (
        ProjectionError,
        project_hook,
        project_transcript,
    )

    parser = Parser(stream_id=STREAM, started=True)
    record = {
        "type": "assistant",
        "sessionId": "test",
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "name": "SENTINEL_UNKNOWN_TOOL",
                    "input": {"message": "SENTINEL_ARGUMENT"},
                }
            ]
        },
    }
    [event] = parser.parse(record, position=1)
    with pytest.raises(
        ProjectionError, match="^unsupported_record$"
    ) as transcript_error:
        project_transcript(
            record, event, stream_id=STREAM, key=KEY, adapter_version=VERSION
        )
    assert transcript_error.value.code == "unsupported_record"
    with pytest.raises(ProjectionError, match="^unsupported_record$"):
        project_hook(
            {"hook_event_name": "SENTINEL_EVENT"},
            observation_id=HOOK_ID,
            key=KEY,
            adapter_version=VERSION,
        )
    with pytest.raises(ProjectionError, match="^invalid_shape$"):
        project_hook(
            {"hook_event_name": ["SENTINEL_EVENT"]},
            observation_id=HOOK_ID,
            key=KEY,
            adapter_version=VERSION,
        )
    with pytest.raises(ProjectionError, match="^invalid_shape$"):
        project_hook(
            {"hook_event_name": "PostToolUse"},
            observation_id=HOOK_ID,
            key=b"",
            adapter_version=VERSION,
        )
    with pytest.raises(ProjectionError, match="^invalid_shape$"):
        project_hook(
            {"hook_event_name": "PostToolUse"},
            observation_id=HOOK_ID,
            key=KEY,
            adapter_version="SENTINEL_ADAPTER",
        )
    with pytest.raises(ProjectionError, match="^invalid_shape$"):
        project_hook(
            {"hook_event_name": "PostToolUse"},
            observation_id=UUID(int=1),
            key=KEY,
            adapter_version=VERSION,
        )

    [gap] = parser.gap("malformed_record", position=2)
    with pytest.raises(ProjectionError, match="^invalid_shape$"):
        project_transcript(
            {},
            gap,
            stream_id="SENTINEL_MISMATCHED_STREAM",
            key=KEY,
            adapter_version=VERSION,
        )
    gap["evidence"]["observation_id"] = "SENTINEL_RAW_PARSER_ID"
    with pytest.raises(ProjectionError, match="^invalid_shape$"):
        project_transcript({}, gap, stream_id=STREAM, key=KEY, adapter_version=VERSION)
    output = capsys.readouterr()
    assert "SENTINEL_" not in output.out + output.err + caplog.text


def test_explicit_malformed_gap_keeps_pinned_parser_identity_and_record_domain():
    from tidewall_collector.projection import project_transcript

    inputs, _ = transcript_inputs()
    [(_, record, event)] = [row for row in inputs if row[2]["kind"] == "sensor"]
    assert event["evidence"]["logical_id"] == (
        "d0f34f5531474e44af422480120c21936f2a8a8a79552a79c3e97b01f23fb99f"
    )
    assert event["evidence"]["observation_id"] == (
        "5ecb83fb4a85aa55c91b3cd910cef800a40bd770a004b478967bb0ac4bd4b719"
    )
    record_id = "e2d15a37bdc2052713a80f0e98f56cbb112c8f1caff5e15e5c2f75c90bbbd9e8"
    assert event["source"]["record_id"] == record_id
    observation = project_transcript(
        record, event, stream_id=STREAM, key=KEY, adapter_version=VERSION
    )
    assert (
        observation["source"]["record_token"]
        == hmac.digest(KEY, f"parser_record\0{record_id}".encode(), "sha256").hex()
    )

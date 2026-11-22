"""Closed collector v1 admission and receipt rules, shared by admission and replay."""

import hashlib
import json
import re
from datetime import datetime
from typing import Any, NoReturn

from . import UPSTREAM_SHA

# Update both components when changing the admitted shape or its semantics.
CONTRACT = (
    "f62c8a1da01877913368c3c9e7f8bc3833ac7e801d2698992388ed675c9c4e96/semantics-1"
)
MAX_INT = (1 << 53) - 1
MAX_OBSERVATION = 4096
MAX_BATCH = 65536
HEX = re.compile("[0-9a-f]{64}")
UUID4 = re.compile(
    "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
GAPS = {
    "malformed_record",
    "content_truncated",
    "missing_tool_call",
    "missing_native_session_id",
    "missing_native_tool_call_id",
    "unsupported_content",
    "skipped_content",
    "other_parser_gap",
}
HOOK_KINDS = {
    "UserPromptSubmit": "prompt",
    "PreToolUse": "tool.call",
    "PostToolUse": "tool.result",
}
LOSSES = (
    "capacity_rejected",
    "oversized_input",
    "invalid_json",
    "invalid_shape",
    "incomplete_tail",
    "unsupported_record",
    "expired",
    "server_conflict",
    "retired_ordinal",
    "row_schema_invalid",
)


class Invalid(ValueError):
    def __init__(self) -> None:
        super().__init__("invalid_shape")


def require(ok: object) -> None:
    if not ok:
        raise Invalid()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reject(_: object) -> NoReturn:
    raise Invalid()


def _unique(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def wire_json(data: bytes, limit: int) -> Any:
    require(type(data) is bytes and 0 < len(data) <= limit)
    depth = 0
    quoted = escaped = False
    for b in data:
        if escaped:
            escaped = False
        elif quoted and b == 92:
            escaped = True
        elif b == 34:
            quoted = not quoted
        elif not quoted and b in (91, 123):
            depth += 1
            require(depth <= 12)
        elif not quoted and b in (93, 125):
            depth -= 1
    try:
        return json.loads(
            data.decode("utf8"),
            object_pairs_hook=_unique,
            parse_float=_reject,
            parse_constant=_reject,
        )
    except (ValueError, RecursionError):
        raise Invalid() from None


def match(pattern: re.Pattern, value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def integer(value: object, low: int, high: int = MAX_INT) -> bool:
    return type(value) is int and low <= value <= high


def _validate(o: dict) -> None:
    required = {
        "source",
        "agent",
        "fixture_profile",
        "upstream_sha",
        "adapter_version",
        "kind",
        "availability",
        "gaps",
    }
    optional = {
        "native_session_token",
        "native_tool_call_token",
        "tool_name",
        "source_at",
    }
    require(type(o) is dict and required <= o.keys() <= required | optional)
    require(
        o["agent"] == "claude-code"
        and o["fixture_profile"] == "claude-fixture-v1"
        and o["upstream_sha"] == UPSTREAM_SHA
    )
    version = o["adapter_version"]
    require(
        isinstance(version, str)
        and len(version) <= 24
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
    )
    for token in ("native_session_token", "native_tool_call_token"):
        if token in o:
            require(match(HEX, o[token]))
    if "tool_name" in o:
        require(o["tool_name"] in ("Read", "WebFetch"))
    if "source_at" in o:
        ts = o["source_at"]
        require(
            isinstance(ts, str)
            and re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
                ts,
            )
        )
        datetime.fromisoformat(ts)
    gaps = o["gaps"]
    require(
        type(gaps) is list
        and len(gaps) <= 8
        and all(isinstance(g, str) and g in GAPS for g in gaps)
        and gaps == sorted(set(gaps))
    )
    require(
        o["availability"]
        in (
            "metadata_only",
            "capture_disabled",
            "redacted",
            "truncated",
            "unsupported",
            "source_unavailable",
        )
    )
    require("content_truncated" not in gaps or o["availability"] == "truncated")
    s = o["source"]
    require(type(s) is dict)
    kind = o["kind"]
    if s.get("channel") == "transcript":
        tokens = {
            "parser_observation_token",
            "parser_logical_token",
            "stream_token",
            "record_token",
        }
        require(
            s.keys()
            == tokens
            | {
                "channel",
                "parser_evidence_version",
                "byte_position",
                "part",
                "record_origin",
            }
        )
        require(all(match(HEX, s[t]) for t in tokens))
        require(
            integer(s["parser_evidence_version"], 1, 1)
            and integer(s["byte_position"], 1)
            and integer(s["part"], 0, 65535)
        )
        require(
            s["record_origin"] in ("native", "parser_generated")
            and kind
            in (
                "session.start",
                "sensor",
                "prompt",
                "file.read",
                "network",
                "tool.result",
            )
        )
        require(
            kind not in ("session.start", "sensor")
            or s["record_origin"] == "parser_generated"
        )
    else:
        require(
            s.keys() == {"channel", "native_event", "collector_observation_id"}
            and s["channel"] == "hook"
        )
        require(
            match(UUID4, s["collector_observation_id"])
            and s["native_event"] in HOOK_KINDS
            and HOOK_KINDS[s["native_event"]] == kind
        )
        require(
            ("missing_native_session_id" in gaps) == ("native_session_token" not in o)
        )
        require(
            ("missing_native_tool_call_id" in gaps)
            == (kind != "prompt" and "native_tool_call_token" not in o)
        )
    check_observation_size(canonical(o))


def check_observation_size(encoded: bytes) -> None:
    require(len(encoded) <= MAX_OBSERVATION)


def validate_observation(observation: dict) -> None:
    try:
        _validate(observation)
    except (ValueError, TypeError, KeyError, OverflowError):
        raise Invalid() from None


def receipt(
    data: bytes, enrollment: str, batch: str, expected: tuple[tuple[int, str], ...]
) -> list[str]:
    body = wire_json(data, MAX_BATCH)
    require(
        isinstance(body, dict)
        and body.keys() == {"version", "enrollment_id", "batch_id", "results"}
    )
    require(
        integer(body["version"], 1, 1)
        and body["enrollment_id"] == enrollment
        and body["batch_id"] == batch
    )
    rows = body["results"]
    require(type(rows) is list and 1 <= len(rows) <= len(expected) <= 32)
    outcomes = []
    for row, (ordinal, sha) in zip(rows, expected):
        require(
            type(row) is dict
            and integer(row.get("ordinal"), 1)
            and row["ordinal"] == ordinal
            and row.get("digest") == sha
        )
        base = {"ordinal", "digest", "outcome"}
        if row.get("outcome") in ("accepted", "duplicate"):
            require(row.keys() == base | {"event_id"} and match(UUID4, row["event_id"]))
            outcomes.append(row["outcome"])
        else:
            require(
                row.keys() == base | {"reason"}
                and row["outcome"] == "rejected"
                and row["reason"] in ("identity_conflict", "retired_ordinal")
            )
            outcomes.append(
                "server_conflict"
                if row["reason"] == "identity_conflict"
                else "retired_ordinal"
            )
    return outcomes

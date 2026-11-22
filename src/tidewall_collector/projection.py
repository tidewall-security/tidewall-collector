"""Allowlisted v1 metadata from transient Claude transcript and hook inputs."""

import hmac
import re
from datetime import UTC, datetime
from uuid import RFC_4122, UUID

from openaidr.core.hook_protocol import normalize
from openaidr.sensor.collectors import native_id, native_record_id

from tidewall_collector import UPSTREAM_SHA

__all__ = ["ProjectionError", "project_hook", "project_transcript"]

_AGENT = "claude-code"
_PROFILE = "claude-fixture-v1"
_TOOL_NAMES = ("Read", "WebFetch")
_TRANSCRIPT_TOOLS = ("file.read", "network", "tool.result")
_PARSER_RECORD_KINDS = ("sensor", "session.start")
_TRANSCRIPT_KINDS = ("prompt", *_TRANSCRIPT_TOOLS, *_PARSER_RECORD_KINDS)
_HOOK_KINDS = {
    "UserPromptSubmit": "prompt",
    "PreToolUse": "tool.call",
    "PostToolUse": "tool.result",
}
_PARSER_GAPS = {
    "content_truncated",
    "malformed_record",
    "missing_tool_call",
    "skipped_content",
    "unsupported_content",
}
_MAX_BYTE_POSITION = (1 << 53) - 1
_MAX_PART = (1 << 16) - 1
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_HEX_ID = re.compile(r"[0-9a-f]{64}")
_NATIVE_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


class ProjectionError(ValueError):
    """Content-free error for fixture admission to classify."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _validate_context(key: bytes, adapter_version: str) -> None:
    if (
        not isinstance(key, bytes)
        or len(key) != 32
        or not isinstance(adapter_version, str)
        or len(adapter_version) > 24
        or _VERSION.fullmatch(adapter_version) is None
    ):
        raise ProjectionError("invalid_shape")


def _token(key: bytes, domain: str, value: str) -> str:
    return hmac.digest(key, (domain + "\0" + value).encode("utf-8"), "sha256").hex()


def _parser_id(value: object) -> str:
    if not isinstance(value, str) or _HEX_ID.fullmatch(value) is None:
        raise ProjectionError("invalid_shape")
    return value


def _transcript_source(
    record: dict, event: dict, *, stream_id: str, key: bytes
) -> dict:
    evidence = event.get("evidence")
    source = event.get("source")
    if not isinstance(evidence, dict) or not isinstance(source, dict):
        raise ProjectionError("invalid_shape")

    version = evidence.get("version")
    position = evidence.get("sequence")
    part = evidence.get("part")
    if (
        native_id(stream_id) is None
        or evidence.get("stream_id") != stream_id
        or type(version) is not int
        or version != 1
        or type(position) is not int
        or not 1 <= position <= _MAX_BYTE_POSITION
        or type(part) is not int
        or not 0 <= part <= _MAX_PART
    ):
        raise ProjectionError("invalid_shape")

    record_id = source.get("record_id")
    origin = source.get("record_origin")
    if origin == "native" and event["kind"] not in _PARSER_RECORD_KINDS:
        native_key = native_record_id(record)
        if native_key is None or record_id != native_key:
            raise ProjectionError("invalid_shape")
        record_token = _token(key, "native_record", native_key)
    elif origin == "parser_generated":
        record_token = _token(key, "parser_record", _parser_id(record_id))
    else:
        raise ProjectionError("invalid_shape")

    return {
        "channel": "transcript",
        "parser_observation_token": _token(
            key, "parser_observation", _parser_id(evidence.get("observation_id"))
        ),
        "parser_logical_token": _token(
            key, "parser_logical", _parser_id(evidence.get("logical_id"))
        ),
        "parser_evidence_version": version,
        "stream_token": _token(key, "stream", stream_id),
        "byte_position": position,
        "part": part,
        "record_token": record_token,
        "record_origin": origin,
    }


def _observation(kind: str, source: dict, adapter_version: str) -> dict:
    return {
        "agent": _AGENT,
        "fixture_profile": _PROFILE,
        "upstream_sha": UPSTREAM_SHA,
        "adapter_version": adapter_version,
        "kind": kind,
        "source": source,
    }


def _linkage(
    observation: dict,
    gaps: set[str],
    key: bytes,
    *,
    session_id: object,
    tool_call_id: object = None,
    tool_name: object = None,
    tool_event: bool = False,
) -> None:
    session_id = native_id(session_id)
    if session_id is None:
        gaps.add("missing_native_session_id")
    else:
        observation["native_session_token"] = _token(key, "session", session_id)
    if tool_event:
        tool_call_id = native_id(tool_call_id)
        if tool_call_id is None:
            gaps.add("missing_native_tool_call_id")
        else:
            observation["native_tool_call_token"] = _token(
                key, "tool_call", tool_call_id
            )
        if tool_name in _TOOL_NAMES:
            observation["tool_name"] = tool_name


def _availability(gaps: set[str]) -> str:
    if "content_truncated" in gaps:
        return "truncated"
    if "malformed_record" in gaps:
        return "source_unavailable"
    if "unsupported_content" in gaps:
        return "unsupported"
    return "metadata_only"


def _source_time(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or _NATIVE_TIME.fullmatch(value) is None
        or value.endswith("-00:00")
    ):
        return None
    try:
        return (
            datetime.fromisoformat(value)
            .astimezone(UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (ValueError, OverflowError):
        return None


def project_transcript(
    record: dict, event: dict, *, stream_id: str, key: bytes, adapter_version: str
) -> dict:
    """Project one event from the selected parser. Supply {} for a framing gap."""
    _validate_context(key, adapter_version)
    if not isinstance(record, dict) or not isinstance(event, dict):
        raise ProjectionError("invalid_shape")
    kind = event.get("kind")
    if not isinstance(kind, str):
        raise ProjectionError("invalid_shape")
    if kind not in _TRANSCRIPT_KINDS:
        raise ProjectionError("unsupported_record")

    source = _transcript_source(record, event, stream_id=stream_id, key=key)
    observation = _observation(kind, source, adapter_version)

    parser_gaps = event["evidence"].get("gaps")
    if not isinstance(parser_gaps, list) or any(
        not isinstance(gap, str) for gap in parser_gaps
    ):
        raise ProjectionError("invalid_shape")
    gaps = {gap if gap in _PARSER_GAPS else "other_parser_gap" for gap in parser_gaps}

    session = event.get("session", {})
    tool = event.get("tool", {})
    if not isinstance(session, dict) or not isinstance(tool, dict):
        raise ProjectionError("invalid_shape")
    session_id = record.get("sessionId")
    _linkage(
        observation,
        gaps,
        key,
        session_id=session_id if session.get("id") == session_id else None,
        tool_call_id=tool.get("call_id"),
        tool_name=tool.get("name") if "missing_tool_call" not in gaps else None,
        tool_event=kind in _TRANSCRIPT_TOOLS,
    )
    source_at = _source_time(record.get("timestamp"))
    if source_at is not None:
        observation["source_at"] = source_at
    observation["gaps"] = sorted(gaps)
    observation["availability"] = _availability(gaps)
    return observation


def project_hook(
    payload: dict, *, observation_id: UUID, key: bytes, adapter_version: str
) -> dict:
    """Project explicitly supplied Claude hook data under its journal UUID."""
    _validate_context(key, adapter_version)
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("hook_event_name"), str)
        or not isinstance(observation_id, UUID)
        or observation_id.version != 4
        or observation_id.variant != RFC_4122
    ):
        raise ProjectionError("invalid_shape")

    normalized = normalize(_AGENT, payload)
    native_event = normalized["hook_event_name"]
    kind = _HOOK_KINDS.get(native_event)
    if kind is None:
        raise ProjectionError("unsupported_record")

    observation = _observation(
        kind,
        {
            "channel": "hook",
            "collector_observation_id": str(observation_id),
            "native_event": native_event,
        },
        adapter_version,
    )
    gaps: set[str] = set()
    _linkage(
        observation,
        gaps,
        key,
        session_id=normalized.get("session_id"),
        tool_call_id=normalized.get("tool_use_id"),
        tool_name=normalized.get("tool_name"),
        tool_event=kind != "prompt",
    )
    observation["gaps"] = sorted(gaps)
    observation["availability"] = "metadata_only"
    return observation

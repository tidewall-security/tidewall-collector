"""Claude transcript parser extracted from OpenAIDR by Tidewall.

Tidewall removed discovery, polling, host/path/time hints and other agent
parsers. The caller supplies an opaque stream ID and source position.
"""

import copy
import hashlib
import json

from openaidr.core.toolmap import map_tool

MAX_PENDING_BYTES = 256 << 10
INJECTED = (
    "<environment_context>",
    "<permissions instructions>",
    "<turn_aborted>",
    "<user_instructions>",
    "<collaboration_mode>",
    "# AGENTS.md instructions",
    "<app-context>",
    "<skills_instructions>",
)
CLAUDE_INJECTED = (
    "<command-name>",
    "<command-message>",
    "<local-command-stdout>",
    "<local-command-caveat>",
    "<system-reminder>",
    "<ide_opened_file>",
    "<bash-input>",
    "<bash-stdout>",
    "<bash-stderr>",
    "<task-notification>",
)


def content_text(value, injected=False, gaps=None):
    gaps = gaps if gaps is not None else []
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        texts = []
        for part in value:
            if not isinstance(part, dict) or not isinstance(part.get("text"), str):
                gaps.append("unsupported_content")
            elif injected and part["text"].strip().startswith(INJECTED):
                gaps.append("skipped_content")
            elif part["text"]:
                texts.append(part["text"])
        return "\n".join(texts)
    if isinstance(value, dict):
        text = value.get("text") or value.get("output")
        if isinstance(text, str):
            return text
        text = json.dumps(value)
        if len(text) > 4096:
            gaps.append("content_truncated")
        return text[:4096]
    if value is not None:
        gaps.append("unsupported_content")
    return ""


def _identity(*parts):
    return hashlib.sha256(
        json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def native_id(value: object) -> str | None:
    """Return a bounded opaque ID without accepting paths or free text."""
    if (
        isinstance(value, str)
        and 1 <= len(value) <= 256
        and all(char.isalnum() or char in "_.:-" for char in value)
    ):
        return value
    return None


def native_record_id(record: dict) -> str | None:
    return native_id(record.get("uuid")) or native_id(record.get("id"))


class Parser:
    def __init__(self, *, stream_id, fresh=True, started=False):
        if native_id(stream_id) is None:
            raise ValueError("invalid stream ID")
        self.product = "claude-code"
        self.fresh = fresh
        self.started = started
        self.session_known = False
        self.pending = {}
        self.pending_bytes = 0
        self.stream_id = stream_id
        self.sequence = 0
        self.record_gaps = []
        self.stream_gaps = []

    def evidence(self, record, line, events, gaps=(), position=None, *, gap_key=None):
        position = line if position is None else position
        if not events and gaps:
            events = [dict(self.base(record, line), kind="sensor")]
            if not self.session_known:
                self.stream_gaps = sorted(set(self.stream_gaps + list(gaps)))
        gaps = sorted(set(list(gaps) + self.stream_gaps))
        native_key = native_record_id(record)
        record_key = native_key or gap_key or _identity(self.stream_id, position)
        part = 0
        for event in events:
            kind = event["kind"]
            source = event["source"]
            if kind in ("session.start", "sensor"):
                event_part = 0
                # Lifecycle and gap observations are parser-generated even
                # when they describe a record with a native ID.
                source["record_id"] = gap_key or _identity(
                    self.stream_id, position, kind
                )
                source["record_origin"] = "parser_generated"
            else:
                part += 1
                event_part = part
                source["record_id"] = record_key
                source["record_origin"] = "native" if native_key else "parser_generated"
            tool_id = native_id(event.get("tool", {}).get("call_id"))
            if tool_id is not None:
                logical_id = _identity(
                    self.product,
                    event.get("session", {}).get("id", ""),
                    "result" if kind == "tool.result" else "call",
                    tool_id,
                )
            else:
                logical_id = _identity(
                    self.product, self.stream_id, record_key, kind, event_part
                )
            event["evidence"] = {
                "version": 1,
                "logical_id": logical_id,
                "observation_id": _identity(
                    self.stream_id, position, event_part, kind, record_key
                ),
                "stream_id": self.stream_id,
                "sequence": position,
                "part": event_part,
                "gaps": sorted(set(gaps + event.pop("_evidence_gaps", []))),
            }
        return events

    def gap(self, reason, line=0, position=None):
        position = line if position is None else position
        # Keep upstream's explicit gap identity with its empty marker. Fixture
        # framing never supplies a raw input snippet as part of the identity.
        return self.evidence(
            {}, line, [], [reason], position, gap_key=_identity(reason, "", position)
        )

    def base(self, record, line=0):
        event = {
            "agent": {"product": self.product},
            "source": {"collector": self.product, "line": line},
        }
        session_id = native_id(record.get("sessionId"))
        if session_id is not None:
            event["session"] = {"id": session_id}
        return event

    def remember(self, call_id, event):
        if call_id:
            self.pop_call(call_id)
            # Results only inherit a tool name and mapped command, not the raw
            # tool input, session, or source record retained in the call event.
            context = {"tool": {"name": event.get("tool", {}).get("name", "unknown")}}
            if event.get("command"):
                context["command"] = event["command"]
            size = len(json.dumps([call_id, context], ensure_ascii=True))
            if size > MAX_PENDING_BYTES:
                return
            while self.pending and self.pending_bytes + size > MAX_PENDING_BYTES:
                self.pop_call(next(iter(self.pending)))
            self.pending[call_id] = (size, copy.deepcopy(context))
            self.pending_bytes += size
            while len(self.pending) > 500:
                self.pop_call(next(iter(self.pending)))

    def pop_call(self, call_id):
        size, context = self.pending.pop(call_id, (0, {}))
        self.pending_bytes -= size
        return context

    def parse(self, record, line=0, position=None):
        self.sequence = line or self.sequence + 1
        line = self.sequence
        if not isinstance(record, dict):
            return self.gap("malformed_record", line, position=position)
        self.record_gaps = []
        try:
            events = self.claude(record, line)
        except (AttributeError, KeyError, TypeError, ValueError):
            events = []
            self.record_gaps.append("malformed_record")
        return self.evidence(record, line, events, self.record_gaps, position)

    def claude(self, r, line):
        if r.get("type") not in ("user", "assistant"):
            return []
        if (
            not isinstance(r.get("message"), dict)
            or native_id(r.get("sessionId")) is None
        ):
            self.record_gaps.append("malformed_record")
            return []
        self.session_known = True
        base = self.base(r, line)
        out = (
            [dict(copy.deepcopy(base), kind="session.start")]
            if self.fresh and not self.started
            else []
        )
        self.started = True
        content = r["message"].get("content", [])
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        if not isinstance(content, list):
            self.record_gaps.append("malformed_record")
        texts = []
        for block in content if isinstance(content, list) else []:
            if not isinstance(block, dict):
                self.record_gaps.append("malformed_record")
                continue
            typ = block.get("type")
            e = copy.deepcopy(base)
            if typ == "text":
                text = block.get("text", "")
                if not isinstance(text, str):
                    self.record_gaps.append("malformed_record")
                elif r["type"] == "user":
                    texts.append(text)
                elif text.strip():
                    out.append(dict(e, kind="response", text=text))
            elif typ == "tool_use" and r["type"] == "assistant":
                e.update(
                    map_tool(self.product, block.get("name", ""), block.get("input"))[0]
                )
                e["tool"] = {
                    "name": block.get("name", ""),
                    "call_id": block.get("id", ""),
                    "input": block.get("input"),
                    "caller": "subagent"
                    if r.get("isSidechain")
                    else (block.get("caller") or {})
                    .get("type", "")
                    .replace("direct", ""),
                }
                self.remember(native_id(block.get("id")), e)
                out.append(e)
            elif typ == "tool_result" and r["type"] == "user":
                call = self.pop_call(native_id(block.get("tool_use_id")))
                e.update(
                    kind="tool.result",
                    tool={
                        "name": call.get("tool", {}).get("name", "unknown"),
                        "call_id": block.get("tool_use_id", ""),
                        "output": content_text(
                            block.get("content"), gaps=self.record_gaps
                        ),
                        "is_error": bool(block.get("is_error")),
                    },
                )
                if not call:
                    e["_evidence_gaps"] = ["missing_tool_call"]
                if call.get("command"):
                    e["command"] = call["command"]
                    result = r.get("toolUseResult") or {}
                    if isinstance(result, dict):
                        for key in ("exitCode", "exit_code", "code"):
                            if key in result:
                                e["command"]["exit_code"] = result[key]
                                break
                out.append(e)
            else:
                self.record_gaps.append("unsupported_content")
        text = "\n".join(texts)
        if (
            text.strip()
            and not text.strip().startswith(CLAUDE_INJECTED)
            and not r.get("isSidechain")
            and "toolUseResult" not in r
        ):
            out.append(dict(copy.deepcopy(base), kind="prompt", text=text))
        elif text.strip():
            self.record_gaps.append("skipped_content")
        return out

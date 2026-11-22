"""Frame only the two explicitly supplied synthetic fixture files."""

import json
import os
import stat
from contextlib import ExitStack
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4

from openaidr.sensor.collectors import Parser

from . import __version__
from .admission import MAX_INT
from .projection import ProjectionError, project_hook, project_transcript
from .state import Owner, QueueError, QueueState

RECORD_LIMIT = 64 << 10
HOOK_LIMIT = 256 << 10
FIXTURE_NAMES = ("claude-session.jsonl", "claude-hooks.json")


def _identity(f: BinaryIO) -> tuple[str, int, int]:
    st = os.fstat(f.fileno())
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise QueueError("invalid_fixture")
    return (
        f"{st.st_dev}/{st.st_ino}/{getattr(st,'st_birthtime_ns',0)}",
        st.st_size,
        st.st_mtime_ns,
    )


def _transcript(
    f: BinaryIO, owner: Owner, state: QueueState, key: bytes, independent: bool
) -> None:
    identity, size, modification = _identity(f)
    stream = state.fixture_stream(
        owner, "transcript", identity, size, modification, independent=independent
    )
    done = state.checkpoint(owner, stream)
    parser = Parser(stream_id=str(stream))
    line = 0
    incomplete = False
    while f.tell() < size:
        start = f.tell()
        line += 1
        raw = f.readline(min(RECORD_LIMIT + 1, size - start))
        if not raw:
            raise QueueError("source_changed")
        oversized = len(raw) > RECORD_LIMIT
        while not raw.endswith(b"\n") and f.tell() < size:
            raw = f.readline(min(RECORD_LIMIT + 1, size - f.tell()))
            if not raw:
                raise QueueError("source_changed")
            oversized = True
        if not raw.endswith(b"\n"):
            incomplete = True
            break
        end = f.tell()
        if start < done < end:
            raise QueueError("source_changed")
        losses = []
        record = {}
        if oversized:
            losses.append("oversized_input")
        else:
            try:
                value = json.loads(raw.decode("utf-8"))
                if isinstance(value, dict):
                    record = value
                else:
                    losses.append("invalid_shape")
            except (ValueError, RecursionError):
                losses.append("invalid_json")
        # Rebuild only the parser's transient context for the checkpointed prefix.
        events = (
            parser.gap("malformed_record", line=line, position=start + 1)
            if losses
            else parser.parse(record, line=line, position=start + 1)
        )
        if end <= done:
            continue
        observations = []
        if not events and not losses:
            losses.append("unsupported_record")
        for event in events:
            try:
                observations.append(
                    project_transcript(
                        record,
                        event,
                        stream_id=str(stream),
                        key=key,
                        adapter_version=__version__,
                    )
                )
            except ProjectionError as exc:
                losses.append(exc.code)
        state.admit_record(
            owner, stream, start, end, observations, losses=tuple(losses)
        )
    state.fixture_tail(owner, stream, incomplete)


def _hook_frames(raw: bytes) -> list[tuple[object, int]]:
    # The container is bounded first. Retain the exact element spans so whitespace
    # inside a native object also counts towards the per-invocation input bound.
    text = raw.decode("utf8")
    decoder = json.JSONDecoder()

    def skip(index: int) -> int:
        while index < len(text) and text[index] in " \n\r\t":
            index += 1
        return index

    i = skip(0)
    if text[i : i + 1] != "[":
        json.loads(text)
        raise QueueError("invalid_shape")
    i = skip(i + 1)
    frames = []
    if text[i : i + 1] != "]":
        while True:
            value, end = decoder.raw_decode(text, i)
            frames.append((value, len(text[i:end].encode("utf8"))))
            i = skip(end)
            if text[i : i + 1] == "]":
                break
            if text[i : i + 1] != ",":
                raise ValueError
            i = skip(i + 1)
    if skip(i + 1) != len(text):
        raise ValueError
    return frames


def _hooks(
    f: BinaryIO, owner: Owner, state: QueueState, key: bytes, independent: bool
) -> None:
    identity, size, modification = _identity(f)
    stream = state.fixture_stream(
        owner, "hook", identity, size, modification, independent=independent
    )
    checkpoint = state.checkpoint(owner, stream)
    if checkpoint == MAX_INT:
        return
    raw = f.read(HOOK_LIMIT + 1)
    loss = None
    frames = []
    if len(raw) > HOOK_LIMIT:
        loss = "oversized_input"
    else:
        try:
            frames = _hook_frames(raw)
        except QueueError:
            loss = "invalid_shape"
        except (ValueError, RecursionError):
            loss = "invalid_json"
    if loss:
        # A malformed/over-budget container is one framed source outcome.
        state.admit_record(owner, stream, checkpoint, MAX_INT, [], losses=(loss,))
        return
    for index, (payload, length) in enumerate(frames, start=1):
        if index <= checkpoint:
            continue
        observations = []
        losses = []
        if length > RECORD_LIMIT:
            losses.append("oversized_input")
        elif not isinstance(payload, dict):
            losses.append("invalid_shape")
        else:
            try:
                observations.append(
                    project_hook(
                        payload,
                        observation_id=uuid4(),
                        key=key,
                        adapter_version=__version__,
                    )
                )
            except ProjectionError as exc:
                losses.append(exc.code)
        state.admit_record(
            owner, stream, index - 1, index, observations, losses=tuple(losses)
        )


def read_fixture(
    root: Path,
    owner: Owner,
    state: QueueState,
    *,
    independent: frozenset[str] = frozenset(),
) -> None:
    """Use a dedicated directory containing exactly claude-session.jsonl and claude-hooks.json."""
    if not independent <= {"transcript", "hook"}:
        raise QueueError("invalid_fixture")
    try:
        with ExitStack() as stack:
            absolute = Path(root).absolute()
            if ".." in absolute.parts:
                raise QueueError("invalid_fixture")
            flags = os.O_NOFOLLOW | os.O_RDONLY | os.O_DIRECTORY
            fd = os.open(absolute.anchor, flags)
            stack.callback(os.close, fd)
            for part in absolute.parts[1:]:
                fd = os.open(part, flags, dir_fd=fd)
                stack.callback(os.close, fd)
            with os.scandir(fd) as entries:
                for entry in entries:
                    if entry.name not in FIXTURE_NAMES:
                        raise QueueError("invalid_fixture")
            files = []
            for name in FIXTURE_NAMES:
                f = stack.enter_context(
                    os.fdopen(
                        os.open(
                            name, os.O_NOFOLLOW | os.O_NONBLOCK | os.O_RDONLY, dir_fd=fd
                        ),
                        "rb",
                    )
                )
                _identity(f)
                files.append(f)
            key = state.projection_key(owner)
            _transcript(files[0], owner, state, key, "transcript" in independent)
            _hooks(files[1], owner, state, key, "hook" in independent)
    except (OSError, RecursionError):
        raise QueueError("invalid_fixture") from None

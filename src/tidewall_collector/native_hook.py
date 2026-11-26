"""POSIX UserPromptSubmit callback. One original budget, one transient attempt."""

from contextlib import contextmanager, suppress
import os
import select
import signal
import time

from openaidr.guardrail.hooks import native_response

from . import admission, native_contract as wire
from .native_state import LOCAL_CODES, NativeState
from .state import QueueError
from .tidewall_backend import BackendError

BUDGET = 1.8
OUTPUT_RESERVE = 0.1
STDIN_LIMIT = 65536


class _Expired(BaseException):
    """Escape even blocking local filesystem work in the dedicated POSIX callback."""


@contextmanager
def _alarm(seconds):
    def expired(*_):
        raise _Expired

    if seconds <= 0:
        raise _Expired
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _read(stream, deadline, clock):
    fd = stream.fileno()
    data = bytearray()
    while len(data) <= STDIN_LIMIT:
        remaining = deadline - clock()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise BackendError("timeout")
        part = os.read(fd, min(8192, STDIN_LIMIT + 1 - len(data)))
        if not part:
            try:
                return admission.wire_json(bytes(data), STDIN_LIMIT, allow_float=True)
            except ValueError:
                raise BackendError("invalid_input") from None
        data.extend(part)
    raise BackendError("input_limit")


def _emit(fd, data, deadline, clock, recheck):
    # One small unbuffered write is the handoff. POSIX pipe writes of this
    # size are atomic. Native process launchers can also supply a socketpair.
    try:
        was_blocking = os.get_blocking(fd)
        os.set_blocking(fd, False)
        try:
            remaining = deadline - clock()
            if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
                raise BackendError("timeout")
            recheck()
            if clock() >= deadline:
                raise BackendError("timeout")
            if os.write(fd, data) != len(data):
                raise BackendError("stdout_failed")
        finally:
            os.set_blocking(fd, was_blocking)
    except OSError:
        raise BackendError("stdout_failed") from None


def _diagnostic(code):
    # A full diagnostic pipe must never delay callback exit.
    try:
        blocking = os.get_blocking(2)
        os.set_blocking(2, False)
        try:
            os.write(2, (code + "\n").encode("ascii"))
        finally:
            os.set_blocking(2, blocking)
    except OSError:
        pass


def run(stdin, stdout, *, backend, session_config, clock=time.monotonic, started=None):
    deadline = (clock() if started is None else started) + BUDGET
    transport_end = deadline - OUTPUT_RESERVE
    state = row = auth = None
    try:
        with _alarm(deadline - clock()):
            state = NativeState(backend, session_config)
            try:
                with state.open() as session:
                    row = session.reserve_invocation()
                    auth = session.authority()
                event = _read(stdin, transport_end, clock)
                # Separate reservation from admission; opening a slow stdin cannot
                # retain an owner lock or silently use an earlier consent.
                with state.open(auth.owner, auth.generation) as session:
                    if session.authority() != auth:
                        raise BackendError("stale_authority")
                    session.check_event(event)
                metadata = dict(
                    version=1,
                    occurrence_id=row["occurrence_id"],
                    agent="claude-code",
                    native_profile=wire.PROFILE,
                    agent_version=wire.VERSION,
                    session_token=auth.session_token,
                )
                request = dict(
                    version=1,
                    request_id=row["request_id"],
                    observation=metadata,
                    input_state="capture_disabled",
                    budget_ms=1800,
                )
                if auth.capture and auth.grant["capture_allowed"]:
                    prompt = event.get("prompt")
                    request["input_state"] = wire.input_state(prompt)
                    if request["input_state"] == "complete":
                        request["prompt"] = prompt
                        if len(wire.encode(request)) > 16384:
                            del request["prompt"]
                            request["input_state"] = "input_too_large"
                del event
                budget_ms = int((transport_end - clock()) * 1000)
                if budget_ms < 1:
                    raise BackendError("timeout")
                request["budget_ms"] = min(1800, budget_ms)
                reply = backend.decide_native(auth, request, transport_end)
                wire.parse("NativeDecisionReply", wire.encode(reply))
                wire.bind_decision(reply, request, auth)
                del request
                if clock() >= transport_end:
                    raise BackendError("timeout")
                with state.open(auth.owner, auth.generation) as session:
                    current = session.authority()
                    if current != auth:
                        raise BackendError("stale_authority")
                    session.prepared(row["request_id"], reply, auth)
                    # Keep the credential lock from this recheck through output.
                    # No filesystem writes or HTTP follow a successful handoff.
                    if clock() >= deadline:
                        raise BackendError("timeout")
                    session.authority()
                    if reply["returned_action"] == "deny":
                        _, directive = native_response(
                            "claude-code",
                            "UserPromptSubmit",
                            "deny",
                            "Blocked by Tidewall policy",
                            {},
                        )
                        _emit(
                            stdout.fileno(),
                            wire.encode(directive) + b"\n",
                            deadline,
                            clock,
                            session.output_authority,
                        )
                return 0
            except (ValueError, KeyError, TypeError, OSError, QueueError) as exc:
                code = getattr(exc, "code", None)
                if isinstance(exc, BrokenPipeError):
                    code = "stdout_failed"
                if code not in LOCAL_CODES | {"stdout_failed"}:
                    code = (
                        "storage_unavailable"
                        if isinstance(exc, (QueueError, OSError, BackendError))
                        else "invalid_reply"
                    )
                if (
                    row is not None
                    and code != "stdout_failed"
                    and clock() < transport_end
                ):
                    # A lost/corrupt binding can also prevent recording the
                    # failure. Preserve the original closed diagnostic.
                    with (
                        suppress(OSError, ValueError, _Expired),
                        state.open() as session,
                    ):
                        session.unavailable(row["request_id"], code)
                _diagnostic(code)
    except _Expired:
        _diagnostic("timeout")
    except (OSError, ValueError, QueueError):
        _diagnostic("storage_unavailable")
    return 0

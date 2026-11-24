"""Explicit-state commands for synthetic fixture collection."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import time
from uuid import UUID

from .state import QueueError, QueueState
from .tidewall_backend import BackendError, RECOVERY_WARNING, TidewallBackend


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):
        # argparse's default diagnostic repeats unrecognized argument values.
        raise BackendError("invalid_arguments")


def _protected_fd(fd: int, limit: int) -> bytes:
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or not (
        stat.S_ISREG(info.st_mode)
        and not info.st_mode & 0o077
        or stat.S_ISFIFO(info.st_mode)
        and (info.st_nlink == 0 or not info.st_mode & 0o077)
    ):
        raise BackendError("unprotected_input")
    data = bytearray()
    while len(data) <= limit:
        part = os.read(fd, limit + 1 - len(data))
        if not part:
            break
        data.extend(part)
    if len(data) > limit:
        raise BackendError("invalid_credential")
    return bytes(data)


def _secret_fd(fd: int) -> str:
    try:
        return (
            _protected_fd(fd, 512).decode("ascii").removesuffix("\n").removesuffix("\r")
        )
    except UnicodeError:
        raise BackendError("invalid_credential") from None


def main(argv: list[str] | None = None) -> int:
    started = time.monotonic()
    parser = _Parser(prog="tidewall-collector", allow_abbrev=False)
    subs = parser.add_subparsers(dest="command", required=True)
    for cmd in (
        "enrol",
        "recover",
        "fixture",
        "ship",
        "status",
        "offboard",
        "prepare-native-session",
        "claude-hook",
        "report-native",
    ):
        p = subs.add_parser(
            cmd,
            allow_abbrev=False,
            description=RECOVERY_WARNING if cmd == "recover" else None,
        )
        p.add_argument("--state-root", type=Path, required=True)
        p.add_argument(
            "--fixture-loopback-http",
            action="store_true",
            help="Permit literal loopback HTTP for an isolated fixture receiver.",
        )
        if cmd in ("prepare-native-session", "claude-hook", "report-native"):
            p.add_argument("--session-config", type=Path, required=True)
        if cmd == "prepare-native-session":
            p.add_argument("--session-id-fd", type=int, required=True)
            p.add_argument("--grant-fd", type=int)
            p.add_argument("--cwd", type=Path, required=True)
            p.add_argument("--agent-version", required=True)
            p.add_argument("--capture", action="store_true")
            p.add_argument(
                "--new-session",
                action="store_true",
                help="Select a fresh metadata-only session and discard prior local reports.",
            )
        if cmd == "report-native":
            mode = p.add_mutually_exclusive_group()
            mode.add_argument("--list", action="store_true")
            mode.add_argument("--evidence-fd", type=int)
        if cmd in ("recover", "enrol"):
            p.add_argument("--origin", required=True)
            p.add_argument("--registration-fd", type=int, required=True)
        if cmd == "recover":
            p.add_argument("--installation-id", type=UUID, required=True)
            p.add_argument("--recovery-fd", type=int, required=True)
        if cmd == "fixture":
            p.add_argument("--fixture-dir", type=Path, required=True)
            p.add_argument(
                "--independent",
                choices=("hook", "transcript"),
                action="append",
                default=[],
            )
        if cmd == "offboard":
            p.add_argument("--device-id", type=UUID, required=True)
        if cmd == "ship":
            p.add_argument(
                "--resume-contract",
                action="store_true",
                help="Retry held rows after verifying receiver compatibility.",
            )
    try:
        args = parser.parse_args(argv)
        back = TidewallBackend(
            args.state_root, fixture_loopback=args.fixture_loopback_http
        )
        if args.command == "claude-hook":
            from . import native_hook

            return native_hook.run(
                sys.stdin.buffer,
                sys.stdout.buffer,
                backend=back,
                session_config=args.session_config,
                clock=time.monotonic,
                started=started,
            )
        if args.command in ("prepare-native-session", "report-native"):
            from . import native_contract as wire
            from .native_state import NativeState

            native = NativeState(back, args.session_config)
            if args.command == "prepare-native-session":
                if args.grant_fd is not None and os.path.samestat(
                    os.fstat(args.grant_fd), os.fstat(args.session_id_fd)
                ):
                    raise BackendError("separate_inputs_required")
                grant = (
                    wire.parse("NativeGrantIssued", _protected_fd(args.grant_fd, 2048))
                    if args.grant_fd is not None
                    else None
                )
                session_id = (
                    _protected_fd(args.session_id_fd, 1025)
                    .decode("utf-8")
                    .removesuffix("\n")
                    .removesuffix("\r")
                )
                token = native.prepare(
                    session_id,
                    args.cwd,
                    args.agent_version,
                    args.capture,
                    grant,
                    new_session=args.new_session,
                )
                print(json.dumps(dict(session_token=token)))
            else:
                # A protected observer pipe can be slow. Read it before taking
                # the enrollment lock so a stalled reporter cannot starve hooks.
                evidence = (
                    wire.parse(
                        "NativeDeliveryReport", _protected_fd(args.evidence_fd, 2048)
                    )
                    if args.evidence_fd is not None
                    else None
                )
                if args.list:
                    with native.open() as session:
                        summary = json.dumps(session.records)
                    print(summary)
                    return 0
                with native.open() as session:
                    if evidence is not None:
                        session.record_emission(evidence)
                    pending = session.pending_reports()
                sent = 0
                for report in pending:
                    with native.open() as session:
                        if report not in session.pending_reports():
                            continue
                        auth = session.authority()
                    ack = back.report_native(auth, report, time.monotonic() + 5)
                    with native.open(auth.owner, auth.generation) as session:
                        if session.authority() != auth:
                            raise BackendError("stale_authority")
                        session.ack_report(ack)
                    sent += 1
                print(json.dumps(dict(acknowledged=sent)))
            return 0
        if args.command in ("enrol", "recover"):
            if args.command == "recover":
                if args.registration_fd == args.recovery_fd or os.path.samestat(
                    os.fstat(args.registration_fd), os.fstat(args.recovery_fd)
                ):
                    raise BackendError("separate_inputs_required")
                owner = back.recover(
                    args.origin,
                    args.installation_id,
                    _secret_fd(args.registration_fd),
                    _secret_fd(args.recovery_fd),
                    args.state_root,
                )
            else:
                owner = back.enrol(
                    args.origin, _secret_fd(args.registration_fd), args.state_root
                )
            print(
                json.dumps(
                    dict(
                        device_id=str(owner.device_id),
                        installation_id=str(back.installation_id),
                        confirmation_code=back.confirmation_code,
                    )
                )
            )
        elif args.command == "offboard":
            back.offboard(args.device_id)
            print("offboarded")
        else:
            owner = back.owner()
            with QueueState.open(args.state_root / "queue", owner) as q:
                if args.command == "fixture":
                    back.ingest_fixture(
                        owner, q, args.fixture_dir, frozenset(args.independent)
                    )
                elif args.command == "ship":
                    if args.resume_contract:
                        back.resume_contract(owner, q)
                    count = back.ship_once(owner, q)
                    back.send_heartbeat(owner, q)
                    print(json.dumps({"acknowledged": count}))
                else:
                    print(json.dumps(back.status(owner, q)))
        return 0
    except (BackendError, QueueError) as error:
        print(error.code, file=sys.stderr)
        if error.code in {
            "timeout",
            "retry_later",
            "offline",
            "busy",
            "blocked_storage",
            "state_unavailable",
        }:
            return 75
        if error.code == "device_pending":
            return 3
        return 2
    except (OSError, ValueError, RuntimeError):
        print("operation_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

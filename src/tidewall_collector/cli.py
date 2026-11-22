"""Explicit-state commands for synthetic fixture collection."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from uuid import UUID

from .state import QueueError, QueueState
from .tidewall_backend import BackendError, RECOVERY_WARNING, TidewallBackend


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):
        # argparse's default diagnostic repeats unrecognized argument values.
        raise BackendError("invalid_arguments")


def _secret_fd(fd: int) -> str:
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or not (
        stat.S_ISREG(info.st_mode)
        and not info.st_mode & 0o077
        or stat.S_ISFIFO(info.st_mode)
        and (info.st_nlink == 0 or not info.st_mode & 0o077)
    ):
        raise BackendError("unprotected_input")
    data = bytearray()
    while len(data) <= 512:
        part = os.read(fd, 513 - len(data))
        if not part:
            break
        data.extend(part)
    if len(data) > 512:
        raise BackendError("invalid_credential")
    try:
        return data.decode("ascii").removesuffix("\n").removesuffix("\r")
    except UnicodeError:
        raise BackendError("invalid_credential") from None


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="tidewall-collector", allow_abbrev=False)
    subs = parser.add_subparsers(dest="command", required=True)
    for cmd in ("enrol", "recover", "fixture", "ship", "status", "offboard"):
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

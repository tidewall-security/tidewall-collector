"""Crash-resumable first publication of an enrollment's authenticated queue."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack
import os
from pathlib import Path
import sqlite3
from uuid import UUID

from openaidr.core.files import sync_directory

from . import state
from .admission import canonical, digest
from .erasure import detached_path
from .state import Owner, QueueError


def _identity(info: os.stat_result) -> list[int]:
    return [info.st_dev, info.st_ino]


def _install(path: Path, data: bytes) -> None:
    """Install an initial file with no partially written final pathname."""
    scratch = path.with_name("seed.tmp")
    state._create_file(scratch, data)
    os.rename(scratch, path)
    sync_directory(path.parent)


def _prepare(
    path: Path, owner: Owner, birth: dict, persist: Callable[[], None]
) -> None:
    entries = {p.name for p in path.iterdir()}
    if entries - {"seed.tmp", "key", "manifest.json", "initial.db"}:
        raise QueueError("quarantined")
    if (
        "manifest.json" in entries
        and "key" not in entries
        or "initial.db" in entries
        and "manifest.json" not in entries
    ):
        raise QueueError("quarantined")
    if "seed.tmp" in entries:
        # The staging file is never a published key, manifest or journal.
        state._private_file(path / "seed.tmp")
        (path / "seed.tmp").unlink()
    keyfile = path / "key"
    if "key" not in entries:
        _install(keyfile, os.urandom(32))
    key = state._read(keyfile, 32)
    if len(key) != 32:
        raise QueueError("quarantined")

    generation = birth["generation"]
    location = digest(canonical([str(path), *birth["directory"]]))
    manifest = state._manifest_bytes(owner, generation, location, key)
    initial = state._initial_database(generation, key)
    files = {"manifest.json": manifest, "initial.db": initial}
    for name, content in files.items():
        if name not in entries:
            _install(path / name, content)
        elif state._read(path / name, len(content)) != content:
            raise QueueError("quarantined")

    # Persist both the directory and the journal identity before making the DB
    # openable. Even a later failure to save ready=True cannot authorize rekey.
    birth["prepared"] = {
        "journal": _identity(state._private_file(path / "initial.db")),
        "manifest_digest": digest(manifest),
        "initial_digest": digest(initial),
    }
    persist()


def prepare_queue(
    path: Path, owner: Owner, birth: dict, persist: Callable[[], None]
) -> None:
    """Finish a private birth plan; ownership and credential locking belong to the caller."""
    try:
        if (
            set(birth)
            not in (
                {"generation"},
                {"generation", "directory"},
                {"generation", "directory", "prepared"},
            )
            or UUID(birth["generation"]).version != 4
        ):
            raise QueueError("quarantined")
        with state._name_lock(path), ExitStack() as stack:
            if os.path.lexists(detached_path(path, owner)):
                raise QueueError("offboarding")
            if "directory" not in birth and not os.path.lexists(path):
                path.mkdir(mode=0o700)
                sync_directory(path.parent)
            fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY)
            stack.callback(os.close, fd)
            state._lock(fd)
            info = os.fstat(fd)
            if (
                info.st_uid != os.getuid()
                or info.st_mode & 0o777 != 0o700
                or not os.path.samestat(path.lstat(), info)
            ):
                raise QueueError("quarantined")
            if "directory" not in birth:
                if os.listdir(fd) or "prepared" in birth:
                    raise QueueError("quarantined")
                birth["directory"] = _identity(info)
                persist()
            if birth["directory"] != _identity(info):
                raise QueueError("quarantined")
            if "prepared" not in birth:
                _prepare(path, owner, birth, persist)
            proof = birth["prepared"]
            if (
                digest(state._read(path / "manifest.json", 1536))
                != proof["manifest_digest"]
            ):
                raise QueueError("quarantined")
            staged = path / "initial.db"
            final = path / "state.db"
            if os.path.lexists(staged):
                record = state._private_file(staged)
                if (
                    os.path.lexists(final)
                    or _identity(record) != proof["journal"]
                    or digest(state._read(staged, 64 << 10)) != proof["initial_digest"]
                ):
                    raise QueueError("quarantined")
                os.rename(staged, final)
            if _identity(state._private_file(final)) != proof["journal"]:
                raise QueueError("quarantined")
            sync_directory(path)
    except (FileNotFoundError, KeyError, TypeError):
        raise QueueError("quarantined") from None
    except (OSError, sqlite3.Error):
        raise QueueError("blocked_storage") from None

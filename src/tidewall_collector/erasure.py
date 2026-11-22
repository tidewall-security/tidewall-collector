"""Owner-checked resumption of an explicit local enrollment erasure."""

import fcntl
import hmac
import json
import os
import sqlite3
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

from openaidr.core.files import sync_directory

from .admission import canonical, digest
from .state import DB_PAGES, PAGE_BYTES, Owner, QueueError, _private_file, _read


def detached_path(path: Path, owner: Owner) -> Path:
    # This namespace also binds the last empty-directory cleanup to its owner.
    return path.parent / (
        ".offboard-"
        + digest(canonical([path.name, owner.origin, str(owner.device_id)]))
    )


def _marker(path: Path, fd: int, owner: Owner, generation: UUID, key: bytes) -> str:
    info = os.fstat(fd)
    binding = canonical(
        [
            str(path),
            info.st_dev,
            info.st_ino,
            owner.origin,
            str(owner.device_id),
            str(generation),
        ]
    )
    tag = hmac.digest(key, b"erase\0" + binding, "sha256").hex()
    return f"erase.{generation}.{tag}"


def _files(directory: Path) -> dict[str, Path]:
    entries: dict[str, Path] = {}
    with os.scandir(directory) as scan:
        for item in scan:
            # A full queue of 256 KiB segments takes fewer than 40 entries.
            if len(entries) >= 128:
                raise QueueError("quarantined")
            p = directory / item.name
            _private_file(p)
            entries[item.name] = p
    return entries


def _fingerprint(path: Path) -> list:
    info = _private_file(path)
    # These are the already-projected queue segments and signed owner manifest.
    # Bound even a file substituted between validation and open.
    data = _read(path, 256 << 10)
    if len(data) != info.st_size:
        raise QueueError("quarantined")
    return [info.st_dev, info.st_ino, info.st_size, digest(data)]


def prepare(path: Path, db: sqlite3.Connection, generation: UUID, key: bytes) -> None:
    files = {
        name: _fingerprint(p)
        for name, p in _files(path).items()
        if name == "manifest.json" or name.endswith(".jsonl")
    }
    payload = canonical([str(generation), files])
    if len(payload) > 32 << 10:
        raise QueueError("quarantined")
    tag = hmac.digest(key, b"erase-files\0" + payload, "sha256").hex()
    # Provisional until the key rename commits. Keeping this separate preserves
    # the full source-intent allowance within the existing database page ceiling.
    with db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS erase_proof(id INTEGER PRIMARY KEY CHECK(id=1),payload BLOB NOT NULL,tag TEXT NOT NULL)"
        )
        db.execute("INSERT OR REPLACE INTO erase_proof VALUES(1,?,?)", (payload, tag))


def _validate_files(
    dbpath: Path, key: bytes, generation: UUID, files: dict[str, Path]
) -> None:
    if _private_file(dbpath).st_size > DB_PAGES * PAGE_BYTES:
        raise QueueError("quarantined")
    db = sqlite3.connect(dbpath.as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        row = db.execute("SELECT payload,tag FROM erase_proof WHERE id=1").fetchone()
        if (
            not row
            or type(row[0]) is not bytes
            or len(row[0]) > 32 << 10
            or not hmac.compare_digest(
                row[1], hmac.digest(key, b"erase-files\0" + row[0], "sha256").hex()
            )
        ):
            raise QueueError("quarantined")
        saved, proof = json.loads(row[0])
        if saved != str(generation):
            raise QueueError("quarantined")
        for name, p in files.items():
            if name not in proof or _fingerprint(p) != proof[name]:
                raise QueueError("quarantined")
    except (ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        raise QueueError("quarantined") from None
    finally:
        db.close()


def _finish(
    path: Path, directory: Path, fd: int, owner: Owner, boundary: Callable[[str], None]
) -> bool:
    detached = detached_path(path, owner)
    if not os.path.samestat(os.fstat(fd), directory.lstat()):
        raise QueueError("quarantined")
    entries = _files(directory)
    markers = [name for name in entries if name.startswith("erase.")]
    if not markers:
        if directory == detached:
            if entries:
                raise QueueError("quarantined")
            directory.rmdir()
            sync_directory(path.parent)
            return True
        return False
    if len(markers) != 1 or "key" in entries:
        raise QueueError("quarantined")
    name = markers[0]
    marker = entries.pop(name)
    parts = name.split(".")
    if len(parts) != 3:
        raise QueueError("quarantined")
    try:
        generation = UUID(parts[1])
    except ValueError:
        raise QueueError("quarantined") from None
    key = _read(marker, 32)
    if len(key) != 32:
        raise QueueError("quarantined")
    if not hmac.compare_digest(name, _marker(path, fd, owner, generation, key)):
        raise QueueError("owner_mismatch")
    db = entries.pop("state.db", None)
    manifest = entries.get("manifest.json")
    if directory == detached and (db or manifest or entries):
        raise QueueError("quarantined")
    if db is None and (manifest or entries):
        raise QueueError("quarantined")
    if db is not None:
        _validate_files(db, key, generation, entries)
        if manifest is not None:
            entries.pop("manifest.json")
            manifest.unlink()
            os.fsync(fd)
            boundary("erase_manifest")
        for p in entries.values():
            p.unlink()
            boundary("erase_segment")
        os.fsync(fd)
        if _files(directory).keys() != {name, "state.db"}:
            raise QueueError("quarantined")
        db.unlink()
        os.fsync(fd)
        boundary("erase_database")
    if directory != detached:
        if os.path.lexists(detached):
            raise QueueError("quarantined")
        directory.rename(detached)
        marker = detached / name
    sync_directory(path.parent)
    if _files(detached).keys() != {name}:
        raise QueueError("quarantined")
    boundary("erase_detach")
    marker.unlink()
    os.fsync(fd)
    boundary("erase_key")
    detached.rmdir()
    sync_directory(path.parent)
    return True


def begin(
    path: Path,
    fd: int,
    owner: Owner,
    generation: UUID,
    key: bytes,
    boundary: Callable[[str], None],
) -> None:
    if os.path.lexists(detached_path(path, owner)):
        raise QueueError("offboarding")
    marker = path / _marker(path, fd, owner, generation, key)
    # Atomic rename makes the original key the sole authenticated erase marker.
    # Its removal is the final file unlink. Normal queue opens require "key".
    (path / "key").rename(marker)
    os.fsync(fd)
    boundary("erase_intent")
    _finish(path, path, fd, owner, boundary)


def resume(path: Path, owner: Owner) -> bool:
    detached = detached_path(path, owner)
    directory = detached if os.path.lexists(detached) else path
    try:
        try:
            fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return False
        try:
            info = os.fstat(fd)
            if info.st_mode & 0o777 != 0o700 or info.st_uid != os.getuid():
                raise QueueError("quarantined")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise QueueError("busy") from None
            return _finish(path, directory, fd, owner, lambda _: None)
        finally:
            os.close(fd)
    except (OSError, sqlite3.Error):
        raise QueueError("blocked_storage") from None

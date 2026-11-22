"""Durable, single-writer enrollment queue for the explicit fixture collector."""

import fcntl
import hmac
import json
import os
import sqlite3
import stat
import time
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from openaidr.core.files import sync_directory
from openaidr.sensor.spool import Spool

from . import UPSTREAM_SHA, __version__, admission
from .admission import canonical, digest

DATA_LIMIT = 8 << 20
SEGMENT_LIMIT = 256 << 10
JOURNAL_LIMIT = 1 << 20
# Reserve room for both database and rollback journal. SQLite's page headers
# and hot-journal headers are covered by the remaining margin.
PAGE_BYTES = 4096
DB_PAGES = JOURNAL_LIMIT // (2 * PAGE_BYTES) - 8
PAYLOAD_LIMIT = 224 << 10
TTL = 7 * 86400


class QueueError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class InvalidHead(QueueError):
    def __init__(self, ordinal: int, admission_digest: str):
        self.ordinal = ordinal
        self.admission_digest = admission_digest
        super().__init__("invalid_head")


@dataclass(frozen=True)
class Owner:
    origin: str
    device_id: UUID

    def __post_init__(self) -> None:
        try:
            u = urlsplit(self.origin)
            allowed = u.scheme == "https" or (
                u.scheme == "http" and u.hostname in ("127.0.0.1", "::1")
            )
            if not (
                allowed
                and u.hostname
                and u.username is None
                and u.password is None
                and not u.path
                and not u.fragment
                and not u.query
                and u.port != 0
                and self.origin == f"{u.scheme}://{u.netloc}"
                and isinstance(self.device_id, UUID)
                and self.device_id.version == 4
            ):
                raise ValueError
            if (
                not self.origin.isascii()
                or len(self.origin) > 512
                or any(c.isspace() or ord(c) < 32 for c in self.origin)
            ):
                raise ValueError
        except (ValueError, AttributeError):
            raise QueueError("invalid_owner") from None


@dataclass(frozen=True)
class Disposition:
    checkpoint: int
    enqueued: int
    losses: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class PendingRow:
    ordinal: int
    data: bytes
    digest: str
    end: tuple[int, int]
    enqueued_at: int


@dataclass(frozen=True)
class PendingBatch:
    owner: Owner
    generation: UUID
    batch_id: UUID
    expected_cursor: tuple[int, int]
    rows: tuple[PendingRow, ...]

    @property
    def body(self) -> bytes:
        return canonical(
            {
                "version": 1,
                "enrollment_id": str(self.owner.device_id),
                "batch_id": str(self.batch_id),
                "rows": [
                    {"ordinal": r.ordinal, "observation": json.loads(r.data)}
                    for r in self.rows
                ],
            }
        )


def _lock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise QueueError("busy") from None


@contextmanager
def _name_lock(path: Path) -> Iterator[None]:
    """Serialize active/detached directory entry changes across inode lifetimes."""
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        _lock(fd)
        yield
    finally:
        os.close(fd)


def _private_file(path: Path) -> os.stat_result:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_mode & 0o777 != 0o600
        or info.st_uid != os.getuid()
    ):
        raise QueueError("quarantined")
    return info


def _read(path: Path, limit: int) -> bytes:
    if _private_file(path).st_size > limit:
        raise QueueError("quarantined")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as f:
        return f.read(limit + 1)


def _create_file(path: Path, data: bytes) -> None:
    with os.fdopen(
        os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600), "wb"
    ) as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _initial(generation: str) -> dict:
    return {
        "generation": generation,
        "contract": admission.CONTRACT,
        "streams": {},
        "sources": {},
        "segments": {},
        "last_segment": 0,
        "next_ordinal": 1,
        "cursor": [0, 0],
        "pending": 0,
        "clock": 0,
        "intent": None,
        "terminal": None,
        "unlink": [],
        "flight": None,
        "last_receipt": None,
        "status": "ready",
        "revision": 0,
        "snapshot": None,
        "totals": dict.fromkeys(admission.LOSSES, 0),
        "loss_evidence": {},
    }


def _segment_bounds(j: dict) -> dict[int, list[int]]:
    bounds = {int(n): [size, size] for n, size in j["segments"].items()}
    for n, offset, row in (j["intent"] or {}).get("rows", []):
        bounds.setdefault(n, [0, 0])[1] = offset + len(canonical(row)) + 1
    return bounds


def _permitted_size(j: dict, bounds: dict[int, list[int]], n: int, size: int) -> bool:
    if n in j["unlink"]:
        expected = j.get("unlink_sizes", {}).get(str(n))
        # Older journals have no per-segment unlink sizes. Their last end
        # cursor remains authoritative; verify every retired frame on cleanup.
        if expected is None and n == j["cursor"][0]:
            expected = j["cursor"][1]
        return size == expected if expected is not None else 0 < size <= SEGMENT_LIMIT
    compact = j.get("compact")
    if (
        compact
        and n == compact["segment"]
        and compact["moved"] == compact["original"] - compact["cut"]
        and size == compact["moved"]
    ):
        return True
    return n in bounds and bounds[n][0] <= size <= bounds[n][1]


class QueueState:
    """Hold this handle (and its directory lock) through send and verification."""

    @classmethod
    def create(cls, path: Path, owner: Owner) -> "QueueState":
        return cls(path, owner, create=True)

    @classmethod
    def open(cls, path: Path, owner: Owner) -> "QueueState":
        return cls(path, owner, create=False)

    def __init__(self, path: Path, owner: Owner, *, create: bool):
        self.path = Path(path).absolute()
        self._dir = -1
        self._pid = os.getpid()
        self._db: sqlite3.Connection
        self._blocked = False
        try:
            with _name_lock(self.path):
                if create:
                    from .erasure import detached_path

                    if os.path.lexists(detached_path(self.path, owner)):
                        raise QueueError("offboarding")
                    try:
                        self.path.mkdir(mode=0o700)
                    except FileExistsError:
                        raise QueueError("state_exists") from None
                    sync_directory(self.path.parent)
                self._dir = os.open(
                    self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                )
                _lock(self._dir)
            info = os.fstat(self._dir)
            if info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
                raise QueueError("quarantined")
            self._location = digest(
                canonical([str(self.path), info.st_dev, info.st_ino])
            )
            if create:
                self._key = os.urandom(32)
                generation = str(uuid4())
                manifest = {
                    "origin": owner.origin,
                    "device_id": str(owner.device_id),
                    "generation": generation,
                    "location": self._location,
                }
                _create_file(self.path / "key", self._key)
                _create_file(
                    self.path / "manifest.json",
                    canonical([manifest, self._mac(b"manifest", canonical(manifest))]),
                )
                _create_file(self.path / "state.db", b"")
                sync_directory(self.path)
            self._key = _read(self.path / "key", 32)
            if len(self._key) != 32:
                raise QueueError("quarantined")
            self.owner = owner
            self.generation = self._manifest(owner)
            dbpath = self.path / "state.db"
            self._db_identity = _private_file(dbpath)
            if self._db_identity.st_size > DB_PAGES * PAGE_BYTES:
                raise QueueError("quarantined")
            # SQLite examines sidecars while opening a database. Validate those
            # directory entries before allowing its recovery path to read them.
            for p in self.path.glob("state.db-*"):
                if (
                    p.name != "state.db-journal"
                    or _private_file(p).st_size > JOURNAL_LIMIT // 2
                ):
                    raise QueueError("quarantined")
            self._db = sqlite3.connect(dbpath.as_uri() + "?mode=rw", uri=True)
            if create:
                self._db.execute(f"PRAGMA page_size={PAGE_BYTES}")
            if self._db.execute("PRAGMA page_size").fetchone() != (PAGE_BYTES,):
                raise QueueError("quarantined")
            self._db.execute("PRAGMA secure_delete=ON")
            self._db.execute("PRAGMA journal_mode=DELETE")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA fullfsync=ON")
            self._db.execute("PRAGMA temp_store=MEMORY")
            self._db.execute(f"PRAGMA max_page_count={DB_PAGES}")
            if create:
                self._db.execute(
                    "CREATE TABLE journal(id INTEGER PRIMARY KEY CHECK(id=1),payload BLOB NOT NULL,tag TEXT NOT NULL)"
                )
                self._save(_initial(str(self.generation)))
                sync_directory(self.path)
            if self._db.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
                raise QueueError("quarantined")
            self._inventory(self._load())
            # A crash before the erasure-key rename leaves a reversible preparation.
            # Normal opens still possess the original key and discard that preparation.
            with self._db:
                self._db.execute("DROP TABLE IF EXISTS erase_proof")
            self._spool = Spool(self.path, SEGMENT_LIMIT, DATA_LIMIT)
            self.reconcile(owner)
        except BaseException as exc:
            self.close()
            if isinstance(
                exc, (OSError, sqlite3.Error, TypeError, KeyError, ValueError)
            ) and not isinstance(exc, QueueError):
                raise QueueError(
                    "blocked_storage" if create else "quarantined"
                ) from None
            raise

    def __enter__(self) -> "QueueState":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._dir != -1:
            if hasattr(self, "_db"):
                self._db.close()
            os.close(self._dir)
            self._dir = -1

    def _boundary(self, name: str) -> None:
        """Named transaction boundaries used by the crash-recovery harness."""

    def _mac(self, domain: bytes, data: bytes) -> str:
        return hmac.digest(self._key, domain + b"\0" + data, "sha256").hex()

    def _manifest(self, owner: Owner) -> UUID:
        try:
            if _read(self.path / "key", 32) != self._key:
                raise QueueError("quarantined")
            manifest, signature = json.loads(_read(self.path / "manifest.json", 1536))
            if (
                not hmac.compare_digest(
                    self._mac(b"manifest", canonical(manifest)), signature
                )
                or manifest["location"] != self._location
            ):
                raise QueueError("quarantined")
            if manifest["origin"] != owner.origin or manifest["device_id"] != str(
                owner.device_id
            ):
                raise QueueError("owner_mismatch")
            return UUID(manifest["generation"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            if isinstance(exc, QueueError):
                raise
            raise QueueError("quarantined") from None

    def _authenticate(self, owner: Owner) -> None:
        if self._dir < 0 or self._pid != os.getpid():
            raise QueueError("closed")
        if (
            os.fstat(self._dir).st_mode & 0o777 != 0o700
            or not os.path.samestat(os.fstat(self._dir), self.path.lstat())
            or self._manifest(owner) != self.generation
            or not os.path.samestat(
                _private_file(self.path / "state.db"), self._db_identity
            )
        ):
            raise QueueError("quarantined")

    def _load(self) -> dict:
        try:
            row = self._db.execute(
                "SELECT payload,tag FROM journal WHERE id=1"
            ).fetchone()
            if (
                not row
                or not isinstance(row[0], bytes)
                or len(row[0]) > PAYLOAD_LIMIT
                or not hmac.compare_digest(row[1], self._mac(b"journal", row[0]))
            ):
                raise QueueError("quarantined")
            j = json.loads(row[0])
            if j["generation"] != str(self.generation):
                raise QueueError("quarantined")
            return j
        except (sqlite3.DatabaseError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, QueueError):
                raise
            raise QueueError("quarantined") from None

    def _save(self, j: dict) -> None:
        data = canonical(j)
        if len(data) > PAYLOAD_LIMIT:
            raise QueueError("blocked_storage")
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO journal VALUES (1,?,?)",
                (data, self._mac(b"journal", data)),
            )

    @contextmanager
    def _operation(self, owner: Owner, *, recover: bool = True) -> Iterator[dict]:
        try:
            self._authenticate(owner)
            j = self._load()
            if recover:
                self._recover(j)
            yield j
        except (sqlite3.Error, OSError) as exc:
            if isinstance(exc, FileNotFoundError):
                raise QueueError("quarantined") from None
            self._blocked = True
            raise QueueError("blocked_storage") from None
        except QueueError as exc:
            if exc.code == "blocked_storage":
                self._blocked = True
            raise

    def projection_key(self, owner: Owner) -> bytes:
        with self._operation(owner) as j:
            if j["contract"] != admission.CONTRACT:
                raise QueueError("contract_mismatch")
            return self._key

    def _inventory(self, j: dict) -> None:
        bounds = _segment_bounds(j)
        seen = set()
        for p in self.path.iterdir():
            if p.name in ("key", "manifest.json", "state.db", "state.db-journal"):
                _private_file(p)
                continue
            if (
                len(p.name) != 26
                or not p.name.endswith(".jsonl")
                or not p.stem.isascii()
                or not p.stem.isdigit()
            ):
                raise QueueError("quarantined")
            n = int(p.stem)
            size = _private_file(p).st_size
            if not _permitted_size(j, bounds, n, size):
                raise QueueError("quarantined")
            seen.add(n)
        if any(low and n not in seen for n, (low, high) in bounds.items()):
            raise QueueError("quarantined")

    def _recover(self, j: dict) -> None:
        self._inventory(j)
        if j["contract"] != admission.CONTRACT:
            return
        if j.get("compact"):
            self._finish_compaction(j)
        if j["intent"] is not None:
            self._finish_record(j)
        if j["terminal"] is not None:
            self._move_cursor(j)
        if j["unlink"]:
            self._cleanup(j)

    def reconcile(self, owner: Owner) -> None:
        with self._operation(owner) as j:
            if j["contract"] == admission.CONTRACT:
                self._reclaim_due_prefix(j, max(int(time.time()), j["clock"]))
            self._blocked = False

    def checkpoint(self, owner: Owner, stream: UUID) -> int:
        with self._operation(owner, recover=False) as j:
            return j["streams"].get(str(stream), 0)

    def _seal(self, ordinal: int, ts: int, sha: str) -> str:
        return self._mac(b"row", canonical([str(self.generation), ordinal, ts, sha]))

    def admit_record(
        self,
        owner: Owner,
        stream: UUID,
        start: int,
        end: int,
        observations: list[dict],
        *,
        losses: tuple[str, ...] = (),
    ) -> Disposition:
        with self._operation(owner) as j:
            if j["contract"] != admission.CONTRACT:
                raise QueueError("contract_mismatch")
            if (
                not isinstance(stream, UUID)
                or not admission.integer(start, 0)
                or not admission.integer(end, start + 1)
            ):
                raise QueueError("invalid_position")
            current = j["streams"].get(str(stream), 0)
            if end <= current:
                return Disposition(current, 0, ())
            if start != current:
                raise QueueError("invalid_position")
            if any(code not in admission.LOSSES[:6] for code in losses):
                raise QueueError("invalid_shape")
            self._expire(j)
            counts = Counter(losses)
            rows = []
            used = sum(j["segments"].values())
            seg = j["last_segment"]
            offset = j["segments"].get(str(seg), 0)
            if not offset:
                seg += 1
            clock = max(j["clock"], int(time.time()))
            ordinal = j["next_ordinal"]
            remaining_intent = PAYLOAD_LIMIT - len(canonical(j)) - 1024
            for o in observations:
                try:
                    admission.validate_observation(o)
                except admission.Invalid:
                    counts["invalid_shape"] += 1
                    continue
                sha = digest(canonical(o))
                row = [ordinal, clock, sha, self._seal(ordinal, clock, sha), o]
                size = len(canonical(row)) + 1
                # Leave journal space for checkpoint, positions and loss evidence.
                if (
                    used + size > DATA_LIMIT
                    or size > SEGMENT_LIMIT
                    or size + 64 > remaining_intent
                ):
                    counts["capacity_rejected"] += 1
                    continue
                if ordinal > admission.MAX_INT:
                    raise QueueError("blocked_storage")
                if offset + size > SEGMENT_LIMIT:
                    seg, offset = seg + 1, 0
                rows.append([seg, offset, row])
                remaining_intent -= size + 64
                used += size
                ordinal += 1
                offset += size
            j["intent"] = {
                "stream": str(stream),
                "start": start,
                "end": end,
                "rows": rows,
                "loss": dict(counts),
                "clock": clock,
            }
            self._boundary("before_intent")
            self._save(j)
            self._boundary("after_intent")
            self._finish_record(j)
            self._blocked = False
            return Disposition(end, len(rows), tuple(sorted(counts.items())))

    def _finish_record(self, j: dict) -> None:
        intent = j["intent"]
        for i, (seg, start, row) in enumerate(intent["rows"]):
            line = canonical(row) + b"\n"
            try:
                self._spool.write_at(seg, start, line)
            except ValueError:
                raise QueueError("quarantined") from None
            if i == 0:
                self._boundary("after_first_row")
            j["segments"][str(seg)] = start + len(line)
            j["last_segment"] = seg
        n = len(intent["rows"])
        j["pending"] += n
        j["next_ordinal"] += n
        j["clock"] = intent["clock"]
        self._add_losses(j, intent["loss"])
        for code, count in intent["loss"].items():
            j["loss_evidence"][code] = [
                intent["stream"],
                intent["start"],
                intent["end"],
                count,
            ]
        j["streams"][intent["stream"]] = intent["end"]
        j["intent"] = None
        self._boundary("before_checkpoint")
        self._save(j)
        self._boundary("after_checkpoint")

    @staticmethod
    def _add_losses(j: dict, counts: dict) -> None:
        for k, n in counts.items():
            if j["totals"][k] + n > admission.MAX_INT:
                raise QueueError("blocked_storage")
            j["totals"][k] += n

    def _read_row(self, number: int, offset: int, base: int) -> PendingRow:
        try:
            data, end = self._spool.read_at(number, offset)
            ordinal, ts, sha, tag, o = json.loads(data)
            body = canonical(o)
            if digest(body) != sha or not hmac.compare_digest(
                self._seal(ordinal, ts, sha), tag
            ):
                raise ValueError
            return PendingRow(ordinal, body, sha, (number, base + end), ts)
        except (ValueError, TypeError, RecursionError):
            raise QueueError("quarantined") from None

    def _rows(self, j: dict) -> Iterator[PendingRow]:
        seg, pos = j["cursor"]
        previous = j["next_ordinal"] - j["pending"] - 1
        for number in sorted(map(int, j["segments"])):
            if number < seg:
                continue
            base = j.get("bases", {}).get(str(number), 0)
            offset = pos - base if number == seg else 0
            while offset < j["segments"][str(number)]:
                row = self._read_row(number, offset, base)
                if row.ordinal != previous + 1:
                    raise QueueError("quarantined")
                previous = row.ordinal
                offset = row.end[1] - base
                yield row
        if previous != j["next_ordinal"] - 1:
            raise QueueError("quarantined")

    def _terminal(
        self,
        j: dict,
        rows: list[PendingRow],
        outcomes: list[str],
        receipt_key: list | None = None,
    ) -> None:
        self._add_losses(j, dict(Counter(o for o in outcomes if o in admission.LOSSES)))
        for row, outcome in zip(rows, outcomes):
            if outcome in admission.LOSSES:
                j["loss_evidence"][outcome] = [row.ordinal, row.digest]
        # FIFO plus durable cursor makes positions unique. Keep the terminal
        # record until the move commits, then retain only aggregates and high-water.
        j["terminal"] = {
            "end": rows[-1].end,
            "count": len(rows),
            "evidence": [[r.ordinal, r.digest, o] for r, o in zip(rows, outcomes)],
        }
        j["flight"] = None
        j["last_receipt"] = receipt_key
        self._boundary("before_terminal")
        self._save(j)
        self._boundary("after_terminal")
        self._move_cursor(j)
        self._cleanup(j)

    def _move_cursor(self, j: dict) -> None:
        terminal = j["terminal"]
        seg, pos = terminal["end"]
        j["cursor"] = [seg, pos]
        j["pending"] -= terminal["count"]
        j["unlink"] = [
            int(n)
            for n, size in j["segments"].items()
            if int(n) < seg
            or (int(n) == seg and pos == size + j.get("bases", {}).get(n, 0))
        ]
        j["unlink_sizes"] = {str(n): j["segments"][str(n)] for n in j["unlink"]}
        for n in j["unlink"]:
            del j["segments"][str(n)]
            j.get("bases", {}).pop(str(n), None)
        j["terminal"] = None
        self._boundary("before_cursor")
        self._save(j)
        self._boundary("after_cursor")

    def _cleanup(self, j: dict) -> None:
        if not j["unlink"]:
            return
        self._boundary("before_unlink")
        self._inventory(j)
        for n in j["unlink"]:
            path = self.path / f"{n:020d}.jsonl"
            if path.exists():
                self._verify_segment(
                    n,
                    _private_file(path).st_size,
                    0,
                    ceiling=j["next_ordinal"] - j["pending"] - 1,
                )
        for n in j["unlink"]:
            (self.path / f"{n:020d}.jsonl").unlink(missing_ok=True)
        sync_directory(self.path)
        self._boundary("after_unlink")
        j["unlink"] = []
        j.pop("unlink_sizes", None)
        self._save(j)

    def _verify_segment(
        self,
        segment: int,
        size: int,
        base: int,
        *,
        cursor: tuple[int, int] | None = None,
        ceiling: int | None = None,
    ) -> None:
        offset = 0
        previous = None
        matched = cursor is None
        while offset < size:
            row = self._read_row(segment, offset, base)
            if previous is not None and row.ordinal != previous + 1:
                raise QueueError("quarantined")
            if ceiling is not None and row.ordinal > ceiling:
                raise QueueError("quarantined")
            if cursor == (row.end[1], row.ordinal):
                matched = True
            previous = row.ordinal
            offset = row.end[1] - base
        if not matched or offset != size:
            raise QueueError("quarantined")

    def _reclaim_due_prefix(self, j: dict, now: int) -> None:
        segment, logical = j["cursor"]
        n = str(segment)
        size = j["segments"].get(n, 0)
        base = j.get("bases", {}).get(n, 0)
        cut = logical - base
        if not 0 < cut < size:
            return
        first = self._read_row(segment, 0, base)
        if first.enqueued_at + TTL > now:
            return
        self._verify_segment(
            segment, size, base, cursor=(logical, j["next_ordinal"] - j["pending"] - 1)
        )
        try:
            suffix_digest = self._spool.suffix_digest(segment, cut, size)
        except ValueError:
            raise QueueError("quarantined") from None
        j["compact"] = {
            "segment": segment,
            "original": size,
            "cut": cut,
            "moved": 0,
            "digest": suffix_digest,
        }
        self._save(j)
        self._boundary("compact_intent")
        self._finish_compaction(j)

    def _finish_compaction(self, j: dict) -> None:
        plan = j["compact"]

        def save_progress(moved: int) -> None:
            plan["moved"] = moved
            self._save(j)

        try:
            self._spool.compact_prefix(plan, save_progress, self._boundary)
        except ValueError:
            raise QueueError("quarantined") from None
        n = str(plan["segment"])
        bases = j.setdefault("bases", {})
        bases[n] = bases.get(n, 0) + plan["cut"]
        j["segments"][n] = plan["original"] - plan["cut"]
        j["compact"] = None
        self._save(j)
        self._boundary("compact_commit")

    def _expire(self, j: dict) -> None:
        now = max(int(time.time()), j["clock"])
        if now > j["clock"]:
            j["clock"] = now
            self._save(j)
        verified: set[int] = set()
        while j["pending"]:
            expired = []
            for r in self._rows(j):
                if r.enqueued_at + TTL > now:
                    break
                expired.append(r)
                if len(expired) == 32:
                    break
            if not expired:
                break
            for n in {r.end[0] for r in expired} - verified:
                self._verify_segment(
                    n, j["segments"][str(n)], j.get("bases", {}).get(str(n), 0)
                )
                verified.add(n)
            self._terminal(j, expired, ["expired"] * len(expired))
        self._reclaim_due_prefix(j, now)

    def _batch(self, j: dict, batch_id: UUID, limit: int) -> PendingBatch | None:
        rows: list[PendingRow] = []
        sources = set()
        for r in self._rows(j):
            o = json.loads(r.data)
            try:
                admission.validate_observation(o)
            except admission.Invalid:
                if not rows:
                    raise InvalidHead(r.ordinal, r.digest) from None
                break
            source = o["source"]
            key = (
                source["channel"],
                source.get("collector_observation_id")
                or source.get("parser_observation_token"),
            )
            if key in sources:
                break
            sources.add(key)
            rows.append(r)
            # At most 32 rows and a bounded envelope, measured as actual wire bytes.
            p = PendingBatch(
                self.owner, self.generation, batch_id, tuple(j["cursor"]), tuple(rows)
            )
            if len(p.body) > admission.MAX_BATCH:
                rows.pop()
                break
            if len(rows) == limit:
                break
        if not rows:
            return None
        return PendingBatch(
            self.owner, self.generation, batch_id, tuple(j["cursor"]), tuple(rows)
        )

    def next_batch(self, owner: Owner, limit: int = 32) -> PendingBatch | None:
        with self._operation(owner) as j:
            if not admission.integer(limit, 1, 32):
                raise QueueError("invalid_limit")
            if (
                j["contract"] != admission.CONTRACT
                or j["status"] == "contract_mismatch"
            ):
                raise QueueError("contract_mismatch")
            self._expire(j)
            batch = self._batch(j, uuid4(), limit)
            j["flight"] = (
                [str(batch.batch_id), list(batch.expected_cursor), len(batch.rows)]
                if batch
                else None
            )
            self._save(j)
            self._blocked = False
            return batch

    def apply_receipt(
        self, owner: Owner, pending: PendingBatch, response: bytes
    ) -> int:
        with self._operation(owner) as j:
            if (
                owner != pending.owner
                or self.generation != pending.generation
                or type(response) is not bytes
                or len(response) > admission.MAX_BATCH
            ):
                raise QueueError("invalid_receipt")
            key = [str(pending.batch_id), digest(response)]
            if j["last_receipt"] == key:
                return 0
            if self._invalid_flight(j, pending):
                raise QueueError("contract_mismatch")
            try:
                outcomes = admission.receipt(
                    response,
                    str(owner.device_id),
                    str(pending.batch_id),
                    tuple((r.ordinal, r.digest) for r in pending.rows),
                )
            except admission.Invalid:
                raise QueueError("invalid_receipt") from None
            self._terminal(j, list(pending.rows[: len(outcomes)]), outcomes, key)
            self._blocked = False
            return len(outcomes)

    def _invalid_flight(
        self, j: dict, pending: PendingBatch
    ) -> tuple[tuple[int, str], ...]:
        if j["contract"] != admission.CONTRACT or j["status"] == "contract_mismatch":
            raise QueueError("contract_mismatch")
        flight = j["flight"]
        if (
            pending.owner != self.owner
            or pending.generation != self.generation
            or list(pending.expected_cursor) != j["cursor"]
            or flight != [str(pending.batch_id), j["cursor"], len(pending.rows)]
            or tuple(islice(self._rows(j), len(pending.rows))) != pending.rows
        ):
            raise QueueError("stale_receipt")
        invalid = []
        for row in pending.rows:
            try:
                admission.validate_observation(json.loads(row.data))
            except admission.Invalid:
                invalid.append((row.ordinal, row.digest))
        return tuple(invalid)

    def invalid_rows(
        self, owner: Owner, pending: PendingBatch
    ) -> tuple[tuple[int, str], ...]:
        """Revalidate a bound in-flight batch after a structural refusal, without advancing."""
        with self._operation(owner) as j:
            return self._invalid_flight(j, pending)

    def cancel_flight(self, owner: Owner) -> None:
        """Fence outstanding replies after a credential or authorization change."""
        with self._operation(owner) as j:
            j["flight"] = None
            self._save(j)

    def finalize_invalid_head(
        self, owner: Owner, ordinal: int, admission_digest: str
    ) -> None:
        with self._operation(owner) as j:
            if (
                j["contract"] != admission.CONTRACT
                or j["status"] == "contract_mismatch"
            ):
                raise QueueError("contract_mismatch")
            row = next(self._rows(j), None)
            if not row or row.ordinal != ordinal:
                raise QueueError("stale_head")
            if row.digest != admission_digest:
                raise QueueError("quarantined")
            try:
                admission.validate_observation(json.loads(row.data))
            except admission.Invalid:
                self._terminal(j, [row], ["row_schema_invalid"])
            else:
                raise QueueError("valid_head")

    def set_contract_mismatch(self, owner: Owner, held: bool = True) -> None:
        with self._operation(owner) as j:
            j["status"] = "contract_mismatch" if held else "ready"
            j["flight"] = None
            self._save(j)

    def heartbeat(self, owner: Owner) -> dict:
        with self._operation(owner, recover=False) as j:
            self._inventory(j)
            if (
                not self._blocked
                and j["contract"] == admission.CONTRACT
                and j["intent"] is None
                and j["terminal"] is None
            ):
                self._recover(j)
                self._expire(j)
            status = j["status"]
            if status == "ready" and any(
                s["tail"] or s["sealed"] for s in j["sources"].values()
            ):
                status = "source_incomplete"
            if j["contract"] != admission.CONTRACT:
                status = "contract_mismatch"
            if self._blocked:
                status = "blocked_storage"
            snapshot = {
                "version": 1,
                "enrollment_id": str(owner.device_id),
                "upstream_sha": UPSTREAM_SHA,
                "adapter_version": __version__,
                "pending": j["pending"],
                "queue_bytes": sum(j["segments"].values()),
                "totals": j["totals"].copy(),
                "state": status,
            }
            sha = digest(canonical(snapshot))
            if sha != j["snapshot"]:
                j["revision"] += 1
                if j["revision"] > admission.MAX_INT:
                    raise QueueError("blocked_storage")
                j["snapshot"] = sha
                self._save(j)
            return dict(snapshot, revision=j["revision"])

    def offboard(self, owner: Owner) -> None:
        from . import erasure

        with self._operation(owner, recover=False) as j:
            self._inventory(j)
            erasure.prepare(self.path, self._db, self.generation, self._key)
            self._boundary("erase_prepared")
            self._db.close()
            try:
                erasure.begin(
                    self.path,
                    self._dir,
                    owner,
                    self.generation,
                    self._key,
                    self._boundary,
                )
            finally:
                self.close()

    @classmethod
    def resume_offboard(cls, path: Path, owner: Owner) -> bool:
        """Finish a durable, owner-verified erasure after interruption."""
        from . import erasure

        return erasure.resume(Path(path).absolute(), owner)

    def fixture_stream(
        self,
        owner: Owner,
        channel: str,
        identity: str,
        size: int,
        modification: int,
        *,
        independent: bool = False,
    ) -> UUID:
        """Seal a changed input. Only an explicitly independent fixture gets new IDs."""
        if channel not in ("transcript", "hook"):
            raise QueueError("invalid_shape")
        with self._operation(owner) as j:
            tag = self._mac(b"fixture", identity.encode())
            s = j["sources"].get(channel)
            retired = s["retired"] if s else []
            fingerprints = s.get("retired_fingerprints", []) if s else []
            fingerprint = self._mac(
                b"sealed-fixture", canonical([tag, size, modification])
            )
            if fingerprint in fingerprints or tag in retired:
                raise QueueError("stale_fixture")
            if s:
                unchanged = s["size"] == size and s["mtime"] == modification
                if (
                    not s["sealed"]
                    and s["tag"] == tag
                    and (unchanged or size > s["size"])
                ):
                    if not unchanged:
                        s.update(size=size, mtime=modification)
                        self._save(j)
                    return UUID(s["stream"])
                if s["sealed"] and s["tag"] == tag and unchanged:
                    raise QueueError("stale_fixture")
                if not s["sealed"]:
                    position = j["streams"].get(s["stream"], 0)
                    if channel == "transcript" and position < s["size"]:
                        self._add_losses(j, {"incomplete_tail": 1})
                        j["loss_evidence"]["incomplete_tail"] = [
                            s["stream"],
                            position,
                            s["size"],
                            1,
                        ]
                    s["sealed"] = True
                    s["tail"] = False
                    self._save(j)
                if not independent:
                    raise QueueError("source_changed")
                if tag != s["tag"]:
                    retired.append(s["tag"])
                else:
                    fingerprints.append(
                        self._mac(
                            b"sealed-fixture", canonical([tag, s["size"], s["mtime"]])
                        )
                    )
            stream = uuid4()
            j["sources"][channel] = {
                "tag": tag,
                "size": size,
                "mtime": modification,
                "sealed": False,
                "tail": False,
                "stream": str(stream),
                "retired": retired,
                "retired_fingerprints": fingerprints,
            }
            self._save(j)
            return stream

    def fixture_tail(self, owner: Owner, stream: UUID, pending: bool) -> None:
        with self._operation(owner) as j:
            s = j["sources"].get("transcript")
            if not s or s["stream"] != str(stream):
                raise QueueError("stale_fixture")
            if s["tail"] != pending:
                s["tail"] = pending
                self._save(j)

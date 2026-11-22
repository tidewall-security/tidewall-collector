"""Segmented JSONL disk queue. Tidewall adds bounded, replayable positioned writes."""

import json
import os
import re
import stat
import threading
from pathlib import Path

from openaidr.core.files import atomic_write, sync_directory

MAX_LINE = 4608


def _boundary(name):
    pass


class Spool:
    """The enrollment journal owns segment allocation, capacity and cursor intent."""

    def __init__(self, directory, max_segment_bytes=256 << 10, max_total_bytes=8 << 20):
        self.path = Path(directory)
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_segment, self.max_total = max_segment_bytes, max_total_bytes
        self.lock = threading.RLock()
        self.closed = False
        self._boundary = _boundary
        # Standalone upstream append/read compatibility. Enrollment cursors live in SQLite.
        self.cursor = {}
        cursor = self.path / "cursor.json"
        if cursor.exists():
            with cursor.open("rb") as f:
                self.cursor = json.loads(f.read(257))
            if not isinstance(self.cursor, dict) or not re.fullmatch(
                r"[0-9]{20}\.jsonl", self.cursor.get("segment", "")
            ):
                raise ValueError("invalid cursor")

    def segments(self):
        return sorted(self.path.glob("*.jsonl"))

    def _path(self, number):
        if type(number) is not int or not 1 <= number < 10**20:
            raise ValueError("invalid segment")
        return self.path / f"{number:020d}.jsonl"

    def write_at(self, number, offset, line):
        """Finish only the prefix previously authorized at this exact position."""
        if (
            self.closed
            or not 0 < len(line) <= MAX_LINE
            or not line.endswith(b"\n")
            or b"\n" in line[:-1]
            or not 0 <= offset <= self.max_segment - len(line)
        ):
            raise ValueError("invalid append")
        path = self._path(number)
        flags = os.O_RDWR | os.O_NOFOLLOW
        if offset == 0:
            flags |= os.O_CREAT
        with self.lock, os.fdopen(os.open(path, flags, 0o600), "r+b") as f:
            info = os.fstat(f.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size < offset
            ):
                raise ValueError("invalid segment")
            f.seek(offset)
            prefix = f.read(len(line))
            if not line.startswith(prefix):
                raise ValueError("invalid segment")
            self._boundary("before_append")
            if len(prefix) < len(line):
                f.write(line[len(prefix) :])
            f.flush()
            self._boundary("after_append")
            self._boundary("before_fsync")
            os.fsync(f.fileno())
            sync_directory(self.path)
            self._boundary("after_fsync")
            f.seek(offset)
            if f.read(len(line)) != line:
                raise ValueError("invalid append")

    def read_at(self, number, offset):
        with os.fdopen(
            os.open(self._path(number), os.O_RDONLY | os.O_NOFOLLOW), "rb"
        ) as f:
            f.seek(offset)
            line = f.readline(MAX_LINE + 1)
            if not 0 < len(line) <= MAX_LINE or not line.endswith(b"\n"):
                raise ValueError("invalid segment")
            return line, f.tell()

    def append(self, event):
        line = (json.dumps(event, separators=(",", ":")) + "\n").encode()
        with self.lock:
            paths = self.segments()
            if sum(p.stat().st_size for p in paths) + len(line) > self.max_total:
                raise BufferError("capacity")
            number = int(paths[-1].stem) if paths else 1
            offset = paths[-1].stat().st_size if paths else 0
            if offset + len(line) > self.max_segment:
                number += 1
                offset = 0
            self.write_at(number, offset, line)

    def read(self, limit=100):
        with self.lock:
            events, cursor = [], None
            for p in self.segments():
                if p.name < self.cursor.get("segment", ""):
                    continue
                offset = (
                    self.cursor["offset"] if p.name == self.cursor.get("segment") else 0
                )
                while offset < p.stat().st_size and len(events) < limit:
                    line, offset = self.read_at(int(p.stem), offset)
                    events.append(json.loads(line))
                    cursor = {"segment": p.name, "offset": offset}
                if len(events) >= limit:
                    break
            return {"events": events, "cursor": cursor} if cursor else None

    def ack(self, batch):
        with self.lock:
            cursor = batch["cursor"]
            if not cursor:
                return
            name = cursor["segment"]
            if not re.fullmatch(r"[0-9]{20}\.jsonl", name):
                raise ValueError("invalid cursor")
            if (name, cursor["offset"]) <= (
                self.cursor.get("segment", ""),
                self.cursor.get("offset", 0),
            ):
                return
            if not 0 < cursor["offset"] <= (self.path / name).stat().st_size:
                raise ValueError("invalid cursor")
            atomic_write(self.path / "cursor.json", json.dumps(cursor))
            self.cursor = cursor
            for p in self.segments():
                if p.name < name:
                    p.unlink()
            sync_directory(self.path)

    @property
    def depth(self):
        with self.lock:
            count = 0
            for path in self.segments():
                if path.name < self.cursor.get("segment", ""):
                    continue
                offset = (
                    self.cursor["offset"]
                    if path.name == self.cursor.get("segment")
                    else 0
                )
                while offset < path.stat().st_size:
                    _, offset = self.read_at(int(path.stem), offset)
                    count += 1
            return count

    def close(self):
        self.closed = True

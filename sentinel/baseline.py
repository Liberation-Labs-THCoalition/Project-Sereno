"""File Integrity Baseline — know your machine so you know when it changes.

AIDE-inspired but pure Python. No compiled deps.

Takes a snapshot of critical files (hashes, permissions, sizes, mtimes).
On subsequent runs, compares against the baseline and reports changes.
Changes aren't inherently bad — but unexpected changes are how you catch
someone who's been in your house.

Usage:
    baseline = FileBaseline()
    baseline.create("/etc", "~/.ssh", "~/.claude")
    baseline.save("~/.sentinel/baseline.json")

    # Later:
    baseline = FileBaseline.load("~/.sentinel/baseline.json")
    changes = baseline.check()
    for change in changes:
        print(change)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .paths import sentinel_home

logger = logging.getLogger(__name__)

DEFAULT_WATCH_PATHS = [
    "~/.ssh",
    "~/.claude",
    "~/.vscode",
    "~/.npmrc",
    "~/.gitconfig",
    "~/.bashrc",
    "~/.zshrc",
    "~/.profile",
    "~/.config/systemd/user",
]

MACOS_WATCH_PATHS = [
    "~/Library/LaunchAgents",
]

LINUX_WATCH_PATHS = [
    "/etc/crontab",
    "/etc/hosts",
    "/etc/passwd",
    "/etc/sudoers",
]

SKIP_PATTERNS = [
    "__pycache__", ".pyc", "node_modules", ".git/objects",
    ".cache", ".npm/_cacache", "Cache", "CacheStorage",
]


@dataclass
class FileRecord:
    """Snapshot of a single file's state."""
    path: str
    sha256: str
    size: int
    mtime: float
    permissions: str
    uid: int = 0
    gid: int = 0


@dataclass
class FileChange:
    """A detected change between baseline and current state."""
    path: str
    change_type: str  # added, removed, modified, permissions_changed
    old_hash: str = ""
    new_hash: str = ""
    old_permissions: str = ""
    new_permissions: str = ""
    old_size: int = 0
    new_size: int = 0

    def human_readable(self) -> str:
        if self.change_type == "added":
            return f"  NEW: {self.path} (wasn't here before)"
        elif self.change_type == "removed":
            return f"  GONE: {self.path} (was here, now missing)"
        elif self.change_type == "modified":
            return f"  CHANGED: {self.path} (content differs, {self.old_size}→{self.new_size} bytes)"
        elif self.change_type == "permissions_changed":
            return f"  PERMS: {self.path} ({self.old_permissions}→{self.new_permissions})"
        return f"  ???: {self.path} ({self.change_type})"


def _hash_file(path: Path) -> str:
    """SHA-256 hash of file contents."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def _should_skip(path: Path) -> bool:
    """Check if path matches any skip patterns."""
    path_str = str(path)
    return any(skip in path_str for skip in SKIP_PATTERNS)


def _file_permissions(path: Path) -> str:
    """Get file permissions as octal string."""
    try:
        return oct(path.stat().st_mode)[-3:]
    except OSError:
        return "???"


def _scan_path(root: Path, max_depth: int = 5) -> list[FileRecord]:
    """Scan a directory tree and record file states."""
    records = []
    root = root.expanduser().resolve()

    if not root.exists():
        return records

    if root.is_file():
        if not _should_skip(root):
            try:
                st = root.stat()
                records.append(FileRecord(
                    path=str(root),
                    sha256=_hash_file(root),
                    size=st.st_size,
                    mtime=st.st_mtime,
                    permissions=_file_permissions(root),
                    uid=st.st_uid,
                    gid=st.st_gid,
                ))
            except OSError:
                pass
        return records

    for dirpath, dirnames, filenames in os.walk(root):
        depth = str(dirpath).count(os.sep) - str(root).count(os.sep)
        if depth >= max_depth:
            dirnames.clear()
            continue

        dirnames[:] = [d for d in dirnames if not _should_skip(Path(dirpath) / d)]

        for fname in filenames:
            fpath = Path(dirpath) / fname
            if _should_skip(fpath):
                continue
            try:
                st = fpath.stat()
                if st.st_size > 10 * 1024 * 1024:
                    continue
                records.append(FileRecord(
                    path=str(fpath),
                    sha256=_hash_file(fpath),
                    size=st.st_size,
                    mtime=st.st_mtime,
                    permissions=_file_permissions(fpath),
                    uid=st.st_uid,
                    gid=st.st_gid,
                ))
            except (OSError, PermissionError):
                continue

    return records


class FileBaseline:
    """Manages file integrity baselines."""

    def __init__(self) -> None:
        self._records: dict[str, FileRecord] = {}
        self._created: str = ""
        self._watch_paths: list[str] = []

    def create(self, *paths: str) -> int:
        """Create a baseline from the given paths."""
        import platform

        all_paths = list(paths) if paths else list(DEFAULT_WATCH_PATHS)
        if platform.system() == "Darwin":
            all_paths.extend(MACOS_WATCH_PATHS)
        elif platform.system() == "Linux":
            all_paths.extend(LINUX_WATCH_PATHS)

        self._watch_paths = all_paths
        self._records.clear()
        self._created = datetime.now(timezone.utc).isoformat()

        for path_str in all_paths:
            path = Path(path_str).expanduser()
            for record in _scan_path(path):
                self._records[record.path] = record

        logger.info("Baseline created: %d files from %d paths", len(self._records), len(all_paths))
        return len(self._records)

    def check(self) -> list[FileChange]:
        """Compare current state against baseline."""
        changes = []
        current_paths: set[str] = set()

        for path_str in self._watch_paths:
            path = Path(path_str).expanduser()
            for record in _scan_path(path):
                current_paths.add(record.path)
                baseline = self._records.get(record.path)

                if baseline is None:
                    changes.append(FileChange(
                        path=record.path,
                        change_type="added",
                        new_hash=record.sha256,
                        new_size=record.size,
                    ))
                elif record.sha256 != baseline.sha256:
                    changes.append(FileChange(
                        path=record.path,
                        change_type="modified",
                        old_hash=baseline.sha256,
                        new_hash=record.sha256,
                        old_size=baseline.size,
                        new_size=record.size,
                    ))
                elif record.permissions != baseline.permissions:
                    changes.append(FileChange(
                        path=record.path,
                        change_type="permissions_changed",
                        old_permissions=baseline.permissions,
                        new_permissions=record.permissions,
                    ))

        for path_str, record in self._records.items():
            if path_str not in current_paths:
                changes.append(FileChange(
                    path=path_str,
                    change_type="removed",
                    old_hash=record.sha256,
                    old_size=record.size,
                ))

        return changes

    def update(self, changes: list[FileChange] | None = None) -> int:
        """Accept current state as the new baseline."""
        count = self.create(*self._watch_paths)
        return count

    def save(self, path: str = "") -> None:
        """Save baseline to disk."""
        save_path = Path(path) if path else sentinel_home() / "baseline.json"
        save_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "created": self._created,
            "watch_paths": self._watch_paths,
            "file_count": len(self._records),
            "records": {k: asdict(v) for k, v in self._records.items()},
        }
        tmp = save_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(str(tmp), str(save_path))

    @classmethod
    def load(cls, path: str = "") -> FileBaseline:
        """Load baseline from disk."""
        load_path = Path(path) if path else sentinel_home() / "baseline.json"
        baseline = cls()
        if not load_path.exists():
            return baseline
        try:
            data = json.loads(load_path.read_text())
            baseline._created = data.get("created", "")
            baseline._watch_paths = data.get("watch_paths", [])
            for path_str, rec_data in data.get("records", {}).items():
                baseline._records[path_str] = FileRecord(**rec_data)
        except (json.JSONDecodeError, TypeError, OSError) as e:
            logger.warning("Failed to load baseline: %s", e)
        return baseline

    @property
    def file_count(self) -> int:
        return len(self._records)

    @property
    def created(self) -> str:
        return self._created

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

from .paths import sentinel_home, skip_list, walk

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

# Inside ~/.claude, only what can change Claude Code's behaviour is watched: its settings, hooks, commands, agents,
# skills, instructions, and the lists of installed plugins. The rest (session transcripts, todos, shell snapshots,
# plugin caches) changes every few minutes, and watching it raised a high alert on every guardian run for every Claude
# Code user (found 2026-10-23: 80 changes in 8 hours on one machine). The rule applies at scan time, so a baseline
# saved with "~/.claude" in its watch list gets it too.
CLAUDE_KEEP_TOP = {"settings.json", "settings.local.json", "CLAUDE.md", "hooks", "commands", "agents", "skills",
                   "keybindings.json"}
CLAUDE_KEEP_FILES = {"plugins/installed_plugins.json", "plugins/known_marketplaces.json"}

# setuid and setgid: a file gaining one can run with its owner's or group's rights
ESCALATING_BITS = 0o6000


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
    owner_known: bool = True  # False for a record loaded from a baseline saved without uid/gid


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
    old_owner: str = ""
    new_owner: str = ""

    def human_readable(self) -> str:
        if self.change_type == "added":
            return f"  NEW: {self.path} (wasn't here before)"
        elif self.change_type == "removed":
            return f"  GONE: {self.path} (was here, now missing)"
        elif self.change_type == "modified":
            return f"  CHANGED: {self.path} (content differs, {self.old_size}→{self.new_size} bytes)"
        elif self.change_type == "permissions_changed":
            return f"  PERMS: {self.path} ({self.old_permissions}→{self.new_permissions})"
        elif self.change_type == "owner_changed":
            return f"  OWNER: {self.path} (uid:gid {self.old_owner}→{self.new_owner})"
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


def _claude_churn(path: Path) -> bool:
    """A path under ~/.claude that isn't one of the watched parts (CLAUDE_KEEP_TOP, CLAUDE_KEEP_FILES)."""
    claude = (Path.home() / ".claude").resolve()
    try:
        rel = Path(path).resolve().relative_to(claude)
    except (ValueError, OSError):
        return False
    if not rel.parts:
        return False
    if rel.parts[0] in CLAUDE_KEEP_TOP:
        return False
    rel_s = rel.as_posix()
    if rel_s in CLAUDE_KEEP_FILES or any(k.startswith(rel_s + "/") for k in CLAUDE_KEEP_FILES):
        return False  # a kept file, or a folder on the way to one
    return True


def _should_skip(path: Path) -> bool:
    """Check if path matches any skip patterns."""
    path_str = str(path)
    return any(skip in path_str for skip in SKIP_PATTERNS) or _claude_churn(path)


def escalates(change) -> bool:
    """A change that gives something more power: a new owner, or a setuid/setgid bit that wasn't there."""
    if change.change_type == "owner_changed":
        return True
    if change.change_type != "permissions_changed":
        return False
    try:
        old, new = int(change.old_permissions, 8), int(change.new_permissions, 8)
    except (TypeError, ValueError):
        return False
    return bool(new & ESCALATING_BITS & ~old)


def _file_permissions(path: Path) -> str:
    """Permissions as an octal string, setuid, setgid and sticky bits included ("755", "4755"). Before 2026-10-23
    only the last three digits were kept, so a setuid bit added to a file went unseen."""
    try:
        return "%o" % (path.stat().st_mode & 0o7777)
    except OSError:
        return "???"


def _scan_path(root: Path, max_depth: int = 5, skip=None) -> list[FileRecord]:
    """Scan a directory tree and record file states. Nothing on the skip list is entered or read (sentinel/paths.py)."""
    records = []
    skip = skip_list(skip)
    root = root.expanduser()
    # Checked as given, before resolving it looks anything up: a watched path can be a link into a skipped folder, or
    # sit in one and link out of it (2026-10-29)
    if skip.covers(root):
        return records
    root = root.resolve()

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

    for dirpath, dirnames, filenames in walk(root, skip):
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
        self.last_skip = None   # the skip list the last create() or check() used, for its notes (sentinel/paths.py)

    def create(self, *paths: str, skip=None) -> int:
        """Create a baseline from the given paths. skip: the folders not to enter (None: the user's skip list)."""
        import platform

        all_paths = list(paths) if paths else list(DEFAULT_WATCH_PATHS)
        if platform.system() == "Darwin":
            all_paths.extend(MACOS_WATCH_PATHS)
        elif platform.system() == "Linux":
            all_paths.extend(LINUX_WATCH_PATHS)

        self._watch_paths = all_paths
        self._records.clear()
        self._created = datetime.now(timezone.utc).isoformat()
        skip = self.last_skip = skip_list(skip)

        for path_str in all_paths:
            path = Path(path_str).expanduser()
            for record in _scan_path(path, skip=skip):
                self._records[record.path] = record

        logger.info("Baseline created: %d files from %d paths", len(self._records), len(all_paths))
        return len(self._records)

    def check(self, skip=None) -> list[FileChange]:
        """Compare current state against baseline. skip: the folders not to enter (None: the user's skip list); a file
        in one wasn't looked at, so it's never reported as removed."""
        changes = []
        current_paths: set[str] = set()
        skip = self.last_skip = skip_list(skip)

        for path_str in self._watch_paths:
            path = Path(path_str).expanduser()
            for record in _scan_path(path, skip=skip):
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
                elif baseline.owner_known and (record.uid, record.gid) != (baseline.uid, baseline.gid):
                    changes.append(FileChange(
                        path=record.path,
                        change_type="owner_changed",
                        old_owner=f"{baseline.uid}:{baseline.gid}",
                        new_owner=f"{record.uid}:{record.gid}",
                    ))

        for path_str, record in self._records.items():
            # A record the skip rules now exclude (a Claude Code transcript in an older baseline) isn't "gone"
            # and one in a folder on the skip list wasn't looked at
            if (path_str not in current_paths and not skip.covers(path_str, record=False)
                    and not _should_skip(Path(path_str))):
                changes.append(FileChange(
                    path=path_str,
                    change_type="removed",
                    old_hash=record.sha256,
                    old_size=record.size,
                ))

        return changes

    def update(self, changes: list[FileChange] | None = None, skip=None) -> int:
        """Accept current state as the new baseline."""
        count = self.create(*self._watch_paths, skip=skip)
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
                rec_data = dict(rec_data)
                rec_data.setdefault("owner_known", "uid" in rec_data and "gid" in rec_data)
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

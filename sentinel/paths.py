"""Where Sereno keeps its state, and the folders under home it must not enter.

State: $SENTINEL_HOME, else ~/.sentinel. Read at call time, never at import, and every scan says which one it used
(2026-10-28: Ember's manual scans read ~/.sentinel for days because SENTINEL_HOME was set only on the cron line).

The skip list (2026-10-28, from Ember's install on a shared home): on a machine where several AI agents keep their
folders under one account's home (~/agents/<name>/), Sereno's searches walked into the other agents' folders. Findings
never carry values, but paths and variable names from someone else's folder in a log the user reads still cross a
line. Every search under home goes through walk() below, which prunes the folders on the skip list before it would
enter them. The list comes from <state>/skip.json and from --skip on the command line; it's empty unless you make one.
A scan that skipped anything says so in one note, so a skip is never silent.
"""
import glob
import json
import os
from pathlib import Path

SKIP_FILE = "skip.json"


def state_folder():
    """(the state folder, True when it's the default because SENTINEL_HOME is unset or empty)."""
    env = os.environ.get("SENTINEL_HOME")
    if env:
        return Path(env), False
    return Path.home() / ".sentinel", True


def sentinel_home() -> Path:
    return state_folder()[0]


def state_folder_note() -> str:
    """The state folder in words, saying where it came from: what every scan's header shows."""
    path, default = state_folder()
    if default:
        return "%s (the default: SENTINEL_HOME isn't set)" % path
    return "%s (from SENTINEL_HOME)" % path


# ── The skip list ──

def _under(real: str, root: str) -> bool:
    return real == root or real.startswith(root if root.endswith(os.sep) else root + os.sep)


class SkipList:
    """The folders (or files) a scan must not enter, matched by resolved path, and what the scan skipped.

    entries are paths as the user wrote them: '~' is expanded, a relative path is taken from home, a * or ? matches
    names (glob's rules: not names starting with a dot), and an entry starting with ! takes a path back off the list
    (["~/agents/*", "!~/agents/mine"] skips every agent folder but your own). problem, when set, is (the skip file, why
    it couldn't be used): the list is then closed, skipping everything a walk would enter, because a skip list that
    can't be read can't promise to keep Sereno out of anyone's folder.

    One SkipList serves one scan: walk() records each folder it prunes, and notes() reports them once."""

    def __init__(self, entries=(), source=None, problem=None, cli=False):
        self.source = source   # the skip file the entries came from, or None
        self.cli = cli         # whether some came from --skip
        self.problem = problem
        self.closed = problem is not None
        self.missing = []      # entries that matched nothing, as written
        self._shown = {}       # resolved root -> the path it was listed as (expanded, not resolved)
        self._roots = set()
        self._dirs = {}        # resolved folder pruned -> the root it fell under
        self._files = {}       # resolved file left unread (a link into a skipped folder, or a listed file) -> its root
        if self.closed:
            return
        home = os.path.expanduser("~")
        keep, drop = {}, []
        for entry in (e.strip() for e in entries):
            negate = entry.startswith("!")
            raw = os.path.expanduser(entry[1:] if negate else entry)
            if not os.path.isabs(raw):
                raw = os.path.join(home, raw)
            found = sorted(glob.glob(raw)) if glob.has_magic(raw) else ([raw] if os.path.lexists(raw) else [])
            if negate:
                drop.append((entry, [os.path.realpath(p) for p in found] or [os.path.realpath(raw)]))
            elif not found:
                self.missing.append(entry)
            for p in found if not negate else ():
                keep.setdefault(os.path.realpath(p), os.path.normpath(p))
        for entry, reals in drop:
            if not any(keep.pop(r, None) is not None for r in reals):
                self.missing.append(entry)   # an exception that took nothing off the list
        self._shown = keep
        self._roots = set(keep)

    def __bool__(self):
        return self.closed or bool(self._shown)

    def _match(self, real: str, full: bool):
        """The root real falls under, or None. full=False is the walk's shortcut for a child that isn't a link: its
        parent wasn't under any root (or it would have been pruned), so it's under one only if it is one."""
        if self.closed:
            return ""
        if real in self._roots:
            return real
        if full:
            for root in self._roots:
                if _under(real, root):
                    return root
        return None

    def prune(self, real: str, link: bool = True, is_dir: bool = True) -> bool:
        """Whether the walk must not enter (or, for a file, read) this resolved path; a pruned one is recorded."""
        root = self._match(real, link)
        if root is None:
            return False
        if not self.closed:
            (self._dirs if is_dir else self._files)[real] = root
        return True

    def skipped(self) -> bool:
        """Whether this list kept a walk out of anything (or, closed, out of everything) so far."""
        return self.closed or bool(self._dirs or self._files)

    def covers(self, path, record: bool = True) -> bool:
        """Whether a path, resolved first so a link can't get around the list, is on the skip list or under it."""
        if not self:
            return False
        real = os.path.realpath(str(path))
        return self.prune(real, True, os.path.isdir(real)) if record else self._match(real, True) is not None

    def notes(self) -> list:
        """(severity, title, description, remediation, details) for what this list did in one scan: an unreadable
        list; the folders it kept Sereno out of (paths only, never contents); entries that matched nothing."""
        source = " and ".join(([str(self.source)] if self.source else []) + (["--skip"] if self.cli else [])) \
            or "given to this scan"
        if self.closed:
            path, why = self.problem
            return [("high", "Skip list unreadable, so Sereno didn't search your folders: %s" % path,
                     ("Sereno couldn't use %s (%s). It lists folders Sereno must not enter, so rather than risk "
                      "entering them, Sereno searched no folders at all: package folders, payload files, .env files, "
                      "git repositories, project settings, startup files and the baseline's watched files weren't "
                      "checked. That's not the same as clean." % (path, why)),
                     ('Fix the file: a JSON list of paths, such as ["~/agents/someone-else"]. Or remove it to skip '
                      "nothing."),
                     {"skip_file": str(path), "error": why})]
        out = []
        if self._dirs or self._files:
            n, files = len(self._dirs), len(self._files)
            roots = sorted(set(self._shown[r] for r in list(self._dirs.values()) + list(self._files.values())))
            counted = "%d folder%s" % (n, "" if n == 1 else "s")
            if files:
                counted += " and %d file%s" % (files, "" if files == 1 else "s")
            out.append(("info", "Not checked: %s on your skip list" % counted,
                        ("Sereno didn't enter %s, because they're on your skip list (%s): %s. Nothing inside them was "
                         "checked, so this scan says nothing about them." % (counted, source, ", ".join(roots))),
                        "Whoever uses those folders should check them. To check them here, take them off the list.",
                        {"skipped_folders": n, "skipped_files": files, "roots": roots,
                         "skip_file": str(self.source) if self.source else None}))
        if self.missing:
            listed = ", ".join(self.missing)
            out.append(("info", "Skip list entr%s not found: %s" % ("y" if len(self.missing) == 1 else "ies", listed),
                        ("%s on your skip list (%s) match%s nothing on this machine, so %s nothing. (An entry "
                         "starting with ! is reported when it takes nothing off the list.)"
                         % (listed, source, "es" if len(self.missing) == 1 else "", "it skipped"
                            if len(self.missing) == 1 else "they skipped")),
                        "Check the spelling, or take the entry off the list.",
                        {"entries": list(self.missing), "skip_file": str(self.source) if self.source else None}))
        return out


def load_skip_list(extra=()) -> SkipList:
    """The skip list for one scan: <state>/skip.json (a JSON list of paths; none when the file isn't there) plus extra
    entries (--skip on the command line, already made absolute). A file that can't be read or isn't a list of
    non-empty strings closes the list (see SkipList)."""
    extra = list(extra)
    path = sentinel_home() / SKIP_FILE
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, NotADirectoryError):   # no file, or no state folder: nothing listed
        return SkipList(extra, cli=bool(extra))
    except (OSError, ValueError, RecursionError) as e:   # RecursionError: JSON nested too deep to parse
        return SkipList(source=path, problem=(path, type(e).__name__))
    if not isinstance(data, list) or not all(isinstance(e, str) and e.strip() for e in data):
        return SkipList(source=path, problem=(path, "not a list of paths"))
    return SkipList(data + extra, source=path, cli=bool(extra))


def skip_list(skip=None) -> SkipList:
    """skip as given: None is the user's list (load_skip_list), a SkipList is used as it is, and a list of strings is
    added to the user's list, as --skip is."""
    if skip is None:
        return load_skip_list()
    if isinstance(skip, SkipList):
        return skip
    return load_skip_list([skip] if isinstance(skip, str) else list(skip))


def walk(top, skip=None):
    """os.walk(top) for every search under home: top-down, links not followed, folders that can't be read passed over,
    and every folder on the skip list pruned before it's entered. Like os.walk, it yields (dirpath, dirnames,
    filenames), and a caller can prune further by editing dirnames in place. A pruned folder is never listed, so a
    caller can't see its name in dirnames; a link whose target is on the list is pruned too, whether it points to a
    folder or a file, so neither shows up for a caller to open."""
    skip = skip_list(skip)
    active = bool(skip)
    top = os.fspath(top)
    real_top = os.path.realpath(top) if active else ""
    if active and skip.prune(real_top, True, True):
        return
    stack = [(top, real_top)]
    while stack:
        path, real = stack.pop()
        try:
            entries = os.scandir(path)
        except OSError:
            continue
        dirs, files, reals, links = [], [], {}, {}
        with entries:
            while True:
                try:
                    entry = next(entries)
                except StopIteration:
                    break
                except OSError:
                    break
                try:
                    is_dir = entry.is_dir()
                except OSError:
                    is_dir = False
                try:
                    link = entry.is_symlink()
                except OSError:
                    link = True   # unknown: resolve it in full
                if active:
                    child = os.path.realpath(entry.path) if link else os.path.join(real, entry.name)
                    if skip.prune(child, link, is_dir):
                        continue
                    reals[entry.name] = child
                if is_dir:
                    dirs.append(entry.name)
                    links[entry.name] = link
                else:
                    files.append(entry.name)
        yield path, dirs, files
        for name in reversed(dirs):
            child = os.path.join(path, name)
            if name in links:
                if links[name]:   # os.walk's rule: a link to a folder is listed, not followed
                    continue
                child_real = reals.get(name, "")
            else:   # a name the caller put in dirnames: checked in full
                if os.path.islink(child):
                    continue
                child_real = os.path.realpath(child) if active else ""
                if active and skip.prune(child_real, True, True):
                    continue
            stack.append((child, child_real))

"""Where Sereno keeps its state, and the folders under home it must not enter.

State: $SENTINEL_HOME, else ~/.sentinel. Read at call time, never at import, and every scan says which one it used
(2026-10-28: Ember's manual scans read ~/.sentinel for days because SENTINEL_HOME was set only on the cron line).

The skip list (2026-10-28, from Ember's install on a shared home): on a machine where several AI agents keep their
folders under one account's home (~/agents/<name>/), Sereno's searches walked into the other agents' folders. Findings
never carry values, but paths and variable names from someone else's folder in a log the user reads still cross a
line. Every search under home goes through walk() below, which prunes the folders on the skip list before it would
enter them, and every other path a check reads (a known project, a settings file, a linked folder) is asked about with
SkipList.covers() before its first stat, open or listing (2026-10-29, round 2). The list comes from <state>/skip.json
and from --skip on the command line; it's empty unless you make one. A scan that skipped anything says so in one note,
so a skip is never silent.
"""
import glob
import json
import os
import stat
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
    """The state folder in words, saying where it came from: what every scan's header shows. A SENTINEL_HOME that's set
    but empty is said to be empty (2026-10-29: it was called "isn't set", which sends you looking for a missing line
    when the line is there with nothing after the =)."""
    path, default = state_folder()
    if default:
        return "%s (the default: SENTINEL_HOME %s)" % (path, "is empty" if "SENTINEL_HOME" in os.environ else "isn't set")
    return "%s (from SENTINEL_HOME)" % path


# ── The skip list ──

def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root if root.endswith(os.sep) else root + os.sep)


def _absolute(path) -> str:
    """The path with '~' expanded and made absolute, and nothing else changed: its '..' still follow the links before
    them when it's resolved, as the system's own lookup does."""
    path = os.path.expanduser(os.fspath(path))
    return path if os.path.isabs(path) else os.path.join(os.getcwd(), path)


class _Root:
    """One folder (or file) on the list, by the three things that can name it: the path as written (lex), where it
    really is (real), and its identity, (st_dev, st_ino). kind is "folder" or "file", or None for a link to nothing
    when the list was read, which is matched by its paths only and counted as skipped only once it's there."""
    __slots__ = ("shown", "lex", "real", "ident", "kind")

    def __init__(self, path: str):
        self.shown = self.lex = os.path.normpath(path)
        self.real = os.path.realpath(path)   # looks up the root's own path, never anything inside it
        try:
            st = os.stat(path)
        except OSError:
            self.ident = self.kind = None
        else:
            self.ident = (st.st_dev, st.st_ino)
            self.kind = "folder" if stat.S_ISDIR(st.st_mode) else "file"

    def same(self, other) -> bool:
        """Two names for one folder: the same place, or the same identity (a link to it, or its name in another case
        on a case-insensitive disk)."""
        return self.real == other.real or (self.ident is not None and self.ident == other.ident)


_CLOSED = object()   # what an unreadable list matches: everything


class _Covered(Exception):
    def __init__(self, root):
        super().__init__()
        self.root = root


class SkipList:
    """The folders (or files) a scan must not enter or read, and what the scan skipped.

    entries are paths as the user wrote them: '~' is expanded, a relative path is taken from home, a * or ? matches
    names (glob's rules: not names starting with a dot), and an entry starting with ! takes a path back off the list
    (["~/agents/*", "!~/agents/mine"] skips every agent folder but your own). problem, when set, is (the skip file, why
    it couldn't be used): the list is then closed, skipping everything a walk would enter, because a skip list that
    can't be read can't promise to keep Sereno out of anyone's folder.

    A path is covered when any of three things holds (2026-10-29, round 2: matching resolved paths alone let a link
    inside a skipped folder lead Sereno out to where it pointed, and read that project's settings):
      (a) the path as written (absolute, '~' expanded, nothing resolved) is a root's path as written, or under it;
      (b) the path resolved, or any folder on the way to it, is where a root really is, or under it;
      (c) a folder on the way to it (or a root file it names) is a root by identity, (st_dev, st_ino): a link to the
          root, a mount of it, or its name in another case on a case-insensitive disk (macOS), all match.
    The path is resolved one name at a time, and each name is checked against the roots before it's looked up, so
    nothing inside a root is ever looked up: not a stat, a readlink, or a listing (a root itself may be, for (c)).

    One SkipList serves one scan: what it kept Sereno out of is recorded, and notes() reports it once, counting each
    root once, however many paths led into it."""

    def __init__(self, entries=(), source=None, problem=None, cli=False):
        self.source = source   # the skip file the entries came from, or None
        self.cli = cli         # whether some came from --skip
        self.problem = problem
        self.closed = problem is not None
        self.missing = []      # entries that matched nothing, as written
        self._roots = []
        self._forms = {}       # a root's path as written (a) and its resolved path (b) -> the root
        self._ids = {}         # (st_dev, st_ino) -> the root (c)
        self._file_inodes = set()   # the inode numbers of roots that are files, so a walk checks a file only on one
        self._hit = {}         # each root this scan was kept out of, as shown -> its kind
        if self.closed:
            return
        home = os.path.expanduser("~")
        roots, drop = [], []
        for entry in (e.strip() for e in entries):
            negate = entry.startswith("!")
            raw = os.path.expanduser(entry[1:] if negate else entry)
            if not os.path.isabs(raw):
                raw = os.path.join(home, raw)
            found = sorted(glob.glob(raw)) if glob.has_magic(raw) else ([raw] if os.path.lexists(raw) else [])
            if negate:
                drop.append((entry, [_Root(p) for p in found] or [_Root(raw)]))
            elif not found:
                self.missing.append(entry)
            else:
                roots += [_Root(p) for p in found]
        for entry, takes in drop:
            kept = [r for r in roots if not any(r.same(t) for t in takes)]
            if len(kept) == len(roots):
                self.missing.append(entry)   # an exception that took nothing off the list
            roots = kept
        for r in roots:   # one root per folder, however many names it was listed by
            if not any(r.same(o) for o in self._roots):
                self._roots.append(r)
        for r in self._roots:
            self._forms.setdefault(r.lex, r)
            self._forms.setdefault(r.real, r)
            if r.ident is not None:
                self._ids.setdefault(r.ident, r)
        self._file_inodes = set(r.ident[1] for r in self._roots if r.kind == "file")

    def __bool__(self):
        return self.closed or bool(self._roots)

    # Finding the root a path falls under, without looking up anything inside one

    def _by_name(self, path: str):
        """The root path is (by (a) or (b)'s paths) or is under, or None; a string comparison, nothing looked up."""
        root = self._forms.get(path)
        if root is not None:
            return root
        for form, root in self._forms.items():
            if _under(path, form):
                return root
        return None

    def _resolve(self, path: str, rest: str, seen: dict) -> str:
        """posixpath's realpath(path/rest), one name at a time, raising _Covered at the first name that's a root: by
        its path, before it's looked up, or by identity, once it has been (it's then the root itself, not something
        in it). A link is read only after its own name has passed, so its target is reached only through names that
        were checked. A name that isn't there is joined as written and still checked."""
        if os.path.isabs(rest):
            path, rest = os.sep, rest.lstrip(os.sep)
        while rest:
            name, _, rest = rest.partition(os.sep)
            if not name or name == os.curdir:
                continue
            if name == os.pardir:
                path = os.path.dirname(path)
                continue
            new = os.path.join(path, name)
            root = self._forms.get(new)
            if root is not None:
                raise _Covered(root)
            try:
                st = os.lstat(new)
            except OSError:
                path = new
                continue
            if not stat.S_ISLNK(st.st_mode):
                root = self._ids.get((st.st_dev, st.st_ino))
                if root is not None:
                    raise _Covered(root)
                path = new
                continue
            if new in seen:
                if seen[new] is None:   # a link loop: unresolvable, so the rest is joined as written
                    return os.path.join(new, rest)
                path = seen[new]
                continue
            seen[new] = None
            try:
                target = os.readlink(new)
            except OSError:
                path = new
                continue
            path = self._resolve(path, target, seen)
            seen[new] = path
        return path

    def _find(self, path):
        """(the root covering path, or None; path resolved when it isn't covered, else None)."""
        if self.closed:
            return _CLOSED, None
        given = _absolute(path)
        lex = os.path.normpath(given)
        root = self._by_name(lex)   # (a): the path as written, before anything is looked up
        if root is not None:
            return root, None
        try:
            # resolved as given, not as folded: in ~/x/link/../y the '..' climbs from where link points
            real = self._resolve(os.sep, given, {})
        except _Covered as c:
            return c.root, None
        root = self._by_name(real)   # (b): the resolved path in full (a link loop's unresolved tail included)
        return root, (real if root is None else None)

    def _child(self, path: str, real: str, entry, link: bool):
        """For walk(): (the root covering a child of a folder that isn't covered, or None; the child resolved). A child
        that isn't a link is covered only if it IS a root: by its path as walked (a), its resolved path (b), or its
        identity (c). A link is resolved from its folder one name at a time, as any path is."""
        if self.closed:
            return _CLOSED, None
        root = self._forms.get(os.path.join(path, entry.name))
        if root is not None:
            return root, None
        if link:
            try:
                child = self._resolve(real, entry.name, {})
            except _Covered as c:
                return c.root, None
            root = self._by_name(child)
            return root, (child if root is None else None)
        child = os.path.join(real, entry.name)
        root = self._forms.get(child)
        if root is None and self._ids:
            # A folder is looked up for its identity (a listing's inode for a mount point is the folder under it); a
            # file only when the listing's inode is a listed file's, which saves a lookup per file in the walk
            try:
                st = entry.stat(follow_symlinks=False) if (entry.is_dir(follow_symlinks=False) or (
                    self._file_inodes and entry.inode() in self._file_inodes)) else None
            except OSError:
                st = None
            if st is not None:
                root = self._ids.get((st.st_dev, st.st_ino))
        return root, (child if root is None else None)

    def _record(self, root):
        if root is _CLOSED:
            return
        kind = root.kind
        if kind is None:   # a link to nothing when the list was read (a drive not mounted): counted once it's there
            try:
                kind = "folder" if stat.S_ISDIR(os.stat(root.lex).st_mode) else "file"
            except OSError:
                return
        self._hit[root.shown] = kind

    def locate(self, path):
        """path resolved, or None when it's covered (and recorded): what walk() starts from."""
        root, real = self._find(path)
        if root is not None:
            self._record(root)
            return None
        return real

    def skipped(self) -> bool:
        """Whether this list kept a scan out of anything (or, closed, out of everything) so far."""
        return self.closed or bool(self._hit)

    def covers(self, path, record: bool = True) -> bool:
        """Whether a path is on the skip list or under it, by (a), (b) or (c) above, found without looking up anything
        inside a root. Call it before any stat, open or listing of the path; a path it covers is recorded for the
        note (record=False: only asked)."""
        if not self:
            return False
        root = self._find(path)[0]
        if root is None:
            return False
        if record:
            self._record(root)
        return True

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
        if self._hit:
            # Each root once, however many paths led into it, and only a root that's there (a folder or file when the
            # list was read, or when a link to nothing then was matched), so nothing absent is counted (2026-10-29:
            # every link into a root counted as a folder of its own, and settings files that didn't exist as files)
            n = sum(1 for k in self._hit.values() if k == "folder")
            files = len(self._hit) - n
            roots = sorted(self._hit)
            counted = "%d folder%s" % (n, "" if n == 1 else "s") if n else ""
            if files:
                counted += (" and " if n else "") + "%d file%s" % (files, "" if files == 1 else "s")
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
    folder or a file, so neither shows up for a caller to open. Each child is checked before anything else is asked of
    it (whether it's a folder follows a link, so it waits until the link is known to stay outside the list)."""
    skip = skip_list(skip)
    active = bool(skip)
    top = os.fspath(top)
    real_top = ""
    if active:
        real_top = skip.locate(top)
        if real_top is None:
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
                    link = entry.is_symlink()
                except OSError:
                    link = True   # unknown: resolved as a link is, one name at a time
                if active:
                    root, child = skip._child(path, real, entry, link)
                    if root is not None:
                        skip._record(root)
                        continue
                    reals[entry.name] = child
                try:
                    is_dir = entry.is_dir()
                except OSError:
                    is_dir = False
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
                child_real = ""
                if active:
                    child_real = skip.locate(child)
                    if child_real is None:
                        continue
                if os.path.islink(child):
                    continue
            stack.append((child, child_real))

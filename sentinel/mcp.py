"""MCP servers: the ones launched without a pinned version, and the ones holding secrets in plain text (2026-10-23).

AI coding tools (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI, Codex) start MCP servers from a
config file. A server started as `npx -y some-server` or `uvx some-server`, with no version, runs whatever release the
launcher fetches. If that package's publishing is hijacked, the bad release reaches you the next time the launcher
takes a new version, without you choosing it. Pinning an exact version (`some-server@1.4.2`, `some-server==1.4.2`)
closes that door. The idea comes from SolanceLab/stack-guard (MIT), which flags the same thing.

The same configs often carry API keys in a server's `env`. Anyone who can read the file has them, and a config
committed to git may already be public. Only key names are ever reported, never values.

Read-only, local, standard library only. A config that can't be parsed is reported as not checked, never as clean.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path

from .redact import redact

# npx-style launchers check the registry for the newest version when no version is given.
NPM_LAUNCHERS = ("npx", "bunx", "pnpx")
# Flags that take a value, per launcher family; everything else starting with "-" is a switch.
NPM_VALUE_FLAGS = {"-p", "--package", "-c", "--call", "--registry", "--cache", "--userconfig", "-w", "--workspace"}
UV_VALUE_FLAGS = {"--from", "--with", "--with-editable", "--with-requirements", "--python", "-p", "--index",
                  "--index-url", "--extra-index-url", "--default-index", "--find-links", "-f", "--cache-dir",
                  "--directory", "--project", "--config-file", "--env-file"}
PIPX_VALUE_FLAGS = {"--spec", "--python", "--pip-args", "--index-url", "-i"}
EXACT_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$")
EXACT_PEP440 = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$")
FULL_SHA = re.compile(r"[0-9a-f]{40}")
WALK_DEPTH = 4  # project folders under home: ~/code/group/project/.mcp.json is depth 4
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".cache", "Library", ".Trash"}


# ── Which package a server's command launches, and whether its version is pinned ──

def _split(command, args) -> list:
    """The full argument list, whether the config gives command + args or one command string."""
    args = [str(a) for a in (args or [])]
    command = str(command or "")
    if not args and " " in command.strip():
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()
    return [command] + args


def _first_positional(words: list, value_flags: set) -> tuple:
    """(first non-flag word, the value of each value flag seen). A bare `--` is skipped like any switch."""
    values, i = {}, 0
    while i < len(words):
        w = words[i]
        if w.startswith("-"):
            name, eq, val = w.partition("=")
            if eq:
                values[name] = val
            elif name in value_flags:
                values[name] = words[i + 1] if i + 1 < len(words) else ""
                i += 1
            i += 1
            continue
        return w, values
    return None, values


def npm_spec_pinned(spec: str) -> tuple:
    """(package name, pinned?, kind) for an npm spec. kind is 'registry', 'url' or 'local'."""
    if spec.startswith((".", "/", "~", "file:")):
        return spec, True, "local"
    if re.match(r"^(git\+|git:|github:|gitlab:|bitbucket:|https?:)", spec):
        return spec, bool(FULL_SHA.search(spec.split("#")[-1])) if "#" in spec else False, "url"
    if spec.startswith("@"):
        scope, _, rest = spec.partition("/")
        name, at, version = rest.partition("@")
        name = scope + "/" + name
    else:
        name, at, version = spec.partition("@")
    return name, bool(at and EXACT_SEMVER.match(version)), "registry"


def pypi_spec_pinned(spec: str) -> tuple:
    """(package name, pinned?, kind) for a uvx/pipx spec: name==1.2.3, name@1.2.3 (uvx), a URL, or a path."""
    if spec.startswith((".", "/", "~", "file:")):
        return spec, True, "local"
    if re.match(r"^(git\+|https?:)", spec):
        tail = spec.rsplit("@", 1)[-1] if "@" in spec.split("://", 1)[-1] else ""
        return spec, bool(FULL_SHA.fullmatch(tail.split("#")[0])), "url"
    m = re.match(r"^([A-Za-z0-9._\-]+)(?:\[[^\]]*\])?\s*(==|@)\s*([^\s;,]+)$", spec)
    if m:
        return m.group(1), bool(EXACT_PEP440.match(m.group(3))), "registry"
    name = re.match(r"^[A-Za-z0-9._\-]+", spec)
    return (name.group(0) if name else spec), False, "registry"


def launched_package(command, args):
    """What a server's command launches from a registry: a dict with launcher, ecosystem, name, spec, pinned and
    kind, or None when the command isn't a package launcher (a local script, a binary, a container)."""
    words = _split(command, args)
    if not words or not words[0]:
        return None
    exe = re.split(r"[\\/]", words[0])[-1].lower()  # a Windows path in a config read on Linux or WSL too
    for suffix in (".cmd", ".exe", ".bat"):
        if exe.endswith(suffix):
            exe = exe[: -len(suffix)]
    rest = words[1:]
    if exe in ("pnpm", "yarn") and rest[:1] == ["dlx"]:
        exe, rest = exe + " dlx", rest[1:]
    elif exe == "npm" and rest[:1] in (["exec"], ["x"]):
        exe, rest = "npm exec", rest[1:]
    elif exe == "bun" and rest[:1] == ["x"]:
        exe, rest = "bunx", rest[1:]
    elif exe == "uv" and rest[:2] == ["tool", "run"]:
        exe, rest = "uvx", rest[2:]
    elif exe == "pipx" and rest[:1] == ["run"]:
        exe, rest = "pipx run", rest[1:]
    if exe in NPM_LAUNCHERS or exe in ("pnpm dlx", "yarn dlx", "npm exec"):
        pos, flags = _first_positional(rest, NPM_VALUE_FLAGS)
        spec = flags.get("--package") or flags.get("-p") or pos
        if not spec:
            return None
        name, pinned, kind = npm_spec_pinned(spec)
        return {"launcher": exe, "ecosystem": "npm", "name": name, "spec": spec, "pinned": pinned, "kind": kind}
    if exe in ("uvx", "pipx run"):
        pos, flags = _first_positional(rest, UV_VALUE_FLAGS if exe == "uvx" else PIPX_VALUE_FLAGS)
        spec = flags.get("--from") or flags.get("--spec") or pos
        if not spec:
            return None
        name, pinned, kind = pypi_spec_pinned(spec)
        return {"launcher": exe, "ecosystem": "PyPI", "name": name, "spec": spec, "pinned": pinned, "kind": kind}
    return None


# ── Where the configs live, and reading them ──

def strip_jsonc(text: str) -> str:
    """JSON with // and /* */ comments and trailing commas (VS Code's mcp.json allows them) made plain JSON.
    Comment markers inside strings, like the // in a URL, are left alone."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _servers_in(data, key_paths) -> list:
    """(project label, server name, server dict) for every server under any of the key paths, e.g.
    ("mcpServers",) or ("projects", "*", "mcpServers"); the label is the project's key, or "" at the top level."""
    found = []
    for path in key_paths:
        nodes = [("", data)]
        for key in path:
            nxt = []
            for label, node in nodes:
                if not isinstance(node, dict):
                    continue
                if key == "*":
                    nxt += [(k, v) for k, v in node.items()]
                elif key in node:
                    nxt.append((label, node[key]))
            nodes = nxt
        for label, servers in nodes:
            if isinstance(servers, dict):
                found += [(label, name, s) for name, s in servers.items() if isinstance(s, dict)]
    return found


def config_files(home: Path) -> list:
    """(path, key paths, tool) for every MCP config location Sereno knows, whether or not it exists."""
    mac_support = home / "Library" / "Application Support"
    appdata = Path(os.environ["APPDATA"]) if os.environ.get("APPDATA") else None
    files = [
        (home / ".claude.json", [("mcpServers",), ("projects", "*", "mcpServers")], "Claude Code"),
        (mac_support / "Claude" / "claude_desktop_config.json", [("mcpServers",)], "Claude Desktop"),
        (home / ".config" / "Claude" / "claude_desktop_config.json", [("mcpServers",)], "Claude Desktop"),
        (home / ".cursor" / "mcp.json", [("mcpServers",)], "Cursor"),
        (mac_support / "Code" / "User" / "mcp.json", [("servers",)], "VS Code"),
        (home / ".config" / "Code" / "User" / "mcp.json", [("servers",)], "VS Code"),
        (home / ".codeium" / "windsurf" / "mcp_config.json", [("mcpServers",)], "Windsurf"),
        (home / ".gemini" / "settings.json", [("mcpServers",)], "Gemini CLI"),
    ]
    if appdata:
        files += [(appdata / "Claude" / "claude_desktop_config.json", [("mcpServers",)], "Claude Desktop"),
                  (appdata / "Code" / "User" / "mcp.json", [("servers",)], "VS Code")]
    return files


def project_configs(home: Path, extra_roots=()) -> list:
    """Project-level configs: .mcp.json, .cursor/mcp.json and .vscode/mcp.json, in Claude Code's known projects and
    anywhere up to WALK_DEPTH folders under home."""
    names = [(Path(".mcp.json"), [("mcpServers",)], "project (.mcp.json)"),
             (Path(".cursor") / "mcp.json", [("mcpServers",)], "project (Cursor)"),
             (Path(".vscode") / "mcp.json", [("servers",)], "project (VS Code)")]
    roots = set()
    for root, dirs, _files in os.walk(str(home)):
        depth = Path(root).relative_to(home).parts
        if len(depth) >= WALK_DEPTH:
            dirs[:] = []
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        if any((Path(root) / n).is_file() for n, _, _ in names):
            roots.add(Path(root))
    roots |= {Path(r) for r in extra_roots}
    return [(r / n, keys, tool) for r in sorted(roots) for n, keys, tool in names if (r / n).is_file()]


def _git_tracked(path: Path):
    """True if git tracks the file, False if not (or it isn't in a repo), None if git couldn't be asked."""
    try:
        # One `ls-files` on one file answers in milliseconds; 10 s only bounds a git that hangs (a network drive)
        p = subprocess.run(["git", "-C", str(path.parent), "ls-files", "--error-unmatch", path.name],
                           capture_output=True, text=True, timeout=10)
        return p.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return None


def _read_toml_servers(path: Path):
    """Codex's config.toml [mcp_servers.<name>] tables; None when this Python can't read TOML (before 3.11)."""
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        return None
    data = tomllib.loads(path.read_text())
    return [("", name, s) for name, s in (data.get("mcp_servers") or {}).items() if isinstance(s, dict)]


# ── The check ──

def check_mcp_servers(finding, home: Path = None, known_bad_npm: dict = None, known_bad_pip: dict = None):
    """Findings for unpinned MCP launchers and plain-text secrets in MCP configs. `finding(severity, title,
    description, remediation, details)` builds one (the scanner passes it, so this module imports nothing of it)."""
    home = home or Path.home()
    known_bad_npm = known_bad_npm or {}
    known_bad_pip = known_bad_pip or {}
    out = []
    seen = set()
    entries = [(p, k, t) for p, k, t in config_files(home) if p.is_file()]
    claude = home / ".claude.json"
    extra = []
    if claude.is_file():
        try:
            extra = [p for p in (json.loads(claude.read_text()).get("projects") or {}) if Path(p).is_dir()]
        except (OSError, ValueError, AttributeError):
            extra = []
    entries += project_configs(home, extra)
    codex = home / ".codex" / "config.toml"
    for path, keys, tool in entries + ([(codex, None, "Codex")] if codex.is_file() else []):
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        try:
            if keys is None:
                servers = _read_toml_servers(path)
                if servers is None:
                    out.append(finding("info", "MCP config not checked: %s" % path,
                                       "Codex keeps its servers in TOML, which this Python (before 3.11) can't read.",
                                       "Run Sereno with Python 3.11 or newer to check it.", {"path": str(path)}))
                    continue
            else:
                servers = _servers_in(json.loads(strip_jsonc(path.read_text(errors="replace"))), keys)
        except (OSError, ValueError) as e:
            out.append(finding("info", "MCP config not checked: %s" % path,
                               "Sereno couldn't read it (%s), so its servers weren't checked." % type(e).__name__,
                               "Check that the file is valid JSON.", {"path": str(path)}))
            continue
        tracked = "unasked"
        for project, name, server in servers:
            where = "%s, server \"%s\"%s" % (tool, name, (" (project %s)" % project) if project else "")
            pkg = launched_package(server.get("command"), server.get("args"))
            if pkg and not pkg["pinned"]:
                bad = _known_bad(pkg, known_bad_npm, known_bad_pip)
                out.append(finding(
                    "high" if bad else "medium",
                    "MCP server with no fixed version: %s (%s)" % (pkg["name"], where),
                    ("%s starts it with `%s %s`. With no exact version, it runs whatever release the launcher "
                     "fetches, so a hijacked release would reach you without you choosing it.%s"
                     % (tool, pkg["launcher"], pkg["spec"],
                        " This package is on Sereno's list of packages that had compromised releases." if bad
                        else "")),
                    ("Pin an exact version you've checked, for example %s, in %s."
                     % (_pinned_example(pkg), path)),
                    {"path": str(path), "server": name, "package": pkg["name"], "launcher": pkg["launcher"],
                     "spec": pkg["spec"]}))
            env = server.get("env") if isinstance(server.get("env"), dict) else {}
            secret_keys = sorted(k for k, v in env.items() if isinstance(v, str) and v and redact(v) != v)
            if secret_keys:
                if tracked == "unasked":
                    tracked = _git_tracked(path)
                out.append(finding(
                    "high" if tracked else "medium",
                    "MCP config holds a secret in plain text: %s (%s)" % (", ".join(secret_keys), where),
                    ("%s keeps the value of %s written in the file. Anyone who can read the file has it.%s"
                     % (path, ", ".join(secret_keys),
                        " Git tracks this file, so the secret may already be in a pushed commit." if tracked
                        else " Sereno couldn't ask git whether it tracks this file." if tracked is None else "")),
                    ("Move the secret to an environment variable or your system's keychain and reference it from "
                     "the config." + (" Rotate it, because it's in git history; deleting it now doesn't remove it "
                                      "from earlier commits." if tracked else "")),
                    {"path": str(path), "server": name, "keys": secret_keys, "git_tracked": tracked}))
    return out


def _known_bad(pkg: dict, npm: dict, pip: dict) -> bool:
    name = pkg["name"]
    if pkg["ecosystem"] == "npm":
        return name in (npm.get("packages") or {}) or name.split("/")[0] in (npm.get("scopes") or [])
    return re.sub(r"[-_.]+", "-", name).lower() in {re.sub(r"[-_.]+", "-", k).lower() for k in pip
                                                    if not k.startswith("_")}


def _pinned_example(pkg: dict) -> str:
    if pkg["ecosystem"] == "npm":
        return "`%s@1.2.3`" % pkg["name"]
    return "`%s==1.2.3`" % pkg["name"]

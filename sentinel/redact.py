"""Secrets out of anything that leaves the machine (Vera's audit, 2026-10-14).

A finding quotes what it found: a process's command line, a hook's command, a listening socket's line, a skill's
raw output. Any of those can hold a token, and a Discord alert sends it to someone else's server. The Discord
transport passes every message through redact() before it builds the payload, so no caller can forget to.

It errs toward redacting: a git hash or a long random file name may come out as [REDACTED ...]. An alert that says
less is better than a token on a server we don't control.
"""
from __future__ import annotations

import re

_SECRET_NAME = r"(?:api[_-]?key|secret|token|passw(?:or)?d|passwd|auth|credentials?|private[_-]?key|access[_-]?key)"

_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Known token shapes: the whole token goes, a label stays so the alert still says what was there.
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}"), "[REDACTED github token]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}"), "[REDACTED github token]"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{16,}"), "[REDACTED npm token]"),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}"), "[REDACTED api key]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), "[REDACTED slack token]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED aws key]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"), "[REDACTED google key]"),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}"), "[REDACTED gitlab token]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "[REDACTED jwt]"),
    (re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"), "discord.com/api/webhooks/[REDACTED]"),
    # A password inside a URL: https://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    # "Authorization: Bearer abc...", "Basic abc..."
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{12,}"), r"\1 [REDACTED]"),
    # name=value, name: value, --name value, --name=value, for any secret-looking name
    (re.compile(r"(?i)(\b[A-Za-z0-9_\-]*" + _SECRET_NAME + r"[A-Za-z0-9_\-]*\s*[=:]\s*)(?!\[REDACTED|bearer\b|basic\b)"
                r"(\"[^\"]*\"|'[^']*'|[^\s,;]+)"),
     r"\1[REDACTED]"),
    (re.compile(r"(?i)(--?[A-Za-z0-9_\-]*" + _SECRET_NAME + r"[A-Za-z0-9_\-]*\s+)(?!-|\[REDACTED)(\S+)"), r"\1[REDACTED]"),
    # Anything else long and random-looking: 32 or more letters, digits, _ or -, with at least one of each kind.
    (re.compile(r"(?<![A-Za-z0-9_\-])(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{32,}"),
     "[REDACTED long secret-like string]"),
]


def redact(text: str) -> str:
    """The text with every secret-shaped part replaced. Never raises: on any error the whole text is withheld."""
    try:
        out = str(text)
        for pattern, repl in _PATTERNS:
            out = pattern.sub(repl, out)
        return out
    except Exception:
        return "[alert text withheld: redaction failed]"

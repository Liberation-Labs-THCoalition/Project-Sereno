"""The pip check (2026-10-23): an entry with no version list is reported, never skipped; exact versions are critical."""
import json

import pytest

from sentinel import scanner
from sentinel.scanner import check_pip_supply_chain, load_known_bad_pip, load_known_bad_npm


def installed(monkeypatch, pkgs):
    out = json.dumps([{"name": n, "version": v} for n, v in pkgs])
    monkeypatch.setattr(scanner, "_run", lambda cmd, timeout=30: (out, 0))


FEED = {"_meta": {"name": "test"}, "badpkg": ["1.0.1"], "allbad": []}


@pytest.mark.parametrize("pkgs,expected", [
    ([("badpkg", "1.0.1")], [("critical", "badpkg")]),
    ([("badpkg", "1.0.2")], []),
    ([("allbad", "3.2.1")], [("medium", "allbad")]),     # skipped entirely before 10-23; high until 10-28
    ([("BadPkg", "1.0.1")], [("critical", "badpkg")]),   # names are lowercased
    ([("_meta", "1")], []),
    ([("fine", "1.0.1")], []),
])
def test_pip_check(monkeypatch, pkgs, expected):
    installed(monkeypatch, pkgs)
    got = [(f.severity, f.details["package"]) for f in check_pip_supply_chain(FEED)]
    assert got == expected


def test_an_unlisted_version_finding_says_what_it_doesnt_know(monkeypatch):
    installed(monkeypatch, [("allbad", "3.2.1")])
    f = check_pip_supply_chain(FEED)[0]
    assert "doesn't say which versions" in f.description and f.details["versions_listed"] is False


@pytest.mark.parametrize("name,good,bad", [("litellm", "1.104.0", "1.107.0"), ("telnyx", "4.87.0", "4.87.2"),
                                           ("lightning", "2.6.1", "2.6.3"), ("pytorch-lightning", "2.6.1", "2.6.2")])
def test_the_shipped_feed_names_this_years_exact_bad_versions(monkeypatch, name, good, bad):
    feed = load_known_bad_pip()
    installed(monkeypatch, [(name, good)])
    assert check_pip_supply_chain(feed) == []
    installed(monkeypatch, [(name, bad)])
    assert [f.severity for f in check_pip_supply_chain(feed)] == ["critical"]


def test_the_npm_feed_lists_tensorlake():
    assert "tensorlake" in load_known_bad_npm()["packages"]

"""The due check's grace (2026-10-27): a periodic intention stamped a few seconds late is still due at its next slot."""
from datetime import datetime, timedelta, timezone

import pytest

from sentinel import skills as S


@pytest.fixture
def bdi(tmp_path):
    return S.BDIEngine(state_file=str(tmp_path / "bdi_state.json"))


def _at(bdi, interval, ago):
    bdi.intentions.clear()
    bdi.add_intention("x", ["scan_packages"], trigger="periodic", interval=interval)
    if ago is not None:
        bdi.intentions[0].last_run = (datetime.now(timezone.utc) - timedelta(seconds=ago)).isoformat()
    return [i.desire for i in bdi.get_due_intentions()]


def test_never_run_is_due(bdi):
    assert _at(bdi, 14400, None) == ["x"]


def test_a_few_seconds_short_is_due(bdi):
    # the case the log showed: stamped after a run of a few seconds, checked at the next cron slot
    assert _at(bdi, 14400, 14400 - 3) == ["x"]


def test_full_interval_is_due(bdi):
    assert _at(bdi, 14400, 14400) == ["x"]


def test_well_short_is_not_due(bdi):
    assert _at(bdi, 14400, 14400 - 600) == []


def test_grace_is_capped_for_short_intervals(bdi):
    assert S.due_grace(60) == 6
    assert _at(bdi, 60, 55) == ["x"]
    assert _at(bdi, 60, 50) == []


def test_manual_intentions_are_never_due(bdi):
    bdi.intentions.clear()
    bdi.add_intention("m", ["scan_packages"], trigger="manual", interval=14400)
    assert bdi.get_due_intentions() == []


@pytest.mark.parametrize("interval_h", [4, 8, 24])
def test_cron_on_the_same_period_runs_each_check_on_time(monkeypatch, bdi, interval_h):
    """Cron every 4 h with 1-2 s start jitter; the chain takes 2 s and is stamped after it. Two days of slots."""
    clock = {"now": datetime(2026, 10, 24, tzinfo=timezone.utc)}

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock["now"]
    monkeypatch.setattr(S, "datetime", Clock)
    bdi.intentions.clear()
    bdi.add_intention("x", ["scan_packages"], trigger="periodic", interval=interval_h * 3600)
    runs = []
    t0 = clock["now"]
    for slot in range(12 if interval_h < 24 else 18):
        start = t0 + timedelta(hours=4 * slot, seconds=1 + slot % 2)
        clock["now"] = start
        if bdi.get_due_intentions():
            runs.append(start)
            clock["now"] = start + timedelta(seconds=2)
            bdi.mark_run(bdi.intentions[0])
    gaps = {round((b - a).total_seconds() / 3600) for a, b in zip(runs, runs[1:])}
    assert gaps == {interval_h}

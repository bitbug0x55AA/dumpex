"""
Call-count regression tests for `collect_hunt()` and `cmd_hunt(...,
collect_records=True)` (PR4) -- confirm the "single-scan, dual-consumer"
unification (see each hunter's own `_build_*_report()`/
`_record_from_*_report()` docstring pair) actually holds at the
orchestrator level: every SELECTED hunter's own `_build_*_report()` is
invoked EXACTLY ONCE per call, whether `selected="all"`/`ttp="all"` or a
single hunter, and a hunter that was NOT selected is never invoked at
all. This guards against either orchestrator regressing into calling
both a `_build_*_report()` and that same hunter's own `_hunt_*()`/
`collect_*_record()` wrapper (which would each build their own separate
Report and scan twice), against a future edit that drops the `selected`
gating and scans every hunter unconditionally, and -- for `cmd_hunt()`
specifically, cli.py's actual `--hunt` entry point -- against console
rendering and record collection ever being driven by two separate
builder calls instead of one.
"""
import pytest

from tests.fixtures.fakes import empty_mf as _empty_mf

import dumpex.hunt as hunt_pkg
from dumpex.output.records import HUNTERS

_BUILDER_ATTR = {
    "injection": "_build_injection_report",
    "hollowing": "_build_hollowing_report",
    "stomping": "_build_stomping_report",
    "pipe": "_build_pipe_report",
    "cs-beacon": "_build_cs_beacon_report",
    "yara": "_build_yara_report",
    "obfuscation": "_build_encoding_report",
}


def _patch_counters(monkeypatch) -> dict:
    """Wrap every hunter's `_build_*_report` binding as seen INSIDE
    `dumpex.hunt` -- the only binding `collect_hunt()` itself ever calls
    -- with a call-counting wrapper around the real function. Returns
    {hunter: list} where len(list) is the call count; the real function
    still runs underneath, so this changes no behavior, only counts
    invocations."""
    counts = {}
    for hunter, attr in _BUILDER_ATTR.items():
        real_fn = getattr(hunt_pkg, attr)
        calls = []

        def make_wrapper(real_fn, calls):
            def wrapper(*args, **kwargs):
                calls.append(1)
                return real_fn(*args, **kwargs)
            return wrapper

        monkeypatch.setattr(hunt_pkg, attr, make_wrapper(real_fn, calls))
        counts[hunter] = calls
    return counts


def test_collect_hunt_all_calls_each_builder_exactly_once(monkeypatch):
    counts = _patch_counters(monkeypatch)
    result = hunt_pkg.collect_hunt(_empty_mf(), "all")

    assert tuple(r.hunter for r in result.records) == HUNTERS
    for hunter in HUNTERS:
        assert len(counts[hunter]) == 1, (
            f"{hunter} builder called {len(counts[hunter])} time(s) under "
            f"selected='all', expected exactly 1")


@pytest.mark.parametrize("selected", HUNTERS)
def test_collect_hunt_single_hunter_calls_only_that_builder_once(monkeypatch, selected):
    counts = _patch_counters(monkeypatch)
    result = hunt_pkg.collect_hunt(_empty_mf(), selected)

    assert tuple(r.hunter for r in result.records) == (selected,)
    for hunter in HUNTERS:
        expected = 1 if hunter == selected else 0
        assert len(counts[hunter]) == expected, (
            f"selected={selected!r}: {hunter} builder called {len(counts[hunter])} "
            f"time(s), expected {expected}")


def test_cmd_hunt_collect_records_all_calls_each_builder_exactly_once(monkeypatch, capsys):
    """`cmd_hunt(..., collect_records=True)` is cli.py's actual CLI-facing
    entry point (PR4) -- it must produce BOTH the console report AND the
    v2.4 records from the SAME builder call per hunter, not two. This is
    the one guarantee the CLI wiring itself depends on: calling both
    `cmd_hunt()` (console) and `collect_hunt()` (JSON) separately for one
    `--hunt` invocation would double every selected hunter's scan."""
    counts = _patch_counters(monkeypatch)
    results, records, _actions, _yara_provenance = hunt_pkg.cmd_hunt(
        _empty_mf(), "all", verbose=False, collect_records=True)

    assert sorted(results.keys()) == sorted(HUNTERS)
    assert tuple(r.hunter for r in records) == HUNTERS
    for hunter in HUNTERS:
        assert len(counts[hunter]) == 1, (
            f"{hunter} builder called {len(counts[hunter])} time(s) under "
            f"cmd_hunt(collect_records=True, ttp='all'), expected exactly 1")
    assert capsys.readouterr().out   # console output still happened


@pytest.mark.parametrize("selected", HUNTERS)
def test_cmd_hunt_collect_records_single_hunter_calls_only_that_builder_once(
        monkeypatch, capsys, selected):
    counts = _patch_counters(monkeypatch)
    results, records, _actions, _yara_provenance = hunt_pkg.cmd_hunt(
        _empty_mf(), selected, verbose=False, collect_records=True)

    assert tuple(results.keys()) == (selected,)
    assert tuple(r.hunter for r in records) == (selected,)
    for hunter in HUNTERS:
        expected = 1 if hunter == selected else 0
        assert len(counts[hunter]) == expected, (
            f"selected={selected!r}: {hunter} builder called {len(counts[hunter])} "
            f"time(s) under cmd_hunt(collect_records=True), expected {expected}")
    assert capsys.readouterr().out   # console output still happened


def test_cmd_hunt_without_collect_records_is_unchanged(monkeypatch):
    """`collect_records` defaults to False -- every existing caller of
    `cmd_hunt()` (tests, other scripts) must keep getting back a bare
    `results` dict, not a tuple."""
    counts = _patch_counters(monkeypatch)
    results = hunt_pkg.cmd_hunt(_empty_mf(), "injection", verbose=False)

    assert isinstance(results, dict)
    assert tuple(results.keys()) == ("injection",)
    assert len(counts["injection"]) == 1

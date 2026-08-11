"""
`collect_hunt()` and `collect_*_record()` must never print anything --
they exist so a caller can use `--hunt` as a pure data API (build a
`CommandResult`/`HunterRecord` and pipe its JSON straight out) without any
console text mixed into stdout. `dumpex.rules_pkg.loader.get_rules()`
prints a one-time "Rules loaded from ..." line on the FIRST real call in
a process (see its own docstring) -- hollowing/stomping/pipe/obfuscation's
own `_build_*_report()` functions all need real rule data
(`get_rules(announce=False)`) to compute detections, so calling any of
them via `collect_hunt()` on a COLD rules cache (nothing has warmed it
yet) is exactly the scenario that silently leaked a "Rules loaded..."
line onto stdout before `announce=False` existed.

The rules-loader's cache (`_RULES_CACHE`/`_EXPLICIT_RULES_PATH`/
`_LAST_SOURCE_INFO`) is reset via `monkeypatch.setattr()` before each
scenario (auto-restored, never a bare global mutation) specifically so
this test exercises the FIRST-load path every time, regardless of
whether an earlier test in the same pytest run already warmed the cache
-- a test that relied on the cache already being cold from process start
would pass or fail depending on test execution order, which is exactly
the flakiness dumpex.hunt.stomping._hunt_stomping's own print-ordering
fixes elsewhere in this suite go out of their way to avoid.
"""
import pytest

import dumpex.rules_pkg.loader as rules_loader
import dumpex.hunt.yara_hunt as yara_hunt_mod
from dumpex.hunt import collect_hunt
from dumpex.hunt.hollowing.collect import collect_hollowing_record
from dumpex.hunt.stomping.collect import collect_stomping_record
from dumpex.hunt.pipe.collect import collect_pipe_record
from dumpex.hunt.encoding.collect import collect_obfuscation_record
from dumpex.output.records import HUNTERS

from tests.fixtures.fakes import FakeMF


def _reset_rules_cache(monkeypatch):
    monkeypatch.setattr(rules_loader, "_RULES_CACHE", None)
    monkeypatch.setattr(rules_loader, "_EXPLICIT_RULES_PATH", None)
    monkeypatch.setattr(rules_loader, "_LAST_SOURCE_INFO", None)
    monkeypatch.setattr(yara_hunt_mod, "_LAST_YARA_PROVENANCE", None)


def _empty_mf():
    class MF(FakeMF):
        memory_segments_64 = None
        memory_segments = None
    return MF()


# Only these four hunters' own _build_*_report() calls dumpex.rules_pkg.
# loader.get_rules() at all (injection/cs-beacon don't use rules.yaml;
# yara uses its own, separate rule-loading system) -- see
# dumpex.hunt.collect_hunt()'s own docstring and each hunter's package
# docstring for which data source each one actually reads.
_RULES_CONSUMING_HUNTERS = ("hollowing", "stomping", "pipe", "obfuscation")


@pytest.mark.parametrize("selected", _RULES_CONSUMING_HUNTERS)
def test_collect_hunt_prints_nothing_on_cold_rules_cache(monkeypatch, capsys, selected):
    _reset_rules_cache(monkeypatch)
    result = collect_hunt(_empty_mf(), selected)

    assert result.records[0].hunter == selected
    assert capsys.readouterr().out == ""


def test_collect_hunt_all_prints_nothing_on_cold_rules_cache(monkeypatch, capsys):
    _reset_rules_cache(monkeypatch)
    result = collect_hunt(_empty_mf(), "all")

    assert tuple(r.hunter for r in result.records) == HUNTERS
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("selected", _RULES_CONSUMING_HUNTERS)
def test_collect_x_record_prints_nothing_on_cold_rules_cache(monkeypatch, capsys, selected):
    """The same guarantee for each hunter's own thin `collect_*_record()`
    compat wrapper (used directly by callers that don't go through
    `collect_hunt()` at all -- see e.g. tests/integration/
    test_hunt_all_seven_collectors.py)."""
    _reset_rules_cache(monkeypatch)
    collector = {
        "hollowing": collect_hollowing_record,
        "stomping": collect_stomping_record,
        "pipe": collect_pipe_record,
        "obfuscation": collect_obfuscation_record,
    }[selected]

    rec = collector(_empty_mf())

    assert rec.hunter == selected
    assert capsys.readouterr().out == ""

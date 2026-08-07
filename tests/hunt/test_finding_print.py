"""
Console-rendering tests for dumpex.hunt._finding.Finding.print() -- distinct
from tests/hunt/test_finding_contract.py (schema/id contract) and
tests/hunt/test_finding_invariants.py (cross-hunter DETECTED/tag invariant).

Covers two review-round regressions:
  1. Finding.print(verbose=False) used to print `len(self.facts)` as if it
     were a trustworthy observed-item count. It never was -- several
     hunters cap facts at 10/15/20 with a synthetic "... and N more" entry
     that is itself counted, others cap with no such marker at all, and a
     few emit more than one fact per logical observation. Fixed by
     dropping the count entirely rather than trying to derive a correct
     one from facts alone.
  2. The old `verbose: bool` + `facts_mode: "full"/"notice"/"omit"`
     combination existed only so a hunter's presentation.py could render
     its OWN separate, uncapped raw-evidence block (reading raw scan
     lists like report.rwx) without Finding.print() also showing a
     duplicate, capped version of the same facts. Replaced by
     `verbose_facts` -- a real field on Finding itself, built once at
     Finding-construction time (see that field's own docstring) -- and a
     single `level: DetailLevel` parameter. See tests/hunt/test_injection.
     py's own verbose-detail tests for the end-to-end (aggregate.py ->
     Finding.verbose_facts -> Finding.print()) version of this.
"""
import io
import contextlib

import pytest

from dumpex.hunt._finding import Finding, DetailLevel, TAG_OBSERVATION, TAG_DETECTION, CONFIDENCE_LOW


def _captured_print(finding: Finding, **kwargs) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        finding.print(**kwargs)
    return buf.getvalue()


def _finding(**overrides) -> Finding:
    kwargs = dict(
        check="test.example",
        facts=["fact one", "fact two"],
        inference="something was observed",
        confidence=CONFIDENCE_LOW,
        rationale="because reasons",
        limitations=["a known gap"],
        tag=TAG_OBSERVATION,
    )
    kwargs.update(overrides)
    return Finding(**kwargs)


def test_normal_mode_does_not_claim_a_fact_count():
    # The bug: printing len(self.facts) as a headcount is wrong whenever
    # facts is truncated (with or without a "... and N more" sentinel) or
    # holds more than one fact per logical observation -- so normal mode
    # must never print a number derived from len(facts) at all.
    out = _captured_print(_finding(facts=["fact one", "fact two", "fact three"]))
    assert "Facts: available" in out
    assert "3 item" not in out
    assert "item(s)" not in out


def test_normal_mode_collapses_facts_regardless_of_count():
    out_one = _captured_print(_finding(facts=["only one fact"]))
    out_many = _captured_print(_finding(facts=[f"fact {i}" for i in range(50)]))
    assert "Facts: available — use --verbose to list" in out_one
    assert "Facts: available — use --verbose to list" in out_many
    assert "only one fact" not in out_one
    assert "fact 0" not in out_many


def test_verbose_mode_lists_every_fact():
    facts = [f"fact {i}" for i in range(5)]
    out = _captured_print(_finding(facts=facts), level=DetailLevel.VERBOSE)
    for fact in facts:
        assert fact in out
    assert "available" not in out


def test_no_facts_line_when_facts_empty():
    out_normal = _captured_print(_finding(facts=[]))
    out_verbose = _captured_print(_finding(facts=[]), level=DetailLevel.VERBOSE)
    assert "Facts" not in out_normal
    assert "Facts" not in out_verbose


def test_limitations_shown_in_both_normal_and_verbose_mode():
    out_normal = _captured_print(_finding(limitations=["gap A", "gap B"]))
    out_verbose = _captured_print(_finding(limitations=["gap A", "gap B"]), level=DetailLevel.VERBOSE)
    for out in (out_normal, out_verbose):
        assert "Limitations:" in out
        assert "gap A" in out
        assert "gap B" in out


def test_indent_applied_to_every_line():
    out = _captured_print(_finding(), indent=6)
    for line in out.splitlines():
        if line.strip():
            assert line.startswith(" " * 6)


def test_verbose_facts_supersede_facts_under_verbose():
    # A Finding with verbose_facts set is asserting "this is the richer
    # view for a human reader" -- Finding.print() must show ONLY
    # verbose_facts under DetailLevel.VERBOSE, never both (which would
    # print the same VA/handle/token twice).
    f = _finding(facts=["short summary fact"],
                 verbose_facts=["item 1 full detail", "item 2 full detail"])
    out = _captured_print(f, level=DetailLevel.VERBOSE)
    assert "item 1 full detail" in out
    assert "item 2 full detail" in out
    assert "short summary fact" not in out


def test_verbose_facts_collapse_to_notice_under_normal():
    f = _finding(facts=["short summary fact"],
                 verbose_facts=["item 1 full detail", "item 2 full detail"])
    out = _captured_print(f)
    assert "Facts: available — use --verbose to list" in out
    assert "item 1 full detail" not in out
    assert "short summary fact" not in out


def test_facts_used_when_no_verbose_facts():
    # The common case (most Findings never set verbose_facts): behavior is
    # unchanged from before verbose_facts existed.
    f = _finding(facts=["fact one", "fact two"])
    assert f.verbose_facts == ()
    out = _captured_print(f, level=DetailLevel.VERBOSE)
    assert "fact one" in out
    assert "fact two" in out


def test_default_level_is_normal():
    facts = ["fact one"]
    out_default = _captured_print(_finding(facts=facts))
    out_explicit = _captured_print(_finding(facts=facts), level=DetailLevel.NORMAL)
    assert out_default == out_explicit
    assert "fact one" not in out_default


def test_inference_confidence_rationale_always_shown():
    f = _finding(inference="the specific claim", rationale="the specific reason",
                 tag=TAG_DETECTION)
    for level in (DetailLevel.NORMAL, DetailLevel.VERBOSE):
        out = _captured_print(f, level=level)
        assert "the specific claim" in out
        assert "the specific reason" in out
        assert f.check in out


def test_level_rejects_non_detail_level_values():
    # The old facts_mode string param raised ValueError on an unrecognized
    # value -- migrating to a DetailLevel enum must not silently lose that
    # protection by falling back to NORMAL for anything that isn't
    # DetailLevel.VERBOSE (a plain `if level is VERBOSE: ... else: NORMAL`
    # would do exactly that for "verbose", True, or None).
    for bad_level in ("verbose", "normal", True, False, None, 1, 0):
        with pytest.raises(TypeError, match="DetailLevel"):
            _captured_print(_finding(), level=bad_level)


def test_level_accepts_both_detail_level_members():
    for level in (DetailLevel.NORMAL, DetailLevel.VERBOSE):
        _captured_print(_finding(), level=level)   # must not raise

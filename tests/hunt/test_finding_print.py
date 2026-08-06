"""
Console-rendering tests for dumpex.hunt._finding.Finding.print() -- distinct
from tests/hunt/test_finding_contract.py (schema/id contract) and
tests/hunt/test_finding_invariants.py (cross-hunter DETECTED/tag invariant).

Covers a review-round regression: Finding.print(verbose=False) used to
print `len(self.facts)` as if it were a trustworthy observed-item count.
It never was -- several hunters cap facts at 10/15/20 with a synthetic
"... and N more" entry that is itself counted, others cap with no such
marker at all, and a few emit more than one fact per logical observation
(e.g. cs_beacon.structural_config: one fact for the config, one for its
enclosing region, per ONE Beacon config). Fixed by dropping the count
entirely rather than trying to derive a correct one from facts alone.
"""
import io
import contextlib

from dumpex.hunt._finding import Finding, TAG_OBSERVATION, TAG_DETECTION, CONFIDENCE_LOW


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
    out = _captured_print(_finding(facts=facts), verbose=True)
    for fact in facts:
        assert fact in out
    assert "available" not in out


def test_no_facts_line_when_facts_empty():
    out_normal = _captured_print(_finding(facts=[]))
    out_verbose = _captured_print(_finding(facts=[]), verbose=True)
    assert "Facts" not in out_normal
    assert "Facts" not in out_verbose


def test_limitations_shown_in_both_normal_and_verbose_mode():
    out_normal = _captured_print(_finding(limitations=["gap A", "gap B"]))
    out_verbose = _captured_print(_finding(limitations=["gap A", "gap B"]), verbose=True)
    for out in (out_normal, out_verbose):
        assert "Limitations:" in out
        assert "gap A" in out
        assert "gap B" in out


def test_indent_applied_to_every_line():
    out = _captured_print(_finding(), indent=6)
    for line in out.splitlines():
        if line.strip():
            assert line.startswith(" " * 6)


def test_facts_mode_notice_never_shows_full_list_even_when_verbose():
    # facts_mode="notice" is for a caller that renders its own separate raw
    # supplement immediately after -- it must always show the "available"
    # notice, ignoring `verbose`, so the caller's supplement stays the one
    # and only place a fact's content appears under --verbose.
    facts = ["fact one", "fact two"]
    out = _captured_print(_finding(facts=facts), verbose=True, facts_mode="notice")
    assert "Facts: available" in out
    assert "fact one" not in out


def test_facts_mode_omit_prints_nothing_about_facts():
    facts = ["fact one", "fact two"]
    for verbose in (False, True):
        out = _captured_print(_finding(facts=facts), verbose=verbose, facts_mode="omit")
        assert "Facts" not in out
        assert "fact one" not in out
        # everything else must still be present
        assert "Limitations:" in out


def test_facts_mode_full_is_the_default_and_unchanged():
    facts = ["fact one"]
    out_default = _captured_print(_finding(facts=facts), verbose=True)
    out_explicit = _captured_print(_finding(facts=facts), verbose=True, facts_mode="full")
    assert out_default == out_explicit
    assert "fact one" in out_default


def test_facts_mode_rejects_unknown_value():
    import pytest
    with pytest.raises(ValueError, match="facts_mode"):
        _captured_print(_finding(), facts_mode="bogus")


def test_inference_confidence_rationale_always_shown():
    f = _finding(inference="the specific claim", rationale="the specific reason",
                 tag=TAG_DETECTION)
    for verbose in (False, True):
        out = _captured_print(f, verbose=verbose)
        assert "the specific claim" in out
        assert "the specific reason" in out
        assert f.check in out

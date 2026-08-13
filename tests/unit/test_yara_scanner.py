"""
Unit tests for dumpex.hunt.yara_hunt.scanner.scan_segments's resource-budget
handling (match() timeout, whole-scan hit cap, per-match string-instance
cap) and for _hunt_yara's yara-python-missing early return.

Deliberately does NOT use pytest.importorskip("yara") anywhere in this
file, unlike the end-to-end tests in tests/hunt/test_yara_hunt.py and
tests/unit/test_yara_hunt.py (which need the real yara-python package to
actually compile a .yar file on disk). Every test here drives
scan_segments with a fake compiled-rule object standing in for a compiled
yara.Rules instance, and fake match objects standing in for yara.Match --
no real YARA engine involved anywhere, so these tests run identically
whether or not yara-python (an optional "full" dependency) happens to be
installed.
"""
import dataclasses
import sys

import pytest

from tests.fixtures.fakes import Segment, FakeReader, FakeMF

from dumpex.hunt.yara_hunt.scanner import scan_segments, ScanResult
from dumpex.hunt.yara_hunt.config import YaraConfig
from dumpex.hunt.yara_hunt.domain import RulesDiagnostics, ScanDiagnostics
from dumpex.hunt.yara_hunt.models import RuleMatchEvidence
from dumpex.hunt.yara_hunt import aggregate
from dumpex.hunt.yara_hunt.report_facts import legacy_coverage_dict, project_coverage_reasons, \
    project_coverage_report
from dumpex.hunt._ui import DETECTED, INCONCLUSIVE
import dumpex.hunt.yara_hunt as yara_hunt


class FakeTimeoutError(Exception):
    """Stands in for yara.TimeoutError. scanner.py classifies a match()
    failure as a timeout by checking whether "timeout" appears in the
    exception CLASS NAME (case-insensitive) -- not by catching
    yara.TimeoutError specifically -- precisely so this can be tested
    without the real yara-python package. See scanner.py's own comment on
    why it does this (yara-python's exact exception type isn't a stable
    contract across versions)."""


class FakeInstance:
    """Stands in for one yara.StringMatchInstance (yara-python >= 4.3)."""
    def __init__(self, offset, matched_data=b"X"):
        self.offset = offset
        self.matched_data = matched_data


class FakeStringMatch:
    """Stands in for one yara.StringMatch (yara-python >= 4.3): an
    identifier plus every instance where that string matched. This is the
    branch scanner.py takes when hasattr(s, 'instances') is True."""
    def __init__(self, identifier, instances):
        self.identifier = identifier
        self.instances = instances


class FakeMatch:
    """Stands in for one yara.Match object -- everything scanner.py reads
    off a match (.rule, .tags, .meta, .strings)."""
    def __init__(self, rule, tags=None, meta=None, strings=None):
        self.rule = rule
        self.tags = tags if tags is not None else []
        self.meta = meta if meta is not None else {}
        self.strings = strings if strings is not None else []


class FakeCompiled:
    """Stands in for one compiled yara.Rules object. Returns `results`
    (a list of FakeMatch) on every match() call, or raises `exc` on every
    call instead if given."""
    def __init__(self, results=None, exc=None):
        self._results = results if results is not None else []
        self._exc = exc
        self.call_count = 0

    def match(self, data, timeout):
        self.call_count += 1
        if self._exc is not None:
            raise self._exc
        return self._results


def _mf_with_segment(seg_va, seg_fo, data):
    seg = Segment(seg_va, seg_fo, len(data))
    mf = FakeMF()
    mf._reader = FakeReader({seg_va: data})
    return mf, seg


def _build_report(result, rule_files, compile_failed=0):
    """`scan_segments()`'s own `ScanResult` -> `YaraReport`, using a
    `RulesDiagnostics` that matches what `_build_yara_report()` would
    have built for the same `(rule_files, compile_failed)` pair."""
    rules_diag = RulesDiagnostics(yara_available=True, rules_dir="fake", attempted=True,
                                   compiled_ok=len(rule_files), compile_failed=compile_failed)
    return aggregate.build_report(result, rules_diag)


# ── ScanResult must be frozen: aggregate's input boundary admits typed
# evidence and scalars only, never a mutable scanner DTO ─────────────────

def test_scan_result_is_a_frozen_dataclass():
    assert dataclasses.is_dataclass(ScanResult)
    assert ScanResult.__dataclass_params__.frozen is True


def test_scan_result_rejects_reassignment_after_construction():
    result = ScanResult(matches=(), diagnostics=ScanDiagnostics())
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.matches = ("poisoned",)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.diagnostics = ScanDiagnostics(segment_count=99)


def test_scan_result_copies_matches_so_caller_list_mutation_cannot_reach_it():
    # frozen=True alone only blocks reassigning result.matches -- it does
    # nothing about the caller mutating the ORIGINAL list after
    # construction. __post_init__ must defensively copy into a fresh tuple.
    matches = []
    result = ScanResult(matches=matches, diagnostics=ScanDiagnostics())
    matches.append(RuleMatchEvidence(rule="Poison", file="poison.yar"))
    assert result.matches == ()


def test_scan_result_rejects_non_rule_match_evidence_items():
    with pytest.raises(TypeError, match="RuleMatchEvidence"):
        ScanResult(matches=["not a RuleMatchEvidence"], diagnostics=ScanDiagnostics())


def test_scan_result_rejects_wrong_diagnostics_type():
    with pytest.raises(TypeError, match="ScanDiagnostics"):
        ScanResult(matches=(), diagnostics="not a ScanDiagnostics")


# ── match() timeout: a coverage gap, not a silent "ran, no match" ────────

def test_match_timeout_marks_partial_and_inconclusive():
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0x1000, 0x100, data)
    compiled = FakeCompiled(exc=FakeTimeoutError("simulated yara timeout"))
    config = YaraConfig()
    rule_files = [("good.yar", compiled)]

    result = scan_segments(mf, [seg], rule_files, modules=[], regions=[],
                            modules_available=False, mem_info_available=False, config=config)

    assert result.diagnostics.timed_out == 1
    assert result.diagnostics.match_failed == 0
    assert result.matches == ()
    # issue #28 P4 follow-up: the segment's own identity is retained, not
    # just tallied -- the same "region/segment identity behind every scan
    # gap counter" issue #28 already gives read_failed/short_reads.
    assert len(result.diagnostics.timed_out_targets) == 1
    assert result.diagnostics.timed_out_targets[0].base_address == 0x1000
    assert result.diagnostics.match_failed_targets == ()

    report = _build_report(result, rule_files)
    coverage = legacy_coverage_dict(report)
    assert coverage["matches_completed"] is False
    assert report.status == INCONCLUSIVE
    assert report.coverage_status == "partial"
    _, reasons = project_coverage_reasons(report)
    assert any("timed out" in r for r in reasons)

    timed_out_lim = next(l for l in project_coverage_report(report).limitations
                          if l.code.value == "YARA_MATCH_TIMED_OUT")
    assert len(timed_out_lim.targets) == 1
    assert timed_out_lim.targets[0].base_address == 0x1000


def test_match_failure_retains_segment_target():
    # Companion to the timeout test above -- a non-timeout match() failure
    # must retain the segment's identity the same way.
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0x5000, 0x500, data)
    compiled = FakeCompiled(exc=ValueError("simulated yara internal error"))
    config = YaraConfig()
    rule_files = [("bad.yar", compiled)]

    result = scan_segments(mf, [seg], rule_files, modules=[], regions=[],
                            modules_available=False, mem_info_available=False, config=config)

    assert result.diagnostics.match_failed == 1
    assert len(result.diagnostics.match_failed_targets) == 1
    assert result.diagnostics.match_failed_targets[0].base_address == 0x5000
    assert result.diagnostics.timed_out_targets == ()

    report = _build_report(result, rule_files)
    match_failed_lim = next(l for l in project_coverage_report(report).limitations
                             if l.code.value == "YARA_MATCH_FAILED")
    assert len(match_failed_lim.targets) == 1
    assert match_failed_lim.targets[0].base_address == 0x5000


def test_same_segment_failing_two_rule_files_contributes_two_targets():
    # `timed_out`/`match_failed` count CALLS, not segments (see
    # scanner.py's own comment) -- a segment whose search fails against
    # TWO different rule files must contribute its target TWICE, keeping
    # len(targets) == affected_count exactly rather than silently
    # switching to per-segment counting.
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0x6000, 0x600, data)
    fail_a = FakeCompiled(exc=ValueError("boom a"))
    fail_b = FakeCompiled(exc=ValueError("boom b"))
    config = YaraConfig()

    result = scan_segments(mf, [seg], [("a.yar", fail_a), ("b.yar", fail_b)],
                            modules=[], regions=[], modules_available=False,
                            mem_info_available=False, config=config)

    assert result.diagnostics.match_failed == 2
    assert len(result.diagnostics.match_failed_targets) == 2
    assert all(t.base_address == 0x6000 for t in result.diagnostics.match_failed_targets)


# ── a confirmed hit must not be erased by a LATER rule file timing out ───

def test_detected_hit_survives_later_timeout():
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0x2000, 0x200, data)
    hit_compiled     = FakeCompiled(results=[FakeMatch("HitRule")])
    timeout_compiled = FakeCompiled(exc=FakeTimeoutError("simulated yara timeout"))
    config = YaraConfig()
    rule_files = [("hit.yar", hit_compiled), ("slow.yar", timeout_compiled)]

    result = scan_segments(mf, [seg], rule_files, modules=[], regions=[],
                            modules_available=False, mem_info_available=False, config=config)

    assert result.diagnostics.timed_out == 1
    assert len(result.matches) == 1
    assert result.matches[0].rule == "HitRule"

    report = _build_report(result, rule_files)
    assert report.status == DETECTED
    assert report.coverage_status == "partial"
    assert "HitRule" in report.triggered_rules


# ── whole-scan hit cap truncates collection rather than growing unbounded ─

def test_total_hit_cap_marks_scan_truncated():
    # Two DISTINCT rules sharing the one segment -- the cap must stop
    # collection after `max_total_hits` raw matches regardless of rule
    # identity; using two different rule names (rather than one repeated
    # match, which the (rule, seg_va) dedup this module applies after the
    # loop ends would collapse to a single entry either way) keeps the
    # post-dedup evidence count meaningful too.
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0x3000, 0x300, data)
    matches = [FakeMatch(f"CapRule{i}") for i in range(5)]
    compiled = FakeCompiled(results=matches)
    config = YaraConfig(max_total_hits=2)
    rule_files = [("cap.yar", compiled)]

    result = scan_segments(mf, [seg], rule_files, modules=[], regions=[],
                            modules_available=False, mem_info_available=False, config=config)

    assert result.diagnostics.truncated is True
    assert len(result.matches) == 2   # never more than the configured cap
    # issue #28 P5 follow-up: the segment the cap was hit inside is
    # retained, not just tallied.
    assert len(result.diagnostics.truncated_targets) == 1
    assert result.diagnostics.truncated_targets[0].base_address == 0x3000

    coverage = legacy_coverage_dict(_build_report(result, rule_files))
    assert coverage["hit_cap_not_reached"] is False

    report = _build_report(result, rule_files)
    assert report.coverage_status == "partial"

    hit_cap_lim = next(l for l in project_coverage_report(report).limitations
                        if l.code.value == "YARA_HIT_CAP_REACHED")
    assert hit_cap_lim.affected_count == 1
    assert len(hit_cap_lim.targets) == 1
    assert hit_cap_lim.targets[0].base_address == 0x3000
    # issue #28 P6 follow-up: the structured budget fact too.
    assert hit_cap_lim.scope == "max_total_hits"
    assert (hit_cap_lim.budget_limit, hit_cap_lim.budget_consumed) == (2, 2)


def test_total_hit_cap_retains_every_later_segment_as_a_target_too():
    # issue #28 P5 follow-up: once the cap is reached inside segment 1,
    # segment 2 -- which the scan never even starts -- must ALSO be
    # named, not just the segment mid-processing when the cap fired.
    data = b'\x00' * 0x100
    mf, seg1 = _mf_with_segment(0x9000, 0x900, data)
    seg2 = Segment(0xA000, 0xA00, len(data))
    matches = [FakeMatch(f"CapRule{i}") for i in range(5)]
    compiled = FakeCompiled(results=matches)
    config = YaraConfig(max_total_hits=2)

    result = scan_segments(mf, [seg1, seg2], [("cap.yar", compiled)], modules=[], regions=[],
                            modules_available=False, mem_info_available=False, config=config)

    assert result.diagnostics.truncated is True
    assert len(result.diagnostics.truncated_targets) == 2
    assert {t.base_address for t in result.diagnostics.truncated_targets} == {0x9000, 0xA000}


def test_deadline_exhausted_marks_budget_exhausted_with_every_unstarted_segment():
    # A deadline already in the past when the scan begins means the FIRST
    # segment never starts at all -- both it and every later segment must
    # be named as budget_exhausted_targets.
    data = b'\x00' * 0x100
    mf, seg1 = _mf_with_segment(0xB000, 0xB00, data)
    seg2 = Segment(0xC000, 0xC00, len(data))
    compiled = FakeCompiled(results=[])
    config = YaraConfig(scan_deadline_seconds=-1)
    rule_files = [("x.yar", compiled)]

    # A fixed (not the real wall clock) monotonic: `scan_start` and the
    # top-of-loop deadline check both see 0, so the REAL elapsed time
    # (issue #28 review follow-up: budget_consumed is now measured, not
    # assumed equal to the limit) comes out deterministically 0 too,
    # rather than depending on however many real microseconds elapsed
    # between two consecutive time.monotonic() calls on this machine.
    result = scan_segments(mf, [seg1, seg2], rule_files, modules=[], regions=[],
                            modules_available=False, mem_info_available=False, config=config,
                            monotonic=_clamped_clock([0, 0]))

    assert result.diagnostics.budget_exhausted is True
    assert result.diagnostics.scanned == 0
    assert len(result.diagnostics.budget_exhausted_targets) == 2
    assert {t.base_address for t in result.diagnostics.budget_exhausted_targets} == {0xB000, 0xC000}
    # issue #28 P6 follow-up: a negative configured deadline reports as
    # limit=0 (the smallest REAL budget), never the literal negative value.
    assert result.diagnostics.budget_exhausted_kind == "scan_deadline_seconds"
    assert result.diagnostics.budget_exhausted_limit == 0

    report = _build_report(result, rule_files)
    budget_lim = next(l for l in project_coverage_report(report).limitations
                       if l.code.value == "YARA_SCAN_BUDGET_EXHAUSTED")
    assert budget_lim.affected_count == 2
    assert budget_lim.scope == "scan_deadline_seconds"
    assert (budget_lim.budget_limit, budget_lim.budget_consumed) == (0, 0)


def test_total_bytes_budget_exhausted_reports_its_own_kind():
    # Companion to the deadline-exhaustion test above -- the OTHER of
    # YARA_SCAN_BUDGET_EXHAUSTED's two possible resources.
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0x12000, 0x1200, data)
    compiled = FakeCompiled(results=[])
    config = YaraConfig(max_total_bytes_scanned=0)   # already exhausted before any read

    result = scan_segments(mf, [seg], [("x.yar", compiled)], modules=[], regions=[],
                            modules_available=False, mem_info_available=False, config=config)

    assert result.diagnostics.budget_exhausted is True
    assert result.diagnostics.budget_exhausted_kind == "max_total_bytes_scanned"
    assert result.diagnostics.budget_exhausted_limit == 0
    assert len(result.diagnostics.budget_exhausted_targets) == 1
    assert result.diagnostics.budget_exhausted_targets[0].base_address == 0x12000


# ── issue #28 P6 follow-up: the deadline can be noticed only AFTER the ────
# current (segment, rule_file) pairing's own work already finished -- that
# must not manufacture a false "this segment is still unexamined" target.

def _clamped_clock(vals):
    calls = {"n": 0}
    def fake_monotonic():
        i = calls["n"]
        calls["n"] += 1
        return vals[min(i, len(vals) - 1)]
    return fake_monotonic


def test_deadline_after_last_pairing_completes_reports_no_false_target():
    # The reviewer's exact repro: 1 segment, 1 rule file, both fully
    # examined -- the deadline is discovered only once there is genuinely
    # nothing left. budget_exhausted still becomes True at the
    # ScanDiagnostics level (a real wall-clock overrun worth recording),
    # but no segment is falsely named, AND (issue #28 review follow-up)
    # this must not be constructed as a CoverageLimitation at all -- a
    # targetless YARA_SCAN_BUDGET_EXHAUSTED used to still flip the whole
    # result to INCONCLUSIVE/partial even though nothing was actually left
    # unexamined.
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0xD000, 0xD00, data)
    compiled = FakeCompiled(results=[])
    config = YaraConfig()
    rule_files = [("r.yar", compiled)]
    # call1: scan_deadline setup: 0 -> deadline=300. call2: top-of-outer-
    # loop check: 1 (ok). call3: rule_index 0's own "remaining" check: 2
    # (ok, match() proceeds). call4: the post-match recheck: 1000 (deadline
    # exceeded) -- and this was the only rule file for the only segment.
    result = scan_segments(mf, [seg], rule_files, modules=[], regions=[],
                            modules_available=False, mem_info_available=False, config=config,
                            monotonic=_clamped_clock([0, 1, 2, 1000]))

    assert result.diagnostics.budget_exhausted is True
    assert result.diagnostics.scanned == 1
    assert result.diagnostics.budget_exhausted_targets == ()

    report = _build_report(result, rule_files)
    assert not any(l.code.value == "YARA_SCAN_BUDGET_EXHAUSTED"
                   for l in project_coverage_report(report).limitations)
    assert project_coverage_report(report).status.value == "complete"
    assert report.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert legacy_coverage_dict(report)["scan_budget_ok"] is True


def test_deadline_mid_rule_files_still_includes_current_segment():
    # Companion: when a LATER rule file for the SAME segment genuinely
    # never runs, that segment IS still a real gap.
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0xE000, 0xE00, data)
    compiled_a = FakeCompiled(results=[])
    compiled_b = FakeCompiled(results=[])
    config = YaraConfig()

    result = scan_segments(mf, [seg], [("a.yar", compiled_a), ("b.yar", compiled_b)],
                            modules=[], regions=[], modules_available=False,
                            mem_info_available=False, config=config,
                            monotonic=_clamped_clock([0, 1, 2, 1000]))

    assert result.diagnostics.budget_exhausted is True
    assert len(result.diagnostics.budget_exhausted_targets) == 1
    assert result.diagnostics.budget_exhausted_targets[0].base_address == 0xE000
    assert compiled_b.call_count == 0   # the second rule file genuinely never ran


def test_deadline_after_segment_zero_finishes_only_names_segment_one():
    # Two segments, one rule file each: segment 0's own (only) rule file
    # completes cleanly, and the deadline is only noticed right after --
    # segment 0 must NOT appear in targets (nothing left for it), only
    # segment 1 (never even started).
    data = b'\x00' * 0x100
    seg0 = Segment(0xF000, 0xF00, len(data))
    seg1 = Segment(0xF100, 0xF10, len(data))
    mf = FakeMF()
    mf._reader = FakeReader({0xF000: data, 0xF100: data})
    compiled = FakeCompiled(results=[])
    config = YaraConfig()

    result = scan_segments(mf, [seg0, seg1], [("r.yar", compiled)], modules=[], regions=[],
                            modules_available=False, mem_info_available=False, config=config,
                            monotonic=_clamped_clock([0, 1, 2, 1000]))

    assert result.diagnostics.budget_exhausted is True
    assert result.diagnostics.scanned == 1   # only segment 0 was actually read/matched
    assert len(result.diagnostics.budget_exhausted_targets) == 1
    assert result.diagnostics.budget_exhausted_targets[0].base_address == 0xF100


def test_deadline_in_except_branch_after_last_pairing_reports_no_false_target():
    # Same "genuinely nothing left" shape as the success-path test above,
    # but reached via the except branch (a raising, non-timeout match()
    # call) instead of a successful one.
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0x11000, 0x1100, data)
    compiled = FakeCompiled(exc=ValueError("boom"))
    config = YaraConfig()
    # call1: deadline setup: 0. call2: top-of-outer-loop: 1 (ok). call3:
    # rule_index 0's "remaining" check: 2 (ok, match() is attempted and
    # raises). call4: the except-branch deadline check: 1000 (exceeded).
    result = scan_segments(mf, [seg], [("r.yar", compiled)], modules=[], regions=[],
                            modules_available=False, mem_info_available=False, config=config,
                            monotonic=_clamped_clock([0, 1, 2, 1000]))

    assert result.diagnostics.match_failed == 1   # the raising call is still counted
    assert result.diagnostics.budget_exhausted is True
    assert result.diagnostics.budget_exhausted_targets == ()


# ── per-match string-instance cap ─────────────────────────────────────────

def test_string_instance_cap():
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0x4000, 0x400, data)
    instances = [FakeInstance(offset=i * 4, matched_data=b"AA") for i in range(10)]
    match = FakeMatch("StringyRule", strings=[FakeStringMatch("$a", instances)])
    compiled = FakeCompiled(results=[match])
    config = YaraConfig(max_strings_per_match=3)

    result = scan_segments(mf, [seg], [("stringy.yar", compiled)], modules=[], regions=[],
                            modules_available=False, mem_info_available=False, config=config)

    assert len(result.matches) == 1
    annotated = result.matches[0].strings
    assert len(annotated) == 3   # capped, not all 10 instances
    assert annotated[0].offset == 0
    assert annotated[0].va == seg.start_virtual_address
    assert annotated[0].fo == seg.start_file_address
    assert annotated[2].offset == 8
    assert annotated[2].va == seg.start_virtual_address + 8


# ── yara-python missing: NOT_EVALUATED, prior provenance cleared ─────────
# Uses sys.modules['yara'] = None to force `import yara` to raise
# ImportError (standard import-system behavior for a None sentinel) --
# this works identically whether or not yara-python is actually
# installed in the environment running this test, so no
# pytest.importorskip is needed (or wanted) here.

def test_yara_missing_returns_not_evaluated(monkeypatch, capsys):
    yara_hunt._LAST_YARA_PROVENANCE = {"rules_dir": "stale", "files": []}
    monkeypatch.setitem(sys.modules, "yara", None)

    f = yara_hunt._hunt_yara(FakeMF(), rules_dir="/does_not_matter", verbose=False)

    assert f["status"] == "NOT_EVALUATED"
    assert f["coverage_status"] == "not_evaluated"
    assert f["verdict_level"] == "not_evaluated"
    assert f["score"] == 0
    assert yara_hunt.get_yara_provenance() is None

    out = capsys.readouterr().out
    assert "yara-python is not installed" in out

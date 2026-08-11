"""Tests for the process-hollowing pure projectors (dumpex/hunt/hollowing/
report_facts.py, report_legacy.py, report_record.py, report_console.py) --
everything that turns a hand-built `HollowingReport`
(dumpex.hunt.hollowing.domain's canonical domain model) into the legacy v1.1
dict, the current-schema `HunterRecord`, and the verdict-first console.
Mirrors tests/hunt/test_stomping_projectors.py and
tests/hunt/test_pipe_projectors.py (the completed reference pilots' own test
suites) -- see those modules' own docstrings for the general split between
this file and its neighbours.

Like those two, this file carries its own fact-text parity test
(`test_fact_text_matches_the_pre_migration_wording`): the hollowing fact
strings are the one part of this migration required to stay byte-identical
(the v1.1 findings dict and the typed `HunterRecord` both embed them, they
feed `Finding.id`'s hash basis, and tests/fixtures/hunt_cli_golden/
hollowing_hunt_dict.json is frozen against them), so they are pinned here
against literals transcribed from the pre-migration builder rather than only
via a golden byte-diff of the one scenario the CLI freeze happens to
exercise.

Builder helpers below reuse test_hollowing_domain.py's own.
"""
import pytest

from tests.hunt.test_hollowing_domain import (
    _check, _context, _coverage, _correlation, _header, _mem_private, _module,
    _name_mismatch, _region, _rwx, _wiped_header, _IMAGE_BASE, _IMAGE_PATH, _ZERO_BYTES,
)

from dumpex.hunt._console import strip_ansi
from dumpex.hunt._finding import (
    CONFIDENCE_HIGH, CONFIDENCE_LOW, CONFIDENCE_MEDIUM, TAG_DETECTION, TAG_LEAD,
    TAG_OBSERVATION,
)
from dumpex.hunt.hollowing.domain import (
    CoverageSnapshot, HollowingEvidence, HollowingReport,
)
from dumpex.hunt.hollowing.models import (
    OUTCOME_EXCEPTION, OUTCOME_SHORT_READ, OUTCOME_WIPED_ZERO,
)
from dumpex.hunt.hollowing.report_console import render_console_lines
from dumpex.hunt.hollowing.report_facts import finding_from_check_result, project_coverage_v1
from dumpex.hunt.hollowing.report_legacy import project_legacy_dict
from dumpex.hunt.hollowing.report_record import project_hunter_record
from dumpex.output.coverage import EXIT_NOT_EVALUATED, EXIT_OK, EXIT_PARTIAL, exit_code_for


# ── Report builders ────────────────────────────────────────────────────────

def _detected_report(score=1, coverage=None, context=None) -> HollowingReport:
    """DETECTED. `score=1` is MEM_PRIVATE + RWX (the MZ header is intact);
    `score=2` adds the wiped header, so all three signals correlate."""
    mem_private = _mem_private()
    rwx = _rwx()
    wiped = _wiped_header() if score == 2 else None
    correlation = _correlation(mem_private=mem_private, wiped_header=wiped, rwx=rwx)
    evidence = HollowingEvidence(
        mem_private=(mem_private,), wiped_headers=(wiped,) if wiped else (),
        rwx=(rwx,), correlations=(correlation,))
    results = [
        _check(check="hollowing.mem_private_at_image_base", tag=TAG_LEAD,
               confidence=CONFIDENCE_MEDIUM,
               inference="The main module's image base is backed by MEM_PRIVATE memory, "
                          "not a file-mapped MEM_IMAGE region.",
               evidence=(mem_private,)),
    ]
    if wiped is not None:
        results.append(_check(check="hollowing.mz_header_missing", tag=TAG_LEAD,
                              confidence=CONFIDENCE_MEDIUM, evidence=(wiped,)))
    results.append(_check(check="hollowing.rwx_at_image_base", tag=TAG_LEAD,
                          confidence=CONFIDENCE_LOW,
                          inference="The main module's image base carries RWX-family "
                                     "protection.",
                          evidence=(rwx,)))
    results.append(_check(
        check="hollowing.structural_correlation", tag=TAG_DETECTION,
        confidence=CONFIDENCE_HIGH if score == 2 else CONFIDENCE_MEDIUM,
        # Distinctive wording so WHY THIS VERDICT can be proven to be driven
        # by THIS check rather than by display order.
        inference="independent structural signal(s) correlate at the same image base",
        limitations=["Structural correlation is strong evidence but not a substitute for "
                     "live-execution corroboration."],
        evidence=(correlation,)))
    header = _header(outcome=OUTCOME_WIPED_ZERO, header_bytes=_ZERO_BYTES) if wiped else _header()
    return HollowingReport(score=score, coverage=coverage or _coverage(),
                            context=context or _context(header=header),
                            results=tuple(results), evidence=evidence)


def _all_checks_report() -> HollowingReport:
    """Every one of the five check ids in one Report -- the full
    three-signal correlation plus the unscored name mismatch."""
    mem_private = _mem_private()
    wiped = _wiped_header()
    rwx = _rwx()
    mismatch = _name_mismatch()
    correlation = _correlation(mem_private=mem_private, wiped_header=wiped, rwx=rwx)
    evidence = HollowingEvidence(
        mem_private=(mem_private,), wiped_headers=(wiped,), rwx=(rwx,),
        name_mismatches=(mismatch,), correlations=(correlation,))
    results = (
        _check(check="hollowing.mem_private_at_image_base", tag=TAG_LEAD,
               confidence=CONFIDENCE_MEDIUM, evidence=(mem_private,)),
        _check(check="hollowing.mz_header_missing", tag=TAG_LEAD,
               confidence=CONFIDENCE_MEDIUM, evidence=(wiped,)),
        _check(check="hollowing.rwx_at_image_base", tag=TAG_LEAD,
               confidence=CONFIDENCE_LOW, evidence=(rwx,)),
        _check(check="hollowing.peb_module_name_mismatch", tag=TAG_LEAD,
               confidence=CONFIDENCE_LOW, evidence=(mismatch,)),
        _check(check="hollowing.structural_correlation", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH,
               inference="independent structural signal(s) correlate at the same image base",
               evidence=(correlation,)),
    )
    return HollowingReport(
        score=2, coverage=_coverage(),
        context=_context(header=_header(outcome=OUTCOME_WIPED_ZERO, header_bytes=_ZERO_BYTES),
                          module=_module(name=r"C:\Windows\System32\other.exe")),
        results=results, evidence=evidence)


def _single_lead_report() -> HollowingReport:
    """One anchor and nothing else -- the exact case the correlation
    requirement exists to keep out of DETECTED."""
    mem_private = _mem_private()
    return HollowingReport(
        score=0, coverage=_coverage(), context=_context(),
        results=(_check(check="hollowing.mem_private_at_image_base", tag=TAG_LEAD,
                        confidence=CONFIDENCE_MEDIUM, evidence=(mem_private,)),),
        evidence=HollowingEvidence(mem_private=(mem_private,)))


def _clean_report() -> HollowingReport:
    return HollowingReport(score=0, coverage=_coverage(),
                            context=_context(region=_region(type="MEM_IMAGE",
                                                             protect="PAGE_READONLY")),
                            results=(), evidence=HollowingEvidence())


def _partial_report() -> HollowingReport:
    """Evaluated, but the header read failed -- anchor 2 never ran, so a
    score of 0 is INCONCLUSIVE, never a clean bill of health."""
    return HollowingReport(
        score=0, coverage=_coverage(mz_read_failed=True),
        context=_context(header=_header(outcome=OUTCOME_EXCEPTION)),
        results=(), evidence=HollowingEvidence())


def _not_evaluated_report() -> HollowingReport:
    return HollowingReport(score=0, coverage=CoverageSnapshot(peb_present=False),
                            context=None, results=(), evidence=HollowingEvidence())


_ALL_REPORTS = [_all_checks_report, _detected_report, _single_lead_report,
                _clean_report, _partial_report, _not_evaluated_report]


# ── 1. Per-projector shape tests ──────────────────────────────────────────

@pytest.mark.parametrize("report_fn", _ALL_REPORTS)
def test_projectors_do_not_raise_for_every_state(report_fn):
    report = report_fn()
    d = project_legacy_dict(report)
    record = project_hunter_record(report)
    lines = render_console_lines(report, verbose=False)
    verbose_lines = render_console_lines(report, verbose=True)
    assert isinstance(d, dict)
    assert record.hunter == "hollowing"
    assert isinstance(lines, list) and all(isinstance(l, str) for l in lines)
    assert isinstance(verbose_lines, list)


def test_legacy_dict_key_set_is_unchanged():
    """The v1.1 findings dict's own key set is a frozen contract (see
    tests/integration/test_hunt_compat_freeze.py's `_HOLLOWING_KEYS`)."""
    d = project_legacy_dict(_all_checks_report())
    assert set(d) == {
        "score", "max_score", "status", "coverage_status", "coverage_reasons",
        "confidence", "verdict_level", "findings", "lead_count", "review_priority",
    }
    assert d["score"] == 2 and d["max_score"] == 2
    assert len(d["findings"]) == 5


def test_legacy_dict_is_the_same_shape_for_a_not_evaluated_run():
    """The pre-migration renderer built this dict TWICE -- an early-return
    literal for the PEB-missing case and a second one for everything else.
    One projector now means the two can no longer disagree."""
    d = project_legacy_dict(_not_evaluated_report())
    assert set(d) == set(project_legacy_dict(_all_checks_report()))
    assert d["score"] == 0 and d["max_score"] == 2
    assert d["status"] == "NOT_EVALUATED"
    assert d["coverage_status"] == "not_evaluated"
    assert d["coverage_reasons"] == ["PEB stream missing from this dump"]
    assert d["findings"] == [] and d["lead_count"] == 0
    assert d["review_priority"] == "none" and d["verdict_level"] == "not_evaluated"


def test_hunter_record_details_shape_is_the_v2_wire_shape():
    record = project_hunter_record(_all_checks_report())
    details = record.details
    assert details.image_base == f"0x{_IMAGE_BASE:016x}"
    assert details.mem_private_at_base is True
    assert details.mz_header_present is False
    assert details.is_rwx_at_base is True
    assert details.peb_image_path == _IMAGE_PATH
    assert details.module_name == r"C:\Windows\System32\other.exe"
    assert details.name_mismatch is True
    assert set(details.to_dict()) == {
        "image_base", "mem_private_at_base", "mz_header_present", "is_rwx_at_base",
        "peb_image_path", "module_name", "name_mismatch"}


def test_console_lines_contain_expected_sections():
    lines = render_console_lines(_all_checks_report(), verbose=False)
    text = "\n".join(lines)
    assert "HUNT: Process Hollowing" in text
    assert "VERDICT" in text
    assert "KEY SIGNALS" in text
    assert "WHY THIS VERDICT" in text


# ── 2. Fact-text parity with the pre-migration builder ────────────────────

def test_fact_text_matches_the_pre_migration_wording():
    """Literal transcriptions of what the pre-migration
    `_build_hollowing_report()` produced for the same evidence -- the fact
    strings are embedded in BOTH the v1.1 dict and the typed
    `HunterRecord`, and feed `Finding.id`, so they may not drift."""
    report = _all_checks_report()
    facts = {r.check: finding_from_check_result(r, report).facts for r in report.results}

    assert facts["hollowing.mem_private_at_image_base"] == (
        f"VA=0x{_IMAGE_BASE:x} type=MEM_PRIVATE protect=PAGE_EXECUTE_READWRITE",)
    assert facts["hollowing.mz_header_missing"] == (
        f"VA=0x{_IMAGE_BASE:x} header_bytes={_ZERO_BYTES[:8].hex()}",)
    assert facts["hollowing.rwx_at_image_base"] == (
        f"VA=0x{_IMAGE_BASE:x} protect=PAGE_EXECUTE_READWRITE",)
    assert facts["hollowing.peb_module_name_mismatch"] == (
        f"PEB_image_path={_IMAGE_PATH!r} module_list_match=True",)
    assert facts["hollowing.structural_correlation"] == (
        f"VA=0x{_IMAGE_BASE:x} MEM_PRIVATE at image base + MZ header missing/wiped "
        f"+ RWX protection",)


def test_name_mismatch_fact_distinguishes_an_unlisted_base_from_a_renamed_one():
    unlisted = _name_mismatch(module=None)
    report = HollowingReport(
        score=0, coverage=_coverage(), context=_context(module=None),
        results=(_check(check="hollowing.peb_module_name_mismatch", tag=TAG_LEAD,
                        confidence=CONFIDENCE_LOW, evidence=(unlisted,)),),
        evidence=HollowingEvidence(name_mismatches=(unlisted,)))
    assert finding_from_check_result(report.results[0], report).facts == (
        f"PEB_image_path={_IMAGE_PATH!r} module_list_match=False",)


def test_unknown_check_id_has_no_silent_fallback_renderer():
    report = HollowingReport(score=0, coverage=_coverage(), context=_context(),
                              results=(_check(check="hollowing.brand_new_check",
                                               evidence=()),),
                              evidence=HollowingEvidence())
    with pytest.raises(ValueError, match="no fact renderer registered"):
        finding_from_check_result(report.results[0], report)


def test_file_offsets_are_verbose_only_console_detail_never_a_wire_fact():
    """Issue #10 asks for the image-base VA/file offset in bounded/verbose
    evidence. They must NOT reach `facts` -- that array is embedded verbatim
    in both the v1.1 dict and the typed `HunterRecord`, whose golden is
    frozen."""
    from dumpex.hunt.hollowing.report_console import _console_finding

    report = _detected_report(score=1)
    for result in report.results:
        wire = finding_from_check_result(result, report)
        assert not any("File_offset" in fact for fact in wire.facts)
        assert wire.verbose_facts == ()

    mem_private_result = next(r for r in report.results
                              if r.check == "hollowing.mem_private_at_image_base")
    verbose_fact = _console_finding(mem_private_result, report).verbose_facts[0]
    assert "File_offset=0x3000" in verbose_fact
    assert "state=MEM_COMMIT" in verbose_fact

    normal = "\n".join(render_console_lines(report, verbose=False))
    verbose = "\n".join(render_console_lines(report, verbose=True))
    assert "File_offset" not in normal
    assert "File_offset=0x3000" in verbose


def test_uncaptured_file_offset_reads_as_not_captured_never_as_zero():
    from dumpex.hunt.hollowing.report_console import _console_finding
    report = _detected_report(
        score=1, context=_context(file_offset=None, region_file_offset=None))
    result = next(r for r in report.results
                  if r.check == "hollowing.mem_private_at_image_base")
    verbose_fact = _console_finding(result, report).verbose_facts[0]
    assert "File_offset=(not captured)" in verbose_fact
    assert "File_offset=0x0" not in verbose_fact


def test_name_mismatch_verbose_fact_spells_out_both_sides_of_the_comparison():
    from dumpex.hunt.hollowing.report_console import _console_finding
    report = _all_checks_report()
    result = next(r for r in report.results
                  if r.check == "hollowing.peb_module_name_mismatch")
    verbose_fact = _console_finding(result, report).verbose_facts[0]
    assert "peb_name='legit.exe'" in verbose_fact
    assert "module_list_name='other.exe'" in verbose_fact


# ── 3. State-matrix tests ─────────────────────────────────────────────────

def test_detected_score_1_state_matches_across_projectors():
    report = _detected_report(score=1)
    d, record = project_legacy_dict(report), project_hunter_record(report)
    assert report.status == "DETECTED"
    assert d["status"] == "DETECTED" == record.status
    assert d["score"] == record.score == 1
    assert d["verdict_level"] == record.verdict_level == "likely"
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "LIKELY HOLLOWING — MEM_PRIVATE at image base correlated with RWX protection" in text
    assert "HIGH CONFIDENCE HOLLOWING" not in text


def test_detected_score_1_names_the_wiped_header_when_that_is_the_second_signal():
    mem_private = _mem_private()
    wiped = _wiped_header()
    correlation = _correlation(mem_private=mem_private, wiped_header=wiped, rwx=None)
    report = HollowingReport(
        score=1, coverage=_coverage(),
        context=_context(header=_header(outcome=OUTCOME_WIPED_ZERO,
                                         header_bytes=_ZERO_BYTES)),
        results=(_check(check="hollowing.structural_correlation", tag=TAG_DETECTION,
                        confidence=CONFIDENCE_MEDIUM, evidence=(correlation,)),),
        evidence=HollowingEvidence(mem_private=(mem_private,), wiped_headers=(wiped,),
                                    correlations=(correlation,)))
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "correlated with MZ header wiped" in text


def test_detected_score_2_state_matches_across_projectors():
    report = _detected_report(score=2)
    d, record = project_legacy_dict(report), project_hunter_record(report)
    assert d["score"] == record.score == 2
    assert d["verdict_level"] == record.verdict_level == "high"
    assert d["confidence"] == record.confidence == "high"
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "HIGH CONFIDENCE HOLLOWING" in text


def test_single_lead_state_is_never_detected_and_says_so():
    report = _single_lead_report()
    assert report.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert report.score == 0
    assert report.lead_count == 1
    assert report.review_priority == "medium"
    d = project_legacy_dict(report)
    assert d["verdict_level"] == "clean"
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "CLEAN — no correlated hollowing indicators" in text
    assert "1 lead(s) found above" in text
    assert "HOLLOWING —" not in text.split("KEY SIGNALS")[0].replace(
        "no correlated hollowing indicators", "")


def test_clean_state_is_not_detected_in_scanned_scope():
    report = _clean_report()
    assert report.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    d, record = project_legacy_dict(report), project_hunter_record(report)
    assert d["status"] == record.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert d["coverage_status"] == "complete"
    assert d["coverage_reasons"] == []
    assert record.details.mem_private_at_base is False
    assert record.details.is_rwx_at_base is False
    assert record.details.name_mismatch is False
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "CLEAN — no correlated hollowing indicators" in text
    # COVERAGE only renders when there is a gap to report.
    assert "COVERAGE" not in text


@pytest.mark.parametrize("overrides, expected_reason, null_field", [
    pytest.param(dict(image_base_region_found=False),
                 "Image base page not captured in this dump", "mem_private_at_base",
                 id="image-base-page-not-captured"),
    pytest.param(dict(mz_read_failed=True),
                 "Image base MZ header could not be read", "mz_header_present",
                 id="header-read-failed"),
    pytest.param(dict(modules_available=False),
                 "ModuleListStream missing/empty from this dump", "name_mismatch",
                 id="module-list-missing"),
])
def test_every_distinct_coverage_gap_is_reported_once_and_nulls_its_own_field(
        overrides, expected_reason, null_field):
    """A check that never ran must be `null` in the typed record -- a
    default `False` would report an unexamined image base as a clean one --
    AND must surface exactly once as a coverage reason plus a real,
    structured limitation."""
    coverage = _coverage(**overrides)
    context = _context()
    if not coverage.image_base_region_found:
        context = _context(region=None, region_file_offset=None)
    if coverage.mz_read_failed:
        context = _context(header=_header(outcome=OUTCOME_SHORT_READ, header_bytes=b"M"))
    report = HollowingReport(score=0, coverage=coverage, context=context, results=(),
                              evidence=HollowingEvidence())

    status, reasons = project_coverage_v1(coverage)
    assert status == "partial"
    assert sum(1 for r in reasons if expected_reason in r) == 1, reasons
    assert report.status == "INCONCLUSIVE"

    record = project_hunter_record(report)
    assert record.coverage.status.value == "partial"
    assert record.coverage.limitations
    assert getattr(record.details, null_field) is None

    text = "\n".join(render_console_lines(report, verbose=False))
    assert "COVERAGE" in text and "PARTIAL" in text
    assert text.count(expected_reason) == 1


def test_partial_state_is_inconclusive_never_clean():
    report = _partial_report()
    assert report.status == "INCONCLUSIVE"
    d = project_legacy_dict(report)
    assert d["coverage_status"] == "partial"
    assert d["verdict_level"] == "inconclusive"
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "INCONCLUSIVE — partial coverage" in text
    assert "CLEAN" not in text
    # A short, wrap-safe anchor: the impact line legitimately wraps at the
    # console width, so a literal count() of the whole sentence would be a
    # false negative rather than a real absence.
    assert "At least one anchor/corroborator never ran" in text


def test_not_evaluated_state_never_implies_clean():
    report = _not_evaluated_report()
    assert report.status == "NOT_EVALUATED"
    d, record = project_legacy_dict(report), project_hunter_record(report)
    assert d["coverage_status"] == "not_evaluated"
    assert d["coverage_reasons"] == ["PEB stream missing from this dump"]
    assert record.coverage.status.value == "not_evaluated"
    assert any(l.code.value == "PEB_UNAVAILABLE" for l in record.coverage.limitations)
    # Every details field is null -- there is no image base to report at all.
    assert all(v is None for v in record.details.to_dict().values())

    text = "\n".join(render_console_lines(report, verbose=False))
    assert "NOT EVALUATED — PEB stream missing from this dump" in text
    assert "CLEAN" not in text
    assert "KEY SIGNALS" not in text
    assert "WHY THIS VERDICT" not in text
    assert "so a score of 0 here is not a clean result" in text
    # No bounded image-base section either, in EITHER mode: there is no
    # image base to describe.
    assert "IMAGE BASE" not in "\n".join(render_console_lines(report, verbose=True))


def test_detection_over_partial_coverage_says_so_in_coverage():
    report = _detected_report(score=1, coverage=_coverage(modules_available=False))
    assert report.status == "DETECTED"
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "Coverage incomplete despite a detection" in text


# ── 4. Ordering / duplication / width ─────────────────────────────────────

def test_key_signals_order_puts_the_correlation_first_then_the_anchors():
    """Issue #10's console scope: structural correlation/detections precede
    MEM_PRIVATE, wiped/missing MZ, RWX, and the name mismatch. The wire
    order (construction order, correlation LAST) is unchanged."""
    report = _all_checks_report()
    d = project_legacy_dict(report)
    assert [f["check"] for f in d["findings"]] == [r.check for r in report.results]
    assert d["findings"][-1]["check"] == "hollowing.structural_correlation"

    text = strip_ansi("\n".join(render_console_lines(report, verbose=False)))
    positions = [text.index(title) for title in (
        "Correlated structural hollowing indicators",
        "MEM_PRIVATE memory at the image base",
        "Missing/wiped MZ header at the image base",
        "RWX protection at the image base",
        "PEB image name vs module list")]
    assert positions == sorted(positions)
    assert text.index("[!] DETECTION") < text.index("[~] LEAD")


def test_an_unranked_check_still_renders_after_the_ranked_ones():
    """A check added to aggregate.py without a `_DISPLAY_RANK` entry falls
    back to the shared tag ranking rather than vanishing from KEY SIGNALS."""
    from dumpex.hunt.hollowing.report_console import _ordered_for_display

    class _F:
        def __init__(self, check, tag):
            self.check, self.tag = check, tag

    ordered = _ordered_for_display([
        _F("hollowing.brand_new_check", TAG_OBSERVATION),
        _F("hollowing.structural_correlation", TAG_DETECTION),
        _F("hollowing.rwx_at_image_base", TAG_LEAD),
    ])
    assert [f.check for f in ordered] == ["hollowing.structural_correlation",
                                           "hollowing.rwx_at_image_base",
                                           "hollowing.brand_new_check"]


def test_why_this_verdict_is_driven_by_the_only_scored_check_when_present():
    report = _all_checks_report()
    text = "\n".join(render_console_lines(report, verbose=False))
    why = text.split("WHY THIS VERDICT", 1)[1]
    assert "independent structural signal(s) correlate at the same image base" in why


def test_why_this_verdict_falls_back_to_the_highest_ranked_lead():
    text = "\n".join(render_console_lines(_single_lead_report(), verbose=False))
    assert "WHY THIS VERDICT" in text
    why = text.split("WHY THIS VERDICT", 1)[1]
    assert "something was observed at the image base" in why


def test_a_report_with_no_checks_gets_no_why_this_verdict_block():
    text = "\n".join(render_console_lines(_clean_report(), verbose=False))
    assert "KEY SIGNALS" not in text
    assert "WHY THIS VERDICT" not in text


@pytest.mark.parametrize("verbose", [False, True], ids=["normal", "verbose"])
def test_each_check_is_rendered_exactly_once(verbose):
    """No hand-rendered `_print_check` status block alongside the unified
    KEY SIGNALS loop -- the pre-migration renderer printed each of the four
    checks TWICE, once as a terse status line and once as a full Finding
    narrative, in two different vocabularies."""
    report = _all_checks_report()
    text = strip_ansi("\n".join(render_console_lines(report, verbose=verbose)))
    for title in ("Correlated structural hollowing indicators",
                  "MEM_PRIVATE memory at the image base",
                  "Missing/wiped MZ header at the image base",
                  "RWX protection at the image base",
                  "PEB image name vs module list"):
        assert text.count(title) == 1, title


def test_raw_image_base_facts_are_verbose_only_and_appear_once():
    """PEB image path, VA/file offset, memory type/protection, header bytes,
    and the module comparison all live in the bounded evidence section --
    never duplicated ahead of the verdict as the pre-migration three-line
    header plus four `_print_check` Detail lines did."""
    report = _all_checks_report()
    normal = strip_ansi("\n".join(render_console_lines(report, verbose=False)))
    verbose = strip_ansi("\n".join(render_console_lines(report, verbose=True)))

    assert "PEB ImagePath" not in normal
    assert "ImageBase: VA" not in normal
    assert "MZ header:" not in normal
    assert "Module list:" not in normal

    assert verbose.count("IMAGE BASE\n") == 1
    assert verbose.count("PEB ImagePath: ") == 1
    assert verbose.count("ImageBase: VA ") == 1
    assert verbose.count("MZ header: ") == 1
    assert verbose.count("Module list: ") == 1
    assert f"0x{_IMAGE_BASE:016x}" in verbose
    assert "MISMATCH — PEB says 'legit.exe', module list says 'other.exe'" in verbose


@pytest.mark.parametrize("report_fn, expected", [
    pytest.param(lambda: _clean_report(), "MZ header: MZ present", id="clean"),
    pytest.param(lambda: HollowingReport(
        score=0, coverage=_coverage(mz_read_failed=True),
        context=_context(header=_header(outcome=OUTCOME_EXCEPTION)),
        results=(), evidence=HollowingEvidence()),
        "MZ header: could not read — simulated read failure", id="exception"),
    pytest.param(lambda: HollowingReport(
        score=0, coverage=_coverage(mz_read_failed=True),
        context=_context(header=_header(outcome=OUTCOME_SHORT_READ, header_bytes=b"M")),
        results=(), evidence=HollowingEvidence()),
        "MZ header: short read — could not check", id="short-read"),
    pytest.param(lambda: HollowingReport(
        score=0, coverage=_coverage(image_base_region_found=False),
        context=_context(region=None, region_file_offset=None),
        results=(), evidence=HollowingEvidence()),
        "Memory: image base page not captured in this dump", id="no-region"),
    pytest.param(lambda: HollowingReport(
        score=0, coverage=_coverage(modules_available=False),
        context=_context(module=None), results=(), evidence=HollowingEvidence()),
        "Module list: ModuleListStream missing/empty", id="no-module-list"),
    pytest.param(lambda: HollowingReport(
        score=0, coverage=_coverage(), context=_context(module=None),
        results=(), evidence=HollowingEvidence()),
        "Module list: image base is not inside any listed module", id="unlisted-base"),
])
def test_image_base_section_renders_every_observation_state(report_fn, expected):
    verbose = strip_ansi("\n".join(render_console_lines(report_fn(), verbose=True)))
    assert expected in verbose


def test_console_wraps_within_requested_width():
    result = _check(check="hollowing.mem_private_at_image_base", tag=TAG_LEAD,
                    confidence=CONFIDENCE_MEDIUM,
                    inference="x " * 60 + "end of a deliberately very long inference sentence "
                              "meant to force wrapping across several lines of output")
    report = HollowingReport(score=0, coverage=_coverage(), context=_context(),
                              results=(result,), evidence=HollowingEvidence())
    # Normal mode only, matching every completed pilot's own width test:
    # --verbose routes each finding through the SHARED
    # `dumpex.hunt._finding.render_finding_lines`, whose own one-line
    # `{title} [{CONF}] {TAG} ({check})` header is deliberately never
    # wrapped -- that is that module's contract, not this projector's.
    for line in render_console_lines(report, verbose=False, width=80):
        # The verdict key/value block and the fixed trailing hint are
        # deliberately never wrapped either (`render_kv_block` lays out one
        # pair per line, and the hint is non-data-dependent) -- only the
        # data-derived lines are expected to respect the requested width.
        if any(label in strip_ansi(line) for label in ("VERDICT", "Confidence  ",
                                                        "Score  ", "Coverage  ",
                                                        "Review  ")):
            continue
        if "Use --verbose" in line:
            continue
        assert len(strip_ansi(line)) <= 80, repr(line)

    # The bounded IMAGE BASE section IS this projector's own layout, and it
    # must respect the requested width in --verbose.
    for line in render_console_lines(report, verbose=True, width=80):
        stripped = strip_ansi(line)
        if not stripped.startswith("      "):
            continue
        assert len(stripped) <= 80, repr(line)


# ── 5. Purity / order-independence ────────────────────────────────────────

def test_projectors_are_order_independent_and_pure():
    report = _all_checks_report()

    legacy_first = project_legacy_dict(report)
    record_first = project_hunter_record(report)
    console_first = render_console_lines(report, verbose=False)
    verbose_first = render_console_lines(report, verbose=True)

    verbose_again = render_console_lines(report, verbose=True)
    console_again = render_console_lines(report, verbose=False)
    record_again = project_hunter_record(report)
    legacy_again = project_legacy_dict(report)

    assert legacy_first == legacy_again
    assert console_first == console_again
    assert verbose_first == verbose_again
    assert record_first.details.to_dict() == record_again.details.to_dict()
    assert record_first.findings == record_again.findings
    assert record_first.status == record_again.status

    legacy_first["findings"].append("tampered")
    legacy_first["coverage_reasons"].append("tampered")
    legacy_third = project_legacy_dict(report)
    assert "tampered" not in legacy_third["findings"]
    assert "tampered" not in legacy_third["coverage_reasons"]


def test_console_verbose_and_normal_never_change_json_projections():
    report = _all_checks_report()
    before = project_legacy_dict(report)
    render_console_lines(report, verbose=True)
    render_console_lines(report, verbose=False)
    render_console_lines(report, verbose=True)
    after = project_legacy_dict(report)
    assert before == after
    assert project_hunter_record(report).findings == project_hunter_record(report).findings


@pytest.mark.parametrize("report_fn", _ALL_REPORTS)
def test_all_three_projections_agree_on_the_verdict_fields(report_fn):
    report = report_fn()
    d, record = project_legacy_dict(report), project_hunter_record(report)
    assert (d["score"], d["max_score"], d["status"], d["verdict_level"], d["confidence"],
            d["lead_count"], d["review_priority"]) == \
        (record.score, record.max_score, record.status, record.verdict_level,
         record.confidence, record.lead_count, record.review_priority)
    assert d["findings"] == record.findings
    assert d["coverage_status"] == record.coverage.status.value


# ── 6. Exit-code parity across coverage states ────────────────────────────

def test_exit_code_complete_coverage_is_ok():
    record = project_hunter_record(_clean_report())
    assert record.coverage.status.value == "complete"
    assert exit_code_for(record.coverage.status) == EXIT_OK == 0


def test_exit_code_partial_coverage_is_partial():
    record = project_hunter_record(_partial_report())
    assert record.coverage.status.value == "partial"
    assert exit_code_for(record.coverage.status) == EXIT_PARTIAL == 3


def test_exit_code_not_evaluated_coverage_is_not_evaluated():
    record = project_hunter_record(_not_evaluated_report())
    assert record.coverage.status.value == "not_evaluated"
    assert exit_code_for(record.coverage.status) == EXIT_NOT_EVALUATED == 4


# ── 7. The "empty/error" acceptance axis ──────────────────────────────────
# `_not_evaluated_report()` (no PEB, no context, no results) stands in for
# "empty" throughout this file -- see test_injection_projectors.py's own
# docstring for why "error" (a hunt run that failed outright) is
# deliberately not representable by this domain model at all; the same
# reasoning applies unchanged to HollowingReport.

def test_hollowing_report_status_has_no_error_representation():
    from dumpex.hunt._ui import (
        DETECTED, INCONCLUSIVE, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED,
    )
    known = {DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, INCONCLUSIVE, NOT_EVALUATED}
    for report_fn in _ALL_REPORTS:
        assert report_fn().status in known

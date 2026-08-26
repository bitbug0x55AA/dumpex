"""Hunter-specific behavior for module-stomping report projectors."""
import pytest

from tests.hunt.test_stomping_domain import (
    _check, _coverage, _identity_mismatch, _ioc_hit, _module, _oversize_target,
    _parse_failed, _protection_lead, _region, _section, _thread, _token,
    _verified_change, _MODULE_BASE, _SECTION_VA,
)

from dumpex.hunt._console import strip_ansi
from dumpex.hunt._finding import (
    CONFIDENCE_HIGH, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    TAG_DETECTION, TAG_LEAD, TAG_OBSERVATION,
)
from dumpex.hunt.stomping.domain import CoverageSnapshot, StompingEvidence, StompingReport
from dumpex.hunt.stomping.models import RipCorrelatedLeadEvidence
from dumpex.hunt.stomping.report_console import render_console_lines
from dumpex.hunt.stomping.report_facts import finding_from_check_result, project_coverage_v1
from dumpex.hunt.stomping.report_legacy import project_legacy_dict
from dumpex.hunt.stomping.report_record import project_hunter_record


# ── Report builders ────────────────────────────────────────────────────────

def _detected_report(score=1, coverage=None) -> StompingReport:
    """DETECTED with a verified content change. `score=2` additionally puts
    a thread's live RIP inside one of the changed ranges."""
    change = _verified_change(rip=score == 2)
    evidence = StompingEvidence(verified_changes=(change,))
    results = (
        _check(check="stomping.protection_deviation_lead", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW,
               inference="No module section declared executable-but-not-writable shows a "
                          "live protection state outside the normal set.",
               rationale="Absence of a protection anomaly is weak evidence of absence."),
        _check(check="stomping.verified_content_change", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH if score == 2 else CONFIDENCE_MEDIUM,
               inference="1 module section(s) have relocation-normalized, byte-level content "
                          "differences from an identity-matched reference file.",
               rationale="Verified byte-level difference against an identity-matched reference.",
               limitations=["IAT/delay-import ranges are not excluded before diffing."],
               evidence=(change,), evidence_limit=15),
    )
    return StompingReport(score=score, coverage=coverage or _coverage(), results=results,
                           evidence=evidence)


def _all_checks_report() -> StompingReport:
    """Every one of the six check ids in one Report -- deliberately richer
    than any single scan `aggregate.build_report` would itself produce,
    purely to exercise every projector code path at once."""
    lead = _protection_lead()
    correlated = RipCorrelatedLeadEvidence(lead=lead, thread=_thread())
    change = _verified_change(rip=True, ranges=tuple((i * 0x40, 0x4) for i in range(7)),
                               total_ranges=25, ranges_truncated=True)
    mismatch = _identity_mismatch()
    parse_failure = _parse_failed()
    ioc = _ioc_hit(tokens=(_token(), _token(offset=0x80, va=_SECTION_VA + 0x80,
                                             token="VirtualAlloc", is_weak=True)))
    evidence = StompingEvidence(
        protection_leads=(lead,), rip_correlated_leads=(correlated,),
        verified_changes=(change,), identity_mismatches=(mismatch,),
        parse_failures=(parse_failure,), ioc_hits=(ioc,))
    results = (
        _check(check="stomping.protection_deviation_lead", tag=TAG_LEAD,
               confidence=CONFIDENCE_MEDIUM, evidence=(lead,), evidence_limit=20),
        _check(check="stomping.rip_in_anomalous_section_lead", tag=TAG_LEAD,
               confidence=CONFIDENCE_MEDIUM, evidence=(correlated,), evidence_limit=20),
        _check(check="stomping.verified_content_change", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=(change,), evidence_limit=15,
               # Distinctive wording so WHY THIS VERDICT can be proven to
               # be driven by THIS check rather than by display order.
               inference="relocation-normalized, byte-level content differences"),
        _check(check="stomping.reference_identity_mismatch", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW, evidence=(mismatch,), evidence_limit=15,
               limitations=["Coverage gap: supply a reference file matching the exact build "
                            "(Machine/SizeOfImage/TimeDateStamp) to verify these sections."]),
        _check(check="stomping.module_header_invalid", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW, evidence=(parse_failure,), evidence_limit=15,
               limitations=["These modules are excluded from both the protection-deviation "
                            "lead and the verified-content-change check."]),
        _check(check="stomping.ioc_string_lead", tag=TAG_LEAD,
               confidence=CONFIDENCE_LOW, evidence=(ioc,), evidence_limit=15),
    )
    return StompingReport(score=2, coverage=_coverage(header_parse_failed=1,
                                                       reference_mismatch=1),
                           results=results, evidence=evidence)


def _ioc_lead_only_report() -> StompingReport:
    """No scored signal at all, one unscored IOC lead, no --ref-dir --
    the "INCONCLUSIVE with leads above" shape."""
    ioc = _ioc_hit()
    evidence = StompingEvidence(ioc_hits=(ioc,))
    results = (
        _check(check="stomping.protection_deviation_lead", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW),
        _check(check="stomping.ioc_string_lead", tag=TAG_LEAD, confidence=CONFIDENCE_LOW,
               evidence=(ioc,), evidence_limit=15),
    )
    return StompingReport(score=0, coverage=_coverage(ref_dir_supplied=False,
                                                       sections_compared=0),
                           results=results, evidence=evidence)


def _clean_report() -> StompingReport:
    return StompingReport(score=0, coverage=_coverage(),
                           results=(_check(tag=TAG_OBSERVATION, confidence=CONFIDENCE_LOW),),
                           evidence=StompingEvidence())


def _inconclusive_report() -> StompingReport:
    return StompingReport(score=0, coverage=_coverage(ref_dir_supplied=False,
                                                       sections_compared=0),
                           results=(), evidence=StompingEvidence())


def _not_evaluated_report(module_list_stream=False, memory_info_stream=True) -> StompingReport:
    coverage = CoverageSnapshot(memory_info_stream=memory_info_stream,
                                 module_list_stream=module_list_stream)
    return StompingReport(score=0, coverage=coverage, results=(), evidence=StompingEvidence())


_ALL_REPORTS = [_all_checks_report, _detected_report, _ioc_lead_only_report,
                _clean_report, _inconclusive_report, _not_evaluated_report]


# ── 1. Per-projector shape tests ──────────────────────────────────────────

@pytest.mark.parametrize("report_fn", _ALL_REPORTS)
def test_projectors_do_not_raise_for_every_state(report_fn):
    report = report_fn()
    d = project_legacy_dict(report)
    record = project_hunter_record(report)
    lines = render_console_lines(report, verbose=False)
    verbose_lines = render_console_lines(report, verbose=True)
    assert isinstance(d, dict)
    assert record.hunter == "stomping"
    assert isinstance(lines, list) and all(isinstance(l, str) for l in lines)
    assert isinstance(verbose_lines, list)


def test_legacy_dict_key_set_is_unchanged():
    """The v1.1 findings dict's own key set is a frozen contract (see
    tests/integration/test_hunt_compat_freeze.py's `_STOMPING_KEYS`)."""
    d = project_legacy_dict(_all_checks_report())
    assert set(d) == {
        "protection_leads", "verified_changes", "score", "max_score", "status",
        "coverage_status", "coverage_reasons", "coverage_counts", "verdict_level",
        "confidence", "findings", "lead_count", "review_priority",
    }
    assert d["score"] == 2 and d["max_score"] == 2
    assert len(d["findings"]) == 6


def test_legacy_dict_entries_hold_no_raw_minidump_objects():
    d = project_legacy_dict(_all_checks_report())
    lead, change = d["protection_leads"][0], d["verified_changes"][0]
    assert isinstance(lead["module"], dict) and isinstance(lead["region"], dict)
    assert isinstance(lead["section"], dict)
    assert lead["region"]["Protect"] == "PAGE_EXECUTE_READWRITE"
    assert lead["va_start"] == _SECTION_VA
    assert change["module"]["base_address"] == _MODULE_BASE
    assert change["total_ranges"] == 25 and change["ranges_truncated"] is True


def test_hunter_record_details_shape_is_the_v2_wire_shape():
    record = project_hunter_record(_all_checks_report())
    details = record.details
    assert len(details.protection_leads) == 1 and len(details.verified_changes) == 1
    lead = details.protection_leads[0]
    assert lead["module"]["base_address"] == f"0x{_MODULE_BASE:016x}"
    assert lead["va_start"] == f"0x{_SECTION_VA:016x}"
    assert set(lead["section"]) == {
        "name", "virtual_address", "virtual_size", "pointer_to_raw_data",
        "size_of_raw_data", "characteristics", "is_executable", "is_writable", "is_readable"}
    change = details.verified_changes[0]
    assert change["va_start"] == f"0x{_SECTION_VA:016x}"
    assert change["diff_ranges"] == [[i * 0x40, 0x4] for i in range(7)]
    assert record.findings and all(isinstance(f, dict) for f in record.findings)


def test_console_lines_contain_expected_sections():
    lines = render_console_lines(_all_checks_report(), verbose=False)
    text = "\n".join(lines)
    assert "HUNT: Module Stomping" in text
    assert "VERDICT" in text
    assert "KEY SIGNALS" in text
    assert "WHY THIS VERDICT" in text
    assert "COVERAGE" in text


# ── 2. Fact-text parity with the pre-migration aggregate.py ───────────────

def test_fact_text_matches_the_pre_migration_wording():
    """Literal transcriptions of what the pre-migration `aggregate.py`
    produced for the same evidence -- the fact strings are embedded in BOTH
    the v1.1 dict and the typed `HunterRecord`, so they may not drift."""
    report = _all_checks_report()
    facts = {r.check: finding_from_check_result(r, report).facts for r in report.results}

    assert facts["stomping.protection_deviation_lead"] == (
        f"module=legit.dll section='.text' VA=0x{_SECTION_VA:x} "
        f"declared=PAGE_EXECUTE_READ actual=PAGE_EXECUTE_READWRITE page_type=MEM_IMAGE",)
    assert facts["stomping.rip_in_anomalous_section_lead"] == (
        f"module=legit.dll section='.text' "
        f"VA=0x{_SECTION_VA:x}-0x{_SECTION_VA + 0x2000:x} "
        f"declared=PAGE_EXECUTE_READ actual=PAGE_EXECUTE_READWRITE "
        f"TID=0x42 RIP=0x{_SECTION_VA + 0x10:x}",)
    assert facts["stomping.verified_content_change"] == (
        f"module=legit.dll section='.text' VA=0x{_SECTION_VA:x} compared=8192 bytes "
        f"changed_ranges=[+0x0(len 0x4), +0x40(len 0x4), +0x80(len 0x4), +0xc0(len 0x4), "
        f"+0x100(len 0x4), ... +2 more shown (25 total differing range(s), truncated for "
        f"display)] disk_sha256_prefix={'a' * 16}… mem_sha256_prefix={'b' * 16}…  "
        f"[LIVE RIP/EIP inside changed range]",)
    assert facts["stomping.reference_identity_mismatch"] == (
        "module=legit.dll section='.text' reason=TimeDateStamp mismatch",)
    assert facts["stomping.module_header_invalid"] == (
        f"module=legit.dll base=0x{_MODULE_BASE:x} reason=no MZ signature",)
    assert facts["stomping.ioc_string_lead"] == (
        f"module=legit.dll VA=0x{_SECTION_VA:x} terms=VirtualAlloc, mimikatz",)


def test_protection_deviation_no_anomaly_fact_comes_from_coverage_not_evidence():
    """The one check that legitimately carries no evidence: its single fact
    is rendered from the Report's own coverage snapshot."""
    report = StompingReport(score=0, coverage=_coverage(headers_parsed=7),
                             results=(_check(check="stomping.protection_deviation_lead",
                                              tag=TAG_OBSERVATION,
                                              confidence=CONFIDENCE_LOW),),
                             evidence=StompingEvidence())
    finding = finding_from_check_result(report.results[0], report)
    assert finding.facts == ("7 module(s) checked",)


def test_unknown_check_id_has_no_silent_fallback_renderer():
    report = StompingReport(score=0, coverage=_coverage(),
                             results=(_check(check="stomping.brand_new_check",
                                              evidence=()),),
                             evidence=StompingEvidence())
    with pytest.raises(ValueError, match="no fact renderer registered"):
        finding_from_check_result(report.results[0], report)


def test_ioc_hit_with_no_resolvable_module_reads_as_unknown():
    ioc = _ioc_hit(module=False)
    report = StompingReport(
        score=0, coverage=_coverage(),
        results=(_check(check="stomping.ioc_string_lead", tag=TAG_LEAD,
                        confidence=CONFIDENCE_LOW, evidence=(ioc,), evidence_limit=15),),
        evidence=StompingEvidence(ioc_hits=(ioc,)))
    assert "module=(unknown)" in finding_from_check_result(report.results[0], report).facts[0]


def test_evidence_limit_caps_facts_but_not_verbose_facts():
    from dumpex.hunt.stomping.report_console import _console_finding

    leads = tuple(_protection_lead(base=_SECTION_VA + i * 0x4000) for i in range(5))
    result = _check(check="stomping.protection_deviation_lead", tag=TAG_LEAD,
                    confidence=CONFIDENCE_MEDIUM, evidence=leads, evidence_limit=2)
    report = StompingReport(score=0, coverage=_coverage(), results=(result,),
                             evidence=StompingEvidence(protection_leads=leads))

    wire_finding = finding_from_check_result(result, report)
    assert len(wire_finding.facts) == 3
    assert wire_finding.facts[-1] == "... and 3 more"
    assert wire_finding.verbose_facts == ()

    console_finding = _console_finding(result, report)
    assert console_finding.facts == wire_finding.facts
    assert len(console_finding.verbose_facts) == 5


def test_file_offsets_are_verbose_only_console_detail_never_a_wire_fact():
    """Issue #8 asks for file offsets in bounded/verbose evidence. They
    must NOT reach `facts` -- that array is embedded verbatim in both the
    v1.1 dict and the typed `HunterRecord`, whose goldens are frozen."""
    from dumpex.hunt.stomping.report_console import _console_finding

    lead = _protection_lead(file_offset=0x3000)
    change = _verified_change(file_offset=0x4000)
    results = (
        _check(check="stomping.protection_deviation_lead", tag=TAG_LEAD,
               confidence=CONFIDENCE_MEDIUM, evidence=(lead,), evidence_limit=20),
        _check(check="stomping.verified_content_change", tag=TAG_DETECTION,
               confidence=CONFIDENCE_MEDIUM, evidence=(change,), evidence_limit=15),
    )
    report = StompingReport(score=1, coverage=_coverage(), results=results,
                             evidence=StompingEvidence(protection_leads=(lead,),
                                                        verified_changes=(change,)))

    for result in results:
        wire = finding_from_check_result(result, report)
        assert not any("File_offset" in fact for fact in wire.facts)
    lead_verbose = _console_finding(results[0], report).verbose_facts
    change_verbose = _console_finding(results[1], report).verbose_facts
    assert "File_offset=0x3000" in lead_verbose[0]
    assert "File_offset=0x4000" in change_verbose[0]
    # The full hashes (not the 16-char wire prefixes) show up too.
    assert f"disk_sha256={'a' * 64}" in change_verbose[0]

    normal = "\n".join(render_console_lines(report, verbose=False))
    verbose = "\n".join(render_console_lines(report, verbose=True))
    assert "File_offset" not in normal
    assert "File_offset=0x3000" in verbose and "File_offset=0x4000" in verbose


def test_uncaptured_file_offset_reads_as_not_captured_never_as_zero():
    from dumpex.hunt.stomping.report_console import _console_finding
    lead = _protection_lead()   # file_offset defaults to None
    assert lead.file_offset is None
    result = _check(check="stomping.protection_deviation_lead", tag=TAG_LEAD,
                    confidence=CONFIDENCE_MEDIUM, evidence=(lead,), evidence_limit=20)
    report = StompingReport(score=0, coverage=_coverage(), results=(result,),
                             evidence=StompingEvidence(protection_leads=(lead,)))
    verbose_fact = _console_finding(result, report).verbose_facts[0]
    assert "File_offset=(not captured)" in verbose_fact
    assert "File_offset=0x0" not in verbose_fact


def test_ioc_verbose_facts_expand_per_token_not_per_region():
    from dumpex.hunt.stomping.report_console import _console_finding
    report = _all_checks_report()
    result = next(r for r in report.results if r.check == "stomping.ioc_string_lead")
    verbose = _console_finding(result, report).verbose_facts
    assert len(verbose) == 2   # one region, two tokens
    assert verbose[0] == (f"module=legit.dll region=0x{_SECTION_VA:x} "
                          f"VA=0x{_SECTION_VA + 0x40:x} encoding=ASCII token=mimikatz")
    assert verbose[1].endswith("token=VirtualAlloc (weak/common API)")


# ── 3. State-matrix tests ─────────────────────────────────────────────────

def test_detected_score_1_state_matches_across_projectors():
    report = _detected_report(score=1)
    d, record = project_legacy_dict(report), project_hunter_record(report)
    assert report.status == "DETECTED"
    assert d["status"] == "DETECTED" == record.status
    assert d["score"] == record.score == 1
    assert d["verdict_level"] == record.verdict_level == "possible"
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "VERIFIED MODULE CODE MODIFICATION" in text
    assert "HIGH CONFIDENCE STOMPING" not in text


def test_detected_score_2_state_matches_across_projectors():
    report = _detected_report(score=2)
    d, record = project_legacy_dict(report), project_hunter_record(report)
    assert d["score"] == record.score == 2
    assert d["verdict_level"] == record.verdict_level == "high"
    assert d["verified_changes"][0]["rip_in_changed_range"] is True
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "HIGH CONFIDENCE STOMPING" in text


def test_ioc_lead_only_state_is_inconclusive_with_a_leads_suffix():
    report = _ioc_lead_only_report()
    assert report.status == "INCONCLUSIVE"
    assert report.lead_count == 1
    assert report.review_priority == "low"
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "INCONCLUSIVE" in text
    assert "1 lead(s) found above" in text
    assert "CLEAN" not in text


def test_clean_state_is_not_detected_in_scanned_scope():
    report = _clean_report()
    assert report.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    d, record = project_legacy_dict(report), project_hunter_record(report)
    assert d["status"] == record.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert d["coverage_status"] == "complete"
    assert d["coverage_reasons"] == []
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "CLEAN — no verified stomping indicators" in text
    # COVERAGE only renders when there is a gap to report.
    assert "COVERAGE" not in text


def test_inconclusive_state_names_the_missing_reference_directory():
    report = _inconclusive_report()
    assert report.status == "INCONCLUSIVE"
    d = project_legacy_dict(report)
    assert d["coverage_status"] == "partial"
    assert any("--ref-dir not supplied" in r for r in d["coverage_reasons"])
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "INCONCLUSIVE" in text and "COVERAGE" in text


@pytest.mark.parametrize("streams, expected_reason", [
    (dict(memory_info_stream=False, module_list_stream=True),
     "MemoryInfoListStream missing from this dump"),
    (dict(memory_info_stream=True, module_list_stream=False),
     "ModuleListStream missing from this dump"),
    (dict(memory_info_stream=False, module_list_stream=False),
     "MemoryInfoListStream missing from this dump"),
])
def test_not_evaluated_state_never_implies_clean(streams, expected_reason):
    report = _not_evaluated_report(**streams)
    assert report.status == "NOT_EVALUATED"
    d = project_legacy_dict(report)
    assert d["status"] == "NOT_EVALUATED"
    assert d["coverage_status"] == "not_evaluated"
    assert expected_reason in d["coverage_reasons"]
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "NOT EVALUATED" in text
    assert "CLEAN" not in text
    assert "KEY SIGNALS" not in text
    assert "WHY THIS VERDICT" not in text


# ── 4. Partial-coverage reason matrix ─────────────────────────────────────

_GAP_REASONS = [
    (dict(header_read_failed=1), "1 module header read(s) failed"),
    (dict(header_parse_failed=1),
     "1 module header(s) failed PE structural validation"),
    (dict(ref_dir_supplied=False, sections_compared=0), "--ref-dir not supplied"),
    (dict(reference_missing=1), "1 section(s) had no matching reference file under --ref-dir"),
    (dict(reference_mismatch=1),
     "1 section(s) had a reference file whose build identity didn't match"),
    (dict(reference_read_failed=1), "1 reference file(s) could not be read"),
    (dict(memory_read_failed=1), "1 section(s) could not be read from memory"),
    (dict(short_reads=1), "1 section(s) had nothing comparable to read"),
    (dict(relocation_failed=1), "1 section(s) needed relocation normalization"),
    (dict(ioc_read_failed=1),
     "1 region(s) failed to read and were not scanned for IOC strings"),
    (dict(ioc_short_reads=1), "1 region(s) returned fewer bytes than declared"),
]


@pytest.mark.parametrize("overrides, expected", _GAP_REASONS,
                         ids=[sorted(o)[0] for o, _ in _GAP_REASONS])
def test_every_distinct_coverage_gap_reason_is_reported_once(overrides, expected):
    coverage = _coverage(**overrides)
    _, status, reasons = project_coverage_v1(coverage)
    assert status == "partial"
    assert sum(1 for r in reasons if expected in r) == 1, reasons
    report = StompingReport(score=0, coverage=coverage, results=(),
                             evidence=StompingEvidence())
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "COVERAGE" in text and "PARTIAL" in text
    # The same gap must also reach the typed record as a real, structured
    # limitation -- the v1.1 reason text and the CoverageReport are two
    # projections of the SAME snapshot and may never disagree about
    # whether coverage was complete.
    record = project_hunter_record(report)
    assert record.coverage.status.value == "partial"
    assert record.coverage.limitations


def test_oversized_ioc_region_names_the_address_and_the_cap():
    coverage = _coverage(ioc_oversized=(_oversize_target(),))
    _, status, reasons = project_coverage_v1(coverage)
    assert status == "partial"
    reason = next(r for r in reasons if "never scanned for IOC strings" in r)
    assert "0x00007ff600100000" in reason and "6 MB > 5 MB limit" in reason
    record = project_hunter_record(
        StompingReport(score=0, coverage=coverage, results=(),
                       evidence=StompingEvidence()))
    limitation = next(l for l in record.coverage.limitations
                      if l.code.value == "SCAN_REGION_OVERSIZED_SKIPPED")
    assert limitation.source == "ioc_string_scan"
    assert limitation.targets[0].base_address == 0x7ff600100000


def test_ioc_gap_survives_a_not_evaluated_module_list():
    """The documented exception: the hunter is NOT_EVALUATED, but the IOC
    sub-scan's own gap is still surfaced as a limitation rather than
    dropped by build_coverage_report()'s group-absent short-circuit."""
    coverage = _coverage(module_list_stream=False, ioc_oversized=(_oversize_target(),))
    report = StompingReport(score=0, coverage=coverage, results=(),
                             evidence=StompingEvidence())
    assert report.status == "NOT_EVALUATED"
    record = project_hunter_record(report)
    assert record.coverage.status.value == "not_evaluated"
    assert any(l.code.value == "SCAN_REGION_OVERSIZED_SKIPPED"
               for l in record.coverage.limitations)


def test_coverage_impacts_are_rendered_for_an_ioc_gap_and_for_a_partial_detection():
    ioc_gap = _coverage(ioc_oversized=(_oversize_target(),))
    text = "\n".join(render_console_lines(
        StompingReport(score=0, coverage=ioc_gap, results=(), evidence=StompingEvidence())))
    assert "--extract" in text and "--strings" in text

    detected_partial = _detected_report(score=1, coverage=ioc_gap)
    detected_text = "\n".join(render_console_lines(detected_partial, verbose=False))
    assert detected_partial.status == "DETECTED"
    assert "Coverage incomplete despite a detection" in detected_text


def test_whitelisted_modules_are_verbose_only_scan_detail_never_a_coverage_gap():
    coverage = _coverage(ioc_whitelisted_modules=("wininet.dll", "ws2_32.dll"))
    report = StompingReport(score=0, coverage=coverage, results=(),
                             evidence=StompingEvidence())
    assert coverage.status == "complete"
    _, _, reasons = project_coverage_v1(coverage)
    assert not any("wininet" in r for r in reasons)
    normal = "\n".join(render_console_lines(report, verbose=False))
    verbose = "\n".join(render_console_lines(report, verbose=True))
    assert "wininet.dll" not in normal
    assert "Whitelisted network DLLs skipped" in verbose and "wininet.dll" in verbose


# ── 5. Ordering / duplication / width ─────────────────────────────────────

def test_console_groups_detection_before_lead_before_context_but_findings_stay_in_order():
    report = _all_checks_report()
    d = project_legacy_dict(report)
    assert [f["check"] for f in d["findings"]] == [r.check for r in report.results]

    text = "\n".join(render_console_lines(report, verbose=False))
    detection_pos = text.index("[!] DETECTION")
    lead_pos = text.index("[~] LEAD")
    assert detection_pos < lead_pos
    # Stable order WITHIN a class: protection_deviation_lead was
    # constructed before rip_in_anomalous_section_lead.
    assert text.index("Section protection deviation") < \
        text.index("Live RIP/EIP inside an anomalously-protected")
    # _all_checks_report()'s only two OBSERVATION-tagged checks
    # (reference_identity_mismatch/module_header_invalid) are both
    # coverage-only -- see test_coverage_only_checks_excluded_from_key_
    # signals -- so no "[i] CONTEXT" entry reaches KEY SIGNALS here at all.
    assert "[i] CONTEXT" not in text


def test_a_genuine_context_observation_sorts_after_detection_and_lead():
    """Unlike the two coverage-only checks, `stomping.protection_deviation_
    lead`'s "no anomaly anywhere" form is a genuine CONTEXT signal (see
    aggregate.py) and DOES reach KEY SIGNALS -- proving CONTEXT still sorts
    last among checks that are actually eligible."""
    change = _verified_change(rip=True)
    ioc = _ioc_hit()
    evidence = StompingEvidence(verified_changes=(change,), ioc_hits=(ioc,))
    results = (
        _check(check="stomping.protection_deviation_lead", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW,
               inference="No module section declared executable-but-not-writable shows a "
                          "live protection state outside the normal set."),
        _check(check="stomping.verified_content_change", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=(change,), evidence_limit=15),
        _check(check="stomping.ioc_string_lead", tag=TAG_LEAD, confidence=CONFIDENCE_LOW,
               evidence=(ioc,), evidence_limit=15),
    )
    report = StompingReport(score=2, coverage=_coverage(), results=results, evidence=evidence)
    text = "\n".join(render_console_lines(report, verbose=False))
    detection_pos = text.index("[!] DETECTION")
    lead_pos = text.index("[~] LEAD")
    context_pos = text.index("[i] CONTEXT")
    assert detection_pos < lead_pos < context_pos


def test_coverage_only_checks_excluded_from_key_signals_but_surfaced_in_coverage():
    """Per issue #1's contract: coverage-only findings never appear in KEY
    SIGNALS or WHY THIS VERDICT. `stomping.reference_identity_mismatch`/
    `stomping.module_header_invalid` are pure coverage-gap admissions, not
    signals about content -- they must still be visible somewhere, just not
    there: once, as a COVERAGE impact in NORMAL mode (no bounded evidence
    section exists there to carry the guidance instead), and with full
    per-item detail in a dedicated --verbose-only section that comes BEFORE
    COVERAGE (issue #1's hierarchy: an optional bounded hunter-specific
    evidence section is item 5, the unified COVERAGE section is item 6)."""
    report = _all_checks_report()

    normal = "\n".join(render_console_lines(report, verbose=False))
    key_signals_block = normal.split("KEY SIGNALS", 1)[1].split("COVERAGE", 1)[0]
    assert "Reference build identity mismatch" not in key_signals_block
    assert "Module PE header failed validation" not in key_signals_block
    coverage_block = normal.split("COVERAGE", 1)[1]
    assert "supply a reference file matching the exact build" in coverage_block
    assert "excluded from both the protection-deviation lead" in coverage_block

    verbose = "\n".join(render_console_lines(report, verbose=True))
    assert "COVERAGE-GAP DETAIL" in verbose
    # Ordering: the bounded evidence section precedes COVERAGE. Anchored on
    # stripped text so ANSI bold codes around each bare heading don't
    # interfere, and specifically on "\n  COVERAGE\n" (not just
    # "COVERAGE") so the real COVERAGE heading isn't confused with
    # "COVERAGE-GAP DETAIL"'s own leading "COVERAGE" substring.
    stripped = strip_ansi(verbose)
    assert stripped.index("COVERAGE-GAP DETAIL") < stripped.index("\n  COVERAGE\n")
    detail_block = verbose.split("COVERAGE-GAP DETAIL", 1)[1]
    assert "Reference build identity mismatch" in detail_block
    assert "Module PE header failed validation" in detail_block
    # No double-guidance: each coverage-only Finding's own limitation text
    # is fully rendered once inside COVERAGE-GAP DETAIL (as part of that
    # Finding's own Limitations block) -- COVERAGE itself must not ALSO
    # carry it as an Impact: line in --verbose mode.
    assert verbose.count("supply a reference file matching the exact build") == 1
    assert verbose.count("excluded from both the protection-deviation lead") == 1


def test_not_evaluated_with_a_real_ioc_lead_shows_the_lead_but_not_why():
    """Stomping's evaluation gate is asymmetric: the unscored IOC sub-scan
    only needs MemoryInfoListStream, so it can fire real evidence while the
    scored path is NOT_EVALUATED for a missing ModuleListStream (see
    domain.CoverageSnapshot.evaluated). The lead is still worth showing in
    KEY SIGNALS, but WHY THIS VERDICT must not use it to "explain" a
    NOT_EVALUATED verdict that has nothing to do with it."""
    ioc = _ioc_hit()
    evidence = StompingEvidence(ioc_hits=(ioc,))
    results = (_check(check="stomping.ioc_string_lead", tag=TAG_LEAD,
                       confidence=CONFIDENCE_LOW, evidence=(ioc,), evidence_limit=15),)
    coverage = CoverageSnapshot(memory_info_stream=True, module_list_stream=False)
    report = StompingReport(score=0, coverage=coverage, results=results, evidence=evidence)
    assert report.status == "NOT_EVALUATED"

    text = "\n".join(render_console_lines(report, verbose=False))
    assert "IOC strings in module code regions" in text.split("KEY SIGNALS", 1)[1]
    assert "WHY THIS VERDICT" not in text


def test_why_this_verdict_is_driven_by_the_only_scored_check_when_present():
    report = _all_checks_report()
    text = "\n".join(render_console_lines(report, verbose=False))
    why = text.split("WHY THIS VERDICT", 1)[1]
    assert "relocation-normalized, byte-level content differences" in why.split("COVERAGE")[0]


def test_why_this_verdict_falls_back_to_the_highest_ranked_lead():
    report = _ioc_lead_only_report()
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "WHY THIS VERDICT" in text
    why = text.split("WHY THIS VERDICT", 1)[1]
    assert "IOC-keyword token(s)" in why or "something was observed" in why


def test_a_context_only_report_gets_no_why_this_verdict_block():
    text = "\n".join(render_console_lines(_clean_report(), verbose=False))
    assert "KEY SIGNALS" in text
    assert "WHY THIS VERDICT" not in text


@pytest.mark.parametrize("verbose", [False, True], ids=["normal", "verbose"])
def test_each_check_is_rendered_exactly_once(verbose):
    """No hand-rendered summary alongside the unified KEY SIGNALS loop --
    the duplicate-print bug tests/hunt/test_stomping.py's own
    `test_ioc_lead_finding_printed_exactly_once` guards end to end.

    The two coverage-only titles are handled separately: excluded from KEY
    SIGNALS entirely (see test_coverage_only_checks_excluded_from_key_
    signals), so they appear zero times in NORMAL mode and exactly once
    (in COVERAGE-GAP DETAIL) in VERBOSE mode."""
    report = _all_checks_report()
    text = "\n".join(render_console_lines(report, verbose=verbose))
    for title in ("Section protection deviation", "Verified module code modification",
                  "IOC strings in module code regions"):
        assert text.count(title) == 1, title
    for title in ("Reference build identity mismatch", "Module PE header failed validation"):
        assert text.count(title) == (1 if verbose else 0), title


def test_ioc_coverage_gap_reason_appears_exactly_once_in_verbose():
    """aggregate.py embeds `CoverageSnapshot.ioc_gap_reasons()` into
    `stomping.ioc_string_lead`'s own `limitations` (so --json's
    findings[].limitations carries them) -- report_console.py must strip
    that console-side duplicate before --verbose prints the Finding's own
    Limitations block, since the SAME text is also, always, rendered once
    in the unified COVERAGE section."""
    target = _oversize_target()
    ioc = _ioc_hit()
    evidence = StompingEvidence(ioc_hits=(ioc,))
    coverage = _coverage(ioc_oversized=(target,))
    # The exact limitation text aggregate.py itself builds (see its own
    # "Coverage gap — {reason}." formatting) -- derived from the SAME
    # `ioc_gap_reasons()` the COVERAGE section renders from, so this test
    # can't drift from either producer's own wording.
    gap_reason_text = coverage.ioc_gap_reasons()[0]
    results = (_check(
        check="stomping.ioc_string_lead", tag=TAG_LEAD, confidence=CONFIDENCE_LOW,
        evidence=(ioc,), evidence_limit=15,
        limitations=["Not corroborated by any structural (section/protection) evidence "
                     "on its own.", f"Coverage gap — {gap_reason_text}."]),)
    report = StompingReport(score=0, coverage=coverage, results=results, evidence=evidence)

    verbose = "\n".join(render_console_lines(report, verbose=True))
    key_signals_block = verbose.split("KEY SIGNALS", 1)[1].split("COVERAGE", 1)[0]
    coverage_block = verbose.split("COVERAGE", 1)[1]
    # A short, wrap-safe anchor (the full reason line legitimately wraps at
    # the requested console width, so a literal count() of the whole
    # sentence would be a false negative, not a real absence).
    anchor = "never scanned for IOC strings"
    assert "Coverage gap —" not in key_signals_block
    assert anchor not in key_signals_block
    assert verbose.count(anchor) == 1
    assert anchor in coverage_block


def test_console_wraps_within_requested_width():
    result = _check(check="stomping.protection_deviation_lead", tag=TAG_LEAD,
                    confidence=CONFIDENCE_MEDIUM,
                    inference="x " * 60 + "end of a deliberately very long inference sentence "
                                "meant to force wrapping across several lines of output")
    report = StompingReport(score=0, coverage=_coverage(), results=(result,),
                             evidence=StompingEvidence())
    lines = render_console_lines(report, verbose=False, width=80)
    for line in lines:
        # The verdict key/value block and the fixed trailing hint are
        # deliberately never wrapped (mirrors both completed pilots:
        # `render_kv_block` lays out one pair per line, and the hint is
        # non-data-dependent) -- only the data-derived lines are expected
        # to respect the requested width.
        if any(label in strip_ansi(line) for label in ("VERDICT", "Confidence  ", "Score  ",
                                                        "Coverage  ", "Review  ")):
            continue
        if "Use --verbose" in line:
            continue
        assert len(strip_ansi(line)) <= 80, repr(line)


# ── 6. Purity / order-independence ────────────────────────────────────────

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

    legacy_first["protection_leads"].append("tampered")
    legacy_first["findings"].append("tampered")
    legacy_first["coverage_counts"]["headers_parsed"] = 999
    legacy_third = project_legacy_dict(report)
    assert "tampered" not in legacy_third["protection_leads"]
    assert "tampered" not in legacy_third["findings"]
    assert legacy_third["coverage_counts"]["headers_parsed"] == 1


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




# ── 8. The "empty/error" acceptance axis ──────────────────────────────────
# `_not_evaluated_report()` (both required streams absent, no results)
# stands in for "empty" throughout this file -- see
# test_injection_projectors.py's own docstring for why "error" (a hunt run
# that failed outright) is deliberately not representable by this domain
# model at all; the same reasoning applies unchanged to StompingReport.

def test_stomping_report_status_has_no_error_representation():
    from dumpex.hunt._ui import DETECTED, INCONCLUSIVE, NOT_DETECTED_IN_SCANNED_SCOPE, \
        NOT_EVALUATED
    known = {DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, INCONCLUSIVE, NOT_EVALUATED}
    for report_fn in _ALL_REPORTS:
        assert report_fn().status in known

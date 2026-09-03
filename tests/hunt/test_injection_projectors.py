"""Hunter-specific behavior for injection report projectors."""
import pytest

from tests.hunt.test_injection_domain import (
    _region, _location, _rwx, _pe_hit, _thread, _coverage, _check, _correlation_for,
)

from dumpex.hunt._finding import (
    CONFIDENCE_HIGH, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    TAG_DETECTION, TAG_LEAD, TAG_OBSERVATION, Finding,
)
from dumpex.hunt._location import Location
from dumpex.hunt.injection.domain import CoverageSnapshot, InjectionEvidence, InjectionReport
from dumpex.hunt.injection.models import (
    Correlation, CorrelatedAllocationEvidence, HiddenPeEvidence, PeHeaderInfo, RegionRef,
    RipHitEvidence, RwxRegionEvidence, StartHitEvidence, ThreadContext, UnbackedThreadEvidence,
)
from dumpex.hunt.injection.report_facts import (
    finding_from_check_result, project_coverage_report, project_coverage_v1,
)
from dumpex.hunt.injection.report_legacy import project_legacy_dict
from dumpex.hunt.injection.report_record import project_hunter_record
from dumpex.hunt.injection.report_console import render_console_lines, print_console
from dumpex.output.coverage import (
    EXIT_PARTIAL, ScanTarget, ScanTargetKind, SourceState, exit_code_for,
)


# ── Report builders ────────────────────────────────────────────────────────

_ALLOC = 0x7ffe30000000


def _full_report() -> InjectionReport:
    """DETECTED, complete coverage, covers 6 of the 8 check ids in one
    Report -- rwx / hidden_pe_validated (suspicious) / hidden_pe_validated_
    context_only (informational) / mz_prefix_unvalidated / unbacked_thread_
    startaddress / allocation_correlation / structural_allocation_
    correlation. Not a scenario `aggregate.build_report` would itself ever
    produce (structural_allocation_correlation and a full RIP correlation
    don't co-occur there) -- deliberately richer, purely to exercise every
    projector code path in one Report."""
    rwx_ev = _rwx(_ALLOC)
    pe_suspicious = _pe_hit(_ALLOC + 0x1000, alloc=_ALLOC)
    pe_informational = _pe_hit(_ALLOC + 0x9000, alloc=_ALLOC + 0x8000)
    mz_only = HiddenPeEvidence(
        region=_region(_ALLOC + 0x20000, "PAGE_READWRITE"),
        pe=PeHeaderInfo(valid=False, machine_name=None, is_pe32_plus=None,
                        number_of_sections=None, address_of_entry_point=None,
                        image_base=None, reason="bad DOS signature"),
        in_module_list=False, location=_location(_ALLOC + 0x20000))
    thread_ev = _thread(tid=0x2, start=_ALLOC + 0x30000)
    thread_ctx = ThreadContext(thread_id=0x1, ip=_ALLOC + 0x1000, ip_reg="RIP", is_wow64=False)
    rip_hit = RipHitEvidence(thread_id=0x1, ip=_ALLOC + 0x1000, ip_reg="RIP",
                              region=pe_suspicious.region)

    correlation = Correlation(
        rwx_by_alloc={_ALLOC: [rwx_ev.region]},
        pe_by_alloc={_ALLOC: [pe_suspicious.region], _ALLOC + 0x8000: [pe_informational.region]},
        rwx_and_pe_alloc_bases={_ALLOC},
        suspicious_alloc_bases={_ALLOC, _ALLOC + 0x8000},
        rip_hits=[rip_hit],
        rip_full_correlation=[rip_hit],
        start_hits=[],
    )
    evidence = InjectionEvidence(
        rwx=[rwx_ev],
        validated_pe_hits=[pe_suspicious, pe_informational],
        mz_only_hits=[mz_only],
        suspicious_pe_hits=[pe_suspicious],
        informational_pe_hits=[pe_informational],
        start_threads=[thread_ev],
        thread_contexts=[thread_ctx],
        correlated_allocations=[CorrelatedAllocationEvidence(
            allocation_base=_ALLOC, regions=[rwx_ev.region, pe_suspicious.region])],
        correlation=correlation,
    )
    results = (
        _check(check="injection.rwx_regions", tag=TAG_LEAD, confidence=CONFIDENCE_MEDIUM,
               evidence=evidence.rwx, evidence_limit=20),
        _check(check="injection.hidden_pe_validated", tag=TAG_LEAD, confidence=CONFIDENCE_MEDIUM,
               evidence=evidence.suspicious_pe_hits, evidence_limit=20),
        _check(check="injection.hidden_pe_validated_context_only", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW, evidence=evidence.informational_pe_hits,
               evidence_limit=20),
        _check(check="injection.mz_prefix_unvalidated", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW, evidence=evidence.mz_only_hits, evidence_limit=10),
        _check(check="injection.unbacked_thread_startaddress", tag=TAG_LEAD,
               confidence=CONFIDENCE_LOW, evidence=evidence.start_threads, evidence_limit=20),
        _check(check="injection.allocation_correlation", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=evidence.correlation.rip_hits,
               evidence_limit=20),
        _check(check="injection.structural_allocation_correlation", tag=TAG_LEAD,
               confidence=CONFIDENCE_MEDIUM, evidence=evidence.correlated_allocations),
    )
    return InjectionReport(score=3, coverage=_coverage(), results=results, evidence=evidence)


def _coverage_gap_report() -> InjectionReport:
    """DETECTED (score=1, rwx-only), but thread_context is entirely
    absent -- exercises `injection.rip_correlation_unavailable` (the one
    coverage-only check, no evidence) plus a genuinely partial
    coverage_status alongside a nonzero score."""
    rwx_ev = _rwx(_ALLOC + 0x40000)
    evidence = InjectionEvidence(rwx=[rwx_ev], correlation=_correlation_for(rwx=[rwx_ev]))
    coverage = CoverageSnapshot(memory_info_stream=True, thread_info_stream=True,
                                 module_list_stream=True, thread_list_stream=True,
                                 threads_total=1, contexts_parsed=0,
                                 region_count=1, thread_info_count=1, module_count=1)
    results = (
        _check(check="injection.rwx_regions", tag=TAG_LEAD, confidence=CONFIDENCE_MEDIUM,
               evidence=evidence.rwx, evidence_limit=20),
        _check(check="injection.rip_correlation_unavailable", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW, evidence=(),
               limitations=["Injection score cannot reach HIGH (3) in this run regardless "
                            "of other signals, since live-execution confirmation is the "
                            "only path to that tier."]),
    )
    return InjectionReport(score=1, coverage=coverage, results=results, evidence=evidence)


def _clean_report() -> InjectionReport:
    """NOT_DETECTED_IN_SCANNED_SCOPE -- ran to completion, nothing found."""
    return InjectionReport(score=0, coverage=_coverage(), results=(), evidence=InjectionEvidence())


def _inconclusive_report() -> InjectionReport:
    """INCONCLUSIVE -- ran, score 0, but coverage did not come out
    complete (ModuleListStream absent)."""
    coverage = CoverageSnapshot(memory_info_stream=True, thread_info_stream=True,
                                 module_list_stream=False, thread_list_stream=True,
                                 threads_total=1, contexts_parsed=1,
                                 region_count=1, thread_info_count=1)
    return InjectionReport(score=0, coverage=coverage, results=(), evidence=InjectionEvidence())


def _not_evaluated_report() -> InjectionReport:
    """NOT_EVALUATED -- no required stream present at all; also this
    module's stand-in for "empty" (default InjectionEvidence, no
    results)."""
    coverage = CoverageSnapshot(memory_info_stream=False, thread_info_stream=False,
                                 module_list_stream=False, thread_list_stream=False)
    return InjectionReport(score=0, coverage=coverage, results=(), evidence=InjectionEvidence())


# ── 1. Per-projector shape tests ──────────────────────────────────────────

@pytest.mark.parametrize("report_fn", [_full_report, _coverage_gap_report, _clean_report,
                                        _inconclusive_report, _not_evaluated_report])
def test_projectors_do_not_raise_for_every_state(report_fn):
    report = report_fn()
    d = project_legacy_dict(report)
    record = project_hunter_record(report)
    lines = render_console_lines(report, verbose=False)
    verbose_lines = render_console_lines(report, verbose=True)
    assert isinstance(d, dict)
    assert record.hunter == "injection"
    assert isinstance(lines, list) and all(isinstance(l, str) for l in lines)
    assert isinstance(verbose_lines, list)


def test_legacy_dict_has_every_v1_key():
    d = project_legacy_dict(_full_report())
    expected_keys = {
        "rwx", "hidden_pe_validated", "hidden_pe_unvalidated", "suspicious_validated_pe_hits",
        "informational_validated_pe_hits", "threads", "thread_contexts",
        "rwx_and_pe_alloc_bases", "rip_hits", "rip_full_correlation", "start_hits",
        "score", "max_score", "status", "coverage", "coverage_status", "coverage_reasons",
        "confidence", "verdict_level", "pe_read_failed", "pe_short_reads", "findings",
        "lead_count", "review_priority",
    }
    assert expected_keys <= set(d)
    assert d["score"] == 3 and d["max_score"] == 3
    assert len(d["findings"]) == 7
    assert d["rwx"][0]["base_address"] == _ALLOC


def test_hunter_record_details_shape():
    record = project_hunter_record(_full_report())
    details = record.details
    assert len(details.rwx) == 1
    assert len(details.hidden_pe_validated) == 2
    assert len(details.informational_validated_pe_hits) == 1
    assert len(details.hidden_pe_unvalidated) == 1
    assert len(details.threads) == 1
    assert len(details.thread_contexts) == 1
    assert len(details.rip_hits) == 1
    assert len(details.rip_full_correlation) == 1
    assert record.findings and all(isinstance(f, dict) for f in record.findings)


def test_console_lines_contain_expected_sections():
    lines = render_console_lines(_full_report(), verbose=False)
    text = "\n".join(lines)
    assert "HUNT: Process Injection" in text
    assert "VERDICT" in text
    assert "KEY SIGNALS" in text
    assert "WHY THIS VERDICT" in text


# ── 2. State-matrix tests ─────────────────────────────────────────────────

def test_detected_state_matches_across_projectors():
    report = _full_report()
    d = project_legacy_dict(report)
    record = project_hunter_record(report)
    assert report.status == "DETECTED"
    assert d["status"] == "DETECTED" == record.status
    assert d["score"] == record.score == 3
    assert d["verdict_level"] == record.verdict_level == "high"


def test_clean_state_is_not_detected_in_scanned_scope():
    report = _clean_report()
    assert report.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    d = project_legacy_dict(report)
    record = project_hunter_record(report)
    assert d["status"] == record.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert d["coverage_status"] == "complete"
    assert d["findings"] == [] and record.findings == []
    lines = render_console_lines(report, verbose=False)
    assert any("CLEAN" in l for l in lines)


def test_inconclusive_state():
    report = _inconclusive_report()
    assert report.status == "INCONCLUSIVE"
    d = project_legacy_dict(report)
    assert d["coverage_status"] == "partial"
    assert "ModuleListStream missing from this dump" in d["coverage_reasons"]
    lines = render_console_lines(report, verbose=False)
    assert any("INCONCLUSIVE" in l for l in lines)


def test_not_evaluated_state_never_implies_clean_or_shows_empty_sections():
    report = _not_evaluated_report()
    assert report.status == "NOT_EVALUATED"
    d = project_legacy_dict(report)
    assert d["status"] == "NOT_EVALUATED"
    lines = render_console_lines(report, verbose=False)
    text = "\n".join(lines)
    assert "NOT EVALUATED" in text
    assert "CLEAN" not in text
    assert "KEY SIGNALS" not in text
    assert "WHY THIS VERDICT" not in text


def test_coverage_gap_report_excludes_coverage_only_check_from_key_signals():
    report = _coverage_gap_report()
    lines = render_console_lines(report, verbose=False)
    text = "\n".join(lines)
    assert "RIP/EIP correlation unavailable" not in text
    assert "RWX memory" in text
    assert "Impact:" in text
    d = project_legacy_dict(report)
    checks = {f["check"] for f in d["findings"]}
    assert "injection.rip_correlation_unavailable" in checks
    assert "injection.rwx_regions" in checks


# ── 3. Ordering / truncation / width tests ────────────────────────────────

def test_console_groups_detection_before_lead_before_context_but_findings_stay_in_construction_order():
    rwx_ev = _rwx(_ALLOC + 0x50000)
    thread_ev = _thread(tid=0x3, start=_ALLOC + 0x60000)
    results = (
        _check(check="injection.hidden_pe_validated_context_only", tag=TAG_OBSERVATION,
               confidence=CONFIDENCE_LOW, evidence=()),
        _check(check="injection.unbacked_thread_startaddress", tag=TAG_LEAD,
               confidence=CONFIDENCE_LOW, evidence=(thread_ev,), evidence_limit=20),
        _check(check="injection.allocation_correlation", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=()),
        _check(check="injection.rwx_regions", tag=TAG_LEAD, confidence=CONFIDENCE_MEDIUM,
               evidence=(rwx_ev,), evidence_limit=20),
    )
    evidence = InjectionEvidence(rwx=[rwx_ev], start_threads=[thread_ev],
                                  correlation=_correlation_for(rwx=[rwx_ev]))
    report = InjectionReport(score=2, coverage=_coverage(), results=results, evidence=evidence)

    d = project_legacy_dict(report)
    assert [f["check"] for f in d["findings"]] == [r.check for r in results]

    lines = render_console_lines(report, verbose=False)
    text = "\n".join(lines)
    detection_pos = text.index("[!] DETECTION")
    first_lead_pos = text.index("[~] LEAD")
    context_pos = text.index("[i] CONTEXT")
    assert detection_pos < first_lead_pos < context_pos


def test_evidence_limit_caps_facts_but_not_verbose_facts():
    from dumpex.hunt.injection.report_console import _console_finding

    regions = [_rwx(_ALLOC + 0x70000 + i * 0x1000) for i in range(5)]
    result = _check(check="injection.rwx_regions", tag=TAG_LEAD, confidence=CONFIDENCE_MEDIUM,
                     evidence=tuple(regions), evidence_limit=2)
    evidence = InjectionEvidence(rwx=tuple(regions), correlation=_correlation_for(rwx=regions))
    report = InjectionReport(score=1, coverage=_coverage(), results=(result,), evidence=evidence)

    # The shared, wire-facing compat Finding (report_facts.py) caps
    # `facts` but never carries `verbose_facts` at all -- that is
    # report_console.py's own normal/verbose detail POLICY (see both
    # modules' docstrings), exercised here via its `_console_finding`.
    wire_finding = finding_from_check_result(result, report)
    assert len(wire_finding.facts) == 3
    assert wire_finding.facts[-1] == "... and 3 more"
    assert wire_finding.verbose_facts == ()

    console_finding = _console_finding(result, report)
    assert console_finding.facts == wire_finding.facts
    assert len(console_finding.verbose_facts) == 5


def test_console_wraps_within_requested_width():
    from dumpex.hunt._console import strip_ansi
    long_region = _rwx(_ALLOC + 0x90000)
    result = _check(check="injection.rwx_regions", tag=TAG_LEAD, confidence=CONFIDENCE_MEDIUM,
                     evidence=(long_region,), evidence_limit=20,
                     inference="x " * 60 + "end of a deliberately very long inference sentence "
                                "meant to force wrapping across several lines of output")
    evidence = InjectionEvidence(rwx=[long_region], correlation=_correlation_for(rwx=[long_region]))
    report = InjectionReport(score=1, coverage=_coverage(), results=(result,), evidence=evidence)

    lines = render_console_lines(report, verbose=False, width=80)
    for line in lines:
        assert len(strip_ansi(line)) <= 80, repr(line)


# ── 4. Purity / order-independence tests ──────────────────────────────────

def test_projectors_are_order_independent_and_pure():
    report = _full_report()

    legacy_first = project_legacy_dict(report)
    record_first = project_hunter_record(report)
    console_first = render_console_lines(report, verbose=False)
    verbose_first = render_console_lines(report, verbose=True)

    # Re-run in the opposite order.
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
    assert record_first.score == record_again.score

    # Mutating a returned container must not affect a fresh call.
    legacy_first["rwx"].append("tampered")
    legacy_first["findings"].append("tampered")
    legacy_third = project_legacy_dict(report)
    assert "tampered" not in legacy_third["rwx"]
    assert "tampered" not in legacy_third["findings"]


def test_console_verbose_and_normal_never_change_json_projections():
    report = _full_report()
    before = project_legacy_dict(report)
    render_console_lines(report, verbose=True)
    render_console_lines(report, verbose=False)
    render_console_lines(report, verbose=True)
    after = project_legacy_dict(report)
    assert before == after
    assert project_hunter_record(report).findings == project_hunter_record(report).findings


# ── 5. Golden-scenario parity test ─────────────────────────────────────────
# Mirrors tests/fixtures/hunt_cli_scenarios.py::_build_injection exactly
# (same addresses/PE header/thread), so this Report describes the SAME
# scenario tests/fixtures/hunt_cli_golden/injection_console.txt and
# injection_hunt_dict.json already pin for the PRODUCTION path -- proving
# the new projectors agree with the approved console/JSON, not merely that
# they're internally consistent with each other.

_GOLDEN_ALLOC = 0x7ff700000000


def _no_offset_location(va: int) -> Location:
    """`tests.fixtures.hunt_cli_scenarios._build_injection`'s `FakeMF`
    never wires up a file-layout translation (`va_to_file_offset`), so the
    real scan/correlation layer resolves every `Location.file_offset` for
    that scenario to `None` ("(not captured)" -- see
    tests/fixtures/hunt_cli_golden/injection_verbose_console.txt). This
    module's shared `_location()` builder (test_injection_domain.py)
    hardcodes a nonzero `file_offset=0x400`, which is right for THAT
    module's own tests but would silently desync this golden-scenario
    Report from the approved verbose console fixture."""
    return Location(va=va, region_base=va, file_offset=None)


def _golden_scenario_report() -> InjectionReport:
    rwx_ev = RwxRegionEvidence(
        region=_region(_GOLDEN_ALLOC, alloc=_GOLDEN_ALLOC),
        location=_no_offset_location(_GOLDEN_ALLOC))
    pe = PeHeaderInfo(valid=True, machine_name="AMD64", is_pe32_plus=True,
                       number_of_sections=1, address_of_entry_point=0x1000,
                       image_base=0x140000000, reason="")
    pe_hit = HiddenPeEvidence(region=_region(_GOLDEN_ALLOC + 0x2000, "PAGE_READWRITE",
                                              alloc=_GOLDEN_ALLOC),
                               pe=pe, in_module_list=False,
                               location=_no_offset_location(_GOLDEN_ALLOC + 0x2000))
    thread_ev = UnbackedThreadEvidence(thread_id=1, start_address=_GOLDEN_ALLOC + 0x2000,
                                        location=_no_offset_location(_GOLDEN_ALLOC + 0x2000))
    thread_ctx = ThreadContext(thread_id=1, ip=_GOLDEN_ALLOC + 0x2000, ip_reg="RIP",
                                is_wow64=False)
    rip_hit = RipHitEvidence(thread_id=1, ip=_GOLDEN_ALLOC + 0x2000, ip_reg="RIP",
                              region=pe_hit.region)
    start_hit = StartHitEvidence(thread_id=1, start_address=_GOLDEN_ALLOC + 0x2000,
                                  region=pe_hit.region)

    correlation = Correlation(
        rwx_by_alloc={_GOLDEN_ALLOC: [rwx_ev.region]},
        pe_by_alloc={_GOLDEN_ALLOC: [pe_hit.region]},
        rwx_and_pe_alloc_bases={_GOLDEN_ALLOC},
        suspicious_alloc_bases={_GOLDEN_ALLOC},
        rip_hits=[rip_hit],
        rip_full_correlation=[rip_hit],
        start_hits=[start_hit],
    )
    evidence = InjectionEvidence(
        rwx=[rwx_ev],
        validated_pe_hits=[pe_hit],
        suspicious_pe_hits=[pe_hit],
        start_threads=[thread_ev],
        thread_contexts=[thread_ctx],
        correlated_allocations=[CorrelatedAllocationEvidence(
            allocation_base=_GOLDEN_ALLOC, regions=[rwx_ev.region, pe_hit.region])],
        correlation=correlation,
    )
    # The short read names the region it happened in, exactly as the CLI
    # scenario behind this same golden does -- a count with no target
    # renders a differently-worded coverage line, so a snapshot that drops
    # the target no longer reproduces the fixture it is checked against.
    coverage = CoverageSnapshot(memory_info_stream=True, thread_info_stream=True,
                                 module_list_stream=True, thread_list_stream=True,
                                 threads_total=1, contexts_parsed=1, pe_short_reads=1,
                                 pe_short_reads_targets=(ScanTarget(
                                     kind=ScanTargetKind.MEMORY_REGION,
                                     base_address=_GOLDEN_ALLOC + 0x2000, size=4096,
                                     allocation_base=_GOLDEN_ALLOC, state="MEM_COMMIT",
                                     type="MEM_PRIVATE", protection="PAGE_READWRITE",
                                     captured_size=0),),
                                 region_count=2, thread_info_count=1, module_count=1)
    results = (
        _check(check="injection.rwx_regions", tag=TAG_LEAD, confidence=CONFIDENCE_MEDIUM,
               evidence=evidence.rwx, evidence_limit=20,
               inference="1 memory region(s) carry PAGE_EXECUTE_READWRITE/WRITECOPY "
                          "protection, spanning 1 distinct allocation(s).",
               rationale="RWX is a directly-observed page protection flag, not a heuristic "
                          "guess — but RWX alone is routinely used by JITs, debuggers, and "
                          "some legitimate packers, so it is a lead, not proof, until "
                          "corroborated by a validated PE header and/or live execution in "
                          "the same allocation.",
               limitations=["Does not by itself distinguish injection from JIT/legitimate "
                            "self-modifying-code use cases."]),
        _check(check="injection.hidden_pe_validated", tag=TAG_LEAD, confidence=CONFIDENCE_MEDIUM,
               evidence=evidence.suspicious_pe_hits, evidence_limit=20,
               inference="1 address(es) contain a structurally-valid PE header (DOS+COFF+"
                          "optional header+full section table all parsed successfully) at "
                          "an address absent from the module list, in MEM_PRIVATE memory, "
                          "an executable unbacked mapping, or otherwise correlated with an "
                          "RWX allocation or live thread execution.",
               rationale="Passing full structural PE validation (not just an 'MZ' prefix) "
                          "rules out coincidental bytes and most decoys, but a valid header "
                          "outside the module list can also occur from a manually-mapped "
                          "but otherwise benign in-process library (e.g. some anti-cheat/DRM "
                          "loaders) — confidence rises to HIGH only when a thread's live "
                          "RIP/EIP actually executes inside the same allocation.",
               limitations=["Header validation read is capped at 4096 bytes; a section "
                            "table extending past that reports as invalid rather than "
                            "being partially trusted."]),
        _check(check="injection.unbacked_thread_startaddress", tag=TAG_LEAD,
               confidence=CONFIDENCE_LOW, evidence=evidence.start_threads, evidence_limit=20,
               inference="1 thread(s) began execution at an address not covered by any "
                          "known module.",
               rationale="StartAddress records where a thread BEGAN, not where it is "
                          "executing now — a thread can legitimately start inside "
                          "unbacked/JIT memory (e.g. a thread pool worker routine passed "
                          "as a raw function pointer into private memory) and still be "
                          "benign. Current RIP/EIP (below, when available) is the stronger "
                          "signal for what a thread is actually doing.",
               limitations=[]),
        _check(check="injection.allocation_correlation", tag=TAG_DETECTION,
               confidence=CONFIDENCE_HIGH, evidence=evidence.correlation.rip_hits,
               evidence_limit=20,
               inference="1 thread(s) currently execute inside an allocation that is "
                          "simultaneously RWX and hosts a validated hidden PE — page type, "
                          "structural PE validation, and live RIP/EIP all converge on the "
                          "same AllocationBase.",
               rationale="This is the strongest evidence this hunter can produce: the "
                          "process is, at the moment of the dump, actively running code "
                          "from an allocation with no legitimate module backing and a "
                          "concealed PE image.",
               limitations=["RIP is a single-point-in-time snapshot; a thread that executed "
                            "there moments before or after the dump was captured would not "
                            "appear here."]),
    )
    return InjectionReport(score=3, coverage=coverage, results=results, evidence=evidence)


@pytest.mark.parametrize("verbose, golden_name", [
    (False, "injection_console.txt"),
    (True, "injection_verbose_console.txt"),
])
def test_golden_scenario_console_matches_approved_fixture(capsys, verbose, golden_name):
    from pathlib import Path
    report = _golden_scenario_report()
    print_console(report, verbose=verbose)
    captured = capsys.readouterr().out
    golden_path = Path(__file__).resolve().parent.parent / "fixtures" / "hunt_cli_golden" / \
        golden_name
    expected = golden_path.read_text(encoding="utf-8")
    assert captured == expected


def test_golden_scenario_finding_ids_match_production():
    report = _golden_scenario_report()
    d = project_legacy_dict(report)
    ids = {f["check"]: f["id"] for f in d["findings"]}
    assert ids["injection.rwx_regions"] == "finding-2f1a5566ce4e5343e45a82598b84c438"
    assert ids["injection.hidden_pe_validated"] == "finding-0268be198e458dfbe0ed3135c961438c"
    assert ids["injection.unbacked_thread_startaddress"] == "finding-865748a357bed2cbe159f41e075ed6a7"
    assert ids["injection.allocation_correlation"] == "finding-cbda63978b1edec28c089433bad8fd1b"


def test_golden_scenario_hunter_record_matches_production():
    report = _golden_scenario_report()
    record = project_hunter_record(report)

    assert record.hunter == "injection"
    assert record.status == "DETECTED"
    assert record.score == 3
    assert record.max_score == 3
    assert record.verdict_level == "high"
    assert record.confidence == "high"
    assert record.lead_count == 3
    assert record.review_priority == "high"

    assert record.coverage.status.value == "partial"
    sources = record.coverage.sources
    assert sources["memory_info"].state == SourceState.PRESENT
    assert sources["memory_info"].record_count == 2
    assert sources["thread_info"].record_count == 1
    assert sources["modules"].record_count == 1
    assert sources["thread_context"].record_count == 1
    assert sources["thread_list"].record_count == 1
    assert sources["hidden_pe_scan"].record_count == 1
    # The structured CoverageReport's own renderer (dumpex.output.coverage.
    # _render_pe_header_short_read) spells this "--", not the em dash the
    # v1.1 coverage_reasons hand-written string uses -- a pre-existing
    # divergence between the two rendering systems, not something this
    # projector introduces (project_coverage_v1's own reasons list, tested
    # elsewhere in this file, keeps the em dash).
    assert record.coverage.reasons == [
        "1 region(s) returned fewer bytes than requested while checking for hidden PE "
        "headers (short read) -- not fully examined: 0x00007ff700002000 (4 KB)"
    ]

    details = record.details.to_dict()
    assert details["rwx"][0]["base_address"] == "0x00007ff700000000"
    assert details["hidden_pe_validated"][0]["region"]["base_address"] == "0x00007ff700002000"
    assert details["rwx_and_pe_alloc_bases"] == ["0x00007ff700000000"]
    assert details["rip_full_correlation"][0]["thread"]["tid"] == 1
    assert details["start_hits"][0]["thread"]["start_address"] == "0x00007ff700002000"


def test_golden_scenario_exit_code_matches_production_partial():
    # tests/fixtures/hunt_cli_scenarios.py's own `_check_injection` pins
    # `expected_exit_code=3` (EXIT_PARTIAL) for this exact scenario --
    # DETECTED (score 3/3) but coverage.status="partial" (one short PE
    # header read), independent axes. `exit_code_for` is the ONE place a
    # coverage status becomes a process exit code (dumpex.output.coverage's
    # own docstring); this asserts the new HunterRecord projector's
    # coverage.status still feeds that same shared function to the same
    # result, not that this module reimplements the mapping itself.
    record = project_hunter_record(_golden_scenario_report())
    assert exit_code_for(record.coverage.status) == EXIT_PARTIAL == 3




# ── 7. The "empty/error" acceptance axis ────────────────────────────────────
# `_not_evaluated_report()` (all streams absent, no results) already stands
# in for "empty" throughout this file. "error" -- a hunt run that failed
# outright, rather than one that ran and simply saw nothing -- is
# DELIBERATELY not representable by `InjectionReport` at all: this domain
# model's own status is derived purely from (evaluated, score>0, complete)
# through `dumpex.hunt._coverage.derive_status`, whose closed vocabulary is
# exactly {DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, INCONCLUSIVE,
# NOT_EVALUATED} -- there is no fifth "failed" status this model, or the
# reducer it calls, can produce. A hunter execution error is caught and
# reported entirely upstream of any `InjectionReport` construction, as the
# whole-command `execution_status` field `dumpex.output.envelope`/
# `dumpex.output.collector` own (EXECUTION_FAILED, a DIFFERENT axis than
# any per-hunter coverage status -- see dumpex.output.coverage's own
# ExecutionStatus) -- covered by that layer's own tests (e.g.
# tests/unit/test_output_collector.py), not by this hunter-specific
# projector suite, since none of the three projectors here are ever on the
# call path for a hunter that never produced a Report at all.

def test_injection_report_status_has_no_error_representation():
    from dumpex.hunt._ui import DETECTED, INCONCLUSIVE, NOT_DETECTED_IN_SCANNED_SCOPE, \
        NOT_EVALUATED
    known_statuses = {DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, INCONCLUSIVE, NOT_EVALUATED}
    for report_fn in (_full_report, _coverage_gap_report, _clean_report,
                       _inconclusive_report, _not_evaluated_report):
        assert report_fn().status in known_statuses


# ── issue #26 / schema 2.11: the candidate's own location reaches the ─────
# structured record, not just the console. A consumer handed only the
# containing region cannot carve a PE found partway into an allocation,
# correlate it, or tell two hits in one region apart.

def _nonbase_pe_report() -> InjectionReport:
    """One validated hidden PE found 0x2000 into its region, with a real
    file offset -- the arrangement the region-base-only scan could not
    produce at all."""
    region_base = _ALLOC + 0x50000
    pe_va = region_base + 0x2000
    hit = HiddenPeEvidence(
        region=_region(region_base, "PAGE_READWRITE", alloc=_ALLOC),
        pe=PeHeaderInfo(valid=True, machine_name="AMD64", is_pe32_plus=True,
                        number_of_sections=1, address_of_entry_point=0x1000,
                        image_base=0x140000000, reason=""),
        in_module_list=False,
        location=Location(va=pe_va, region_base=region_base, file_offset=0x8400))
    evidence = InjectionEvidence(validated_pe_hits=[hit], suspicious_pe_hits=[hit],
                                  correlation=_correlation_for(validated_pe_hits=[hit]))
    results = (_check(check="injection.hidden_pe_validated", tag=TAG_LEAD,
                       confidence=CONFIDENCE_MEDIUM, evidence=evidence.suspicious_pe_hits,
                       evidence_limit=20),)
    return InjectionReport(score=1, coverage=_coverage(), results=results, evidence=evidence)


def test_hunter_record_pe_hit_carries_the_candidate_location():
    record = project_hunter_record(_nonbase_pe_report())
    hit = record.details.hidden_pe_validated[0]
    assert hit.va == "0x00007ffe30052000"
    assert hit.region_offset == 0x2000
    assert hit.file_offset == "0x0000000000008400"
    # The containing region is unchanged -- it is what allocation
    # correlation is keyed on, and it is NOT where the PE starts.
    assert hit.region.base_address == "0x00007ffe30050000"


def test_hunter_record_pe_hit_location_survives_the_json_projection():
    d = project_hunter_record(_nonbase_pe_report()).to_dict()
    hit = d["details"]["hidden_pe_validated"][0]
    assert hit["va"] == "0x00007ffe30052000"
    assert hit["region_offset"] == 0x2000
    assert hit["file_offset"] == "0x0000000000008400"


def test_hunter_record_pe_hit_file_offset_none_is_not_offset_zero():
    # "not captured" and "byte zero of the .dmp" are different claims --
    # see Location.file_offset's own docstring.
    region_base = _ALLOC + 0x50000
    hit = HiddenPeEvidence(
        region=_region(region_base, "PAGE_READWRITE", alloc=_ALLOC),
        pe=PeHeaderInfo(valid=False, machine_name=None, is_pe32_plus=None,
                        number_of_sections=None, address_of_entry_point=None,
                        image_base=None, reason="truncated header"),
        in_module_list=False,
        location=Location(va=region_base + 0x10, region_base=region_base, file_offset=None))
    evidence = InjectionEvidence(mz_only_hits=[hit], correlation=Correlation())
    results = (_check(check="injection.mz_prefix_unvalidated", tag=TAG_OBSERVATION,
                       confidence=CONFIDENCE_LOW, evidence=evidence.mz_only_hits,
                       evidence_limit=10),)
    report = InjectionReport(score=0, coverage=_coverage(), results=results, evidence=evidence)

    hit_dict = project_hunter_record(report).to_dict()["details"]["hidden_pe_unvalidated"][0]
    assert hit_dict["file_offset"] is None
    assert hit_dict["va"] == "0x00007ffe30050010"
    assert hit_dict["region_offset"] == 0x10


def test_hunter_record_with_candidate_location_validates_against_the_current_schema():
    jsonschema = pytest.importorskip("jsonschema")
    import json
    from dumpex.schemas import CURRENT_SCHEMA, schema_path

    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    wrapper = {"$schema": schema["$schema"], "$ref": "#/$defs/hunterRecord",
                "$defs": schema["$defs"]}
    validator = jsonschema.Draft202012Validator(wrapper)
    assert list(validator.iter_errors(project_hunter_record(_nonbase_pe_report()).to_dict())) == []


def test_facts_name_the_pe_address_only_when_it_is_not_the_region_base():
    # A hit at the region base reads exactly as it always has (the region
    # facts already say that address once); a hit found partway in names
    # its own VA and offset, so the fact line cannot be misread as
    # pointing at the region's first byte. PE_VA renders through the same
    # fixed-width convention as every other address-like fact (issue #31)
    # -- region_offset is not itself a virtual address and keeps its
    # existing compact form.
    nonbase = finding_from_check_result(_nonbase_pe_report().results[0], _nonbase_pe_report())
    assert "PE_VA=0x00007ffe30052000 region_offset=0x2000" in nonbase.facts[0]

    base_report = _full_report()
    pe_check = next(r for r in base_report.results if r.check == "injection.hidden_pe_validated")
    at_base = finding_from_check_result(pe_check, base_report)
    assert "PE_VA=" not in at_base.facts[0]


def test_declared_image_base_is_padded_in_facts_verbose_and_structured_record():
    """`declared_image_base`/`Declared_ImageBase` is the PE header's OWN
    declared base -- a real address (see `HuntPeHeaderHit.image_base`'s
    own docstring, validated as a hex address by
    `dumpex.output.records._require_optional_hex_address`), not an RVA --
    so it renders through the same fixed-width convention as every other
    address-like field, consistently across normal facts, verbose facts,
    and the structured `HunterRecord` (issue #31 follow-up)."""
    from dumpex.hunt.injection.report_console import _console_finding

    pe_hit = _pe_hit(_ALLOC + 0x1000, alloc=_ALLOC)
    result = _check(check="injection.hidden_pe_validated", tag=TAG_LEAD,
                     confidence=CONFIDENCE_MEDIUM, evidence=(pe_hit,), evidence_limit=20)
    evidence = InjectionEvidence(suspicious_pe_hits=[pe_hit], validated_pe_hits=[pe_hit],
                                  correlation=_correlation_for(validated_pe_hits=[pe_hit]))
    report = InjectionReport(score=1, coverage=_coverage(), results=(result,), evidence=evidence)

    fact = finding_from_check_result(result, report).facts[0]
    assert "declared_image_base=0x0000000140000000" in fact

    console_finding = _console_finding(result, report)
    assert "Declared_ImageBase=0x0000000140000000" in console_finding.verbose_facts[0]

    record = project_hunter_record(report)
    assert record.details.hidden_pe_validated[0].image_base == "0x0000000140000000"


def _low_address_mz_report():
    """dumpex issue #31's own repro: a memory region at 0x270000 with an
    unvalidated-MZ candidate 0x8dd0 into it -- the exact case the issue
    filed against `injection.mz_prefix_unvalidated`."""
    region_base = 0x270000
    pe_va = region_base + 0x8dd0
    hit = HiddenPeEvidence(
        region=_region(region_base, "PAGE_READONLY", alloc=region_base),
        pe=PeHeaderInfo(valid=False, machine_name=None, is_pe32_plus=None,
                        number_of_sections=None, address_of_entry_point=None,
                        image_base=None, reason="no PE\\0\\0 signature at e_lfanew"),
        in_module_list=False,
        location=Location(va=pe_va, region_base=region_base, file_offset=None))
    evidence = InjectionEvidence(mz_only_hits=[hit], correlation=Correlation())
    result = _check(check="injection.mz_prefix_unvalidated", tag=TAG_OBSERVATION,
                     confidence=CONFIDENCE_LOW, evidence=(hit,), evidence_limit=10)
    report = InjectionReport(score=0, coverage=_coverage(), results=(result,), evidence=evidence)
    return result, report


def test_facts_pad_a_low_address_pe_candidate_reproducing_issue_31():
    """Under the old variable-width `:x` formatting, PE_VA for this
    scenario read as the truncated-looking `0x278dd0`; it must now match
    the same fixed-width (16 hex digit) convention the verbose console/
    HunterRecord already use for every other address."""
    result, report = _low_address_mz_report()

    fact = finding_from_check_result(result, report).facts[0]
    assert "VA=0x0000000000270000 AllocationBase=0x0000000000270000" in fact
    assert "PE_VA=0x0000000000278dd0 region_offset=0x8dd0" in fact


def test_finding_id_changes_deterministically_for_a_low_address_pe_candidate():
    """`facts` feeds `Finding.id`'s hash basis (dumpex.hunt._finding.
    Finding), so the fixed-width facts contract deliberately, and
    deterministically, changes the id this low-address finding produces
    versus the old variable-width text for the identical evidence --
    pinned here so a regression back to variable-width silently
    reproducing the OLD id would be caught."""
    result, report = _low_address_mz_report()
    finding = finding_from_check_result(result, report)
    assert finding.id == "finding-98588ce6ea6b0547b4ca229842f48858"

    old_style_text = ("VA=0x270000 AllocationBase=0x270000 size=0x1000 type=MEM_PRIVATE "
                       "protect=PAGE_READONLY PE_VA=0x278dd0 region_offset=0x8dd0  |  "
                       "PE header INVALID (no PE\\0\\0 signature at e_lfanew)")
    old_style = Finding(check=result.check, facts=[old_style_text], inference=result.inference,
                         confidence=result.confidence, rationale=result.rationale,
                         limitations=list(result.limitations), tag=result.tag,
                         technique_ids=list(result.technique_ids),
                         evidence_refs=list(result.evidence_refs), iocs=list(result.iocs),
                         rule_id=result.rule_id, rule_version=result.rule_version)
    assert old_style.id != finding.id

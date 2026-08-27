"""Hunter-specific behavior for named-pipe report projectors."""
import dataclasses

import pytest

from tests.hunt.test_pipe_domain import (
    _c2_context, _c2_record, _check, _corroborated, _coverage, _framework_string_hit,
    _handle, _handle_ref, _oversize_target, _region, _start_lead, _string_lead, _thread_hit,
    _thread_start, _unbacked, _PIPE_VA, _REGION_BASE,
)

from dumpex.hunt._console import strip_ansi
from dumpex.hunt._finding import (
    CONFIDENCE_HIGH, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    TAG_DETECTION, TAG_LEAD, TAG_OBSERVATION,
)
from dumpex.hunt.pipe import aggregate as pipe_aggregate
from dumpex.hunt.pipe.domain import CoverageSnapshot, PipeEvidence, PipeReport
from dumpex.hunt.pipe.models import CorroboratedHandleEvidence, StartAddressLeadEvidence
from dumpex.hunt.pipe.report_console import render_console_lines
from dumpex.hunt.pipe.report_facts import finding_from_check_result, project_coverage_v1
from dumpex.hunt.pipe.report_legacy import project_legacy_dict
from dumpex.hunt.pipe.report_record import project_hunter_record


# ── Report builders ────────────────────────────────────────────────────────

def _detected_report(score=3, coverage=None) -> PipeReport:
    """DETECTED. score=1 is a framework-named handle alone; score=2 adds
    ONE corroborating memory signal; score=3 adds both."""
    handle = _handle()
    lead   = _string_lead()
    results = [
        _check(check="pipe.open_handles", tag=TAG_OBSERVATION, confidence=CONFIDENCE_MEDIUM,
               inference="Process holds 1 open handle(s) to named pipe object(s), per "
                          "HandleDataStream.",
               evidence=(handle,), evidence_limit=20),
        _check(check="pipe.handle_framework_match", tag=TAG_DETECTION,
               confidence=CONFIDENCE_MEDIUM,
               inference="1 open pipe handle(s) match a known C2/lateral-movement framework "
                          "naming convention.",
               evidence=(handle,)),
        _check(check="pipe.string_scan_lead", tag=TAG_LEAD, confidence=CONFIDENCE_LOW,
               inference="1 occurrence(s) of a '\\pipe\\' name found in non-system-DLL memory "
                          "via byte-pattern scan.",
               evidence=(lead,), evidence_limit=15),
    ]
    corroborated = ()
    if score >= 2:
        corroborated = (_corroborated(handle=handle, string_hit=lead,
                                       nearby_c2=(_c2_record(),),
                                       rip_hit=_thread_hit() if score == 3 else None),)
        results.append(_check(
            check="pipe.corroboration", tag=TAG_DETECTION,
            confidence=CONFIDENCE_HIGH if score == 3 else CONFIDENCE_MEDIUM,
            # Distinctive wording so WHY THIS VERDICT can be proven to be
            # driven by THIS check rather than by display order.
            inference="corroborated by C2-style context and/or live RIP/EIP execution",
            limitations=["Proximity window is not a proof of logical association."],
            evidence=corroborated, evidence_limit=10))
    evidence = PipeEvidence(handle_pipes=(handle,), string_leads=(lead,),
                             corroborated_handles=corroborated)
    return PipeReport(score=score, coverage=coverage or _coverage(), results=tuple(results),
                       evidence=evidence)


def _all_checks_report() -> PipeReport:
    """Every one of the five check ids in one Report, plus all three kinds
    of unchecked evidence -- deliberately richer than any single scan
    `aggregate.build_report` would itself produce, purely to exercise every
    projector code path at once."""
    handle       = _handle()
    plain_handle = _handle(handle=_handle_ref(handle=0x90,
                                               object_name=r"\Device\NamedPipe\ordinary"),
                            canonical_name="ordinary", framework=False)
    lead         = _string_lead()
    other_lead   = _string_lead(offset=0x400, name="\\\\.\\pipe\\ordinary", sha256="e" * 64)
    corroborated = _corroborated(handle=handle, string_hit=lead,
                                  nearby_c2=(_c2_record(),
                                             _c2_record(match="198.51.100.7:8080",
                                                        va=_PIPE_VA + 0x1c)),
                                  rip_hit=_thread_hit())
    start_lead   = _start_lead(handle=plain_handle, string_hit=other_lead)
    evidence = PipeEvidence(
        handle_pipes=(handle, plain_handle), string_leads=(lead, other_lead),
        corroborated_handles=(corroborated,), start_address_leads=(start_lead,),
        # `string_hit=lead`/`string_hit=other_lead`: the SAME objects
        # `string_leads` above holds, by identity -- PipeEvidence rejects a
        # c2_context/framework_string_hits entry whose string_hit is not
        # one of its own string_leads (see domain.PipeEvidence's own
        # identity-subset check).
        c2_context=(_c2_context(string_hit=lead),),
        framework_string_hits=(_framework_string_hit(string_hit=other_lead),),
        unbacked_threads=(_unbacked(),))
    results = (
        _check(check="pipe.open_handles", tag=TAG_OBSERVATION, confidence=CONFIDENCE_MEDIUM,
               evidence=(handle, plain_handle), evidence_limit=20),
        _check(check="pipe.handle_framework_match", tag=TAG_DETECTION,
               confidence=CONFIDENCE_MEDIUM, evidence=(handle,)),
        _check(check="pipe.string_scan_lead", tag=TAG_LEAD, confidence=CONFIDENCE_LOW,
               evidence=(lead, other_lead), evidence_limit=15),
        _check(check="pipe.corroboration", tag=TAG_DETECTION, confidence=CONFIDENCE_HIGH,
               inference="corroborated by C2-style context and/or live RIP/EIP execution",
               evidence=(corroborated,), evidence_limit=10),
        _check(check="pipe.start_address_proximity_lead", tag=TAG_LEAD,
               confidence=CONFIDENCE_LOW, evidence=(start_lead,), evidence_limit=15),
    )
    return PipeReport(score=3, coverage=_coverage(short_reads=1), results=results,
                       evidence=evidence)


def _five_c2_records_report() -> "tuple[PipeReport, tuple]":
    """One retained C2-context region at the scanner's current five-hit
    acquisition cap, also used as handle corroboration so both verbose
    console C2 render paths exercise the same complete record set."""
    handle = _handle()
    lead = _string_lead()
    matches = ("http://", "198.51.100.7", "198.51.100.7:8080", "submit.php",
               "beacon.example")
    records = tuple(
        _c2_record(match=match, va=_PIPE_VA + 0x20 + i * 0x10,
                   sha256=f"{i + 1:064x}", original_length=len(match))
        for i, match in enumerate(matches)
    )
    corroborated = _corroborated(handle=handle, string_hit=lead, nearby_c2=records)
    result = _check(
        check="pipe.corroboration", tag=TAG_DETECTION, confidence=CONFIDENCE_HIGH,
        evidence=(corroborated,), evidence_limit=10)
    evidence = PipeEvidence(
        handle_pipes=(handle,), string_leads=(lead,),
        corroborated_handles=(corroborated,),
        c2_context=(_c2_context(records=records, string_hit=lead),))
    return PipeReport(score=2, coverage=_coverage(), results=(result,), evidence=evidence), records


def _string_lead_only_report() -> PipeReport:
    """No handle evidence at all -- the "bare pipe strings are leads and
    never become scored handle evidence" shape, including a framework
    naming-convention match ON A STRING that still must not score."""
    lead = _string_lead()
    evidence = PipeEvidence(string_leads=(lead,),
                             framework_string_hits=(_framework_string_hit(string_hit=lead),),
                             unbacked_threads=(_unbacked(),))
    results = (_check(check="pipe.string_scan_lead", tag=TAG_LEAD, confidence=CONFIDENCE_LOW,
                       inference="1 occurrence(s) of a '\\pipe\\' name found in non-system-DLL "
                                  "memory via byte-pattern scan.",
                       evidence=(lead,), evidence_limit=15),)
    return PipeReport(score=0, coverage=_coverage(handle_data_stream=False), results=results,
                       evidence=evidence)


def _clean_report() -> PipeReport:
    handle = _handle(canonical_name="ordinary", framework=False)
    results = (_check(check="pipe.open_handles", tag=TAG_OBSERVATION,
                       confidence=CONFIDENCE_MEDIUM, evidence=(handle,), evidence_limit=20),)
    return PipeReport(score=0, coverage=_coverage(), results=results,
                       evidence=PipeEvidence(handle_pipes=(handle,)))


def _inconclusive_report() -> PipeReport:
    return PipeReport(score=0, coverage=_coverage(short_reads=1), results=(),
                       evidence=PipeEvidence())


def _not_evaluated_report() -> PipeReport:
    coverage = CoverageSnapshot(memory_info_stream=False, handle_data_stream=False)
    return PipeReport(score=0, coverage=coverage, results=(), evidence=PipeEvidence())


_ALL_REPORTS = [_all_checks_report, _detected_report, _string_lead_only_report,
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
    assert record.hunter == "pipe"
    assert isinstance(lines, list) and all(isinstance(l, str) for l in lines)
    assert isinstance(verbose_lines, list)


def test_legacy_dict_key_set_is_unchanged():
    """The v1.1 findings dict's own key set is a frozen contract (see
    tests/integration/test_hunt_compat_freeze.py's `_PIPE_KEYS`)."""
    d = project_legacy_dict(_all_checks_report())
    assert set(d) == {
        "budget_exhausted", "c2_context", "confidence", "coverage_reasons", "coverage_status",
        "findings", "framework_pipes", "handle_pipes", "lead_count", "max_score",
        "private_pipes", "review_priority", "scan_complete", "score", "status",
        "unbacked_in_rgn", "verdict_level",
    }
    assert d["score"] == 3 and d["max_score"] == 3
    assert len(d["findings"]) == 5


def test_legacy_dict_entries_hold_no_raw_minidump_objects():
    d = project_legacy_dict(_all_checks_report())
    handle_entry = d["handle_pipes"][0]
    assert isinstance(handle_entry["handle"], dict)
    assert handle_entry["handle"]["Handle"] == 0x88
    assert handle_entry["handle"]["GrantedAccess"] == 0x12019f
    assert handle_entry["canonical_name"] == "msagent_1337"
    # v1.1 has always carried this as a positional 3-tuple.
    assert handle_entry["framework_match"] == ("Cobalt Strike", "SMB Beacon peer-to-peer pipe",
                                                "T1090.001")
    assert d["handle_pipes"][1]["framework_match"] is None
    # framework_pipes is the derived SUBSET, never a second stored bucket.
    assert len(d["framework_pipes"]) == 1
    assert d["framework_pipes"][0] == handle_entry

    private = d["private_pipes"][0]
    assert isinstance(private["region"], dict)
    assert private["region"]["Protect"] == "PAGE_EXECUTE_READ"
    assert private["region"]["BaseAddress"] == _REGION_BASE

    # c2_context/unbacked_in_rgn stay positionally-indexed tuples.
    region_dict, name, records = d["c2_context"][0]
    assert isinstance(region_dict, dict) and name == "\\\\.\\pipe\\msagent_1337"
    assert records[0]["match"] == "http://"
    assert records[0]["context"] == b"AAAA"
    thread_dict, region_dict = d["unbacked_in_rgn"][0]
    assert thread_dict == {"ThreadId": 0x999, "StartAddress": _REGION_BASE + 0x10}
    assert isinstance(region_dict, dict)


def test_legacy_dict_is_json_safe_after_the_projects_own_sanitizer():
    """`dumpex.ui.structured._json_safe`'s `str(obj)` fallback used to
    embed the ANALYSIS HOST's own Python heap address for every raw
    Region/Handle/ThreadInfo the pre-migration dict carried. Nothing here
    can produce that any more."""
    import json
    from dumpex.ui.structured import _json_safe
    safe = _json_safe(project_legacy_dict(_all_checks_report()))
    text = json.dumps(safe)
    assert "object at 0x" not in text


def test_hunter_record_details_shape_is_the_v2_wire_shape():
    record = project_hunter_record(_all_checks_report())
    details = record.details
    assert len(details.handle_pipes) == 2 and len(details.framework_pipes) == 1
    handle_entry = details.handle_pipes[0]
    assert handle_entry["handle"]["handle"] == f"0x{0x88:016x}"
    assert handle_entry["handle"]["granted_access"] == 0x12019f   # plain int, never hex
    assert handle_entry["framework_match"] == {"framework": "Cobalt Strike",
                                                "technique": "SMB Beacon peer-to-peer pipe",
                                                "mitre": "T1090.001"}
    private = details.private_pipes[0]
    assert private["region"]["base_address"] == f"0x{_REGION_BASE:016x}"
    assert set(private) == {"region", "offset", "name", "sha256", "original_length",
                            "truncated", "encoding"}
    c2 = details.c2_context[0]
    assert c2["records"][0]["context"] == b"AAAA".hex()
    assert c2["records"][0]["va"] == f"0x{_PIPE_VA + 0x15:016x}"
    unbacked = details.unbacked_in_rgn[0]
    assert unbacked["thread"] == {"tid": 0x999,
                                  "start_address": f"0x{_REGION_BASE + 0x10:016x}"}
    assert record.findings and all(isinstance(f, dict) for f in record.findings)


def test_a_thread_with_no_start_address_reads_as_null_never_as_zero():
    unbacked = _unbacked()
    unbacked = type(unbacked)(thread=_thread_start(start_address=None), region=_region())
    report = PipeReport(score=0, coverage=_coverage(), results=(),
                         evidence=PipeEvidence(unbacked_threads=(unbacked,)))
    record = project_hunter_record(report)
    assert record.details.unbacked_in_rgn[0]["thread"]["start_address"] is None


def test_console_lines_contain_expected_sections():
    lines = render_console_lines(_all_checks_report(), verbose=False)
    text = "\n".join(lines)
    assert "HUNT: Named Pipe C2 / Lateral Movement" in text
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

    assert facts["pipe.open_handles"] == (
        "Handle=0x88 ObjectName=\\Device\\NamedPipe\\msagent_1337 GrantedAccess=0x12019f"
        "  [framework=Cobalt Strike]",
        "Handle=0x90 ObjectName=\\Device\\NamedPipe\\ordinary GrantedAccess=0x12019f")
    assert facts["pipe.handle_framework_match"] == (
        "Handle=0x88 ObjectName=\\Device\\NamedPipe\\msagent_1337 framework=Cobalt Strike "
        "technique=SMB Beacon peer-to-peer pipe mitre=T1090.001",)
    assert facts["pipe.string_scan_lead"] == (
        f"VA=0x{_PIPE_VA:x} file_offset=(not captured) "
        f"name='\\\\\\\\.\\\\pipe\\\\msagent_1337' region_type=MEM_PRIVATE",
        f"VA=0x{_REGION_BASE + 0x400:x} file_offset=(not captured) "
        f"name='\\\\\\\\.\\\\pipe\\\\ordinary' region_type=MEM_PRIVATE")
    assert facts["pipe.corroboration"] == (
        f"Handle=0x88 ObjectName=\\Device\\NamedPipe\\msagent_1337 pipe_va=0x{_PIPE_VA:x}"
        f"  c2_va=0x{_PIPE_VA + 0x15:x} c2_match='http://' distance=0x15 same_page=True"
        f"  live_rip=TID:0x999@RIP=0x{_PIPE_VA + 4:x} distance=0x4 same_page=True",)
    assert facts["pipe.start_address_proximity_lead"] == (
        f"Handle=0x90 ObjectName=\\Device\\NamedPipe\\ordinary "
        f"pipe_va=0x{_REGION_BASE + 0x400:x} TID=0x999 StartAddr=0x{_REGION_BASE + 0x10:x} "
        f"distance=0x3f0 same_page=True",)


def test_corroboration_wire_fact_names_only_the_first_nearby_c2_record():
    """The wire fact carries one record; --verbose expands every one."""
    report = _all_checks_report()
    result = next(r for r in report.results if r.check == "pipe.corroboration")
    fact = finding_from_check_result(result, report).facts[0]
    assert fact.count("c2_va=") == 1
    assert "198.51.100.7:8080" not in fact


def test_a_file_offset_that_was_captured_is_rendered_as_hex_never_as_none():
    lead = _string_lead(file_offset=0x3000)
    report = PipeReport(
        score=0, coverage=_coverage(),
        results=(_check(check="pipe.string_scan_lead", tag=TAG_LEAD,
                        confidence=CONFIDENCE_LOW, evidence=(lead,), evidence_limit=15),),
        evidence=PipeEvidence(string_leads=(lead,)))
    assert "file_offset=0x3000" in finding_from_check_result(report.results[0], report).facts[0]


def test_unknown_check_id_has_no_silent_fallback_renderer():
    report = PipeReport(score=0, coverage=_coverage(),
                         results=(_check(check="pipe.brand_new_check", evidence=()),),
                         evidence=PipeEvidence())
    with pytest.raises(ValueError, match="no fact renderer registered"):
        finding_from_check_result(report.results[0], report)


def test_evidence_limit_caps_facts_but_not_verbose_facts():
    from dumpex.hunt.pipe.report_console import _console_finding

    handles = tuple(_handle(handle=_handle_ref(handle=0x100 + i,
                                                object_name=rf"\Device\NamedPipe\test_{i}"),
                             canonical_name=f"test_{i}", framework=False)
                    for i in range(5))
    result = _check(check="pipe.open_handles", tag=TAG_OBSERVATION,
                    confidence=CONFIDENCE_MEDIUM, evidence=handles, evidence_limit=2)
    report = PipeReport(score=0, coverage=_coverage(), results=(result,),
                         evidence=PipeEvidence(handle_pipes=handles))

    wire_finding = finding_from_check_result(result, report)
    assert len(wire_finding.facts) == 3
    assert wire_finding.facts[-1] == "... and 3 more"
    assert wire_finding.verbose_facts == ()

    console_finding = _console_finding(result, report)
    assert console_finding.facts == wire_finding.facts
    assert len(console_finding.verbose_facts) == 5


def test_canonical_names_and_region_identity_are_verbose_only_console_detail():
    """Issue #7 asks for full handle lists, canonicalized names, VA/file
    offsets and nearby C2 context in bounded/verbose evidence. They must
    NOT reach `facts` -- that array is embedded verbatim in both the v1.1
    dict and the typed `HunterRecord`, whose goldens are frozen."""
    report = _all_checks_report()
    for result in report.results:
        wire = finding_from_check_result(result, report)
        assert not any("canonical=" in fact for fact in wire.facts)
        assert not any("File_offset" in fact for fact in wire.facts)

    normal = "\n".join(render_console_lines(report, verbose=False))
    verbose = "\n".join(render_console_lines(report, verbose=True))
    assert "canonical=" not in normal
    assert "canonical='msagent_1337'" in verbose
    assert "198.51.100.7:8080" not in normal
    assert "198.51.100.7:8080" in verbose


def test_corroboration_verbose_facts_expand_per_signal_not_per_handle():
    from dumpex.hunt.pipe.report_console import _console_finding
    report = _all_checks_report()
    result = next(r for r in report.results if r.check == "pipe.corroboration")
    verbose = _console_finding(result, report).verbose_facts
    # one handle line + two nearby C2 records + one live RIP line
    assert len(verbose) == 4
    assert verbose[0].startswith("Handle=0x88 ")
    assert "c2_match='http://'" in verbose[1]
    assert "c2_match='198.51.100.7:8080'" in verbose[2]
    assert "live_rip=TID:0x999@RIP" in verbose[3]
    assert not any("sha256_prefix=" in fact for fact in verbose)


def test_verbose_console_shows_all_five_retained_c2_records_without_digests_or_summary():
    report, records = _five_c2_records_report()
    verbose = strip_ansi("\n".join(render_console_lines(report, verbose=True)))

    for rec in records:
        assert f"C2: {rec.match} VA 0x{rec.va:016x}" in verbose
        assert f"c2_va=0x{rec.va:016x} c2_match={rec.match!r}" in verbose
    assert "more record(s)" not in verbose
    assert "sha256_prefix=" not in verbose


def test_five_retained_c2_records_keep_full_sha256_and_wire_shapes_in_both_json_projections():
    report, records = _five_c2_records_report()
    legacy_records = project_legacy_dict(report)["c2_context"][0][2]
    current_records = project_hunter_record(report).details.c2_context[0]["records"]

    assert len(legacy_records) == len(current_records) == len(records) == 5
    assert [item["match"] for item in legacy_records] == [rec.match for rec in records]
    assert [item["match"] for item in current_records] == [rec.match for rec in records]
    assert all(set(item) == {"match", "context", "va", "sha256", "original_length"}
               for item in legacy_records)
    assert all(set(item) == {"match", "context", "va", "sha256", "original_length"}
               for item in current_records)
    for source, legacy, current in zip(records, legacy_records, current_records):
        assert legacy["sha256"] == current["sha256"] == source.sha256
        assert len(legacy["sha256"]) == 64
        assert legacy["va"] == source.va
        assert current["va"] == f"0x{source.va:016x}"
        assert legacy["context"] == source.context
        assert current["context"] == source.context.hex()


# ── 3. State-matrix tests ─────────────────────────────────────────────────

@pytest.mark.parametrize("score, verdict_level, verdict_text", [
    (1, "possible", "POSSIBLE C2 PIPE"),
    (2, "likely", "LIKELY C2 PIPE"),
    (3, "high", "HIGH CONFIDENCE C2 PIPE / LATERAL MOVEMENT"),
])
def test_every_detected_tier_matches_across_projectors(score, verdict_level, verdict_text):
    report = _detected_report(score=score)
    d, record = project_legacy_dict(report), project_hunter_record(report)
    assert report.status == "DETECTED"
    assert d["status"] == "DETECTED" == record.status
    assert d["score"] == record.score == score
    assert d["verdict_level"] == record.verdict_level == verdict_level
    text = "\n".join(render_console_lines(report, verbose=False))
    assert verdict_text in text


def test_string_lead_only_state_never_scores_and_stays_inconclusive():
    """The hunter's core policy: a bare '\\pipe\\' string -- even one
    matching a known framework naming convention -- is a LEAD and never
    becomes scored handle evidence."""
    report = _string_lead_only_report()
    assert report.score == 0
    assert report.status == "INCONCLUSIVE"
    assert report.lead_count == 1
    d = project_legacy_dict(report)
    assert d["handle_pipes"] == [] and d["framework_pipes"] == []
    assert len(d["private_pipes"]) == 1
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "INCONCLUSIVE" in text
    assert "1 lead(s) found above" in text
    assert "CLEAN" not in text
    assert "HandleDataStream missing from this dump" in text
    assert "never becomes handle evidence" in text


def test_clean_state_is_not_detected_in_scanned_scope():
    report = _clean_report()
    assert report.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    d, record = project_legacy_dict(report), project_hunter_record(report)
    assert d["status"] == record.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert d["coverage_status"] == "complete"
    assert d["coverage_reasons"] == []
    assert d["scan_complete"] is True and d["budget_exhausted"] is False
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "CLEAN — no handle-confirmed C2 pipe indicators" in text
    # COVERAGE only renders when there is a gap to report.
    assert "COVERAGE" not in text


def test_partial_state_names_the_gap_but_keeps_the_detection():
    report = _detected_report(score=3, coverage=_coverage(short_reads=1))
    d = project_legacy_dict(report)
    assert d["status"] == "DETECTED"
    assert d["coverage_status"] == "partial"
    assert d["scan_complete"] is False
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "Coverage incomplete despite a detection" in text


def test_inconclusive_state_names_the_short_read():
    report = _inconclusive_report()
    assert report.status == "INCONCLUSIVE"
    d = project_legacy_dict(report)
    assert d["coverage_status"] == "partial"
    assert any("short read" in r for r in d["coverage_reasons"])
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "INCONCLUSIVE" in text and "COVERAGE" in text


def test_not_evaluated_state_never_implies_clean():
    report = _not_evaluated_report()
    assert report.status == "NOT_EVALUATED"
    d = project_legacy_dict(report)
    assert d["status"] == "NOT_EVALUATED"
    assert d["coverage_status"] == "not_evaluated"
    assert "MemoryInfoListStream missing from this dump" in d["coverage_reasons"]
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "NOT EVALUATED" in text
    assert "CLEAN" not in text
    assert "KEY SIGNALS" not in text
    assert "WHY THIS VERDICT" not in text


# ── 4. Partial-coverage reason matrix ─────────────────────────────────────

_GAP_REASONS = [
    (dict(memory_info_stream=False, handle_data_stream=False),
     "MemoryInfoListStream missing from this dump"),
    (dict(handle_data_stream=False), "HandleDataStream missing from this dump"),
    (dict(skipped_oversize=(_oversize_target(),)), "1 oversized region(s) skipped"),
    (dict(read_failed=1), "1 region(s) failed to read"),
    (dict(short_reads=1), "1 region(s) returned fewer bytes than declared"),
    (dict(c2_budget_exhausted=True, c2_budget_reason="deadline"),
     "C2-context scan budget exhausted (deadline)"),
    (dict(pipe_name_budget_exhausted=True, pipe_name_budget_reason="max_hits"),
     "pipe-name scan budget exhausted (max_hits)"),
]


@pytest.mark.parametrize("overrides, expected", _GAP_REASONS,
                         ids=[sorted(o)[0] for o, _ in _GAP_REASONS])
def test_every_distinct_coverage_gap_reason_is_reported_once(overrides, expected):
    coverage = _coverage(**overrides)
    status, reasons = project_coverage_v1(coverage)
    assert status in ("partial", "not_evaluated")
    assert sum(1 for r in reasons if expected in r) == 1, reasons
    report = PipeReport(score=0, coverage=coverage, results=(), evidence=PipeEvidence())
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "COVERAGE" in text
    # The same gap must also reach the typed record as a real, structured
    # limitation -- the v1.1 reason text and the CoverageReport are two
    # projections of the SAME snapshot and may never disagree about
    # whether coverage was complete.
    record = project_hunter_record(report)
    assert record.coverage.status.value != "complete"
    assert record.coverage.limitations


def test_oversized_region_names_the_address_and_the_cap():
    coverage = _coverage(skipped_oversize=(_oversize_target(),))
    _, reasons = project_coverage_v1(coverage)
    reason = next(r for r in reasons if "oversized region(s) skipped" in r)
    assert "0x00007ff600100000" in reason and "9 MB > 8 MB limit" in reason
    record = project_hunter_record(
        PipeReport(score=0, coverage=coverage, results=(), evidence=PipeEvidence()))
    limitation = next(l for l in record.coverage.limitations
                      if l.code.value == "SCAN_REGION_OVERSIZED_SKIPPED")
    assert limitation.source == "pipe_name_scan"
    assert limitation.targets[0].base_address == 0x7ff600100000


def test_the_two_budgets_are_separate_limitations_distinguished_by_scope():
    coverage = _coverage(c2_budget_exhausted=True, c2_budget_reason="deadline",
                          pipe_name_budget_exhausted=True, pipe_name_budget_reason="max_hits")
    record = project_hunter_record(
        PipeReport(score=0, coverage=coverage, results=(), evidence=PipeEvidence()))
    budget_limits = {l.scope: l.detail for l in record.coverage.limitations
                     if l.code.value == "SCAN_BUDGET_EXHAUSTED"}
    assert budget_limits == {"c2_context": "deadline", "pipe_name": "max_hits"}


def _budget_target(base):
    return dataclasses.replace(_oversize_target(base=base), size_limit=None)


def test_a_budget_limitation_carries_its_unresolved_regions_as_targets():
    targets = (_budget_target(0x1000000), _budget_target(0x2000000))
    coverage = _coverage(pipe_name_budget_exhausted=True, pipe_name_budget_reason="deadline",
                          pipe_name_budget_exhausted_targets=targets)
    record = project_hunter_record(
        PipeReport(score=0, coverage=coverage, results=(), evidence=PipeEvidence()))
    lim = next(l for l in record.coverage.limitations
               if l.code.value == "SCAN_BUDGET_EXHAUSTED" and l.scope == "pipe_name")
    assert lim.affected_count == 2
    assert [t.base_address for t in lim.targets] == [0x1000000, 0x2000000]


def test_a_budget_limitation_stays_reason_only_when_nothing_was_left_to_name():
    coverage = _coverage(c2_budget_exhausted=True, c2_budget_reason="deadline")
    record = project_hunter_record(
        PipeReport(score=0, coverage=coverage, results=(), evidence=PipeEvidence()))
    lim = next(l for l in record.coverage.limitations
               if l.code.value == "SCAN_BUDGET_EXHAUSTED" and l.scope == "c2_context")
    assert lim.affected_count is None and lim.targets == ()


def test_memory_info_absent_alone_stays_complete_in_both_coverage_projections():
    coverage = _coverage(memory_info_stream=False)
    status, reasons = project_coverage_v1(coverage)
    assert status == "complete"
    assert reasons == ["MemoryInfoListStream missing from this dump"]
    record = project_hunter_record(
        PipeReport(score=0, coverage=coverage, results=(), evidence=PipeEvidence()))
    assert record.coverage.status.value == "complete"


def test_system_dll_pipe_refs_are_verbose_only_scan_detail_never_a_coverage_gap():
    coverage = _coverage(image_pipe_refs=4, image_pipe_modules=("kernel32.dll", "ntdll.dll"))
    report = PipeReport(score=0, coverage=coverage, results=(), evidence=PipeEvidence())
    assert coverage.status == "complete"
    _, reasons = project_coverage_v1(coverage)
    assert not any("kernel32" in r for r in reasons)
    normal = "\n".join(render_console_lines(report, verbose=False))
    verbose = "\n".join(render_console_lines(report, verbose=True))
    assert "kernel32.dll" not in normal
    assert "4 pipe reference(s) in system DLLs" in verbose and "kernel32.dll" in verbose


# ── 5. Ordering / duplication / width ─────────────────────────────────────

def test_key_signals_order_is_corroboration_then_framework_then_handles_then_strings():
    """Issue #7's console scope, verbatim: handle-confirmed corroboration/
    detections precede framework matches, open-handle context, and
    string-only leads."""
    report = _all_checks_report()
    text = strip_ansi("\n".join(render_console_lines(report, verbose=False)))
    key_signals = text.split("KEY SIGNALS", 1)[1].split("WHY THIS VERDICT", 1)[0]
    positions = [key_signals.index(title) for title in (
        "Handle-confirmed pipe corroborated by memory evidence",
        "Known C2 framework pipe naming convention on an open handle",
        "Open pipe handles (HandleDataStream)",
        "Unbacked thread StartAddress near a handle-confirmed pipe",
        "Pipe name strings in non-system memory")]
    assert positions == sorted(positions), key_signals


def test_json_findings_order_is_construction_order_not_console_order():
    """The console's display order is a presentation decision; the
    `findings[]` array's order is a frozen wire contract, and the two are
    deliberately different for this hunter."""
    report = _all_checks_report()
    d = project_legacy_dict(report)
    assert [f["check"] for f in d["findings"]] == [r.check for r in report.results]
    assert [f["check"] for f in d["findings"]][:2] == ["pipe.open_handles",
                                                        "pipe.handle_framework_match"]


def test_an_unranked_check_still_reaches_key_signals():
    """A check added to aggregate.py without a `_DISPLAY_RANK` entry falls
    back to the shared tag ranking rather than silently vanishing."""
    handle = _handle()
    results = (_check(check="pipe.open_handles", tag=TAG_OBSERVATION,
                       confidence=CONFIDENCE_MEDIUM, evidence=(handle,), evidence_limit=20),)
    report = PipeReport(score=0, coverage=_coverage(), results=results,
                         evidence=PipeEvidence(handle_pipes=(handle,)))
    from dumpex.hunt.pipe.report_console import _console_finding, _ordered_for_display
    import dataclasses as dc
    finding = dc.replace(_console_finding(results[0], report), check="pipe.future_check")
    assert [f.check for f in _ordered_for_display([finding])] == ["pipe.future_check"]


def test_why_this_verdict_is_driven_by_corroboration_when_present():
    report = _all_checks_report()
    text = "\n".join(render_console_lines(report, verbose=False))
    why = text.split("WHY THIS VERDICT", 1)[1].split("COVERAGE")[0]
    assert "corroborated by C2-style context and/or live RIP/EIP execution" in why


def test_why_this_verdict_falls_back_to_the_framework_match_when_that_is_the_score():
    report = _detected_report(score=1)
    text = "\n".join(render_console_lines(report, verbose=False))
    why = text.split("WHY THIS VERDICT", 1)[1]
    assert "match a known C2/lateral-movement framework naming convention" in why


def test_why_this_verdict_falls_back_to_the_highest_ranked_lead():
    report = _string_lead_only_report()
    text = "\n".join(render_console_lines(report, verbose=False))
    assert "WHY THIS VERDICT" in text
    why = text.split("WHY THIS VERDICT", 1)[1]
    assert "byte-pattern scan" in why


def test_a_context_only_report_gets_no_why_this_verdict_block():
    text = "\n".join(render_console_lines(_clean_report(), verbose=False))
    assert "KEY SIGNALS" in text
    assert "WHY THIS VERDICT" not in text


@pytest.mark.parametrize("verbose", [False, True], ids=["normal", "verbose"])
def test_each_check_is_rendered_exactly_once(verbose):
    """No hand-rendered `_print_check` summary alongside the unified KEY
    SIGNALS loop -- the pre-migration renderer printed both."""
    report = _all_checks_report()
    text = strip_ansi("\n".join(render_console_lines(report, verbose=verbose)))
    for title in ("Handle-confirmed pipe corroborated by memory evidence",
                  "Known C2 framework pipe naming convention on an open handle",
                  "Open pipe handles (HandleDataStream)",
                  "Pipe name strings in non-system memory",
                  "Unbacked thread StartAddress near a handle-confirmed pipe"):
        assert text.count(title) == 1, title


def test_evidence_detail_is_verbose_only_and_precedes_coverage():
    """The three kinds of evidence this hunter collects but never turns
    into a check (framework attribution on string leads, C2-context
    evidence attached to string leads, unbacked threads) live in the
    bounded --verbose evidence section -- issue #1's hierarchy item 5,
    ahead of COVERAGE (item 6). Handle correlation for each entry is
    determined during projection (see test_c2_context_notes_a_matching_
    open_handle_instead_of_denying_one below), not at collection time."""
    report = _all_checks_report()
    normal = strip_ansi("\n".join(render_console_lines(report, verbose=False)))
    verbose = strip_ansi("\n".join(render_console_lines(report, verbose=True)))
    assert "EVIDENCE DETAIL" not in normal
    assert "unbacked thread(s) starting in a pipe-name-string region" not in normal
    assert "EVIDENCE DETAIL" in verbose
    assert verbose.index("EVIDENCE DETAIL") < verbose.index("\n  COVERAGE\n")
    detail = verbose.split("EVIDENCE DETAIL", 1)[1]
    assert "attribution only, never scored" in detail
    # _all_checks_report()'s c2_context/framework_string_hits entries share
    # their canonical name with an open handle (see its own comment) -- the
    # neutral, handle-aware wording must appear, NOT the blanket
    # "uncorrelated to any open handle" claim a matched name would falsify.
    assert "this name also has an open handle" in detail
    assert "uncorrelated to any open handle" not in detail
    assert "unbacked thread(s) starting in a pipe-name-string region" in detail


def test_evidence_detail_is_bounded():
    """A pathological dump must not turn --verbose into an unbounded dump
    of every region the scan touched."""
    leads = tuple(_string_lead(offset=0x400 + i, name=f"\\.\\pipe\\beacon_{i}",
                                sha256=f"{i:064x}") for i in range(14))
    hits = tuple(_framework_string_hit(pipe_name=f"\\.\\pipe\\beacon_{i}", string_hit=lead)
                 for i, lead in enumerate(leads))
    report = PipeReport(score=0, coverage=_coverage(), results=(),
                         evidence=PipeEvidence(string_leads=leads, framework_string_hits=hits))
    verbose = strip_ansi("\n".join(render_console_lines(report, verbose=True)))
    assert "beacon_9" in verbose
    assert "beacon_13" not in verbose
    assert "... and 4 more" in verbose


# ── P1 regression: a matched-handle string lead must not be reported as
# uncorrelated in the informational c2_context/framework_string_hits
# buckets, even though those buckets are populated independently of
# handle correlation (see report_console._evidence_detail_lines and
# aggregate.build_report's pipe.string_scan_lead limitations text). ──────

def test_c2_context_notes_a_matching_open_handle_instead_of_denying_one():
    handle = _handle(canonical_name="msagent_1337")
    lead   = _string_lead(name="\\\\.\\pipe\\msagent_1337")
    evidence = PipeEvidence(handle_pipes=(handle,), string_leads=(lead,),
                             c2_context=(_c2_context(string_hit=lead),))
    report = PipeReport(score=0, coverage=_coverage(), results=(), evidence=evidence)
    verbose = strip_ansi("\n".join(render_console_lines(report, verbose=True)))
    assert "this name also has an open handle" in verbose
    assert "uncorrelated to any open handle" not in verbose


def test_c2_context_still_reports_uncorrelated_when_no_handle_matches():
    lead = _string_lead(name="\\\\.\\pipe\\unrelated")
    evidence = PipeEvidence(string_leads=(lead,), c2_context=(_c2_context(string_hit=lead),))
    report = PipeReport(score=0, coverage=_coverage(), results=(), evidence=evidence)
    verbose = strip_ansi("\n".join(render_console_lines(report, verbose=True)))
    assert "no corresponding open handle for this exact name" in verbose
    assert "this name also has an open handle" not in verbose


def test_framework_string_hit_notes_a_matching_open_handle():
    handle = _handle(canonical_name="msagent_1337")
    lead   = _string_lead(name="\\\\.\\pipe\\msagent_1337")
    evidence = PipeEvidence(handle_pipes=(handle,), string_leads=(lead,),
                             framework_string_hits=(_framework_string_hit(string_hit=lead),))
    report = PipeReport(score=0, coverage=_coverage(), results=(), evidence=evidence)
    verbose = strip_ansi("\n".join(render_console_lines(report, verbose=True)))
    assert "this name also has an open handle" in verbose


def test_string_scan_lead_limitation_when_every_lead_matches_a_handle():
    """`pipe.string_scan_lead`'s wire-facing `limitations` text (embedded
    in the v1.1 findings dict and the current-schema Finding) must not
    claim an unmatched remainder ("others") when EVERY string lead it
    describes shares its canonical name with an open handle -- a plain
    "any correlated" boolean collapses this case into the same wording as
    a genuine partial match, which is false when nothing is left
    unmatched. The count must be exact (1/1 here), and the text must still
    make clear the string match itself stays unscored."""
    handle = _handle(canonical_name="msagent_1337")
    lead   = _string_lead(name="\\\\.\\pipe\\msagent_1337")
    report = pipe_aggregate.build_report(handle_pipes=(handle,), string_leads=(lead,),
                                          handle_data_stream=True)
    check = next(r for r in report.results if r.check == "pipe.string_scan_lead")
    text = " ".join(check.limitations)
    assert "No corresponding open handle" not in text
    assert "others" not in text
    assert "Every one of these 1 occurrence(s) shares a canonical name" in text
    assert "still not scored" in text


def test_string_scan_lead_limitation_when_only_some_leads_match_a_handle():
    """A genuine mixed case: one lead matches an open handle, one does
    not -- the text must name the exact split (1 of 2, 1 remaining), not
    a vague "some ... others"."""
    handle       = _handle(canonical_name="msagent_1337")
    matched_lead = _string_lead(name="\\\\.\\pipe\\msagent_1337")
    other_lead   = _string_lead(offset=0x400, name="\\\\.\\pipe\\unrelated", sha256="e" * 64)
    report = pipe_aggregate.build_report(
        handle_pipes=(handle,), string_leads=(matched_lead, other_lead),
        handle_data_stream=True)
    check = next(r for r in report.results if r.check == "pipe.string_scan_lead")
    text = " ".join(check.limitations)
    assert "1 of these 2 occurrence(s) share a canonical name" in text
    assert "the remaining 1 have no corresponding open handle" in text


def test_string_scan_lead_limitation_keeps_original_wording_when_uncorrelated():
    """No lead matches any handle at all (0/N) -- the original, unqualified
    wording."""
    lead = _string_lead(name="\\\\.\\pipe\\unrelated")
    report = pipe_aggregate.build_report(string_leads=(lead,), handle_data_stream=True)
    check = next(r for r in report.results if r.check == "pipe.string_scan_lead")
    assert check.limitations == ("No corresponding open handle found for this exact name.",)


# ── P2 regression: pipe_va can never diverge from string_hit.va -- it is a
# derived property, not a second stored field (see models.py's own
# CorroboratedHandleEvidence/StartAddressLeadEvidence docstrings). ───────

def test_corroborated_handle_pipe_va_always_tracks_its_own_string_hit():
    lead = _string_lead(offset=0x555, name="\\\\.\\pipe\\tracked")
    corrob = _corroborated(string_hit=lead)
    assert corrob.pipe_va == lead.va
    assert "pipe_va" not in {f.name for f in dataclasses.fields(CorroboratedHandleEvidence)}
    with pytest.raises(TypeError):
        CorroboratedHandleEvidence(handle=_handle(), string_hit=lead, pipe_va=0xdead)


def test_start_address_lead_pipe_va_always_tracks_its_own_string_hit():
    lead = _string_lead(offset=0x555, name="\\\\.\\pipe\\tracked")
    lead_ev = _start_lead(string_hit=lead)
    assert lead_ev.pipe_va == lead.va
    assert "pipe_va" not in {f.name for f in dataclasses.fields(StartAddressLeadEvidence)}


# ── P3 regression: c2_context/framework_string_hits must cite one of the
# Report's OWN string_leads objects by identity, never a reconstructed
# equal copy (see domain.PipeEvidence's own identity-subset check). ──────

def test_c2_context_rejects_a_string_hit_that_is_not_one_of_the_reports_own():
    foreign_lead = _string_lead(name="\\\\.\\pipe\\foreign")
    with pytest.raises(ValueError, match="not one of"):
        PipeEvidence(c2_context=(_c2_context(string_hit=foreign_lead),))


def test_framework_string_hit_rejects_a_string_hit_that_is_not_one_of_the_reports_own():
    foreign_lead = _string_lead(name="\\\\.\\pipe\\foreign")
    with pytest.raises(ValueError, match="not one of"):
        PipeEvidence(framework_string_hits=(_framework_string_hit(string_hit=foreign_lead),))


def test_console_wraps_within_requested_width():
    result = _check(check="pipe.string_scan_lead", tag=TAG_LEAD, confidence=CONFIDENCE_LOW,
                    inference="x " * 60 + "end of a deliberately very long inference sentence "
                                "meant to force wrapping across several lines of output")
    report = PipeReport(score=0, coverage=_coverage(short_reads=1), results=(result,),
                         evidence=PipeEvidence())
    lines = render_console_lines(report, verbose=False, width=80)
    for line in lines:
        # The verdict key/value block and the fixed trailing hint are
        # deliberately never wrapped (mirrors every completed pilot:
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

    legacy_first["handle_pipes"].append("tampered")
    legacy_first["findings"].append("tampered")
    legacy_first["coverage_reasons"].append("tampered")
    legacy_third = project_legacy_dict(report)
    assert "tampered" not in legacy_third["handle_pipes"]
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




# ── 8. The "empty/error" acceptance axis ──────────────────────────────────
# `_not_evaluated_report()` (both streams absent, no results) stands in for
# "empty" throughout this file -- see test_injection_projectors.py's own
# docstring for why "error" (a hunt run that failed outright) is
# deliberately not representable by this domain model at all; the same
# reasoning applies unchanged to PipeReport.

def test_pipe_report_status_has_no_error_representation():
    from dumpex.hunt._ui import DETECTED, INCONCLUSIVE, NOT_DETECTED_IN_SCANNED_SCOPE, \
        NOT_EVALUATED
    known = {DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, INCONCLUSIVE, NOT_EVALUATED}
    for report_fn in _ALL_REPORTS:
        assert report_fn().status in known

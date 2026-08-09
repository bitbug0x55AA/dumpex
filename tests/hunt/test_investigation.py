"""Unit tests for dumpex.hunt._investigation.build_investigation_queue() --
the default, metadata-only skipped-target investigation queue for
`--hunt all` (issue #19). Builds synthetic `HunterRecord`/`ScanTarget`/
`CoverageLimitation` directly (same style as tests/hunt/test_coverage.py
and tests/unit/test_hunt_region_correlation.py) -- no real dump, no real
memory content, and no read whose cost scales with a skipped target's
size.
"""
import pytest

from dumpex.hunt._investigation import (
    build_investigation_queue, InvestigationAction, SkipRelationship, TriageInfo,
    RecommendedAction, _derive_priority, _has_exec_signal,
)
from dumpex.output.coverage import (
    ScanTarget, ScanTargetKind, CoverageLimitation, LimitationCode,
    CoverageReport, CoverageStatus,
)
from dumpex.output.records import (
    HunterRecord, PipeDetails, ObfuscationDetails, StompingDetails, InjectionDetails,
)
from tests.fixtures.fakes import Region


def target(base=0x1000, size=20 * 1024 * 1024, size_limit=8 * 1024 * 1024,
           file_offset=999, type_="MEM_PRIVATE", protection="PAGE_READWRITE",
           kind=ScanTargetKind.MEMORY_REGION):
    kwargs = dict(kind=kind, base_address=base, size=size, size_limit=size_limit,
                  file_offset=file_offset)
    if kind == ScanTargetKind.MEMORY_REGION:
        kwargs.update(allocation_base=base, state="MEM_COMMIT", type=type_, protection=protection)
    return ScanTarget(**kwargs)


def limitation(source, targets, scope=None):
    return CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                               source=source, scope=scope, affected_count=len(targets),
                               targets=tuple(targets))


def pipe_record(limitations=(), status="NOT_DETECTED_IN_SCANNED_SCOPE"):
    details = PipeDetails(handle_pipes=[], private_pipes=[], c2_context=[],
                           framework_pipes=[], unbacked_in_rgn=[])
    return HunterRecord(hunter="pipe", status=status, score=0, max_score=3,
        verdict_level="clean", confidence="none", lead_count=0, review_priority="none",
        coverage=CoverageReport(status=CoverageStatus.PARTIAL, limitations=list(limitations)),
        findings=[], details=details)


def obfuscation_record(limitations=()):
    details = ObfuscationDetails(sleep_mask=[], entropy=[], base64=[], xor=[],
                                  compressed=[], hidden_pe=[], hidden_shellcode=[])
    return HunterRecord(hunter="obfuscation", status="NOT_DETECTED_IN_SCANNED_SCOPE", score=0,
        max_score=2, verdict_level="clean", confidence="none", lead_count=0,
        review_priority="none",
        coverage=CoverageReport(status=CoverageStatus.PARTIAL, limitations=list(limitations)),
        findings=[], details=details)


def stomping_record(limitations=(), protection_leads=(), status="DETECTED", lead_count=1):
    details = StompingDetails(protection_leads=list(protection_leads), verified_changes=[])
    detected = status == "DETECTED"
    return HunterRecord(hunter="stomping", status=status, score=1 if detected else 0, max_score=2,
        verdict_level="likely" if detected else "clean", confidence="high" if detected else "none",
        lead_count=lead_count, review_priority="high" if detected else "none",
        coverage=CoverageReport(status=CoverageStatus.PARTIAL, limitations=list(limitations)),
        findings=[], details=details)


def injection_record(rwx=(), status="DETECTED", lead_count=1):
    details = InjectionDetails(
        rwx=list(rwx), hidden_pe_validated=[], hidden_pe_unvalidated=[],
        suspicious_validated_pe_hits=[], informational_validated_pe_hits=[],
        threads=[], thread_contexts=[], rwx_and_pe_alloc_bases=[],
        rip_hits=[], rip_full_correlation=[], start_hits=[])
    detected = status == "DETECTED"
    return HunterRecord(hunter="injection", status=status, score=3 if detected else 0, max_score=3,
        verdict_level="high" if detected else "clean", confidence="high" if detected else "none",
        lead_count=lead_count, review_priority="high" if detected else "none",
        coverage=CoverageReport(status=CoverageStatus.COMPLETE), findings=[], details=details)


# ── input validation ─────────────────────────────────────────────────────

def test_rejects_non_hunter_record_list():
    with pytest.raises(TypeError):
        build_investigation_queue([object()], [])


def test_empty_when_nothing_skipped():
    assert build_investigation_queue([pipe_record()], []) == []


# ── dedup ─────────────────────────────────────────────────────────────────

def test_two_different_hunters_same_physical_region_dedup_to_one_action():
    t1 = target(base=0x2000, size_limit=8 * 1024 * 1024)
    t2 = target(base=0x2000, size_limit=10 * 1024 * 1024)
    records = [
        pipe_record([limitation("pipe_name_scan", [t1])]),
        obfuscation_record([limitation("encoding_scan", [t2], scope="entropy")]),
    ]
    actions = build_investigation_queue(records, [])
    assert len(actions) == 1
    action = actions[0]
    assert len(action.skipped_by) == 2
    hunters = {s.hunter for s in action.skipped_by}
    assert hunters == {"pipe", "obfuscation"}
    assert "MULTIPLE_SCOPES_SKIPPED" in action.priority_reason_codes


def test_obfuscation_three_layers_same_hunter_dedup_to_one_action_with_three_skips():
    base = 0x3000
    t_sleep = target(base=base, size_limit=10 * 1024 * 1024)
    t_entropy = target(base=base, size_limit=10 * 1024 * 1024)
    t_decode = target(base=base, size_limit=2 * 1024 * 1024)
    lims = [
        limitation("encoding_scan", [t_sleep], scope="sleep_mask"),
        limitation("encoding_scan", [t_entropy], scope="entropy"),
        limitation("encoding_scan", [t_decode], scope="decode"),
    ]
    actions = build_investigation_queue([obfuscation_record(lims)], [])
    assert len(actions) == 1
    action = actions[0]
    assert len(action.skipped_by) == 3
    assert {s.scope for s in action.skipped_by} == {"sleep_mask", "entropy", "decode"}
    assert "MULTIPLE_SCOPES_SKIPPED" in action.priority_reason_codes


def test_two_distinct_regions_stay_two_actions():
    t1 = target(base=0x4000)
    t2 = target(base=0x5000)
    records = [pipe_record([limitation("pipe_name_scan", [t1, t2])])]
    actions = build_investigation_queue(records, [])
    assert len(actions) == 2
    assert {a.target.base_address for a in actions} == {0x4000, 0x5000}
    assert all(len(a.skipped_by) == 1 for a in actions)


def test_different_size_same_base_are_not_deduped():
    t1 = target(base=0x6000, size=20 * 1024 * 1024)
    t2 = target(base=0x6000, size=40 * 1024 * 1024)
    records = [
        pipe_record([limitation("pipe_name_scan", [t1])]),
        obfuscation_record([limitation("encoding_scan", [t2], scope="entropy")]),
    ]
    actions = build_investigation_queue(records, [])
    assert len(actions) == 2


# ── priority truth table ─────────────────────────────────────────────────

def test_priority_truth_table():
    assert _derive_priority(False, False) == "low"
    assert _derive_priority(True, False) == "medium"
    assert _derive_priority(False, True) == "medium"
    assert _derive_priority(True, True) == "high"


def test_priority_low_when_no_exec_and_single_skip_no_correlation():
    t = target(base=0x7000, type_="MEM_MAPPED", protection="PAGE_READWRITE")
    actions = build_investigation_queue([pipe_record([limitation("pipe_name_scan", [t])])], [])
    assert actions[0].priority == "low"
    assert actions[0].priority_reason_codes == ()


def test_plain_private_readwrite_memory_gets_no_exec_signal_regression():
    # Regression: ordinary MEM_PRIVATE heap memory (PAGE_READWRITE, no
    # execute permission at all) is completely mundane and must NEVER be
    # flagged as "private executable" -- only PRIVATE memory that is ALSO
    # executable is suspicious.
    t = target(base=0x8000, type_="MEM_PRIVATE", protection="PAGE_READWRITE")
    actions = build_investigation_queue([pipe_record([limitation("pipe_name_scan", [t])])], [])
    assert actions[0].priority == "low"
    assert actions[0].priority_reason_codes == ()


def test_priority_medium_for_private_executable_memory():
    t = target(base=0x8100, type_="MEM_PRIVATE", protection="PAGE_EXECUTE_READ")
    actions = build_investigation_queue([pipe_record([limitation("pipe_name_scan", [t])])], [])
    assert actions[0].priority == "medium"
    assert actions[0].priority_reason_codes == ("PRIVATE_EXECUTABLE_MEMORY",)


def test_priority_medium_for_rwx_alone():
    t = target(base=0x9000, type_="MEM_MAPPED", protection="PAGE_EXECUTE_READWRITE")
    actions = build_investigation_queue([pipe_record([limitation("pipe_name_scan", [t])])], [])
    assert actions[0].priority == "medium"
    assert actions[0].priority_reason_codes == ("RWX_PROTECTION",)


def test_ordinary_execute_read_mapping_gets_no_rwx_reason_code_regression():
    # Regression: PAGE_EXECUTE_READ (an entirely ordinary read+execute
    # code mapping, e.g. a loaded DLL's .text section) must never be
    # mislabeled RWX_PROTECTION -- RWX means read+write+execute
    # specifically, not "any executable protection".
    t = target(base=0x9100, type_="MEM_MAPPED", protection="PAGE_EXECUTE_READ")
    actions = build_investigation_queue([pipe_record([limitation("pipe_name_scan", [t])])], [])
    assert actions[0].priority == "low"
    assert actions[0].priority_reason_codes == ()


def test_private_and_rwx_together_get_both_reason_codes():
    # The two facts are independent, not mutually exclusive -- a target
    # that is BOTH private AND true RWX gets both reason codes, not just
    # the first one checked.
    t = target(base=0x9200, type_="MEM_PRIVATE", protection="PAGE_EXECUTE_READWRITE")
    actions = build_investigation_queue([pipe_record([limitation("pipe_name_scan", [t])])], [])
    assert set(actions[0].priority_reason_codes) == {"PRIVATE_EXECUTABLE_MEMORY", "RWX_PROTECTION"}


def test_has_exec_signal_helper():
    assert _has_exec_signal(target(type_="MEM_PRIVATE", protection="PAGE_READWRITE")) is False
    assert _has_exec_signal(target(type_="MEM_PRIVATE", protection="PAGE_EXECUTE_READ")) is True
    assert _has_exec_signal(target(type_="MEM_MAPPED", protection="PAGE_EXECUTE_READ")) is False
    assert _has_exec_signal(target(type_="MEM_MAPPED", protection="PAGE_EXECUTE_READWRITE")) is True
    assert _has_exec_signal(target(type_="MEM_MAPPED", protection="PAGE_READWRITE")) is False


def test_memory_segment_target_never_gets_exec_signal():
    seg = target(base=0xA000, kind=ScanTargetKind.MEMORY_SEGMENT, size=60 * 1024 * 1024,
                 size_limit=50 * 1024 * 1024)
    lim = CoverageLimitation(code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED,
                              source="segment_scan", affected_count=1, targets=(seg,))
    actions = build_investigation_queue([pipe_record([lim])], [])
    assert actions[0].priority_reason_codes == ()
    assert actions[0].priority == "low"


def test_correlated_region_evidence_bumps_priority():
    from tests.fixtures.hunt_records import region as region_ref

    base = 0xB000
    t = target(base=base, type_="MEM_MAPPED", protection="PAGE_READWRITE")
    ref = region_ref(addr=f"0x{base:016x}", size=t.size)
    # pipe skips this target for being oversized; MEANWHILE two OTHER,
    # DIFFERENT hunters (injection's rwx, stomping's protection_leads)
    # both have real DETECTED evidence resolving to the SAME region, so
    # build_region_correlations() finds a genuine cross-hunter
    # correlation there -- independent of, and in addition to, the
    # oversized-skip itself.
    pipe = pipe_record([limitation("pipe_name_scan", [t])])
    inj = injection_record(rwx=[ref])
    stomp = stomping_record(protection_leads=[
        {"module": "a.dll", "va_start": f"0x{base:016x}",
         "region": {"base_address": f"0x{base:016x}", "size": t.size, "allocation_base": None}}])
    regions = [Region(base, base, t.size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_MAPPED")]
    actions = build_investigation_queue([pipe, inj, stomp], regions)
    assert len(actions) == 1
    assert "CORRELATED_REGION_EVIDENCE" in actions[0].priority_reason_codes
    assert actions[0].priority == "medium"


# ── evidence_availability ────────────────────────────────────────────────

def test_evidence_availability_captured_vs_not():
    captured = target(base=0xC000, file_offset=123)
    not_captured = target(base=0xD000, file_offset=None)
    records = [pipe_record([limitation("pipe_name_scan", [captured, not_captured])])]
    actions = {a.target.base_address: a for a in build_investigation_queue(records, [])}
    assert actions[0xC000].evidence_availability == "captured"
    assert actions[0xD000].evidence_availability == "not_captured"


# ── recommended_actions ──────────────────────────────────────────────────

def test_recommended_actions_captured_low_priority():
    t = target(base=0xE000, type_="MEM_MAPPED", protection="PAGE_READWRITE", file_offset=1)
    actions = build_investigation_queue([pipe_record([limitation("pipe_name_scan", [t])])], [])
    types = [a.type for a in actions[0].recommended_actions]
    assert types == ["inspect_metadata", "extract_captured_range", "targeted_hunter_rescan"]


def test_recommended_actions_not_captured_adds_recollect():
    t = target(base=0xF000, type_="MEM_MAPPED", protection="PAGE_READWRITE", file_offset=None)
    actions = build_investigation_queue([pipe_record([limitation("pipe_name_scan", [t])])], [])
    types = [a.type for a in actions[0].recommended_actions]
    assert "recollect_dump" in types
    assert "extract_captured_range" not in types


def test_recommended_actions_high_priority_adds_preserve_artifact():
    base = 0x11000
    t1 = target(base=base, size_limit=8 * 1024 * 1024, type_="MEM_PRIVATE",
                protection="PAGE_EXECUTE_READWRITE")
    t2 = target(base=base, size_limit=10 * 1024 * 1024, type_="MEM_PRIVATE",
                protection="PAGE_EXECUTE_READWRITE")
    records = [
        pipe_record([limitation("pipe_name_scan", [t1])]),
        obfuscation_record([limitation("encoding_scan", [t2], scope="entropy")]),
    ]
    actions = build_investigation_queue(records, [])
    assert actions[0].priority == "high"
    types = [a.type for a in actions[0].recommended_actions]
    assert "preserve_artifact" in types


def test_targeted_hunter_rescan_names_all_skipping_hunters_in_fixed_order():
    base = 0x12000
    t1 = target(base=base, size_limit=8 * 1024 * 1024)
    t2 = target(base=base, size_limit=10 * 1024 * 1024)
    records = [
        obfuscation_record([limitation("encoding_scan", [t2], scope="entropy")]),
        pipe_record([limitation("pipe_name_scan", [t1])]),
    ]
    actions = build_investigation_queue(records, [])
    rescan = next(a for a in actions[0].recommended_actions if a.type == "targeted_hunter_rescan")
    # HUNTERS' own fixed order (pipe before obfuscation), not input order.
    assert rescan.hunters == ("pipe", "obfuscation")


# ── determinism / sort order ─────────────────────────────────────────────

def test_sort_order_priority_then_skip_count_then_address():
    low = target(base=0x100, type_="MEM_MAPPED", protection="PAGE_READWRITE")
    high_a = target(base=0x300, size_limit=8 * 1024 * 1024, type_="MEM_PRIVATE",
                     protection="PAGE_EXECUTE_READWRITE")
    high_b = target(base=0x300, size_limit=10 * 1024 * 1024, type_="MEM_PRIVATE",
                     protection="PAGE_EXECUTE_READWRITE")
    records = [
        pipe_record([limitation("pipe_name_scan", [low, high_a])]),
        obfuscation_record([limitation("encoding_scan", [high_b], scope="entropy")]),
    ]
    actions = build_investigation_queue(records, [])
    assert [a.target.base_address for a in actions] == [0x300, 0x100]
    assert actions[0].priority == "high"
    assert actions[1].priority == "low"


def test_result_is_deterministic_across_calls():
    t1 = target(base=0x400)
    t2 = target(base=0x500)
    records = [pipe_record([limitation("pipe_name_scan", [t1, t2])])]
    a1 = build_investigation_queue(records, [])
    a2 = build_investigation_queue(records, [])
    assert [a.to_dict() for a in a1] == [a.to_dict() for a in a2]


# ── dataclass validation ─────────────────────────────────────────────────

def test_skip_relationship_rejects_unknown_hunter():
    with pytest.raises(ValueError):
        SkipRelationship(hunter="not-a-hunter", source="x", size_limit=1)


def test_triage_info_metadata_mode_rejects_nondefault_fields():
    with pytest.raises(ValueError):
        TriageInfo(mode="metadata", status="partial")
    with pytest.raises(ValueError):
        TriageInfo(mode="metadata", bytes_examined=1)
    with pytest.raises(ValueError):
        TriageInfo(mode="metadata", region_fully_examined=True)


def test_triage_info_rejects_unknown_mode_or_status():
    with pytest.raises(ValueError):
        TriageInfo(mode="not-a-real-mode")
    with pytest.raises(ValueError):
        TriageInfo(mode="metadata", status="not-a-real-status")


def test_triage_info_deep_mode_is_reserved_but_constructible():
    # Phase-2-compatible shape (per the issue's own follow-up comment):
    # "deep" mode and the wider TriageStatus vocabulary are already valid
    # so a future --triage-skipped phase does not require a schema break.
    # This phase never actually constructs mode="deep" itself.
    info = TriageInfo(mode="deep", status="partial", bytes_examined=4096,
                       region_fully_examined=True)
    assert info.to_dict() == {"mode": "deep", "status": "partial",
                               "bytes_examined": 4096, "region_fully_examined": True}


def test_recommended_action_rejects_hunters_on_wrong_type():
    with pytest.raises(ValueError):
        RecommendedAction(type="inspect_metadata", hunters=("pipe",))


def test_recommended_action_targeted_hunter_rescan_requires_nonempty_hunters():
    with pytest.raises(ValueError):
        RecommendedAction(type="targeted_hunter_rescan", hunters=())
    with pytest.raises(ValueError):
        RecommendedAction(type="targeted_hunter_rescan")   # default hunters=()


def test_preserve_artifact_not_recommended_when_evidence_not_captured():
    # A high-priority target whose bytes were never captured in this dump
    # has nothing local to preserve -- preserve_artifact must never appear
    # alongside recollect_dump.
    base = 0x13000
    t1 = target(base=base, size_limit=8 * 1024 * 1024, type_="MEM_PRIVATE",
                protection="PAGE_EXECUTE_READWRITE", file_offset=None)
    t2 = target(base=base, size_limit=10 * 1024 * 1024, type_="MEM_PRIVATE",
                protection="PAGE_EXECUTE_READWRITE", file_offset=None)
    records = [
        pipe_record([limitation("pipe_name_scan", [t1])]),
        obfuscation_record([limitation("encoding_scan", [t2], scope="entropy")]),
    ]
    actions = build_investigation_queue(records, [])
    assert actions[0].priority == "high"
    assert actions[0].evidence_availability == "not_captured"
    types = [a.type for a in actions[0].recommended_actions]
    assert "preserve_artifact" not in types
    assert "recollect_dump" in types


def test_investigation_action_requires_nonempty_skipped_by():
    t = target()
    with pytest.raises(ValueError):
        InvestigationAction(
            target=t, skipped_by=(), priority="low", priority_reason_codes=(),
            evidence_availability="captured", triage=TriageInfo(),
            recommended_actions=(RecommendedAction(type="inspect_metadata"),))

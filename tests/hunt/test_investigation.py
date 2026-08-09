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
    ContentFinding, MAX_FINDINGS_PER_TARGET, MAX_FINDING_VALUE_LEN,
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


# ── TriageInfo mode="deep" invariants (issue #19 Phase 2) ──────────────────
# dumpex.hunt._deep_triage.run_deep_triage() is the only real constructor of
# mode="deep" TriageInfo instances (see tests/hunt/test_deep_triage.py for
# that engine's own tests) -- these exercise TriageInfo.__post_init__'s own
# validation directly, the one place both producers (the always-on
# metadata pass and the opt-in deep pass) share their invariants.

@pytest.mark.parametrize("status", ["not_captured", "budget_deferred", "unreadable"])
def test_triage_info_deep_mode_zero_byte_status_accepts_zero_bytes(status):
    info = TriageInfo(mode="deep", status=status, bytes_examined=0,
                       region_fully_examined=False, content_reason_codes=())
    assert info.to_dict() == {
        "mode": "deep", "status": status, "bytes_examined": 0,
        "region_fully_examined": False, "content_reason_codes": [], "findings": [],
        "finding_count": 0, "findings_truncated": False,
    }


@pytest.mark.parametrize("status", ["not_captured", "budget_deferred", "unreadable"])
def test_triage_info_deep_mode_zero_byte_status_rejects_nonzero_bytes(status):
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status=status, bytes_examined=1,
                   region_fully_examined=False)


@pytest.mark.parametrize("status", ["not_captured", "budget_deferred", "unreadable"])
def test_triage_info_deep_mode_zero_byte_status_rejects_region_fully_examined(status):
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status=status, bytes_examined=0,
                   region_fully_examined=True)


@pytest.mark.parametrize("status", ["not_captured", "budget_deferred", "unreadable"])
def test_triage_info_deep_mode_zero_byte_status_rejects_content_reason_codes(status):
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status=status, bytes_examined=0,
                   region_fully_examined=False,
                   content_reason_codes=("IOC_PATTERN_STRING_MATCH",))


def test_triage_info_deep_mode_completed_requires_region_fully_examined_true():
    info = TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                       region_fully_examined=True)
    assert info.region_fully_examined is True
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                   region_fully_examined=False)


@pytest.mark.parametrize("status", ["partial", "clamped"])
def test_triage_info_deep_mode_incomplete_read_requires_region_fully_examined_false(status):
    info = TriageInfo(mode="deep", status=status, bytes_examined=4096,
                       region_fully_examined=False)
    assert info.region_fully_examined is False
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status=status, bytes_examined=4096,
                   region_fully_examined=True)


@pytest.mark.parametrize("status", ["completed", "partial", "clamped"])
def test_triage_info_deep_mode_real_read_status_requires_positive_bytes_examined(status):
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status=status, bytes_examined=0,
                   region_fully_examined=(status == "completed"))


def test_triage_info_deep_mode_completed_accepts_content_reason_codes():
    info = TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                       region_fully_examined=True,
                       content_reason_codes=("IOC_PATTERN_STRING_MATCH", "INJECTED_PE_HEADER"))
    assert info.content_reason_codes == ("IOC_PATTERN_STRING_MATCH", "INJECTED_PE_HEADER")
    assert info.to_dict()["content_reason_codes"] == ["IOC_PATTERN_STRING_MATCH", "INJECTED_PE_HEADER"]


def test_triage_info_content_reason_codes_rejects_unknown_value():
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                   region_fully_examined=True, content_reason_codes=("NOT_A_REAL_CODE",))


def test_triage_info_metadata_mode_rejects_nonempty_content_reason_codes():
    with pytest.raises(ValueError):
        TriageInfo(mode="metadata", status="completed", bytes_examined=0,
                   region_fully_examined=False,
                   content_reason_codes=("IOC_PATTERN_STRING_MATCH",))


def test_triage_info_metadata_mode_default_still_valid():
    # Unchanged default-construction contract from Phase 1.
    info = TriageInfo()
    assert info.to_dict() == {"mode": "metadata", "status": "completed",
                               "bytes_examined": 0, "region_fully_examined": False,
                               "content_reason_codes": [], "findings": [],
                               "finding_count": 0, "findings_truncated": False}


# ── ContentFinding + TriageInfo.findings (issue #19 Phase 2 review, item 4) ──

def _ioc_finding(**overrides):
    kwargs = dict(type="ioc_string", address="0x000001d400001230", offset=16,
                  encoding="ASCII", value="http://evil.example/beacon",
                  is_network_pattern=True)
    kwargs.update(overrides)
    return ContentFinding(**kwargs)


def _mz_finding(**overrides):
    kwargs = dict(type="mz_header", address="0x000001d400000000",
                  module_context="unregistered")
    kwargs.update(overrides)
    return ContentFinding(**kwargs)


def test_content_finding_ioc_string_valid_round_trips():
    f = _ioc_finding()
    assert f.to_dict() == {
        "type": "ioc_string", "address": "0x000001d400001230", "offset": 16,
        "encoding": "ASCII", "value": "http://evil.example/beacon",
        "is_network_pattern": True, "module_context": None,
    }


def test_content_finding_mz_header_valid_round_trips():
    f = _mz_finding()
    assert f.to_dict() == {
        "type": "mz_header", "address": "0x000001d400000000", "offset": None,
        "encoding": None, "value": None, "is_network_pattern": None,
        "module_context": "unregistered",
    }


def test_content_finding_ioc_string_rejects_module_context():
    with pytest.raises(ValueError):
        _ioc_finding(module_context="unregistered")


def test_content_finding_mz_header_rejects_ioc_only_fields():
    with pytest.raises(ValueError):
        _mz_finding(offset=0)


def test_content_finding_ioc_string_requires_valid_encoding():
    with pytest.raises(ValueError):
        _ioc_finding(encoding="LATIN1")


def test_content_finding_mz_header_requires_valid_module_context():
    with pytest.raises(ValueError):
        _mz_finding(module_context="bogus")


def test_content_finding_value_length_is_capped():
    with pytest.raises(ValueError):
        _ioc_finding(value="A" * (MAX_FINDING_VALUE_LEN + 1))
    # Exactly at the cap is fine.
    _ioc_finding(value="A" * MAX_FINDING_VALUE_LEN)


def test_triage_info_findings_must_be_content_finding_instances():
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                   region_fully_examined=True, content_reason_codes=("IOC_PATTERN_STRING_MATCH",),
                   findings=({"type": "ioc_string"},))


def test_triage_info_findings_capped_at_max_per_target():
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                   region_fully_examined=True, content_reason_codes=("IOC_PATTERN_STRING_MATCH",),
                   findings=tuple(_ioc_finding() for _ in range(MAX_FINDINGS_PER_TARGET + 1)),
                   finding_count=MAX_FINDINGS_PER_TARGET + 1, findings_truncated=False)
    # Exactly at the cap is fine.
    TriageInfo(mode="deep", status="completed", bytes_examined=4096,
               region_fully_examined=True, content_reason_codes=("IOC_PATTERN_STRING_MATCH",),
               findings=tuple(_ioc_finding() for _ in range(MAX_FINDINGS_PER_TARGET)),
               finding_count=MAX_FINDINGS_PER_TARGET, findings_truncated=False)


@pytest.mark.parametrize("status", ["not_captured", "budget_deferred", "unreadable"])
def test_triage_info_zero_byte_status_rejects_nonempty_findings(status):
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status=status, bytes_examined=0,
                   region_fully_examined=False, findings=(_mz_finding(),))


def test_triage_info_metadata_mode_rejects_nonempty_findings():
    with pytest.raises(ValueError):
        TriageInfo(mode="metadata", status="completed", bytes_examined=0,
                   region_fully_examined=False, findings=(_mz_finding(),))


def test_triage_info_deep_completed_accepts_and_round_trips_findings():
    info = TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                       region_fully_examined=True,
                       content_reason_codes=("IOC_PATTERN_STRING_MATCH", "MZ_HEADER_DETECTED"),
                       findings=(_ioc_finding(), _mz_finding()),
                       finding_count=2, findings_truncated=False)
    assert info.to_dict()["findings"] == [
        {"type": "ioc_string", "address": "0x000001d400001230", "offset": 16,
         "encoding": "ASCII", "value": "http://evil.example/beacon",
         "is_network_pattern": True, "module_context": None},
        {"type": "mz_header", "address": "0x000001d400000000", "offset": None,
         "encoding": None, "value": None, "is_network_pattern": None,
         "module_context": "unregistered"},
    ]
    assert info.to_dict()["finding_count"] == 2
    assert info.to_dict()["findings_truncated"] is False


# ── TriageInfo.finding_count/findings_truncated (issue #19 Phase 2 review
# round 2, item 2) -- see ContentFinding's own findings-selection docstring
# in dumpex.hunt._deep_triage._content_signals() for why these exist. ─────

def test_triage_info_finding_count_must_be_at_least_len_findings():
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                   region_fully_examined=True, content_reason_codes=("IOC_PATTERN_STRING_MATCH",),
                   findings=(_ioc_finding(), _mz_finding()), finding_count=1,
                   findings_truncated=False)


def test_triage_info_findings_truncated_must_match_finding_count_vs_findings():
    # finding_count > len(findings) but findings_truncated left False.
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                   region_fully_examined=True, content_reason_codes=("IOC_PATTERN_STRING_MATCH",),
                   findings=(_ioc_finding(),), finding_count=5, findings_truncated=False)
    # finding_count == len(findings) but findings_truncated left True.
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                   region_fully_examined=True, content_reason_codes=("IOC_PATTERN_STRING_MATCH",),
                   findings=(_ioc_finding(),), finding_count=1, findings_truncated=True)
    # Correctly matched is fine.
    info = TriageInfo(mode="deep", status="completed", bytes_examined=4096,
                       region_fully_examined=True, content_reason_codes=("IOC_PATTERN_STRING_MATCH",),
                       findings=(_ioc_finding(),), finding_count=5, findings_truncated=True)
    assert info.finding_count == 5
    assert info.findings_truncated is True


@pytest.mark.parametrize("status", ["not_captured", "budget_deferred", "unreadable"])
def test_triage_info_zero_byte_status_rejects_nonzero_finding_count(status):
    with pytest.raises(ValueError):
        TriageInfo(mode="deep", status=status, bytes_examined=0,
                   region_fully_examined=False, finding_count=3, findings_truncated=True)


def test_triage_info_metadata_mode_rejects_nonzero_finding_count():
    with pytest.raises(ValueError):
        TriageInfo(mode="metadata", status="completed", bytes_examined=0,
                   region_fully_examined=False, finding_count=1, findings_truncated=False)


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

"""Unit tests for dumpex.hunt.region_correlation.build_region_correlations() --
the display-only, `--hunt all`-only cross-hunter co-location reducer. Builds
synthetic `HunterRecord`s directly (same style as
tests/fixtures/hunt_records.py) and synthetic `MinidumpMemoryInfo` stand-ins
(tests/fixtures/fakes.Region) -- no real dump, no real memory content.
"""
import pytest

from dumpex.hunt.region_correlation import (
    RegionSignal, RegionCorrelation, build_region_correlations,
    _RegionIndex, _safe_hex_int, _safe_nonneg_int, _embedded_region,
)
from dumpex.output.coverage import CoverageReport, CoverageStatus
from dumpex.output.records import (
    HunterRecord, InjectionDetails, HollowingDetails, StompingDetails, PipeDetails,
    CsBeaconDetails, YaraDetails, ObfuscationDetails, HuntThreadRegionHit, hex_address,
)
from tests.fixtures.fakes import Region
from tests.fixtures.hunt_records import region as region_ref, thread_ref


def _cov(status=CoverageStatus.COMPLETE):
    return CoverageReport(status=status)


def injection_record(rwx=(), hidden_pe_validated=(), hidden_pe_unvalidated=(),
                      rip_hits=(), start_hits=(), status="DETECTED", lead_count=1):
    details = InjectionDetails(
        rwx=list(rwx), hidden_pe_validated=list(hidden_pe_validated),
        hidden_pe_unvalidated=list(hidden_pe_unvalidated),
        suspicious_validated_pe_hits=[], informational_validated_pe_hits=[],
        threads=[], thread_contexts=[], rwx_and_pe_alloc_bases=[],
        rip_hits=list(rip_hits), rip_full_correlation=[], start_hits=list(start_hits))
    detected = status == "DETECTED"
    return HunterRecord(
        hunter="injection", status=status, score=3 if detected else 0, max_score=3,
        verdict_level="high" if detected else "clean", confidence="high" if detected else "none",
        lead_count=lead_count, review_priority="high" if detected else "none",
        coverage=_cov(), findings=[], details=details)


def hollowing_record(image_base=None, mem_private_at_base=None, mz_header_present=None,
                      is_rwx_at_base=None, name_mismatch=None, status="DETECTED", lead_count=1):
    details = HollowingDetails(
        image_base=image_base, mem_private_at_base=mem_private_at_base,
        mz_header_present=mz_header_present, is_rwx_at_base=is_rwx_at_base,
        peb_image_path=None, module_name=None, name_mismatch=name_mismatch)
    detected = status == "DETECTED"
    return HunterRecord(
        hunter="hollowing", status=status, score=1 if detected else 0, max_score=1,
        verdict_level="possible" if detected else "clean",
        confidence="medium" if detected else "none", lead_count=lead_count,
        review_priority="medium" if detected else "none", coverage=_cov(), findings=[],
        details=details)


def stomping_record(protection_leads=(), verified_changes=(), status="DETECTED", lead_count=1):
    details = StompingDetails(protection_leads=list(protection_leads),
                               verified_changes=list(verified_changes))
    detected = status == "DETECTED"
    return HunterRecord(
        hunter="stomping", status=status, score=1 if detected else 0, max_score=2,
        verdict_level="likely" if detected else "clean", confidence="high" if detected else "none",
        lead_count=lead_count, review_priority="high" if detected else "none", coverage=_cov(),
        findings=[], details=details)


def pipe_record(private_pipes=(), c2_context=(), unbacked_in_rgn=(), status="DETECTED",
                 lead_count=1):
    details = PipeDetails(handle_pipes=[], private_pipes=list(private_pipes),
                           c2_context=list(c2_context), framework_pipes=[],
                           unbacked_in_rgn=list(unbacked_in_rgn))
    detected = status == "DETECTED"
    return HunterRecord(
        hunter="pipe", status=status, score=3 if detected else 0, max_score=3,
        verdict_level="high" if detected else "clean", confidence="high" if detected else "none",
        lead_count=lead_count, review_priority="high" if detected else "none", coverage=_cov(),
        findings=[], details=details)


def cs_beacon_record(configs=(), status="DETECTED", lead_count=0):
    details = CsBeaconDetails(configs=list(configs), config_count=len(configs))
    detected = status == "DETECTED"
    return HunterRecord(
        hunter="cs-beacon", status=status, score=2 if detected else 0, max_score=2,
        verdict_level="high" if detected else "clean", confidence="high" if detected else "none",
        lead_count=lead_count, review_priority="high" if detected else "none", coverage=_cov(),
        findings=[], details=details)


def yara_record(matches=(), status="DETECTED"):
    rules = sorted({m["rule"] for m in matches if isinstance(m, dict) and "rule" in m})
    details = YaraDetails(matches=list(matches), rules_hit=rules)
    return HunterRecord(
        hunter="yara", status=status, score=1 if status == "DETECTED" else 0, max_score=None,
        verdict_level="high" if status == "DETECTED" else "clean", confidence=None,
        lead_count=None, review_priority=None, coverage=_cov(), findings=[], details=details)


def obfuscation_record(hidden_pe=(), entropy=(), status="DETECTED", lead_count=1):
    details = ObfuscationDetails(sleep_mask=[], entropy=list(entropy), base64=[], xor=[],
                                  compressed=[], hidden_pe=list(hidden_pe), hidden_shellcode=[])
    detected = status == "DETECTED"
    return HunterRecord(
        hunter="obfuscation", status=status, score=1 if detected else 0, max_score=2,
        verdict_level="likely" if detected else "clean", confidence="medium" if detected else "none",
        lead_count=lead_count, review_priority="medium" if detected else "none", coverage=_cov(),
        findings=[], details=details)


def region_dict(base, size, alloc=None):
    return {"base_address": hex_address(base), "allocation_base": hex_address(alloc),
            "size": size, "type": "MEM_PRIVATE", "protect": "PAGE_EXECUTE_READWRITE"}


def mem_region(base, size, alloc=None, protect="PAGE_EXECUTE_READWRITE"):
    return Region(base, alloc if alloc is not None else base, size, "MEM_COMMIT", protect,
                  "MEM_PRIVATE")


# ── 1. Injection + CS Beacon share one region ────────────────────────────

def test_injection_and_cs_beacon_same_region_correlate():
    r = region_ref(addr=hex_address(0x1000), size=0x1000, alloc_base=hex_address(0x1000))
    injection = injection_record(rwx=[r])
    beacon = cs_beacon_record(configs=[{
        "va": hex_address(0x1000), "region_base": hex_address(0x1000), "region_size": 0x1000,
        "context_corroborated": True,
    }])
    correlations = build_region_correlations([injection, beacon], [])
    assert len(correlations) == 1
    corr = correlations[0]
    assert corr.region_base == 0x1000
    assert corr.region_size == 0x1000
    assert corr.hunters == ("injection", "cs-beacon")
    kinds = {(s.hunter, s.kind) for s in corr.signals}
    assert ("injection", "rwx") in kinds
    assert ("cs-beacon", "valid_config") in kinds
    assert ("cs-beacon", "context_corroborated") in kinds


# ── 2. Injection + YARA at different VAs, same region via containment ────
# yara matches use the REAL production shape from
# dumpex.hunt.yara_hunt.collect._match_dict(): "strings" is a list of
# string-hit dicts each with their own "va", "seg_va" is only the
# enclosing scanned SEGMENT's own start.

def _yara_match(rule, string_vas=(), seg_va=None, seg_size=None):
    m = {"rule": rule}
    if string_vas:
        m["strings"] = [{"va": hex_address(v)} for v in string_vas]
    if seg_va is not None:
        m["seg_va"] = hex_address(seg_va)
    if seg_size is not None:
        m["seg_size"] = seg_size
    return m


def test_injection_and_yara_different_va_resolve_to_same_region_via_containment():
    regions = [mem_region(0x2000, 0x2000, alloc=0x2000)]
    r = region_ref(addr=hex_address(0x2000), size=0x2000, alloc_base=hex_address(0x2000))
    injection = injection_record(rwx=[r])
    # The injection region is [0x2000, 0x4000); the yara STRING hit sits at
    # 0x2500 -- a different address than injection's own (region-base)
    # 0x2000, but the same normalized region.
    yara = yara_record(matches=[_yara_match("RuleA", string_vas=[0x2500])])
    correlations = build_region_correlations([injection, yara], regions)
    assert len(correlations) == 1
    corr = correlations[0]
    assert (corr.region_base, corr.region_size) == (0x2000, 0x2000)
    assert corr.hunters == ("injection", "yara")
    yara_signal = next(s for s in corr.signals if s.hunter == "yara")
    assert yara_signal.label == "RuleA"
    # yara's own signal is a per-region aggregate (a region can have many
    # string hits for one rule) -- region-level by design, like RWX/entropy.
    assert yara_signal.address == yara_signal.region_base == 0x2000


# ── YARA: string VA takes priority over the enclosing segment's own start ─

def test_yara_uses_actual_string_hit_va_not_segment_start():
    # Segment starts in region A; the REAL string hit is in region B.
    # Only B may correlate -- A must not, even though seg_va points there.
    region_a = mem_region(0x30000, 0x1000, alloc=0x30000)
    region_b = mem_region(0x31000, 0x1000, alloc=0x31000)
    yara = yara_record(matches=[
        _yara_match("RuleA", string_vas=[0x31050], seg_va=0x30000, seg_size=0x2000)])
    pipe_a = pipe_record(private_pipes=[{"region": region_dict(0x30000, 0x1000, alloc=0x30000)}])
    pipe_b = pipe_record(private_pipes=[{"region": region_dict(0x31000, 0x1000, alloc=0x31000)}])

    correlations_a = build_region_correlations([yara, pipe_a], [region_a, region_b])
    assert correlations_a == []   # yara never resolved to region A

    correlations_b = build_region_correlations([yara, pipe_b], [region_a, region_b])
    assert len(correlations_b) == 1
    assert (correlations_b[0].region_base, correlations_b[0].region_size) == (0x31000, 0x1000)


def test_yara_segment_spanning_two_regions_with_no_string_va_produces_no_signal():
    region_a = mem_region(0x32000, 0x1000, alloc=0x32000)
    region_b = mem_region(0x33000, 0x1000, alloc=0x33000)
    # seg_va (0x32000) + seg_size (0x2000) = 0x34000 -- crosses past region A
    # into region B. No string-level VA survived (e.g. every string
    # instance was budget-dropped) -- must NOT be pinned to region A just
    # because that's where the segment happens to start.
    yara = yara_record(matches=[_yara_match("RuleA", seg_va=0x32000, seg_size=0x2000)])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x32000, 0x1000, alloc=0x32000)}])
    correlations = build_region_correlations([yara, pipe], [region_a, region_b])
    assert correlations == []


def test_yara_segment_fully_enclosed_in_one_region_uses_segment_fallback():
    region_a = mem_region(0x34000, 0x4000, alloc=0x34000)
    # seg_va + seg_size stays fully inside region_a -- the fallback IS
    # allowed here.
    yara = yara_record(matches=[_yara_match("RuleA", seg_va=0x34100, seg_size=0x1000)])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x34000, 0x4000, alloc=0x34000)}])
    correlations = build_region_correlations([yara, pipe], [region_a])
    assert len(correlations) == 1
    assert (correlations[0].region_base, correlations[0].region_size) == (0x34000, 0x4000)


def test_yara_segment_passing_through_a_nested_region_produces_no_signal():
    # The segment STARTS and ENDS inside A, so a start-only + end-bound
    # check would wrongly accept it -- but a nested region B sits in the
    # middle of the segment, so the segment does not uniquely belong to A.
    region_a = mem_region(0x36000, 0x4000, alloc=0x36000)   # [0x36000, 0x3a000)
    region_b = mem_region(0x37000, 0x800, alloc=0x37000)    # [0x37000, 0x37800) nested in A
    yara = yara_record(matches=[_yara_match("RuleA", seg_va=0x36100, seg_size=0x2000)])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x36000, 0x4000, alloc=0x36000)}])
    correlations = build_region_correlations([yara, pipe], [region_a, region_b])
    assert correlations == []


def test_yara_segment_starting_in_overlapping_regions_produces_no_signal():
    region_a = mem_region(0x3b000, 0x2000, alloc=0x3b000)   # [0x3b000, 0x3d000)
    region_b = mem_region(0x3b000, 0x1000, alloc=0x3b000)   # [0x3b000, 0x3c000) overlaps A
    yara = yara_record(matches=[_yara_match("RuleA", seg_va=0x3b100, seg_size=0x100)])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x3b000, 0x2000, alloc=0x3b000)}])
    correlations = build_region_correlations([yara, pipe], [region_a, region_b])
    assert correlations == []


def test_yara_segment_ending_exactly_at_region_end_is_accepted():
    region_a = mem_region(0x3e000, 0x1000, alloc=0x3e000)   # [0x3e000, 0x3f000)
    # Segment ends EXACTLY at the region's own end -- half-open semantics
    # mean that's still fully contained.
    yara = yara_record(matches=[_yara_match("RuleA", seg_va=0x3ef00, seg_size=0x100)])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x3e000, 0x1000, alloc=0x3e000)}])
    correlations = build_region_correlations([yara, pipe], [region_a])
    assert len(correlations) == 1
    assert correlations[0].region_base == 0x3e000


@pytest.mark.parametrize("seg_size", [0, -1, None, True, "0x100"])
def test_yara_segment_fallback_rejects_invalid_seg_size(seg_size):
    region_a = mem_region(0x3f000, 0x2000, alloc=0x3f000)
    match = {"rule": "RuleA", "seg_va": hex_address(0x3f100), "seg_size": seg_size}
    yara = yara_record(matches=[match])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x3f000, 0x2000, alloc=0x3f000)}])
    correlations = build_region_correlations([yara, pipe], [region_a])
    assert correlations == []


def test_yara_multiple_string_hits_same_region_dedup_to_one_rule_label():
    region_a = mem_region(0x35000, 0x1000, alloc=0x35000)
    yara = yara_record(matches=[_yara_match("RuleA", string_vas=[0x35010, 0x35020, 0x35030])])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x35000, 0x1000, alloc=0x35000)}])
    correlations = build_region_correlations([yara, pipe], [region_a])
    assert len(correlations) == 1
    yara_signals = [s for s in correlations[0].signals if s.hunter == "yara"]
    assert len(yara_signals) == 1
    assert yara_signals[0].label == "RuleA"


# ── 3. Hollowing image_base resolves via MemoryInfo containment ──────────

def test_hollowing_image_base_resolves_via_containment():
    regions = [mem_region(0x5000, 0x1000, alloc=0x5000)]
    hollowing = hollowing_record(image_base=hex_address(0x5000), mem_private_at_base=True,
                                  mz_header_present=True, is_rwx_at_base=False)
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x5000, 0x1000, alloc=0x5000)}])
    correlations = build_region_correlations([hollowing, pipe], regions)
    assert len(correlations) == 1
    corr = correlations[0]
    assert (corr.region_base, corr.region_size) == (0x5000, 0x1000)
    assert corr.hunters == ("hollowing", "pipe")
    hollowing_labels = {s.label for s in corr.signals if s.hunter == "hollowing"}
    assert "private memory at image base" in hollowing_labels


# ── 4. Stomping verified_changes' own changed bytes resolve via containment

def _verified_change(va_start, diff_ranges):
    return {"va_start": hex_address(va_start), "diff_ranges": [list(r) for r in diff_ranges]}


def test_stomping_verified_change_va_start_resolves_via_containment():
    regions = [mem_region(0x6000, 0x1000, alloc=0x6000)]
    # va_start (section start) is 0x6000; the actual changed bytes (offset
    # 0x10, length 8) land at [0x6010, 0x6018) -- still inside the same
    # region here.
    stomping = stomping_record(verified_changes=[_verified_change(0x6000, [(0x10, 8)])])
    r = region_ref(addr=hex_address(0x6000), size=0x1000, alloc_base=hex_address(0x6000))
    injection = injection_record(rwx=[r])
    correlations = build_region_correlations([stomping, injection], regions)
    assert len(correlations) == 1
    corr = correlations[0]
    assert (corr.region_base, corr.region_size) == (0x6000, 0x1000)
    stomping_labels = {s.label for s in corr.signals if s.hunter == "stomping"}
    assert "verified relocation-normalized byte changes" in stomping_labels


def test_stomping_changed_bytes_in_different_region_than_section_start():
    # The SECTION starts in region A, but the byte range the diff actually
    # touches (va_start + offset .. + length) is entirely inside region B.
    # Only B may correlate.
    region_a = mem_region(0x40000, 0x1000, alloc=0x40000)
    region_b = mem_region(0x41000, 0x1000, alloc=0x41000)
    # va_start=0x40000 (region A), offset=0x1050 -> changed_start=0x41050,
    # inside region B, not A.
    stomping = stomping_record(
        verified_changes=[_verified_change(0x40000, [(0x1050, 8)])])
    pipe_a = pipe_record(private_pipes=[{"region": region_dict(0x40000, 0x1000, alloc=0x40000)}])
    pipe_b = pipe_record(private_pipes=[{"region": region_dict(0x41000, 0x1000, alloc=0x41000)}])

    correlations_a = build_region_correlations([stomping, pipe_a], [region_a, region_b])
    assert correlations_a == []

    correlations_b = build_region_correlations([stomping, pipe_b], [region_a, region_b])
    assert len(correlations_b) == 1
    assert (correlations_b[0].region_base, correlations_b[0].region_size) == (0x41000, 0x1000)


def test_stomping_diff_range_spanning_two_regions_signals_both():
    region_a = mem_region(0x42000, 0x1000, alloc=0x42000)   # [0x42000, 0x43000)
    region_b = mem_region(0x43000, 0x1000, alloc=0x43000)   # [0x43000, 0x44000)
    # va_start + offset = 0x42f00, length 0x200 -> [0x42f00, 0x43100) --
    # crosses the A/B boundary at 0x43000, touching both.
    stomping = stomping_record(
        verified_changes=[_verified_change(0x42000, [(0xf00, 0x200)])])
    pipe_a = pipe_record(private_pipes=[{"region": region_dict(0x42000, 0x1000, alloc=0x42000)}])
    pipe_b = pipe_record(private_pipes=[{"region": region_dict(0x43000, 0x1000, alloc=0x43000)}])
    correlations = build_region_correlations([stomping, pipe_a, pipe_b], [region_a, region_b])
    assert {(c.region_base, c.region_size) for c in correlations} == {
        (0x42000, 0x1000), (0x43000, 0x1000)}
    for corr in correlations:
        stomping_signals = [s for s in corr.signals if s.hunter == "stomping"]
        assert len(stomping_signals) == 1   # deduped: one signal per (change, region)


def test_stomping_diff_range_end_boundary_is_exclusive():
    region_a = mem_region(0x44000, 0x100, alloc=0x44000)   # [0x44000, 0x44100)
    # offset+length lands EXACTLY at the region's own end -- must not touch it.
    stomping = stomping_record(verified_changes=[_verified_change(0x44000, [(0x100, 8)])])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x44000, 0x100, alloc=0x44000)}])
    correlations = build_region_correlations([stomping, pipe], [region_a])
    assert correlations == []


# ── Stomping: ambiguous (mutually-overlapping) regions never correlate ────

def test_stomping_diff_range_in_two_overlapping_regions_produces_no_signal():
    # A and B OVERLAP each other; the changed bytes fall inside both, so no
    # byte in the range has a unique owner -- the same rule containing()
    # applies to a single address must apply to a range.
    region_a = mem_region(0x45000, 0x1000, alloc=0x45000)   # [0x45000, 0x46000)
    region_b = mem_region(0x45800, 0x1000, alloc=0x45800)   # [0x45800, 0x46800)
    stomping = stomping_record(verified_changes=[_verified_change(0x45000, [(0x800, 0x10)])])
    pipe_a = pipe_record(private_pipes=[{"region": region_dict(0x45000, 0x1000, alloc=0x45000)}])
    pipe_b = pipe_record(private_pipes=[{"region": region_dict(0x45800, 0x1000, alloc=0x45800)}])
    for pipe in (pipe_a, pipe_b):
        correlations = build_region_correlations([stomping, pipe], [region_a, region_b])
        assert correlations == []


def test_stomping_diff_range_with_duplicate_memory_info_regions_produces_no_signal():
    dup = mem_region(0x46000, 0x1000, alloc=0x46000)
    stomping = stomping_record(verified_changes=[_verified_change(0x46000, [(0x10, 8)])])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x46000, 0x1000, alloc=0x46000)}])
    correlations = build_region_correlations([stomping, pipe], [dup, mem_region(0x46000, 0x1000,
                                                                                alloc=0x46000)])
    assert correlations == []


def test_stomping_diff_range_only_partially_inside_a_region_signals_the_intersection():
    # The range starts BEFORE the region (in a gap MemoryInfo doesn't cover)
    # and runs into it -- only the real intersection may produce a signal,
    # anchored at the first changed byte actually inside the region.
    region_b = mem_region(0x48000, 0x1000, alloc=0x48000)   # [0x48000, 0x49000)
    stomping = stomping_record(verified_changes=[_verified_change(0x47f00, [(0, 0x200)])])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x48000, 0x1000, alloc=0x48000)}])
    correlations = build_region_correlations([stomping, pipe], [region_b])
    assert len(correlations) == 1
    sig = next(s for s in correlations[0].signals
               if s.hunter == "stomping" and s.kind == "verified_change")
    assert sig.address == 0x48000


# ── Stomping: a boundary-spanning range anchors each signal in its own region

def test_stomping_boundary_spanning_range_addresses_stay_inside_their_own_region():
    region_a = mem_region(0x4a000, 0x1000, alloc=0x4a000)   # [0x4a000, 0x4b000)
    region_b = mem_region(0x4b000, 0x1000, alloc=0x4b000)   # [0x4b000, 0x4c000)
    # changed bytes [0x4aff0, 0x4b010) -- last 0x10 of A, first 0x10 of B.
    stomping = stomping_record(verified_changes=[_verified_change(0x4a000, [(0xff0, 0x20)])])
    pipe_a = pipe_record(private_pipes=[{"region": region_dict(0x4a000, 0x1000, alloc=0x4a000)}])
    pipe_b = pipe_record(private_pipes=[{"region": region_dict(0x4b000, 0x1000, alloc=0x4b000)}])
    correlations = build_region_correlations(
        [stomping, pipe_a, pipe_b], [region_a, region_b])
    by_base = {c.region_base: c for c in correlations}
    assert set(by_base) == {0x4a000, 0x4b000}

    sig_a = next(s for s in by_base[0x4a000].signals if s.hunter == "stomping")
    sig_b = next(s for s in by_base[0x4b000].signals if s.hunter == "stomping")
    assert sig_a.address == 0x4aff0            # the range's own start, inside A
    assert sig_b.address == 0x4b000            # B's own first changed byte, NOT 0x4aff0
    # The invariant every RegionSignal must satisfy.
    for sig in (sig_a, sig_b):
        assert sig.region_base <= sig.address < sig.region_base + sig.region_size


def test_stomping_two_diff_ranges_in_one_region_keep_the_lowest_changed_address():
    region_a = mem_region(0x4d000, 0x1000, alloc=0x4d000)
    stomping = stomping_record(
        verified_changes=[_verified_change(0x4d000, [(0x200, 8), (0x100, 8)])])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x4d000, 0x1000, alloc=0x4d000)}])
    correlations = build_region_correlations([stomping, pipe], [region_a])
    assert len(correlations) == 1
    stomping_signals = [s for s in correlations[0].signals if s.hunter == "stomping"]
    assert len(stomping_signals) == 1
    assert stomping_signals[0].address == 0x4d100   # the lower of the two, deterministically


# ── 5. Same hunter, many signals in one region -> no correlation ─────────

def test_single_hunter_multiple_signals_does_not_correlate():
    r1 = region_ref(addr=hex_address(0x7000), size=0x1000)
    r2 = region_ref(addr=hex_address(0x7000), size=0x1000)  # same region, different object
    injection = injection_record(rwx=[r1], start_hits=[])
    injection2 = injection_record(rwx=[r2])
    # Two evidence ITEMS in the SAME hunter/region (rwx + hidden_pe_validated
    # both pointing at 0x7000) must not manufacture a correlation on their own.
    from tests.fixtures.hunt_records import valid_pe_hit
    pe = valid_pe_hit(r1)
    injection3 = injection_record(rwx=[r1], hidden_pe_validated=[pe])
    correlations = build_region_correlations([injection3], [])
    assert correlations == []


# ── 6. Same AllocationBase, different BaseAddress -> not merged ──────────

def test_same_allocation_base_different_region_not_merged():
    alloc = 0x8000
    r_a = region_ref(addr=hex_address(0x8000), size=0x1000, alloc_base=hex_address(alloc))
    injection = injection_record(rwx=[r_a])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x9000, 0x1000, alloc=alloc)}])
    correlations = build_region_correlations([injection, pipe], [])
    # injection's own region (0x8000) has only injection; pipe's own region
    # (0x9000) has only pipe -- sharing AllocationBase must NOT merge them
    # into one artificially cross-hunter region.
    assert correlations == []


# ── 7. Region end boundary is exclusive ───────────────────────────────────

def test_region_index_containment_is_half_open():
    idx = _RegionIndex([mem_region(0x1000, 0x100)])
    assert idx.containing(0x1000) == (0x1000, 0x100, 0x1000)
    assert idx.containing(0x1000 + 0x100 - 1) == (0x1000, 0x100, 0x1000)
    assert idx.containing(0x1000 + 0x100) is None


# ── _RegionIndex's three lookups have three distinct ambiguity rules ──────

def test_unambiguous_overlaps_allows_adjacent_regions_but_not_overlapping_ones():
    adjacent = _RegionIndex([mem_region(0x1000, 0x1000), mem_region(0x2000, 0x1000)])
    # A range crossing the A/B boundary legitimately touches both.
    assert {r[0] for r in adjacent.unambiguous_overlaps(0x1ff0, 0x2010)} == {0x1000, 0x2000}
    # Abutting regions do not count as overlapping each other.
    assert len(adjacent.unambiguous_overlaps(0x1000, 0x3000)) == 2

    overlapping = _RegionIndex([mem_region(0x1000, 0x1000), mem_region(0x1800, 0x1000)])
    assert overlapping.unambiguous_overlaps(0x1800, 0x1810) == []
    # A part of the range with an unambiguous owner is still refused as a
    # whole -- the range is one indivisible piece of evidence.
    assert overlapping.unambiguous_overlaps(0x1000, 0x1900) == []
    # ...but a range that only touches the non-overlapped part resolves.
    assert [r[0] for r in overlapping.unambiguous_overlaps(0x1000, 0x1100)] == [0x1000]


def test_unambiguous_overlaps_rejects_degenerate_ranges():
    idx = _RegionIndex([mem_region(0x1000, 0x1000)])
    assert idx.unambiguous_overlaps(None, 0x1010) == []
    assert idx.unambiguous_overlaps(0x1000, None) == []
    assert idx.unambiguous_overlaps(0x1010, 0x1010) == []   # empty range
    assert idx.unambiguous_overlaps(0x1010, 0x1000) == []   # inverted


def test_uniquely_contains_range_requires_whole_range_in_exactly_one_region():
    idx = _RegionIndex([mem_region(0x1000, 0x1000)])
    assert idx.uniquely_contains_range(0x1000, 0x2000) == (0x1000, 0x1000, 0x1000)
    assert idx.uniquely_contains_range(0x1100, 0x1200) == (0x1000, 0x1000, 0x1000)
    assert idx.uniquely_contains_range(0x1100, 0x2001) is None   # runs past the end
    assert idx.uniquely_contains_range(0xfff, 0x1100) is None    # starts before the base

    # Adjacent regions: spanning them is fine for unambiguous_overlaps()
    # but NOT for uniquely_contains_range().
    adjacent = _RegionIndex([mem_region(0x1000, 0x1000), mem_region(0x2000, 0x1000)])
    assert adjacent.uniquely_contains_range(0x1ff0, 0x2010) is None

    # Nested second region intersecting the middle of the range.
    nested = _RegionIndex([mem_region(0x1000, 0x4000), mem_region(0x2000, 0x800)])
    assert nested.uniquely_contains_range(0x1100, 0x3000) is None
    # ...but a range avoiding the nested region entirely still resolves.
    assert nested.uniquely_contains_range(0x1100, 0x1200) == (0x1000, 0x4000, 0x1000)


# ── 8. Missing MemoryInfo: embedded-complete refs still usable ───────────

def test_missing_memory_info_uses_embedded_region_for_complete_refs():
    r = region_ref(addr=hex_address(0xa000), size=0x1000)
    injection = injection_record(rwx=[r])
    beacon = cs_beacon_record(configs=[{
        "va": hex_address(0xa000), "region_base": hex_address(0xa000), "region_size": 0x1000,
    }])
    correlations = build_region_correlations([injection, beacon], [])
    assert len(correlations) == 1
    assert correlations[0].region_base == 0xa000


# ── 9. Missing MemoryInfo: VA-only evidence is skipped, not guessed ──────

def test_missing_memory_info_skips_va_only_evidence():
    hollowing = hollowing_record(image_base=hex_address(0xb000), mem_private_at_base=True)
    pipe = pipe_record(private_pipes=[{"region": region_dict(0xb000, 0x1000)}])
    correlations = build_region_correlations([hollowing, pipe], [])
    assert correlations == []   # hollowing's image_base never resolves without MemoryInfo


# ── 10. file_offset never participates in matching ───────────────────────

def test_file_offset_is_never_used_for_matching():
    r = region_ref(addr=hex_address(0xc000), size=0x1000)
    injection = injection_record(rwx=[r])
    beacon = cs_beacon_record(configs=[{
        "va": hex_address(0xc000), "file_offset": 0x7FFFFFFF,  # wildly unrelated file offset
        "region_base": hex_address(0xc000), "region_size": 0x1000,
    }])
    correlations = build_region_correlations([injection, beacon], [])
    assert len(correlations) == 1
    assert correlations[0].region_base == 0xc000


# ── CS Beacon: MemoryInfo present must NEVER fall back to embedded region ─
# on an unresolved/ambiguous VA -- a stale or overlapping MemoryInfo list
# would otherwise still let the config's own embedded region_base/
# region_size manufacture a correlation.

def test_cs_beacon_va_ambiguous_in_overlapping_regions_does_not_fall_back():
    # Two overlapping MemoryInfo entries both claim the config's own `va`.
    regions = [mem_region(0x50000, 0x1000), mem_region(0x50000, 0x2000)]
    beacon = cs_beacon_record(configs=[{
        "va": hex_address(0x50000), "region_base": hex_address(0x50000), "region_size": 0x1000}])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x50000, 0x1000)}])
    correlations = build_region_correlations([beacon, pipe], regions)
    assert correlations == []


def test_cs_beacon_va_not_in_any_current_region_does_not_fall_back():
    # MemoryInfo IS present (and non-empty), but doesn't cover this VA at
    # all -- the config's own embedded region_base/region_size must still
    # not be trusted.
    regions = [mem_region(0x60000, 0x1000)]   # does not cover 0x70000
    beacon = cs_beacon_record(configs=[{
        "va": hex_address(0x70000), "region_base": hex_address(0x70000), "region_size": 0x1000}])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x70000, 0x1000)}])
    correlations = build_region_correlations([beacon, pipe], regions)
    assert correlations == []


def test_cs_beacon_embedded_fallback_only_when_memory_info_truly_absent():
    beacon = cs_beacon_record(configs=[{
        "va": hex_address(0x80000), "region_base": hex_address(0x80000), "region_size": 0x1000}])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x80000, 0x1000)}])
    correlations = build_region_correlations([beacon, pipe], [])   # no MemoryInfo at all
    assert len(correlations) == 1
    assert correlations[0].region_base == 0x80000


# ── 11. Signal de-duplication ─────────────────────────────────────────────

def test_signal_deduplication():
    r = region_ref(addr=hex_address(0xd000), size=0x1000)
    injection = injection_record(rwx=[r, r])   # same region ref twice
    beacon = cs_beacon_record(configs=[{
        "va": hex_address(0xd000), "region_base": hex_address(0xd000), "region_size": 0x1000,
    }])
    correlations = build_region_correlations([injection, beacon], [])
    assert len(correlations) == 1
    injection_signals = [s for s in correlations[0].signals if s.hunter == "injection"]
    assert len(injection_signals) == 1


# ── 12. Correlation ordering is deterministic ─────────────────────────────

def test_correlation_sort_order_is_deterministic():
    # Region X: 3 hunters, high severity -- should sort first.
    r_x = region_ref(addr=hex_address(0x10000), size=0x1000)
    inj_x = injection_record(rwx=[r_x])
    beacon_x = cs_beacon_record(configs=[{
        "va": hex_address(0x10000), "region_base": hex_address(0x10000), "region_size": 0x1000}])
    pipe_x = pipe_record(private_pipes=[{"region": region_dict(0x10000, 0x1000)}])

    # Region Y: 2 hunters only -- should sort after X.
    inj_y = injection_record(rwx=[region_ref(addr=hex_address(0x20000), size=0x1000)])
    beacon_y = cs_beacon_record(configs=[{
        "va": hex_address(0x20000), "region_base": hex_address(0x20000), "region_size": 0x1000}])

    records = [inj_x, beacon_x, pipe_x]
    # cs-beacon/injection/pipe records for region Y use different variable
    # names but the SAME hunter keys -- build_region_correlations() accepts
    # any records list, so combine both scenarios' evidence onto one
    # per-hunter record instead (two separate HunterRecords for the same
    # hunter is not a valid input): merge region X and Y evidence into the
    # single per-hunter record.
    injection_both = injection_record(rwx=[r_x, region_ref(addr=hex_address(0x20000), size=0x1000)])
    beacon_both = cs_beacon_record(configs=[
        {"va": hex_address(0x10000), "region_base": hex_address(0x10000), "region_size": 0x1000},
        {"va": hex_address(0x20000), "region_base": hex_address(0x20000), "region_size": 0x1000},
    ])
    pipe_only_x = pipe_record(private_pipes=[{"region": region_dict(0x10000, 0x1000)}])

    correlations = build_region_correlations([injection_both, beacon_both, pipe_only_x], [])
    assert len(correlations) == 2
    assert correlations[0].region_base == 0x10000   # 3 hunters beats 2
    assert correlations[1].region_base == 0x20000

    # Reproducible across repeated calls.
    correlations2 = build_region_correlations([injection_both, beacon_both, pipe_only_x], [])
    assert [c.region_base for c in correlations] == [c.region_base for c in correlations2]


# ── 13. Invalid/missing optional addresses never crash ───────────────────

def test_invalid_addresses_do_not_crash():
    assert _safe_hex_int(None) is None
    assert _safe_hex_int(True) is None
    assert _safe_hex_int(False) is None
    assert _safe_hex_int(123) is None
    assert _safe_hex_int("not-hex") is None
    assert _safe_hex_int("0x") is None
    assert _safe_hex_int("0xzz") is None
    assert _safe_nonneg_int(None) is None
    assert _safe_nonneg_int(True) is None
    assert _safe_nonneg_int(-1) is None
    assert _embedded_region(None) is None
    assert _embedded_region({"base_address": None, "size": None}) is None

    hollowing = hollowing_record(image_base=None, mem_private_at_base=True)
    stomping = stomping_record(verified_changes=[{"va_start": "garbage"}])
    beacon = cs_beacon_record(configs=[{"va": None, "region_base": None, "region_size": None}])
    yara = yara_record(matches=[{"rule": "R", "seg_va": None}, {"seg_va": "0x1"}])
    correlations = build_region_correlations([hollowing, stomping, beacon, yara], [])
    assert correlations == []   # nothing resolvable -- and, crucially, no exception


# ── 14. Overlapping regions -> ambiguous match is skipped, not guessed ───

def test_overlapping_regions_skip_ambiguous_match():
    # Two overlapping MemoryInfo entries both claim 0xe000 -- a malformed/
    # unusual MemoryInfo list must never produce an unreliable correlation.
    regions = [mem_region(0xe000, 0x1000), mem_region(0xe000, 0x2000)]
    hollowing = hollowing_record(image_base=hex_address(0xe000), mem_private_at_base=True)
    pipe = pipe_record(private_pipes=[{"region": region_dict(0xe000, 0x1000)}])
    correlations = build_region_correlations([hollowing, pipe], regions)
    assert correlations == []


# ── Embedded-region canonicalization against the CURRENT MemoryInfo list ──
# Injection/Pipe/Stomping(protection_leads)/Obfuscation all carry an
# embedded (already-complete) region reference -- but it must still be
# re-confirmed against the CURRENT MemoryInfo list when one is present, not
# trusted blindly just because it once came from a real scan.

def test_injection_embedded_region_rejected_when_not_in_current_memory_info():
    # The embedded ref claims (0x90000, 0x1000), but the CURRENT MemoryInfo
    # list has a DIFFERENT region at that base (stale/mismatched size) --
    # must be rejected, not silently trusted.
    regions = [mem_region(0x90000, 0x2000)]   # size differs from embedded's 0x1000
    r = region_ref(addr=hex_address(0x90000), size=0x1000)
    injection = injection_record(rwx=[r])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x90000, 0x2000)}])   # matches current
    correlations = build_region_correlations([injection, pipe], regions)
    assert correlations == []   # injection's own stale embedded ref never resolves


def test_pipe_embedded_region_rejected_when_not_in_current_memory_info():
    regions = [mem_region(0x91000, 0x2000)]
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x91000, 0x1000)}])   # stale size
    injection = injection_record(rwx=[region_ref(addr=hex_address(0x91000), size=0x2000)])
    correlations = build_region_correlations([injection, pipe], regions)
    assert correlations == []   # pipe's own stale embedded ref never resolves


def test_obfuscation_embedded_region_rejected_when_not_in_current_memory_info():
    regions = [mem_region(0x92000, 0x2000)]
    obf = obfuscation_record(hidden_pe=[{"region": region_dict(0x92000, 0x1000), "offset": 0}])
    injection = injection_record(rwx=[region_ref(addr=hex_address(0x92000), size=0x2000)])
    correlations = build_region_correlations([injection, obf], regions)
    assert correlations == []   # obfuscation's own stale embedded ref never resolves


def test_injection_embedded_region_confirmed_when_it_exactly_matches_current_memory_info():
    regions = [mem_region(0x93000, 0x1000)]
    r = region_ref(addr=hex_address(0x93000), size=0x1000)
    injection = injection_record(rwx=[r])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x93000, 0x1000)}])
    correlations = build_region_correlations([injection, pipe], regions)
    assert len(correlations) == 1
    assert (correlations[0].region_base, correlations[0].region_size) == (0x93000, 0x1000)


# ── AllocationBase conflict guard ─────────────────────────────────────────

def test_allocation_base_conflict_drops_the_region_instead_of_first_wins():
    # Same (base, size), but two different hunters' OWN embedded
    # allocation_base disagree -- only reachable with no MemoryInfo present
    # (MemoryInfo, when present, always supplies one canonical
    # allocation_base via _canonicalize(), so this can only arise from
    # inconsistent embedded evidence itself).
    r = region_ref(addr=hex_address(0x94000), size=0x1000, alloc_base=hex_address(0x94000))
    injection = injection_record(rwx=[r])
    pipe = pipe_record(private_pipes=[
        {"region": region_dict(0x94000, 0x1000, alloc=0x90000)}])   # different allocation_base
    correlations = build_region_correlations([injection, pipe], [])
    assert correlations == []   # inconsistent evidence -- never shown as a reliable correlation


# ── Eligibility filter ────────────────────────────────────────────────────

def test_not_evaluated_hunter_with_no_leads_contributes_no_signal():
    r = region_ref(addr=hex_address(0xf000), size=0x1000)
    injection = injection_record(rwx=[r], status="DETECTED")
    beacon = cs_beacon_record(configs=[{
        "va": hex_address(0xf000), "region_base": hex_address(0xf000), "region_size": 0x1000}],
        status="NOT_DETECTED_IN_SCANNED_SCOPE", lead_count=0)
    correlations = build_region_correlations([injection, beacon], [])
    assert correlations == []   # cs-beacon has no evidence value here (clean, no leads)


def test_lead_only_hunter_still_contributes():
    r = region_ref(addr=hex_address(0x11000), size=0x1000)
    injection = injection_record(rwx=[r], status="DETECTED")
    beacon = cs_beacon_record(configs=[{
        "va": hex_address(0x11000), "region_base": hex_address(0x11000), "region_size": 0x1000}],
        status="NOT_DETECTED_IN_SCANNED_SCOPE", lead_count=1)
    correlations = build_region_correlations([injection, beacon], [])
    assert len(correlations) == 1
    assert correlations[0].hunters == ("injection", "cs-beacon")


# ── Real evidence addresses are preserved, not collapsed to region base ───

def test_injection_rip_hit_uses_real_ip_not_region_base():
    r = region_ref(addr=hex_address(0x95000), size=0x1000)
    t = thread_ref(tid=7, ip=hex_address(0x95100), ip_reg="RIP")
    injection = injection_record(rip_hits=[HuntThreadRegionHit(thread=t, region=r)])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x95000, 0x1000)}])
    correlations = build_region_correlations([injection, pipe], [])
    assert len(correlations) == 1
    rip_signal = next(s for s in correlations[0].signals
                       if s.hunter == "injection" and s.kind == "rip_hit")
    assert rip_signal.address == 0x95100
    assert rip_signal.address != rip_signal.region_base


def test_injection_start_hit_uses_real_start_address_not_region_base():
    r = region_ref(addr=hex_address(0x96000), size=0x1000)
    t = thread_ref(tid=8, start_address=hex_address(0x96200))
    injection = injection_record(start_hits=[HuntThreadRegionHit(thread=t, region=r)])
    pipe = pipe_record(private_pipes=[{"region": region_dict(0x96000, 0x1000)}])
    correlations = build_region_correlations([injection, pipe], [])
    assert len(correlations) == 1
    start_signal = next(s for s in correlations[0].signals
                         if s.hunter == "injection" and s.kind == "start_hit")
    assert start_signal.address == 0x96200


def test_pipe_private_pipe_uses_region_base_plus_offset():
    pipe = pipe_record(private_pipes=[
        {"region": region_dict(0x97000, 0x1000), "offset": 0x40}])
    injection = injection_record(rwx=[region_ref(addr=hex_address(0x97000), size=0x1000)])
    correlations = build_region_correlations([injection, pipe], [])
    assert len(correlations) == 1
    sig = next(s for s in correlations[0].signals
               if s.hunter == "pipe" and s.kind == "private_pipe")
    assert sig.address == 0x97040


def test_pipe_c2_context_uses_each_records_own_va():
    pipe = pipe_record(c2_context=[{
        "region": region_dict(0x98000, 0x1000), "name": "x",
        "records": [{"va": hex_address(0x98010)}, {"va": hex_address(0x98050)}]}])
    injection = injection_record(rwx=[region_ref(addr=hex_address(0x98000), size=0x1000)])
    correlations = build_region_correlations([injection, pipe], [])
    assert len(correlations) == 1
    c2_addrs = {s.address for s in correlations[0].signals
                if s.hunter == "pipe" and s.kind == "c2_context"}
    assert c2_addrs == {0x98010, 0x98050}


def test_obfuscation_hidden_pe_uses_region_base_plus_offset():
    obf = obfuscation_record(hidden_pe=[
        {"region": region_dict(0x99000, 0x1000), "offset": 0x20}])
    injection = injection_record(rwx=[region_ref(addr=hex_address(0x99000), size=0x1000)])
    correlations = build_region_correlations([injection, obf], [])
    assert len(correlations) == 1
    sig = next(s for s in correlations[0].signals
               if s.hunter == "obfuscation" and s.kind == "hidden_pe")
    assert sig.address == 0x99020


def test_obfuscation_entropy_is_region_level_uses_region_base():
    obf = obfuscation_record(entropy=[{"region": region_dict(0x9a000, 0x1000)}])
    injection = injection_record(rwx=[region_ref(addr=hex_address(0x9a000), size=0x1000)])
    correlations = build_region_correlations([injection, obf], [])
    assert len(correlations) == 1
    sig = next(s for s in correlations[0].signals
               if s.hunter == "obfuscation" and s.kind == "entropy")
    assert sig.address == sig.region_base == 0x9a000


def test_stomping_protection_lead_uses_va_start_not_region_base():
    lead = {"region": region_dict(0x9b000, 0x1000), "va_start": hex_address(0x9b040)}
    stomping = stomping_record(protection_leads=[lead])
    injection = injection_record(rwx=[region_ref(addr=hex_address(0x9b000), size=0x1000)])
    correlations = build_region_correlations([injection, stomping], [])
    assert len(correlations) == 1
    sig = next(s for s in correlations[0].signals
               if s.hunter == "stomping" and s.kind == "protection_lead")
    assert sig.address == 0x9b040


# ── Type checking ──────────────────────────────────────────────────────────

def test_rejects_non_hunter_record_list():
    with pytest.raises(TypeError):
        build_region_correlations([{"hunter": "injection"}], [])

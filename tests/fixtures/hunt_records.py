"""
Synthetic HunterRecord fixtures for the v2.4 hunt migration's PR3 tests
(schema validation, structured-output checks) -- no real dump, no real memory
content, following the synthetic-fixture and deterministic-output boundary
documented in docs/developer/hunt_architecture.md and tests/corpus/README.md for
tests/fixtures/hunt_cases.py. These build dumpex.output.records.HunterRecord
instances directly (the same way tests/unit/test_hunt_records.py does) --
NOT through any hunter's real collect_*() pipeline (every hunter has one
as of PR2b; see e.g. dumpex.hunt.injection.collect.collect_injection_record())
-- deliberately, so PR3's schema tests stay independent of any given
hunter's own detection logic and exercise only the record/summary shape
itself.
"""
import dataclasses

from dumpex.hunt.summary import build_hunt_summary
from dumpex.hunt._investigation import build_investigation_queue
from dumpex.hunt._finding import Finding, TAG_LEAD, CONFIDENCE_MEDIUM
from dumpex.output.coverage import CoverageReport, CoverageStatus
from dumpex.output.records import (
    HunterRecord, InjectionDetails, HollowingDetails, StompingDetails, PipeDetails,
    CsBeaconDetails, YaraDetails, ObfuscationDetails, HuntRegionRef, HuntThreadRef,
    HuntPeHeaderHit, HuntThreadRegionHit,
)


def region(addr="0x0000000000000001", alloc_base=None, size=4096, type_="MEM_PRIVATE",
           protect="PAGE_EXECUTE_READWRITE"):
    return HuntRegionRef(base_address=addr, allocation_base=alloc_base, size=size, type=type_,
                          protect=protect)


def thread_ref(tid=1, start_address=None, ip=None, ip_reg=None):
    return HuntThreadRef(tid=tid, start_address=start_address, ip=ip, ip_reg=ip_reg)


def valid_pe_hit(r=None):
    # A candidate found PART WAY into its region (region_offset != 0) --
    # the case the hidden-PE scan could not see at all before the
    # whole-region candidate search (issue #26), and the reason
    # va/region_offset/file_offset exist on this record at all: a fixture
    # pinned at the region base would exercise the one arrangement where
    # `region.base_address` happens to answer "where is the PE".
    r = r or region()
    return HuntPeHeaderHit(region=r, valid=True, va="0x0000000000001001",
                            region_offset=0x1000, file_offset="0x0000000000000401",
                            machine_name="AMD64", is_pe32_plus=True,
                            number_of_sections=1, entry_point_rva=0x1000,
                            image_base="0x0000000000000002")


def invalid_pe_hit(r=None):
    r = r or region()
    return HuntPeHeaderHit(region=r, valid=False, va="0x0000000000000001",
                            region_offset=0, file_offset=None, reason="no MZ prefix")


def a_finding(check="injection.rwx_regions"):
    # Built through the real Finding dataclass (not a hand-typed dict) so
    # this fixture never drifts from Finding.to_dict()'s own shape -- see
    # dumpex/hunt/_finding.py for id/severity's auto-derivation.
    return Finding(check=check, facts=["VA=0x0000000000000001"], inference="x",
                    confidence=CONFIDENCE_MEDIUM, rationale="y", tag=TAG_LEAD).to_dict()


def coverage(status=CoverageStatus.COMPLETE, sources=None, limitations=None):
    return CoverageReport(status=status, sources=sources or {}, limitations=limitations or [])


# ── one DETECTED HunterRecord per hunter (full-shape, non-empty evidence) ──

def injection_detected():
    r = region()
    pe_valid = valid_pe_hit(r)
    pe_invalid = invalid_pe_hit(r)
    t = thread_ref()
    hit = HuntThreadRegionHit(thread=t, region=r)
    details = InjectionDetails(
        rwx=[r], hidden_pe_validated=[pe_valid], hidden_pe_unvalidated=[pe_invalid],
        suspicious_validated_pe_hits=[pe_valid], informational_validated_pe_hits=[],
        threads=[t], thread_contexts=[t], rwx_and_pe_alloc_bases=["0x0000000000000003"],
        rip_hits=[hit], rip_full_correlation=[hit], start_hits=[],
    )
    return HunterRecord(hunter="injection", status="DETECTED", score=3, max_score=3,
        verdict_level="high", confidence="high", lead_count=1, review_priority="high",
        coverage=coverage(), findings=[a_finding()], details=details)


def hollowing_not_evaluated():
    # image_base=None: the PEB itself is missing in this state -- there is
    # no image base to report at all (see HollowingDetails' own docstring).
    details = HollowingDetails(image_base=None, mem_private_at_base=None,
        mz_header_present=None, is_rwx_at_base=None, peb_image_path=None, module_name=None,
        name_mismatch=None)
    return HunterRecord(hunter="hollowing", status="NOT_EVALUATED", score=0, max_score=1,
        verdict_level="not_evaluated", confidence="none", lead_count=0, review_priority="none",
        coverage=coverage(CoverageStatus.NOT_EVALUATED), findings=[], details=details)


def hollowing_detected():
    details = HollowingDetails(image_base="0x0000000000000004", mem_private_at_base=True,
        mz_header_present=False, is_rwx_at_base=True, peb_image_path="C:\\a.exe",
        module_name="a.exe", name_mismatch=True)
    return HunterRecord(hunter="hollowing", status="DETECTED", score=1, max_score=1,
        verdict_level="possible", confidence="medium", lead_count=1, review_priority="medium",
        coverage=coverage(), findings=[a_finding("hollowing.name_mismatch")], details=details)


def stomping_inconclusive():
    details = StompingDetails(protection_leads=[{"module": "a.dll", "va": "0x0000000000000005"}],
                               verified_changes=[])
    return HunterRecord(hunter="stomping", status="INCONCLUSIVE", score=0, max_score=2,
        verdict_level="inconclusive", confidence="low", lead_count=1, review_priority="low",
        coverage=coverage(CoverageStatus.PARTIAL), findings=[], details=details)


def stomping_detected():
    details = StompingDetails(protection_leads=[],
        verified_changes=[{"module": "a.dll", "section": ".text", "va_start": "0x0000000000000005",
                            "diff_ranges": [[0, 8]], "ranges_truncated": False, "total_ranges": 1,
                            "compared_len": 8, "rip_in_changed_range": False,
                            "disk_sha256": "a" * 64, "mem_sha256": "b" * 64}])
    return HunterRecord(hunter="stomping", status="DETECTED", score=1, max_score=2,
        verdict_level="likely", confidence="high", lead_count=0, review_priority="high",
        coverage=coverage(), findings=[a_finding("stomping.tampered_content")], details=details)


def pipe_clean():
    details = PipeDetails(handle_pipes=[], private_pipes=[], c2_context=[], framework_pipes=[],
                           unbacked_in_rgn=[])
    return HunterRecord(hunter="pipe", status="NOT_DETECTED_IN_SCANNED_SCOPE", score=0,
        max_score=3, verdict_level="clean", confidence="none", lead_count=0,
        review_priority="none", coverage=coverage(), findings=[], details=details)


def pipe_detected():
    details = PipeDetails(handle_pipes=[{"Handle": "0x0000000000000006", "ObjectName": "\\pipe\\x"}],
        private_pipes=[], c2_context=[{"pipe": "\\pipe\\x"}], framework_pipes=[], unbacked_in_rgn=[])
    return HunterRecord(hunter="pipe", status="DETECTED", score=3, max_score=3,
        verdict_level="high", confidence="high", lead_count=0, review_priority="high",
        coverage=coverage(), findings=[a_finding("pipe.full_corroboration")], details=details)


def cs_beacon_detected():
    details = CsBeaconDetails(configs=[{"cs_version": 4, "c2_host": "example.test"}],
                               config_count=1)
    return HunterRecord(hunter="cs-beacon", status="DETECTED", score=2, max_score=2,
        verdict_level="high", confidence="high", lead_count=0, review_priority="high",
        coverage=coverage(), findings=[a_finding("cs_beacon.config_extracted")], details=details)


def yara_not_evaluated():
    details = YaraDetails(matches=[], rules_hit=[])
    return HunterRecord(hunter="yara", status="NOT_EVALUATED", score=0, max_score=None,
        verdict_level="not_evaluated", confidence=None, lead_count=None, review_priority=None,
        coverage=coverage(CoverageStatus.NOT_EVALUATED), findings=[], details=details)


def yara_detected():
    details = YaraDetails(matches=[{"rule": "CS_Beacon_Config_XOR69",
                                     "strings": [{"identifier": "$a", "data": "deadbeef"}]}],
                           rules_hit=["CS_Beacon_Config_XOR69"])
    return HunterRecord(hunter="yara", status="DETECTED", score=1, max_score=None,
        verdict_level="high", confidence=None, lead_count=None, review_priority=None,
        coverage=coverage(), findings=[], details=details)


def obfuscation_detected():
    details = ObfuscationDetails(sleep_mask=[], entropy=[{"score": 7.9}], base64=[], xor=[],
        compressed=[], hidden_pe=[{"rva": 0x1000}], hidden_shellcode=[])
    return HunterRecord(hunter="obfuscation", status="DETECTED", score=1, max_score=2,
        verdict_level="likely", confidence="medium", lead_count=1, review_priority="medium",
        coverage=coverage(), findings=[a_finding("obfuscation.hidden_pe_validated")],
        details=details)


def all_seven_detected_variety():
    """One record per hunter, mixing DETECTED/INCONCLUSIVE/NOT_EVALUATED/
    clean states -- used for --hunt all-style schema round-trips."""
    return [
        injection_detected(),
        hollowing_not_evaluated(),
        stomping_inconclusive(),
        pipe_clean(),
        cs_beacon_detected(),
        yara_detected(),
        obfuscation_detected(),
    ]


def _as_not_evaluated(record):
    """Same hunter/max_score/details as `record`, but re-shaped into the
    NOT_EVALUATED state (score/verdict_level/confidence/lead_count/
    review_priority/coverage) -- exactly what dumpex.hunt._coverage.
    derive_status()/derive_coverage_status() produce when a hunter never
    got the data source it needed (see that module's own docstring)."""
    yara_only = record.hunter == "yara"
    return dataclasses.replace(
        record, status="NOT_EVALUATED", score=0, verdict_level="not_evaluated",
        confidence=None if yara_only else "none",
        lead_count=None if yara_only else 0,
        review_priority=None if yara_only else "none",
        coverage=CoverageReport(status=CoverageStatus.NOT_EVALUATED),
        findings=[],
    )


def all_seven_not_evaluated():
    """One NOT_EVALUATED record per hunter, in the fixed HUNTERS order --
    the "--hunt all, nothing could be evaluated" scenario (e.g. every
    required stream absent from the dump)."""
    return [_as_not_evaluated(r) for r in all_seven_detected_variety()]


def hunt_summary_for(records, selected="all", memory_regions=None):
    """Thin delegator to the real production reducer
    (dumpex.hunt.summary.build_hunt_summary) -- every schema test
    that calls this is therefore an end-to-end test of that reducer
    too, not a second, independently-maintained copy of its logic.

    `investigation_actions` (issue #19) is NOT part of build_hunt_summary()
    itself (see dumpex.hunt._investigation_actions_json()'s own docstring
    for why it's computed at each real call site instead) -- this
    delegator adds it the same way, so existing callers that don't pass
    `memory_regions` keep getting `investigation_actions: []` (still a
    valid, required field) without having to know this field exists.
    Pass `memory_regions` (dumpex.core.memory.get_memory_regions(mf)'s own
    return shape, or a list of tests.fixtures.fakes.Region) to exercise a
    populated queue."""
    summary = build_hunt_summary(records, selected=selected)
    if selected == "all":
        actions = build_investigation_queue(records, memory_regions or [])
        summary["investigation_actions"] = [a.to_dict() for a in actions]
    else:
        summary["investigation_actions"] = []
    return summary

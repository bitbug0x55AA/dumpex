"""
Unit tests for the v2.4 hunt record types (dumpex.output.records:
HunterRecord, HuntRegionRef, HuntThreadRef, HuntPeHeaderHit,
InjectionDetails, and the 6 shape-only *Details stubs). See
docs/hunt_migration_field_matrix.md for the field-by-field rationale these
types implement.
"""
import pytest

from dumpex.output.coverage import CoverageReport, CoverageStatus
from dumpex.output.records import (
    HunterRecord, HuntRegionRef, HuntThreadRef, HuntPeHeaderHit, InjectionDetails,
    HollowingDetails, StompingDetails, PipeDetails, CsBeaconDetails, YaraDetails,
    ObfuscationDetails,
)


def _complete_coverage():
    return CoverageReport(status=CoverageStatus.COMPLETE)


# ── HuntRegionRef ────────────────────────────────────────────────────────

def test_region_ref_requires_hex_addresses():
    with pytest.raises(ValueError):
        HuntRegionRef(base_address="0x1000", allocation_base=None, size=0x1000,
                      type="MEM_PRIVATE", protect="PAGE_READWRITE")


def test_region_ref_to_dict_shape():
    r = HuntRegionRef(base_address="0x0000000000001000", allocation_base=None,
                       size=0x1000, type="MEM_PRIVATE", protect="PAGE_READWRITE")
    assert r.to_dict() == {
        "base_address": "0x0000000000001000", "allocation_base": None,
        "size": 0x1000, "type": "MEM_PRIVATE", "protect": "PAGE_READWRITE",
    }


# ── HuntThreadRef ────────────────────────────────────────────────────────

def test_thread_ref_ip_requires_ip_reg():
    with pytest.raises(ValueError):
        HuntThreadRef(tid=1, ip="0x0000000000001000", ip_reg=None)


def test_thread_ref_ip_reg_requires_ip():
    with pytest.raises(ValueError):
        HuntThreadRef(tid=1, ip=None, ip_reg="RIP")


def test_thread_ref_to_dict_shape():
    t = HuntThreadRef(tid=5, start_address="0x0000000000002000",
                       ip="0x0000000000002000", ip_reg="RIP")
    assert t.to_dict() == {
        "tid": 5, "start_address": "0x0000000000002000",
        "ip": "0x0000000000002000", "ip_reg": "RIP",
    }


# ── HuntPeHeaderHit ──────────────────────────────────────────────────────

def _region():
    return HuntRegionRef(base_address="0x0000000000001000", allocation_base=None,
                          size=0x1000, type="MEM_PRIVATE", protect="PAGE_READWRITE")


def test_pe_header_hit_valid_true_rejects_reason():
    with pytest.raises(ValueError):
        HuntPeHeaderHit(region=_region(), valid=True, reason="bad header")


def test_pe_header_hit_valid_false_rejects_pe_fields():
    with pytest.raises(ValueError):
        HuntPeHeaderHit(region=_region(), valid=False, machine_name="AMD64")


def test_pe_header_hit_valid_true_requires_pe_fields():
    # A "valid" header with no PE facts attached at all is not a legal
    # construction -- a structurally-valid header always carries them.
    with pytest.raises(ValueError):
        HuntPeHeaderHit(region=_region(), valid=True)


def test_pe_header_hit_valid_true_requires_every_pe_field():
    # Partial: some PE fields set, one left None -- still rejected.
    with pytest.raises(ValueError):
        HuntPeHeaderHit(region=_region(), valid=True, machine_name="AMD64",
                        is_pe32_plus=True, number_of_sections=1, entry_point_rva=0x1000)
                        # image_base left unset


def test_pe_header_hit_valid_false_requires_reason():
    with pytest.raises(ValueError):
        HuntPeHeaderHit(region=_region(), valid=False)


def test_pe_header_hit_valid_true_to_dict():
    hit = HuntPeHeaderHit(region=_region(), valid=True, machine_name="AMD64",
                           is_pe32_plus=True, number_of_sections=1, entry_point_rva=0x1000,
                           image_base="0x0000000140000000")
    d = hit.to_dict()
    assert d["valid"] is True
    assert d["reason"] is None
    assert d["machine_name"] == "AMD64"
    assert d["region"]["base_address"] == "0x0000000000001000"


def test_pe_header_hit_valid_false_to_dict():
    hit = HuntPeHeaderHit(region=_region(), valid=False, reason="truncated header")
    d = hit.to_dict()
    assert d["valid"] is False
    assert d["reason"] == "truncated header"
    assert d["machine_name"] is None


# ── InjectionDetails ─────────────────────────────────────────────────────

def _empty_injection_details():
    return InjectionDetails(
        rwx=[], hidden_pe_validated=[], hidden_pe_unvalidated=[],
        suspicious_validated_pe_hits=[], informational_validated_pe_hits=[],
        threads=[], thread_contexts=[], rwx_and_pe_alloc_bases=[],
        rip_hits=[], rip_full_correlation=[], start_hits=[])


def test_injection_details_empty_to_dict():
    d = _empty_injection_details().to_dict()
    assert d == {
        "rwx": [], "hidden_pe_validated": [], "hidden_pe_unvalidated": [],
        "suspicious_validated_pe_hits": [], "informational_validated_pe_hits": [],
        "threads": [], "thread_contexts": [], "rwx_and_pe_alloc_bases": [],
        "rip_hits": [], "rip_full_correlation": [], "start_hits": [],
    }


def test_injection_details_rejects_raw_object_in_rwx():
    with pytest.raises(TypeError):
        InjectionDetails(
            rwx=[object()], hidden_pe_validated=[], hidden_pe_unvalidated=[],
            suspicious_validated_pe_hits=[], informational_validated_pe_hits=[],
            threads=[], thread_contexts=[], rwx_and_pe_alloc_bases=[],
            rip_hits=[], rip_full_correlation=[], start_hits=[])


def test_injection_details_rwx_and_pe_alloc_bases_must_be_hex():
    with pytest.raises(ValueError):
        InjectionDetails(
            rwx=[], hidden_pe_validated=[], hidden_pe_unvalidated=[],
            suspicious_validated_pe_hits=[], informational_validated_pe_hits=[],
            threads=[], thread_contexts=[], rwx_and_pe_alloc_bases=["0x1000"],
            rip_hits=[], rip_full_correlation=[], start_hits=[])


def test_injection_details_full_shape_to_dict():
    details = InjectionDetails(
        rwx=[_region()], hidden_pe_validated=[], hidden_pe_unvalidated=[],
        suspicious_validated_pe_hits=[], informational_validated_pe_hits=[],
        threads=[HuntThreadRef(tid=1, start_address="0x0000000000002000")],
        thread_contexts=[], rwx_and_pe_alloc_bases=["0x0000000000001000"],
        rip_hits=[], rip_full_correlation=[], start_hits=[])
    d = details.to_dict()
    assert d["rwx"][0]["base_address"] == "0x0000000000001000"
    assert d["threads"][0]["tid"] == 1
    assert d["rwx_and_pe_alloc_bases"] == ["0x0000000000001000"]


# ── HunterRecord ─────────────────────────────────────────────────────────

def test_hunter_record_injection_round_trip():
    rec = HunterRecord(
        hunter="injection", status="DETECTED", score=3, max_score=3,
        verdict_level="high", confidence="high", lead_count=0, review_priority="high",
        coverage=_complete_coverage(), findings=[], details=_empty_injection_details())
    d = rec.to_dict()
    assert d["hunter"] == "injection"
    assert d["score"] == 3
    assert d["coverage"]["status"] == "complete"
    assert d["details"]["rwx"] == []


def test_hunter_record_rejects_unknown_hunter():
    with pytest.raises(ValueError):
        HunterRecord(
            hunter="not-a-real-hunter", status="DETECTED", score=1, max_score=1,
            verdict_level="high", confidence="high", lead_count=0, review_priority="high",
            coverage=_complete_coverage(), findings=[], details=_empty_injection_details())


def test_hunter_record_rejects_details_type_mismatch():
    with pytest.raises(TypeError):
        HunterRecord(
            hunter="hollowing", status="DETECTED", score=1, max_score=2,
            verdict_level="likely", confidence="medium", lead_count=0, review_priority="high",
            coverage=_complete_coverage(), findings=[],
            details=_empty_injection_details())   # wrong Details type for hollowing


def test_hunter_record_yara_requires_all_four_fields_null():
    yara_details = YaraDetails(matches=[], rules_hit=[])
    # all-null: valid
    rec = HunterRecord(
        hunter="yara", status="NOT_EVALUATED", score=0, max_score=None,
        verdict_level="not_evaluated", confidence=None, lead_count=None, review_priority=None,
        coverage=CoverageReport(status=CoverageStatus.NOT_EVALUATED), findings=[],
        details=yara_details)
    assert rec.to_dict()["max_score"] is None


def test_hunter_record_yara_rejects_nonempty_findings():
    # YARA deliberately stays off the shared Finding model -- findings must
    # be [] for hunter="yara", never a populated list of arbitrary dicts.
    yara_details = YaraDetails(matches=[], rules_hit=["HitRule"])
    with pytest.raises(ValueError):
        HunterRecord(
            hunter="yara", status="DETECTED", score=1, max_score=None,
            verdict_level="likely", confidence=None, lead_count=None, review_priority=None,
            coverage=_complete_coverage(), findings=[{"check": "not-a-real-finding"}],
            details=yara_details)


def test_hunter_record_yara_rejects_partially_set_fields():
    yara_details = YaraDetails(matches=[], rules_hit=[])
    with pytest.raises(ValueError):
        HunterRecord(
            hunter="yara", status="DETECTED", score=1, max_score=None,
            verdict_level="likely", confidence="high",   # confidence set -- must be None for yara
            lead_count=None, review_priority=None,
            coverage=_complete_coverage(), findings=[], details=yara_details)


def test_hunter_record_non_yara_rejects_null_confidence():
    with pytest.raises(ValueError):
        HunterRecord(
            hunter="injection", status="DETECTED", score=1, max_score=3,
            verdict_level="possible", confidence=None,   # must be set for non-yara
            lead_count=0, review_priority="high",
            coverage=_complete_coverage(), findings=[], details=_empty_injection_details())


def test_hunter_record_rejects_non_coverage_report():
    with pytest.raises(TypeError):
        HunterRecord(
            hunter="injection", status="DETECTED", score=1, max_score=3,
            verdict_level="possible", confidence="high", lead_count=0, review_priority="high",
            coverage="complete",   # must be a real CoverageReport, not a bare string
            findings=[], details=_empty_injection_details())


def test_hunter_record_rejects_bad_findings_shape():
    with pytest.raises(TypeError):
        HunterRecord(
            hunter="injection", status="DETECTED", score=1, max_score=3,
            verdict_level="possible", confidence="high", lead_count=0, review_priority="high",
            coverage=_complete_coverage(), findings=["not-a-dict"],
            details=_empty_injection_details())


# HUNTERS itself is not re-asserted against a second copy of the seven
# names here -- that assertion can only fail if this file and records.py
# are edited apart, which no roster change ever does. What HUNTERS has to
# agree with lives elsewhere and is pinned there instead:
#   * tests/unit/test_hunter_roster_alignment.py -- the four schema
#     enums, the console display maps, region correlation's collector
#     table, cmd_hunt()'s accepted set, the CLI help, README and
#     CLI_REFERENCE.
#   * tests/integration/test_hunt_all_seven_collectors.py -- the emitted
#     order from a real `--hunt all` run.
#   * tests/unit/test_corpus_manager.py -- scripts/corpus_manager.py's
#     own copy.


# ── The 6 not-yet-wired *Details shapes ────────────────────────────────

def test_hollowing_details_to_dict():
    d = HollowingDetails(
        image_base="0x0000000140000000", mem_private_at_base=True, mz_header_present=True,
        is_rwx_at_base=True, peb_image_path=r"C:\a.exe", module_name="a.exe",
        name_mismatch=False).to_dict()
    assert d["image_base"] == "0x0000000140000000"
    assert d["mem_private_at_base"] is True


def test_hollowing_details_allows_null_image_base_when_peb_missing():
    # PR2b: the NOT_EVALUATED (PEB-missing) case genuinely has no image
    # base at all -- HollowingDetails must accept null here, unlike
    # every other hunter's *Details (which always has SOME evidence to
    # convert even under incomplete coverage).
    d = HollowingDetails(
        image_base=None, mem_private_at_base=None, mz_header_present=None,
        is_rwx_at_base=None, peb_image_path=None, module_name=None,
        name_mismatch=None).to_dict()
    assert d["image_base"] is None


def test_stomping_details_rejects_non_dict_entries():
    with pytest.raises(TypeError):
        StompingDetails(protection_leads=["oops"], verified_changes=[])


def test_stomping_details_to_dict():
    d = StompingDetails(protection_leads=[{"module": "a.dll"}], verified_changes=[]).to_dict()
    assert d["protection_leads"] == [{"module": "a.dll"}]


def test_pipe_details_to_dict():
    d = PipeDetails(handle_pipes=[], private_pipes=[], c2_context=[],
                     framework_pipes=[], unbacked_in_rgn=[]).to_dict()
    assert d == {"handle_pipes": [], "private_pipes": [], "c2_context": [],
                 "framework_pipes": [], "unbacked_in_rgn": []}


def test_cs_beacon_details_config_count_must_match():
    with pytest.raises(ValueError):
        CsBeaconDetails(configs=[{"va": 1}], config_count=2)


def test_cs_beacon_details_to_dict():
    d = CsBeaconDetails(configs=[{"va": 1}], config_count=1).to_dict()
    assert d["config_count"] == 1


def test_yara_details_rules_hit_must_be_strings():
    with pytest.raises(TypeError):
        YaraDetails(matches=[], rules_hit=[123])


def test_obfuscation_details_to_dict():
    d = ObfuscationDetails(sleep_mask=[], entropy=[], base64=[], xor=[], compressed=[],
                            hidden_pe=[], hidden_shellcode=[]).to_dict()
    assert set(d.keys()) == {"sleep_mask", "entropy", "base64", "xor", "compressed",
                              "hidden_pe", "hidden_shellcode"}


# ── Additional negative-branch coverage (CI fail-under=95 on records.py) ──

def test_region_ref_rejects_empty_type():
    with pytest.raises(ValueError):
        HuntRegionRef(base_address="0x0000000000001000", allocation_base=None,
                      size=0x1000, type="", protect="PAGE_READWRITE")


def test_region_ref_rejects_empty_protect():
    with pytest.raises(ValueError):
        HuntRegionRef(base_address="0x0000000000001000", allocation_base=None,
                      size=0x1000, type="MEM_PRIVATE", protect="")


def test_thread_ref_rejects_non_string_ip_reg():
    with pytest.raises(ValueError):
        HuntThreadRef(tid=1, ip="0x0000000000001000", ip_reg=123)


def test_thread_region_hit_rejects_wrong_thread_type():
    from dumpex.output.records import HuntThreadRegionHit
    with pytest.raises(TypeError):
        HuntThreadRegionHit(thread=object(), region=_region())


def test_thread_region_hit_rejects_wrong_region_type():
    from dumpex.output.records import HuntThreadRegionHit
    with pytest.raises(TypeError):
        HuntThreadRegionHit(thread=HuntThreadRef(tid=1), region=object())


def test_pe_header_hit_rejects_wrong_region_type():
    with pytest.raises(TypeError):
        HuntPeHeaderHit(region=object(), valid=False, reason="bad header")


def test_injection_details_alloc_bases_rejects_non_str():
    with pytest.raises(TypeError):
        InjectionDetails(
            rwx=[], hidden_pe_validated=[], hidden_pe_unvalidated=[],
            suspicious_validated_pe_hits=[], informational_validated_pe_hits=[],
            threads=[], thread_contexts=[], rwx_and_pe_alloc_bases=[123],
            rip_hits=[], rip_full_correlation=[], start_hits=[])


def test_pipe_details_rejects_non_dict_in_every_field():
    valid = {"handle_pipes": [], "private_pipes": [], "c2_context": [],
             "framework_pipes": [], "unbacked_in_rgn": []}
    for name in valid:
        kwargs = dict(valid)
        kwargs[name] = ["not-a-dict"]
        with pytest.raises(TypeError):
            PipeDetails(**kwargs)


def test_cs_beacon_details_rejects_non_dict_configs():
    with pytest.raises(TypeError):
        CsBeaconDetails(configs=["not-a-dict"], config_count=1)


def test_yara_details_rejects_non_dict_matches():
    with pytest.raises(TypeError):
        YaraDetails(matches=["not-a-dict"], rules_hit=[])


def test_obfuscation_details_rejects_non_dict_in_every_field():
    valid = {"sleep_mask": [], "entropy": [], "base64": [], "xor": [], "compressed": [],
             "hidden_pe": [], "hidden_shellcode": []}
    for name in valid:
        kwargs = dict(valid)
        kwargs[name] = ["not-a-dict"]
        with pytest.raises(TypeError):
            ObfuscationDetails(**kwargs)


def test_hunter_record_rejects_unknown_status():
    with pytest.raises(ValueError):
        HunterRecord(
            hunter="injection", status="MADE_UP_STATUS", score=1, max_score=3,
            verdict_level="possible", confidence="high", lead_count=0, review_priority="high",
            coverage=_complete_coverage(), findings=[], details=_empty_injection_details())


def test_hunter_record_rejects_unknown_verdict_level():
    with pytest.raises(ValueError):
        HunterRecord(
            hunter="injection", status="DETECTED", score=1, max_score=3,
            verdict_level="made_up_level", confidence="high", lead_count=0, review_priority="high",
            coverage=_complete_coverage(), findings=[], details=_empty_injection_details())


def test_hunter_record_rejects_unknown_confidence():
    with pytest.raises(ValueError):
        HunterRecord(
            hunter="injection", status="DETECTED", score=1, max_score=3,
            verdict_level="possible", confidence="made_up", lead_count=0, review_priority="high",
            coverage=_complete_coverage(), findings=[], details=_empty_injection_details())


def test_hunter_record_rejects_unknown_review_priority():
    with pytest.raises(ValueError):
        HunterRecord(
            hunter="injection", status="DETECTED", score=1, max_score=3,
            verdict_level="possible", confidence="high", lead_count=0, review_priority="made_up",
            coverage=_complete_coverage(), findings=[], details=_empty_injection_details())


def test_pe_header_hit_valid_true_rejects_non_string_machine_name():
    with pytest.raises(ValueError):
        HuntPeHeaderHit(region=_region(), valid=True, machine_name=123,
                        is_pe32_plus=True, number_of_sections=1, entry_point_rva=0x1000,
                        image_base="0x0000000140000000")


def test_pe_header_hit_valid_true_rejects_empty_machine_name():
    with pytest.raises(ValueError):
        HuntPeHeaderHit(region=_region(), valid=True, machine_name="",
                        is_pe32_plus=True, number_of_sections=1, entry_point_rva=0x1000,
                        image_base="0x0000000140000000")


def test_pe_header_hit_valid_true_rejects_non_bool_is_pe32_plus():
    with pytest.raises(ValueError):
        HuntPeHeaderHit(region=_region(), valid=True, machine_name="AMD64",
                        is_pe32_plus=1, number_of_sections=1, entry_point_rva=0x1000,
                        image_base="0x0000000140000000")


def test_pe_header_hit_valid_false_rejects_empty_reason():
    with pytest.raises(ValueError):
        HuntPeHeaderHit(region=_region(), valid=False, reason="")


def test_pe_header_hit_valid_false_rejects_non_string_reason():
    with pytest.raises(ValueError):
        HuntPeHeaderHit(region=_region(), valid=False, reason=123)

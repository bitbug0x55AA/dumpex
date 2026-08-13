"""
Unit tests for dumpex.hunt.stomping.collect.collect_stomping_record() --
PR2b's HunterRecord-producing path for the stomping hunter. Every
scenario here mirrors tests/hunt/test_stomping.py's own fixtures (same
literal inputs), confirming collect_stomping_record() and the console
path (_hunt_stomping()) always agree on the same underlying Report.
"""
import json
import os
import tempfile

import pytest

from tests.fixtures.fakes import (Region, Module, FakeStream, FakeMF, build_pe_header,
                                   IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
                                   mem_reader, matching_module_and_ref)

import dumpex.hunt.stomping as stomping
from dumpex.hunt.stomping.collect import collect_stomping_record
from dumpex.hunt.stomping.config import IOC_SCAN_MAX
from dumpex.output.records import HunterRecord, StompingDetails

jsonschema = pytest.importorskip("jsonschema")
from dumpex.schemas import CURRENT_SCHEMA, schema_path


@pytest.fixture(scope="module")
def hunter_record_validator():
    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    wrapper = {"$schema": schema["$schema"], "$ref": "#/$defs/hunterRecord", "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


def _assert_matches_console_dict(rec: HunterRecord, console_dict: dict):
    assert rec.score == console_dict["score"]
    assert rec.max_score == console_dict["max_score"]
    assert rec.status == console_dict["status"]
    assert rec.verdict_level == console_dict["verdict_level"]
    assert rec.confidence == console_dict["confidence"]
    assert rec.lead_count == console_dict["lead_count"]
    assert rec.review_priority == console_dict["review_priority"]
    assert rec.findings == console_dict["findings"]


def test_normal_writecopy_is_clean(hunter_record_validator):
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        console_dict = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        rec = collect_stomping_record(MF(), ref_dir=d)

    assert isinstance(rec, HunterRecord)
    assert rec.hunter == "stomping"
    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert rec.coverage.status.value == "complete"
    assert isinstance(rec.details, StompingDetails)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_no_ref_dir_is_inconclusive_partial(hunter_record_validator):
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text})

    console_dict = stomping._hunt_stomping(MF(), verbose=False, ref_dir=None)
    rec = collect_stomping_record(MF(), ref_dir=None)

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "INCONCLUSIVE"
    assert rec.coverage.status.value == "partial"
    assert any(lim.code.value == "STOMPING_REFERENCE_NOT_SUPPLIED"
               for lim in rec.coverage.limitations)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_all_headers_invalid_is_partial(hunter_record_validator):
    module_base = 0x7ff600000000
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base, module_base, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: b"not a real PE header"})

    console_dict = stomping._hunt_stomping(MF(), verbose=False, ref_dir=None)
    rec = collect_stomping_record(MF(), ref_dir=None)

    _assert_matches_console_dict(rec, console_dict)
    assert rec.coverage.status.value == "partial"
    assert any(lim.code.value == "MODULE_HEADER_PARSE_FAILED"
               for lim in rec.coverage.limitations)
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_oversized_ioc_region_is_identified_in_the_typed_record(hunter_record_validator):
    """The unscored IOC-string scan's oversized skips reach `--json` as a
    real SCAN_REGION_OVERSIZED_SKIPPED limitation carrying the region's own
    identity -- the same shape every other hunter's oversized skips use
    (dumpex.hunt._coverage.region_scan_target), so one consumer reads them
    all. Mirrors tests/hunt/test_stomping.py::test_only_oversized_ioc_
    region_is_incomplete_not_clean."""
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    oversized_base = module_base + 0x100000
    oversized_size = IOC_SCAN_MAX + 0x100000
    regions = [Region(oversized_base, module_base, oversized_size, "MEM_COMMIT",
                       "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    stomping.read_region = mem_reader({module_base: header,
                                        module_base + section["vaddr"]: mem_text})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        console_dict = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        rec = collect_stomping_record(MF(), ref_dir=d)

    _assert_matches_console_dict(rec, console_dict)
    # coverage.status and the console dict's own coverage_status agree, and
    # the status the contract pins to "partial" coverage comes with them --
    # never a NOT_DETECTED_IN_SCANNED_SCOPE record claiming complete
    # coverage over a region that was never read.
    assert rec.coverage.status.value == "partial"
    assert console_dict["coverage_status"] == "partial"
    assert rec.status == "INCONCLUSIVE"

    lim = next(l for l in rec.coverage.limitations
               if l.code.value == "SCAN_REGION_OVERSIZED_SKIPPED")
    assert lim.source == "ioc_string_scan"
    assert lim.scope is None
    assert lim.affected_count == 1
    assert len(lim.targets) == lim.affected_count
    target = lim.targets[0]
    assert target.kind.value == "memory_region"
    assert target.base_address == oversized_base
    assert target.size == oversized_size
    assert target.size_limit == IOC_SCAN_MAX
    assert target.allocation_base == module_base
    assert (target.state, target.type, target.protection) == (
        "MEM_COMMIT", "MEM_IMAGE", "PAGE_EXECUTE_READ")
    # No memory-segment table in this fixture, so the region's bytes were
    # never written to the .dmp at all -- the distinction between "extract
    # it from this dump" and "recollect" (see ScanTarget.file_offset).
    assert target.file_offset is None
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_ioc_region_read_failure_is_identified_in_the_typed_record(hunter_record_validator):
    """Read-failure companion to the oversized case above: attached to the
    same `ioc_string_scan` source, equally unable to leave coverage reading
    "complete", and (issue #28) the failed region's own identity is
    retained, not just counted."""
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    unreadable_base = module_base + 0x100000
    regions = [Region(unreadable_base, module_base, 0x1000, "MEM_COMMIT",
                       "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")

    base_reader = mem_reader({module_base: header,
                               module_base + section["vaddr"]: mem_text})

    def flaky_reader(mf, addr, size):
        if addr == unreadable_base:
            raise OSError("simulated unreadable region")
        return base_reader(mf, addr, size)
    stomping.read_region = flaky_reader

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        console_dict = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        rec = collect_stomping_record(MF(), ref_dir=d)

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "INCONCLUSIVE"
    assert rec.coverage.status.value == "partial"
    lim = next(l for l in rec.coverage.limitations
               if l.code.value == "SCAN_REGION_READ_FAILED")
    assert lim.source == "ioc_string_scan"
    assert lim.affected_count == 1 == len(lim.targets)
    target = lim.targets[0]
    assert target.base_address == unreadable_base
    assert target.size_limit is None
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_ioc_region_short_read_is_identified_in_the_typed_record(hunter_record_validator):
    """Short-read companion to the oversized/read-failure cases above: an
    eligible region that returned fewer bytes than its own declared
    RegionSize (dumpex.hunt.stomping.memory_scan.scan_ioc_strings's own
    `len(data) < r.RegionSize` check) is a coverage gap too, reported as
    SCAN_REGION_SHORT_READ under the same `ioc_string_scan` source -- but
    the readable PREFIX is still scanned, so a real IOC hit sitting inside
    it must not be discarded just because the rest of the region was
    truncated."""
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]

    filler = bytearray((i * 7) % 251 for i in range(0x1000))
    filler[0x40:0x40 + 8] = b"mimikatz"   # strong IOC token, inside the readable prefix
    short_read_base = module_base + 0x100000
    full_size = 0x1000
    truncated_size = 0x800   # only half comes back -- the token at 0x40 is still included
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE"),
               Region(short_read_base, module_base, full_size,
                      "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")

    base_reader = mem_reader({module_base: header, module_base + section["vaddr"]: mem_text,
                               short_read_base: bytes(filler)})

    def short_reader(mf, addr, size):
        if addr == short_read_base:
            return base_reader(mf, addr, size)[:truncated_size]
        return base_reader(mf, addr, size)
    stomping.read_region = short_reader

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(ref_file)
        console_dict = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        rec = collect_stomping_record(MF(), ref_dir=d)

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "INCONCLUSIVE"
    assert rec.coverage.status.value == "partial"

    lim = next(l for l in rec.coverage.limitations
               if l.code.value == "SCAN_REGION_SHORT_READ")
    assert lim.source == "ioc_string_scan"
    assert lim.affected_count == 1 == len(lim.targets)
    # issue #28: the short-read region's own identity is retained.
    target = lim.targets[0]
    assert target.base_address == short_read_base
    assert target.size_limit is None

    # The hit in the readable prefix survives the truncation.
    ioc_findings = [x for x in rec.findings if x["check"] == "stomping.ioc_string_lead"]
    assert len(ioc_findings) == 1
    assert "mimikatz" in ioc_findings[0]["facts"][0]
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_oversized_ioc_region_survives_not_evaluated_when_module_list_absent(hunter_record_validator):
    """ModuleListStream absent -> the hunter-level `evaluated` gate is
    False regardless of the IOC scan (the scored content-diff check needs
    that stream and never runs at all -- see `_build_stomping_report()`'s
    own `evaluated = mem_info_available and module_list_available`), so
    `status`/`coverage.status` are NOT_EVALUATED. But scan_ioc_strings()
    only needs MemoryInfoListStream (it tolerates an empty/absent module
    list via addr_to_module returning None), so it still runs and can
    still find a real oversized region -- that target must not be
    silently dropped from --json just because build_coverage_report()'s
    own group-absent short-circuit fires for the UNRELATED `modules`
    source. See dumpex/hunt/stomping/__init__.py's own
    _stomping_coverage_report, which appends this limitation to the
    already-built report rather than folding it into completeness_checks."""
    module_base = 0x7ff600000000
    oversized_base = module_base + 0x100000
    oversized_size = IOC_SCAN_MAX + 0x100000
    regions = [Region(oversized_base, module_base, oversized_size, "MEM_COMMIT",
                       "PAGE_EXECUTE_READ", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        # `modules` stays the FakeMF default (None) -- ModuleListStream
        # absent from this dump.

    stomping.read_region = mem_reader({})

    console_dict = stomping._hunt_stomping(MF(), verbose=False, ref_dir=None)
    rec = collect_stomping_record(MF(), ref_dir=None)

    _assert_matches_console_dict(rec, console_dict)
    assert rec.status == "NOT_EVALUATED"
    assert rec.coverage.status.value == "not_evaluated"
    assert console_dict["status"] == "NOT_EVALUATED"
    assert console_dict["coverage_status"] == "not_evaluated"
    assert any("ModuleListStream" in r for r in console_dict["coverage_reasons"])

    lim = next(l for l in rec.coverage.limitations
               if l.code.value == "SCAN_REGION_OVERSIZED_SKIPPED")
    assert lim.source == "ioc_string_scan"
    assert lim.affected_count == 1
    target = lim.targets[0]
    assert target.kind.value == "memory_region"
    assert target.base_address == oversized_base
    assert target.size == oversized_size
    assert target.size_limit == IOC_SCAN_MAX
    assert list(hunter_record_validator.iter_errors(rec.to_dict())) == []


def test_verified_change_scores_1_then_2_with_rip(hunter_record_validator):
    module_base = 0x7ff600000000
    timestamp = 0x11111111
    sections = [{"name": b".text", "vaddr": 0x1000, "vsize": 0x2000, "rawptr": 0x400,
                 "rawsize": 0x2000, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}]
    header = build_pe_header(sections, timestamp=timestamp, size_of_image=0x5000,
                              image_base=module_base)

    text_original = bytes((i * 7) % 251 for i in range(0x2000))
    ref_file = bytearray(header)
    ref_file += b'\x00' * (sections[0]["rawptr"] - len(ref_file))
    ref_file += text_original

    mem_text = bytearray(text_original)
    mem_text[0x100:0x110] = b'\xCC' * 0x10

    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + 0x1000, module_base, 0x2000, "MEM_COMMIT",
                       "PAGE_EXECUTE_READ", "MEM_IMAGE")]
    read_map = {module_base: header, module_base + 0x1000: bytes(mem_text)}

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(bytes(ref_file))

        stomping.read_region = mem_reader(read_map)
        stomping.get_thread_contexts = lambda mf: []
        console_dict1 = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        rec1 = collect_stomping_record(MF(), ref_dir=d)
        _assert_matches_console_dict(rec1, console_dict1)
        assert rec1.score == 1
        assert rec1.status == "DETECTED"
        assert len(rec1.details.verified_changes) == 1
        vc = rec1.details.verified_changes[0]
        assert vc["va_start"] == f"0x{module_base + 0x1000:016x}"
        assert vc["module"]["name"] == r"C:\Windows\System32\legit.dll"
        assert vc["rip_in_changed_range"] is False
        assert list(hunter_record_validator.iter_errors(rec1.to_dict())) == []

        changed_va = module_base + 0x1000 + 0x100
        stomping.get_thread_contexts = lambda mf: [{"ThreadId": 1, "ip": changed_va + 2,
                                                      "ip_reg": "RIP", "is_wow64": False}]
        console_dict2 = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        rec2 = collect_stomping_record(MF(), ref_dir=d)
        _assert_matches_console_dict(rec2, console_dict2)
        assert rec2.score == 2
        assert rec2.details.verified_changes[0]["rip_in_changed_range"] is True
        assert list(hunter_record_validator.iter_errors(rec2.to_dict())) == []

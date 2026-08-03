"""
Unit tests for dumpex.hunt.injection.collect.collect_injection_record() --
the v2.4 migration's (PR2) HunterRecord-producing path for the injection
hunter. Every scenario here mirrors tests/fixtures/hunt_cases.py's
injection_detected_full_correlation/injection_inconclusive_no_thread_context
builders exactly (same literal inputs), so the score/status/verdict/
confidence this test asserts are the SAME values PR1's compatibility-freeze
suite already pinned for `_hunt_injection()` -- confirming collect_
injection_record() and the console path agree on the same underlying
Report, never a separately (and possibly differently) computed one.

test_only_memory_info_missing_is_partial_not_complete/
test_only_thread_info_missing_is_partial_not_complete are the regression
tests for a confirmed bug in an earlier draft of this file: `memory_info`/
`thread_info` were only in `evaluation_sources` (all-absent -> NOT_
EVALUATED), never in `completeness_checks` too -- so a dump missing only
ONE of the two (the other still present) produced coverage.status=
"complete" instead of "partial", silently disagreeing with the v1.1
`coverage_status` field computed from the exact same facts.
"""
import json
import re

from tests.fixtures.fakes import (
    Region, Module, ThreadInfo, Ctx, Thread, FakeStream, FakeMF,
    build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader,
)

import dumpex.hunt.injection as injection
from dumpex.hunt.injection.collect import collect_injection_record
from dumpex.output.records import HunterRecord, InjectionDetails, HuntThreadRegionHit


def test_collect_injection_record_detected_full_correlation(monkeypatch):
    alloc_base = 0x7ff700000000
    pe_bytes = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000, "rawptr": 0x400,
          "rawsize": 0x1000, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300)
    regions = [
        Region(alloc_base, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(alloc_base + 0x2000, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mods = [Module(0x7ffe00000000, 0x10000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x1, alloc_base + 0x2000)]
    thread_list = [Thread(0x1, Ctx(alloc_base + 0x2000))]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        threads        = FakeStream(thread_list, "threads")
    monkeypatch.setattr(injection, "read_region", mem_reader({alloc_base + 0x2000: pe_bytes}))

    rec = collect_injection_record(MF())
    assert isinstance(rec, HunterRecord)
    assert rec.hunter == "injection"
    # Same values PR1's test_hunt_compat_freeze.py::test_injection_detected_
    # full_correlation already froze for _hunt_injection()'s v1.1 dict.
    assert rec.score == 3
    assert rec.max_score == 3
    assert rec.status == "DETECTED"
    assert rec.verdict_level == "high"
    assert rec.confidence == "high"
    assert rec.lead_count == 3
    assert rec.review_priority == "high"
    assert rec.coverage.status.value == "partial"

    d = rec.to_dict()
    # No raw-object str(obj) addresses anywhere in the serialized output --
    # the confirmed pre-migration defect (field matrix finding #1) this
    # collect path exists specifically to fix.
    blob = json.dumps(d)
    assert not re.search(r"object at 0x[0-9A-Fa-f]+", blob)

    assert isinstance(rec.details, InjectionDetails)
    assert len(rec.details.rwx) == 1
    assert rec.details.rwx[0].base_address == "0x00007ff700000000"
    assert len(rec.details.hidden_pe_validated) == 1
    assert rec.details.hidden_pe_validated[0].valid is True
    assert rec.details.hidden_pe_validated[0].machine_name == "AMD64"
    assert len(rec.details.rip_full_correlation) == 1
    hit = rec.details.rip_full_correlation[0]
    assert isinstance(hit, HuntThreadRegionHit)
    assert hit.thread.ip == "0x00007ff700002000"
    # The region RIP is actually executing inside (the hidden-PE region),
    # whose AllocationBase is the RWX+PE allocation base.
    assert hit.region.base_address == "0x00007ff700002000"
    assert hit.region.allocation_base == "0x00007ff700000000"
    assert rec.details.rwx_and_pe_alloc_bases == ["0x00007ff700000000"]

    # The one coverage limitation this scenario is known to hit (a short
    # read while validating the PE header, by construction of the test's
    # own trailing-padding-truncated header bytes).
    codes = {lim.code.value for lim in rec.coverage.limitations}
    assert codes == {"PE_HEADER_SHORT_READ"}
    assert rec.coverage.sources["memory_info"].record_count == 2
    assert rec.coverage.sources["thread_info"].record_count == 1
    assert rec.coverage.sources["modules"].record_count == 1
    assert rec.coverage.sources["thread_list"].record_count == 1


def test_collect_injection_record_inconclusive_no_thread_context(monkeypatch):
    dummy_regions = [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")   # present-but-empty -> treated as absent
        threads        = None
    monkeypatch.setattr(injection, "read_region", mem_reader({}))

    rec = collect_injection_record(MF())
    assert rec.score == 0
    assert rec.status == "INCONCLUSIVE"
    assert rec.verdict_level == "inconclusive"
    assert rec.coverage.status.value == "partial"
    codes = {lim.code.value for lim in rec.coverage.limitations}
    # thread_info is present-but-empty here (empty ThreadInfoListStream),
    # which reads as ABSENT for coverage purposes -- both the thread_info
    # gap itself AND the resulting inability to run RIP correlation
    # (thread_context) are now surfaced, not just the latter.
    assert codes == {"SOURCE_ABSENT", "THREAD_CONTEXT_UNAVAILABLE"}
    assert rec.details.rwx == []
    assert rec.details.threads == []


def test_only_memory_info_missing_is_partial_not_complete():
    """Regression: memory_info absent, thread_info present -> coverage
    must be "partial" (a real gap in ONE of the two required sources),
    never "complete" -- confirmed broken in an earlier draft (see this
    file's own module docstring)."""
    class MF(FakeMF):
        memory_info = None
        modules = FakeStream([Module(0x20000, 0x1000, "a.dll")], "modules")
        thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
        threads = FakeStream([Thread(1, Ctx(0x1000))], "threads")

    rec = collect_injection_record(MF())
    assert rec.coverage.status.value == "partial"
    codes = {(lim.code.value, lim.source) for lim in rec.coverage.limitations}
    assert ("SOURCE_ABSENT", "memory_info") in codes
    assert rec.coverage.sources["memory_info"].state.value == "absent"


def test_only_thread_info_missing_is_partial_not_complete():
    """Regression: thread_info absent, memory_info present -> "partial",
    never "complete" (same bug as the memory_info case above, mirrored)."""
    class MF(FakeMF):
        memory_info = FakeStream(
            [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
        modules = FakeStream([Module(0x20000, 0x1000, "a.dll")], "modules")
        thread_info = None
        threads = FakeStream([Thread(1, Ctx(0x1000))], "threads")

    rec = collect_injection_record(MF())
    assert rec.coverage.status.value == "partial"
    codes = {(lim.code.value, lim.source) for lim in rec.coverage.limitations}
    assert ("SOURCE_ABSENT", "thread_info") in codes
    assert rec.coverage.sources["thread_info"].state.value == "absent"


def test_thread_list_present_but_context_partial():
    """Thread list (ThreadListStream) present, but only some threads have
    a parsed CONTEXT -- a genuine partial gap in the thread_context
    source, distinct from it being fully absent."""
    class MF(FakeMF):
        memory_info = FakeStream(
            [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
        modules = FakeStream([Module(0x20000, 0x1000, "a.dll")], "modules")
        thread_info = FakeStream([ThreadInfo(1, 0x1000), ThreadInfo(2, 0x1000)], "infos")
        threads = FakeStream([Thread(1, Ctx(0x1000)), Thread(2, None)], "threads")

    rec = collect_injection_record(MF())
    assert rec.coverage.status.value == "partial"
    codes = {(lim.code.value, lim.source, lim.affected_count) for lim in rec.coverage.limitations}
    assert ("THREAD_CONTEXT_PARTIAL", "thread_context", 1) in codes
    assert rec.coverage.sources["thread_context"].state.value == "present"
    assert rec.coverage.sources["thread_list"].record_count == 2


def test_coverage_limitation_order_matches_v1_1_coverage_reasons_order(monkeypatch):
    """Regression: an earlier draft listed thread_context's SourceRequirement
    BEFORE the PE-scan checks in completeness_checks, so a dump hitting
    both a PE short-read AND a fully-absent thread_context produced
    limitations in the OPPOSITE order from the v1.1 `coverage_reasons` list
    computed from the exact same facts (memory_info, thread_info, modules,
    PE read-failed, PE short-read, THEN thread_context -- see
    aggregate.py's own coverage_reasons construction)."""
    alloc_base = 0x7ff700000000
    pe_bytes = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000, "rawptr": 0x400,
          "rawsize": 0x1000, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300)
    regions = [
        Region(alloc_base, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(alloc_base + 0x2000, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mods = [Module(0x7ffe00000000, 0x10000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")   # present-but-empty -> absent
        threads        = None                       # no ThreadListStream -> thread_context absent
    monkeypatch.setattr(injection, "read_region", mem_reader({alloc_base + 0x2000: pe_bytes}))

    rec = collect_injection_record(MF())
    assert rec.coverage.status.value == "partial"
    order = [lim.code.value for lim in rec.coverage.limitations]
    assert order == ["SOURCE_ABSENT", "PE_HEADER_SHORT_READ", "THREAD_CONTEXT_UNAVAILABLE"]

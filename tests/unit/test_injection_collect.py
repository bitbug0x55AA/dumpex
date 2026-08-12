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
    short_read = next(lim for lim in rec.coverage.limitations
                       if lim.code.value == "PE_HEADER_SHORT_READ")
    # issue #28: the affected region's own identity is retained, not just
    # counted -- the exact region the short read happened in (not the
    # unrelated RWX allocation-base region), with no size_limit (this was
    # never skipped for being oversized).
    assert len(short_read.targets) == 1
    target = short_read.targets[0]
    assert target.base_address == alloc_base + 0x2000
    assert target.size_limit is None
    assert target.protection == "PAGE_READWRITE"
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


# ── issue #28: PE_HEADER_READ_FAILED/_SCAN_TRUNCATED also retain target ────
# identity, the same way PE_HEADER_SHORT_READ already does above.

def test_pe_read_failed_retains_the_exact_region_as_a_target(monkeypatch):
    region_base = 0x8000000
    dummy_regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT",
                             "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    def flaky_reader(mf, addr, size):
        if addr == region_base and size <= 2:
            return b'MZ'
        raise OSError("simulated deep-read failure")

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    monkeypatch.setattr(injection, "read_region", flaky_reader)

    rec = collect_injection_record(MF())
    read_failed = next(lim for lim in rec.coverage.limitations
                        if lim.code.value == "PE_HEADER_READ_FAILED")
    assert read_failed.affected_count == 1
    assert len(read_failed.targets) == 1
    target = read_failed.targets[0]
    assert target.base_address == region_base
    assert target.size == 0x1000
    assert target.size_limit is None
    assert target.type == "MEM_PRIVATE"


def test_pe_scan_not_started_retains_the_exact_region_as_a_target(monkeypatch):
    from dumpex.hunt.injection import memory_scan
    region1_base, region_size = 0x73000000, 0x2000
    region2_base = 0x74000000
    monkeypatch.setattr(memory_scan, "PE_SCAN_WINDOW", region_size)
    # +1: see tests/hunt/test_injection.py's own
    # test_later_region_never_started_when_whole_hunt_byte_budget_is_already_spent
    # for why region 1 needs exactly one byte more than its own size to
    # complete cleanly (the sliding-window search's trailing overlap read).
    monkeypatch.setattr(memory_scan, "PE_SCAN_TOTAL_BYTES_MAX", region_size + 1)
    regions = [Region(region1_base, region1_base, region_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE"),
               Region(region2_base, region2_base, region_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    monkeypatch.setattr(injection, "read_region", mem_reader(
        {region1_base: b"\x00" * region_size, region2_base: b"\x00" * region_size}))

    rec = collect_injection_record(MF())
    codes = {lim.code.value for lim in rec.coverage.limitations}
    assert "PE_HEADER_SCAN_NOT_STARTED" in codes
    assert "PE_HEADER_SCAN_TRUNCATED" not in codes   # region 1 completed cleanly
    not_started = next(lim for lim in rec.coverage.limitations
                        if lim.code.value == "PE_HEADER_SCAN_NOT_STARTED")
    assert not_started.affected_count == 1
    assert len(not_started.targets) == 1
    target = not_started.targets[0]
    assert target.base_address == region2_base   # the region never even started, not region 1
    assert target.size_limit is None


def test_pe_scan_truncated_retains_the_exact_region_as_a_target(monkeypatch):
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_WINDOW", 0x1000)
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_READS_PER_REGION", 3)
    region_base = 0x70000000
    region_size = 0x8000   # 8 windows, only 3 of them affordable

    dummy_regions = [Region(region_base, region_base, region_size, "MEM_COMMIT",
                             "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    monkeypatch.setattr(injection, "read_region", lambda mf, addr, size: b"\x00" * size)

    rec = collect_injection_record(MF())
    truncated = next(lim for lim in rec.coverage.limitations
                      if lim.code.value == "PE_HEADER_SCAN_TRUNCATED")
    assert truncated.affected_count == 1
    assert len(truncated.targets) == 1
    target = truncated.targets[0]
    # issue #28 P2 follow-up: the target names the UNEXAMINED REMAINDER,
    # not the whole region -- 3 affordable reads already covered a real
    # prefix of it before the per-region budget ran out, so the target's
    # own base sits strictly past the region's own base, and its size is
    # correspondingly smaller than the region's full declared size.
    assert region_base < target.base_address < region_base + region_size
    assert target.base_address + target.size == region_base + region_size
    assert target.size < region_size
    assert target.size_limit is None


def test_pe_scan_truncated_carries_validation_budget_attribution(monkeypatch):
    # issue #28 P4 follow-up: PE_HEADER_SCAN_TRUNCATED now names WHICH of
    # the hidden-PE scan's four independent budgets stopped it, and that
    # budget's own configured limit/consumed, via scope/detail.
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_VALIDATIONS_TOTAL", 0)
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_VALIDATIONS_PER_REGION", 0)
    region_base = 0xB2000000
    region_size = 0x2000
    content = bytearray(b"\x00" * region_size)
    content[0x10:0x12] = b"MZ"

    regions = [Region(region_base, region_base, region_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    monkeypatch.setattr(injection, "read_region", mem_reader({region_base: bytes(content)}))

    rec = collect_injection_record(MF())
    truncated = next(lim for lim in rec.coverage.limitations
                      if lim.code.value == "PE_HEADER_SCAN_TRUNCATED")
    assert truncated.scope == "validations_total"
    assert truncated.budget_limit == 0
    assert truncated.budget_consumed == 0

    # issue #28 P6 follow-up: a real zero-budget scan run must not crash
    # when --hunt all folds it into the investigation queue.
    from dumpex.hunt._investigation import build_investigation_queue
    actions = build_investigation_queue([rec], [])
    rel = actions[0].skipped_by[0]
    assert (rel.budget_kind, rel.budget_limit, rel.budget_consumed) == ("validations_total", 0, 0)


def test_two_regions_truncated_by_two_different_budgets_are_attributed_separately(monkeypatch):
    # issue #28 P5 follow-up: region 1's own search exhausts
    # validations_per_region; a DIFFERENT region 2, scanned later in the
    # SAME hunt run, exhausts validations_total instead. These are two
    # distinct facts about two distinct regions and must surface as two
    # separate PE_HEADER_SCAN_TRUNCATED limitations, each correctly
    # scoped to its own budget -- not one limitation whose single
    # first-occurrence attribution falsely claims region 2 was ALSO
    # stopped by validations_per_region.
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_VALIDATIONS_PER_REGION", 2)
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_VALIDATIONS_TOTAL", 3)
    monkeypatch.setattr(memory_scan, "PE_SCAN_WINDOW", 0x1000)

    region1_base, region2_base = 0xC0000000, 0xC1000000
    region_size = 0x1000

    def _content_with_three_mz():
        content = bytearray(b"\x00" * region_size)
        for off in (0x10, 0x20, 0x30):
            content[off:off + 2] = b"MZ"
        return bytes(content)

    regions = [Region(region1_base, region1_base, region_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE"),
               Region(region2_base, region2_base, region_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    monkeypatch.setattr(injection, "read_region", mem_reader(
        {region1_base: _content_with_three_mz(), region2_base: _content_with_three_mz()}))

    rec = collect_injection_record(MF())
    truncated_lims = [l for l in rec.coverage.limitations
                       if l.code.value == "PE_HEADER_SCAN_TRUNCATED"]
    scopes = {l.scope for l in truncated_lims}
    assert scopes == {"validations_per_region", "validations_total"}

    per_region_lim = next(l for l in truncated_lims if l.scope == "validations_per_region")
    total_lim = next(l for l in truncated_lims if l.scope == "validations_total")
    assert (per_region_lim.budget_limit, per_region_lim.budget_consumed) == (2, 2)
    assert (total_lim.budget_limit, total_lim.budget_consumed) == (3, 3)
    assert {t.base_address for t in per_region_lim.targets} == {region1_base + 0x30}
    assert {t.base_address for t in total_lim.targets} == {region2_base + 0x10}


def test_pe_scan_truncated_target_starts_at_unvalidated_candidate_not_window_end(monkeypatch):
    # issue #28 P3 follow-up: a validation-budget exhaustion partway
    # through a window must not claim the whole window -- up to
    # PE_SCAN_WINDOW bytes -- was examined. A region larger than one
    # window, with its only 'MZ' candidate a few bytes in and a
    # validation budget that dies on that very first candidate, must
    # report the truncated remainder starting at the CANDIDATE's own
    # offset, not at the window boundary far past it.
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_WINDOW", 0x100000)          # 1 MiB
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_VALIDATIONS_TOTAL", 0)
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_VALIDATIONS_PER_REGION", 0)
    region_base = 0xB1000000
    region_size = 0x200000    # 2 MiB, > one window
    mz_offset = 0x14
    content = bytearray(b"\x00" * region_size)
    content[mz_offset:mz_offset + 2] = b"MZ"

    regions = [Region(region_base, region_base, region_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    monkeypatch.setattr(injection, "read_region", mem_reader({region_base: bytes(content)}))

    rec = collect_injection_record(MF())
    truncated = next(lim for lim in rec.coverage.limitations
                      if lim.code.value == "PE_HEADER_SCAN_TRUNCATED")
    assert len(truncated.targets) == 1
    target = truncated.targets[0]
    assert target.base_address == region_base + mz_offset, (
        f"budget died validating the candidate at region_base+{mz_offset:#x}; "
        f"the reported remainder must start there, not at the window boundary "
        f"region_base+{0x100000:#x}")
    assert target.base_address + target.size == region_base + region_size

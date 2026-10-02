"""Unit tests for dumpex.commands.comparison's pure domain functions
(Phase C, PR2). No CLI wiring exists for this module yet -- these test
collect_module_diff/collect_thread_diff/collect_memory_diff/
collect_comparison() directly, the same way test_modules_cmd.py etc.
test the six migrated recon commands' collect_*() functions.
"""
import io
import struct

import pytest
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

from tests.fixtures.fakes import (
    Module, ThreadInfo, Region, FakeStream, FakeMF, Thread, Ctx,
    build_thread_info_stream, parsed_thread_info_stream, ThreadInfoStreamDirectory,
    THREAD_INFO_ENTRY_SIZE, FakeHeader, MiscInfo, Peb, SysInfo, Segment, build_pe_header,
)
from tests.unit.test_process_cmd import _FakeBufferedReader, _FakeReader, _mf as _process_mf
from dumpex.core.memory import (
    parse_thread_info_stream, truncated_thread_info_count, dump_flags_tags,
)

from dumpex.commands.comparison import (
    collect_module_diff, collect_thread_diff, collect_memory_diff, collect_comparison,
    collect_comparison_premise,
)
from dumpex.output.records import (
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
    COMPARISON_FACTS,
)
from dumpex.output.coverage import combine_coverage_reports, COVERAGE_COMPLETE, COVERAGE_PARTIAL


class _ExplodingThreadInfoMF(FakeMF):
    """A minidump stand-in whose `.thread_info` access raises -- reproduces
    a genuinely malformed sub-structure (as opposed to a stream that's
    merely absent or empty), which _observe_or_failed() must catch and
    report as SourceState.FAILED rather than crash the whole comparison
    or silently misreport the OTHER side's real items as 100%
    added/removed."""
    @property
    def thread_info(self):
        raise RuntimeError("thread_info stream could not be read")

    @thread_info.setter
    def thread_info(self, value):
        pass


class _ExplodingMemoryInfoMF(FakeMF):
    """Same as _ExplodingThreadInfoMF, for `.memory_info`."""
    @property
    def memory_info(self):
        raise RuntimeError("memory_info stream could not be read")

    @memory_info.setter
    def memory_info(self, value):
        pass


# ── collect_module_diff ───────────────────────────────────────────────────

def test_collect_module_diff_added_removed_rebased():
    mf_baseline = FakeMF()
    mf_baseline.modules = FakeStream([
        Module(0x1000, 0x1000, r"C:\a.dll"), Module(0x2000, 0x1000, r"C:\b.dll"),
    ], "modules")
    mf_target = FakeMF()
    mf_target.modules = FakeStream([
        Module(0x9000, 0x1000, r"C:\a.dll"), Module(0x3000, 0x1000, r"C:\c.dll"),
    ], "modules")

    records, coverage = collect_module_diff(mf_baseline, mf_target)
    assert coverage.status == "complete"
    by_type = {r.change_type: r for r in records}
    assert set(by_type) == {"added", "removed", "rebased"}
    assert by_type["added"].name == "c.dll"
    assert by_type["removed"].name == "b.dll"
    rebased = by_type["rebased"]
    assert rebased.name == "a.dll"
    assert rebased.base_address_before != rebased.base_address_after


def test_collect_module_diff_baseline_absent_is_not_evaluated():
    mf_baseline = FakeMF()
    mf_target = FakeMF()
    mf_target.modules = FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")
    records, coverage = collect_module_diff(mf_baseline, mf_target)
    assert records == []
    assert coverage.status == "not_evaluated"
    assert coverage.reasons == ["baseline ModuleListStream not present in this dump"]


def test_collect_module_diff_both_absent_produces_two_limitations():
    records, coverage = collect_module_diff(FakeMF(), FakeMF())
    assert records == []
    assert coverage.status == "not_evaluated"
    assert len(coverage.limitations) == 2
    assert {l.source for l in coverage.limitations} == {"baseline.modules", "target.modules"}


def test_collect_module_diff_same_basename_different_directory_reports_rebased():
    # Regression for module_name_only()'s cross-platform bug: the same
    # module relocated to a different directory between two dumps must
    # still match by basename alone (ntpath.basename, not os.path.
    # basename) and report as "rebased," not a spurious removed+added
    # pair -- see dumpex/core/memory.py's module_name_only().
    mf_baseline = FakeMF()
    mf_baseline.modules = FakeStream(
        [Module(0x1000, 0x1000, r"C:\Program Files\App\a.dll")], "modules")
    mf_target = FakeMF()
    mf_target.modules = FakeStream(
        [Module(0x9000, 0x1000, r"C:\Windows\System32\a.dll")], "modules")

    records, coverage = collect_module_diff(mf_baseline, mf_target)
    assert len(records) == 1
    assert records[0].change_type == "rebased"
    assert records[0].name == "a.dll"


def test_collect_module_diff_multiple_anonymous_modules_do_not_collide():
    # Regression: module_name_only(None) == "" for every anonymous
    # module -- using that alone as a dict key would silently collide,
    # keeping only the last one and dropping the rest from the diff.
    mf_baseline = FakeMF()
    mf_baseline.modules = FakeStream([], "modules")
    mf_target = FakeMF()
    mf_target.modules = FakeStream([
        Module(0x1000, 0x1000, None), Module(0x2000, 0x1000, ""),
    ], "modules")

    records, coverage = collect_module_diff(mf_baseline, mf_target)
    assert coverage.status == "complete"
    assert len(records) == 2   # neither anonymous module was dropped
    assert {r.base_address_after for r in records} == {
        "0x0000000000001000", "0x0000000000002000"}
    # Wire name is always a non-empty string (v2.1 schema requires it),
    # never the raw "" module_name_only() would have produced.
    assert all(r.name == "(unnamed)" for r in records)
    assert all(r.full_path_after is None for r in records)


def test_collect_module_diff_baseline_present_empty_treats_all_target_as_added():
    # The confirmed "missing != empty" rule: a present-but-empty baseline
    # is evaluable (diffed against an empty set), unlike an absent one.
    mf_baseline = FakeMF()
    mf_baseline.modules = FakeStream([], "modules")
    mf_target = FakeMF()
    mf_target.modules = FakeStream(
        [Module(i * 0x1000, 0x1000, f"m{i}.dll") for i in range(5)], "modules")

    records, coverage = collect_module_diff(mf_baseline, mf_target)
    assert coverage.status == "complete"
    assert len(records) == 5
    assert all(r.change_type == "added" for r in records)


# ── collect_thread_diff ───────────────────────────────────────────────────

def test_collect_thread_diff_added_with_unknown_start_address_stays_null_not_fabricated():
    # Regression: StartAddress=None must never be folded to 0 -- doing so
    # would feed a fabricated address into addr_to_module() and could
    # produce MODULE_CONTEXT_UNREGISTERED, a real "confirmed not backed
    # by any module" DFIR signal, for a thread whose address was simply
    # never known at all.
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([], "infos")
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, None)], "infos")
    mf_target.modules = FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")

    records, coverage = collect_thread_diff(mf_baseline, mf_target)
    assert coverage.status == "complete"
    added = records[0]
    assert added.start_address_after is None
    assert added.backing_module_after is None
    assert added.backing_module_context is None


def test_collect_thread_diff_removed_with_unknown_start_address_stays_null():
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([ThreadInfo(1, None)], "infos")
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([], "infos")

    records, coverage = collect_thread_diff(mf_baseline, mf_target)
    assert coverage.status == "complete"
    assert records[0].start_address_before is None


def test_collect_thread_diff_target_modules_absent_is_partial_not_complete():
    # Regression: an added thread with a KNOWN start address that can't
    # be resolved because target.modules is absent must not report
    # coverage="complete" -- that would silently contradict
    # backing_module_context="unavailable" on the record itself.
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([], "infos")
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    # mf_target.modules deliberately left unset (absent)

    records, coverage = collect_thread_diff(mf_baseline, mf_target)
    assert coverage.status == "partial"
    assert coverage.reasons == [
        "target ModuleListStream not present; backing_module_after/"
        "backing_module_context unavailable"]
    assert coverage.limitations[0].scope == "thread"
    assert coverage.sources["target.modules"].state == "absent"
    assert records[0].backing_module_context == MODULE_CONTEXT_UNAVAILABLE


def test_collect_thread_diff_target_modules_not_consulted_when_no_added_thread_has_address():
    # target.modules must only be registered as a coverage source when it
    # would actually be consulted -- an added thread with an UNKNOWN
    # start address never looks at it, so its absence must not affect
    # coverage at all.
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([], "infos")
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, None)], "infos")
    # mf_target.modules deliberately left unset (absent)

    records, coverage = collect_thread_diff(mf_baseline, mf_target)
    assert coverage.status == "complete"
    assert "target.modules" not in coverage.sources


class _ExplodingModulesMF(FakeMF):
    """A minidump stand-in whose `.modules` access raises -- reproduces
    the round-2 finding that mf_target.modules was still read
    UNCONDITIONALLY (bool(mf_target.modules)/get_modules(mf_target)
    sitting outside the `if needs_target_modules:` guard), contradicting
    collect_thread_diff's own docstring claim that it's "only read... when
    at least one ADDED thread has a known StartAddress." """
    @property
    def modules(self):
        raise RuntimeError("modules stream should not be touched here")

    @modules.setter
    def modules(self, value):
        pass


def test_collect_thread_diff_does_not_touch_target_modules_when_not_needed():
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([], "infos")
    mf_target = _ExplodingModulesMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, None)], "infos")   # unknown address

    records, coverage = collect_thread_diff(mf_baseline, mf_target)   # must not raise
    assert coverage.status == "complete"
    assert records[0].backing_module_context is None


def test_collect_thread_diff_added_resolves_backing_module_against_target():
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, 0x1000), ThreadInfo(2, 0x5000)], "infos")
    mf_target.modules = FakeStream([Module(0x5000, 0x1000, "legit.dll")], "modules")

    records, coverage = collect_thread_diff(mf_baseline, mf_target)
    assert coverage.status == "complete"
    assert len(records) == 1
    added = records[0]
    assert added.change_type == "added"
    assert added.tid == 2
    assert added.backing_module_after == "legit.dll"
    assert added.backing_module_context == MODULE_CONTEXT_RESOLVED


@pytest.mark.parametrize("anonymous_name", [None, ""])
def test_collect_thread_diff_added_resolved_against_an_anonymous_module(anonymous_name):
    # Regression: an added thread's start address can fall inside a REAL
    # module that simply has no name recorded (mod.name is None or "") --
    # ntpath.basename(None) raises TypeError outright, and basename-ing
    # "" would produce another "" that the wire's non-empty-string
    # contract for backing_module_after rejects. Must fall back to the
    # same "(unnamed)" placeholder ModuleRecord/ModuleDiffRecord already
    # use for a nameless module, not crash or emit "".
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, 0x1000), ThreadInfo(2, 0x5000)], "infos")
    mf_target.modules = FakeStream([Module(0x5000, 0x1000, anonymous_name)], "modules")

    records, coverage = collect_thread_diff(mf_baseline, mf_target)
    assert coverage.status == "complete"
    added = records[0]
    assert added.backing_module_context == MODULE_CONTEXT_RESOLVED
    assert added.backing_module_after == "(unnamed)"


def test_collect_thread_diff_added_unregistered_when_modules_present_but_unmatched():
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([], "infos")   # present, genuinely empty -- evaluable
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, 0x9999)], "infos")
    mf_target.modules = FakeStream([Module(0x1000, 0x1000, "legit.dll")], "modules")

    records, coverage = collect_thread_diff(mf_baseline, mf_target)
    assert records[0].backing_module_context == MODULE_CONTEXT_UNREGISTERED
    assert records[0].backing_module_after is None


def test_collect_thread_diff_added_unavailable_when_target_modules_missing():
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([], "infos")   # present, genuinely empty -- evaluable
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    # mf_target.modules left entirely unset -- ModuleListStream itself
    # missing, distinct from "present but this address isn't in it."

    records, coverage = collect_thread_diff(mf_baseline, mf_target)
    assert records[0].backing_module_context == MODULE_CONTEXT_UNAVAILABLE
    assert records[0].backing_module_after is None


def test_collect_thread_diff_removed_has_no_backing_module_fields():
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([], "infos")

    records, coverage = collect_thread_diff(mf_baseline, mf_target)
    assert coverage.status == "complete"
    assert len(records) == 1
    removed = records[0]
    assert removed.change_type == "removed"
    assert removed.tid == 1
    assert removed.backing_module_after is None
    assert removed.backing_module_context is None


def test_collect_thread_diff_either_side_absent_is_not_evaluated():
    mf_baseline = FakeMF()
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    records, coverage = collect_thread_diff(mf_baseline, mf_target)
    assert records == []
    assert coverage.status == "not_evaluated"


# ── collect_memory_diff ───────────────────────────────────────────────────

def test_collect_memory_diff_added_removed_protection_changed():
    mf_baseline = FakeMF()
    mf_baseline.memory_info = FakeStream([
        Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
        Region(0x2000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE"),
    ], "infos")
    mf_target = FakeMF()
    mf_target.memory_info = FakeStream([
        Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(0x3000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ], "infos")

    records, coverage = collect_memory_diff(mf_baseline, mf_target)
    assert coverage.status == "complete"
    by_type = {r.change_type: r for r in records}
    assert set(by_type) == {"added", "removed", "protection_changed"}
    changed = by_type["protection_changed"]
    assert changed.protect_before == "PAGE_READWRITE"
    assert changed.protect_after == "PAGE_EXECUTE_READWRITE"
    assert changed.suspicious_before is False
    assert changed.suspicious_after is True
    assert by_type["added"].size_before is None
    assert by_type["removed"].size_after is None


def test_collect_memory_diff_either_side_absent_is_not_evaluated():
    mf_target = FakeMF()
    mf_target.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
    records, coverage = collect_memory_diff(FakeMF(), mf_target)
    assert records == []
    assert coverage.status == "not_evaluated"


# ── collect_comparison ────────────────────────────────────────────────────

def test_collect_comparison_rejects_unknown_mode():
    with pytest.raises(ValueError, match="mode"):
        collect_comparison(FakeMF(), FakeMF(), mode="bogus")


def test_collect_comparison_mode_modules_only_touches_modules():
    mf_baseline = FakeMF()
    mf_baseline.modules = FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")
    mf_target = FakeMF()
    mf_target.modules = FakeStream([Module(0x2000, 0x1000, "b.dll")], "modules")
    result = collect_comparison(mf_baseline, mf_target, mode="modules")
    assert result.kind == "comparison"
    assert {r.entity_type for r in result.records} == {"module"}
    assert list(result.summary) == ["count", "premise"]
    assert result.summary["count"] == len(result.records)


def test_collect_comparison_mode_threads_only_touches_threads():
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([ThreadInfo(2, 0x2000)], "infos")
    result = collect_comparison(mf_baseline, mf_target, mode="threads")
    assert {r.entity_type for r in result.records} == {"thread"}


def test_collect_comparison_mode_memory_only_touches_memory():
    mf_baseline = FakeMF()
    mf_baseline.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
    mf_target = FakeMF()
    mf_target.memory_info = FakeStream(
        [Region(0x2000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
    result = collect_comparison(mf_baseline, mf_target, mode="memory")
    assert {r.entity_type for r in result.records} == {"memory_region"}


def test_collect_comparison_all_mode_combines_every_entity():
    mf_baseline = FakeMF()
    mf_baseline.modules = FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")
    mf_baseline.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    mf_baseline.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
    mf_target = FakeMF()
    mf_target.modules = FakeStream([Module(0x2000, 0x1000, "b.dll")], "modules")
    mf_target.thread_info = FakeStream([ThreadInfo(2, 0x2000)], "infos")
    mf_target.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")

    result = collect_comparison(mf_baseline, mf_target, mode="all")
    assert result.coverage.status == "complete"
    assert {r.entity_type for r in result.records} == {"module", "thread", "memory_region"}
    # target.modules is legitimately read by BOTH collect_module_diff (its
    # own primary source) and collect_thread_diff (to resolve the added
    # thread's backing module) -- combine_coverage_reports must merge
    # this shared source cleanly rather than raising a spurious collision.
    assert result.coverage.sources["target.modules"].state == "present"


def test_collect_comparison_all_mode_one_not_evaluated_entity_is_partial_overall():
    # --diff-scope all cross-entity aggregation: modules entirely absent on
    # both sides (not_evaluated for that entity alone) while threads/
    # memory are both fully evaluable must yield PARTIAL overall, not
    # not_evaluated -- one weak entity must not drag the whole comparison
    # down to "nothing was evaluated."
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    mf_baseline.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    mf_target.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
    # modules absent on both sides -- collect_module_diff's own coverage
    # is not_evaluated in isolation.

    result = collect_comparison(mf_baseline, mf_target, mode="all")
    assert result.coverage.status == "partial"
    assert result.records == []   # module diff contributed nothing; threads/memory had no changes


def test_collect_comparison_all_mode_unanimous_not_evaluated_stays_not_evaluated():
    # Every entity absent on both sides -- unanimous not_evaluated.
    result = collect_comparison(FakeMF(), FakeMF(), mode="all")
    assert result.coverage.status == "not_evaluated"


def test_collect_comparison_all_mode_target_modules_limitations_are_distinguishable():
    # Regression: when target.modules is needed by BOTH collect_module_diff
    # (its own primary source) and collect_thread_diff (to classify an
    # added thread), the two resulting limitations must not be
    # byte-identical duplicates of the same fact -- thread_diff's own
    # says WHICH thread-side fields are unavailable, not just that the
    # stream is absent.
    mf_baseline = FakeMF()
    mf_baseline.modules = FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")
    mf_baseline.thread_info = FakeStream([], "infos")
    mf_baseline.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
    mf_target = FakeMF()
    # mf_target.modules deliberately left unset (absent) -- needed by both
    # collect_module_diff (its own gate) and collect_thread_diff (to
    # classify the added thread below).
    mf_target.thread_info = FakeStream([ThreadInfo(1, 0x2000)], "infos")
    mf_target.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")

    result = collect_comparison(mf_baseline, mf_target, mode="all")
    limitations = [l for l in result.coverage.limitations if l.source == "target.modules"]
    assert len(limitations) == 2
    # Distinct structured shape -- not two copies of the same fact.
    assert {l.scope for l in limitations} == {"dump", "thread"}
    thread_side = next(l for l in limitations if l.scope == "thread")
    assert set(thread_side.unavailable_fields) == {"backing_module_after", "backing_module_context"}
    # Distinct rendered text too.
    assert len(set(result.coverage.reasons)) == len(result.coverage.reasons)
    # module_diff contributed nothing (not_evaluated), but thread_diff's
    # own coverage is only "partial" (target.modules is a completeness
    # check there, not a gate) -- the added thread itself is still
    # reported, just with an unresolved backing module.
    assert len(result.records) == 1
    assert result.records[0].backing_module_context == "unavailable"


# ── SourceState.FAILED (Phase D) ──────────────────────────────────────────
# comparison.py's _observe_or_failed() isolates one side's stream read: a
# genuine exception (not just an absent/empty stream) becomes
# SourceState.FAILED for that side specifically, rather than crashing the
# whole comparison or silently misreporting the OTHER side's real items.

def test_collect_module_diff_target_read_failure_is_partial_not_crash():
    mf_baseline = FakeMF()
    mf_baseline.modules = FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")
    mf_target = _ExplodingModulesMF()

    records, coverage = collect_module_diff(mf_baseline, mf_target)
    assert records == []   # must NOT misreport baseline's real module as "removed"
    assert coverage.status == "partial"
    assert coverage.sources["target.modules"].state == "failed"
    assert coverage.sources["target.modules"].detail == "modules stream should not be touched here"
    assert [l.code for l in coverage.limitations] == ["SOURCE_FAILED"]


def test_collect_thread_diff_baseline_read_failure_is_partial_not_crash():
    mf_baseline = _ExplodingThreadInfoMF()
    mf_target = FakeMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")

    records, coverage = collect_thread_diff(mf_baseline, mf_target)
    assert records == []   # must NOT misreport target's real thread as "added"
    assert coverage.status == "partial"
    assert coverage.sources["baseline.thread_info"].state == "failed"
    assert [l.code for l in coverage.limitations] == ["SOURCE_FAILED"]


def test_collect_memory_diff_target_read_failure_is_partial_not_crash():
    mf_baseline = FakeMF()
    mf_baseline.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
    mf_target = _ExplodingMemoryInfoMF()

    records, coverage = collect_memory_diff(mf_baseline, mf_target)
    assert records == []   # must NOT misreport baseline's real region as "removed"
    assert coverage.status == "partial"
    assert coverage.sources["target.memory_info"].state == "failed"
    assert [l.code for l in coverage.limitations] == ["SOURCE_FAILED"]


def test_collect_thread_diff_target_modules_failure_degrades_not_aborts():
    # Unlike a FAILED baseline/target.thread_info (which aborts the whole
    # thread diff, see above), a FAILED target.modules is a strictly
    # optional enrichment -- thread add/remove detection doesn't need it,
    # only the backing-module lookup does, so it degrades to "unavailable"
    # the same way an absent target.modules already does, rather than
    # discarding the otherwise-valid added-thread record.
    mf_baseline = FakeMF()
    mf_baseline.thread_info = FakeStream([], "infos")
    mf_target = _ExplodingModulesMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")

    records, coverage = collect_thread_diff(mf_baseline, mf_target)
    assert len(records) == 1
    assert records[0].backing_module_context == MODULE_CONTEXT_UNAVAILABLE
    assert records[0].backing_module_after is None
    assert coverage.status == "partial"
    assert coverage.sources["target.modules"].state == "failed"
    assert [l.code for l in coverage.limitations] == ["SOURCE_FAILED"]
    # The FAILED limitation must carry the SAME SourceRequirement
    # customization (scope="thread" + unavailable_fields) an ABSENT
    # target.modules already gets here -- otherwise a thread-only console
    # never shows the read failure at all (scope="dump" doesn't match
    # render_thread_diff's own scope=="thread" filter), and mode="all"
    # would produce a limitation byte-identical to module diff's own
    # unrelated target.modules failure, which combine_coverage_reports'
    # dedup would then incorrectly collapse into one.
    failed_limitation = coverage.limitations[0]
    assert failed_limitation.scope == "thread"
    assert failed_limitation.unavailable_fields == (
        "backing_module_after", "backing_module_context")


def test_collect_comparison_mode_all_keeps_distinct_dump_and_thread_failed_limitations():
    # mode="all" reads target.modules TWICE for the same underlying
    # failure -- once as module diff's own primary source (scope="dump"),
    # once as thread diff's optional enrichment source (scope="thread",
    # with unavailable_fields). These must NOT collapse into one via
    # combine_coverage_reports' dedup (which only removes byte-identical
    # limitations) -- each section needs its own reason line.
    mf_baseline = FakeMF()
    mf_baseline.modules = FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")
    mf_baseline.thread_info = FakeStream([], "infos")
    mf_target = _ExplodingModulesMF()
    mf_target.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")

    result = collect_comparison(mf_baseline, mf_target, mode="all")
    failed = [l for l in result.coverage.limitations if l.code == "SOURCE_FAILED"]
    assert len(failed) == 2
    scopes = {l.scope for l in failed}
    assert scopes == {"dump", "thread"}
    thread_lim = next(l for l in failed if l.scope == "thread")
    assert thread_lim.unavailable_fields == ("backing_module_after", "backing_module_context")
    dump_lim = next(l for l in failed if l.scope == "dump")
    assert dump_lim.unavailable_fields == ()


def test_combine_coverage_reports_rolls_a_failed_entity_into_overall_partial():
    mf_a1 = FakeMF()
    mf_a1.modules = FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules")
    mf_b1 = _ExplodingModulesMF()
    _, module_coverage = collect_module_diff(mf_a1, mf_b1)
    assert module_coverage.status == COVERAGE_PARTIAL

    mf_a2, mf_b2 = FakeMF(), FakeMF()
    mf_a2.thread_info = FakeStream([], "infos")
    mf_b2.thread_info = FakeStream([], "infos")
    _, thread_coverage = collect_thread_diff(mf_a2, mf_b2)
    assert thread_coverage.status == COVERAGE_COMPLETE

    combined = combine_coverage_reports([module_coverage, thread_coverage])
    assert combined.status == COVERAGE_PARTIAL


# -- a truncated ThreadInfoListStream cannot settle which TIDs exist ----

def _mf_with_thread_info(parsed, base_tids=()):
    mf = FakeMF()
    mf.thread_info = parsed
    if base_tids:
        mf.threads = FakeStream([Thread(tid, Ctx(0x1000)) for tid in base_tids], "threads")
    return mf


def test_a_cut_short_tail_record_is_not_reported_as_a_removed_thread():
    # The stream declares two records and the second survives only as far
    # as its ThreadId and DumpFlags. That thread exists -- the base
    # ThreadListStream still lists it -- so dropping the partial record
    # would report it as removed from a dump it is plainly still in.
    full = parsed_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x0, "start_address": 0x400100},
         {"tid": 2, "dump_flags": 0x10, "start_address": 0x500100}])
    body, data_size = build_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x0, "start_address": 0x400100},
         {"tid": 2, "dump_flags": 0x10, "start_address": 0x500100}],
        body_bytes=12 + THREAD_INFO_ENTRY_SIZE + 8)
    cut = parse_thread_info_stream(
        ThreadInfoStreamDirectory(rva=0, data_size=data_size), io.BytesIO(body))

    records, coverage = collect_thread_diff(
        _mf_with_thread_info(full, base_tids=(1, 2)),
        _mf_with_thread_info(cut, base_tids=(1, 2)))
    assert [r.change_type for r in records] == []
    assert coverage.status == "complete"

    # The fields the tail record DID carry survive with it.
    tail = cut.infos[1]
    assert dump_flags_tags(tail) == ["NO_CTX"]


def test_a_record_that_never_arrived_stops_the_diff_claiming_completeness():
    # Not even a whole ThreadId remains, so nothing about that thread was
    # captured at all. The diff still reports what it has, but it can no
    # longer present added/removed as a settled answer.
    full = parsed_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x0, "start_address": 0x400100},
         {"tid": 2, "dump_flags": 0x0, "start_address": 0x500100}])
    body, data_size = build_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x0, "start_address": 0x400100},
         {"tid": 2, "dump_flags": 0x0, "start_address": 0x500100}],
        body_bytes=12 + THREAD_INFO_ENTRY_SIZE + 3)
    cut = parse_thread_info_stream(
        ThreadInfoStreamDirectory(rva=0, data_size=data_size), io.BytesIO(body))
    assert truncated_thread_info_count(cut) == 1

    records, coverage = collect_thread_diff(
        _mf_with_thread_info(full, base_tids=(1, 2)),
        _mf_with_thread_info(cut, base_tids=(1, 2)))
    assert coverage.status == "partial"
    codes = [limitation.code.value for limitation in coverage.limitations]
    assert "THREAD_INFO_STREAM_TRUNCATED" in codes
    assert any("cannot settle which TIDs exist" in reason for reason in coverage.reasons)
    # TID 2 is still reported as removed -- it genuinely is not in the
    # target's delivered records -- but no longer as a complete result.
    assert [(r.change_type, r.tid) for r in records] == [("removed", 2)]


def test_threads_reports_an_undelivered_record_as_its_own_coverage_gap():
    from dumpex.commands.threads import collect_threads

    body, data_size = build_thread_info_stream(
        [{"tid": 1, "dump_flags": 0x0, "start_address": 0x400100},
         {"tid": 2, "dump_flags": 0x0, "start_address": 0x500100}],
        body_bytes=12 + THREAD_INFO_ENTRY_SIZE + 3)
    cut = parse_thread_info_stream(
        ThreadInfoStreamDirectory(rva=0, data_size=data_size), io.BytesIO(body))

    result = collect_threads(_mf_with_thread_info(cut, base_tids=(1,)))
    assert result.coverage.status == "partial"
    codes = [limitation.code.value for limitation in result.coverage.limitations]
    assert "THREAD_INFO_STREAM_TRUNCATED" in codes


# ── collect_comparison_premise ────────────────────────────────────────────
# The premise discloses what two captures share and, for every fact a
# capture does not establish, why. It never gates the inventory
# comparison: records, coverage and exit code are those of the
# inventories alone, whatever the identity facts say.

_IMAGE_BASE = 0x00007FF600010000
_TEXT_SECTION = {"name": b".text", "vaddr": 0x1000, "vsize": 0x100, "rawptr": 0x400,
                 "rawsize": 0x200, "chars": 0x60000020}


def _identified_mf(*, capture=1_700_000_100, pid=4660, created=1_700_000_000, build=19041,
                   peb_path="C:\\app\\app.exe", module_path=None, image_size=0x5000,
                   image_timestamp=0x5F5E1000, machine=0x8664, other_modules=()):
    """A capture establishing every premise fact: header, MiscInfo,
    SystemInfo (AMD64 host), a PEB, a ModuleListStream entry at the PEB
    image base, and a captured PE header there whose Machine is
    `machine`."""
    main = Module(_IMAGE_BASE, image_size, module_path or peb_path)
    main.timestamp = image_timestamp
    mf = _process_mf(misc_info=MiscInfo(process_id=pid, process_create_time=created),
                     peb=Peb(_IMAGE_BASE, peb_path), modules=[main, *other_modules],
                     memory={_IMAGE_BASE: build_pe_header([_TEXT_SECTION], machine=machine)})
    mf.header = FakeHeader(capture)
    mf.sysinfo = SysInfo(build_number=build, processor_architecture=PROCESSOR_ARCHITECTURE.AMD64)
    return mf


def _facts(premise) -> dict:
    return {f.fact: f for f in premise.facts}


def test_premise_same_instance_differs_only_in_capture_time():
    premise = collect_comparison_premise(_identified_mf(capture=1_700_000_100),
                                         _identified_mf(capture=1_700_000_200))
    assert premise.scope == "inventory"
    assert premise.process_instance == "same"
    assert premise.capture_order == "baseline_first"
    assert premise.known_differences == ("capture_time",)
    assert premise.unknown_premises == ()
    assert premise.capture_diagnostics == ()
    assert [(f.fact, f.baseline, f.baseline_state) for f in premise.facts] == [
        ("capture_time", "2023-11-14 22:15:00 UTC", "recorded"),
        ("process_id", 4660, "recorded"),
        ("process_create_time", "2023-11-14 22:13:20 UTC", "recorded"),
        ("host_architecture", "AMD64", "recorded"),
        ("os_version", "10.0.19041", "recorded"),
        ("image_machine", "AMD64", "recorded"),
        ("peb_image_path", "C:\\app\\app.exe", "recorded"),
        ("module_image_path", "C:\\app\\app.exe", "recorded"),
        ("module_image_size", 0x5000, "recorded"),
        ("module_image_timestamp", 0x5F5E1000, "recorded")]


def test_premise_unrelated_instance_keeps_every_inventory_record():
    baseline = _identified_mf(pid=100, peb_path="C:\\a\\one.exe",
                              other_modules=[Module(0x1000, 0x1000, "C:\\a.dll")])
    target = _identified_mf(pid=200, peb_path="C:\\b\\two.exe",
                            other_modules=[Module(0x2000, 0x1000, "C:\\b.dll")])
    result = collect_comparison(baseline, target, mode="modules")

    premise = result.summary["premise"]
    assert premise["process_instance"] == "different"
    assert premise["known_differences"] == ["process_id", "peb_image_path", "module_image_path"]
    # An unrelated pair is still an inventory comparison: nothing withheld.
    assert result.coverage.status == "complete"
    assert sorted((r.change_type, r.name) for r in result.records) == [
        ("added", "b.dll"), ("added", "two.exe"), ("removed", "a.dll"), ("removed", "one.exe")]


def test_premise_differing_build_is_disclosed_without_changing_coverage_or_records():
    same = collect_comparison(_identified_mf(), _identified_mf(), mode="modules")
    other_build = collect_comparison(_identified_mf(), _identified_mf(build=22631),
                                     mode="modules")

    premise = other_build.summary["premise"]
    assert premise["known_differences"] == ["os_version"]
    os_fact = next(f for f in premise["facts"] if f["fact"] == "os_version")
    assert (os_fact["baseline"], os_fact["target"]) == ("10.0.19041", "10.0.22631")
    # Process instance rests on PID and creation time alone; a differing
    # build is disclosed, never used to decide the instance.
    assert premise["process_instance"] == "same"
    assert other_build.coverage.status == same.coverage.status == "complete"
    assert other_build.coverage.limitations == same.coverage.limitations
    assert [r.to_dict() for r in other_build.records] == [r.to_dict() for r in same.records]


def test_premise_missing_identity_is_absent_not_different():
    bare = FakeMF()
    bare.modules = FakeStream([Module(0x1000, 0x1000, "C:\\a.dll")], "modules")
    result = collect_comparison(bare, _identified_mf(), mode="modules")

    premise = result.summary["premise"]
    assert premise["process_instance"] == "unknown"
    assert premise["capture_order"] == "unknown"
    assert premise["known_differences"] == []
    assert premise["unknown_premises"] == list(COMPARISON_FACTS)
    assert all(f["baseline"] is None and f["relation"] == "unknown" for f in premise["facts"])
    # Each fact says why: its stream is absent, the PEB was never
    # reconstructed (no SystemInfo or thread list), or the facts located at
    # the PEB image base have no base to be located at.
    assert {f["fact"]: f["baseline_state"] for f in premise["facts"]} == {
        "capture_time": "absent", "process_id": "absent", "process_create_time": "absent",
        "host_architecture": "absent", "os_version": "absent",
        "image_machine": "base_unknown", "peb_image_path": "unreconstructed",
        "module_image_path": "base_unknown", "module_image_size": "base_unknown",
        "module_image_timestamp": "base_unknown"}
    # Missing identity is a disclosed premise, never a coverage gap.
    assert result.coverage.status == "complete"
    assert result.coverage.limitations == []


def test_premise_same_pid_without_creation_time_is_not_the_same_instance():
    """A PID alone can be reused; it does not establish an instance."""
    premise = collect_comparison_premise(_identified_mf(created=0), _identified_mf())
    facts = _facts(premise)
    assert facts["process_id"].relation == "same"
    assert (facts["process_create_time"].relation,
            facts["process_create_time"].baseline_state) == ("unknown", "unset")
    assert premise.process_instance == "unknown"


def test_premise_differing_creation_time_is_a_different_instance_even_with_the_same_pid():
    premise = collect_comparison_premise(_identified_mf(created=1_700_000_000),
                                         _identified_mf(created=1_700_000_050))
    assert premise.process_instance == "different"


def test_premise_orders_a_target_captured_before_its_baseline():
    premise = collect_comparison_premise(_identified_mf(capture=1_700_000_200),
                                         _identified_mf(capture=1_700_000_100))
    assert premise.capture_order == "target_first"
    same = collect_comparison_premise(_identified_mf(), _identified_mf())
    assert same.capture_order == "same_second"
    assert same.known_differences == ()


def test_premise_compares_paths_without_case():
    premise = collect_comparison_premise(_identified_mf(peb_path="C:\\App\\App.exe"),
                                         _identified_mf(peb_path="c:\\app\\APP.EXE"))
    facts = _facts(premise)
    assert facts["peb_image_path"].relation == "same"
    assert facts["module_image_path"].relation == "same"
    # Each capture's own spelling is kept as evidence.
    assert (facts["peb_image_path"].baseline, facts["peb_image_path"].target) == (
        "C:\\App\\App.exe", "c:\\app\\APP.EXE")


# -- the main image's identity, by source --

def test_premise_peb_masquerade_is_a_module_path_difference_and_a_capture_disagreement():
    """The target's PEB still names svchost.exe while the module registered
    at its image base is another file: the PEB path alone agrees with the
    baseline, so it must not stand for the main image's identity."""
    baseline = _identified_mf(peb_path="C:\\Windows\\System32\\svchost.exe")
    target = _identified_mf(peb_path="C:\\Windows\\System32\\svchost.exe",
                            module_path="C:\\ProgramData\\Cache\\evil.exe")
    premise = collect_comparison_premise(baseline, target)
    facts = _facts(premise)

    assert facts["peb_image_path"].relation == "same"
    assert facts["module_image_path"].relation == "different"
    assert premise.known_differences == ("module_image_path",)
    assert [(d.side, d.code, d.severity) for d in premise.capture_diagnostics] == [
        ("target", "PROCESS_MODULE_IDENTITY_MISMATCH", "warning")]


def test_premise_masquerade_in_both_captures_is_disclosed_by_each_capture_alone():
    """Both captures record the same disagreeing paths, so no fact differs
    between them; each capture's own diagnostic is the disclosure."""
    def masqueraded():
        return _identified_mf(peb_path="C:\\Windows\\System32\\svchost.exe",
                              module_path="C:\\ProgramData\\Cache\\evil.exe")

    premise = collect_comparison_premise(masqueraded(), masqueraded())
    assert _facts(premise)["module_image_path"].relation == "same"
    assert premise.known_differences == ()
    assert [(d.side, d.code) for d in premise.capture_diagnostics] == [
        ("baseline", "PROCESS_MODULE_IDENTITY_MISMATCH"),
        ("target", "PROCESS_MODULE_IDENTITY_MISMATCH")]


def test_premise_capture_diagnostics_match_what_process_reports():
    from dumpex.commands.process import collect_process

    target = _identified_mf(peb_path="C:\\Windows\\System32\\svchost.exe",
                            module_path="C:\\ProgramData\\Cache\\evil.exe")
    premise = collect_comparison_premise(_identified_mf(), target)
    process = collect_process(target).records[0].identity_evidence["diagnostics"]
    assert [(d.code, d.message) for d in premise.capture_diagnostics] == [
        (d["code"], d["message"]) for d in process]


def test_premise_same_file_name_in_another_directory_is_a_path_mismatch():
    target = _identified_mf(peb_path="C:\\Windows\\System32\\svchost.exe",
                            module_path="C:\\ProgramData\\Cache\\svchost.exe")
    premise = collect_comparison_premise(_identified_mf(), target)
    assert [(d.side, d.code) for d in premise.capture_diagnostics] == [
        ("target", "PEB_MODULE_PATH_MISMATCH")]
    assert "C:\\ProgramData\\Cache\\svchost.exe" in premise.capture_diagnostics[0].message


def test_premise_wow64_process_differs_in_image_machine_not_host_architecture():
    """SystemInfo describes the host: a WOW64 build of the same program on
    the same x64 host differs only in its main image's Machine."""
    premise = collect_comparison_premise(_identified_mf(machine=0x8664),
                                         _identified_mf(machine=0x014C))
    facts = _facts(premise)
    assert facts["host_architecture"].relation == "same"
    assert (facts["image_machine"].baseline, facts["image_machine"].target) == ("AMD64", "I386")
    assert premise.known_differences == ("image_machine",)


def test_premise_module_facts_are_unmatched_without_a_module_at_the_peb_base():
    mf = _identified_mf()
    mf.peb = Peb(0x7FF700000000, "C:\\app\\app.exe")   # no module registered there
    premise = collect_comparison_premise(mf, _identified_mf())
    facts = _facts(premise)
    assert facts["peb_image_path"].baseline == "C:\\app\\app.exe"
    for name in ("module_image_path", "module_image_size", "module_image_timestamp"):
        assert (facts[name].baseline, facts[name].baseline_state) == (None, "unmatched")
    # app.exe is still registered, at another base.
    assert [(d.side, d.code) for d in premise.capture_diagnostics] == [
        ("baseline", "PROCESS_MODULE_BASE_CONFLICT")]


def test_premise_image_machine_is_uncaptured_without_header_bytes():
    mf = _identified_mf()
    mf.memory_segments_64 = None   # the image base holds no captured bytes
    premise = collect_comparison_premise(mf, _identified_mf())
    machine = _facts(premise)["image_machine"]
    assert (machine.baseline, machine.baseline_state) == (None, "uncaptured")


def test_premise_unset_module_timestamp_is_unset_not_unmatched():
    premise = collect_comparison_premise(_identified_mf(image_timestamp=0), _identified_mf())
    assert premise.unknown_premises == ("module_image_timestamp",)
    assert _facts(premise)["module_image_timestamp"].baseline_state == "unset"


def test_premise_without_a_peb_the_module_facts_have_no_base_not_no_source():
    """The ModuleListStream is present: the module facts are blocked by the
    missing PEB image base, which is what they say, while the PEB path
    carries why the PEB is missing."""
    mf = _identified_mf()
    mf.peb = None
    facts = _facts(collect_comparison_premise(mf, _identified_mf()))
    assert facts["peb_image_path"].baseline_state == "unreconstructed"   # no thread list
    for name in ("image_machine", "module_image_path", "module_image_size",
                 "module_image_timestamp"):
        assert facts[name].baseline_state == "base_unknown"


def test_premise_peb_whose_reconstruction_raised_is_failed():
    mf = _identified_mf()
    mf.peb = None
    mf.threads = FakeStream([Thread(1, Ctx(0x1000))], "threads")
    mf._dumpex_peb_failure = "Exception: Memory address 0x7060 is not in process memory space"
    assert _facts(collect_comparison_premise(mf, _identified_mf()))[
        "peb_image_path"].baseline_state == "failed"


def test_premise_peb_attempted_without_failure_is_absent():
    mf = _identified_mf()
    mf.peb = None
    mf.threads = FakeStream([Thread(1, Ctx(0x1000))], "threads")
    assert _facts(collect_comparison_premise(mf, _identified_mf()))[
        "peb_image_path"].baseline_state == "absent"


# -- the header at the PEB image base, by --process's own classification --

def test_premise_non_pe_bytes_at_the_image_base_are_invalid_and_a_capture_diagnostic():
    """Hollowing or unmapping can leave bytes at the base that are not a PE
    header: that is not "unset", and it is a disagreement inside the
    capture, as --process also reports it."""
    target = _identified_mf()
    target.memory_segments_64 = FakeStream([Segment(_IMAGE_BASE, _IMAGE_BASE, 0x400)],
                                           "memory_segments")
    target.get_reader = lambda: _FakeReader(_FakeBufferedReader({_IMAGE_BASE: b"\x00" * 0x400}))
    premise = collect_comparison_premise(_identified_mf(), target)

    machine = _facts(premise)["image_machine"]
    assert (machine.baseline, machine.target, machine.target_state) == ("AMD64", None, "invalid")
    assert [(d.side, d.code, d.severity) for d in premise.capture_diagnostics] == [
        ("target", "PROCESS_MAIN_IMAGE_PE_INVALID", "warning")]
    assert "0x00007ff600010000" in premise.capture_diagnostics[0].message


def test_premise_header_capture_short_of_machine_is_truncated():
    mf = _identified_mf()
    header = build_pe_header([_TEXT_SECTION])[:0x40]   # DOS header only
    mf.memory_segments_64 = FakeStream([Segment(_IMAGE_BASE, _IMAGE_BASE, len(header))],
                                       "memory_segments")
    mf.get_reader = lambda: _FakeReader(_FakeBufferedReader({_IMAGE_BASE: header}))
    premise = collect_comparison_premise(mf, _identified_mf())
    assert _facts(premise)["image_machine"].baseline_state == "truncated"
    assert premise.capture_diagnostics == ()


def test_premise_captured_header_that_cannot_be_read_is_failed():
    mf = _identified_mf()
    mf.get_reader = lambda: _FakeReader(_FakeBufferedReader({}))   # segment listed, no bytes
    assert _facts(collect_comparison_premise(mf, _identified_mf()))[
        "image_machine"].baseline_state == "failed"


def test_premise_memory_list_that_failed_to_parse_is_failed_not_uncaptured():
    from minidump.constants import MINIDUMP_STREAM_TYPE

    mf = _identified_mf()
    mf.memory_segments_64 = None
    mf._dumpex_stream_failures = {MINIDUMP_STREAM_TYPE.Memory64ListStream: "ValueError: x"}
    assert _facts(collect_comparison_premise(mf, _identified_mf()))[
        "image_machine"].baseline_state == "failed"


# -- PEB and module paths in different Windows path forms --

def _path_diagnostics(peb_path, module_path) -> list:
    premise = collect_comparison_premise(
        _identified_mf(), _identified_mf(peb_path=peb_path, module_path=module_path))
    return [(d.code, d.severity) for d in premise.capture_diagnostics]


@pytest.mark.parametrize("peb_path,module_path", [
    ("\\SystemRoot\\System32\\smss.exe", "\\SystemRoot\\system32\\SMSS.EXE"),
    ("\\??\\C:\\Windows\\System32\\smss.exe", "C:\\Windows\\System32\\smss.exe"),
    ("\\\\?\\C:\\Windows\\System32\\smss.exe", "C:\\Windows\\System32\\smss.exe"),
    ("\\Device\\HarddiskVolume3\\Windows\\app.exe", "\\Device\\HarddiskVolume3\\Windows\\app.exe"),
    ("C:/Windows/System32/smss.exe", "c:\\windows\\system32\\SMSS.EXE"),
])
def test_premise_equivalent_path_forms_are_no_disagreement(peb_path, module_path):
    assert _path_diagnostics(peb_path, module_path) == []


@pytest.mark.parametrize("peb_path,module_path", [
    ("\\SystemRoot\\System32\\smss.exe", "C:\\ProgramData\\Cache\\smss.exe"),
    ("C:\\Windows\\System32\\smss.exe", "C:\\ProgramData\\Cache\\smss.exe"),
    # Two volumes are two files, whatever the paths on them share.
    ("\\Device\\HarddiskVolume1\\Windows\\app.exe", "\\Device\\HarddiskVolume2\\Windows\\app.exe"),
    ("\\Device\\HarddiskVolume3\\Windows\\app.exe", "C:\\Other\\app.exe"),
    ("\\SystemRoot\\System32\\smss.exe", "\\Device\\HarddiskVolume3\\Temp\\smss.exe"),
    ("\\SystemRoot\\System32\\smss.exe", "\\Device\\HarddiskVolume3\\Temp\\System32x\\smss.exe"),
])
def test_premise_paths_that_cannot_name_one_file_disagree(peb_path, module_path):
    assert _path_diagnostics(peb_path, module_path) == [("PEB_MODULE_PATH_MISMATCH", "warning")]


@pytest.mark.parametrize("peb_path,module_path", [
    # The dump records neither which drive a \Device volume is nor where
    # \SystemRoot points, so a consistent path is not an established one --
    # not even \SystemRoot against C:\Windows.
    ("\\Device\\HarddiskVolume3\\Windows\\System32\\smss.exe",
     "C:\\Windows\\System32\\smss.exe"),
    ("\\Device\\HarddiskVolume3\\Windows\\System32\\smss.exe",
     "\\SystemRoot\\System32\\smss.exe"),
    ("\\SystemRoot\\System32\\smss.exe", "C:\\Windows\\System32\\smss.exe"),
    ("\\SystemRoot\\System32\\smss.exe", "D:\\Windows\\System32\\smss.exe"),
    ("\\SystemRoot\\System32\\smss.exe", "D:\\OS\\System32\\smss.exe"),
    # Windows installed at the root of a volume.
    ("\\SystemRoot\\System32\\smss.exe", "\\Device\\HarddiskVolume3\\System32\\smss.exe"),
    ("\\SystemRoot\\System32\\smss.exe", "E:\\System32\\smss.exe"),
    ("C:\\PROGRA~1\\App\\app.exe", "C:\\Program Files\\App\\app.exe"),
])
def test_premise_undecidable_path_forms_are_unresolved_info(peb_path, module_path):
    assert _path_diagnostics(peb_path, module_path) == [("PEB_MODULE_PATH_UNRESOLVED", "info")]


# -- a source that cannot be read costs only its own facts --

class _ExplodingMiscInfoMF(FakeMF):
    @property
    def misc_info(self):
        raise RuntimeError("misc_info stream could not be read")

    @misc_info.setter
    def misc_info(self, value):
        pass


class _ExplodingModulesWithPebMF(FakeMF):
    @property
    def modules(self):
        raise RuntimeError("modules stream could not be read")

    @modules.setter
    def modules(self, value):
        pass


def test_premise_unreadable_stream_is_failed_and_aborts_nothing():
    mf = _ExplodingMiscInfoMF()
    mf.header = FakeHeader(1_700_000_100)
    result = collect_comparison(mf, _identified_mf(), mode="memory")

    premise = result.summary["premise"]
    states = {f["fact"]: f["baseline_state"] for f in premise["facts"]}
    assert states["process_id"] == states["process_create_time"] == "failed"
    assert states["capture_time"] == "recorded"
    assert premise["process_instance"] == "unknown"


def test_premise_unreadable_module_list_keeps_the_peb_path():
    mf = _ExplodingModulesWithPebMF()
    mf.peb = Peb(_IMAGE_BASE, "C:\\app\\app.exe")
    facts = _facts(collect_comparison_premise(mf, _identified_mf()))
    assert (facts["peb_image_path"].baseline, facts["peb_image_path"].baseline_state) == (
        "C:\\app\\app.exe", "recorded")
    for name in ("module_image_path", "module_image_size", "module_image_timestamp"):
        assert facts[name].baseline_state == "failed"


def test_premise_stream_that_failed_to_parse_is_failed_not_absent(tmp_path):
    """Through the real loader: a SystemInfoStream whose architecture the
    parser rejects is recorded as a stream failure, and the premise says
    the source could not be read rather than that the dump lacks it."""
    from tests.fixtures.minidump_bytes import (
        DumpSpec, RawStreamSpec, SYSTEM_INFO, write_minidump)
    from dumpex.core.memory import open_dump, peb_failure

    body = struct.pack("<HHHBB", 0x7777, 6, 0, 4, 1) + b"\x00" * 40
    broken = open_dump(write_minidump(tmp_path / "broken.dmp", DumpSpec(
        architecture=None, raw_streams=(RawStreamSpec(SYSTEM_INFO, body),))))
    missing = open_dump(write_minidump(tmp_path / "missing.dmp", DumpSpec(architecture=None)))
    # Without SystemInfo the loader never attempts the PEB, so no failure is recorded.
    assert broken.peb is None and peb_failure(broken) is None

    facts = _facts(collect_comparison_premise(broken, missing))
    for name in ("host_architecture", "os_version"):
        assert (facts[name].baseline_state, facts[name].target_state) == ("failed", "absent")
    assert facts["capture_time"].relation == "same"
    # The PEB is reconstructed from SystemInfo: without it the dump does not
    # lack a PEB, it was never reconstructed, and nothing derived from it
    # claims an absent source.
    assert facts["peb_image_path"].baseline_state == "unreconstructed"
    for name in ("image_machine", "module_image_path", "module_image_size",
                 "module_image_timestamp"):
        assert facts[name].baseline_state == "base_unknown"


def test_premise_peb_reconstruction_that_raised_is_failed_through_the_loader(tmp_path):
    """A thread whose TEB lies outside the captured memory: the loader
    attempts the PEB, the attempt raises, and the premise reports a PEB
    that could not be read rather than one the dump lacks."""
    from tests.fixtures.minidump_bytes import DumpSpec, ThreadSpec, write_minidump
    from dumpex.core.memory import open_dump, peb_failure

    dump = open_dump(write_minidump(tmp_path / "peb.dmp", DumpSpec(
        threads=(ThreadSpec(tid=1, ip=0x1000, teb=0x7000),))))
    assert dump.peb is None and peb_failure(dump)
    facts = _facts(collect_comparison_premise(dump, dump))
    assert facts["peb_image_path"].baseline_state == "failed"
    assert facts["module_image_path"].baseline_state == "base_unknown"


@pytest.mark.parametrize("mode", ["modules", "threads", "memory", "all"])
def test_every_mode_carries_the_inventory_premise(mode):
    result = collect_comparison(_identified_mf(), _identified_mf(), mode=mode)
    assert list(result.summary) == ["count", "premise"]
    assert result.summary["premise"]["scope"] == "inventory"

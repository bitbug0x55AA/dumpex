"""Unit tests for dumpex.commands.comparison's pure domain functions
(Phase C, PR2). No CLI wiring exists for this module yet -- these test
collect_module_diff/collect_thread_diff/collect_memory_diff/
collect_comparison() directly, the same way test_modules_cmd.py etc.
test the six migrated recon commands' collect_*() functions.
"""
import pytest

from tests.fixtures.fakes import Module, ThreadInfo, Region, FakeStream, FakeMF

from dumpex.commands.comparison import (
    collect_module_diff, collect_thread_diff, collect_memory_diff, collect_comparison,
)
from dumpex.output.records import (
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
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
    assert result.summary == {"count": len(result.records)}


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

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


def test_collect_comparison_all_mode_one_not_evaluated_entity_is_partial_overall():
    # --diff-mode all cross-entity aggregation: modules entirely absent on
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
    assert result.records == []

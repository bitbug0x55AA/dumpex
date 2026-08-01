"""Comparison infrastructure (Phase C, PR2) -- pure domain functions only.

No CLI wiring, no V2Output call, no --json/--csv handling here. --diff
(dumpex/commands/diff.py) stays console-only and untouched; this module
exists so a LATER migration of --diff has a typed, tested comparison
result to build on, reviewed as its own state machine rather than bundled
with a CLI change. That future migration would open both dumps
(open_dump()), build two EvidenceInput entries (id="baseline"/"target"),
construct a V2Output via V2Output.from_evidence() (see
dumpex.output.collector), and call collect_comparison() here with the two
already-open MinidumpFile objects -- exactly the shape cmd_diff() in
diff.py already uses (mf_a already open, path_b opened internally).

Each collect_*_diff() function's set logic (added/removed/rebased,
added/removed, added/removed/protection_changed) is ported directly from
diff.py's diff_modules/diff_threads/diff_memory -- not reinvented -- so a
future console-renderer for this data can still cross-check against the
original, still-shipping console output.

Source naming is dotted and entity-namespaced (e.g. "baseline.modules"/
"target.modules") rather than the bare names the six single-dump commands
use, so a comparison's two sides never collide as coverage facts about a
same-named source, and dumpex.output.coverage._display_name() renders
them as "baseline ModuleListStream"/"target ModuleListStream" accordingly.

Per-entity coverage uses build_coverage_report()'s evaluation_groups (two
independent single-source groups, one per side) rather than a single
merged evaluation_sources group: EITHER side being entirely absent must
make that entity not_evaluated (an absent baseline can't be diffed
against a present target any more than the reverse), while still
producing a DISTINCT limitation per absent side, so "baseline missing",
"target missing", and "both missing" stay structurally different in the
output. A present-but-EMPTY side is not absence -- diffed against an
empty set, so e.g. a present_empty baseline with 5 target modules
legitimately reports all 5 as "added", not not_evaluated.
"""
import ntpath

from dumpex.core.memory import (
    get_modules, get_thread_infos, get_memory_regions, addr_to_module,
    module_name_only, prot_str,
)
from dumpex.rules_pkg.loader import SUSPICIOUS_PROTS
from dumpex.output.records import (
    ModuleDiffRecord, MODULE_DIFF_ADDED, MODULE_DIFF_REMOVED, MODULE_DIFF_REBASED,
    ThreadDiffRecord, THREAD_DIFF_ADDED, THREAD_DIFF_REMOVED,
    MemoryDiffRecord, MEMORY_DIFF_ADDED, MEMORY_DIFF_REMOVED, MEMORY_DIFF_PROTECTION_CHANGED,
    hex_address, MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
)
from dumpex.output.coverage import (
    observe_source, build_coverage_report, combine_coverage_reports,
    EvaluationRequirement, COVERAGE_NOT_EVALUATED,
)
from dumpex.output.command_result import CommandResult

_DIFF_MODES = ("modules", "threads", "memory", "all")


def collect_module_diff(mf_baseline, mf_target) -> "tuple[list, object]":
    """(records, coverage) -- ported from diff.py's diff_modules. Matches
    modules by module_name_only(m.name), exactly like the console
    version. Returns ([], coverage) without attempting a diff at all when
    either side's ModuleListStream is entirely absent."""
    raw_baseline = get_modules(mf_baseline)
    raw_target = get_modules(mf_target)

    sources = {
        "baseline.modules": observe_source(
            "baseline.modules", present=bool(mf_baseline.modules), items=raw_baseline),
        "target.modules": observe_source(
            "target.modules", present=bool(mf_target.modules), items=raw_target),
    }
    coverage = build_coverage_report(sources, evaluation_groups=[
        EvaluationRequirement(("baseline.modules",)),
        EvaluationRequirement(("target.modules",)),
    ])
    if coverage.status == COVERAGE_NOT_EVALUATED:
        return [], coverage

    mods_baseline = {module_name_only(m.name): m for m in raw_baseline}
    mods_target = {module_name_only(m.name): m for m in raw_target}
    added = set(mods_target) - set(mods_baseline)
    removed = set(mods_baseline) - set(mods_target)
    rebased = [n for n in (set(mods_baseline) & set(mods_target))
               if mods_baseline[n].baseaddress != mods_target[n].baseaddress]

    records = []
    for n in sorted(added):
        m = mods_target[n]
        records.append(ModuleDiffRecord(
            change_type=MODULE_DIFF_ADDED, name=n,
            full_path_before=None, full_path_after=m.name or None,
            base_address_before=None, base_address_after=hex_address(m.baseaddress)))
    for n in sorted(removed):
        m = mods_baseline[n]
        records.append(ModuleDiffRecord(
            change_type=MODULE_DIFF_REMOVED, name=n,
            full_path_before=m.name or None, full_path_after=None,
            base_address_before=hex_address(m.baseaddress), base_address_after=None))
    for n in sorted(rebased):
        ma, mb = mods_baseline[n], mods_target[n]
        records.append(ModuleDiffRecord(
            change_type=MODULE_DIFF_REBASED, name=n,
            full_path_before=ma.name or None, full_path_after=mb.name or None,
            base_address_before=hex_address(ma.baseaddress),
            base_address_after=hex_address(mb.baseaddress)))
    return records, coverage


def collect_thread_diff(mf_baseline, mf_target) -> "tuple[list, object]":
    """(records, coverage) -- ported from diff.py's diff_threads.
    ThreadInfoListStream (mf.thread_info), not the base ThreadListStream --
    diff_threads itself only ever reads get_thread_infos(). A removed
    thread never gets a backing_module_before -- diff_threads never
    attempts baseline-side module resolution either."""
    raw_baseline = get_thread_infos(mf_baseline)
    raw_target = get_thread_infos(mf_target)

    sources = {
        "baseline.thread_info": observe_source(
            "baseline.thread_info", present=bool(mf_baseline.thread_info), items=raw_baseline),
        "target.thread_info": observe_source(
            "target.thread_info", present=bool(mf_target.thread_info), items=raw_target),
    }
    coverage = build_coverage_report(sources, evaluation_groups=[
        EvaluationRequirement(("baseline.thread_info",)),
        EvaluationRequirement(("target.thread_info",)),
    ])
    if coverage.status == COVERAGE_NOT_EVALUATED:
        return [], coverage

    ta = {ti.ThreadId: ti for ti in raw_baseline}
    tb = {ti.ThreadId: ti for ti in raw_target}
    modules_target = get_modules(mf_target)
    modules_target_available = bool(mf_target.modules)

    added = set(tb) - set(ta)
    removed = set(ta) - set(tb)

    records = []
    for tid in sorted(added):
        sa = tb[tid].StartAddress or 0
        mod = addr_to_module(sa, modules_target)
        if mod is not None:
            backing_module_after = ntpath.basename(mod.name)
            backing_module_context = MODULE_CONTEXT_RESOLVED
        elif modules_target_available:
            backing_module_after = None
            backing_module_context = MODULE_CONTEXT_UNREGISTERED
        else:
            backing_module_after = None
            backing_module_context = MODULE_CONTEXT_UNAVAILABLE
        records.append(ThreadDiffRecord(
            change_type=THREAD_DIFF_ADDED, tid=tid,
            start_address_before=None, start_address_after=hex_address(sa),
            backing_module_after=backing_module_after,
            backing_module_context=backing_module_context))
    for tid in sorted(removed):
        sa = ta[tid].StartAddress or 0
        records.append(ThreadDiffRecord(
            change_type=THREAD_DIFF_REMOVED, tid=tid,
            start_address_before=hex_address(sa), start_address_after=None))
    return records, coverage


def collect_memory_diff(mf_baseline, mf_target) -> "tuple[list, object]":
    """(records, coverage) -- ported from diff.py's diff_memory.
    suspicious_before/_after reuse MemoryRegionRecord.suspicious's own
    SUSPICIOUS_PROTS check rather than diff_memory's own 4-tier console
    categorization (rwx/exec/notable/noise), which stays a future
    console-renderer concern."""
    raw_baseline = get_memory_regions(mf_baseline)
    raw_target = get_memory_regions(mf_target)

    sources = {
        "baseline.memory_info": observe_source(
            "baseline.memory_info", present=bool(mf_baseline.memory_info), items=raw_baseline),
        "target.memory_info": observe_source(
            "target.memory_info", present=bool(mf_target.memory_info), items=raw_target),
    }
    coverage = build_coverage_report(sources, evaluation_groups=[
        EvaluationRequirement(("baseline.memory_info",)),
        EvaluationRequirement(("target.memory_info",)),
    ])
    if coverage.status == COVERAGE_NOT_EVALUATED:
        return [], coverage

    ra = {r.BaseAddress: r for r in raw_baseline}
    rb = {r.BaseAddress: r for r in raw_target}
    added = set(rb) - set(ra)
    removed = set(ra) - set(rb)
    changed = {addr for addr in (set(ra) & set(rb))
               if prot_str(ra[addr].Protect) != prot_str(rb[addr].Protect)}

    records = []
    for addr in sorted(added):
        r = rb[addr]
        protect = prot_str(r.Protect)
        records.append(MemoryDiffRecord(
            change_type=MEMORY_DIFF_ADDED, base_address=hex_address(addr),
            size_before=None, size_after=r.RegionSize,
            protect_before=None, protect_after=protect,
            type_before=None, type_after=prot_str(r.Type),
            suspicious_before=None,
            suspicious_after=any(s in protect for s in SUSPICIOUS_PROTS)))
    for addr in sorted(removed):
        r = ra[addr]
        protect = prot_str(r.Protect)
        records.append(MemoryDiffRecord(
            change_type=MEMORY_DIFF_REMOVED, base_address=hex_address(addr),
            size_before=r.RegionSize, size_after=None,
            protect_before=protect, protect_after=None,
            type_before=prot_str(r.Type), type_after=None,
            suspicious_before=any(s in protect for s in SUSPICIOUS_PROTS),
            suspicious_after=None))
    for addr in sorted(changed):
        r_before, r_after = ra[addr], rb[addr]
        protect_before, protect_after = prot_str(r_before.Protect), prot_str(r_after.Protect)
        records.append(MemoryDiffRecord(
            change_type=MEMORY_DIFF_PROTECTION_CHANGED, base_address=hex_address(addr),
            size_before=r_before.RegionSize, size_after=r_after.RegionSize,
            protect_before=protect_before, protect_after=protect_after,
            type_before=prot_str(r_before.Type), type_after=prot_str(r_after.Type),
            suspicious_before=any(s in protect_before for s in SUSPICIOUS_PROTS),
            suspicious_after=any(s in protect_after for s in SUSPICIOUS_PROTS)))
    return records, coverage


def collect_comparison(mf_baseline, mf_target, mode: str = "all") -> CommandResult:
    """Mirrors diff.py's cmd_diff() gating (`if mode in (...)`) but
    returns a single CommandResult instead of printing -- one
    kind="comparison" result whose `records` is a tagged union of
    whichever entity types `mode` selected, and whose `coverage` is every
    selected entity's own CoverageReport combined via
    combine_coverage_reports() (unanimous not_evaluated required across
    entities; a single weak entity among otherwise-fine ones is partial,
    not not_evaluated). Takes already-open mf_baseline/mf_target -- same
    shape as cmd_diff's own mf_a (already open) -- opening dumps is the
    caller's job."""
    if mode not in _DIFF_MODES:
        raise ValueError(f"collect_comparison() mode must be one of {_DIFF_MODES}, got {mode!r}")

    all_records = []
    reports = []
    if mode in ("modules", "all"):
        records, coverage = collect_module_diff(mf_baseline, mf_target)
        all_records.extend(records)
        reports.append(coverage)
    if mode in ("threads", "all"):
        records, coverage = collect_thread_diff(mf_baseline, mf_target)
        all_records.extend(records)
        reports.append(coverage)
    if mode in ("memory", "all"):
        records, coverage = collect_memory_diff(mf_baseline, mf_target)
        all_records.extend(records)
        reports.append(coverage)

    combined = combine_coverage_reports(reports)
    return CommandResult(kind="comparison", records=all_records, coverage=combined,
                          summary={"count": len(all_records)})

"""Comparison infrastructure (Phase C, PR2/D) -- pure domain functions only.

No CLI wiring, no V2Output call, no --json handling here --
dumpex/commands/diff.py owns all of that (collect_diff/render_diff_console/
cmd_diff), calling collect_comparison() here with two already-open
MinidumpFile objects.

Each collect_*_diff() function's set logic (added/removed/rebased,
added/removed, added/removed/protection_changed) is ported directly from
diff.py's original diff_modules/diff_threads/diff_memory -- not
reinvented -- so diff.py's console renderer can still cross-check against
that lineage.

Per-side stream reads are isolated via _observe_or_failed(): a genuinely
raised exception (not just an absent/empty stream) becomes
SourceState.FAILED for that side specifically, rather than crashing the
whole comparison or letting the OTHER side's real data get silently
misreported as 100% added/removed against an empty stand-in -- see each
collect_*_diff()'s own FAILED-gate comment for why the diff-building step
must never run when a side is FAILED.

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
    EvaluationRequirement, SourceRequirement, COVERAGE_NOT_EVALUATED,
    SourceObservation, SourceState,
)
from dumpex.output.command_result import CommandResult

_DIFF_MODES = ("modules", "threads", "memory", "all")


def _observe_or_failed(name: str, mf, stream_attr: str, getter) -> "tuple[SourceObservation, list]":
    """(observation, items) -- isolates one side's stream-presence-check +
    read into a single try/except. A genuinely raised exception (e.g. an
    mf.modules property that raises on access, as opposed to a stream
    that's merely absent or empty) is reported as SourceState.FAILED for
    THIS side specifically, via the same SourceObservation shape
    observe_source() already produces for the absent/present_empty/
    present cases -- never silently treated as "zero items," which would
    misreport every one of the OTHER side's real items as added/removed
    instead of correctly refusing to diff at all (see each
    collect_*_diff()'s own post-coverage FAILED gate, which this return
    value drives)."""
    try:
        present = bool(getattr(mf, stream_attr))
        items = getter(mf)
        return observe_source(name, present=present, items=items), items
    except Exception as e:
        # str(e) can legitimately be "" for an exception raised with no
        # message (e.g. bare `raise RuntimeError()`) -- SourceObservation.
        # detail requires None or a NON-EMPTY string, so fall back to
        # repr(e) (always non-empty: at minimum the exception's class
        # name) rather than let a message-less exception crash here too.
        return SourceObservation(name=name, state=SourceState.FAILED,
                                  detail=str(e) or repr(e)), []


def _module_match_key(m) -> str:
    """The cross-dump matching key for one module -- module_name_only()
    when the module has a real name, or an address-qualified key when it
    doesn't. module_name_only() returns "" for an anonymous module (no
    name at all, or an empty one), and "" alone would collide across
    EVERY anonymous module in the same dump -- {module_name_only(m.name):
    m for m in raw_...} would then silently keep only the last one,
    dropping every other anonymous module's diff entirely. Two anonymous
    modules can never share a base address within one dump, so this key
    is always unique there. Across dumps, an anonymous module's
    address-qualified key differs whenever its address differs, so it can
    never be matched as "rebased" -- the conservative, correct choice,
    since nothing else identifies it as "the same" module between two
    captures (unlike a named module, whose key is stable across dumps by
    construction)."""
    name_key = module_name_only(m.name)
    return name_key if name_key else f"<unnamed@0x{m.baseaddress:016x}>"


def _module_display_name(m) -> str:
    """The wire `name` field -- module_name_only() when available, else
    the same "(unnamed)" placeholder dumpex.commands.modules.py's
    ModuleRecord.name already uses for an anonymous module, so `name`
    always stays a non-empty string (required by the v2.1 schema) without
    leaking _module_match_key's internal address-qualified form onto the
    wire."""
    return module_name_only(m.name) or "(unnamed)"


def collect_module_diff(mf_baseline, mf_target) -> "tuple[list, object]":
    """(records, coverage) -- ported from diff.py's diff_modules. Matches
    modules by _module_match_key(m) (module_name_only(m.name), same as
    the console version, for a named module), exactly like the console
    version for named modules -- see _module_match_key's own docstring
    for anonymous ones. Returns ([], coverage) without attempting a diff
    at all when either side's ModuleListStream is entirely absent OR
    failed to read (see _observe_or_failed)."""
    baseline_obs, raw_baseline = _observe_or_failed(
        "baseline.modules", mf_baseline, "modules", get_modules)
    target_obs, raw_target = _observe_or_failed(
        "target.modules", mf_target, "modules", get_modules)
    sources = {"baseline.modules": baseline_obs, "target.modules": target_obs}

    coverage = build_coverage_report(
        sources,
        evaluation_groups=[EvaluationRequirement(("baseline.modules",)),
                            EvaluationRequirement(("target.modules",))],
        # Bare names here so a FAILED side (which the evaluation_groups
        # gate above does NOT catch -- not_evaluated only fires on
        # ABSENT, never FAILED) still produces a SOURCE_FAILED limitation
        # via the reducer's existing FAILED branch, yielding PARTIAL
        # rather than a false COMPLETE with zero limitations.
        completeness_checks=["baseline.modules", "target.modules"],
    )
    if coverage.status == COVERAGE_NOT_EVALUATED:
        return [], coverage
    if baseline_obs.state == SourceState.FAILED or target_obs.state == SourceState.FAILED:
        # Required in addition to the NOT_EVALUATED check above: a FAILED
        # side is not ABSENT, so it survives that gate, but raw_baseline/
        # raw_target is [] for it (the _observe_or_failed fallback) --
        # proceeding to diff against that [] would silently misreport
        # 100% of the OTHER side's real items as added/removed.
        return [], coverage

    mods_baseline = {_module_match_key(m): m for m in raw_baseline}
    mods_target = {_module_match_key(m): m for m in raw_target}
    added = set(mods_target) - set(mods_baseline)
    removed = set(mods_baseline) - set(mods_target)
    rebased = [n for n in (set(mods_baseline) & set(mods_target))
               if mods_baseline[n].baseaddress != mods_target[n].baseaddress]

    records = []
    for n in sorted(added):
        m = mods_target[n]
        records.append(ModuleDiffRecord(
            change_type=MODULE_DIFF_ADDED, name=_module_display_name(m),
            full_path_before=None, full_path_after=m.name or None,
            base_address_before=None, base_address_after=hex_address(m.baseaddress)))
    for n in sorted(removed):
        m = mods_baseline[n]
        records.append(ModuleDiffRecord(
            change_type=MODULE_DIFF_REMOVED, name=_module_display_name(m),
            full_path_before=m.name or None, full_path_after=None,
            base_address_before=hex_address(m.baseaddress), base_address_after=None))
    for n in sorted(rebased):
        ma, mb = mods_baseline[n], mods_target[n]
        records.append(ModuleDiffRecord(
            change_type=MODULE_DIFF_REBASED, name=_module_display_name(mb),
            full_path_before=ma.name or None, full_path_after=mb.name or None,
            base_address_before=hex_address(ma.baseaddress),
            base_address_after=hex_address(mb.baseaddress)))
    return records, coverage


def collect_thread_diff(mf_baseline, mf_target) -> "tuple[list, object]":
    """(records, coverage) -- ported from diff.py's diff_threads.
    ThreadInfoListStream (mf.thread_info), not the base ThreadListStream --
    diff_threads itself only ever reads get_thread_infos(). A removed
    thread never gets a backing_module_before -- diff_threads never
    attempts baseline-side module resolution either.

    Unlike diff_threads' own console rendering (`sa = ti.StartAddress or
    0`, which folds "unknown" and "genuinely 0" into the same printed
    "0x0"), a missing StartAddress is never coerced to 0 here: doing so
    would feed a fabricated address into addr_to_module() and could
    produce MODULE_CONTEXT_UNREGISTERED -- a real, confirmed "this thread
    is not backed by any known module" DFIR signal -- for a thread whose
    address was simply never known at all. start_address_*/
    backing_module_after/backing_module_context all stay null when
    StartAddress itself is null, mirroring ThreadRecord's own module_context
    convention (see records.py).

    target.modules is only read, and only registered as a coverage
    source, when at least one ADDED thread has a known StartAddress
    (removed threads never need it -- see above). Registering it
    unconditionally would silently mismatch "coverage says complete" with
    a backing_module_context that says "unavailable" whenever
    ModuleListStream happens to be missing from a dump with no added
    threads at all to explain it; registering it only when it's actually
    consulted keeps the two in sync -- an absent target.modules makes
    coverage partial (with its own reason) exactly when a
    backing_module_context could actually come back "unavailable"."""
    baseline_obs, raw_baseline = _observe_or_failed(
        "baseline.thread_info", mf_baseline, "thread_info", get_thread_infos)
    target_obs, raw_target = _observe_or_failed(
        "target.thread_info", mf_target, "thread_info", get_thread_infos)
    sources = {"baseline.thread_info": baseline_obs, "target.thread_info": target_obs}
    completeness_checks = ["baseline.thread_info", "target.thread_info"]

    ta = {ti.ThreadId: ti for ti in raw_baseline}
    tb = {ti.ThreadId: ti for ti in raw_target}
    added = set(tb) - set(ta)
    removed = set(ta) - set(tb)
    # If either REQUIRED side already failed to read, `added`/`ta`/`tb`
    # are meaningless (built from the [] fallback for whichever side
    # failed) -- the whole diff is about to be discarded below (the
    # thread_info_failed gate after build_coverage_report), so skip even
    # ATTEMPTING the target.modules read here: doing so anyway would
    # produce a spurious, misleading SOURCE_ABSENT/SOURCE_FAILED
    # limitation about modules when the actual, real problem is the
    # failed thread_info read.
    thread_info_failed = (baseline_obs.state == SourceState.FAILED
                           or target_obs.state == SourceState.FAILED)
    needs_target_modules = (not thread_info_failed
                             and any(tb[tid].StartAddress is not None for tid in added))

    modules_target_available = None
    modules_target = None
    if needs_target_modules:
        # mf_target.modules/get_modules(mf_target) are only ever touched
        # here, inside this branch -- when no added thread has a known
        # StartAddress, nothing below ever consults modules_target/
        # modules_target_available (see the "sa is None" branch further
        # down), so accessing the stream at all would be an unjustified
        # read of data this call never actually needed.
        modules_obs, modules_target = _observe_or_failed(
            "target.modules", mf_target, "modules", get_modules)
        sources["target.modules"] = modules_obs
        # A FAILED target.modules degrades the SAME way an absent one
        # does (module resolution just isn't attempted -- thread add/
        # remove detection itself never needed this stream) rather than
        # aborting the whole thread diff the way a FAILED thread_info
        # side does below -- this stream is a strictly optional
        # enrichment, not a source the diff computation itself depends on.
        # PRESENT_EMPTY still counts as "available" (the stream itself
        # exists; an address just won't resolve, correctly reported as
        # UNREGISTERED, not UNAVAILABLE) -- only ABSENT/FAILED are not.
        modules_target_available = modules_obs.state in (
            SourceState.PRESENT, SourceState.PRESENT_EMPTY)
        # A plain bare-name completeness check here would produce a
        # limitation byte-identical to collect_module_diff's own ("target
        # ModuleListStream not present in this dump" for ABSENT, or the
        # same SOURCE_FAILED text for FAILED) when both fire together
        # under collect_comparison(mode="all") -- scope="thread" +
        # unavailable_fields differentiates the two for EITHER state: this
        # one says WHICH thread-side fields are unavailable as a result,
        # not just that the stream is absent/unreadable.
        # _derive_required_source_limitation applies this customization to
        # both its ABSENT and FAILED branches identically, so the two
        # entities' limitations never collide (and combine_coverage_
        # reports' dedup, which only collapses byte-identical limitations,
        # correctly leaves both in place). affected_count is deliberately
        # not set -- SOURCE_ABSENT's own contract only allows it paired
        # with a counterpart_source whose record_count it must equal
        # exactly (see coverage.py's _validate_source_absent_against_
        # sources), and no such counterpart exists here (this fact is
        # about a SUBSET of target.thread_info's threads -- the added ones
        # with a known address -- not "every record in some counterpart
        # source").
        completeness_checks.append(SourceRequirement(
            "target.modules", scope="thread",
            unavailable_fields=("backing_module_after", "backing_module_context")))

    coverage = build_coverage_report(
        sources,
        evaluation_groups=[EvaluationRequirement(("baseline.thread_info",)),
                            EvaluationRequirement(("target.thread_info",))],
        completeness_checks=completeness_checks,
    )
    if coverage.status == COVERAGE_NOT_EVALUATED:
        return [], coverage
    if baseline_obs.state == SourceState.FAILED or target_obs.state == SourceState.FAILED:
        # Only the two REQUIRED sources abort the whole thread diff --
        # target.modules failing is handled above (degrade, don't abort).
        return [], coverage

    records = []
    for tid in sorted(added):
        sa = tb[tid].StartAddress
        if sa is None:
            backing_module_after = None
            backing_module_context = None
        else:
            mod = addr_to_module(sa, modules_target)
            if mod is not None:
                # mod.name or "(unnamed)" BEFORE ntpath.basename -- same
                # order modules.py's own ModuleRecord.name uses, and for
                # the same reason: ntpath.basename(None) raises TypeError
                # outright (an anonymous module's name is None, not ""),
                # and basename-ing the empty string would otherwise
                # produce "" itself, which the wire's non-empty-string
                # contract for backing_module_after rejects.
                backing_module_after = ntpath.basename(mod.name or "(unnamed)")
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
        sa = ta[tid].StartAddress
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
    baseline_obs, raw_baseline = _observe_or_failed(
        "baseline.memory_info", mf_baseline, "memory_info", get_memory_regions)
    target_obs, raw_target = _observe_or_failed(
        "target.memory_info", mf_target, "memory_info", get_memory_regions)
    sources = {"baseline.memory_info": baseline_obs, "target.memory_info": target_obs}

    coverage = build_coverage_report(
        sources,
        evaluation_groups=[EvaluationRequirement(("baseline.memory_info",)),
                            EvaluationRequirement(("target.memory_info",))],
        completeness_checks=["baseline.memory_info", "target.memory_info"],
    )
    if coverage.status == COVERAGE_NOT_EVALUATED:
        return [], coverage
    if baseline_obs.state == SourceState.FAILED or target_obs.state == SourceState.FAILED:
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

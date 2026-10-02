"""--diff command.

collect_diff()/render_diff_console()/cmd_diff() -- the same collect/
render/cmd trio every other recon command uses. The set-difference logic
(added/removed/rebased, added/removed, added/removed/protection_changed)
and the comparison premise live in dumpex.commands.comparison;
render_diff_console renders them from the resulting CommandResult alone.

The console states inventory relations, never history: an entry is "only
in" one capture, a module has a "different base address", a region's
"protection differs" -- none of them is an observed load, unload, rebase
or protection change. The premise block renders result.summary.premise,
the same value --json emits.
"""
import ntpath

from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN, console_safe
from dumpex.rules_pkg.loader import SUSPICIOUS_PROTS
from dumpex.output.command_result import CommandResult
from dumpex.output.records import (
    MODULE_CONTEXT_RESOLVED,
    FACT_RELATION_SAME, FACT_RELATION_DIFFERENT, FACT_RELATION_UNKNOWN,
    FACT_STATE_RECORDED, FACT_STATE_ABSENT, FACT_STATE_FAILED, FACT_STATE_UNSET,
    FACT_STATE_UNRECONSTRUCTED, FACT_STATE_BASE_UNKNOWN, FACT_STATE_UNMATCHED,
    FACT_STATE_UNCAPTURED, FACT_STATE_TRUNCATED, FACT_STATE_INVALID,
    PROCESS_INSTANCE_SAME, PROCESS_INSTANCE_DIFFERENT,
    CAPTURE_ORDER_BASELINE_FIRST, CAPTURE_ORDER_TARGET_FIRST, CAPTURE_ORDER_SAME_SECOND,
    CAPTURE_ORDER_UNKNOWN,
)
from dumpex.output.coverage import render_limitation, SourceState
from dumpex.commands.comparison import collect_comparison

# MemoryDiffRecord deliberately only carries the coarse suspicious_before/
# _after bool (see comparison.py's own docstring) -- the console's own
# 4-tier added categorization (rwx/exec/notable/noise) and 2-tier removed
# categorization (exec/other) are re-derived here, at render time, from
# protect_after/protect_before directly, exactly mirroring the original
# diff_memory's own NOTABLE_PROTS/EXEC_PROTS membership checks.
NOTABLE_PROTS = {
    "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",  # RWX -- always report
    "PAGE_EXECUTE_READ", "PAGE_EXECUTE",                  # executable -- report
    "PAGE_READWRITE",                                     # writable -- report if private
}
EXEC_PROTS = {"PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",
              "PAGE_EXECUTE_READ", "PAGE_EXECUTE"}


def collect_diff(mf_target, mf_baseline, mode: str = "all") -> CommandResult:
    """Collect changes in the primary target relative to the baseline.

    comparison.collect_comparison() uses the domain-level baseline/target
    ordering, while this CLI-facing wrapper follows command-line ordering:
    primary target first, ``--diff`` reference second.
    """
    return collect_comparison(mf_baseline, mf_target, mode)


def _int_or(hex_str, default: int = 0) -> int:
    """Parses one of dumpex.output.records' fixed-16-digit hex_address() strings
    back into a plain int -- needed wherever diff's OWN console has
    always used VARIABLE-width hex (`0x{n:x}`, not `0x{n:016x}`), unlike
    every other wire-format address string. `default` reproduces the
    original console's own `x or 0` fold for a genuinely unknown address
    (there is no old behavior to match here beyond "print SOME number";
    see comparison.py's "never coerced to 0" comment -- the fold only
    ever happens here, at render time, never in the stored record)."""
    return int(hex_str, 16) if hex_str else default


def _reasons_for(coverage, predicate) -> list:
    return [render_limitation(l) for l in coverage.limitations if predicate(l)]


def _print_reasons(reasons) -> None:
    for reason in reasons:
        print(YELLOW(f"  [~] {reason}"))


_UNEVALUATED_STATES = (SourceState.ABSENT, SourceState.FAILED)


def _count_or_na(obs) -> str:
    """record_count is None for both ABSENT and FAILED -- `or 0` would
    print "0" for a side that was never actually read, indistinguishable
    from a side genuinely confirmed to have zero items. N/A only when
    there is truly no count to report; PRESENT_EMPTY still prints 0 (it
    IS a confirmed zero)."""
    return "N/A" if obs.record_count is None else str(obs.record_count)


def _entity_not_evaluated(coverage, baseline_source: str, target_source: str) -> bool:
    """True when EITHER required side for this entity is ABSENT or FAILED
    -- exactly the condition under which collect_module_diff/
    collect_thread_diff/collect_memory_diff each return records=[] without
    attempting a diff at all (see their own post-coverage gates in
    comparison.py). Deliberately checks only the entity's own two required
    sources (e.g. thread's baseline.thread_info/target.thread_info), never
    an optional enrichment source like target.modules -- a FAILED/ABSENT
    target.modules degrades thread backing-module resolution but must
    never suppress the add/remove section itself, which never depended on
    it."""
    baseline_state = coverage.sources[baseline_source].state
    target_state = coverage.sources[target_source].state
    return baseline_state in _UNEVALUATED_STATES or target_state in _UNEVALUATED_STATES


def _render_module_diff(records, coverage, label_baseline, label_target) -> None:
    module_records = [r for r in records if r.entity_type == "module"]
    baseline_obs = coverage.sources["baseline.modules"]
    target_obs = coverage.sources["target.modules"]

    print(f"\n{BOLD('═══ MODULE DIFF ═══')}")
    _print_reasons(_reasons_for(
        coverage, lambda l: l.source in ("baseline.modules", "target.modules")
        and l.scope != "thread"))
    print(f"  {DIM(label_baseline)}: {_count_or_na(baseline_obs)} modules")
    print(f"  {DIM(label_target)}: {_count_or_na(target_obs)} modules")

    if _entity_not_evaluated(coverage, "baseline.modules", "target.modules"):
        # collect_module_diff never attempted a diff at all here (either
        # side ABSENT/FAILED) -- module_records is unconditionally [], so
        # printing "No new modules."/"No removed modules." below would
        # read as "compared, found nothing," not "never compared."
        print(DIM("\n  Comparison not evaluated."))
        return
    print()

    # Header counts come from the SOURCE's own record_count, not a
    # recount of `records` (which only holds the diff, not a full
    # inventory) -- see this function's own note on the one narrow,
    # accepted divergence from the original console's counting: the
    # original silently deduplicates by lowercase basename before
    # counting (a pre-existing bug when two named modules share a
    # basename), this uses the true raw stream count instead.
    added = [r for r in module_records if r.change_type == "added"]
    if added:
        print(GREEN(f"  [+] Only in {label_target} ({len(added)}):"))
        for r in added:
            print(GREEN(f"      {r.base_address_after}  {console_safe(r.full_path_after)}"))
    else:
        print(DIM(f"  [+] No modules only in {label_target}."))

    removed = [r for r in module_records if r.change_type == "removed"]
    if removed:
        print(RED(f"\n  [-] Only in {label_baseline} ({len(removed)}):"))
        for r in removed:
            print(RED(f"      {r.base_address_before}  {console_safe(r.full_path_before)}"))
    else:
        print(DIM(f"\n  [-] No modules only in {label_baseline}."))

    rebased = [r for r in module_records if r.change_type == "rebased"]
    if rebased:
        print(YELLOW(f"\n  [~] Different base address ({len(rebased)}):"))
        for r in rebased:
            before = _int_or(r.base_address_before)
            after = _int_or(r.base_address_after)
            print(YELLOW(f"      {console_safe(r.name)}: baseline 0x{before:x}, "
                         f"target 0x{after:x}"))


def _render_thread_diff(records, coverage, label_baseline, label_target) -> None:
    thread_records = [r for r in records if r.entity_type == "thread"]
    baseline_obs = coverage.sources["baseline.thread_info"]
    target_obs = coverage.sources["target.thread_info"]

    print(f"\n{BOLD('═══ THREAD DIFF ═══')}")
    _print_reasons(_reasons_for(
        coverage, lambda l: l.source in ("baseline.thread_info", "target.thread_info")
        or (l.source == "target.modules" and l.scope == "thread")))
    print(f"  {DIM(label_baseline)}: {_count_or_na(baseline_obs)} threads")
    print(f"  {DIM(label_target)}: {_count_or_na(target_obs)} threads")

    if _entity_not_evaluated(coverage, "baseline.thread_info", "target.thread_info"):
        # Only the two REQUIRED thread_info sides gate this -- an ABSENT/
        # FAILED target.modules is an OPTIONAL enrichment source (see
        # comparison.py's collect_thread_diff) and must never suppress
        # add/remove rendering, which never depended on it.
        print(DIM("\n  Comparison not evaluated."))
        return
    print()

    added = [r for r in thread_records if r.change_type == "added"]
    if added:
        print(GREEN(f"  [+] TIDs only in {label_target} ({len(added)}):"))
        for r in added:
            sa = _int_or(r.start_address_after)
            if r.backing_module_context == MODULE_CONTEXT_RESOLVED:
                backed = console_safe(r.backing_module_after)
            else:
                # Matches the original console's own conflation of
                # "confirmed unregistered" and "ModuleListStream itself
                # absent" into one string -- extended, not newly
                # invented, to also cover the genuinely-unknown-address
                # case the original console never had a name for (it
                # coerced StartAddress=None to 0 and looked THAT up
                # instead, almost never finding a match either).
                backed = RED("NOT IN ANY MODULE ⚠")
            print(GREEN(f"      TID=0x{r.tid:x}  StartAddr=0x{sa:x}  Backed by: {backed}"))
    else:
        print(DIM(f"  [+] No TIDs only in {label_target}."))

    removed = [r for r in thread_records if r.change_type == "removed"]
    if removed:
        print(RED(f"\n  [-] TIDs only in {label_baseline} ({len(removed)}):"))
        for r in removed:
            sa = _int_or(r.start_address_before)
            print(RED(f"      TID=0x{r.tid:x}  StartAddr=0x{sa:x}"))
    else:
        print(DIM(f"\n  [-] No TIDs only in {label_baseline}."))


def _render_memory_diff(records, coverage, label_baseline, label_target, verbose=False) -> None:
    memory_records = [r for r in records if r.entity_type == "memory_region"]
    baseline_obs = coverage.sources["baseline.memory_info"]
    target_obs = coverage.sources["target.memory_info"]

    added = [r for r in memory_records if r.change_type == "added"]
    removed = [r for r in memory_records if r.change_type == "removed"]
    changed = [r for r in memory_records if r.change_type == "protection_changed"]

    def region_label_after(r):
        p, t = r.protect_after, r.type_after
        rwx = RED(" ◄ RWX!") if r.suspicious_after else ""
        priv = YELLOW(" [PRIVATE]") if t and "MEM_PRIVATE" in t else ""
        exec_ = YELLOW(" [EXEC]") if p and any(e in p for e in EXEC_PROTS) and not rwx else ""
        return f"{r.base_address}  size=0x{r.size_after:<8x}  {p:<32}{rwx}{priv}{exec_}"

    def region_label_before(r):
        p, t = r.protect_before, r.type_before
        rwx = RED(" ◄ RWX!") if r.suspicious_before else ""
        priv = YELLOW(" [PRIVATE]") if t and "MEM_PRIVATE" in t else ""
        exec_ = YELLOW(" [EXEC]") if p and any(e in p for e in EXEC_PROTS) and not rwx else ""
        return f"{r.base_address}  size=0x{r.size_before:<8x}  {p:<32}{rwx}{priv}{exec_}"

    added_rwx = [r for r in added if r.suspicious_after]
    added_exec = [r for r in added if r.protect_after and any(e in r.protect_after for e in EXEC_PROTS)
                  and r not in added_rwx]
    added_notable = [r for r in added
                      if r.protect_after and any(n in r.protect_after for n in NOTABLE_PROTS)
                      and r not in added_rwx and r not in added_exec]
    added_noise = [r for r in added
                   if r not in added_rwx and r not in added_exec and r not in added_notable]

    removed_exec = [r for r in removed
                     if r.protect_before and any(e in r.protect_before for e in EXEC_PROTS)]
    removed_other = [r for r in removed if r not in removed_exec]

    print(f"\n{BOLD('═══ MEMORY REGION DIFF ═══')}")
    _print_reasons(_reasons_for(
        coverage, lambda l: l.source in ("baseline.memory_info", "target.memory_info")))
    print(f"  {DIM(label_baseline)}: {_count_or_na(baseline_obs)} regions")
    print(f"  {DIM(label_target)}: {_count_or_na(target_obs)} regions")

    if _entity_not_evaluated(coverage, "baseline.memory_info", "target.memory_info"):
        # added/removed/changed are unconditionally [] here, so a count
        # line or "No RWX regions only in ..." would read as a completed
        # comparison that found nothing, not one that never ran.
        print(DIM("\n  Comparison not evaluated."))
        return
    print(f"  {DIM('Base addresses in one capture only')}: "
          f"{len(added)} in {label_target}, {len(removed)} in {label_baseline}\n")

    if added_rwx:
        print(RED(f"  [!] RWX regions only in {label_target} ({len(added_rwx)}) — HIGH SUSPICION:"))
        for r in added_rwx:
            print(RED(f"      {region_label_after(r)}"))
    else:
        print(DIM(f"  [!] No RWX regions only in {label_target}."))

    if added_exec:
        print(YELLOW(f"\n  [+] Executable regions only in {label_target} ({len(added_exec)}):"))
        for r in added_exec:
            print(YELLOW(f"      {region_label_after(r)}"))

    if added_notable and verbose:
        print(f"\n  [+] Other notable regions only in {label_target} ({len(added_notable)}):")
        for r in added_notable:
            print(f"      {region_label_after(r)}")

    if added_noise:
        if verbose:
            print(f"\n  [+] Routine regions only in {label_target} ({len(added_noise)}):")
            for r in added_noise:
                print(DIM(f"      {r.base_address}  size=0x{r.size_after:<8x}  {r.protect_after}"))
        else:
            print(DIM(f"\n  [·] {len(added_noise)} routine regions only in {label_target} hidden "
                      f"(read-only, no-access and other non-executable protections)."))
            print(DIM("      Use --verbose to show all."))

    if removed_exec:
        print(RED(f"\n  [-] Executable regions only in {label_baseline} ({len(removed_exec)}):"))
        for r in removed_exec:
            print(RED(f"      {region_label_before(r)}"))

    if removed_other and verbose:
        print(f"\n  [-] Other regions only in {label_baseline} ({len(removed_other)}):")
        for r in removed_other:
            print(DIM(f"      {r.base_address}  size=0x{r.size_before:<8x}  {r.protect_before}"))
    elif removed_other:
        print(DIM(f"\n  [·] {len(removed_other)} non-executable regions only in {label_baseline} "
                  f"hidden. Use --verbose to show all."))

    if changed:
        print(YELLOW(f"\n  [~] Protection differs at the same base ({len(changed)}):"))
        for r in changed:
            flag = RED(" ◄ RWX in target!") if r.suspicious_after else ""
            print(YELLOW(f"      {r.base_address}  baseline {r.protect_before}, "
                         f"target {r.protect_after}{flag}"))
    else:
        print(DIM("\n  [~] No protection differences at shared bases."))


_FACT_LABELS = {
    "capture_time":           "capture time",
    "process_id":             "process ID",
    "process_create_time":    "process create time",
    "host_architecture":      "host architecture",
    "os_version":             "OS version",
    "image_machine":          "image machine",
    "peb_image_path":         "PEB image path",
    "module_image_path":      "module image path",
    "module_image_size":      "module image size",
    "module_image_timestamp": "module image timestamp",
}

# Why a capture holds no value for a fact, as the console words it.
_STATE_TEXT = {
    FACT_STATE_ABSENT:          "source absent",
    FACT_STATE_FAILED:          "source unreadable",
    FACT_STATE_UNSET:           "not set",
    FACT_STATE_UNRECONSTRUCTED: "PEB not reconstructed (SystemInfo or thread list unavailable)",
    FACT_STATE_BASE_UNKNOWN:    "PEB image base unknown",
    FACT_STATE_UNMATCHED:       "no module registered at the PEB image base",
    FACT_STATE_UNCAPTURED:      "nothing captured at the PEB image base",
    FACT_STATE_TRUNCATED:       "header capture ends before Machine",
    FACT_STATE_INVALID:         "not a valid PE header",
}

_CAPTURE_ORDER_TEXT = {
    CAPTURE_ORDER_BASELINE_FIRST: "baseline captured first",
    CAPTURE_ORDER_TARGET_FIRST:   "target captured first",
    CAPTURE_ORDER_SAME_SECOND:    "both captured in the same second",
    CAPTURE_ORDER_UNKNOWN:        "not established",
}


def _fact_side_text(fact: str, value, state: str) -> str:
    if state != FACT_STATE_RECORDED:
        return _STATE_TEXT[state]
    if fact in ("module_image_size", "module_image_timestamp"):
        return f"0x{value:x}"
    return console_safe(str(value))


def _fact_pair_text(f: dict) -> str:
    return (f"{_FACT_LABELS[f['fact']]}: "
            f"{_fact_side_text(f['fact'], f['baseline'], f['baseline_state'])} (baseline) / "
            f"{_fact_side_text(f['fact'], f['target'], f['target_state'])} (target)")


def _render_premise(premise: dict) -> None:
    """result.summary.premise as console text. Every fact appears exactly
    once -- under Same, Differs or Not established -- and an unestablished
    one says why for each capture, so the block discloses each premise
    the comparison rests on, known or not."""
    facts = premise["facts"]
    by_fact = {f["fact"]: f for f in facts}

    print(f"\n{BOLD('═══ COMPARISON PREMISE ═══')}")
    print(f"  {DIM('Scope')}: inventory relations between two captures — "
          f"not observed load, unload, rebase or protection events")

    instance = premise["process_instance"]
    if instance == PROCESS_INSTANCE_SAME:
        pid = by_fact["process_id"]["baseline"]
        created = console_safe(by_fact["process_create_time"]["baseline"])
        instance_text = (f"same PID and creation time (PID {pid}, created {created}); "
                         f"host identity not established")
    elif instance == PROCESS_INSTANCE_DIFFERENT:
        instance_text = YELLOW("different")
    else:
        instance_text = YELLOW("not established")
    print(f"  {DIM('Process instance')}: {instance_text}")
    print(f"  {DIM('Capture order')}: {_CAPTURE_ORDER_TEXT[premise['capture_order']]}")

    same = [_FACT_LABELS[f["fact"]] for f in facts if f["relation"] == FACT_RELATION_SAME]
    print(f"  {DIM('Same')}: {', '.join(same) if same else 'none'}")

    differs = [f for f in facts if f["relation"] == FACT_RELATION_DIFFERENT]
    if differs:
        print(f"  {DIM('Differs')}:")
        for f in differs:
            print(YELLOW(f"      {_fact_pair_text(f)}"))
    else:
        print(f"  {DIM('Differs')}: none")

    unknown = [f for f in facts if f["relation"] == FACT_RELATION_UNKNOWN]
    if unknown:
        print(f"  {DIM('Not established')}:")
        # Facts neither capture records for the same reason share a line.
        shared = {}
        for f in unknown:
            if f["baseline_state"] == f["target_state"]:
                shared.setdefault(f["baseline_state"], []).append(_FACT_LABELS[f["fact"]])
        for state, labels in shared.items():
            print(YELLOW(f"      {_STATE_TEXT[state]} in both captures: {', '.join(labels)}"))
        for f in unknown:
            if f["baseline_state"] != f["target_state"]:
                print(YELLOW(f"      {_fact_pair_text(f)}"))
    else:
        print(f"  {DIM('Not established')}: none")

    diagnostics = premise["capture_diagnostics"]
    if diagnostics:
        print(f"  {DIM('Within one capture')}:")
        for d in diagnostics:
            print(YELLOW(f"      {d['side']}: {console_safe(d['message'])} [{d['code']}]"))
    else:
        print(f"  {DIM('Within one capture')}: no identity disagreement")


def render_diff_console(result: CommandResult, label_baseline, label_target,
                         verbose: bool = False) -> None:
    """Console text for one comparison, driven by `result` alone: its
    records, coverage and summary.premise -- the very dict --json emits,
    so the console and the document cannot state different premises. A
    result without a premise is refused rather than rendered without one.
    Each entity section is gated on whether that entity was requested
    (present in coverage.sources), not on a separately-threaded mode
    string -- collect_module_diff/collect_thread_diff/collect_memory_diff
    always register their own sources when called, whether or not the
    diff itself could be computed."""
    premise = result.summary.get("premise")
    if premise is None:
        raise ValueError("render_diff_console() requires a comparison result carrying "
                         "summary['premise']")
    records, coverage = result.records, result.coverage
    print(f"\n{BOLD('dumpex diff')}: target {CYAN(label_target)} vs "
          f"baseline {CYAN(label_baseline)}")
    print("─" * 60)

    _render_premise(premise)
    if "baseline.modules" in coverage.sources:
        _render_module_diff(records, coverage, label_baseline, label_target)
    if "baseline.thread_info" in coverage.sources:
        _render_thread_diff(records, coverage, label_baseline, label_target)
    if "baseline.memory_info" in coverage.sources:
        _render_memory_diff(records, coverage, label_baseline, label_target, verbose=verbose)

    print()


def cmd_diff(mf_target, mf_baseline, mode: str = "all", verbose: bool = False) -> CommandResult:
    """Compare the primary CLI dump (target) against --diff's reference
    dump (baseline).

    Keeping that direction explicit matters for forensic use: in
    ``dumpex suspect.dmp --diff clean.dmp``, entries only in the target
    and suspicious protections must describe ``suspect.dmp``, not the
    clean reference.
    """
    result = collect_diff(mf_target, mf_baseline, mode)
    label_baseline = ntpath.basename(mf_baseline.filename)
    label_target = ntpath.basename(mf_target.filename)
    render_diff_console(result, label_baseline, label_target, verbose=verbose)
    return result

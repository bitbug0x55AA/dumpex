"""--diff command.

collect_diff()/render_diff_console()/cmd_diff() -- the same collect/
render/cmd trio every other recon command uses. The actual set-difference
logic (added/removed/rebased, added/removed, added/removed/
protection_changed) lives in dumpex.commands.comparison, ported there
from this file's own original diff_modules/diff_threads/diff_memory;
render_diff_console reconstructs the identical console text from the
resulting ComparisonRecords for every state the original console could
reach, with two deliberate exceptions documented at their call sites
(multiple anonymous modules colliding, and a thread's backing-module
context being "unavailable"/unknown-address) where the original console
had no correct behavior to reproduce -- comparison.py's own docstrings
explain why those states were fixed, not preserved.
"""
import ntpath

from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN
from dumpex.rules_pkg.loader import SUSPICIOUS_PROTS
from dumpex.output.command_result import CommandResult
from dumpex.output.records import MODULE_CONTEXT_RESOLVED
from dumpex.output.coverage import render_limitation
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


def collect_diff(mf_baseline, mf_target, mode: str = "all") -> CommandResult:
    """Thin wrapper over comparison.collect_comparison() -- kept as its
    own function here purely for naming-convention parity with the other
    six recon commands' collect_X()/render_X_console()/cmd_X() trio."""
    return collect_comparison(mf_baseline, mf_target, mode)


def _int_or(hex_str, default: int = 0) -> int:
    """Parses one of records.py's fixed-16-digit hex_address() strings
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


def _render_module_diff(records, coverage, label_baseline, label_target) -> None:
    module_records = [r for r in records if r.entity_type == "module"]
    # Header counts come from the SOURCE's own record_count, not a
    # recount of `records` (which only holds the diff, not a full
    # inventory) -- see this function's own note on the one narrow,
    # accepted divergence from the original console's counting: the
    # original silently deduplicates by lowercase basename before
    # counting (a pre-existing bug when two named modules share a
    # basename), this uses the true raw stream count instead.
    baseline_count = coverage.sources["baseline.modules"].record_count or 0
    target_count = coverage.sources["target.modules"].record_count or 0

    print(f"\n{BOLD('═══ MODULE DIFF ═══')}")
    _print_reasons(_reasons_for(
        coverage, lambda l: l.source in ("baseline.modules", "target.modules")
        and l.scope != "thread"))
    print(f"  {DIM(label_baseline)}: {baseline_count} modules")
    print(f"  {DIM(label_target)}: {target_count} modules\n")

    added = [r for r in module_records if r.change_type == "added"]
    if added:
        print(GREEN(f"  [+] Added in {label_target} ({len(added)}):"))
        for r in added:
            print(GREEN(f"      {r.base_address_after}  {r.full_path_after}"))
    else:
        print(DIM("  [+] No new modules."))

    removed = [r for r in module_records if r.change_type == "removed"]
    if removed:
        print(RED(f"\n  [-] Removed from {label_baseline} ({len(removed)}):"))
        for r in removed:
            print(RED(f"      {r.base_address_before}  {r.full_path_before}"))
    else:
        print(DIM("\n  [-] No removed modules."))

    rebased = [r for r in module_records if r.change_type == "rebased"]
    if rebased:
        print(YELLOW(f"\n  [~] Rebased ({len(rebased)}):"))
        for r in rebased:
            before = _int_or(r.base_address_before)
            after = _int_or(r.base_address_after)
            print(YELLOW(f"      {r.name}: 0x{before:x} → 0x{after:x}"))


def _render_thread_diff(records, coverage, label_baseline, label_target) -> None:
    thread_records = [r for r in records if r.entity_type == "thread"]
    baseline_count = coverage.sources["baseline.thread_info"].record_count or 0
    target_count = coverage.sources["target.thread_info"].record_count or 0

    print(f"\n{BOLD('═══ THREAD DIFF ═══')}")
    _print_reasons(_reasons_for(
        coverage, lambda l: l.source in ("baseline.thread_info", "target.thread_info")
        or (l.source == "target.modules" and l.scope == "thread")))
    print(f"  {DIM(label_baseline)}: {baseline_count} threads")
    print(f"  {DIM(label_target)}: {target_count} threads\n")

    added = [r for r in thread_records if r.change_type == "added"]
    if added:
        print(GREEN(f"  [+] New threads in {label_target} ({len(added)}):"))
        for r in added:
            sa = _int_or(r.start_address_after)
            if r.backing_module_context == MODULE_CONTEXT_RESOLVED:
                backed = r.backing_module_after
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
        print(DIM("  [+] No new threads."))

    removed = [r for r in thread_records if r.change_type == "removed"]
    if removed:
        print(RED(f"\n  [-] Threads gone from {label_target} ({len(removed)}):"))
        for r in removed:
            sa = _int_or(r.start_address_before)
            print(RED(f"      TID=0x{r.tid:x}  StartAddr=0x{sa:x}"))
    else:
        print(DIM("\n  [-] No removed threads."))


def _render_memory_diff(records, coverage, label_baseline, label_target, verbose=False) -> None:
    memory_records = [r for r in records if r.entity_type == "memory_region"]
    baseline_count = coverage.sources["baseline.memory_info"].record_count or 0
    target_count = coverage.sources["target.memory_info"].record_count or 0

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
    print(f"  {DIM(label_baseline)}: {baseline_count} regions")
    print(f"  {DIM(label_target)}: {target_count} regions")
    print(f"  {DIM('Delta')}: +{len(added)} / -{len(removed)} regions\n")

    if added_rwx:
        print(RED(f"  [!] RWX regions in {label_target} ({len(added_rwx)}) — HIGH SUSPICION:"))
        for r in added_rwx:
            print(RED(f"      {region_label_after(r)}"))
    else:
        print(DIM("  [!] No RWX regions added."))

    if added_exec:
        print(YELLOW(f"\n  [+] New executable regions in {label_target} ({len(added_exec)}):"))
        for r in added_exec:
            print(YELLOW(f"      {region_label_after(r)}"))

    if added_notable and verbose:
        print(f"\n  [+] Other notable new regions ({len(added_notable)}):")
        for r in added_notable:
            print(f"      {region_label_after(r)}")

    if added_noise:
        if verbose:
            print(f"\n  [+] Routine new regions ({len(added_noise)}) — likely from new DLLs:")
            for r in added_noise:
                print(DIM(f"      {r.base_address}  size=0x{r.size_after:<8x}  {r.protect_after}"))
        else:
            print(DIM(f"\n  [·] {len(added_noise)} routine regions hidden "
                      f"(PAGE_READONLY/NOACCESS from new DLLs)."))
            print(DIM("      Use --verbose to show all."))

    if removed_exec:
        print(RED(f"\n  [-] Executable regions gone from {label_target} ({len(removed_exec)}):"))
        for r in removed_exec:
            print(RED(f"      {region_label_before(r)}"))

    if removed_other and verbose:
        print(f"\n  [-] Other removed regions ({len(removed_other)}):")
        for r in removed_other:
            print(DIM(f"      {r.base_address}  size=0x{r.size_before:<8x}  {r.protect_before}"))
    elif removed_other:
        print(DIM(f"\n  [·] {len(removed_other)} removed non-exec regions hidden. "
                  f"Use --verbose to show all."))

    if changed:
        print(YELLOW(f"\n  [~] Protection changed ({len(changed)}):"))
        for r in changed:
            flag = RED(" ← now RWX!") if r.suspicious_after else ""
            print(YELLOW(f"      {r.base_address}  {r.protect_before} → {r.protect_after}{flag}"))
    else:
        print(DIM("\n  [~] No protection changes."))


def render_diff_console(records, coverage, label_baseline, label_target, verbose: bool = False) -> None:
    """Reproduces the original diff_modules/diff_threads/diff_memory
    console output, driven by ComparisonRecords/CoverageReport instead of
    raw MinidumpFile objects. Each section is gated on whether that
    entity was actually requested (present in coverage.sources), not on
    a separately-threaded mode string -- collect_module_diff/
    collect_thread_diff/collect_memory_diff always register their own
    sources when called, whether or not the diff itself could be
    computed."""
    print(f"\n{BOLD('dumpex diff')}: {CYAN(label_baseline)} vs {CYAN(label_target)}")
    print("─" * 60)

    if "baseline.modules" in coverage.sources:
        _render_module_diff(records, coverage, label_baseline, label_target)
    if "baseline.thread_info" in coverage.sources:
        _render_thread_diff(records, coverage, label_baseline, label_target)
    if "baseline.memory_info" in coverage.sources:
        _render_memory_diff(records, coverage, label_baseline, label_target, verbose=verbose)

    print()


def cmd_diff(mf_baseline, mf_target, mode: str = "all", verbose: bool = False) -> CommandResult:
    result = collect_diff(mf_baseline, mf_target, mode)
    label_baseline = ntpath.basename(mf_baseline.filename)
    label_target = ntpath.basename(mf_target.filename)
    render_diff_console(result.records, result.coverage, label_baseline, label_target,
                         verbose=verbose)
    return result

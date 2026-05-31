"""--diff command."""
import os
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, addr_to_module, prot_str,
    open_dump, module_name_only)
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN
from dumpex.rules_pkg.loader import SUSPICIOUS_PROTS

def diff_modules(mf_a, mf_b, label_a, label_b):
    mods_a = {module_name_only(m.name): m for m in get_modules(mf_a)}
    mods_b = {module_name_only(m.name): m for m in get_modules(mf_b)}

    added   = set(mods_b) - set(mods_a)
    removed = set(mods_a) - set(mods_b)
    both    = set(mods_a) & set(mods_b)

    print(f"\n{BOLD('═══ MODULE DIFF ═══')}")
    print(f"  {DIM(label_a)}: {len(mods_a)} modules")
    print(f"  {DIM(label_b)}: {len(mods_b)} modules\n")

    if added:
        print(GREEN(f"  [+] Added in {label_b} ({len(added)}):"))
        for name in sorted(added):
            m = mods_b[name]
            print(GREEN(f"      0x{m.baseaddress:016x}  {m.name}"))
    else:
        print(DIM("  [+] No new modules."))

    if removed:
        print(RED(f"\n  [-] Removed from {label_a} ({len(removed)}):"))
        for name in sorted(removed):
            m = mods_a[name]
            print(RED(f"      0x{m.baseaddress:016x}  {m.name}"))
    else:
        print(DIM("\n  [-] No removed modules."))

    # Rebased modules (same name, different base)
    rebased = [(n, mods_a[n], mods_b[n]) for n in both
               if mods_a[n].baseaddress != mods_b[n].baseaddress]
    if rebased:
        print(YELLOW(f"\n  [~] Rebased ({len(rebased)}):"))
        for name, ma, mb in sorted(rebased):
            print(YELLOW(f"      {name}: 0x{ma.baseaddress:x} → 0x{mb.baseaddress:x}"))


def diff_threads(mf_a, mf_b, label_a, label_b):
    def tid_map(mf):
        return {ti.ThreadId: ti for ti in get_thread_infos(mf)}

    ta = tid_map(mf_a)
    tb = tid_map(mf_b)
    modules_b = get_modules(mf_b)

    added   = set(tb) - set(ta)
    removed = set(ta) - set(tb)

    print(f"\n{BOLD('═══ THREAD DIFF ═══')}")
    print(f"  {DIM(label_a)}: {len(ta)} threads")
    print(f"  {DIM(label_b)}: {len(tb)} threads\n")

    if added:
        print(GREEN(f"  [+] New threads in {label_b} ({len(added)}):"))
        for tid in sorted(added):
            ti = tb[tid]
            sa = ti.StartAddress or 0
            mod = addr_to_module(sa, modules_b)
            backed = os.path.basename(mod.name) if mod else RED("NOT IN ANY MODULE ⚠")
            print(GREEN(f"      TID=0x{tid:x}  StartAddr=0x{sa:x}  Backed by: {backed}"))
    else:
        print(DIM("  [+] No new threads."))

    if removed:
        print(RED(f"\n  [-] Threads gone from {label_b} ({len(removed)}):"))
        for tid in sorted(removed):
            ti = ta[tid]
            print(RED(f"      TID=0x{tid:x}  StartAddr=0x{ti.StartAddress or 0:x}"))
    else:
        print(DIM("\n  [-] No removed threads."))


def diff_memory(mf_a, mf_b, label_a, label_b, verbose=False):
    # Protection flags worth reporting
    NOTABLE_PROTS = {
        "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",  # RWX — always report
        "PAGE_EXECUTE_READ", "PAGE_EXECUTE",                  # executable — report
        "PAGE_READWRITE",                                     # writable — report if private
    }
    EXEC_PROTS = {"PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",
                  "PAGE_EXECUTE_READ", "PAGE_EXECUTE"}

    def region_map(mf):
        return {r.BaseAddress: r for r in get_memory_regions(mf)}

    def is_notable(r):
        p = prot_str(r.Protect)
        return any(n in p for n in NOTABLE_PROTS)

    def region_label(r):
        p = prot_str(r.Protect)
        t = prot_str(r.Type)
        rwx  = RED(" ◄ RWX!")        if any(s in p for s in SUSPICIOUS_PROTS) else ""
        priv = YELLOW(" [PRIVATE]")  if "MEM_PRIVATE" in t else ""
        exec_ = YELLOW(" [EXEC]")    if any(e in p for e in EXEC_PROTS) and not rwx else ""
        return f"0x{r.BaseAddress:016x}  size=0x{r.RegionSize:<8x}  {p:<32}{rwx}{priv}{exec_}"

    ra = region_map(mf_a)
    rb = region_map(mf_b)

    added   = set(rb) - set(ra)
    removed = set(ra) - set(rb)
    changed = {addr for addr in set(ra) & set(rb)
               if prot_str(ra[addr].Protect) != prot_str(rb[addr].Protect)}

    # Categorize added regions
    added_rwx      = [a for a in added if any(s in prot_str(rb[a].Protect) for s in SUSPICIOUS_PROTS)]
    added_exec     = [a for a in added if any(e in prot_str(rb[a].Protect) for e in EXEC_PROTS)
                      and a not in added_rwx]
    added_notable  = [a for a in added if is_notable(rb[a])
                      and a not in added_rwx and a not in added_exec]
    added_noise    = [a for a in added if a not in added_rwx
                      and a not in added_exec and a not in added_notable]

    # Removed: only show executable ones (likely code that disappeared)
    removed_exec   = [r for r in removed if any(e in prot_str(ra[r].Protect) for e in EXEC_PROTS)]
    removed_other  = [r for r in removed if r not in removed_exec]

    print(f"\n{BOLD('═══ MEMORY REGION DIFF ═══')}")
    print(f"  {DIM(label_a)}: {len(ra)} regions")
    print(f"  {DIM(label_b)}: {len(rb)} regions")
    print(f"  {DIM('Delta')}: +{len(added)} / -{len(removed)} regions\n")

    # ── Added: RWX (always show) ──
    if added_rwx:
        print(RED(f"  [!] RWX regions in {label_b} ({len(added_rwx)}) — HIGH SUSPICION:"))
        for addr in sorted(added_rwx):
            print(RED(f"      {region_label(rb[addr])}"))
    else:
        print(DIM("  [!] No RWX regions added."))

    # ── Added: other executable ──
    if added_exec:
        print(YELLOW(f"\n  [+] New executable regions in {label_b} ({len(added_exec)}):"))
        for addr in sorted(added_exec):
            print(YELLOW(f"      {region_label(rb[addr])}"))

    # ── Added: notable (writable etc) ──
    if added_notable and verbose:
        print(f"\n  [+] Other notable new regions ({len(added_notable)}):") 
        for addr in sorted(added_notable):
            print(f"      {region_label(rb[addr])}")

    # ── Noise summary (not shown unless --verbose) ──
    if added_noise:
        if verbose:
            print(f"\n  [+] Routine new regions ({len(added_noise)}) — likely from new DLLs:")
            for addr in sorted(added_noise):
                r = rb[addr]
                print(DIM(f"      0x{addr:016x}  size=0x{r.RegionSize:<8x}  {prot_str(r.Protect)}"))
        else:
            print(DIM(f"\n  [·] {len(added_noise)} routine regions hidden (PAGE_READONLY/NOACCESS from new DLLs)."))
            print(DIM( "      Use --verbose to show all."))

    # ── Removed: executable (most interesting) ──
    if removed_exec:
        print(RED(f"\n  [-] Executable regions gone from {label_b} ({len(removed_exec)}):"))
        for addr in sorted(removed_exec):
            print(RED(f"      {region_label(ra[addr])}"))

    if removed_other and verbose:
        print(f"\n  [-] Other removed regions ({len(removed_other)}):")
        for addr in sorted(removed_other):
            r = ra[addr]
            print(DIM(f"      0x{addr:016x}  size=0x{r.RegionSize:<8x}  {prot_str(r.Protect)}"))
    elif removed_other:
        print(DIM(f"\n  [·] {len(removed_other)} removed non-exec regions hidden. Use --verbose to show all."))

    # ── Protection changes ──
    if changed:
        print(YELLOW(f"\n  [~] Protection changed ({len(changed)}):"))
        for addr in sorted(changed):
            old_p = prot_str(ra[addr].Protect)
            new_p = prot_str(rb[addr].Protect)
            flag  = RED(" ← now RWX!") if any(s in new_p for s in SUSPICIOUS_PROTS) else ""
            print(YELLOW(f"      0x{addr:016x}  {old_p} → {new_p}{flag}"))
    else:
        print(DIM("\n  [~] No protection changes."))


def cmd_diff(mf_a, path_b, mode, verbose=False):
    mf_b   = open_dump(path_b)
    label_a = os.path.basename(mf_a.filename)
    label_b = os.path.basename(path_b)

    print(f"\n{BOLD('dumpex diff')}: {CYAN(label_a)} vs {CYAN(label_b)}")
    print("─" * 60)

    if mode in ("modules", "all"):
        diff_modules(mf_a, mf_b, label_a, label_b)
    if mode in ("threads", "all"):
        diff_threads(mf_a, mf_b, label_a, label_b)
    if mode in ("memory", "all"):
        diff_memory(mf_a, mf_b, label_a, label_b, verbose=verbose)

    print()


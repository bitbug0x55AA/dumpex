"""Process injection hunter (RWX / hidden PE / unbacked threads)."""
import os
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.rules_pkg.loader import SUSPICIOUS_PROTS
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, addr_to_module, va_to_file_offset, prot_str,
    read_region, SYSTEM_RANGE)
from dumpex.hunt._ui import _print_hunt_header, _print_check

def _hunt_rwx(mf: MinidumpFile) -> list:
    """Return list of RWX regions. Internal — used by --hunt injection."""
    regions = get_memory_regions(mf)
    hits = []
    for r in regions:
        p = prot_str(r.Protect)
        if any(s in p for s in SUSPICIOUS_PROTS):
            hits.append(r)
    return hits


def _hunt_hidden_pe(mf: MinidumpFile) -> list:
    """Return list of (region, in_module_list) for MZ headers. Internal."""
    modules    = get_modules(mf)
    known_bases = {m.baseaddress for m in modules}
    hits = []
    for r in get_memory_regions(mf):
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        try:
            data = read_region(mf, r.BaseAddress, min(2, r.RegionSize))
        except Exception:
            continue
        if data[:2] == b'MZ':
            hits.append((r, r.BaseAddress in known_bases))
    return hits


def _hunt_unbacked_threads(mf: MinidumpFile) -> list:
    """Return list of ThreadInfo with no module backing. Internal."""
    modules = get_modules(mf)
    infos   = get_thread_infos(mf)
    return [ti for ti in infos
            if not addr_to_module(ti.StartAddress or 0, modules)]


def _hunt_injection(mf: MinidumpFile, verbose: bool = False) -> dict:
    """\n    Detect classic process injection via cross-correlation of three signals.\n    Each signal alone can be noise; overlap between them raises confidence.\n    Returns dict of findings for use in --hunt all summary.\n    """
    modules = get_modules(mf)
    rwx     = _hunt_rwx(mf)
    pe_hits = _hunt_hidden_pe(mf)
    threads = _hunt_unbacked_threads(mf)

    injected_pe_regions = {r.BaseAddress for r, known in pe_hits if not known}
    rwx_bases           = {r.BaseAddress for r in rwx}

    # Cross-correlate: regions that are BOTH RWX and contain a hidden PE
    rwx_and_pe = rwx_bases & injected_pe_regions

    # Threads whose start addr falls inside a RWX region
    def in_rwx(addr):
        for r in rwx:
            if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
                return r
        return None

    threads_in_rwx = [(ti, in_rwx(ti.StartAddress or 0)) for ti in threads
                      if in_rwx(ti.StartAddress or 0)]

    # Score (independent signals)
    score = 0
    if rwx:            score += 1
    if injected_pe_regions: score += 1
    if threads:        score += 1

    findings = {
        "rwx":        rwx,
        "hidden_pe":  [(r, k) for r, k in pe_hits if not k],
        "threads":    threads,
        "rwx_and_pe": rwx_and_pe,
        "threads_in_rwx": threads_in_rwx,
        "score":      score,
    }

    # ── Output ────────────────────────────────────────────────────────
    _print_hunt_header("Process Injection")

    # Check 1: RWX memory
    if rwx:
        detail = f"{len(rwx)} region(s)"
        if verbose:
            for r in rwx:
                p = prot_str(r.Protect)
                t = prot_str(r.Type)
                fo = va_to_file_offset(mf, r.BaseAddress)
                fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
                detail += (f"\n          VA (process)      0x{r.BaseAddress:016x}"
                           f"  size=0x{r.RegionSize:x}"
                           f"\n          File offset       {fo_str}"
                           f"\n          Region base (VA)  0x{r.BaseAddress:016x}"
                           f"\n          {p}  {t}")
        _print_check("RWX memory regions", RED("SUSPICIOUS"), detail)
    else:
        _print_check("RWX memory regions", GREEN("CLEAN — none found"))

    # Check 2: Hidden PE headers
    hidden = [(r, k) for r, k in pe_hits if not k]
    if hidden:
        detail = f"{len(hidden)} unregistered PE(s)"
        if verbose:
            for r, _ in hidden:
                p = prot_str(r.Protect)
                fo = va_to_file_offset(mf, r.BaseAddress)
                fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
                detail += (f"\n          VA (process)      0x{r.BaseAddress:016x}"
                           f"\n          File offset       {fo_str}"
                           f"\n          Region base (VA)  0x{r.BaseAddress:016x}"
                           f"\n          {p}")
        _print_check("Hidden PE headers (MZ not in module list)", RED("SUSPICIOUS"), detail)
    else:
        _print_check("Hidden PE headers", GREEN("CLEAN — all MZ headers in module list"))

    # Check 3: Unbacked threads
    if threads:
        detail = f"{len(threads)} thread(s) with no module backing"
        if verbose:
            for ti in threads:
                sa = ti.StartAddress or 0
                fo = va_to_file_offset(mf, sa)
                fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
                detail += (f"\n          TID=0x{ti.ThreadId:x}"
                           f"\n          VA (process)   0x{sa:016x}"
                           f"\n          File offset    {fo_str}"
                           f"\n          Region base (VA) — see StartAddr above")
        _print_check("Unbacked threads", RED("SUSPICIOUS"), detail)
    else:
        _print_check("Unbacked threads", GREEN("CLEAN — all threads backed by known modules"))

    # Check 4: Correlation bonus
    if rwx_and_pe:
        addrs = ", ".join(f"0x{a:x}" for a in rwx_and_pe)
        _print_check("RWX + hidden PE overlap", RED("SUSPICIOUS — high confidence injection"),
                     f"Regions with both signals: {addrs}")
    if threads_in_rwx:
        for ti, r in threads_in_rwx:
            _print_check("Thread executing inside RWX region",
                         RED("SUSPICIOUS — active shellcode execution"),
                         f"TID=0x{ti.ThreadId:x} in region 0x{r.BaseAddress:x}")

    # Verdict
    verdict = (RED("HIGH CONFIDENCE INJECTION") if score >= 3 else
               YELLOW("LIKELY INJECTION") if score == 2 else
               YELLOW("POSSIBLE INJECTION") if score == 1 else
               GREEN("CLEAN"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/3 independent signals)\n")

    if not verbose and (rwx or hidden or threads):
        print(DIM("  Use --verbose to list individual addresses.\n"))

    return findings


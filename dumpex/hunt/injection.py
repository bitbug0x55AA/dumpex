"""Process injection hunter (RWX / hidden PE / unbacked threads)."""
import os
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, addr_to_module, va_to_file_offset, prot_str,
    read_region, SYSTEM_RANGE)
from dumpex.hunt._ui import (_print_hunt_header, _print_check, _status_text,
    _scan_status, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED)

def _hunt_rwx(mf: MinidumpFile) -> list:
    """Return list of RWX regions. Internal — used by --hunt injection."""
    susp_prots = get_rules()["suspicious_protections"]
    regions = get_memory_regions(mf)
    hits = []
    for r in regions:
        p = prot_str(r.Protect)
        if any(s in p for s in susp_prots):
            hits.append(r)
    return hits


def _hunt_hidden_pe(mf: MinidumpFile, module_list_available: bool = True) -> list:
    """
    Return list of (region, in_module_list) for MZ headers. Internal.

    If ModuleListStream isn't present, module_list_available is False and
    this returns [] rather than flagging every MZ header as "hidden": an
    empty modules list doesn't mean "nothing here is a known module" — it
    means we have no way to tell. Producing a hit for every legitimate
    loaded PE header would be pure false-positive noise, not a finding.
    """
    if not module_list_available:
        return []
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


def _hunt_unbacked_threads(mf: MinidumpFile, module_list_available: bool = True) -> list:
    """
    Return list of ThreadInfo with no module backing. Internal.

    Same reasoning as _hunt_hidden_pe: without ModuleListStream, every
    thread would look "unbacked" regardless of whether it actually is —
    that's an absence-of-data artifact, not evidence of injection.
    """
    if not module_list_available:
        return []
    modules = get_modules(mf)
    infos   = get_thread_infos(mf)
    return [ti for ti in infos
            if not addr_to_module(ti.StartAddress or 0, modules)]


def _hunt_injection(mf: MinidumpFile, verbose: bool = False) -> dict:
    """\n    Detect classic process injection via cross-correlation of three signals.\n    Each signal alone can be noise; overlap between them raises confidence.\n    Returns dict of findings for use in --hunt all summary.\n    """
    # RWX/hidden-PE need MemoryInfoListStream; unbacked-thread needs
    # ThreadInfoListStream; hidden-PE and unbacked-thread BOTH additionally
    # need ModuleListStream to tell known from unknown — computed first so
    # _hunt_hidden_pe/_hunt_unbacked_threads can refuse to guess when it's
    # missing, rather than treating every PE/thread as suspicious by default.
    coverage = {
        "memory_info_stream": bool(mf.memory_info and mf.memory_info.infos),
        "thread_info_stream": bool(mf.thread_info and mf.thread_info.infos),
        "module_list_stream": bool(mf.modules and mf.modules.modules),
    }

    modules = get_modules(mf)
    rwx     = _hunt_rwx(mf)
    pe_hits = _hunt_hidden_pe(mf, module_list_available=coverage["module_list_stream"])
    threads = _hunt_unbacked_threads(mf, module_list_available=coverage["module_list_stream"])

    evaluated = coverage["memory_info_stream"] or coverage["thread_info_stream"]
    complete  = (coverage["memory_info_stream"] and coverage["thread_info_stream"]
                 and coverage["module_list_stream"])

    hidden_pe_regions   = [r for r, known in pe_hits if not known]
    injected_pe_regions = {r.BaseAddress for r in hidden_pe_regions}
    rwx_bases           = {r.BaseAddress for r in rwx}

    def in_region(addr, region_list):
        for r in region_list:
            if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
                return r
        return None

    # Cross-correlate: regions that are BOTH RWX and contain a hidden PE
    # (same memory region carrying two signals — not "one RWX region here,
    # one unrelated MZ somewhere else").
    rwx_and_pe = rwx_bases & injected_pe_regions

    # Threads whose start addr falls inside a RWX region / a hidden-PE region
    # (execution correlation — the thread is actually running inside the
    # flagged region, not just coincidentally unbacked elsewhere).
    threads_in_rwx       = [(ti, r) for ti in threads
                             if (r := in_region(ti.StartAddress or 0, rwx))]
    threads_in_hidden_pe = [(ti, r) for ti in threads
                             if (r := in_region(ti.StartAddress or 0, hidden_pe_regions))]

    # Strongest possible evidence: a thread executing inside a region that
    # is simultaneously RWX *and* hosts a hidden PE — all three signals
    # converge on the same memory region.
    full_correlation = [(ti, r) for ti, r in threads_in_rwx
                         if r.BaseAddress in rwx_and_pe]

    region_correlated = bool(rwx_and_pe) or bool(threads_in_rwx) or bool(threads_in_hidden_pe)

    # Score requires correlation, not just co-occurrence: three unrelated
    # signals scattered across memory with no shared region and no thread
    # executing inside any of them stay at "possible", not "high confidence".
    if not (rwx or injected_pe_regions or threads):
        score = 0
    elif full_correlation:
        score = 3
    elif region_correlated:
        score = 2
    else:
        score = 1

    status = _scan_status(evaluated=evaluated, detected=score > 0, complete=complete)

    findings = {
        "rwx":            rwx,
        "hidden_pe":      [(r, k) for r, k in pe_hits if not k],
        "threads":        threads,
        "rwx_and_pe":     rwx_and_pe,
        "threads_in_rwx": threads_in_rwx,
        "threads_in_hidden_pe": threads_in_hidden_pe,
        "full_correlation": full_correlation,
        "score":          score,
        "status":         status,
        "coverage":       coverage,
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

    # Check 4: Correlation (this is what actually drives the score — see below)
    if rwx_and_pe:
        addrs = ", ".join(f"0x{a:x}" for a in rwx_and_pe)
        _print_check("RWX + hidden PE, same region", RED("SUSPICIOUS — region-level correlation"),
                     f"Regions with both signals: {addrs}")
    for ti, r in threads_in_rwx:
        _print_check("Thread executing inside RWX region",
                     RED("SUSPICIOUS — execution correlation"),
                     f"TID=0x{ti.ThreadId:x} in region 0x{r.BaseAddress:x}")
    for ti, r in threads_in_hidden_pe:
        _print_check("Thread executing inside hidden PE region",
                     RED("SUSPICIOUS — execution correlation"),
                     f"TID=0x{ti.ThreadId:x} in region 0x{r.BaseAddress:x}")
    if full_correlation:
        for ti, r in full_correlation:
            _print_check("Thread executing inside RWX+hidden-PE region",
                         RED("HIGH CONFIDENCE — all signals converge on one region"),
                         f"TID=0x{ti.ThreadId:x} in region 0x{r.BaseAddress:x}")

    if not coverage["memory_info_stream"]:
        print(YELLOW("  [~] MemoryInfoListStream not in this dump — RWX / hidden-PE checks could not run.\n"))
    if not coverage["thread_info_stream"]:
        print(YELLOW("  [~] ThreadInfoListStream not in this dump — unbacked-thread check could not run.\n"))
    if not coverage["module_list_stream"] and (coverage["memory_info_stream"] or coverage["thread_info_stream"]):
        print(YELLOW("  [~] ModuleListStream not in this dump — hidden-PE and unbacked-thread checks "
                      "were skipped rather than guessed (an empty module list would otherwise make "
                      "every PE look hidden and every thread look unbacked).\n"))

    # Verdict — driven by correlation, not by how many independent checks
    # happened to fire somewhere in the address space. Signals that never
    # share a region and are never executed by an unbacked thread stay at
    # "possible", even if all three checks tripped individually.
    if status == NOT_EVALUATED:
        print(f"  {BOLD('[ VERDICT ]')}  {_status_text(status, 'no required stream present in this dump')}\n")
        return findings

    verdict = (RED("HIGH CONFIDENCE INJECTION") if score >= 3 else
               YELLOW("LIKELY INJECTION") if score == 2 else
               YELLOW("POSSIBLE INJECTION") if score == 1 else
               GREEN("CLEAN") if status == NOT_DETECTED_IN_SCANNED_SCOPE else
               YELLOW("INCONCLUSIVE — partial stream coverage"))
    basis = ("no correlated signals" if score == 0 else
              "uncorrelated signals only — no shared region, no execution overlap" if score == 1 else
              "same-region or execution correlation found" if score == 2 else
              "thread executing in a region where RWX + hidden PE overlap")
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  (score {score}/3 — {basis})\n")

    if not verbose and (rwx or hidden or threads):
        print(DIM("  Use --verbose to list individual addresses.\n"))

    return findings


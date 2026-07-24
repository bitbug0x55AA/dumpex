"""Module stomping hunter."""
import os
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (get_modules, get_memory_regions,
    addr_to_module, va_to_file_offset, prot_str,
    read_region, _extract_ioc_strings)
from dumpex.hunt._ui import (_print_hunt_header, _print_check, _status_text,
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE)

def _hunt_stomping(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Detect Module Stomping: malicious code written into a legitimate
    loaded DLL's memory, which retains its MEM_IMAGE type and stays
    in the module list — invisible to thread/RWX checks.

    Fingerprints:
      1. MEM_IMAGE region with RWX protection (write needed to stomp)
      2. Executable MEM_IMAGE region containing IOC strings
         — whitelisted network DLLs (wininet, winhttp etc.) are excluded
           to suppress systematic false positives
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    mem_info_available = bool(mf.memory_info and mf.memory_info.infos)

    findings = {"rwx_image": [], "ioc_image": [], "score": 0}
    _r               = get_rules()
    STOMPING_WHITELIST  = _r["stomping_whitelist"]
    STOMPING_IOC        = _r["stomping_ioc_patterns"]
    STOMPING_NET_IOC    = _r["stomping_net_ioc_patterns"]
    SUSPICIOUS_PROTS    = _r["suspicious_protections"]

    _print_hunt_header("Module Stomping")

    # ── Check 1: MEM_IMAGE regions with RWX ───────────────────────────
    rwx_image = []
    for r in regions:
        p     = prot_str(r.Protect)
        mtype = prot_str(r.Type)
        if "MEM_IMAGE" in mtype and any(s in p for s in SUSPICIOUS_PROTS):
            mod = addr_to_module(r.BaseAddress, modules)
            rwx_image.append((r, mod))

    if rwx_image:
        detail = f"{len(rwx_image)} MEM_IMAGE region(s) with RWX"
        if verbose:
            for r, mod in rwx_image:
                name = os.path.basename(mod.name) if mod else "(unknown module)"
                detail += f"\n          0x{r.BaseAddress:x}  {name}  {prot_str(r.Protect)}"
        _print_check("MEM_IMAGE regions with RWX protection",
                     RED("SUSPICIOUS — write access to mapped module memory"),
                     detail)
        findings["rwx_image"] = rwx_image
        findings["score"] += 1
    else:
        _print_check("MEM_IMAGE regions with RWX protection",
                     GREEN("CLEAN — no mapped module regions are writable+executable"))

    # ── Check 2: IOC strings in executable MEM_IMAGE regions ─────────
    print(f"  {DIM('[*] Scanning executable MEM_IMAGE regions for IOC strings...')}\n")
    ioc_hits    = []
    skipped_wl  = []
    weak_only_skipped = []   # regions whose hits were entirely common API names

    # Some rules.yaml IOC patterns are legitimate, commonly-imported WinAPI
    # names (VirtualAlloc, WriteProcessMemory, CreateRemoteThread, WSASocket)
    # or a generic term (base64) — any non-trivial DLL that happens to call
    # one of these has it in its import table or string table for entirely
    # benign reasons. Multiple of these together are still not independent
    # corroborating evidence: VirtualAlloc + WriteProcessMemory routinely
    # co-occur in the import tables of many ordinary, unmodified programs
    # (debuggers, AV, admin tools) — the two aren't uncorrelated events the
    # way two genuinely distinct suspicious terms would be, so counting
    # "2+ distinct weak terms" as sufficient just moves the false-positive
    # bar rather than raising it. Only a match outside this weak set counts.
    _WEAK_IOC_TERMS = {"virtualalloc", "writeprocessmemory",
                       "createremotethread", "wsasocket", "base64"}

    def _classify_ioc_hits(strings, patterns) -> list:
        """
        Classify each individual regex match (token) as weak or strong —
        NOT the whole printable string it was found in. A single extracted
        string containing both a weak, ubiquitous API name (VirtualAlloc)
        and a genuinely strong IOC (powershell) previously got judged as a
        single unit: any weak term anywhere in the string made the whole
        string "weak-only" and dropped the co-located strong token along
        with it (e.g. "...VirtualAlloc...powershell..." lost "powershell"
        entirely). Matching per-token keeps that strong hit regardless of
        what else shares the same string.
        Returns list of (offset, enc, token, is_weak).
        """
        hits = []
        for off, enc, s in strings:
            for pat in patterns:
                for m in pat.finditer(s):
                    token = m.group(0)
                    hits.append((off + m.start(), enc, token,
                                 token.casefold() in _WEAK_IOC_TERMS))
        return hits

    ioc_skipped_size = 0
    ioc_read_failed  = 0

    for r in regions:
        mtype = prot_str(r.Type)
        p     = prot_str(r.Protect)
        state = prot_str(r.State)
        if "MEM_IMAGE" not in mtype or state != "MEM_COMMIT":
            continue
        if "EXECUTE" not in p:
            continue
        if r.RegionSize > 0x500000:
            ioc_skipped_size += 1
            continue

        mod      = addr_to_module(r.BaseAddress, modules)
        mod_name = os.path.basename(mod.name).lower() if mod else ""
        is_wl    = mod_name in STOMPING_WHITELIST

        try:
            data    = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            ioc_read_failed += 1
            continue

        strings = _extract_ioc_strings(data, r.BaseAddress)

        # Apply appropriate pattern based on whitelist status
        patterns = ([STOMPING_IOC] if is_wl else   # whitelisted: only the
                                                     # truly unusual IOCs,
                                                     # not network strings
                    [STOMPING_IOC, STOMPING_NET_IOC])
        hits = _classify_ioc_hits(strings, patterns)

        if not hits:
            if is_wl:
                skipped_wl.append(mod_name)
            continue
        strong_hits = [h for h in hits if not h[3]]
        if not strong_hits:
            weak_only_skipped.append((r, mod, hits))
            continue
        ioc_hits.append((r, mod, hits, not is_wl))

    if skipped_wl:
        unique_wl = sorted(set(skipped_wl))
        print(f"  {DIM(f'[·] Whitelisted network DLLs skipped (network strings expected): {chr(44).join(unique_wl)}')}")
        print()

    if weak_only_skipped:
        print(DIM(f"  [·] {len(weak_only_skipped)} region(s) matched only a single common "
                  f"API name (e.g. VirtualAlloc/WriteProcessMemory/CreateRemoteThread/"
                  f"WSASocket) — not scored on its own, since any DLL calling that API "
                  f"has it in its import table legitimately:"))
        if verbose:
            for r, mod, hits in weak_only_skipped:
                name = os.path.basename(mod.name) if mod else "(unknown)"
                terms = sorted({tok for _, _, tok, _ in hits})
                print(f"      0x{r.BaseAddress:x}  [{name}]  {', '.join(terms)}")
        print()

    if ioc_hits:
        n_strong = sum(sum(1 for h in hits if not h[3]) for _, _, hits, _ in ioc_hits)
        n_weak   = sum(sum(1 for h in hits if h[3]) for _, _, hits, _ in ioc_hits)
        detail = (f"{n_strong} strong + {n_weak} weak IOC token(s) "
                  f"across {len(ioc_hits)} module region(s)")
        _print_check("IOC strings in module code regions",
                     RED("SUSPICIOUS — malicious strings inside legitimate module memory"),
                     detail)
        if verbose:
            for r, mod, hits, _ in ioc_hits:
                name = os.path.basename(mod.name) if mod else "(unknown)"
                print(f"    {YELLOW(f'Region 0x{r.BaseAddress:x}  [{name}]')}")
                # Strong hits are the confirmed signal; weak ones are shown
                # too (an investigator should still see them) but tagged so
                # they aren't mistaken for independent corroborating evidence.
                for off, enc, tok, is_weak in hits[:10]:
                    tag = DIM(" (weak/common API — not scored alone)") if is_weak else ""
                    print(f"      0x{r.BaseAddress+off:x}  [{enc}]  {tok}{tag}")
                if len(hits) > 10:
                    print(DIM(f"      ... and {len(hits)-10} more"))
                print()
        findings["ioc_image"] = ioc_hits
        findings["score"] += 1
    else:
        _print_check("IOC strings in module code regions",
                     GREEN("CLEAN — no IOC patterns in executable module memory"))

    # Check 1 (RWX MEM_IMAGE) and Check 2 (IOC strings in EXECUTE MEM_IMAGE)
    # scan independently — Check 2 only requires "EXECUTE" in the protection
    # string, not RWX, so it can fire on a completely different, unrelated
    # module region than Check 1. Two unrelated facts about two unrelated
    # regions must not combine into HIGH CONFIDENCE; only escalate when the
    # *same* region shows both signals. This also keeps findings["score"]
    # itself correlation-aware, since --hunt all's generic aggregate table
    # reads score/max_score directly and would otherwise call a single
    # uncorrelated check "HIGH CONFIDENCE" too.
    rwx_bases       = {r.BaseAddress for r, _ in rwx_image}
    ioc_bases       = {r.BaseAddress for r, _, _, _ in ioc_hits}
    correlated_bases = rwx_bases & ioc_bases

    raw_hits = int(bool(rwx_image)) + int(bool(ioc_hits))
    score = 2 if correlated_bases else (1 if raw_hits else 0)
    findings["score"] = score
    findings["correlated_regions"] = correlated_bases

    coverage_gap = bool(ioc_skipped_size or ioc_read_failed)
    if not mem_info_available:
        status = NOT_EVALUATED
    elif score == 0 and coverage_gap:
        status = INCONCLUSIVE
    else:
        status = DETECTED if score > 0 else NOT_DETECTED_IN_SCANNED_SCOPE
    findings["status"] = status

    if not mem_info_available:
        verdict = _status_text(NOT_EVALUATED, "MemoryInfoListStream missing from this dump")
    elif status == INCONCLUSIVE:
        reason = ", ".join(filter(None, [
            f"{ioc_skipped_size} oversized region(s) skipped" if ioc_skipped_size else "",
            f"{ioc_read_failed} region(s) failed to read" if ioc_read_failed else "",
        ]))
        verdict = _status_text(INCONCLUSIVE, reason)
    elif correlated_bases:
        addrs = ", ".join(f"0x{a:x}" for a in correlated_bases)
        print(RED(f"  [!] Same region carries BOTH signals: {addrs}\n"))
        verdict = RED("HIGH CONFIDENCE STOMPING — RWX and IOC strings in the same region")
    elif raw_hits >= 2:
        verdict = YELLOW("POSSIBLE STOMPING — RWX and IOC strings found, but in different, "
                          "unrelated regions (not correlated)")
    elif raw_hits == 1:
        verdict = YELLOW("POSSIBLE STOMPING")
    else:
        verdict = GREEN("CLEAN — no stomping indicators")
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/2 checks flagged, {raw_hits} raw signal(s))\n")

    if not verbose and ioc_hits:
        print(DIM("  Use --verbose to list matched strings per region.\n"))

    return findings


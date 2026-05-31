"""Module stomping hunter."""
import os
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.rules_pkg.loader import get_rules, SUSPICIOUS_PROTS
from dumpex.core.memory import (get_modules, get_memory_regions,
    addr_to_module, va_to_file_offset, prot_str,
    read_region, _extract_ioc_strings)
from dumpex.hunt._ui import _print_hunt_header, _print_check

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

    findings = {"rwx_image": [], "ioc_image": [], "score": 0}
    _r               = get_rules()
    STOMPING_WHITELIST  = _r["stomping_whitelist"]
    STOMPING_IOC        = _r["stomping_ioc_patterns"]
    STOMPING_NET_IOC    = _r["stomping_net_ioc_patterns"]

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

    for r in regions:
        mtype = prot_str(r.Type)
        p     = prot_str(r.Protect)
        state = prot_str(r.State)
        if "MEM_IMAGE" not in mtype or state != "MEM_COMMIT":
            continue
        if "EXECUTE" not in p:
            continue
        if r.RegionSize > 0x500000:
            continue

        mod      = addr_to_module(r.BaseAddress, modules)
        mod_name = os.path.basename(mod.name).lower() if mod else ""
        is_wl    = mod_name in STOMPING_WHITELIST

        try:
            data    = read_region(mf, r.BaseAddress, r.RegionSize)
            strings = _extract_ioc_strings(data, r.BaseAddress)

            # Apply appropriate pattern based on whitelist status
            if is_wl:
                # Whitelisted: only flag the truly unusual IOCs, not network strings
                hits = [(off, enc, s) for off, enc, s in strings
                        if STOMPING_IOC.search(s)]
                if hits:
                    ioc_hits.append((r, mod, hits, False))
                else:
                    skipped_wl.append(mod_name)
            else:
                # Non-whitelisted: flag both general IOCs and network patterns
                hits = [(off, enc, s) for off, enc, s in strings
                        if STOMPING_IOC.search(s) or STOMPING_NET_IOC.search(s)]
                if hits:
                    ioc_hits.append((r, mod, hits, True))
        except Exception:
            continue

    if skipped_wl:
        unique_wl = sorted(set(skipped_wl))
        print(f"  {DIM(f'[·] Whitelisted network DLLs skipped (network strings expected): {chr(44).join(unique_wl)}')}")
        print()

    if ioc_hits:
        total = sum(len(h) for _, _, h, _ in ioc_hits)
        detail = f"{total} IOC string(s) across {len(ioc_hits)} module region(s)"
        _print_check("IOC strings in module code regions",
                     RED("SUSPICIOUS — malicious strings inside legitimate module memory"),
                     detail)
        if verbose:
            for r, mod, hits, _ in ioc_hits:
                name = os.path.basename(mod.name) if mod else "(unknown)"
                print(f"    {YELLOW(f'Region 0x{r.BaseAddress:x}  [{name}]')}")
                for off, enc, s in hits[:10]:
                    print(f"      0x{r.BaseAddress+off:x}  [{enc}]  {s}")
                if len(hits) > 10:
                    print(DIM(f"      ... and {len(hits)-10} more"))
                print()
        findings["ioc_image"] = ioc_hits
        findings["score"] += 1
    else:
        _print_check("IOC strings in module code regions",
                     GREEN("CLEAN — no IOC patterns in executable module memory"))

    score = findings["score"]
    verdict = (RED("HIGH CONFIDENCE STOMPING") if score >= 2 else
               YELLOW("POSSIBLE STOMPING") if score == 1 else
               GREEN("CLEAN — no stomping indicators"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/2 checks flagged)\n")

    if not verbose and ioc_hits:
        print(DIM("  Use --verbose to list matched strings per region.\n"))

    return findings


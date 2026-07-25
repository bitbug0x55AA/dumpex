"""Process injection hunter (RWX / hidden PE / unbacked threads).

Phase-two correlation model
────────────────────────────
Signals are grouped and correlated by **AllocationBase** — the address a
single VirtualAlloc/VirtualAllocEx call originally reserved — rather than
by the BaseAddress of whichever individual MemoryInfo sub-region happened
to carry each signal. A single allocation routinely gets split into
several MemoryInfo entries with different protections after
VirtualProtect calls (header page, RW-then-reprotected-to-RX code page,
guard page, ...): an RWX signal on one sub-region and a hidden-PE header
on a different sub-region of the SAME allocation are one suspicious
allocation, not two unrelated observations that happen to be near each
other.

Thread execution correlation now prefers each thread's CURRENT
RIP/EIP — read from ThreadListStream's per-thread CONTEXT at the moment
the dump was captured (see core.memory.get_thread_contexts) — over
ThreadInfoListStream.StartAddress. StartAddress only tells you where a
thread BEGAN; RIP/EIP tells you where it IS, which is what actually
matters for "is this allocation being executed right now". Both are
still reported (StartAddress correlation is kept as a secondary,
lower-confidence signal), but only a live RIP/EIP landing inside a
suspicious allocation can reach HIGH confidence.

A "hidden PE" is no longer just a region beginning with the two bytes
'MZ'. dumpex.core.pe_utils.parse_pe_header() structurally validates the
DOS header, PE signature, COFF file header (Machine/NumberOfSections),
optional header (PE32/PE32+ Magic), and the full section table before a
region counts as a validated hidden PE. A region with an 'MZ' prefix that
fails structural validation (truncated header, garbage Machine field,
implausible section count) is reported separately as a low-confidence
observation, not folded into the same bucket as a confirmed module.

Every reported item is a dumpex.hunt._finding.Finding — facts, inference,
confidence, rationale, limitations — so the distinction between "this
allocation shows page-type + PE-header + live-execution convergence"
(high confidence) and "an MZ-prefixed region exists somewhere, unrelated
to anything else" (low confidence) is explicit, not implied by wording.
"""
import os
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, get_thread_contexts, group_regions_by_allocation,
    addr_to_module, va_to_file_offset, prot_str, read_region)
from dumpex.core.pe_utils import parse_pe_header
from dumpex.hunt._ui import (_print_hunt_header, _print_check, _status_text,
    _scan_status, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED)
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION)

# Bytes read per MZ-prefixed candidate for structural PE validation — large
# enough for the DOS/COFF/optional headers plus a section table of typical
# size (a handful to a few dozen sections). A candidate whose section table
# extends past this just reports valid=False with a truncation reason
# (parse_pe_header) rather than growing this unboundedly for every
# MZ-prefixed hit in the dump.
PE_VALIDATE_READ_MAX = 4096


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


def _hunt_hidden_pe(mf: MinidumpFile, module_list_available: bool = True) -> tuple:
    """
    Return (list of hit dicts, read_failed_count).

    If ModuleListStream isn't present, module_list_available is False and
    this returns [] rather than flagging every MZ header as "hidden": an
    empty modules list doesn't mean "nothing here is a known module" — it
    means we have no way to tell. Producing a hit for every legitimate
    loaded PE header would be pure false-positive noise, not a finding.

    A region whose header read fails is not the same as a region that was
    read and doesn't start with 'MZ' — it was never actually looked at, so
    it's tracked separately rather than silently dropped.

    Each hit dict: {"region", "in_module_list", "pe"} where "pe" is the
    full dumpex.core.pe_utils.parse_pe_header() result — callers decide
    what "valid" means for their purposes rather than this function
    silently only returning validated hits.
    """
    if not module_list_available:
        return [], 0
    modules    = get_modules(mf)
    known_bases = {m.baseaddress for m in modules}
    hits = []
    read_failed = 0
    for r in get_memory_regions(mf):
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        try:
            prefix = read_region(mf, r.BaseAddress, min(2, r.RegionSize))
        except Exception:
            read_failed += 1
            continue
        if prefix[:2] != b'MZ':
            continue
        try:
            deep = read_region(mf, r.BaseAddress, min(PE_VALIDATE_READ_MAX, r.RegionSize))
        except Exception:
            deep = prefix   # fall back to what we already have; parse_pe_header
                             # will report a truncation reason on 2 bytes
        pe = parse_pe_header(deep)
        hits.append({"region": r, "in_module_list": r.BaseAddress in known_bases, "pe": pe})
    return hits, read_failed


def _hunt_unbacked_threads(mf: MinidumpFile, module_list_available: bool = True) -> list:
    """
    Return list of ThreadInfo with no module backing (by StartAddress).
    Internal — retained as a secondary signal; see module docstring for
    why current RIP/EIP (get_thread_contexts) is now the primary
    execution-correlation signal instead.

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


def _region_for_addr(addr, regions):
    for r in regions:
        if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
            return r
    return None


def _region_facts(r) -> str:
    return (f"VA=0x{r.BaseAddress:x} AllocationBase=0x{r.AllocationBase:x} "
            f"size=0x{r.RegionSize:x} type={prot_str(r.Type)} protect={prot_str(r.Protect)}")


def _pe_facts(pe: dict) -> str:
    if pe['valid']:
        return (f"PE header VALID: machine={pe['machine_name']} "
                f"pe32plus={pe['is_pe32_plus']} sections={pe['number_of_sections']} "
                f"entrypoint_rva=0x{pe['address_of_entry_point']:x} "
                f"declared_image_base=0x{pe['image_base']:x}")
    return f"PE header INVALID ({pe['reason']})"


def _hunt_injection(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Detect classic process injection via AllocationBase + current RIP/EIP
    + page type + structural PE validation. Each signal alone can be
    noise; correlation by allocation and live execution raises confidence.
    Returns dict of findings for use in --hunt all summary.
    """
    # RWX/hidden-PE need MemoryInfoListStream; unbacked-thread needs
    # ThreadInfoListStream; hidden-PE and unbacked-thread BOTH additionally
    # need ModuleListStream to tell known from unknown — computed first so
    # _hunt_hidden_pe/_hunt_unbacked_threads can refuse to guess when it's
    # missing, rather than treating every PE/thread as suspicious by default.
    coverage = {
        "memory_info_stream": bool(mf.memory_info and mf.memory_info.infos),
        "thread_info_stream": bool(mf.thread_info and mf.thread_info.infos),
        "module_list_stream": bool(mf.modules and mf.modules.modules),
        "thread_list_stream": bool(mf.threads and mf.threads.threads),
    }

    modules  = get_modules(mf)
    regions  = get_memory_regions(mf)
    rwx      = _hunt_rwx(mf)
    pe_hits, pe_read_failed = _hunt_hidden_pe(mf, module_list_available=coverage["module_list_stream"])
    start_threads    = _hunt_unbacked_threads(mf, module_list_available=coverage["module_list_stream"])
    thread_contexts  = get_thread_contexts(mf)   # [{ThreadId, ip, ip_reg, is_wow64}, ...]
    coverage["thread_context"] = bool(thread_contexts)

    evaluated = coverage["memory_info_stream"] or coverage["thread_info_stream"]
    complete  = (coverage["memory_info_stream"] and coverage["thread_info_stream"]
                 and coverage["module_list_stream"] and pe_read_failed == 0)

    # Only STRUCTURALLY VALID hidden PEs count toward correlation; an
    # MZ-prefixed region that fails header validation is a much weaker
    # observation (could be a decoy, a truncated read, or coincidental
    # bytes) — see module docstring.
    validated_pe_hits = [h for h in pe_hits if not h["in_module_list"] and h["pe"]["valid"]]
    mz_only_hits      = [h for h in pe_hits if not h["in_module_list"] and not h["pe"]["valid"]]

    rwx_by_alloc = group_regions_by_allocation(rwx)
    pe_regions   = [h["region"] for h in validated_pe_hits]
    pe_by_alloc  = group_regions_by_allocation(pe_regions)

    rwx_alloc_bases = set(rwx_by_alloc)
    pe_alloc_bases  = set(pe_by_alloc)
    # Structural correlation: same ALLOCATION carries both an RWX
    # sub-region and a validated hidden PE header, regardless of whether
    # they're the same MemoryInfo sub-region.
    rwx_and_pe_alloc_bases = rwx_alloc_bases & pe_alloc_bases
    suspicious_alloc_bases = rwx_alloc_bases | pe_alloc_bases

    # Execution correlation via CURRENT RIP/EIP — the primary signal.
    rip_hits = []   # (thread_ctx, region)
    for tc in thread_contexts:
        r = _region_for_addr(tc["ip"], regions)
        if r is not None and r.AllocationBase in suspicious_alloc_bases:
            rip_hits.append((tc, r))
    rip_full_correlation = [(tc, r) for tc, r in rip_hits
                             if r.AllocationBase in rwx_and_pe_alloc_bases]

    # Secondary, weaker execution correlation via StartAddress.
    start_hits = []   # (thread_info, region)
    for ti in start_threads:
        r = _region_for_addr(ti.StartAddress or 0, regions)
        if r is not None and r.AllocationBase in suspicious_alloc_bases:
            start_hits.append((ti, r))

    # ── Score ────────────────────────────────────────────────────────────
    # 3 (HIGH)   — a thread's CURRENT RIP/EIP executes inside an allocation
    #               that structurally carries BOTH RWX protection AND a
    #               validated hidden PE header: page type + PE validation +
    #               live execution all converge on one AllocationBase.
    # 2 (MEDIUM) — same-allocation structural correlation (RWX + validated
    #               PE) without confirmed live execution, OR a thread's
    #               current RIP/EIP executing inside a suspicious
    #               allocation with only one signal, OR StartAddress-only
    #               correlation.
    # 1 (LOW)    — raw signals exist but never share an allocation and no
    #               thread (by RIP or StartAddress) executes inside one.
    # 0          — nothing.
    if not (rwx or validated_pe_hits or start_threads):
        score = 0
    elif rip_full_correlation:
        score = 3
    elif rwx_and_pe_alloc_bases or rip_hits or start_hits:
        score = 2
    else:
        score = 1

    status = _scan_status(evaluated=evaluated, detected=score > 0, complete=complete)

    # ── Findings (facts / inference / confidence / rationale / limitations) ──
    findings_list = []

    if rwx:
        allocs = sorted({f"0x{r.AllocationBase:x}" for r in rwx})
        findings_list.append(Finding(
            check="injection.rwx_regions",
            facts=[_region_facts(r) for r in rwx[:20]] + (
                [f"... and {len(rwx)-20} more"] if len(rwx) > 20 else []),
            inference=f"{len(rwx)} memory region(s) carry PAGE_EXECUTE_READWRITE/"
                       f"WRITECOPY protection, spanning {len(allocs)} distinct allocation(s).",
            confidence=CONFIDENCE_MEDIUM,
            rationale="RWX is a directly-observed page protection flag, not a heuristic "
                       "guess — but RWX alone is routinely used by JITs, debuggers, and "
                       "some legitimate packers, so it is a lead, not proof, until "
                       "corroborated by a validated PE header and/or live execution in "
                       "the same allocation.",
            limitations=["Does not by itself distinguish injection from JIT/legitimate "
                         "self-modifying-code use cases."],
            tag=TAG_LEAD,
        ))

    if validated_pe_hits:
        facts = []
        for h in validated_pe_hits[:20]:
            facts.append(_region_facts(h["region"]) + "  |  " + _pe_facts(h["pe"]))
        if len(validated_pe_hits) > 20:
            facts.append(f"... and {len(validated_pe_hits)-20} more")
        findings_list.append(Finding(
            check="injection.hidden_pe_validated",
            facts=facts,
            inference=f"{len(validated_pe_hits)} region(s) contain a structurally-valid "
                       f"PE header (DOS+COFF+optional header+full section table all "
                       f"parsed successfully) at an address absent from the module list.",
            confidence=CONFIDENCE_MEDIUM,
            rationale="Passing full structural PE validation (not just an 'MZ' prefix) "
                       "rules out coincidental bytes and most decoys, but a valid header "
                       "outside the module list can also occur from a manually-mapped "
                       "but otherwise benign in-process library (e.g. some anti-cheat/DRM "
                       "loaders) — confidence rises to HIGH only when a thread's live "
                       "RIP/EIP actually executes inside the same allocation.",
            limitations=[f"Header validation read is capped at {PE_VALIDATE_READ_MAX} bytes; "
                         "a section table extending past that reports as invalid rather "
                         "than being partially trusted."],
            tag=TAG_LEAD,
        ))

    if mz_only_hits:
        facts = []
        for h in mz_only_hits[:10]:
            facts.append(_region_facts(h["region"]) + "  |  " + _pe_facts(h["pe"]))
        if len(mz_only_hits) > 10:
            facts.append(f"... and {len(mz_only_hits)-10} more")
        findings_list.append(Finding(
            check="injection.mz_prefix_unvalidated",
            facts=facts,
            inference=f"{len(mz_only_hits)} region(s) begin with the 2-byte 'MZ' prefix "
                       f"but fail structural PE header validation.",
            confidence=CONFIDENCE_LOW,
            rationale="Two matching bytes is extremely weak evidence on its own — this "
                       "is reported for analyst awareness (a truncated read, a genuine "
                       "decoy header, or a non-PE structure that happens to start with "
                       "'MZ' are all more likely explanations than a hidden module) and "
                       "is NOT counted toward the injection score.",
            limitations=["Not corroborated by section-table/entry-point validation; "
                         "treat as informational only."],
            tag=TAG_OBSERVATION,
        ))

    if start_threads:
        findings_list.append(Finding(
            check="injection.unbacked_thread_startaddress",
            facts=[f"TID=0x{ti.ThreadId:x} StartAddress=0x{(ti.StartAddress or 0):x}"
                   for ti in start_threads[:20]] + (
                   [f"... and {len(start_threads)-20} more"] if len(start_threads) > 20 else []),
            inference=f"{len(start_threads)} thread(s) began execution at an address not "
                       f"covered by any known module.",
            confidence=CONFIDENCE_LOW,
            rationale="StartAddress records where a thread BEGAN, not where it is "
                       "executing now — a thread can legitimately start inside "
                       "unbacked/JIT memory (e.g. a thread pool worker routine passed "
                       "as a raw function pointer into private memory) and still be "
                       "benign. Current RIP/EIP (below, when available) is the stronger "
                       "signal for what a thread is actually doing.",
            limitations=[],
            tag=TAG_LEAD,
        ))

    if not coverage["thread_context"]:
        findings_list.append(Finding(
            check="injection.rip_correlation_unavailable",
            facts=[f"thread_list_stream_present={coverage['thread_list_stream']}"],
            inference="No per-thread CONTEXT (RIP/EIP) could be read from this dump — "
                       "live-execution correlation could not run.",
            confidence=CONFIDENCE_LOW,
            rationale="Coverage gap, not a negative result: a suspicious allocation with "
                       "no RIP correlation available cannot be distinguished from one "
                       "that was checked and found not currently executing.",
            limitations=["Injection score cannot reach HIGH (3) in this run regardless "
                         "of other signals, since live-execution confirmation is the "
                         "only path to that tier."],
            tag=TAG_OBSERVATION,
        ))
    elif rip_hits:
        facts = []
        for tc, r in rip_hits[:20]:
            full = r.AllocationBase in rwx_and_pe_alloc_bases
            facts.append(f"TID=0x{tc['ThreadId']:x} {tc['ip_reg']}=0x{tc['ip']:x} "
                         f"-> {_region_facts(r)}  {'[FULL: RWX+validated-PE]' if full else ''}")
        if len(rip_hits) > 20:
            facts.append(f"... and {len(rip_hits)-20} more")
        conf = CONFIDENCE_HIGH if rip_full_correlation else CONFIDENCE_MEDIUM
        findings_list.append(Finding(
            check="injection.allocation_correlation",
            facts=facts,
            inference=(f"{len(rip_full_correlation)} thread(s) currently execute inside "
                        f"an allocation that is simultaneously RWX and hosts a validated "
                        f"hidden PE — page type, structural PE validation, and live "
                        f"RIP/EIP all converge on the same AllocationBase."
                        if rip_full_correlation else
                        f"{len(rip_hits)} thread(s) currently execute inside an "
                        f"allocation carrying at least one suspicious signal (RWX or a "
                        f"validated hidden PE), but not both at once."),
            confidence=conf,
            rationale=("This is the strongest evidence this hunter can produce: the "
                       "process is, at the moment of the dump, actively running code "
                       "from an allocation with no legitimate module backing and a "
                       "concealed PE image."
                       if rip_full_correlation else
                       "Live execution inside a flagged allocation is meaningful, but "
                       "only one structural signal (not both RWX and a validated PE) "
                       "was present in that allocation."),
            limitations=["RIP is a single-point-in-time snapshot; a thread that executed "
                         "there moments before or after the dump was captured would not "
                         "appear here."],
            tag=TAG_DETECTION if rip_full_correlation else TAG_LEAD,
        ))

    if rwx_and_pe_alloc_bases and not rip_full_correlation:
        findings_list.append(Finding(
            check="injection.structural_allocation_correlation",
            facts=[f"AllocationBase=0x{ab:x}  regions="
                   f"{', '.join(f'0x{r.BaseAddress:x}({prot_str(r.Type)}/{prot_str(r.Protect)})' for r in (rwx_by_alloc.get(ab, []) + pe_by_alloc.get(ab, [])))}"
                   for ab in sorted(rwx_and_pe_alloc_bases)],
            inference=f"{len(rwx_and_pe_alloc_bases)} allocation(s) carry BOTH an RWX "
                       f"sub-region AND a validated hidden PE header, without a "
                       f"currently-observed thread executing inside them.",
            confidence=CONFIDENCE_MEDIUM,
            rationale="Same-allocation structural correlation is stronger than either "
                       "signal alone, but without a live RIP/EIP inside the allocation "
                       "this cannot be elevated to HIGH confidence — the code may not "
                       "(yet, or ever, at dump time) have been executed.",
            limitations=[] if coverage["thread_context"] else
                        ["RIP/EIP correlation could not run at all in this dump (see "
                         "injection.rip_correlation_unavailable) — this may understate "
                         "the true confidence."],
            tag=TAG_LEAD,
        ))

    findings = {
        "rwx":                  rwx,
        "hidden_pe_validated":  validated_pe_hits,
        "hidden_pe_unvalidated": mz_only_hits,
        "threads":              start_threads,
        "thread_contexts":      thread_contexts,
        "rwx_and_pe_alloc_bases":  sorted(rwx_and_pe_alloc_bases),
        "rip_hits":             rip_hits,
        "rip_full_correlation": rip_full_correlation,
        "start_hits":           start_hits,
        "score":                score,
        "status":               status,
        "coverage":             coverage,
        "pe_read_failed":       pe_read_failed,
        "findings":             [f.to_dict() for f in findings_list],
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
                           f"\n          AllocationBase    0x{r.AllocationBase:016x}"
                           f"\n          File offset       {fo_str}"
                           f"\n          {p}  {t}")
        _print_check("RWX memory regions", RED("SUSPICIOUS"), detail)
    else:
        _print_check("RWX memory regions", GREEN("CLEAN — none found"))

    # Check 2: Hidden PE headers (structurally validated)
    if validated_pe_hits:
        detail = f"{len(validated_pe_hits)} structurally-validated unregistered PE(s)"
        if verbose:
            for h in validated_pe_hits:
                r, pe = h["region"], h["pe"]
                fo = va_to_file_offset(mf, r.BaseAddress)
                fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
                detail += (f"\n          VA (process)      0x{r.BaseAddress:016x}"
                           f"\n          AllocationBase    0x{r.AllocationBase:016x}"
                           f"\n          File offset       {fo_str}"
                           f"\n          Page type         {prot_str(r.Type)}  {prot_str(r.Protect)}"
                           f"\n          PE machine        {pe['machine_name']}"
                           f"\n          PE sections       {pe['number_of_sections']}"
                           f"\n          Entry point RVA   0x{pe['address_of_entry_point']:x}"
                           f"\n          Declared ImageBase 0x{pe['image_base']:x}")
        _print_check("Hidden PE headers (structurally validated, MZ not in module list)",
                     RED("SUSPICIOUS"), detail)
    else:
        _print_check("Hidden PE headers", GREEN("CLEAN — no structurally-valid unregistered PE headers"))

    if mz_only_hits and verbose:
        print(DIM(f"  [·] {len(mz_only_hits)} region(s) start with 'MZ' but failed structural "
                  f"PE validation — not counted as hidden PEs (see injection.mz_prefix_unvalidated "
                  f"in findings; use --json to inspect reasons).\n"))

    # Check 3: Unbacked threads (StartAddress)
    if start_threads:
        detail = f"{len(start_threads)} thread(s) with no module backing (by StartAddress)"
        if verbose:
            for ti in start_threads:
                sa = ti.StartAddress or 0
                fo = va_to_file_offset(mf, sa)
                fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
                detail += (f"\n          TID=0x{ti.ThreadId:x}"
                           f"\n          StartAddress (VA) 0x{sa:016x}"
                           f"\n          File offset       {fo_str}")
        _print_check("Unbacked threads (StartAddress)", YELLOW("LEAD"), detail)
    else:
        _print_check("Unbacked threads (StartAddress)", GREEN("CLEAN — all threads backed by known modules"))

    # Check 4: Allocation-based correlation — this is what drives the score.
    for f in findings_list:
        if f.tag in (TAG_DETECTION, TAG_LEAD) and f.check in (
                "injection.allocation_correlation", "injection.structural_allocation_correlation"):
            f.print()

    if not coverage["thread_context"]:
        print(YELLOW("  [~] No per-thread CONTEXT (RIP/EIP) available in this dump — "
                      "live-execution correlation could not run; score capped below HIGH.\n"))
    if not coverage["memory_info_stream"]:
        print(YELLOW("  [~] MemoryInfoListStream not in this dump — RWX / hidden-PE checks could not run.\n"))
    if not coverage["thread_info_stream"]:
        print(YELLOW("  [~] ThreadInfoListStream not in this dump — StartAddress-based unbacked-thread check could not run.\n"))
    if not coverage["module_list_stream"] and (coverage["memory_info_stream"] or coverage["thread_info_stream"]):
        print(YELLOW("  [~] ModuleListStream not in this dump — hidden-PE and unbacked-thread checks "
                      "were skipped rather than guessed (an empty module list would otherwise make "
                      "every PE look hidden and every thread look unbacked).\n"))
    if pe_read_failed:
        print(YELLOW(f"  [~] {pe_read_failed} region(s) could not be read while checking for "
                      f"hidden PE headers — coverage is incomplete.\n"))

    # Verdict — driven by AllocationBase correlation + live execution, not
    # by how many independent checks happened to fire somewhere in the
    # address space.
    if status == NOT_EVALUATED:
        print(f"  {BOLD('[ VERDICT ]')}  {_status_text(status, 'no required stream present in this dump')}\n")
        return findings

    verdict = (RED("HIGH CONFIDENCE INJECTION") if score >= 3 else
               YELLOW("LIKELY INJECTION") if score == 2 else
               YELLOW("POSSIBLE INJECTION") if score == 1 else
               GREEN("CLEAN") if status == NOT_DETECTED_IN_SCANNED_SCOPE else
               YELLOW("INCONCLUSIVE — partial stream coverage"))
    basis = ("no correlated signals" if score == 0 else
              "raw signals only — no shared allocation, no execution overlap" if score == 1 else
              "same-allocation structural correlation, or thread execution in a flagged allocation" if score == 2 else
              "current RIP/EIP executing in an allocation where RWX + validated PE overlap")
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  (score {score}/3 — {basis})\n")

    if not verbose and (rwx or validated_pe_hits or start_threads):
        print(DIM("  Use --verbose to list individual addresses.\n"))

    return findings

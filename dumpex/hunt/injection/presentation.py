"""All console rendering for the process injection hunter. Reads only
from the aggregate.Report the caller already built — never recomputes
score/status/coverage itself.
"""
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.core.memory import prot_str, va_to_file_offset
from dumpex.hunt._ui import _print_hunt_header, _print_check, _status_text, \
    NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED
from dumpex.hunt._finding import leads_suffix

# injection.rwx_regions/hidden_pe_validated/unbacked_thread_startaddress each
# get a separate, uncapped --verbose-only raw-evidence block below (matching
# what presentation.py showed before rendering was centralized on
# Finding.print()) instead of Finding.facts' own capped list, which is why
# they're rendered with facts_mode="omit"/"notice" in render() below rather
# than "full" -- printing both would show the same VA twice under
# --verbose. See Finding.print()'s own docstring for what those modes mean.
_SUPPLEMENTED_CHECKS = frozenset({
    "injection.rwx_regions", "injection.hidden_pe_validated",
    "injection.unbacked_thread_startaddress",
})


def _print_rwx_detail(mf: MinidumpFile, rwx) -> None:
    print(DIM("      RWX memory regions — full detail:"))
    for r in rwx:
        fo = va_to_file_offset(mf, r.BaseAddress)
        fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
        print(DIM(f"          VA (process)      0x{r.BaseAddress:016x}  size=0x{r.RegionSize:x}"))
        print(DIM(f"          AllocationBase    0x{r.AllocationBase:016x}"))
        print(DIM(f"          File offset       {fo_str}"))
        print(DIM(f"          {prot_str(r.Protect)}  {prot_str(r.Type)}"))
    print()


def _print_hidden_pe_detail(mf: MinidumpFile, suspicious_pe_hits) -> None:
    print(DIM("      Hidden PE headers — full detail:"))
    for h in suspicious_pe_hits:
        r, pe = h["region"], h["pe"]
        fo = va_to_file_offset(mf, r.BaseAddress)
        fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
        print(DIM(f"          VA (process)      0x{r.BaseAddress:016x}"))
        print(DIM(f"          AllocationBase    0x{r.AllocationBase:016x}"))
        print(DIM(f"          File offset       {fo_str}"))
        print(DIM(f"          Page type         {prot_str(r.Type)}  {prot_str(r.Protect)}"))
        print(DIM(f"          PE machine        {pe['machine_name']}"))
        print(DIM(f"          PE sections       {pe['number_of_sections']}"))
        print(DIM(f"          Entry point RVA   0x{pe['address_of_entry_point']:x}"))
        print(DIM(f"          Declared ImageBase 0x{pe['image_base']:x}"))
    print()


def _print_unbacked_threads_detail(mf: MinidumpFile, start_threads) -> None:
    print(DIM("      Unbacked threads (StartAddress) — full detail:"))
    for ti in start_threads:
        sa = ti.StartAddress or 0
        fo = va_to_file_offset(mf, sa)
        fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
        print(DIM(f"          TID=0x{ti.ThreadId:x}"))
        print(DIM(f"          StartAddress (VA) 0x{sa:016x}"))
        print(DIM(f"          File offset       {fo_str}"))
    print()


def render(mf: MinidumpFile, report, verbose: bool = False) -> dict:
    """Render the full result and return the same findings dict for the
    caller to hand back."""
    findings = report.findings
    rwx = report.rwx
    validated_pe_hits = report.validated_pe_hits
    mz_only_hits = report.mz_only_hits
    suspicious_pe_hits = report.suspicious_pe_hits
    informational_pe_hits = report.informational_pe_hits
    start_threads = report.start_threads
    coverage = report.coverage
    score = report.score
    status = report.status
    pe_read_failed = findings["pe_read_failed"]
    pe_short_reads = findings["pe_short_reads"]

    _print_hunt_header("Process Injection")

    # Check 1: RWX memory
    if rwx:
        _print_check("RWX memory regions", RED("SUSPICIOUS"), f"{len(rwx)} region(s)")
    else:
        _print_check("RWX memory regions", GREEN("CLEAN — none found"))

    # Check 2: Hidden PE headers (structurally validated) — only the
    # scoreable subset (MEM_PRIVATE, executable unbacked mapping, or
    # correlated with RWX/live execution) is shown as SUSPICIOUS; a
    # read-only/non-executable, uncorrelated hit is context-only and must
    # not read as a detection at a glance (see aggregate.py's
    # _split_scoreable_pe_hits).
    if suspicious_pe_hits:
        _print_check("Hidden PE headers (structurally validated, MZ not in module list)",
                     RED("SUSPICIOUS"), f"{len(suspicious_pe_hits)} structurally-validated unregistered PE(s)")
    elif informational_pe_hits:
        detail = (f"{len(informational_pe_hits)} structurally-validated unregistered PE(s) — "
                  f"read-only/non-executable, no RWX or live-execution correlation")
        _print_check("Hidden PE headers (structurally validated, MZ not in module list)",
                     DIM("OBSERVATION — context-only, not scored"), detail)
    else:
        _print_check("Hidden PE headers", GREEN("CLEAN — no structurally-valid unregistered PE headers"))

    # Check 3: Unbacked threads (StartAddress)
    if start_threads:
        _print_check("Unbacked threads (StartAddress)", YELLOW("LEAD"),
                     f"{len(start_threads)} thread(s) with no module backing (by StartAddress)")
    else:
        _print_check("Unbacked threads (StartAddress)", GREEN("CLEAN — all threads backed by known modules"))

    # Every Finding this hunter built (RWX/hidden-PE/unbacked-thread leads,
    # the MZ-prefix and RIP-correlation-unavailable observations, and the
    # allocation-correlation detection/lead that drives the score) — one
    # print() each, in construction order, so the narrative (inference/
    # confidence/rationale/limitations) that used to be --json-only is
    # visible on console too. See Finding.print()'s own docstring for how
    # `verbose` controls fact-list expansion.
    for f in report.findings_list:
        if f.check in _SUPPLEMENTED_CHECKS:
            f.print(verbose=verbose, facts_mode="omit" if verbose else "notice")
        else:
            f.print(verbose=verbose)

    if verbose:
        if rwx:
            _print_rwx_detail(mf, rwx)
        if suspicious_pe_hits:
            _print_hidden_pe_detail(mf, suspicious_pe_hits)
        if start_threads:
            _print_unbacked_threads_detail(mf, start_threads)

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
    if pe_short_reads:
        print(YELLOW(f"  [~] {pe_short_reads} region(s) returned fewer bytes than requested "
                      f"while checking for hidden PE headers — coverage is incomplete.\n"))

    # Verdict — driven by AllocationBase correlation + live execution, not
    # by how many independent checks happened to fire somewhere in the
    # address space.
    if status == NOT_EVALUATED:
        print(f"  {BOLD('[ VERDICT ]')}  {_status_text(status, 'no required stream present in this dump')}\n")
        return findings

    verdict = (RED("HIGH CONFIDENCE INJECTION") if score >= 3 else
               YELLOW("LIKELY INJECTION") if score == 2 else
               YELLOW("POSSIBLE INJECTION") if score == 1 else
               GREEN("CLEAN" + leads_suffix(report.findings_list)) if status == NOT_DETECTED_IN_SCANNED_SCOPE else
               YELLOW("INCONCLUSIVE — partial stream coverage" + leads_suffix(report.findings_list)))
    basis = ("no correlated signals" if score == 0 else
              "raw signals only — no shared allocation, no execution overlap" if score == 1 else
              "same-allocation structural correlation, or thread execution in a flagged allocation" if score == 2 else
              "current RIP/EIP executing in an allocation where RWX + validated PE overlap")
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  (score {score}/3 — {basis})\n")

    if not verbose and (rwx or validated_pe_hits or start_threads):
        print(DIM("  Use --verbose to list individual addresses.\n"))

    return findings

"""Final-result console rendering for the stomping hunter.

Header and in-progress scan announcements remain in the entry point so
they are emitted before/during potentially expensive scanning; this
module renders only what's left once a Report already exists — findings,
coverage-gap notes, and the verdict line. Reads only from the
aggregate.Report the caller already built — never recomputes score/
status/coverage itself.
"""
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._ui import (_print_check, _status_text, DETECTED,
    NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE)
from dumpex.hunt._finding import DetailLevel, leads_suffix


def render(report, verbose: bool = False) -> dict:
    """Render the full result and return the same findings dict for the
    caller to hand back."""
    findings = report.findings
    ioc_scan = report.ioc_scan
    ref_dir = report.ref_dir
    score = report.score
    status = report.status
    coverage_status = report.coverage_status
    coverage_reasons = report.coverage_reasons
    verified_changes = report.verified_changes

    if ioc_scan.skipped_wl:
        unique_wl = sorted(set(ioc_scan.skipped_wl))
        print(f"  {DIM(f'[·] Whitelisted network DLLs skipped (network strings expected): {chr(44).join(unique_wl)}')}")
        print()

    # The IOC sub-scan's check line. "CLEAN — no IOC patterns in executable
    # module memory" is a claim about ALL eligible executable module memory,
    # so it may only be printed when the scan actually read all of it: an
    # oversized region never scanned, or one whose read failed, makes this
    # check INCOMPLETE even when nothing was found in the part that WAS
    # read. When the scan did have hits, the hits themselves are rendered
    # by the findings_list loop below (their Finding carries the same gap in
    # `limitations`) — but the check-level coverage statement still belongs
    # here, since a hit list from a partial scan is a floor, not a total.
    ioc_reasons = report.ioc_coverage_reasons
    if ioc_reasons:
        _print_check("IOC strings in module code regions",
                     YELLOW("INCOMPLETE — part of the eligible executable module memory was "
                            "not examined for IOC strings"),
                     "; ".join(ioc_reasons))
        print(YELLOW("  [~] Targeted follow-up needed on the region(s) above: --extract / "
                      "--strings that VA, or re-scan it with an external scanner — an IOC "
                      "result cannot be called clean for memory that was never read.\n"))
    elif not ioc_scan.ioc_hits:
        _print_check("IOC strings in module code regions",
                     GREEN("CLEAN — no IOC patterns in executable module memory"))

    # ── Print detection/lead findings ─────────────────────────────────────
    level = DetailLevel.VERBOSE if verbose else DetailLevel.NORMAL
    for f in report.findings_list:
        f.print(level=level)

    if status == NOT_EVALUATED:
        verdict = _status_text(NOT_EVALUATED, "; ".join(coverage_reasons) or "required streams missing")
    elif status == DETECTED:
        # score==1 is a verified, relocation-normalized byte difference with
        # NO corroborating live execution in the changed range — that is
        # also exactly what a legitimate hotpatch/EDR-hook trampoline
        # produces (see stomping.verified_content_change's limitations), so
        # it is reported as a neutral, factual "modification confirmed"
        # rather than "STOMPING", which would over-attribute malicious
        # intent from content-diff alone. The "stomping" framing is
        # reserved for score==2, where a thread's own RIP/EIP is executing
        # inside the changed bytes.
        verdict = (RED("HIGH CONFIDENCE STOMPING — verified content change, RIP/EIP inside "
                       "the changed range") if score == 2 else
                   YELLOW("VERIFIED MODULE CODE MODIFICATION — content differs from reference "
                          "file, but no observed thread executes inside the changed range "
                          "(uncorroborated; consistent with hotpatch/EDR-hook activity as well "
                          "as stomping)"))
    elif status == INCONCLUSIVE:
        verdict = _status_text(INCONCLUSIVE,
                                ("; ".join(coverage_reasons) or "partial coverage")
                                + leads_suffix(report.findings_list))
    else:
        verdict = GREEN("CLEAN — no verified stomping indicators" + leads_suffix(report.findings_list))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/2, requires --ref-dir; "
          f"protection-deviation and string-IOC leads above are informational and not counted)\n")

    # NOT_EVALUATED/INCONCLUSIVE already carry coverage_reasons inside the
    # verdict text above; DETECTED does not, so a detection over partial
    # coverage must not leave a red verdict line standing on its own.
    if status == DETECTED and coverage_status == "partial":
        print(YELLOW(f"  [~] Coverage incomplete despite a detection: {'; '.join(coverage_reasons)} "
                      f"— additional stomped modules may exist beyond what could be checked.\n"))

    if not verbose and verified_changes:
        print(DIM("  Use --verbose to list every verified change in detail.\n"))
    if not ref_dir:
        print(DIM("  [·] --ref-dir not supplied — verified content-diff (the only scored "
                  "signal) was not attempted; reported as INCONCLUSIVE/partial coverage, "
                  "not a clean result.\n"))

    return findings

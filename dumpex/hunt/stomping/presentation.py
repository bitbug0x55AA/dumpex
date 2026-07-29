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
from dumpex.hunt._finding import leads_suffix
from dumpex.hunt.stomping.memory_scan import _module_basename


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

    if ioc_scan.ioc_hits:
        n_strong = sum(sum(1 for h in hits if not h[3]) for _, _, hits, _ in ioc_scan.ioc_hits)
        n_weak   = sum(sum(1 for h in hits if h[3]) for _, _, hits, _ in ioc_scan.ioc_hits)
        detail = (f"{n_strong} strong + {n_weak} weak IOC token(s) across "
                  f"{len(ioc_scan.ioc_hits)} module region(s) — LEAD ONLY, not scored")
        if ioc_scan.ioc_read_failed:
            detail += f"  ({ioc_scan.ioc_read_failed} region(s) failed to read, not scanned)"
        if verbose:
            for r, mod, hits, _ in ioc_scan.ioc_hits:
                name = _module_basename(mod) if mod else "(unknown)"
                detail += f"\n          {name}  0x{r.BaseAddress:x}"
                for off, enc, tok, is_weak in hits[:10]:
                    tag = DIM(" (weak/common API)") if is_weak else ""
                    detail += f"\n            0x{r.BaseAddress+off:x}  [{enc}]  {tok}{tag}"
        _print_check("IOC strings in module code regions (lead)",
                     YELLOW("LEAD — not scored, see structural checks above"), detail)
    else:
        detail = (f"{ioc_scan.ioc_read_failed} region(s) failed to read and were not scanned"
                  if ioc_scan.ioc_read_failed else "")
        _print_check("IOC strings in module code regions",
                     GREEN("CLEAN — no IOC patterns in executable module memory")
                     if not ioc_scan.ioc_read_failed else
                     YELLOW("INCOMPLETE — some regions could not be read"),
                     detail)

    # ── Print detection/lead findings ─────────────────────────────────────
    for f in report.findings_list:
        f.print()

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

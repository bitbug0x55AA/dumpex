"""Final-result console rendering for the pipe hunter.

Header and any in-progress scan announcements remain in the entry point
so they are emitted before/during potentially expensive scanning
(dumpex/hunt/pipe/ currently has no such mid-scan announcement, only the
header — see dumpex/hunt/pipe/__init__.py). This module renders only
what's left once a Report already exists — findings, coverage-gap notes,
and the verdict line. Reads only from the aggregate.Report the caller
already built — never recomputes score/status/coverage itself.
"""
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._ui import _print_check, _status_text, NOT_EVALUATED, INCONCLUSIVE
from dumpex.hunt._finding import DetailLevel, leads_suffix
from dumpex.hunt.pipe.config import PIPE_CONTEXT_DISTANCE


def render(report, verbose: bool = False) -> dict:
    findings = report.findings
    handle_scan = report.handle_scan
    pipe_name_scan = report.pipe_name_scan
    correlation = report.correlation
    handle_stream_available = report.handle_stream_available
    evaluated = report.evaluated
    score = report.score
    status = report.status

    handle_pipe_hits = handle_scan.handle_pipe_hits
    handle_classified = handle_scan.handle_classified
    private_pipes = pipe_name_scan.private_pipes
    image_pipes = pipe_name_scan.image_pipes
    pipe_name_budget = pipe_name_scan.pipe_name_budget
    c2_budget = pipe_name_scan.c2_budget
    c2_hits = correlation.c2_hits
    corroborated_handles = correlation.corroborated_handles
    framework_string_hits = correlation.framework_string_hits
    unbacked_in_pipe_rgn = correlation.unbacked_in_pipe_rgn

    # ── Check A: open pipe handles (HandleDataStream) ─────────────────────
    if handle_stream_available:
        if handle_pipe_hits:
            _print_check("Open pipe handles (HandleDataStream)",
                         GREEN(f"{len(handle_pipe_hits)} found") if not any(hc["framework_match"] for hc in handle_classified)
                         else RED("SUSPICIOUS — framework-pattern match"),
                         f"{len(handle_pipe_hits)} pipe handle(s)")
        else:
            _print_check("Open pipe handles (HandleDataStream)",
                         GREEN("CLEAN — no pipe handles open"))
    else:
        _print_check("Open pipe handles (HandleDataStream)",
                     YELLOW("NOT AVAILABLE — dump was not captured with MiniDumpWithHandleData"))

    # ── String-scan lead ───────────────────────────────────────────────────
    if private_pipes:
        _print_check("Pipe name strings in non-system memory (lead only)",
                     YELLOW("LEAD — not scored, see handle checks above"),
                     f"{len(private_pipes)} occurrence(s)")
    else:
        _print_check("Pipe name strings in non-system memory",
                     GREEN("CLEAN — no pipe-name byte patterns found"))

    if image_pipes and verbose:
        mod_names = sorted({h["module"] for h in image_pipes})
        print(DIM(f"  [·] {len(image_pipes)} pipe reference(s) in system DLLs "
                  f"({', '.join(mod_names)}) — expected, skipped\n"))

    if pipe_name_budget.exhausted():
        print(YELLOW(f"  [~] Pipe-name scan budget exhausted "
                      f"({pipe_name_budget.exhausted_reason}) — some regions may not "
                      f"have been checked for pipe names.\n"))

    # ── Corroborated handles (the scored Check B) ─────────────────────────
    if corroborated_handles:
        for entry in corroborated_handles:
            hc = entry["hc"]
            h = hc["handle"]
            detail = f"ObjectName={h.ObjectName}  pipe_va=0x{entry['pipe_va']:x}"
            _print_check("Handle-confirmed pipe corroborated by memory evidence",
                         RED(f"SUSPICIOUS — C2 context and/or execution within "
                             f"{PIPE_CONTEXT_DISTANCE} bytes of handle-confirmed pipe"),
                         detail)

    if c2_hits and verbose:
        detail = f"{len(c2_hits)} region(s) with pipe-name string + C2 artifacts (uncorrelated to a handle)"
        for r, pipe_name, records in c2_hits:
            detail += f"\n          Region 0x{r.BaseAddress:x}  pipe: {pipe_name}"
            for rec in records[:3]:
                detail += (f"\n            C2: {rec['match']}"
                           f"  VA 0x{rec['va']:016x}"
                           f"  sha256_prefix={rec['sha256'][:16]}…")
        print(DIM(detail) + "\n")
    if c2_budget.exhausted():
        print(YELLOW(f"  [~] C2-context scan budget exhausted "
                      f"({c2_budget.exhausted_reason}) — some pipe-bearing regions "
                      f"may not have been checked for C2 context.\n"))

    # ── Known framework patterns on the STRING leads too (attribution only) ──
    if framework_string_hits:
        detail = f"{len(framework_string_hits)} match(es) on string leads — framework attribution (not scored):"
        for r, pipe_name, framework, technique, mitre in framework_string_hits:
            detail += f"\n          Pipe     : {pipe_name}"
            detail += f"\n          Framework: {framework}"
            detail += f"\n          Technique: {technique}"
            detail += f"\n          MITRE    : {mitre}"
        _print_check("Known C2 framework pipe naming pattern (string lead attribution)",
                     YELLOW(f"NOTABLE — matches known {framework_string_hits[0][2]} pipe naming, "
                            f"lead only"),
                     detail)
    else:
        _print_check("Known C2 framework pipe naming pattern (string leads)",
                     DIM("CLEAN — no known framework patterns among string leads"))

    # ── Unbacked threads in same region as a string pipe-name lead ────────
    if unbacked_in_pipe_rgn and verbose:
        detail = f"{len(unbacked_in_pipe_rgn)} unbacked thread(s) executing in a pipe-name-string region (lead only)"
        for ti, r in unbacked_in_pipe_rgn:
            detail += (f"\n          TID=0x{ti.ThreadId:x}  "
                       f"StartAddr=0x{ti.StartAddress:x}  "
                       f"Region=0x{r.BaseAddress:x}")
        print(DIM(detail) + "\n")

    # ── Every Finding this hunter built ───────────────────────────────────
    # One print() each, in construction order. See Finding.print()'s own
    # docstring for how `level` gates fact-list expansion.
    level = DetailLevel.VERBOSE if verbose else DetailLevel.NORMAL
    for f in report.findings_list:
        f.print(level=level)

    # ── Score / Verdict ───────────────────────────────────────────────────
    # `report.verdict_reason` is aggregate.py's — the same coverage_reasons
    # list --json returns, not a separately re-derived subset (see
    # aggregate.build_report's comment for the drift bug this replaced:
    # this text could previously omit a short-read/budget-exhaustion gap
    # that coexisted with a missing HandleDataStream).
    if not evaluated:
        verdict = _status_text(NOT_EVALUATED, report.verdict_reason)
    elif not handle_stream_available:
        verdict = _status_text(INCONCLUSIVE, report.verdict_reason + leads_suffix(report.findings_list))
    elif status == INCONCLUSIVE:
        verdict = _status_text(INCONCLUSIVE, report.verdict_reason + leads_suffix(report.findings_list))
    else:
        verdict = (RED("HIGH CONFIDENCE C2 PIPE / LATERAL MOVEMENT") if score >= 3 else
                   YELLOW("LIKELY C2 PIPE")                           if score == 2 else
                   YELLOW("POSSIBLE C2 PIPE")                         if score == 1 else
                   GREEN("CLEAN — no handle-confirmed C2 pipe indicators" + leads_suffix(report.findings_list)))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/3 — handle-anchored; string leads "
          f"shown above are informational only)\n")

    if not verbose and (private_pipes or handle_pipe_hits):
        print(DIM("  Use --verbose to expand handle list, pipe names, and C2 strings.\n"))

    return findings

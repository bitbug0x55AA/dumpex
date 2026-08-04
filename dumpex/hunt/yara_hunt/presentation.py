"""Final-result console rendering for the YARA hunter.

Header and in-progress scan announcements ("Loaded N rule file(s)...",
"Scanning N segment(s)...", "Scan complete...") are printed by
`_hunt_yara()` in `dumpex/hunt/yara_hunt/__init__.py`, AFTER the fully
silent `_build_yara_report()` returns (see that function's own
docstring for how it hands back everything `_hunt_yara()` needs to
reproduce them without rescanning). This module renders only what's
left once a Report already exists — findings, coverage-gap notes, and
the verdict line. This includes the four "prerequisite missing"
NOT_EVALUATED cases: `_hunt_yara()` picks which of the four render_*
functions below to call from `report.render_kind`, itself set by
aggregate.build_not_evaluated_report() -- so aggregate stays the only
place that constructs or mutates status/coverage_status/verdict_level,
even for these early-return paths.
"""
import os
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.core.memory import addr_to_module
from dumpex.hunt._ui import _print_check, _status_text, DETECTED, NOT_EVALUATED, INCONCLUSIVE
from dumpex.hunt.yara_hunt.context import context_unverified_reason


def _print_not_evaluated_verdict(report) -> dict:
    print(f"  {BOLD('[ VERDICT ]')}  {_status_text(NOT_EVALUATED, report.verdict_reason)}\n")
    return report.findings


def render_yara_not_installed(report) -> dict:
    print(YELLOW("  [~] yara-python is not installed."))
    print(DIM ("      Install with: pip install yara-python"))
    print()
    return _print_not_evaluated_verdict(report)


def render_no_rules_dir(report) -> dict:
    print(YELLOW(f"  [~] No YARA rules directory found."))
    print(DIM (f"      Expected: ./rules/yara/  (or pass --yara-dir PATH)"))
    print()
    return _print_not_evaluated_verdict(report)


def render_no_rule_files(report, rules_dir: str, compile_failed: int) -> dict:
    print(YELLOW(f"  [~] No .yar / .yara files found in {rules_dir}"))
    if compile_failed:
        print(YELLOW(f"      ({compile_failed} file(s) present but failed to compile)"))
    print()
    return _print_not_evaluated_verdict(report)


def render_no_segments(report) -> dict:
    print(YELLOW("  [~] No memory segments in dump — cannot scan."))
    print()
    return _print_not_evaluated_verdict(report)


def render_result(report, modules: list, verbose: bool = False) -> dict:
    """Render the scan-completed result: no hits (CLEAN/INCONCLUSIVE), or
    grouped per-rule detail + verdict."""
    findings = report.findings

    if not report.has_hits:
        print()
        if report.any_gap:
            _print_check("YARA rules", _status_text(INCONCLUSIVE, report.verdict_reason))
        else:
            _print_check("YARA rules", GREEN("CLEAN — no rules matched"))
        return findings

    has_verbose_overflow = False   # tracks whether any rule has >5 regions when not verbose

    for group in report.rule_groups:
        meta  = group.meta
        rfile = group.file
        desc  = meta.get("description", "")
        mitre = meta.get("mitre", "")
        ref   = meta.get("reference", "")
        tags  = group.tags
        seen_vas = group.seen_vas

        n_segs    = len(seen_vas)
        n_strings = sum(len(h["strings"]) for h in seen_vas.values())

        # ── Compact detail (always shown) ────────────────────────────
        tag_part   = f"  [{', '.join(tags)}]" if tags else ""
        mitre_part = f"  {mitre}"             if mitre else ""
        desc_part  = f"  {desc[:72]}{'…' if len(desc) > 72 else ''}" if desc else ""
        detail     = (f"{n_segs} region(s), {n_strings} string hit(s)"
                      f"{mitre_part}{tag_part}"
                      f"\n          {DIM(rfile)}{desc_part}")
        if ref:
            detail += f"\n          ref: {ref}"

        # ── Verbose expansion: per-region hit lines ───────────────────
        if verbose:
            for seg_va, hit in sorted(seen_vas.items()):
                mod     = addr_to_module(seg_va, modules)
                backing = os.path.basename(mod.name) if mod else "(private/unbacked)"
                detail += (f"\n\n          Region  VA 0x{seg_va:016x}"
                           f"  size 0x{hit['seg_size']:x}"
                           f"  ← {backing}")

                for sv in hit["strings"]:
                    raw      = sv["data"]
                    is_text  = all(0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d)
                                   for b in raw[:64])
                    preview  = (raw[:64].decode("ascii", errors="replace").rstrip()
                                if is_text else raw[:24].hex())
                    detail  += (f"\n            {DIM(sv['var']):<18}"
                                f"  VA 0x{sv['va']:016x}"
                                f"  DMP 0x{sv['fo']:x}"
                                f"  {preview}")
        else:
            # Non-verbose: show first 5 regions as a one-liner summary
            region_list = [f"0x{va:x}" for va in sorted(seen_vas)[:5]]
            overflow    = n_segs - 5
            detail += f"\n          regions: {', '.join(region_list)}"
            if overflow > 0:
                detail    += f"  … +{overflow} more"
                has_verbose_overflow = True

        # A rule whose EVERY hit is context_unverified (PE_In_Private_Memory
        # in a MemoryContext.OTHER or MemoryContext.UNKNOWN region — see
        # dumpex/hunt/yara_hunt/context.py) cannot be reported as a
        # confirmed detection — it's shown for visibility but with a
        # distinct, non-alarming status. The two contexts are different
        # findings (OTHER means MemoryInfo WAS available and resolved to
        # some other type; UNKNOWN means neither context source classified
        # it at all), so the message must say which applies, not always
        # claim "no ModuleList/MemoryInfo".
        if group.rule_is_unverified:
            status_label = YELLOW(f"CONTEXT UNVERIFIED — {context_unverified_reason(group.unverified_contexts)}")
        else:
            status_label = RED("SUSPICIOUS")
        _print_check(
            f"Rule: {group.rule_name}  {DIM('(' + rfile + ')')}",
            status_label,
            detail,
        )

    outcome = report.outcome
    # suppressed_module_pe/suppressed_scoped are already printed once, right
    # after the scan completes, in __init__.py's "Scan complete ..." block
    # (which runs unconditionally, unlike this function's has_hits-gated
    # rendering) — printing them again here would just duplicate the same
    # two lines whenever has_hits is True.
    if outcome.context_unverified:
        # Shared across PE_In_Private_Memory and any dumpex_scope-scoped
        # rule (see scanner.py's dispatch) — not attributable to one rule
        # name, so the message stays generic rather than naming either.
        all_unverified_contexts = {h.get("memory_context") for h in outcome.all_hits
                                   if h.get("context_unverified")}
        print(YELLOW(f"  [~] {outcome.context_unverified} match(es) could not be "
                      f"classified ({context_unverified_reason(all_unverified_contexts)}).\n"))

    # ── Verdict ───────────────────────────────────────────────────────
    score  = findings["score"]
    status = findings["status"]
    if status == DETECTED:
        verdict = (RED(f"HIGH — {score} distinct rule(s) matched")      if score >= 3 else
                   YELLOW(f"MEDIUM — {score} distinct rule(s) matched") if score >= 1 else
                   GREEN("CLEAN"))
        print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score} rule(s))\n")
    else:
        print(f"  {BOLD('[ VERDICT ]')}  {_status_text(INCONCLUSIVE, report.verdict_reason)}\n")

    if outcome.truncated or outcome.timed_out or outcome.match_failed or report.compile_failed:
        print(YELLOW(f"  [~] Scan did not fully complete "
                      f"({'hit result cap' if outcome.truncated else ''}"
                      f"{' + ' if outcome.truncated and (outcome.timed_out or outcome.match_failed or report.compile_failed) else ''}"
                      f"{f'{outcome.timed_out} timeout(s)' if outcome.timed_out else ''}"
                      f"{' + ' if outcome.timed_out and (outcome.match_failed or report.compile_failed) else ''}"
                      f"{f'{outcome.match_failed} match failure(s)' if outcome.match_failed else ''}"
                      f"{' + ' if outcome.match_failed and report.compile_failed else ''}"
                      f"{f'{report.compile_failed} rule file(s) failed to compile' if report.compile_failed else ''}"
                      f") — there may be more matches than shown.\n"))

    if not verbose and has_verbose_overflow:
        print(DIM("  Use --verbose to expand all region and string match details.\n"))

    return findings

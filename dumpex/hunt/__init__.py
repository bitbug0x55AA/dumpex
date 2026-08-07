"""Hunt command dispatcher."""
import os
import sys
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.core.memory import va_to_file_offset, prot_str
from dumpex.hunt._ui import _print_hunt_header, _status_text, NOT_EVALUATED, INCONCLUSIVE

from dumpex.hunt.injection  import _build_injection_report
from dumpex.hunt.injection.presentation import render as _render_injection_console
from dumpex.hunt.hollowing  import (_build_hollowing_report, _render_hollowing_console,
    _print_hollowing_pre_build_console)
from dumpex.hunt.stomping   import _build_stomping_report, _print_stomping_pre_build_console
from dumpex.hunt.stomping.presentation import render as _render_stomping_console
from dumpex.hunt.pipe       import _build_pipe_report, _print_pipe_pre_build_console
from dumpex.hunt.pipe.presentation import render as _render_pipe_console
from dumpex.hunt.cs_beacon  import (_build_cs_beacon_report, _print_cs_beacon_pre_build_console,
    _render_cs_beacon_post_build_console)
from dumpex.hunt.yara_hunt  import _build_yara_report, _render_yara_console
from dumpex.hunt.encoding   import (_build_encoding_report, _print_encoding_pre_build_console,
    _render_encoding_console)

from dumpex.hunt.injection.collect import _record_from_injection_report
from dumpex.hunt.hollowing          import _record_from_hollowing_report
from dumpex.hunt.stomping.collect  import _record_from_stomping_report
from dumpex.hunt.pipe.collect      import _record_from_pipe_report
from dumpex.hunt.cs_beacon.collect import _record_from_cs_beacon_report
from dumpex.hunt.yara_hunt.collect import _record_from_yara_report
from dumpex.hunt.encoding.collect  import _record_from_encoding_report

from dumpex.hunt.summary import build_hunt_summary
from dumpex.output.command_result import CommandResult
from dumpex.output.coverage import CoverageReport
from dumpex.output.records import HUNTERS


def _hunt_coverage_report(records: "list", summary: dict) -> CoverageReport:
    """The single, document-level `CommandResult.coverage` for `--hunt`
    -- required to be ONE CoverageReport instance, unlike the real
    per-hunter coverage detail (which already lives, in full, on each
    HunterRecord.coverage produced by collect_hunt() below). NOT derived
    from `summary` alone: `status` (DETECTED/INCONCLUSIVE/NOT_EVALUATED/
    NOT_DETECTED_IN_SCANNED_SCOPE) and `coverage.status` (complete/
    partial/not_evaluated) are independent dimensions on every
    HunterRecord -- a hunter can be DETECTED from a config/finding in one
    region while ANOTHER region failed to read or a required context
    source was missing, which is `status=DETECTED` with
    `coverage.status=partial` at the same time. `summary`'s own
    detected_count/inconclusive_count/not_evaluated_count are derived
    from `status` only (see build_hunt_summary()), so a DETECTED-with-
    partial-coverage record contributes to NONE of them -- deriving this
    document-level coverage from `summary` counts alone would silently
    report "complete" for a run that genuinely has an evidence gap. Every
    record's own `coverage.status` must be checked directly instead; this
    document-level rollup only needs to say whether anything was
    evaluated at all (not_evaluated), and whether EVERY selected hunter's
    own coverage was fully conclusive (complete) or not (partial) --
    never combining the individual CoverageReports themselves via
    dumpex.output.coverage.combine_coverage_reports(), since their source
    names (e.g. "memory_info") are not namespaced per hunter and
    legitimately disagree in meaning between hunters (pipe's own
    "memory_info" completeness rule is not cs-beacon's).

    `not_evaluated` here is exactly `summary["overall_status"] ==
    "NOT_EVALUATED"` -- the one relationship
    dumpex-output-v2.6.schema.json's own kind=="hunt" branch enforces as
    a biconditional between `coverage.status` and `summary.overall_status`.
    """
    if summary["overall_status"] == "NOT_EVALUATED":
        return CoverageReport(status="not_evaluated")
    if any(record.coverage.status != "complete" for record in records):
        return CoverageReport(status="partial")
    return CoverageReport(status="complete")


def collect_hunt(mf: MinidumpFile, selected: str, *, yara_dir: str = None,
                  ref_dir: str = None) -> CommandResult:
    """
    The v2.4 migration's `CommandResult`-producing entry point for
    `--hunt` (PR4) -- builds each SELECTED hunter's `Report` exactly
    ONCE, via that hunter's own `_build_*_report()`, and converts it
    straight to a `HunterRecord` via `_record_from_*_report()`. Never
    calls `_hunt_*()` or `collect_*_record()` -- both are thin compat
    wrappers that each build their OWN fresh Report, so calling either
    of them here (in addition to this function's own builder calls)
    would scan every selected hunter twice for one `--hunt` invocation.
    See each hunter's own `_build_*_report()`/`_record_from_*_report()`
    docstring pair for why a single Report safely feeds both a console
    consumer and this JSON-record consumer.

    `selected` is the `--hunt` argument: `"all"` or one of `HUNTERS`
    (the same contract `dumpex.hunt.summary.build_hunt_summary()`
    documents). Console rendering (the printed `--hunt` summary/detail)
    remains `cmd_hunt()`'s own separate concern in this module -- this
    function produces only the v2.4 JSON/CSV side and prints nothing.
    """
    valid = set(HUNTERS) | {"all"}
    if selected not in valid:
        raise ValueError(
            f"collect_hunt() got unknown selected={selected!r} -- must be 'all' or "
            f"one of {HUNTERS}")

    def _wanted(hunter: str) -> bool:
        return selected in (hunter, "all")

    records = []
    if _wanted("injection"):
        records.append(_record_from_injection_report(_build_injection_report(mf)))
    if _wanted("hollowing"):
        records.append(_record_from_hollowing_report(_build_hollowing_report(mf)))
    if _wanted("stomping"):
        records.append(_record_from_stomping_report(_build_stomping_report(mf, ref_dir=ref_dir)))
    if _wanted("pipe"):
        records.append(_record_from_pipe_report(_build_pipe_report(mf)))
    if _wanted("cs-beacon"):
        records.append(_record_from_cs_beacon_report(_build_cs_beacon_report(mf)))
    if _wanted("yara"):
        records.append(_record_from_yara_report(_build_yara_report(mf, rules_dir=yara_dir)))
    if _wanted("obfuscation"):
        records.append(_record_from_encoding_report(_build_encoding_report(mf)))

    summary = build_hunt_summary(records, selected=selected)
    return CommandResult(kind="hunt", records=records,
                          coverage=_hunt_coverage_report(records, summary), summary=summary)

def cmd_hunt(mf: MinidumpFile, ttp: str, verbose: bool = False, yara_dir: str = None,
             ref_dir: str = None, collect_records: bool = False):
    """Run TTP-specific detection playbooks, printing the console report
    exactly as always.

    `collect_records=True` (used by cli.py's `--hunt` branch, PR4) makes
    this function ALSO build the v2.4 `HunterRecord` for every selected
    hunter and return `(results, records)` instead of the bare `results`
    dict every existing caller already gets back unchanged. Each
    selected hunter's own `_build_*_report()` is still called EXACTLY
    ONCE either way -- this function has always called it directly
    (never through the `_hunt_*()`/`collect_*_record()` compat wrappers,
    which would each build their own separate Report), feeding that one
    Report to both this hunter's console-render function and, when
    `collect_records` is set, `_record_from_*_report()` too. See
    `collect_hunt()` above for the equivalent silent, JSON-only path
    used by any caller that doesn't want console output at all.

    The `--hunt all` console summary card's own "Overall: ..." line is
    derived from the exact same `dumpex.hunt.summary.build_hunt_summary()`
    reduction the JSON/CSV side uses (via the `summary` this function
    always computes internally, from the same `records` -- see that
    module's own docstring) -- not a second, independently-maintained
    any_hit/any_not_evaluated/any_inconclusive reduction, which could
    silently disagree with `result.summary.overall_status` if only one
    side's rule were ever updated. Per-hunter DISPLAY formatting (name/
    verdict color/score suffix/lead count) still reads from `results`,
    since that's each hunter's own presentation choice, not a
    cross-hunter reduction."""
    valid = {"injection", "hollowing", "stomping", "pipe", "cs-beacon", "yara", "obfuscation", "all"}
    if ttp not in valid:
        print(RED(f"[!] Unknown TTP '{ttp}'. Choose from: {', '.join(sorted(valid))}"))
        sys.exit(1)

    run_injection  = ttp in ("injection",  "all")
    run_hollowing  = ttp in ("hollowing",  "all")
    run_stomping   = ttp in ("stomping",   "all")
    run_pipe       = ttp in ("pipe",       "all")
    run_cs_beacon  = ttp in ("cs-beacon",  "all")
    run_yara       = ttp in ("yara",       "all")
    run_obfuscation   = ttp in ("obfuscation",   "all")

    results = {}
    # Built unconditionally (not gated by collect_records): the console
    # "--hunt all" summary card below needs the real HunterRecords too --
    # see this function's own docstring update on why the Overall line is
    # now derived from dumpex.hunt.summary.build_hunt_summary() rather
    # than a second, independently-computed reduction over `results`.
    # Each _record_from_*_report() call is a pure, cheap conversion of a
    # Report already built above (never a re-scan), so computing this
    # even for a caller that ignores the second return value costs
    # nothing worth gating.
    records = []

    if run_injection:
        report = _build_injection_report(mf)
        results["injection"] = _render_injection_console(report, verbose)
        records.append(_record_from_injection_report(report))
    if run_hollowing:
        _print_hollowing_pre_build_console()
        report = _build_hollowing_report(mf)
        results["hollowing"] = _render_hollowing_console(mf, report, verbose)
        records.append(_record_from_hollowing_report(report))
    if run_stomping:
        _print_stomping_pre_build_console()
        report = _build_stomping_report(mf, ref_dir=ref_dir)
        results["stomping"] = _render_stomping_console(report, verbose)
        records.append(_record_from_stomping_report(report))
    if run_pipe:
        _print_pipe_pre_build_console()
        report = _build_pipe_report(mf)
        results["pipe"] = _render_pipe_console(report, verbose)
        records.append(_record_from_pipe_report(report))
    if run_cs_beacon:
        # --hunt all always runs the full memory scan now — skipping it when
        # prior TTPs scored 0 meant a beacon could be present in a dump with
        # no injection/hollowing/stomping/pipe indicators (e.g. a beacon
        # sitting in ordinary-looking memory) and --hunt all would still
        # report "No TTP indicators found" without ever having looked.
        segs = _print_cs_beacon_pre_build_console(mf)
        report = _build_cs_beacon_report(mf)
        results["cs-beacon"] = _render_cs_beacon_post_build_console(report, segs, verbose)
        records.append(_record_from_cs_beacon_report(report))
    if run_yara:
        _print_hunt_header("YARA Memory Scan")
        report = _build_yara_report(mf, rules_dir=yara_dir)
        results["yara"] = _render_yara_console(report, verbose)
        records.append(_record_from_yara_report(report))
    if run_obfuscation:
        _print_encoding_pre_build_console()
        report = _build_encoding_report(mf)
        results["obfuscation"] = _render_encoding_console(report, verbose)
        records.append(_record_from_encoding_report(report))

    # The single cross-hunter reducer JSON (dumpex.hunt.cmd_hunt(...,
    # collect_records=True) -> cli.py), CSV, and this function's own
    # console summary card below all derive their overall
    # detected/inconclusive/not_evaluated classification from -- see
    # dumpex.hunt.summary.build_hunt_summary()'s own docstring. Computed
    # unconditionally (cheap: pure aggregation over already-built
    # records, no re-scan) even for a single-TTP run that never reads it.
    summary = build_hunt_summary(records, selected=ttp)

    # Rule provenance (path + sha256 of the rules.yaml that actually
    # produced these verdicts) is surfaced once, in --json meta.rules
    # (dumpex.ui.structured.StructuredOutput._rules_meta()) — not
    # duplicated here inside the hunt results themselves.

    # ── Sanitize for JSON serialization ───────────────────────────────────
    # CS beacon: convert int-keyed field dicts + bytes. Every OTHER key in
    # cfg (context_corroborated, cs_version_note, and anything added to
    # _hunt_cs_beacon's findings["configs"] entries in the future) is
    # passed through unchanged via `{**cfg, ...}` rather than hand-picked
    # field-by-field — a hand-reconstructed dict silently drops any field
    # this dispatcher doesn't already know about.
    if "cs-beacon" in results:
        safe_cfgs = []
        for cfg in results["cs-beacon"].get("configs", []):
            safe_fields = {}
            for fid, rec in cfg.get("fields", {}).items():
                raw = rec.get("raw", b"")
                safe_fields[str(fid)] = {
                    "name":  rec.get("name", ""),
                    "type":  rec.get("type", ""),
                    "raw":   raw.hex() if isinstance(raw, bytes) else str(raw),
                    "value": (rec["value"].hex()
                              if isinstance(rec.get("value"), bytes)
                              else rec.get("value")),
                }
            safe_cfgs.append({**cfg, "fields": safe_fields})
        results["cs-beacon"]["configs"] = safe_cfgs

    # YARA: bytes → hex in matched string data
    if "yara" in results:
        for match in results["yara"].get("matches", []):
            for sv in match.get("strings", []):
                if isinstance(sv.get("data"), bytes):
                    sv["data"] = sv["data"].hex()

    # Summary card for --hunt all
    if ttp == "all" and "yara" not in results:
        results["yara"] = {"matches": [], "score": 0, "rules_hit": [], "status": NOT_EVALUATED}
    if ttp == "all" and "obfuscation" not in results:
        results["obfuscation"] = {"score": 0, "status": NOT_EVALUATED}

    if ttp == "all":
        print(BOLD("══════════════════════════════════════════"))
        print(BOLD("  HUNT SUMMARY"))
        print(BOLD("══════════════════════════════════════════"))
        labels = {
            "injection": ("Process Injection",          results["injection"]["score"],  3),
            "hollowing": ("Process Hollowing",          results["hollowing"]["score"],
                          results["hollowing"].get("max_score", 2)),
            "stomping":  ("Module Stomping",            results["stomping"]["score"],   2),
            "pipe":      ("Named Pipe C2 / Lat. Move.", results["pipe"]["score"],       3),
            "cs-beacon": ("Cobalt Strike Beacon",       results["cs-beacon"]["score"],
                          results["cs-beacon"].get("max_score", 2)),
            "yara":      ("YARA Rules",                 results["yara"]["score"],       3),
            "obfuscation":  ("Obfuscation Detection",       results["obfuscation"]["score"],   2),
        }
        _LEVEL_COLOR = {"high": RED, "likely": RED, "possible": YELLOW, "clean": GREEN}
        for key, (name, score, max_score) in labels.items():
            hunt_result   = results.get(key, {})
            status        = hunt_result.get("status")
            verdict_level = hunt_result.get("verdict_level")   # phase-two hunters only
            if status == NOT_EVALUATED:
                verdict = _status_text(NOT_EVALUATED)
            elif status == INCONCLUSIVE:
                verdict = _status_text(INCONCLUSIVE)
            elif key == "yara" and score > 0:
                rules_hit = results["yara"].get("rules_hit", [])
                verdict = RED(f"RULES MATCHED: {', '.join(rules_hit[:4])}{'…' if len(rules_hit) > 4 else ''}")
            elif score == 0:
                verdict = GREEN("CLEAN")
            elif verdict_level is not None:
                # The hunter's OWN verdict_level, printed as-is — see
                # structured.py for why this must not be re-derived here
                # (score/max_score arithmetic previously disagreed with
                # what the same hunter's console output said elsewhere,
                # e.g. stomping 1/2 showing LIKELY on one and POSSIBLE on
                # the other for the identical finding).
                color = _LEVEL_COLOR.get(verdict_level, YELLOW)
                verdict = color(verdict_level.upper())
            elif score >= max_score - 1:
                verdict = RED("HIGH CONFIDENCE")
            else:
                verdict = YELLOW("POSSIBLE")
            if hunt_result.get("coverage_status") == "partial" and status not in (NOT_EVALUATED, INCONCLUSIVE):
                verdict += YELLOW("  [partial coverage]")
            suffix = (f"  ({score}/{max_score})" if key != "yara" else "")
            if key == "cs-beacon" and hunt_result.get("config_count"):
                suffix += f"  [{hunt_result['config_count']} config(s)]"
            # Surfaced regardless of status/score — a CLEAN or INCONCLUSIVE
            # line must not read as "nothing here" when unscored leads
            # (pipe names, C2 strings, shellcode patterns, ...) were
            # actually found for this TTP; see dumpex.hunt._finding
            # .lead_count/.review_priority (only set for hunters on the
            # shared Finding model — legacy yara_hunt has neither, so
            # this is silently a no-op for it via .get()).
            lead_n = hunt_result.get("lead_count") or 0
            if lead_n:
                prio = hunt_result.get("review_priority")
                suffix += YELLOW(f"  [{lead_n} lead(s)"
                                  + (f", review: {prio}" if prio and prio != "none" else "")
                                  + "]")
            print(f"  {name:<25} {verdict}{suffix}")
        print()
        # Derived from the SAME build_hunt_summary() reduction the JSON/CSV
        # side uses (see this function's own `summary` computation above)
        # -- not a second, independently-computed any_hit/any_not_evaluated/
        # any_inconclusive reduction over `results`, which could silently
        # disagree with summary.overall_status if either reduction's rule
        # changed without the other. overall_status is one of DETECTED/
        # INCONCLUSIVE/NOT_EVALUATED/NOT_DETECTED_IN_SCANNED_SCOPE (see
        # build_hunt_summary()'s own docstring).
        overall_status = summary["overall_status"]
        if overall_status == "DETECTED":
            print(YELLOW("  Overall: One or more TTPs detected. Run --report for deep-dive."))
        elif overall_status in (INCONCLUSIVE, NOT_EVALUATED):
            print(YELLOW("  Overall: No TTPs detected in what was scanned, but coverage is "
                          "incomplete — one or more checks were NOT EVALUATED or INCONCLUSIVE "
                          "(see per-TTP status above). This is not a clean bill of health."))
        else:
            print(GREEN("  Overall: No TTP indicators found in this dump."))
        print()

    if collect_records:
        return results, records
    return results


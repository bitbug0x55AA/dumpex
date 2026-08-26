"""Named-pipe C2 hunter centered on captured handle evidence.

A HandleDataStream pipe object proves the process held the pipe at dump time and
is the primary scored signal. Memory strings are unscored leads: they can locate
names and nearby context but may be stale, copied, or decoy data. Framework
naming on a string does not convert it into handle evidence. Thread StartAddress
proximity is also a lead because it does not show current execution.

Pipe-name and C2-context scans have independent whole-hunt budgets; exhaustion,
failed reads, and short reads produce partial coverage.
"""
import time
from minidump.minidumpfile import MinidumpFile
from dumpex.rules_pkg.loader import get_rules, get_rules_source_info
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, get_thread_contexts, get_handles, read_region)
from dumpex.hunt._coverage import CoverageTracker
from dumpex.hunt._budget import ScanBudget
from dumpex.hunt._runtime import HunterRuntime

from dumpex.hunt.pipe.config import (PIPE_CONTEXT_DISTANCE,
    PIPE_C2_BUDGET_MAX_HITS, PIPE_C2_BUDGET_MAX_RETAINED, PIPE_C2_BUDGET_TIME_SECONDS,
    PIPE_NAME_BUDGET_MAX_HITS, PIPE_NAME_BUDGET_MAX_RETAINED, PIPE_NAME_BUDGET_TIME_SECONDS)
from dumpex.hunt.pipe import handle_scan as handle_scan_mod
from dumpex.hunt.pipe import memory_scan
from dumpex.hunt.pipe import correlation
from dumpex.hunt.pipe.aggregate import build_report
from dumpex.hunt.pipe import report_console, report_legacy


def _build_pipe_report(mf: MinidumpFile):
    """Run the scan/correlate/aggregate pipeline and return the immutable
    `dumpex.hunt.pipe.domain.PipeReport` -- the ONE place this pipeline is
    assembled, and it runs EXACTLY ONCE per call. Prints nothing at all
    (see `_hunt_pipe()`/`collect_hunt()` for the console/typed-record
    consumers of the same Report)."""
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    infos   = get_thread_infos(mf)
    thread_contexts = get_thread_contexts(mf)
    handles = get_handles(mf)
    mem_info_available    = bool(mf.memory_info and mf.memory_info.infos)
    # Stream PRESENCE, not "the handle list happens to be non-empty" — a
    # dump captured with MiniDumpWithHandleData can legitimately show a
    # process holding zero pipe handles (or, in principle, zero handles at
    # all); that is a checked-and-clean result, not "the stream is
    # missing". Only `mf.handles is None` means the stream itself wasn't
    # captured, and only THAT should report a coverage gap.
    handle_stream_available = mf.handles is not None

    # Pipe attribution and C2 context patterns loaded from rules.yaml.
    # Each KNOWN_FRAMEWORK_PIPES entry: (compiled_regex, framework, technique, mitre)
    _r                    = get_rules(announce=False)
    KNOWN_FRAMEWORK_PIPES = _r["framework_pipes"]
    C2_PAT                = _r["pipe_c2_context_patterns"]
    # The loaded ruleset's own CONTENT hash -- the one real, non-fabricated
    # rule_version this hunter can attach to the
    # `pipe.handle_framework_match` detection, since that specific check's
    # evidence IS a framework_pipes entry from this exact ruleset.
    # Deliberately NOT rules.yaml's own top-level "version:" field: that is
    # an explicit FORMAT/schema version ("bump when schema changes", per
    # rules.yaml's own comment), not a content version -- editing a pipe
    # pattern or a MITRE mapping leaves it unchanged, so using it here
    # would silently report the same rule_version for materially different
    # detection content (a prior version of this code did exactly that).
    # "sha256" is None only for the packaged built-in defaults (no real
    # file was loaded at all) -- rule_version correctly stays None there
    # too, rather than reporting a version for a ruleset that was never
    # actually read from disk. get_rules() was just called above, so
    # get_rules_source_info() is guaranteed populated here.
    _rules_source = get_rules_source_info()
    RULE_VERSION  = _rules_source["sha256"] if _rules_source else None

    # `read_region` is looked up HERE (this module's own re-exported,
    # still-monkeypatchable global) rather than imported separately inside
    # memory_scan.py — see dumpex/hunt/_runtime.py and this package's own
    # docstring above for why.
    runtime = HunterRuntime(read_region=read_region)

    # ── Primary, scored: handle objects ──────────────────────────────────
    hscan = handle_scan_mod.scan_handles(handles, KNOWN_FRAMEWORK_PIPES)

    # ── Collect all pipe name occurrences (string scan — lead only), plus
    # C2-context records for regions that yielded one. TWO INDEPENDENT
    # whole-hunt budgets — see dumpex/hunt/pipe/config.py for why they
    # must never be merged. Both are ordinary mutable accumulators that
    # live only for the duration of this call: `scan_pipe_names()` freezes
    # them into an immutable `PipeScanCoverage` before returning, so
    # neither the tracker nor either budget is reachable from the Report.
    coverage_counts = CoverageTracker()
    c2_budget = ScanBudget(
        max_bytes_read=PIPE_C2_BUDGET_MAX_RETAINED * 4,
        max_attempts=10**9,   # matching is cheap regex work, not the resource
                               # this budget bounds — hits/retained-bytes are
        max_retained_bytes=PIPE_C2_BUDGET_MAX_RETAINED,
        max_hits=PIPE_C2_BUDGET_MAX_HITS,
        deadline=time.monotonic() + PIPE_C2_BUDGET_TIME_SECONDS,
    )
    # Separate budget for pipe-NAME collection itself (the raw material
    # every handle-correlation check needs) — independent of c2_budget,
    # which only bounds C2-context gathering.
    pipe_name_budget = ScanBudget(
        max_bytes_read=PIPE_NAME_BUDGET_MAX_RETAINED * 4,
        max_attempts=10**9,
        max_retained_bytes=PIPE_NAME_BUDGET_MAX_RETAINED,
        max_hits=PIPE_NAME_BUDGET_MAX_HITS,
        deadline=time.monotonic() + PIPE_NAME_BUDGET_TIME_SECONDS,
    )
    pname_scan = memory_scan.scan_pipe_names(
        mf, runtime.read_region, regions, modules, coverage_counts, pipe_name_budget, c2_budget, C2_PAT)

    # Correlation is the last thing that needs the raw thread-context
    # dicts/ThreadInfo entries -- every call below returns typed Evidence,
    # so `build_report` never sees them.
    corr = correlation.correlate(hscan, pname_scan, thread_contexts, infos, modules,
                                  regions, KNOWN_FRAMEWORK_PIPES, PIPE_CONTEXT_DISTANCE)

    scan_coverage = pname_scan.coverage
    return build_report(
        hscan.handles, pname_scan.string_leads,
        corr.corroborated_handles, corr.start_address_leads,
        corr.c2_context, corr.framework_string_hits, corr.unbacked_threads,
        memory_info_stream=mem_info_available, handle_data_stream=handle_stream_available,
        skipped_oversize=scan_coverage.skipped_oversize_targets,
        read_failed=scan_coverage.read_failed,
        read_failed_targets=scan_coverage.read_failed_targets,
        short_reads=scan_coverage.short_reads,
        short_read_targets=scan_coverage.short_read_targets,
        c2_budget_exhausted=scan_coverage.c2_budget_exhausted,
        c2_budget_reason=scan_coverage.c2_budget_reason,
        pipe_name_budget_exhausted=scan_coverage.pipe_name_budget_exhausted,
        pipe_name_budget_reason=scan_coverage.pipe_name_budget_reason,
        image_pipe_refs=scan_coverage.image_pipe_refs,
        image_pipe_modules=scan_coverage.image_pipe_modules,
        rule_version=RULE_VERSION)


def _hunt_pipe(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Detect Named Pipe C2 / Lateral Movement channels.

    Primary (scored):
      HandleDataStream entries for open pipe handles, matched against
      known C2/lateral-movement framework naming conventions (rules.yaml
      framework_pipes), and the corroboration of a handle-confirmed pipe
      by C2 artifacts (IP:port, HTTP URLs) or live execution (current
      RIP/EIP) within PIPE_CONTEXT_DISTANCE of a same-named string
      occurrence's own address.

    Secondary (leads, never scored):
      The memory-string "\\pipe\\" scan — kept for coverage when
      HandleDataStream is unavailable and to locate the regions
      corroboration correlates against, but a bare string match is never,
      by itself, evidence of anything (see package docstring). A
      handle-confirmed pipe's unbacked thread StartAddress proximity (as
      opposed to current RIP/EIP) is also a LOW-confidence lead only.

    Nothing prints before `_build_pipe_report()` returns:
    `report_console.render_console_lines` is a pure post-hoc projection of
    the already-built Report (see this package's own docstring on where
    the old header/check-line prints went).
    """
    report = _build_pipe_report(mf)
    return _render_pipe_console(report, verbose)


def _render_pipe_console(report, verbose: bool = False) -> dict:
    """Render the console report for an ALREADY-BUILT `PipeReport`,
    returning the same v1.1-shaped findings dict `_hunt_pipe()` always
    has -- extracted so `dumpex.hunt.cmd_hunt()`'s console+JSON
    orchestrator can feed ONE built Report to both this and
    `_record_from_pipe_report()` without scanning twice."""
    report_console.print_console(report, verbose)
    return report_legacy.project_legacy_dict(report)

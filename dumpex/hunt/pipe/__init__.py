"""Named pipe C2 hunter.

Phase-two detection model
──────────────────────────
The primary, scored signal is now **handle objects**, not string
scanning. HandleDataStream (when the dump was captured with
MiniDumpWithHandleData) records the OS's own account of every open
handle the process held, including .TypeName ("File" for a pipe handle)
and .ObjectName (the actual kernel object name, e.g.
"\\Device\\NamedPipe\\mypipe") — proof the process actually opened that
pipe, not just that the bytes "\\pipe\\mypipe" happen to sit somewhere in
its memory (which could be freed heap, a copy-pasted string, a decoy, or
data belonging to something else entirely).

The original memory-string scan for "\\pipe\\" occurrences is still run
— it is the only way to find a pipe name in a dump with no
HandleDataStream, and it is genuinely useful for locating nearby C2
context (URLs/IPs) and correlating execution — but per phase-two policy
it is explicitly demoted: a bare string match, on its own, is reported as
a `tag="lead"` / LOW-confidence finding and does NOT contribute to
`score`. Only a handle-object match — optionally corroborated by a
same-named string hit's surrounding C2 context or by a thread executing
in that string's region — can raise the verdict.

This is a package, not a single file: handle_scan.py collects
HandleDataStream facts; memory_scan.py collects the '\\pipe\\' string
scan and C2-context records (see its own docstring for why the two
whole-hunt budgets it applies, pipe-name and C2-context, must stay
independent); correlation.py establishes handle/string/thread/proximity
relationships between those facts; patterns.py holds the shared
canonicalization/regex/streaming-match helpers; aggregate.py is the ONE
place score/status/coverage_status/verdict_level/confidence/lead_count/
review_priority get computed; presentation.py is the ONE place FINAL-
RESULT console output (findings, coverage-gap notes, the verdict line)
gets rendered, once the scan is done and a Report exists to render. None
of handle_scan.py/memory_scan.py/correlation.py/aggregate.py ever print
anything, under any circumstance. This __init__.py is the thin entry
point: it is also where the hunt header prints, before any scanning
starts.

The stable contract is `_hunt_pipe` itself (imported by
dumpex/hunt/__init__.py): same signature, same fields, same score/status/
coverage/JSON shape as before this package split — this refactor only
changes internal structure. `read_region`/`get_thread_contexts` are
re-exported here and remain monkeypatchable (`pipe.read_region = fake`
before calling `_hunt_pipe()` still changes its behavior — see
dumpex/hunt/_runtime.py) because they are threaded explicitly/looked up
fresh at call time rather than each submodule importing its own separate
copy. Private per-step helper functions (`_is_pipe_handle`,
`_extract_pipe_name`, etc.) are NOT re-exported here and make no
compatibility promise at all — import them from their actual module
(dumpex.hunt.pipe.handle_scan/.memory_scan/...) if you need them
directly.
"""
import time
from minidump.minidumpfile import MinidumpFile
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, get_thread_contexts, get_handles, read_region)
from dumpex.hunt._ui import _print_hunt_header
from dumpex.hunt._coverage import CoverageTracker
from dumpex.hunt._budget import ScanBudget
from dumpex.hunt._runtime import HunterRuntime
from dumpex.output.coverage import (
    build_coverage_report, observe_source, EvaluationRequirement, CoverageLimitation,
    LimitationCode,
)

from dumpex.hunt.pipe.config import (PIPE_CONTEXT_DISTANCE,
    PIPE_C2_BUDGET_MAX_HITS, PIPE_C2_BUDGET_MAX_RETAINED, PIPE_C2_BUDGET_TIME_SECONDS,
    PIPE_NAME_BUDGET_MAX_HITS, PIPE_NAME_BUDGET_MAX_RETAINED, PIPE_NAME_BUDGET_TIME_SECONDS)
from dumpex.hunt.pipe import handle_scan as handle_scan_mod
from dumpex.hunt.pipe import memory_scan
from dumpex.hunt.pipe import correlation
from dumpex.hunt.pipe import aggregate
from dumpex.hunt.pipe import presentation


def _pipe_coverage_report(mem_info_available, handle_stream_available, coverage_counts,
                           c2_budget, pipe_name_budget):
    """Real dumpex.output.coverage.CoverageReport for a pipe run -- built
    at each gap site aggregate.build_report() already derives
    coverage_status/coverage_reasons from. `memory_info`/`handle_data` are
    ONE combined evaluation_sources group (OR-of-presence, matching this
    hunter's own `evaluated = mem_info_available or handle_stream_
    available`) -- unlike stomping's AND-of-presence, which needs two
    independent groups instead (see that hunter's own
    _stomping_coverage_report)."""
    sources = {
        "memory_info": observe_source("memory_info", present=mem_info_available,
                                       items=["present"] if mem_info_available else []),
        "handle_data": observe_source("handle_data", present=handle_stream_available,
                                       items=["present"] if handle_stream_available else []),
        # Synthetic, always-present source (the scan attempt itself, not
        # an optional minidump stream) -- mirrors injection's own
        # "hidden_pe_scan" pattern, purely so the SCAN_REGION_*/
        # SCAN_BUDGET_EXHAUSTED limitations below have a source key to
        # attach to and validate against.
        "pipe_name_scan": observe_source("pipe_name_scan", present=True, items=["scanned"]),
    }
    # "memory_info" is deliberately NOT a completeness_check: this
    # hunter's own `complete = handle_stream_available and coverage_
    # counts.complete and not budget_exhausted` never consults mem_info_
    # available at all (only `evaluated` does, via the combined group
    # above) -- adding it here would make memory_info's absence alone
    # flip coverage.status to "partial" even when the real v1.1
    # coverage_status still says "complete" (confirmed by
    # tests/hunt/test_pipe_collect.py::test_empty_handle_stream_is_
    # complete_clean, which is memory_info-present but would regress if
    # this were reintroduced with memory_info absent instead).
    completeness_checks = ["handle_data"]
    if coverage_counts.skipped_oversize:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="pipe_name_scan",
            affected_count=coverage_counts.skipped_oversize))
    if coverage_counts.read_failed:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source="pipe_name_scan",
            affected_count=coverage_counts.read_failed))
    if coverage_counts.short_reads:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source="pipe_name_scan",
            affected_count=coverage_counts.short_reads))
    if c2_budget.exhausted():
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source="pipe_name_scan",
            scope="c2_context", detail=c2_budget.exhausted_reason))
    if pipe_name_budget.exhausted():
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SCAN_BUDGET_EXHAUSTED, source="pipe_name_scan",
            scope="pipe_name", detail=pipe_name_budget.exhausted_reason))

    return build_coverage_report(
        sources, evaluation_sources=EvaluationRequirement(("memory_info", "handle_data")),
        completeness_checks=completeness_checks)


def _build_pipe_report(mf: MinidumpFile):
    """Run the scan/correlate/aggregate pipeline and return the
    aggregate.Report -- the ONE place this pipeline is assembled, shared
    by `_hunt_pipe()` (console path, below) and `collect_pipe_record()`
    (the v2.4 migration's HunterRecord-producing path). Prints nothing at
    all (see `_hunt_pipe()`/`collect_hunt()` for the two console/typed-
    record consumers of the same Report -- PR4 of the `--hunt` v2.4
    migration unified every hunter onto this build-once, multiple-
    consumers shape)."""
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
    # captured, and only THAT should report "NOT AVAILABLE".
    handle_stream_available = mf.handles is not None

    # Pipe attribution and C2 context patterns loaded from rules.yaml.
    # Each KNOWN_FRAMEWORK_PIPES entry: (compiled_regex, framework, technique, mitre)
    _r                    = get_rules(announce=False)
    KNOWN_FRAMEWORK_PIPES = _r["framework_pipes"]
    C2_PAT                = _r["pipe_c2_context_patterns"]

    # `read_region` is looked up HERE (this module's own re-exported,
    # still-monkeypatchable global) rather than imported separately inside
    # memory_scan.py — see dumpex/hunt/_runtime.py and this package's own
    # docstring above for why.
    runtime = HunterRuntime(read_region=read_region)

    # ── Check A (primary, scored): handle objects ────────────────────────
    hscan = handle_scan_mod.scan_handles(handles, KNOWN_FRAMEWORK_PIPES)

    # ── Collect all pipe name occurrences (string scan — lead only), plus
    # C2-context records for regions that yielded one. TWO INDEPENDENT
    # whole-hunt budgets — see dumpex/hunt/pipe/config.py for why they
    # must never be merged.
    coverage_counts = CoverageTracker()
    c2_budget = ScanBudget(
        max_bytes_read=PIPE_C2_BUDGET_MAX_RETAINED * 4,
        max_attempts=10**9,   # matching is cheap regex work, not the resource
                               # this budget bounds — hits/retained-bytes are
        max_retained_bytes=PIPE_C2_BUDGET_MAX_RETAINED,
        max_hits=PIPE_C2_BUDGET_MAX_HITS,
        deadline=time.monotonic() + PIPE_C2_BUDGET_TIME_SECONDS,
    )
    # Separate budget for pipe-NAME collection itself (Check A/C/D's raw
    # material) — independent of c2_budget, which only bounds Check B.
    pipe_name_budget = ScanBudget(
        max_bytes_read=PIPE_NAME_BUDGET_MAX_RETAINED * 4,
        max_attempts=10**9,
        max_retained_bytes=PIPE_NAME_BUDGET_MAX_RETAINED,
        max_hits=PIPE_NAME_BUDGET_MAX_HITS,
        deadline=time.monotonic() + PIPE_NAME_BUDGET_TIME_SECONDS,
    )
    pname_scan = memory_scan.scan_pipe_names(
        mf, runtime.read_region, regions, modules, coverage_counts, pipe_name_budget, c2_budget, C2_PAT)

    corr = correlation.correlate(hscan, pname_scan, thread_contexts, infos, modules,
                                  regions, KNOWN_FRAMEWORK_PIPES, PIPE_CONTEXT_DISTANCE)

    report = aggregate.build_report(mf, hscan, pname_scan, corr, mem_info_available,
                                     handle_stream_available)
    report.coverage_report = _pipe_coverage_report(
        mem_info_available, handle_stream_available, coverage_counts, c2_budget, pipe_name_budget)
    return report


def _hunt_pipe(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Detect Named Pipe C2 / Lateral Movement channels.

    Primary (scored):
      Check A — HandleDataStream entries for open pipe handles, matched
                against known C2/lateral-movement framework naming
                conventions (rules.yaml framework_pipes).
      Check B — Corroboration of a handle-confirmed pipe: C2 artifacts
                (IP:port, HTTP URLs) or live execution (current RIP/EIP)
                found in the memory region backing a same-named string
                occurrence, when one exists.

    Secondary (leads, not scored):
      Memory-string "\\pipe\\" scan — kept for coverage when
      HandleDataStream is unavailable and to locate the regions Check B
      correlates against, but a bare string match is never, by itself,
      evidence of anything (see package docstring). A handle-confirmed
      pipe's unbacked thread StartAddress proximity (as opposed to
      current RIP/EIP) is also reported here as a LOW-confidence lead
      only — it records where a thread BEGAN, not where it is executing
      now, so it never contributes to score (see
      pipe.start_address_proximity_lead).

    The header print below happens BEFORE the (now fully silent)
    `_build_pipe_report()` call rather than inside it -- console output
    is only ever observed as one fully-captured block (never mid-run) by
    anything that checks it, so this reordering changes nothing any
    consumer can see. `get_rules()` is called here too, redundantly,
    before the header print, for the same reason
    dumpex.hunt.stomping's own console wrapper does -- it prints a
    one-time "Rules loaded from ..." line the FIRST time it's ever
    called in a process, and the pre-split function called it before
    printing the header; the builder calls it again internally (a cheap
    cache hit after the first real load, see
    dumpex.rules_pkg.loader.get_rules), so this preserves that print
    order without the builder itself printing anything.
    """
    _print_pipe_pre_build_console()
    report = _build_pipe_report(mf)
    return presentation.render(report, verbose)


def _print_pipe_pre_build_console() -> None:
    """The header print, extracted so `dumpex.hunt.collect_hunt()`'s
    console+JSON orchestrator (see that function's own docstring) can
    print the exact same line `_hunt_pipe()` does, BEFORE calling
    `_build_pipe_report()` itself, without duplicating this print (and
    its `get_rules()` print-ordering fix, see `_hunt_pipe()`'s own
    docstring) as a second copy."""
    get_rules()
    _print_hunt_header("Named Pipe C2 / Lateral Movement")

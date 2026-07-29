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

from dumpex.hunt.pipe.config import (PIPE_CONTEXT_DISTANCE,
    PIPE_C2_BUDGET_MAX_HITS, PIPE_C2_BUDGET_MAX_RETAINED, PIPE_C2_BUDGET_TIME_SECONDS,
    PIPE_NAME_BUDGET_MAX_HITS, PIPE_NAME_BUDGET_MAX_RETAINED, PIPE_NAME_BUDGET_TIME_SECONDS)
from dumpex.hunt.pipe import handle_scan as handle_scan_mod
from dumpex.hunt.pipe import memory_scan
from dumpex.hunt.pipe import correlation
from dumpex.hunt.pipe import aggregate
from dumpex.hunt.pipe import presentation


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
    """
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
    _r                    = get_rules()
    KNOWN_FRAMEWORK_PIPES = _r["framework_pipes"]
    C2_PAT                = _r["pipe_c2_context_patterns"]

    _print_hunt_header("Named Pipe C2 / Lateral Movement")

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

    return presentation.render(report, verbose)

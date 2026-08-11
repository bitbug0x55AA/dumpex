"""Process hollowing / image-base mismatch hunter.

Detection model
───────────────
Every check is anchored on ONE address: the image base the process's own
PEB reports for its main module. Two STRUCTURAL ANCHORS, each meaningful
alone but each with a plausible benign explanation in isolation:

  1. The memory backing that base is not MEM_IMAGE — nothing was mapped
     from the executable file this process is supposed to be running.
  2. The MZ/DOS header at that base is missing or zeroed — no valid PE
     header where one is expected.

Two CORROBORATORS — weak on their own (RWX/JIT-style memory and name/case/
redirection comparisons are routinely benign):

  3. The image base memory is RWX (what writing replacement code needs).
  4. The PEB's ImagePath name doesn't match the module list's own name for
     this base address (or the base isn't in the module list at all).

DETECTED requires CORRELATION, not a single flag: anchor 1 (MEM_PRIVATE)
firing together with EITHER anchor 2 (MZ wiped) or corroborator 3 (RWX) —
mirroring dumpex/hunt/injection/'s own RWX+hidden-PE same-allocation
requirement. Score 1 for that pair, 2 when all three correlate at once. A
single signal alone — including either anchor by itself, and corroborator 4
in any combination — is reported as a LEAD, not a detection; see
dumpex.hunt._finding.review_priority for how it still surfaces for an
analyst at score 0. Corroborator 4 never contributes to the score at all:
DLL redirection, WoW64 path differences, and capture-time races all produce
it benignly (see correlation.py).

Coverage is per-check, not per-hunter: the PEB's own absence means nothing
ran (NOT_EVALUATED), while an uncaptured image-base page, a failed header
read, or a missing ModuleListStream each disable a different subset of the
four checks and make the run "partial" — at score 0 that is INCONCLUSIVE,
never a bare "checked and clean". See domain.CoverageSnapshot.

This is a package, not a single file, and since the canonical-Report
migration (issue #10) it has the same shape as dumpex/hunt/injection/,
dumpex/hunt/encoding/, dumpex/hunt/stomping/, and dumpex/hunt/pipe/ (the
four completed reference pilots):

  config.py         — the header read's size, its minimum usable length,
                       and the display preview bound.
  models.py         — the immutable Evidence value objects every layer
                       below produces; the ONE place a raw `Module`/
                       `MinidumpMemoryInfo`/`mf.peb` is snapshotted, and
                       the ONE place the image base's .dmp file offset,
                       `prot_str()` protection text, and module basename
                       get resolved.
  memory_scan.py    — the image-base region lookup, the single MZ/DOS-
                       header read and its classification, and the
                       observation of which of the four anchors/
                       corroborators actually fired.
  correlation.py    — the ONE statement of this hunter's correlation
                       requirement (which observations relate to each
                       other), separate from turning that into a score.
  domain.py         — `HollowingReport`/`HollowingEvidence`/
                       `CoverageSnapshot`: the canonical, recursively
                       immutable result.
  aggregate.py      — the ONE place score/coverage/the five CheckResults
                       get computed. Takes typed evidence + scalars only.
  report_console.py — the ONE place console output is rendered, as a pure
                       post-hoc projection of an already-built Report.
  report_facts.py   — the fact strings + coverage projections the other
                       three projectors share.
  report_legacy.py  — `HollowingReport` -> the v1.1 findings dict.
  report_record.py  — `HollowingReport` -> the typed `HunterRecord`.
  collect.py        — the thin `collect_hollowing_record()` compat wrapper.

This __init__.py is the thin entry point: it holds the process
ORCHESTRATION (load rules and streams, resolve the image-base context once,
observe the four signals, correlate, aggregate once), then hands the one
built Report to whichever projector the caller wants.

Nothing prints before the Report exists any more. The pre-migration
`_print_hollowing_pre_build_console()` — an ANNOUNCING `get_rules()` call
whose entire purpose was to order its one-time "Rules loaded from ..." line
BEFORE the hunt header the renderer printed after the builder had already
run — is gone entirely, following dumpex.hunt.stomping's and
dumpex.hunt.pipe's own resolution of the identical problem:
`report_console.render_console_lines` emits the header itself via
`dumpex.hunt._report_console.header_lines()`, and the builder's own
`get_rules(announce=False)` call is now the only one this hunter makes. As
a consequence `--hunt all` no longer prints a "Rules loaded from ..." line
at all — hollowing was the last hunter still announcing it, which is
exactly what stomping's and pipe's own package docstrings recorded as the
remaining case. Rule PROVENANCE is unaffected: it is reported in --json
`meta.rules` from `dumpex.rules_pkg.loader.get_rules_source_info()`, which
`get_rules(announce=False)` populates exactly the same way.

The stable contract is `_hunt_hollowing` itself (imported by
dumpex/hunt/__init__.py): same signature, same fields, same score/status/
coverage/JSON shape. `read_region` is re-exported here and remains
monkeypatchable (`hollowing.read_region = fake` before calling
`_hunt_hollowing()` still changes its behavior — see dumpex/hunt/_runtime.py)
because it is threaded explicitly into memory_scan.py rather than imported
separately there. Private per-step helpers (`find_image_base_region`,
`collect_signals`, ...) are NOT re-exported here and make no compatibility
promise at all — import them from their actual module
(dumpex.hunt.hollowing.memory_scan/.models/...) if you need them directly.
"""
from minidump.minidumpfile import MinidumpFile
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import get_modules, get_memory_regions, read_region
from dumpex.hunt._runtime import HunterRuntime

from dumpex.hunt.hollowing import correlation
from dumpex.hunt.hollowing import memory_scan
from dumpex.hunt.hollowing.aggregate import build_report
from dumpex.hunt.hollowing import report_console, report_legacy


def _build_hollowing_report(mf: MinidumpFile):
    """Run the resolve/observe/correlate/aggregate pipeline and return the
    immutable `dumpex.hunt.hollowing.domain.HollowingReport` -- the ONE
    place this pipeline is assembled, and it runs EXACTLY ONCE per call.
    Prints nothing at all (see `_hunt_hollowing()`/`collect_hunt()` for the
    console/typed-record consumers of the same Report).

    `get_modules`/`get_memory_regions`/`get_rules(announce=False)` run
    unconditionally, BEFORE the `peb` check below, matching the pre-split
    function's own exact order: `get_rules()` is what populates
    `get_rules_source_info()` for --json `meta.rules`, and moving it behind
    the early return would silently drop rule provenance from a PEB-less
    dump's own output. `announce=False`: this function must stay silent
    (see dumpex.hunt.collect_hunt()'s own docstring on why), and since this
    migration it is the ONLY `get_rules()` call this hunter makes at all.
    """
    modules = get_modules(mf)
    # `get_modules()` returns [] both when ModuleList is entirely missing/
    # empty AND when it's present but genuinely has no entry for this
    # address -- those are different coverage situations for check 4 (the
    # first means the check never actually ran; the second is a real
    # signal), and only this flag can tell them apart.
    modules_available = bool(mf.modules and mf.modules.modules)
    regions = get_memory_regions(mf)
    suspicious_protections = get_rules(announce=False)["suspicious_protections"]

    peb = mf.peb
    if not peb:
        # Every default on `build_report` is the "nothing was observed"
        # value, so the NOT_EVALUATED result is this one call -- not a
        # twenty-argument `Report(...)` literal restating it by hand.
        return build_report()

    # `read_region` is looked up HERE (this module's own re-exported,
    # still-monkeypatchable global) rather than imported separately inside
    # memory_scan.py -- see dumpex/hunt/_runtime.py and this package's own
    # docstring above for why.
    runtime = HunterRuntime(read_region=read_region)

    context = memory_scan.resolve_image_base_context(
        mf, runtime.read_region, peb, regions, modules)
    mem_private, wiped_headers, rwx, name_mismatches = memory_scan.collect_signals(
        context, suspicious_protections, modules_available=modules_available)
    correlations = correlation.correlate(mem_private, wiped_headers, rwx, context.image_base)

    return build_report(
        mem_private, wiped_headers, rwx, name_mismatches, correlations,
        context=context, peb_present=True,
        image_base_region_found=context.region is not None,
        mz_read_failed=context.header.read_failed,
        modules_available=modules_available)


def _hunt_hollowing(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Detect Process Hollowing by comparing the PEB's own image path and base
    address against the actual memory backing that address. See this
    package's docstring for the two anchors, two corroborators, and the
    correlation requirement DETECTED depends on.

    Nothing prints before `_build_hollowing_report()` returns:
    `report_console.render_console_lines` is a pure post-hoc projection of
    the already-built Report (see this package's own docstring on where the
    old pre-build `get_rules()` announcement and the four `_print_check`
    blocks went).
    """
    report = _build_hollowing_report(mf)
    return _render_hollowing_console(report, verbose)


def _render_hollowing_console(report, verbose: bool = False) -> dict:
    """Render the console report for an ALREADY-BUILT `HollowingReport`,
    returning the same v1.1-shaped findings dict `_hunt_hollowing()` always
    has -- extracted so `dumpex.hunt.cmd_hunt()`'s console+JSON orchestrator
    can feed ONE built Report to both this and
    `_record_from_hollowing_report()` without scanning twice.

    No `mf` parameter any more: everything this renders was resolved once,
    at scan time, onto `report.context` (see report_console.py's own
    docstring)."""
    report_console.print_console(report, verbose)
    return report_legacy.project_legacy_dict(report)

"""Process-hollowing hunter anchored on the PEB-reported image base.

A non-MEM_IMAGE backing and a missing MZ header are structural anchors. RWX
protection and a PEB/module-name mismatch are corroborators; name mismatch never
scores by itself. Detection requires a private image base together with a
missing header or RWX protection.

Coverage is per check: a missing PEB is not evaluated, while an uncaptured page,
failed header read, or unavailable module list disables only dependent checks.
At score zero, partial coverage is inconclusive rather than clean.
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

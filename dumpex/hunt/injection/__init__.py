"""Process-injection hunter for RWX memory, hidden PE images, and unbacked threads.

Signals correlate by allocation base because one allocation may be split into
regions with different protections. Current RIP/EIP captured in thread context
is stronger execution evidence than StartAddress, which records only where a
thread began.

Eligible non-module regions are searched throughout for MZ candidates. Each
candidate keeps its own VA and dump offset, then undergoes bounded structural PE
validation. MZ-only observations remain lower confidence than validated images.
Scan budgets cover bytes, validations, and retained evidence; any incomplete
search is reported as partial coverage rather than a clean result.
"""
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import get_memory_regions, read_region
from dumpex.hunt._runtime import HunterRuntime

from dumpex.hunt.injection import memory_scan
from dumpex.hunt.injection import thread_scan
from dumpex.hunt.injection import correlation
from dumpex.hunt.injection import aggregate
from dumpex.hunt.injection import report_console
from dumpex.hunt.injection import report_legacy


def _build_injection_report(mf: MinidumpFile):
    """Run the scan/correlate/aggregate pipeline and return the canonical
    `dumpex.hunt.injection.domain.InjectionReport` -- the ONE place this
    pipeline is assembled, shared by `_hunt_injection()` (console path,
    below) and `dumpex.hunt.injection.collect.collect_injection_record()`
    (the HunterRecord-producing path). Both consuming the exact same
    Report is what guarantees they can never compute a different
    score/status/coverage for the same input."""
    # RWX/hidden-PE need MemoryInfoListStream; unbacked-thread needs
    # ThreadInfoListStream; hidden-PE and unbacked-thread BOTH additionally
    # need ModuleListStream to tell known from unknown — computed first so
    # memory_scan._hunt_hidden_pe/thread_scan._hunt_unbacked_threads can
    # refuse to guess when it's missing, rather than treating every PE/
    # thread as suspicious by default.
    memory_info_stream = bool(mf.memory_info and mf.memory_info.infos)
    thread_info_stream = bool(mf.thread_info and mf.thread_info.infos)
    module_list_stream = bool(mf.modules and mf.modules.modules)
    thread_list_stream = bool(mf.threads and mf.threads.threads)

    regions = get_memory_regions(mf)
    # `read_region` is looked up HERE (this module's own re-exported,
    # still-monkeypatchable global) rather than imported separately inside
    # memory_scan.py — see dumpex/hunt/_runtime.py and this package's own
    # docstring above for why.
    runtime = HunterRuntime(read_region=read_region)

    rwx = memory_scan._hunt_rwx(mf)
    hidden_pe_scan = memory_scan._hunt_hidden_pe(
        mf, runtime.read_region, module_list_available=module_list_stream)
    validated_pe_hits, mz_only_hits = memory_scan.split_hidden_pe_hits(hidden_pe_scan)
    start_threads = thread_scan._hunt_unbacked_threads(mf, module_list_available=module_list_stream)
    thread_contexts = thread_scan.resolve_thread_contexts(mf)   # tuple[ThreadContext, ...]

    # Explicit counts so a PARTIAL context gap is visible even when it
    # doesn't zero out thread_context entirely (some threads parsed, some
    # didn't) — bare booleans can't distinguish "every thread's context
    # parsed" from "1 out of 200 did".
    threads_total   = len(mf.threads.threads) if (mf.threads and mf.threads.threads) else 0
    contexts_parsed = len(thread_contexts)

    correlation_result = correlation.correlate(
        rwx, validated_pe_hits, thread_contexts, start_threads, regions)

    # Record counts only -- computed HERE, at the scan boundary that still
    # has `mf`, so aggregate.build_report() itself never receives a raw
    # dump-derived list (mf.memory_info.infos/mf.thread_info.infos/
    # mf.modules.modules), only the resulting int.
    region_count      = len(regions)
    thread_info_count = len(mf.thread_info.infos) if thread_info_stream else 0
    module_count       = len(mf.modules.modules) if module_list_stream else 0

    return aggregate.build_report(
        rwx, hidden_pe_scan, validated_pe_hits, mz_only_hits, start_threads,
        thread_contexts, correlation_result, memory_info_stream, thread_info_stream,
        module_list_stream, thread_list_stream, threads_total, contexts_parsed,
        region_count=region_count, thread_info_count=thread_info_count,
        module_count=module_count)


def _render_injection_console(report, verbose: bool = False) -> dict:
    """Print the verdict-first console projection of `report`, then return
    the legacy v1.1 dict projection of the SAME `report` -- the ONE place
    both projections of an already-built Report happen together, for
    callers that need both (this module's own `_hunt_injection()`, and
    `dumpex.hunt.__init__.run_hunt()`, which also needs the printed console
    output and the returned dict from one already-built Report)."""
    report_console.print_console(report, verbose)
    return report_legacy.project_legacy_dict(report)


def _hunt_injection(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Detect classic process injection via AllocationBase + current RIP/EIP
    + page type + structural PE validation. Each signal alone can be
    noise; correlation by allocation and live execution raises confidence.
    Returns dict of findings for use in --hunt all summary.
    """
    return _render_injection_console(_build_injection_report(mf), verbose)

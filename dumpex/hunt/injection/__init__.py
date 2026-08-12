"""Process injection hunter (RWX / hidden PE / unbacked threads).

Phase-two correlation model
────────────────────────────
Signals are grouped and correlated by **AllocationBase** — the address a
single VirtualAlloc/VirtualAllocEx call originally reserved — rather than
by the BaseAddress of whichever individual MemoryInfo sub-region happened
to carry each signal. A single allocation routinely gets split into
several MemoryInfo entries with different protections after
VirtualProtect calls (header page, RW-then-reprotected-to-RX code page,
guard page, ...): an RWX signal on one sub-region and a hidden-PE header
on a different sub-region of the SAME allocation are one suspicious
allocation, not two unrelated observations that happen to be near each
other.

Thread execution correlation now prefers each thread's CURRENT
RIP/EIP — read from ThreadListStream's per-thread CONTEXT at the moment
the dump was captured (see core.memory.get_thread_contexts) — over
ThreadInfoListStream.StartAddress. StartAddress only tells you where a
thread BEGAN; RIP/EIP tells you where it IS, which is what actually
matters for "is this allocation being executed right now". Both are
still reported (StartAddress correlation is kept as a secondary,
lower-confidence signal), but only a live RIP/EIP landing inside a
suspicious allocation can reach HIGH confidence.

A "hidden PE" is not just a region beginning with the two bytes 'MZ' --
and it is no longer only looked for AT each region's base address either.
Every eligible (committed, not-inside-a-known-module) region is searched
for candidate 'MZ' headers at EVERY byte offset, so an image mapped
partway into a private or unbacked allocation -- behind loader metadata,
as one of several objects in the same allocation, or aligned to nothing in
particular -- is examined instead of being invisible because the region's
first two bytes were clean (issue #26). Each candidate keeps its OWN
address and file offset (see models.HiddenPeEvidence), which the current
schema's `huntPeHeaderHit` carries too, while correlation stays keyed on
the containing allocation's identity.

Searching everything makes the dump's own contents decide how much work
this hunter does, so that search runs under explicit budgets -- bytes
read, structural validations performed, evidence retained (see
config.py's PE_SCAN_* family and memory_scan._ScanBudget). What a budget
cut short is never silent: a region whose search stopped early is counted
in coverage (alongside failed and short reads) rather than reported as
clean, and candidates that were examined but not retained are stated,
with their count, on the check that would have listed them.

dumpex.core.pe_utils.parse_pe_header() structurally validates the
DOS header, PE signature, COFF file header (Machine/NumberOfSections),
optional header (PE32/PE32+ Magic), and the full section table before a
region counts as a validated hidden PE. A region with an 'MZ' prefix that
fails structural validation (truncated header, garbage Machine field,
implausible section count) is reported separately as a low-confidence
observation, not folded into the same bucket as a confirmed module.

Every reported item is a dumpex.hunt._finding.Finding — facts, inference,
confidence, rationale, limitations — so the distinction between "this
allocation shows page-type + PE-header + live-execution convergence"
(high confidence) and "an MZ-prefixed region exists somewhere, unrelated
to anything else" (low confidence) is explicit, not implied by wording.

This is a package, not a single file: memory_scan.py/thread_scan.py only
collect facts (RWX regions, hidden-PE candidates, unbacked threads,
resolved thread contexts) and never score or print; correlation.py
establishes AllocationBase/RIP/StartAddress relationships between those
facts; aggregate.py is the ONE place score/coverage/CheckResult get
computed, returning the canonical, immutable `dumpex.hunt.injection.
domain.InjectionReport`; report_console.py is the ONE place anything gets
printed to the console, as a pure projection of that Report (see
report_facts.py/report_legacy.py/report_record.py for the other
projections). This __init__.py is the thin entry point: run the scans,
correlate, aggregate, render, return the legacy findings dict.

The stable contract is `_hunt_injection` itself (imported by
dumpex/hunt/__init__.py): same signature, same fields, same score/status/
coverage/JSON shape as this package has always had -- internally, every
fact flows through one immutable `InjectionReport` rather than a
dict-keyed `Report` carrying parallel `findings`/`findings_list`
representations. `report_console.render_console_lines()`/`print_console()`
never hand a typed Evidence dataclass back to a caller:
`dumpex.hunt.injection.report_legacy.project_legacy_dict()` projects every
one of them into a plain, JSON-safe dict (stable field names --
base_address/allocation_base/size/type/protect for a region, etc. -- see
that module's own docstring) before `_hunt_injection()`/`cmd_hunt()`'s
bare `results["injection"]` return. `read_region` is re-exported here and
remains monkeypatchable (`injection.read_region = fake` before calling
`_hunt_injection()` still changes its behavior — see
dumpex/hunt/_runtime.py) because it is threaded explicitly into
memory_scan._hunt_hidden_pe rather than that module importing its own
separate copy. Private per-step helper functions (`_hunt_rwx`,
`_hunt_hidden_pe`, `_hunt_unbacked_threads`, `_region_for_addr`, etc.) are
NOT re-exported here and make no compatibility promise at all — import
them from their actual module (dumpex.hunt.injection.memory_scan/
.thread_scan/.correlation/...) if you need them directly, as this
package's own tests do.
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

"""Unbacked-thread (StartAddress) scan. Only collects facts."""
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import get_modules, get_thread_contexts, get_thread_infos, addr_to_module
from dumpex.hunt._location import resolve_location
from dumpex.hunt.injection.models import ThreadContext, UnbackedThreadEvidence


def _hunt_unbacked_threads(mf: MinidumpFile, module_list_available: bool = True) -> tuple:
    """
    Return tuple of UnbackedThreadEvidence -- each built here, at the scan
    boundary, WITH its file offset already resolved (see
    dumpex.hunt._location.resolve_location), so aggregate.py never needs
    `mf` or a separate ThreadId -> Location lookup table.

    Retained as a secondary signal; see dumpex/hunt/injection/__init__.py's
    module docstring for why current RIP/EIP is now the primary
    execution-correlation signal instead.

    Same reasoning as memory_scan._hunt_hidden_pe: without ModuleListStream,
    every thread would look "unbacked" regardless of whether it actually
    is — that's an absence-of-data artifact, not evidence of injection.

    StartAddress has no containing "region" the way an RWX/hidden-PE hit
    does, so region_base == lookup_address when resolving (region_offset
    trivially 0) -- see Location's own docstring on why that's still a
    valid Location.

    A ThreadInfo with StartAddress=None uses a 0-substituted LOCAL
    `lookup_address` for the addr_to_module() classification check and for
    Location resolution (matching this hunter's pre-Evidence-migration
    behavior) -- but the Evidence's own `start_address` field keeps the
    true, un-substituted value (including None). See
    UnbackedThreadEvidence's own docstring for why: silently storing the
    substituted 0 would make the v2.6 record report a fabricated "known"
    address where the correct wire value is `null`.
    """
    if not module_list_available:
        return ()
    modules = get_modules(mf)
    infos   = get_thread_infos(mf)
    hits = []
    for ti in infos:
        lookup_address = ti.StartAddress or 0
        if not addr_to_module(lookup_address, modules):
            hits.append(UnbackedThreadEvidence(
                thread_id=ti.ThreadId, start_address=ti.StartAddress,
                location=resolve_location(mf, lookup_address, lookup_address)))
    return tuple(hits)


def resolve_thread_contexts(mf: MinidumpFile) -> tuple:
    """`dumpex.core.memory.get_thread_contexts(mf)`'s raw
    `{"ThreadId", "ip", "ip_reg", "is_wow64"}` dicts, resolved once here
    into typed, immutable `ThreadContext` evidence (dumpex.hunt.injection.
    models) -- the scan/enrichment step that lets correlation.py and the
    domain model (dumpex.hunt.injection.domain) work exclusively with typed
    evidence and never see a raw per-thread CONTEXT dict."""
    return tuple(ThreadContext(thread_id=c["ThreadId"], ip=c["ip"], ip_reg=c["ip_reg"],
                                is_wow64=c["is_wow64"])
                 for c in get_thread_contexts(mf))

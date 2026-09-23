"""Unbacked-thread (StartAddress) scan. Only collects facts."""
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import (
    get_modules, get_thread_infos, addr_to_module, enriched_thread_contexts,
    recorded_start_address, START_ADDRESS_RECORDED,
)
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

    Only an address its own record stands behind is scanned at all (see
    dumpex.core.memory.recorded_start_address): a record whose DumpFlags
    mark its thread information invalid carries nothing beyond the thread
    identifier, and one whose DumpFlags could not be read establishes
    nothing about the address it holds. An unbacked-thread hit from
    either would turn missing evidence into a scored finding -- the same
    rule --report applies to its own `unbacked_thread` dimension, so the
    two commands cannot disagree about the same TID.
    `count_unestablished_start_addresses` reports how many were held back,
    so the exclusion is never silent.
    """
    if not module_list_available:
        return ()
    modules = get_modules(mf)
    infos   = get_thread_infos(mf)
    hits = []
    for ti in infos:
        start_address, start_address_state = recorded_start_address(ti)
        if start_address_state != START_ADDRESS_RECORDED:
            continue
        lookup_address = start_address or 0
        if not addr_to_module(lookup_address, modules):
            hits.append(UnbackedThreadEvidence(
                thread_id=ti.ThreadId, start_address=start_address,
                location=resolve_location(mf, lookup_address, lookup_address)))
    return tuple(hits)


def count_unestablished_start_addresses(mf: MinidumpFile) -> int:
    """How many ThreadInfoListStream records `_hunt_unbacked_threads`
    held back because no start address was established for them -- the
    record disowns its own fields, its DumpFlags could not be read, or it
    carried no StartAddress field.

    Counts only records that actually arrived. A thread this stream never
    covered at all is the same gap by a different route, but it is a
    different FACT -- a cross-source key mismatch, not a record that came
    up short -- and is counted by
    `count_threads_without_a_thread_info_record` so each can be reported
    in the words that are true of it.

    Counted at the scan boundary, which is the only layer that still has
    `mf`, and passed to the aggregate as a plain int (see
    `aggregate.build_report`'s own record-count rule). Lets the report
    say that a thread was excluded from this hunter's start-address
    evidence without letting the excluded thread reach the score."""
    return sum(1 for ti in get_thread_infos(mf)
               if recorded_start_address(ti)[1] != START_ADDRESS_RECORDED)


def count_threads_without_a_thread_info_record(mf: MinidumpFile) -> int:
    """How many threads the base ThreadListStream lists that
    ThreadInfoListStream never covered -- the same per-TID mismatch
    `--threads` reports as SOURCE_KEY_MISMATCH, counted here so this
    hunter's own coverage knows about the threads whose start address it
    could not check for lack of any record at all.

    0 when ThreadInfoListStream is absent or empty: that is its own
    coverage fact, reported on its own, and counting every thread again
    underneath it would describe one gap twice. 0 as well when the base
    stream is absent, which leaves no known TID to be missing."""
    infos = get_thread_infos(mf)
    if not infos:
        return 0
    covered = {ti.ThreadId for ti in infos}
    base_threads = mf.threads.threads if getattr(mf, "threads", None) else ()
    return len({t.ThreadId for t in base_threads} - covered)


def resolve_thread_contexts(mf: MinidumpFile) -> tuple:
    """`dumpex.core.memory.enriched_thread_contexts(mf)`'s dicts, resolved
    once here into typed, immutable `ThreadContext` evidence (dumpex.hunt.
    injection.models) -- the scan/enrichment step that lets correlation.py
    and the domain model (dumpex.hunt.injection.domain) work exclusively
    with typed evidence and never see a raw per-thread CONTEXT dict.

    `enriched_thread_contexts` already joins in each TID's own
    ThreadInfoListStream record (the same join dumpex.commands.threads/
    report, and every other hunter reading a thread's current RIP/EIP,
    now share) -- `start_address` and `ip_context_conflict` are a SECOND,
    independent source resolved at that shared collection boundary, not
    re-derived downstream. A TID whose ThreadInfoListStream record is
    missing, or present but disowning its own fields, gets
    `start_address=None`; one whose DumpFlags could not be established
    at all gets `ip_context_conflict=None` (undeterminable), never a
    fabricated confirmed value."""
    return tuple(ThreadContext(
        thread_id=c["ThreadId"], ip=c["ip"], ip_reg=c["ip_reg"], is_wow64=c["is_wow64"],
        start_address=c["start_address"], ip_context_conflict=c["ip_context_conflict"])
        for c in enriched_thread_contexts(mf))

"""Handle/string/thread/proximity correlation for the pipe hunter.
Establishes relationships between the handle scan's and the pipe-name
scan's typed evidence — never scores, never prints.

This is the last place a raw `MinidumpThreadInfo`/thread-context dict is
touched: every relationship it derives comes back as typed
`dumpex.hunt.pipe.models` evidence, so `aggregate.build_report()` never
sees a raw minidump object at all.

Each derived relationship CITES the handle/string-lead evidence objects it
was built from BY IDENTITY (never a reconstructed equal copy) -- the
Report enforces that at construction (see
`dumpex.hunt.pipe.domain.PipeEvidence`), which is what makes
"corroborated handle #1" and "open handle #1" provably the same handle.
"""
from dumpex.core.memory import addr_to_module
from dumpex.hunt.pipe.patterns import canonical_pipe_name, framework_match
from dumpex.hunt.pipe.models import (
    C2ContextEvidence, CorrelationResult, CorroboratedHandleEvidence,
    FrameworkStringHitEvidence, StartAddressLeadEvidence, UnbackedThreadEvidence,
    dedupe_evidence, framework_attribution, thread_hit_ref, thread_start_ref,
)


def _string_hit_for_handle(string_leads, canonical_name: str):
    """
    EXACT match on canonicalized names only — see patterns.canonical_pipe_name's
    docstring for why substring containment ("a in b or b in a") is wrong
    here: it lets an unrelated pipe whose name happens to be a
    prefix/suffix of another (or an empty canonical name from a
    malformed match) manufacture a false "same pipe" link.
    """
    if not canonical_name:
        return None
    for hit in string_leads:
        if canonical_pipe_name(hit.name) == canonical_name:
            return hit
    return None


def correlate(handle_scan, pipe_name_scan, thread_contexts: list, infos: list,
              modules: list, regions: list, known_framework_pipes,
              context_distance: int) -> CorrelationResult:
    string_leads = pipe_name_scan.string_leads
    # The immutable `RegionC2Records` tuple rebuilt as a plain LOCAL lookup
    # dict: a dict can never be recursively immutable, so it may exist here
    # (inside one function call, unreachable afterwards) but never on the
    # Report -- see dumpex.hunt.pipe.models.RegionC2Records.
    records_by_region = {entry.region.base_address: entry.records
                          for entry in pipe_name_scan.c2_regions}
    # Every pipe-bearing region's already-resolved identity snapshot,
    # keyed by base address, so the unbacked-thread walk below can report a
    # region WITHOUT re-snapshotting the raw one it is iterating.
    region_by_base = {hit.region.base_address: hit.region for hit in string_leads}

    # ── C2-context evidence attached to string leads (informational only —
    # see report_console.py for where this is surfaced, in bounded
    # --verbose evidence rather than as a check). Collected here purely by
    # region/string-name proximity, independent of whether that same
    # canonical name also has an open handle -- handle correlation is
    # determined later, at projection time (report_console.py/aggregate.py
    # cross-reference this against handle_scan.handles), not here.
    c2_context = []
    for hit in string_leads:
        records = records_by_region.get(hit.region.base_address)
        if not records:
            continue
        c2_context.append(C2ContextEvidence(string_hit=hit, records=records))

    # ── Corroboration (scored): C2 context / live execution WITHIN
    # context_distance of a handle-confirmed pipe's matching string
    # occurrence, if one exists. Anchored on the pipe hit's own VA, not
    # "anywhere in the same MemoryInfo region" — a region can span
    # megabytes, so a C2-looking string or an executing thread far away in
    # the same region says nothing about THIS pipe reference.
    corroborated_handles = []
    start_address_leads  = []   # LEAD ONLY, never scored
    for handle in handle_scan.handles:
        sh = _string_hit_for_handle(string_leads, handle.canonical_name)
        if sh is None:
            continue
        pipe_va = sh.va

        all_records = records_by_region.get(sh.region.base_address) or ()
        nearby_c2 = tuple(rec for rec in all_records
                           if abs(rec.va - pipe_va) <= context_distance)

        # RIP/EIP corroboration additionally requires the region actually
        # BE executable — a thread whose current instruction pointer sits
        # near a pipe-name string in non-executable (e.g. data-only)
        # memory can't actually be running code from that location.
        rip_hit = None
        if sh.region.is_executable:
            for tc in thread_contexts:
                if abs(tc["ip"] - pipe_va) <= context_distance:
                    rip_hit = thread_hit_ref(tc)
                    break

        # StartAddress proximity is collected but NEVER scored — it's
        # where a thread began, not where it is now (see
        # dumpex/hunt/injection/ for the same distinction), and is
        # reported as a lead only.
        if rip_hit is None:
            for ti in infos:
                sa = ti.StartAddress or 0
                if sa and abs(sa - pipe_va) <= context_distance and not addr_to_module(sa, modules):
                    start_address_leads.append(StartAddressLeadEvidence(
                        handle=handle, string_hit=sh,
                        thread=thread_start_ref(ti)))
                    break

        if nearby_c2 or rip_hit:
            corroborated_handles.append(CorroboratedHandleEvidence(
                handle=handle, string_hit=sh,
                nearby_c2=nearby_c2, rip_hit=rip_hit))

    # ── Known framework patterns on the STRING leads too ──────────────────
    # (attribution only — a name-pattern match on a string that has no
    # corresponding handle is still informational, never scored: a bare
    # pipe string does not become handle evidence by matching a rule.)
    framework_string_hits = []
    for hit in string_leads:
        clean = hit.name.strip()
        attribution = framework_attribution(framework_match(clean, known_framework_pipes))
        if attribution is not None:
            framework_string_hits.append(FrameworkStringHitEvidence(
                string_hit=hit, framework=attribution))

    # ── Unbacked threads in the same region as a string pipe-name lead ────
    # (kept for analyst visibility; NOT independently scored — see
    # CorroboratedHandleEvidence for the scored, handle-anchored version)
    unbacked_threads = []
    for ti in infos:
        sa = ti.StartAddress or 0
        for r in regions:
            region = region_by_base.get(r.BaseAddress)
            if region is None:
                continue
            if r.BaseAddress <= sa < r.BaseAddress + r.RegionSize:
                if not addr_to_module(sa, modules):
                    unbacked_threads.append(UnbackedThreadEvidence(
                        thread=thread_start_ref(ti), region=region))

    return CorrelationResult(
        corroborated_handles=tuple(corroborated_handles),
        start_address_leads=tuple(start_address_leads),
        # Deduped by equality: two string leads in the SAME region whose
        # bounded previews coincide would otherwise produce two identical
        # entries describing the same region, the same name, and the same
        # records -- which the Report's evidence buckets reject outright
        # (see dumpex.hunt.pipe.models.dedupe_evidence).
        c2_context=dedupe_evidence(c2_context),
        framework_string_hits=dedupe_evidence(framework_string_hits),
        unbacked_threads=dedupe_evidence(unbacked_threads),
    )

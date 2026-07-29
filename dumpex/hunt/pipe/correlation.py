"""Handle/string/thread/proximity correlation for the pipe hunter.
Establishes relationships between HandleScan and PipeNameScan facts —
never scores, never prints.
"""
from dumpex.core.memory import addr_to_module, prot_str
from dumpex.hunt.pipe.patterns import canonical_pipe_name, framework_match
from dumpex.hunt.pipe.models import CorrelationResult


def _string_hit_for_handle(private_pipes: list, canonical_name: str):
    """
    EXACT match on canonicalized names only — see patterns.canonical_pipe_name's
    docstring for why substring containment ("a in b or b in a") is wrong
    here: it lets an unrelated pipe whose name happens to be a
    prefix/suffix of another (or an empty canonical name from a
    malformed match) manufacture a false "same pipe" link.
    """
    if not canonical_name:
        return None
    for hit in private_pipes:
        if canonical_pipe_name(hit["name"]) == canonical_name:
            return hit
    return None


def correlate(handle_scan, pipe_name_scan, thread_contexts: list, infos: list,
              modules: list, regions: list, known_framework_pipes, context_distance: int) -> CorrelationResult:
    private_pipes = pipe_name_scan.private_pipes
    region_c2_records = pipe_name_scan.region_c2_records

    # ── C2-context regions with a pipe-name string, uncorrelated to any
    # handle (informational only — see aggregate.py/presentation.py for
    # how each of these is used).
    c2_hits = []
    for hit in private_pipes:
        records = region_c2_records.get(hit["region"].BaseAddress)
        if not records:
            continue
        c2_hits.append((hit["region"], hit["name"].strip(), records))

    # ── Check B (corroboration, scored): C2 context / execution WITHIN
    # context_distance of a handle-confirmed pipe's matching string
    # occurrence, if one exists. Anchored on the pipe hit's own VA, not
    # "anywhere in the same MemoryInfo region" — a region can span
    # megabytes, so a C2-looking string or an executing thread far away in
    # the same region says nothing about THIS pipe reference.
    corroborated_handles = []   # [{"hc", "string_hit", "pipe_va", "nearby_c2", "rip_hit"}, ...]
    start_addr_leads      = []  # [{"hc", "string_hit", "pipe_va", "thread_info"}, ...] — LEAD ONLY, never scored
    for hc in handle_scan.handle_classified:
        sh = _string_hit_for_handle(private_pipes, hc["canonical_name"])
        if sh is None:
            continue
        r = sh["region"]
        pipe_va = r.BaseAddress + sh["offset"]
        region_is_executable = "EXECUTE" in prot_str(r.Protect)

        all_records = region_c2_records.get(r.BaseAddress) or []
        nearby_c2 = [rec for rec in all_records
                     if abs(rec["va"] - pipe_va) <= context_distance]

        # RIP/EIP corroboration additionally requires the region actually
        # BE executable — a thread whose current instruction pointer sits
        # near a pipe-name string in non-executable (e.g. data-only)
        # memory can't actually be running code from that location.
        rip_hit = None
        if region_is_executable:
            for tc in thread_contexts:
                if abs(tc["ip"] - pipe_va) <= context_distance:
                    rip_hit = tc
                    break

        # StartAddress proximity is collected but NEVER scored — it's
        # where a thread began, not where it is now (see
        # dumpex/hunt/injection/ for the same distinction), and is
        # reported as a lead only.
        if rip_hit is None:
            for ti in infos:
                sa = ti.StartAddress or 0
                if sa and abs(sa - pipe_va) <= context_distance and not addr_to_module(sa, modules):
                    start_addr_leads.append({"hc": hc, "string_hit": sh, "pipe_va": pipe_va, "thread_info": ti})
                    break

        if nearby_c2 or rip_hit:
            corroborated_handles.append({
                "hc": hc, "string_hit": sh, "pipe_va": pipe_va,
                "nearby_c2": nearby_c2, "rip_hit": rip_hit,
            })

    # ── Check 3: Known framework patterns on the STRING leads too ─────────
    # (attribution only — a name-pattern match on a string that has no
    # corresponding handle is still informational, not separately scored)
    framework_string_hits = []  # (region, full_pipe_name, framework, technique, mitre_id)
    for hit in private_pipes:
        r = hit["region"]
        clean = hit["name"].strip()
        fm = framework_match(clean, known_framework_pipes)
        if fm is not None:
            framework, technique, mitre = fm
            framework_string_hits.append((r, clean, framework, technique, mitre))

    # ── Check 4: Unbacked threads in same region as a string pipe-name lead ──
    # (kept for analyst visibility; NOT independently scored — see
    # pipe.corroboration for the scored, handle-anchored version)
    pipe_regions = {hit["region"].BaseAddress for hit in private_pipes}
    unbacked_in_pipe_rgn = []
    for ti in infos:
        sa = ti.StartAddress or 0
        for r in regions:
            if r.BaseAddress in pipe_regions:
                if r.BaseAddress <= sa < r.BaseAddress + r.RegionSize:
                    if not addr_to_module(sa, modules):
                        unbacked_in_pipe_rgn.append((ti, r))

    return CorrelationResult(
        c2_hits=c2_hits, corroborated_handles=corroborated_handles,
        start_addr_leads=start_addr_leads, framework_string_hits=framework_string_hits,
        unbacked_in_pipe_rgn=unbacked_in_pipe_rgn,
    )

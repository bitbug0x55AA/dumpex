"""Per-region '\\pipe\\' string scan (ASCII/UTF-16LE) and the C2-context
records gathered from the same pipe-bearing regions. Only collects facts
— never scores, never prints. Applies TWO INDEPENDENT whole-hunt budgets
(pipe_name_budget, c2_budget) — see dumpex/hunt/pipe/config.py for why
they must never be merged.

Produces typed `dumpex.hunt.pipe.models` evidence rather than hand-rolled
dicts: this is the ONE place a raw `MinidumpMemoryInfo` becomes a
`RegionRef` identity snapshot (`prot_str()` resolved once, here) and the
ONE place a string hit's absolute VA and .dmp `file_offset` are resolved
(`va_to_file_offset()` called once per retained hit, here) -- never
re-derived at aggregate or render time.
"""
import os
import hashlib
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import (
    addr_to_module, prot_str, va_range_captured_bytes, va_to_file_offset,
)
from dumpex.hunt._coverage import region_scan_target
from dumpex.hunt.pipe.config import (PIPE_SCAN_MAX, PIPE_MAX_MATCHES_PER_REGION,
    PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION, PIPE_C2_CONTEXT_BYTES,
    PIPE_C2_TOKEN_PREVIEW, PIPE_NAME_MAX_CHARS, PIPE_CONTEXT_DISTANCE)
from dumpex.hunt.pipe.patterns import (PIPE_PAT_ASCII, PIPE_PAT_UTF16, _iter_c2_matches,
    is_proximity_match)
from dumpex.hunt.pipe.models import (
    C2ContextRecord, PipeNameScanResult, PipeScanCoverage, PipeStringEvidence, RegionC2Records,
    region_ref,
)


def _is_system_dll(module) -> bool:
    """
    Only Microsoft system DLLs under System32/SysWOW64 are treated as
    "expected". Any other image-backed region — including executables
    like update.exe, or DLLs outside the system directories — is flagged
    the same as private memory so it cannot hide pipe refs.
    """
    if module is None:
        return False
    path = (module.name or "").replace("\\", "/").lower()
    return (
        "/windows/system32/"  in path or
        "/windows/syswow64/" in path or
        "/windows/winsxs/"   in path
    )


def _extract_pipe_name(data, m, is_utf16, max_chars=PIPE_NAME_MAX_CHARS) -> dict:
    """
    Walk forward from the \\pipe\\ match to find the full printable
    run (needed for an accurate sha256/length even when that run is
    huge), but DECODE/RETAIN at most max_chars of it as the preview —
    a 1 MiB printable run following the match must not become a
    1 MiB "pipe name" string kept in findings. Building the raw byte
    slice to hash/measure it is transient (freed once this call
    returns); only the bounded preview + digest + length survive.

    `truncated` is computed here by comparing raw BYTES against
    preview_src BYTES — both in the same unit, before any decoding —
    rather than leaving callers to compare a decoded preview's
    CHARACTER count against a byte length. For UTF-16LE (2 bytes per
    char), comparing len(decoded preview) against len(raw bytes)
    reports "truncated" for every non-empty name even when nothing
    was actually cut.

    Returns a dict: {"preview", "sha256", "original_length",
    "truncated", "encoding"}. Deliberately still a plain dict and
    deliberately still private: it is a transient intermediate consumed
    exactly once, three lines later, by the `PipeStringEvidence`
    construction in `scan_pipe_names()` -- it never crosses a module
    boundary, so promoting it to its own frozen value object would add a
    type without adding a barrier.
    """
    end = m.end()
    if is_utf16:
        # Read UTF-16LE chars until double-null or end
        while end + 1 < len(data):
            ch = data[end]
            hi = data[end + 1]
            if hi == 0 and 32 <= ch < 127:
                end += 2
            else:
                break
        raw = data[m.start():end]
        preview_src = raw[:max_chars * 2]
        try:
            preview = preview_src.decode("utf-16-le", errors="replace")
        except Exception:
            preview = repr(preview_src)
        encoding = "utf16le"
    else:
        while end < len(data) and 32 <= data[end] < 127:
            end += 1
        raw = data[m.start():end]
        preview_src = raw[:max_chars]
        try:
            preview = preview_src.decode("ascii", errors="replace")
        except Exception:
            preview = repr(preview_src)
        encoding = "ascii"
    return {
        "preview":          preview,
        "sha256":           hashlib.sha256(raw).hexdigest(),
        "original_length":  len(raw),
        "truncated":        len(raw) > len(preview_src),
        "encoding":         encoding,
    }


def dedupe_private_pipes(private_pipes: list) -> list:
    """
    Deduplicate private pipes by (region_base, sha256) — sha256 is over
    the FULL match regardless of preview truncation, so two different
    long names that happen to share the same truncated preview are never
    wrongly merged.
    """
    seen = set()
    deduped = []
    for hit in private_pipes:
        key = (hit.region.base_address, hit.sha256)
        if key not in seen:
            seen.add(key)
            deduped.append(hit)
    return deduped


def _dedupe_targets(targets: list) -> tuple:
    """Collapse targets naming the same physical region (base + size),
    preserving first-seen order -- a duplicate MemoryInfo entry, or a
    region observed through more than one budget-exhaustion check, must
    not inflate a scope's target tuple or its affected_count."""
    seen = set()
    out = []
    for t in targets:
        key = (t.base_address, t.size)
        if key not in seen:
            seen.add(key)
            out.append(t)
    return tuple(out)


def _build_c2_record(data: bytes, start: int, end: int, token: bytes,
                      region_base: int) -> C2ContextRecord:
    """One `C2ContextRecord` from a raw match span -- shared by both the
    proximity and context-only retention passes in `scan_pipe_names()` so
    the context-window-slicing/hashing logic isn't duplicated between
    them."""
    ctx_half  = PIPE_C2_CONTEXT_BYTES // 2
    ctx_start = max(0, start - ctx_half)
    ctx_end   = min(len(data), end + ctx_half)
    context   = bytes(data[ctx_start:ctx_end][:PIPE_C2_CONTEXT_BYTES])
    match_b   = data[start:end]
    return C2ContextRecord(
        match=token[:PIPE_C2_TOKEN_PREVIEW],
        context=context,
        va=region_base + start,
        sha256=hashlib.sha256(match_b).hexdigest(),
        original_length=end - start)


def scan_pipe_names(mf: MinidumpFile, read_region, regions: list, modules: list,
                     coverage_counts, pipe_name_budget, c2_budget, c2_pattern,
                     scan_max: "int | None" = None) -> PipeNameScanResult:
    """
    Walk every committed, not-oversized region: collect '\\pipe\\' string
    occurrences (private leads / expected system-DLL references) under
    pipe_name_budget, and — for any region that yielded a NEW private pipe
    name and while c2_budget still has room — C2-context match records
    under c2_budget. The two budgets are independent: pipe-name collection
    (the handle-correlation checks' raw material) is unaffected by
    c2_budget running out, and vice versa.

    `scan_max` is the per-region size cap a region has to stay under to be
    read at all. `None` means this module's own `PIPE_SCAN_MAX`, resolved
    per call rather than bound at import so the module-global monkeypatch
    seam keeps working; a targeted rescan (dumpex.hunt.pipe.targeted) passes
    an explicit value to bypass that ONE cap for the range an investigator
    named. Every other budget is unaffected by it.

    Returns a fully immutable `PipeNameScanResult` -- including a frozen
    `PipeScanCoverage` snapshot of the still-live tracker/budgets this
    function was handed, so neither can be mutated after the scan finishes
    and silently change what the Report reports.
    """
    region_cap = PIPE_SCAN_MAX if scan_max is None else scan_max
    string_leads = []
    image_pipe_refs = 0
    image_pipe_modules = []
    c2_regions = []
    # A per-region quota that actually DROPPED an occurrence, recorded at the
    # site that dropped it. These are not budget exhaustion (no whole-hunt
    # resource ran out) and not a read gap, but they do mean the pattern walk
    # over that region stopped before every occurrence was processed -- so a
    # negative from it is not a full-search negative.
    match_cap_hit = False
    context_only_cap_hit = False
    # One ScanTarget per eligible region a spent budget left unresolved for
    # its scope, accumulated at the decision site that could not proceed --
    # never reconstructed after the fact from a stop index or the final
    # budget state. Deduped by physical region at the end.
    pipe_name_budget_affected = []
    c2_budget_affected = []

    for r in regions:
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        if r.RegionSize <= 0:
            # A zero-length region has nothing to read and no bytes anyone
            # could miss: a filter, not a coverage gap. It is also not
            # something a ScanTarget can identify -- a target has an
            # extent by definition.
            continue
        # Every committed, non-empty region the walk reaches is in scope and
        # owes the ledger a disposition -- including one the walk can do no
        # scan work on because both budgets are already spent. The walk does
        # NOT stop early on exhaustion: enumerating the rest is metadata-only
        # (no region-content reads) and is what keeps every oversized skip
        # and every unresolved region visible instead of silently dropped.
        coverage_counts.note_eligible(
            va_range_captured_bytes(mf, r.BaseAddress, r.RegionSize))
        if r.RegionSize > region_cap:
            coverage_counts.note_skipped_oversize(
                region_scan_target(mf, r, region_cap))
            continue
        if pipe_name_budget.exhausted() and c2_budget.exhausted():
            # Neither pipe-name matching nor its dependent C2 collection can
            # make a claim for this region; no scan work runs. Attributed to
            # BOTH scopes -- the conservative contract, since neither signal
            # can vouch for the range.
            target = region_scan_target(mf, r)
            pipe_name_budget_affected.append(target)
            c2_budget_affected.append(target)
            coverage_counts.note_budget_skipped()
            continue
        mtype = prot_str(r.Type)
        mod   = addr_to_module(r.BaseAddress, modules)

        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            # The MemoryInfo region that failed is still in scope right
            # here -- retained as a ScanTarget (issue #28) so the failure
            # is more than a count: an investigator can go extract,
            # rescan, or recollect this exact region.
            coverage_counts.note_read_failed(region_scan_target(mf, r))
            continue
        if not data:
            # Nothing came back at all: there is no readable portion to
            # scan, so this is a failed read rather than a short one -- a
            # short read ANNOTATES a region that was otherwise scanned.
            coverage_counts.note_read_failed(region_scan_target(mf, r))
            continue
        if len(data) < r.RegionSize:
            # Fewer bytes came back than the region's own declared size —
            # not the same as "read fine, nothing here". Still scan what
            # WAS returned (a real pipe name/C2 string can still be found
            # in the readable portion), but this region must not silently
            # count toward a "complete" scan.
            coverage_counts.note_short_read(region_scan_target(mf, r))
        # Resolved ONCE per region, here, rather than per hit or at render
        # time -- every projection reads these already-resolved strings.
        region = region_ref(r)
        pipes_before = len(string_leads)

        # Whether any pattern was actually run over `data`. The region's
        # disposition is decided by this at the end of the iteration, not
        # by having reached this line: with pipe_name_budget already
        # exhausted the loop below runs no pattern at all, and the C2
        # passes are gated on this region yielding a NEW pipe name, so
        # nothing would examine the bytes that were read.
        examined = False
        # True once this region's pipe-name matching stopped short for lack
        # of budget -- it could not start at all, or it ran out partway.
        pipe_name_cut = pipe_name_budget.exhausted()
        region_matches = 0
        for pat, is_utf16 in ((PIPE_PAT_ASCII, False), (PIPE_PAT_UTF16, True)):
            if pipe_name_budget.exhausted():
                pipe_name_cut = True
                break
            examined = True
            for m in pat.finditer(data):
                if region_matches >= PIPE_MAX_MATCHES_PER_REGION:
                    # Every iteration of this loop is a real match, so reaching
                    # the quota here always means at least one occurrence went
                    # unprocessed.
                    match_cap_hit = True
                    break
                if pipe_name_budget.exhausted():
                    pipe_name_cut = True
                    break
                region_matches += 1
                info = _extract_pipe_name(data, m, is_utf16)
                if not pipe_name_budget.take_hit(len(info["preview"])):
                    pipe_name_cut = True
                    break
                if "MEM_IMAGE" in mtype and _is_system_dll(mod):
                    # Expected, and never a lead: counted (plus the module
                    # names) as a --verbose scan-detail fact rather than
                    # retained as evidence.
                    image_pipe_refs += 1
                    image_pipe_modules.append(os.path.basename(mod.name))
                    continue
                va = r.BaseAddress + m.start()
                string_leads.append(PipeStringEvidence(
                    region=region, offset=m.start(), name=info["preview"],
                    sha256=info["sha256"], original_length=info["original_length"],
                    truncated=info["truncated"], encoding=info["encoding"], va=va,
                    # Resolved here, once per retained hit -- None means
                    # those bytes were never written to the .dmp at all,
                    # which is NOT the same claim as "offset zero".
                    file_offset=va_to_file_offset(mf, va)))

        # This region's pipe-name matching could not run to completion
        # within budget -- it could not start (already spent when the region
        # was reached) or a hit/match check inside the loop was refused. A
        # region whose matching finished within budget is never here, even
        # if the budget then reads exhausted on its final hit.
        if pipe_name_cut:
            pipe_name_budget_affected.append(region_scan_target(mf, r))

        # This region's C2 coverage is incomplete only if the c2_budget
        # actually blocked work here: collection could not start (already
        # spent), a `take_hit` was refused, `_iter_c2_matches` cut a match
        # stream short, or the budget ran out between the two passes so the
        # second never ran. A region whose passes both ran to their natural
        # end within budget is never flagged, even when a whole-hunt
        # deadline is observed to have expired immediately afterward.
        c2_context_incomplete = False
        new_pipe_leads = len(string_leads) > pipes_before
        if new_pipe_leads and c2_budget.exhausted():
            # Already spent before this region: its C2 context cannot be
            # gathered at all.
            c2_context_incomplete = True
        elif new_pipe_leads:
            # Build small, bounded C2ContextRecords right here while `data`
            # is still in scope — the raw region bytes are never cached or
            # retained past this loop iteration. Only C2-context gathering
            # stops once its budget is spent; pipe-name detection is
            # unaffected.
            #
            # Retention is proximity-first AND budget-driven (issue #24 and
            # its own follow-up) via TWO independent streaming passes over
            # `_iter_c2_matches`, rather than one pass that buffers every
            # examined match before retaining any of them: buffering is
            # itself an unbounded-memory concern for a crafted, C2-pattern-
            # dense region, exactly the failure mode a per-region "matches
            # examined" ceiling was wrongly reintroduced to paper over.
            region_pipe_offsets = [hit.offset for hit in string_leads[pipes_before:]]
            records = []

            # Pass 1 — proximity evidence (within PIPE_CONTEXT_DISTANCE of
            # one of THIS region's own pipe-name hits): NO per-region cap
            # of its own. Retained for as long as the whole-hunt c2_budget
            # has room, full stop — a region with many corroborating
            # matches keeps every one of them the budget allows.
            pass1_truncated = [False]
            for start, end, token in _iter_c2_matches(data, c2_pattern, c2_budget, pass1_truncated):
                if not is_proximity_match(start, region_pipe_offsets, PIPE_CONTEXT_DISTANCE):
                    continue
                record = _build_c2_record(data, start, end, token, r.BaseAddress)
                if not c2_budget.take_hit(len(record.context) + len(record.match)):
                    c2_context_incomplete = True
                    break
                records.append(record)
            if pass1_truncated[0]:
                c2_context_incomplete = True

            # Pass 2 — context-only evidence: a SEPARATE, small, fixed
            # per-region quota (PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION) so it
            # can only ever claim a modest, bounded slice of c2_budget and
            # can never compete with or displace proximity evidence above
            # — re-scanning `data` is cheap regex work, not the resource
            # c2_budget bounds (see its own construction in
            # dumpex/hunt/pipe/__init__.py).
            if not c2_budget.exhausted():
                context_kept = 0
                pass2_truncated = [False]
                for start, end, token in _iter_c2_matches(data, c2_pattern, c2_budget,
                                                           pass2_truncated):
                    # The proximity test comes FIRST so the quota is only
                    # consulted for a match this pass would actually have
                    # retained: a stream whose next match is proximity evidence
                    # (pass 1's, already kept) has had nothing dropped, and
                    # stopping on it would report a quota gap that did not
                    # happen -- and, worse, would hide a context-only match
                    # further along that genuinely is dropped.
                    if is_proximity_match(start, region_pipe_offsets, PIPE_CONTEXT_DISTANCE):
                        continue
                    if context_kept >= PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION:
                        context_only_cap_hit = True
                        break
                    record = _build_c2_record(data, start, end, token, r.BaseAddress)
                    if not c2_budget.take_hit(len(record.context) + len(record.match)):
                        c2_context_incomplete = True
                        break
                    records.append(record)
                    context_kept += 1
                if pass2_truncated[0]:
                    c2_context_incomplete = True
            else:
                # Pass 2 (context-only C2 evidence over the same bytes)
                # could not start -- the c2_budget was spent during pass 1
                # or in the gap before this check, so this region's
                # context-only matches were never gathered.
                c2_context_incomplete = True

            if records:
                c2_regions.append(RegionC2Records(region=region, records=tuple(records)))

        # A region whose new pipe-name leads the c2_budget could not gather
        # full C2 context for -- recorded at the point the budget actually
        # blocked a pass, never inferred from the final budget state, so a
        # deadline observed only after BOTH passes already finished does not
        # flag a region whose C2 context is in fact complete.
        if c2_context_incomplete:
            c2_budget_affected.append(region_scan_target(mf, r))

        # Exactly one disposition, on every path out of this iteration:
        # `scanned` when at least one pattern ran over the region's bytes,
        # `budget_skipped` when the whole-hunt budgets left nothing to run
        # -- read fine and perfectly analyzable, just not examined. Kept
        # out of `not_applicable`, which claims a rescan would find the
        # same nothing; a bigger budget reaches these.
        if examined:
            coverage_counts.note_scanned()
        else:
            coverage_counts.note_budget_skipped()

    coverage = PipeScanCoverage.from_scan(
        coverage_counts, pipe_name_budget, c2_budget,
        image_pipe_refs=image_pipe_refs, image_pipe_modules=image_pipe_modules,
        pipe_name_budget_exhausted_targets=_dedupe_targets(pipe_name_budget_affected),
        c2_budget_exhausted_targets=_dedupe_targets(c2_budget_affected),
        match_cap_hit=match_cap_hit, context_only_cap_hit=context_only_cap_hit)
    return PipeNameScanResult(string_leads=tuple(dedupe_private_pipes(string_leads)),
                               c2_regions=tuple(c2_regions), coverage=coverage)

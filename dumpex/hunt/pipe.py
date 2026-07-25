"""Named pipe C2 hunter."""
import os
import re
import time
import hashlib
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, addr_to_module, va_to_file_offset, prot_str,
    read_region)
from dumpex.hunt._ui import (_print_hunt_header, _print_check, _status_text,
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE)
from dumpex.hunt._budget import ScanBudget

PIPE_SCAN_MAX = 8 * 1024 * 1024   # skip regions > 8MB; pipe names / C2 context
                                   # are short strings, no need to read huge
                                   # regions in full to find them

PIPE_MAX_MATCHES_PER_REGION = 50    # cap raw \pipe\ matches processed per region
PIPE_C2_MAX_HITS_PER_REGION = 5     # cap C2_PAT matches recorded per pipe-bearing region
PIPE_C2_CONTEXT_BYTES       = 512   # total context window (before+after) kept per match
PIPE_C2_TOKEN_PREVIEW       = 256   # bound on the match token itself — every one of
                                     # C2_PAT's own patterns (a literal "http://", an
                                     # IP:port, "submit.php", ...) already produces a
                                     # short match on its own; this is defense in depth,
                                     # not the primary bound (see _iter_c2_matches)
PIPE_C2_BUDGET_MAX_HITS     = 200               # cumulative C2 hits retained, whole hunt
PIPE_C2_BUDGET_MAX_RETAINED = 2 * 1024 * 1024   # cumulative context bytes retained, whole hunt
PIPE_C2_BUDGET_TIME_SECONDS = 30.0

PIPE_NAME_MAX_CHARS   = 512     # bound on the retained pipe-name PREVIEW; the true
                                 # extent is still walked (for an accurate sha256/
                                 # original_length) but never fully decoded/kept
PIPE_NAME_BUDGET_MAX_HITS     = 500               # cumulative private+image pipe
                                                   # names retained, whole hunt
PIPE_NAME_BUDGET_MAX_RETAINED = 1 * 1024 * 1024   # cumulative preview bytes retained
PIPE_NAME_BUDGET_TIME_SECONDS = 30.0

_MIN_RUN_LEN = 6   # matches the min_len _extract_strings_from_data previously used here

_ASCII_RUN_PAT = re.compile(rb'[ -~]{%d,}' % _MIN_RUN_LEN)
_UTF16_RUN_PAT = re.compile(rb'(?:[ -~]\x00){%d,}' % _MIN_RUN_LEN)


def _iter_printable_runs(data: bytes):
    """
    Yield (byte_offset, text, is_utf16) for each ASCII and UTF16LE
    printable run in `data` — one pass each via re.finditer, so nothing is
    collected into a persisted list. `text` is only meant for transient use
    by the caller (matching a pattern against it); it is not retained here
    and callers must not retain it either beyond what they actually need
    to keep (see _iter_c2_matches).
    """
    for m in _ASCII_RUN_PAT.finditer(data):
        yield m.start(), m.group().decode('ascii', errors='replace'), False
    for m in _UTF16_RUN_PAT.finditer(data):
        yield m.start(), m.group().decode('utf-16-le', errors='replace'), True


def _iter_c2_matches(data: bytes, pattern, max_per_region: int):
    """
    Stream C2_PAT matches against each ASCII/UTF16LE printable run found in
    `data` individually — matching the same string boundaries a human or
    the original _extract_strings_from_data-based scan would see — rather
    than running the pattern against the ENTIRE region decoded as one
    latin-1 blob. Matching against the whole region breaks two things:
    end-anchored patterns like `/ca$` (the `$` then anchors to the
    region's end instead of each individual string's end, so it almost
    never matches) and UTF16LE C2 strings entirely (interleaved NUL bytes
    prevent any match against a pattern written for contiguous ASCII).

    Each run's decoded text is used only transiently for matching here;
    only the short, bounded match token and its BYTE offset within `data`
    are ever yielded — the full run itself (which can be enormous) is
    never retained.
    """
    count = 0
    for run_offset, text, is_utf16 in _iter_printable_runs(data):
        if count >= max_per_region:
            return
        for m in pattern.finditer(text):
            if count >= max_per_region:
                return
            count += 1
            if is_utf16:
                byte_start = run_offset + m.start() * 2
                byte_end   = run_offset + m.end() * 2
            else:
                byte_start = run_offset + m.start()
                byte_end   = run_offset + m.end()
            yield byte_start, byte_end, m.group(0)

def _hunt_pipe(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Detect Named Pipe C2 / Lateral Movement channels.

    Strategy: structural, not signature-based.
      Check 1 — Pipe names in MEM_PRIVATE memory
                 (system DLLs legitimately reference pipes; private memory does not)
      Check 2 — C2 artifacts near private pipe names
                 (IP:port, HTTP URLs in same region = strong signal)
      Check 3 — Known framework pipe naming patterns (bonus score only)
      Check 4 — Unbacked thread executing in same region as pipe name
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    infos   = get_thread_infos(mf)
    mem_info_available = bool(mf.memory_info and mf.memory_info.infos)

    # Pipe name patterns
    # Match pipe names in both ASCII and UTF-16LE.
    # UTF-16LE pattern built at runtime to avoid null bytes in source.
    PIPE_PAT_ASCII = re.compile(
        rb'(?:\\[?]{0,2}\\pipe\\|\\pipe\\|\\.\\pipe\\)',
        re.IGNORECASE
    )
    _utf16_pipe = '\\pipe\\'.encode('utf-16-le')
    PIPE_PAT_UTF16 = re.compile(re.escape(_utf16_pipe), re.IGNORECASE)
    # Pipe attribution and C2 context patterns loaded from rules.yaml
    # Each KNOWN_FRAMEWORK_PIPES entry: (compiled_regex, framework, technique, mitre)
    _r                    = get_rules()
    KNOWN_FRAMEWORK_PIPES = _r["framework_pipes"]
    C2_PAT                = _r["pipe_c2_context_patterns"]
    SUSPICIOUS_PROTS      = _r["suspicious_protections"]

    findings = {
        "private_pipes":   [],   # [{"region","offset","name","sha256","original_length"}, ...]
        "c2_context":      [],   # (region, pipe_name, [bounded C2 match record, ...])
        "framework_pipes": [],   # (region, pipe_name, framework, technique, mitre)
        "unbacked_in_rgn": [],   # (thread_info, region)
        "score": 0,
    }

    _print_hunt_header("Named Pipe C2 / Lateral Movement")

    # ── Collect all pipe name occurrences ────────────────────────────
    # Each entry: {"region", "offset", "name" (bounded preview),
    # "sha256" (of the FULL match, however long), "original_length"} — a
    # 1 MiB printable run following a \pipe\ match must never turn into a
    # 1 MiB retained "pipe name"; see _extract_pipe_name.
    private_pipes = []
    image_pipes   = []
    region_c2_records = {}   # region.BaseAddress -> [bounded C2 match records],
                              # ONLY for regions with a private pipe name. Each
                              # record is {match, context, offset, sha256,
                              # original_length} — never the region's raw
                              # bytes, and never an unboundedly long
                              # printable "string" (see _iter_c2_matches).
                              # Bounded further by c2_budget across the
                              # whole hunt, not just per region.
    skipped_size  = 0
    read_failed   = 0

    c2_budget = ScanBudget(
        max_bytes_read=PIPE_C2_BUDGET_MAX_RETAINED * 4,
        max_attempts=10**9,   # matching is cheap regex work, not the resource
                               # this budget bounds — hits/retained-bytes are
        max_retained_bytes=PIPE_C2_BUDGET_MAX_RETAINED,
        max_hits=PIPE_C2_BUDGET_MAX_HITS,
        deadline=time.monotonic() + PIPE_C2_BUDGET_TIME_SECONDS,
    )
    # Separate budget for pipe-NAME collection itself (Check 1/3/4's raw
    # material) — independent of c2_budget, which only bounds Check 2.
    pipe_name_budget = ScanBudget(
        max_bytes_read=PIPE_NAME_BUDGET_MAX_RETAINED * 4,
        max_attempts=10**9,
        max_retained_bytes=PIPE_NAME_BUDGET_MAX_RETAINED,
        max_hits=PIPE_NAME_BUDGET_MAX_HITS,
        deadline=time.monotonic() + PIPE_NAME_BUDGET_TIME_SECONDS,
    )

    def _extract_pipe_name(data, m, is_utf16, max_chars=PIPE_NAME_MAX_CHARS):
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
        "truncated", "encoding"}.
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

    for r in regions:
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        if r.RegionSize > PIPE_SCAN_MAX:
            skipped_size += 1
            continue
        if pipe_name_budget.exhausted() and c2_budget.exhausted():
            break   # nothing left this loop could still usefully collect
        mtype = prot_str(r.Type)
        mod   = addr_to_module(r.BaseAddress, modules)

        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            read_failed += 1
            continue
        pipes_before = len(private_pipes)

        # Classify: only Microsoft system DLLs under System32/SysWOW64 are
        # treated as "expected".  Any other image-backed region — including
        # executables like update.exe, or DLLs outside the system directories
        # — is flagged the same as private memory so it cannot hide pipe refs.
        def _is_system_dll(module) -> bool:
            if module is None:
                return False
            path = (module.name or "").replace("\\", "/").lower()
            return (
                "/windows/system32/"  in path or
                "/windows/syswow64/" in path or
                "/windows/winsxs/"   in path
            )

        region_matches = 0
        for pat, is_utf16 in ((PIPE_PAT_ASCII, False), (PIPE_PAT_UTF16, True)):
            if pipe_name_budget.exhausted():
                break
            for m in pat.finditer(data):
                if region_matches >= PIPE_MAX_MATCHES_PER_REGION:
                    break
                if pipe_name_budget.exhausted():
                    break
                region_matches += 1
                info = _extract_pipe_name(data, m, is_utf16)
                if not pipe_name_budget.take_hit(len(info["preview"])):
                    break
                hit = {"region": r, "offset": m.start(), "name": info["preview"],
                       "sha256": info["sha256"], "original_length": info["original_length"],
                       "truncated": info["truncated"], "encoding": info["encoding"]}
                if "MEM_IMAGE" in mtype and _is_system_dll(mod):
                    image_pipes.append({**hit, "module": os.path.basename(mod.name)})
                else:
                    private_pipes.append(hit)

        if len(private_pipes) > pipes_before and not c2_budget.exhausted():
            # Stream C2 matches directly over `data` (bounded per-match
            # span, see _iter_c2_matches) and build small, bounded records
            # right here while `data` is still in scope — the raw region
            # bytes are never cached or retained past this loop iteration.
            # Only Check 2's C2-context gathering stops once its budget is
            # spent; pipe-name detection (Check 1/3/4) is unaffected.
            records = []
            for start, end, token in _iter_c2_matches(data, C2_PAT, PIPE_C2_MAX_HITS_PER_REGION):
                ctx_half  = PIPE_C2_CONTEXT_BYTES // 2
                ctx_start = max(0, start - ctx_half)
                ctx_end   = min(len(data), end + ctx_half)
                context   = data[ctx_start:ctx_end][:PIPE_C2_CONTEXT_BYTES]
                match_b   = data[start:end]
                record = {
                    "match":           token[:PIPE_C2_TOKEN_PREVIEW],
                    "context":         context,
                    "va":              r.BaseAddress + start,
                    "sha256":          hashlib.sha256(match_b).hexdigest(),
                    "original_length": end - start,
                }
                if not c2_budget.take_hit(len(record["context"]) + len(record["match"])):
                    break
                records.append(record)
            if records:
                region_c2_records[r.BaseAddress] = records

    # Deduplicate private pipes by (region_base, sha256) — sha256 is over
    # the FULL match regardless of preview truncation, so two different
    # long names that happen to share the same truncated preview are never
    # wrongly merged.
    seen_private = set()
    deduped = []
    for hit in private_pipes:
        key = (hit["region"].BaseAddress, hit["sha256"])
        if key not in seen_private:
            seen_private.add(key)
            deduped.append(hit)
    private_pipes = deduped

    # ── Check 1: Pipe names outside trusted system DLLs ──────────────
    if private_pipes:
        detail = f"{len(private_pipes)} pipe name(s) in non-system memory"
        if verbose:
            for hit in private_pipes:
                r, off, name = hit["region"], hit["offset"], hit["name"]
                p    = prot_str(r.Protect)
                mtype_r = prot_str(r.Type)
                mod_r   = addr_to_module(r.BaseAddress, modules)
                rwx  = RED(" [RWX]") if any(s in p for s in SUSPICIOUS_PROTS) else ""
                abs_va = r.BaseAddress + off
                fo_abs = va_to_file_offset(mf, abs_va)
                fo_str = f"0x{fo_abs:x}" if fo_abs is not None else "(not captured)"
                if mod_r and "MEM_IMAGE" in mtype_r:
                    backer = YELLOW(f" [image: {os.path.basename(mod_r.name)}]")
                else:
                    backer = DIM(" [private/unregistered]")
                truncated = f"  [truncated, full length {hit['original_length']} bytes]" \
                    if hit.get("truncated") else ""
                detail += (f"\n          VA (process)   0x{abs_va:016x}{rwx}{backer}"
                           f"\n          File offset    {fo_str}"
                           f"\n          Region base    0x{r.BaseAddress:016x}"
                           f"\n          Pipe name: {name.strip()}{truncated}")
        _print_check("Pipe names outside trusted system DLLs",
                     RED("SUSPICIOUS — pipe name found in non-system memory"),
                     detail)
        findings["private_pipes"] = private_pipes
        findings["score"] += 1
    else:
        _print_check("Pipe names outside trusted system DLLs",
                     GREEN("CLEAN — all pipe name references are in known system modules"))

    if image_pipes and verbose:
        mod_names = sorted({h["module"] for h in image_pipes})
        print(DIM(f"  [·] {len(image_pipes)} pipe reference(s) in system DLLs "
                  f"({', '.join(mod_names)}) — expected, skipped\n"))

    if pipe_name_budget.exhausted():
        print(YELLOW(f"  [~] Pipe-name scan budget exhausted "
                      f"({pipe_name_budget.exhausted_reason}) — some regions may not "
                      f"have been checked for pipe names.\n"))

    # ── Check 2: C2 artifacts near private pipe names ─────────────────
    # Uses the bounded C2 match records already built inline in the main
    # loop above (region_c2_records) — no re-read of the region and no
    # retained copy of its raw bytes or any unboundedly long string, only
    # the short {match, context, ...} records built under c2_budget.
    c2_hits = []
    for hit in private_pipes:
        records = region_c2_records.get(hit["region"].BaseAddress)
        if not records:
            continue
        c2_hits.append((hit["region"], hit["name"].strip(), records))

    if c2_hits:
        detail = f"{len(c2_hits)} region(s) with pipe name + C2 artifacts"
        if verbose:
            for r, pipe_name, records in c2_hits:
                detail += f"\n          Region 0x{r.BaseAddress:x}  pipe: {pipe_name}"
                for rec in records[:3]:
                    detail += (f"\n            C2: {rec['match']}"
                               f"  VA 0x{rec['va']:016x}"
                               f"  sha256={rec['sha256'][:16]}…")
                if len(records) > 3:
                    detail += f"\n            ... and {len(records)-3} more"
        _print_check("C2 artifacts co-located with pipe name",
                     RED("SUSPICIOUS — C2 IP/URL in same region as private pipe name"),
                     detail)
        findings["c2_context"] = c2_hits
        findings["score"] += 1
    else:
        _print_check("C2 artifacts near pipe names",
                     GREEN("CLEAN — no C2 patterns found near private pipe names"))
    if c2_budget.exhausted():
        print(YELLOW(f"  [~] C2-context scan budget exhausted "
                      f"({c2_budget.exhausted_reason}) — some pipe-bearing regions "
                      f"may not have been checked for C2 context.\n"))

    # ── Check 3: Known framework patterns — attribution only, not scored ──
    # This re-classifies the exact same strings Check 1 already counted
    # (a framework match can only happen on a name already in
    # private_pipes) — it tells you WHICH framework a pipe name looks
    # like, it isn't a second independent piece of evidence. Counting it
    # as its own +1 double-counts one observation as two signals.
    framework_hits = []  # (region, full_pipe_name, framework, technique, mitre_id)
    for hit in private_pipes:
        r = hit["region"]
        clean = hit["name"].strip()
        for pat, framework, technique, mitre in KNOWN_FRAMEWORK_PIPES:
            if pat.search(clean):
                framework_hits.append((r, clean, framework, technique, mitre))
                break  # one attribution per pipe name

    if framework_hits:
        detail = f"{len(framework_hits)} match(es) — framework attribution:"
        for r, pipe_name, framework, technique, mitre in framework_hits:
            detail += f"\n          Pipe     : {pipe_name}"
            detail += f"\n          Framework: {framework}"
            detail += f"\n          Technique: {technique}"
            detail += f"\n          MITRE    : {mitre}"
        _print_check("Known C2 framework pipe naming pattern (attribution)",
                     YELLOW(f"NOTABLE — matches known {framework_hits[0][2]} pipe naming, "
                            f"not scored separately from Check 1"),
                     detail)
        findings["framework_pipes"] = framework_hits
    else:
        _print_check("Known C2 framework pipe naming pattern",
                     DIM("CLEAN — no known framework patterns (note: custom names evade this check)"))

    # ── Check 4: Unbacked threads in same region as pipe name ─────────
    pipe_regions = {hit["region"].BaseAddress for hit in private_pipes}
    unbacked_in_pipe_rgn = []
    for ti in infos:
        sa = ti.StartAddress or 0
        for r in regions:
            if r.BaseAddress in pipe_regions:
                if r.BaseAddress <= sa < r.BaseAddress + r.RegionSize:
                    if not addr_to_module(sa, modules):
                        unbacked_in_pipe_rgn.append((ti, r))

    if unbacked_in_pipe_rgn:
        detail = f"{len(unbacked_in_pipe_rgn)} unbacked thread(s) executing in pipe-name region"
        if verbose:
            for ti, r in unbacked_in_pipe_rgn:
                detail += (f"\n          TID=0x{ti.ThreadId:x}  "
                           f"StartAddr=0x{ti.StartAddress:x}  "
                           f"Region=0x{r.BaseAddress:x}")
        _print_check("Unbacked thread in same region as pipe name",
                     RED("SUSPICIOUS — active execution at pipe name location"),
                     detail)
        findings["unbacked_in_rgn"] = unbacked_in_pipe_rgn
        findings["score"] += 1
    else:
        _print_check("Unbacked threads in pipe-name region",
                     GREEN("CLEAN — no unbacked threads in regions containing pipe names"))

    # ── Verdict ───────────────────────────────────────────────────────
    score = findings["score"]
    c2_exhausted   = c2_budget.exhausted()
    name_exhausted = pipe_name_budget.exhausted()
    budget_exhausted = c2_exhausted or name_exhausted
    findings["budget_exhausted"] = budget_exhausted
    findings["scan_complete"] = not (budget_exhausted or skipped_size or read_failed)
    if not mem_info_available:
        status = NOT_EVALUATED
    elif score == 0 and (skipped_size or read_failed or budget_exhausted):
        status = INCONCLUSIVE
    else:
        status = DETECTED if score > 0 else NOT_DETECTED_IN_SCANNED_SCOPE
    findings["status"] = status

    if not mem_info_available:
        verdict = _status_text(NOT_EVALUATED, "MemoryInfoListStream missing from this dump")
    elif status == INCONCLUSIVE:
        reason = ", ".join(filter(None, [
            f"{skipped_size} oversized region(s) skipped" if skipped_size else "",
            f"{read_failed} region(s) failed to read" if read_failed else "",
            f"C2-context budget exhausted ({c2_budget.exhausted_reason})" if c2_exhausted else "",
            f"pipe-name budget exhausted ({pipe_name_budget.exhausted_reason})" if name_exhausted else "",
        ]))
        verdict = _status_text(INCONCLUSIVE, reason)
    else:
        verdict = (RED("HIGH CONFIDENCE C2 PIPE / LATERAL MOVEMENT") if score >= 3 else
                   YELLOW("LIKELY C2 PIPE")                           if score == 2 else
                   YELLOW("POSSIBLE C2 PIPE")                         if score == 1 else
                   GREEN("CLEAN — no named pipe C2 indicators"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/3 checks flagged — "
          f"framework attribution is informational, not separately scored)\n")

    if not verbose and private_pipes:
        print(DIM("  Use --verbose to expand pipe names, C2 strings, and thread details.\n"))

    return findings


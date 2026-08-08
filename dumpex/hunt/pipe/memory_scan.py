"""Per-region '\\pipe\\' string scan (ASCII/UTF-16LE) and the C2-context
records gathered from the same pipe-bearing regions. Only collects facts
— never scores, never prints. Applies TWO INDEPENDENT whole-hunt budgets
(pipe_name_budget, c2_budget) — see dumpex/hunt/pipe/config.py for why
they must never be merged.
"""
import os
import hashlib
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import addr_to_module, prot_str
from dumpex.hunt._coverage import region_scan_target
from dumpex.hunt.pipe.config import (PIPE_SCAN_MAX, PIPE_MAX_MATCHES_PER_REGION,
    PIPE_C2_MAX_HITS_PER_REGION, PIPE_C2_CONTEXT_BYTES, PIPE_C2_TOKEN_PREVIEW,
    PIPE_NAME_MAX_CHARS)
from dumpex.hunt.pipe.patterns import PIPE_PAT_ASCII, PIPE_PAT_UTF16, _iter_c2_matches
from dumpex.hunt.pipe.models import PipeNameScan


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
        key = (hit["region"].BaseAddress, hit["sha256"])
        if key not in seen:
            seen.add(key)
            deduped.append(hit)
    return deduped


def scan_pipe_names(mf: MinidumpFile, read_region, regions: list, modules: list,
                     coverage_counts, pipe_name_budget, c2_budget, c2_pattern) -> PipeNameScan:
    """
    Walk every committed, not-oversized region: collect '\\pipe\\' string
    occurrences (private_pipes / image_pipes) under pipe_name_budget, and
    — for any region that yielded a NEW private pipe name and while
    c2_budget still has room — C2-context match records under c2_budget.
    The two budgets are independent: pipe-name collection (Checks A/C/D's
    raw material) is unaffected by c2_budget running out, and vice versa.
    """
    private_pipes = []
    image_pipes = []
    region_c2_records = {}

    for r in regions:
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        if r.RegionSize > PIPE_SCAN_MAX:
            coverage_counts.note_skipped_oversize(
                region_scan_target(mf, r, PIPE_SCAN_MAX))
            continue
        if pipe_name_budget.exhausted() and c2_budget.exhausted():
            break   # nothing left this loop could still usefully collect
        mtype = prot_str(r.Type)
        mod   = addr_to_module(r.BaseAddress, modules)

        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            coverage_counts.note_read_failed()
            continue
        if len(data) < r.RegionSize:
            # Fewer bytes came back than the region's own declared size —
            # not the same as "read fine, nothing here". Still scan what
            # WAS returned (a real pipe name/C2 string can still be found
            # in the readable portion), but this region must not silently
            # count toward a "complete" scan.
            coverage_counts.note_short_read()
            if not data:
                continue
        pipes_before = len(private_pipes)

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
            # span, see patterns._iter_c2_matches) and build small, bounded
            # records right here while `data` is still in scope — the raw
            # region bytes are never cached or retained past this loop
            # iteration. Only Check B's C2-context gathering stops once
            # its budget is spent; pipe-name detection (Checks A/C/D) is
            # unaffected.
            records = []
            for start, end, token in _iter_c2_matches(data, c2_pattern, PIPE_C2_MAX_HITS_PER_REGION):
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

    private_pipes = dedupe_private_pipes(private_pipes)

    return PipeNameScan(private_pipes=private_pipes, image_pipes=image_pipes,
                         region_c2_records=region_c2_records,
                         coverage_counts=coverage_counts,
                         pipe_name_budget=pipe_name_budget, c2_budget=c2_budget)

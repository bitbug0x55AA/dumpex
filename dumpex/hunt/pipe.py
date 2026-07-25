"""Named pipe C2 hunter.

Phase-two detection model
──────────────────────────
The primary, scored signal is now **handle objects**, not string
scanning. HandleDataStream (when the dump was captured with
MiniDumpWithHandleData) records the OS's own account of every open
handle the process held, including .TypeName ("File" for a pipe handle)
and .ObjectName (the actual kernel object name, e.g.
"\\Device\\NamedPipe\\mypipe") — proof the process actually opened that
pipe, not just that the bytes "\\pipe\\mypipe" happen to sit somewhere in
its memory (which could be freed heap, a copy-pasted string, a decoy, or
data belonging to something else entirely).

The original memory-string scan for "\\pipe\\" occurrences is still run
— it is the only way to find a pipe name in a dump with no
HandleDataStream, and it is genuinely useful for locating nearby C2
context (URLs/IPs) and correlating execution — but per phase-two policy
it is explicitly demoted: a bare string match, on its own, is reported as
a `tag="lead"` / LOW-confidence finding and does NOT contribute to
`score`. Only a handle-object match — optionally corroborated by a
same-named string hit's surrounding C2 context or by a thread executing
in that string's region — can raise the verdict.
"""
import os
import re
import time
import hashlib
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, get_thread_contexts, get_handles,
    addr_to_module, va_to_file_offset, prot_str, read_region)
from dumpex.hunt._ui import (_print_hunt_header, _print_check, _status_text,
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE)
from dumpex.hunt._budget import ScanBudget
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION, overall_confidence)

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

# Handle ObjectName patterns identifying a named-pipe kernel object.
_HANDLE_PIPE_PAT = re.compile(r'\\Device\\NamedPipe\\|\\pipe\\', re.IGNORECASE)

# Known prefix forms a pipe reference can appear under — a kernel handle's
# ObjectName ("\Device\NamedPipe\foo"), a Win32 device-namespace string
# ("\\.\pipe\foo"), an NT-namespace string ("\??\pipe\foo"), or the bare
# ("\pipe\foo") form the byte-pattern scan matches.
#
# "\.\pipe\foo" (single leading backslash) is ALSO listed even though the
# genuine Win32 string is "\\.\pipe\foo" (two leading backslashes): the
# byte-pattern regex's "\\.\\pipe\\" alternative only anchors on ONE
# literal backslash before the "." (its second character class is "any
# byte", which the following literal backslash of the double-backslash
# prefix happens to satisfy) — so PIPE_PAT_ASCII/UTF16 always match
# starting one byte INTO a genuine "\\.\pipe\" string, and every preview
# built from that match (_extract_pipe_name) is missing the first
# backslash. Without this second entry, canonicalizing a string-scan hit
# never strips anything for that form and silently fails to line up with
# a handle's full "\Device\NamedPipe\foo" name.
_CANONICAL_PIPE_PREFIXES = (
    "\\device\\namedpipe\\",
    "\\\\.\\pipe\\",
    "\\.\\pipe\\",
    "\\??\\pipe\\",
    "\\pipe\\",
)


def canonical_pipe_name(name: str) -> str:
    """
    Strip any known pipe-namespace prefix and casefold, so the SAME pipe
    referenced via a kernel handle ("\\Device\\NamedPipe\\foo"), a Win32
    string ("\\\\.\\pipe\\foo"), or an NT-namespace string ("\\??\\pipe\\foo")
    all normalize to the identical "foo" for comparison.

    Callers MUST compare two canonical names for EXACT equality, never
    substring containment ("a in b or b in a") — substring containment
    means any pipe name that happens to be a prefix/suffix of another
    (e.g. "lsass" inside "lsass-rpc", or an empty/near-empty canonical
    name after a malformed match) silently links two UNRELATED pipes,
    which previously let a coincidental short-name match manufacture a
    handle+string "corroboration" that was never actually about the same
    pipe.
    """
    n = (name or "").strip().casefold()
    for prefix in _CANONICAL_PIPE_PREFIXES:
        if n.startswith(prefix):
            return n[len(prefix):]
    return n


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


def _is_pipe_handle(h) -> bool:
    if not getattr(h, "ObjectName", None):
        return False
    type_name = (getattr(h, "TypeName", None) or "").lower()
    if type_name and "file" not in type_name:
        return False
    return bool(_HANDLE_PIPE_PAT.search(h.ObjectName))


def _hunt_pipe(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Detect Named Pipe C2 / Lateral Movement channels.

    Primary (scored):
      Check A — HandleDataStream entries for open pipe handles, matched
                against known C2/lateral-movement framework naming
                conventions (rules.yaml framework_pipes).
      Check B — Corroboration of a handle-confirmed pipe: C2 artifacts
                (IP:port, HTTP URLs) or execution (current RIP/EIP, or a
                thread's StartAddress) found in the memory region backing
                a same-named string occurrence, when one exists.

    Secondary (leads, not scored):
      Memory-string "\\pipe\\" scan — kept for coverage when
      HandleDataStream is unavailable and to locate the regions Check B
      correlates against, but a bare string match is never, by itself,
      evidence of anything (see module docstring).
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    infos   = get_thread_infos(mf)
    thread_contexts = get_thread_contexts(mf)
    handles = get_handles(mf)
    mem_info_available    = bool(mf.memory_info and mf.memory_info.infos)
    # Stream PRESENCE, not "the handle list happens to be non-empty" — a
    # dump captured with MiniDumpWithHandleData can legitimately show a
    # process holding zero pipe handles (or, in principle, zero handles at
    # all); that is a checked-and-clean result, not "the stream is
    # missing". Only `mf.handles is None` means the stream itself wasn't
    # captured, and only THAT should report "NOT AVAILABLE".
    handle_stream_available = mf.handles is not None

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

    findings = {
        "handle_pipes":    [],   # [{"handle", "framework_match"}, ...]
        "private_pipes":   [],   # string-scan leads (unchanged shape)
        "c2_context":      [],
        "framework_pipes": [],
        "unbacked_in_rgn": [],
        "score": 0,
    }

    _print_hunt_header("Named Pipe C2 / Lateral Movement")

    # ── Check A (primary, scored): handle objects ────────────────────────
    handle_pipe_hits = [h for h in handles if _is_pipe_handle(h)]
    findings_list = []

    def _framework_match(name: str):
        for pat, framework, technique, mitre in KNOWN_FRAMEWORK_PIPES:
            if pat.search(name):
                return (framework, technique, mitre)
        return None

    handle_classified = []   # {"handle", "canonical_name", "framework_match"}
    for h in handle_pipe_hits:
        handle_classified.append({
            "handle": h, "canonical_name": canonical_pipe_name(h.ObjectName),
            "framework_match": _framework_match(h.ObjectName),
        })

    if handle_stream_available:
        if handle_pipe_hits:
            facts = []
            for hc in handle_classified[:20]:
                h = hc["handle"]
                fm = f"  [framework={hc['framework_match'][0]}]" if hc["framework_match"] else ""
                facts.append(f"Handle=0x{h.Handle:x} ObjectName={h.ObjectName} "
                             f"GrantedAccess=0x{h.GrantedAccess:x}{fm}")
            if len(handle_classified) > 20:
                facts.append(f"... and {len(handle_classified)-20} more")
            findings_list.append(Finding(
                check="pipe.open_handles",
                facts=facts,
                inference=f"Process holds {len(handle_pipe_hits)} open handle(s) to named "
                           f"pipe object(s), per HandleDataStream.",
                confidence=CONFIDENCE_MEDIUM,
                rationale="HandleDataStream is the OS's own record of what this process "
                           "actually has open — far stronger than a bare string match, but "
                           "having ANY pipe handle open is completely ordinary for most "
                           "Windows processes (IPC, RPC, print spooler, etc.); only a "
                           "handle whose name matches a known C2/lateral-movement framework "
                           "convention, or one corroborated by nearby C2 context / active "
                           "execution, is treated as a detection.",
                limitations=["Presence of a pipe handle is not inherently suspicious."],
                tag=TAG_OBSERVATION,
            ))
            _print_check("Open pipe handles (HandleDataStream)",
                         GREEN(f"{len(handle_pipe_hits)} found") if not any(hc["framework_match"] for hc in handle_classified)
                         else RED("SUSPICIOUS — framework-pattern match"),
                         f"{len(handle_pipe_hits)} pipe handle(s)" if not verbose else
                         "\n          " + "\n          ".join(f"0x{hc['handle'].Handle:x}  {hc['handle'].ObjectName}"
                                                                for hc in handle_classified))
        else:
            _print_check("Open pipe handles (HandleDataStream)",
                         GREEN("CLEAN — no pipe handles open"))
    else:
        _print_check("Open pipe handles (HandleDataStream)",
                     YELLOW("NOT AVAILABLE — dump was not captured with MiniDumpWithHandleData"))

    findings["handle_pipes"] = handle_classified

    framework_handle_hits = [hc for hc in handle_classified if hc["framework_match"]]
    if framework_handle_hits:
        facts = []
        for hc in framework_handle_hits:
            h = hc["handle"]
            fw, tech, mitre = hc["framework_match"]
            facts.append(f"Handle=0x{h.Handle:x} ObjectName={h.ObjectName} "
                         f"framework={fw} technique={tech} mitre={mitre}")
        findings_list.append(Finding(
            check="pipe.handle_framework_match",
            facts=facts,
            inference=f"{len(framework_handle_hits)} open pipe handle(s) match a known "
                       f"C2/lateral-movement framework naming convention.",
            confidence=CONFIDENCE_MEDIUM,
            rationale="An OS-confirmed open handle (not just a string sitting in memory) "
                       "whose name matches a specific, narrow framework convention "
                       "(e.g. Cobalt Strike's msagent_/postex_ or PsExec's psexesvc) is "
                       "meaningfully unlikely to be coincidental — raised to HIGH only "
                       "when further corroborated (see pipe.corroboration below).",
            limitations=["Framework pipe-name conventions can be renamed/customized by an "
                         "operator; absence of a match does not mean absence of C2."],
            tag=TAG_DETECTION,
        ))
        findings["framework_pipes"] = framework_handle_hits

    # ── Collect all pipe name occurrences (string scan — lead only) ──────
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
    findings["private_pipes"] = private_pipes

    if private_pipes:
        facts = []
        for hit in private_pipes[:15]:
            r = hit["region"]
            abs_va = r.BaseAddress + hit["offset"]
            fo = va_to_file_offset(mf, abs_va)
            fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
            facts.append(f"VA=0x{abs_va:x} file_offset={fo_str} name={hit['name'].strip()!r} "
                         f"region_type={prot_str(r.Type)}")
        if len(private_pipes) > 15:
            facts.append(f"... and {len(private_pipes)-15} more")
        findings_list.append(Finding(
            check="pipe.string_scan_lead",
            facts=facts,
            inference=f"{len(private_pipes)} occurrence(s) of a '\\pipe\\' name found in "
                       f"non-system-DLL memory via byte-pattern scan.",
            confidence=CONFIDENCE_LOW,
            rationale="A string match proves only that these bytes exist somewhere in "
                       "memory — not that any handle was ever opened by that name, nor "
                       "that the name isn't leftover/freed heap data or an unrelated "
                       "buffer. Reported as a lead for the analyst and to locate regions "
                       "for C2-context/execution correlation; does NOT contribute to the "
                       "pipe score on its own.",
            limitations=["Not corroborated by HandleDataStream."] if not handle_stream_available
                        else ["No corresponding open handle found for this exact name."],
            tag=TAG_LEAD,
        ))
        _print_check("Pipe name strings in non-system memory (lead only)",
                     YELLOW("LEAD — not scored, see handle checks above"),
                     f"{len(private_pipes)} occurrence(s)")
    else:
        _print_check("Pipe name strings in non-system memory",
                     GREEN("CLEAN — no pipe-name byte patterns found"))

    if image_pipes and verbose:
        mod_names = sorted({h["module"] for h in image_pipes})
        print(DIM(f"  [·] {len(image_pipes)} pipe reference(s) in system DLLs "
                  f"({', '.join(mod_names)}) — expected, skipped\n"))

    if pipe_name_budget.exhausted():
        print(YELLOW(f"  [~] Pipe-name scan budget exhausted "
                      f"({pipe_name_budget.exhausted_reason}) — some regions may not "
                      f"have been checked for pipe names.\n"))

    # ── Check B (corroboration, scored): C2 context / execution near a ───
    # handle-confirmed pipe's matching string occurrence, if one exists.
    c2_hits = []
    for hit in private_pipes:
        records = region_c2_records.get(hit["region"].BaseAddress)
        if not records:
            continue
        c2_hits.append((hit["region"], hit["name"].strip(), records))
    findings["c2_context"] = c2_hits

    def _string_hit_for_handle(canonical_name: str):
        """
        EXACT match on canonicalized names only — see canonical_pipe_name()
        docstring for why substring containment ("a in b or b in a") is
        wrong here: it lets an unrelated pipe whose name happens to be a
        prefix/suffix of another (or an empty canonical name from a
        malformed match) manufacture a false "same pipe" link.
        """
        if not canonical_name:
            return None
        for hit in private_pipes:
            if canonical_pipe_name(hit["name"]) == canonical_name:
                return hit
        return None

    corroborated_handles = []   # (handle_classified_entry, string_hit, c2_records, exec_hit)
    for hc in handle_classified:
        sh = _string_hit_for_handle(hc["canonical_name"])
        if sh is None:
            continue
        c2_records = region_c2_records.get(sh["region"].BaseAddress)
        r = sh["region"]
        exec_hit = None
        for tc in thread_contexts:
            if r.BaseAddress <= tc["ip"] < r.BaseAddress + r.RegionSize:
                exec_hit = ("rip", tc)
                break
        if exec_hit is None:
            for ti in infos:
                sa = ti.StartAddress or 0
                if r.BaseAddress <= sa < r.BaseAddress + r.RegionSize and not addr_to_module(sa, modules):
                    exec_hit = ("start_addr", ti)
                    break
        if c2_records or exec_hit:
            corroborated_handles.append((hc, sh, c2_records, exec_hit))

    if corroborated_handles:
        facts = []
        for hc, sh, c2_records, exec_hit in corroborated_handles[:10]:
            h = hc["handle"]
            f = f"Handle=0x{h.Handle:x} ObjectName={h.ObjectName} region=0x{sh['region'].BaseAddress:x}"
            if c2_records:
                f += f"  C2_context={c2_records[0]['match']!r}"
            if exec_hit:
                kind, obj = exec_hit
                f += (f"  live_rip=TID:0x{obj['ThreadId']:x}@{obj['ip_reg']}" if kind == "rip"
                      else f"  unbacked_thread_start=TID:0x{obj.ThreadId:x}")
            facts.append(f)
        # HIGH only when at least one corroborated handle has BOTH C2
        # context AND execution evidence at once (the score=3 case below) —
        # a Finding's confidence must track what actually justified it, not
        # be uniformly HIGH regardless of whether one or both signals fired.
        full_corroboration = any(c2 and ex for _, _, c2, ex in corroborated_handles)
        findings_list.append(Finding(
            check="pipe.corroboration",
            facts=facts,
            inference=f"{len(corroborated_handles)} open pipe handle(s) are corroborated "
                       f"by C2-style context and/or active/unbacked-thread execution in "
                       f"the memory region backing a matching pipe-name string.",
            confidence=CONFIDENCE_HIGH if full_corroboration else CONFIDENCE_MEDIUM,
            rationale=("Combines an OS-confirmed open handle with BOTH independent memory "
                       "signals (C2 artifacts AND execution) in the SAME region as that "
                       "pipe's name string — the strongest correlation this hunter can "
                       "produce." if full_corroboration else
                       "Combines an OS-confirmed open handle with ONE independent memory "
                       "signal (C2 artifacts or execution, not both) in the same region as "
                       "that pipe's name string."),
            limitations=["Name correlation between a handle's ObjectName and a string scan "
                         "hit uses exact match on the canonicalized pipe name (prefix "
                         "stripped, casefolded) — still not a cryptographic guarantee both "
                         "refer to the identical kernel object if the process has multiple "
                         "same-named pipe instances."],
            tag=TAG_DETECTION,
        ))
        for hc, sh, c2_records, exec_hit in corroborated_handles:
            h = hc["handle"]
            detail = f"ObjectName={h.ObjectName}  region=0x{sh['region'].BaseAddress:x}"
            _print_check("Handle-confirmed pipe corroborated by memory evidence",
                         RED("SUSPICIOUS — C2 context and/or execution near handle-confirmed pipe"),
                         detail)

    if c2_hits and verbose:
        detail = f"{len(c2_hits)} region(s) with pipe-name string + C2 artifacts (uncorrelated to a handle)"
        for r, pipe_name, records in c2_hits:
            detail += f"\n          Region 0x{r.BaseAddress:x}  pipe: {pipe_name}"
            for rec in records[:3]:
                detail += (f"\n            C2: {rec['match']}"
                           f"  VA 0x{rec['va']:016x}"
                           f"  sha256={rec['sha256'][:16]}…")
        print(DIM(detail) + "\n")
    if c2_budget.exhausted():
        print(YELLOW(f"  [~] C2-context scan budget exhausted "
                      f"({c2_budget.exhausted_reason}) — some pipe-bearing regions "
                      f"may not have been checked for C2 context.\n"))

    # ── Check 3: Known framework patterns on the STRING leads too ─────────
    # (attribution only — a name-pattern match on a string that has no
    # corresponding handle is still informational, not separately scored)
    framework_string_hits = []  # (region, full_pipe_name, framework, technique, mitre_id)
    for hit in private_pipes:
        r = hit["region"]
        clean = hit["name"].strip()
        for pat, framework, technique, mitre in KNOWN_FRAMEWORK_PIPES:
            if pat.search(clean):
                framework_string_hits.append((r, clean, framework, technique, mitre))
                break

    if framework_string_hits:
        detail = f"{len(framework_string_hits)} match(es) on string leads — framework attribution (not scored):"
        for r, pipe_name, framework, technique, mitre in framework_string_hits:
            detail += f"\n          Pipe     : {pipe_name}"
            detail += f"\n          Framework: {framework}"
            detail += f"\n          Technique: {technique}"
            detail += f"\n          MITRE    : {mitre}"
        _print_check("Known C2 framework pipe naming pattern (string lead attribution)",
                     YELLOW(f"NOTABLE — matches known {framework_string_hits[0][2]} pipe naming, "
                            f"lead only"),
                     detail)
    else:
        _print_check("Known C2 framework pipe naming pattern (string leads)",
                     DIM("CLEAN — no known framework patterns among string leads"))

    # ── Check 4: Unbacked threads in same region as a string pipe-name lead ──
    # (kept for analyst visibility; NOT independently scored — see
    # pipe.corroboration above for the scored, handle-anchored version)
    pipe_regions = {hit["region"].BaseAddress for hit in private_pipes}
    unbacked_in_pipe_rgn = []
    for ti in infos:
        sa = ti.StartAddress or 0
        for r in regions:
            if r.BaseAddress in pipe_regions:
                if r.BaseAddress <= sa < r.BaseAddress + r.RegionSize:
                    if not addr_to_module(sa, modules):
                        unbacked_in_pipe_rgn.append((ti, r))
    findings["unbacked_in_rgn"] = unbacked_in_pipe_rgn

    if unbacked_in_pipe_rgn and verbose:
        detail = f"{len(unbacked_in_pipe_rgn)} unbacked thread(s) executing in a pipe-name-string region (lead only)"
        for ti, r in unbacked_in_pipe_rgn:
            detail += (f"\n          TID=0x{ti.ThreadId:x}  "
                       f"StartAddr=0x{ti.StartAddress:x}  "
                       f"Region=0x{r.BaseAddress:x}")
        print(DIM(detail) + "\n")

    # ── Print corroboration/handle findings ──────────────────────────────
    for f in findings_list:
        if f.tag == TAG_DETECTION:
            f.print()

    # ── Score / Verdict ───────────────────────────────────────────────────
    # 0 — string leads / a generic open handle only.
    # 1 — a handle-confirmed pipe matches a known C2/lateral-movement
    #     framework naming convention (OS-confirmed usage + specific name),
    #     even with no further corroboration.
    # 2 — ANY handle-confirmed pipe (framework-matched or not) is
    #     corroborated by C2-style context OR execution evidence in the
    #     region backing a same-named string occurrence.
    # 3 — corroborated by BOTH C2 context AND execution evidence at once.
    #
    # Deliberately NOT gated on framework_match for tiers 2-3: a
    # same-named handle actively corroborated by C2 context or live
    # execution is strong evidence on its own (an OS-confirmed handle
    # PLUS independent memory evidence in the same region), and requiring
    # a framework-name match on top of that would silently downgrade a
    # genuinely corroborated custom/non-framework pipe to a Finding the
    # score doesn't reflect — exactly the Finding/verdict mismatch this
    # scoring model exists to avoid.
    score = 0
    if framework_handle_hits:
        score = 1
    for hc, sh, c2_records, exec_hit in corroborated_handles:
        if c2_records and exec_hit:
            score = max(score, 3)
        elif c2_records or exec_hit:
            score = max(score, 2)

    findings["score"] = score
    findings["max_score"] = 3

    c2_exhausted   = c2_budget.exhausted()
    name_exhausted = pipe_name_budget.exhausted()
    budget_exhausted = c2_exhausted or name_exhausted
    findings["budget_exhausted"] = budget_exhausted
    findings["scan_complete"] = not (budget_exhausted or skipped_size or read_failed)
    findings["findings"] = [f.to_dict() for f in findings_list]

    # Coverage is tracked independently of status/score, so "DETECTED but
    # coverage was partial" stays representable rather than a nonzero
    # score silently implying every region/handle was checked.
    coverage_reasons = []
    if not mem_info_available:
        coverage_reasons.append("MemoryInfoListStream missing from this dump")
    if not handle_stream_available:
        coverage_reasons.append("HandleDataStream missing from this dump (needs "
                                 "MiniDumpWithHandleData) — the primary, scored "
                                 "pipe-handle check could not run")
    if skipped_size:
        coverage_reasons.append(f"{skipped_size} oversized region(s) skipped")
    if read_failed:
        coverage_reasons.append(f"{read_failed} region(s) failed to read")
    if c2_exhausted:
        coverage_reasons.append(f"C2-context scan budget exhausted ({c2_budget.exhausted_reason})")
    if name_exhausted:
        coverage_reasons.append(f"pipe-name scan budget exhausted ({pipe_name_budget.exhausted_reason})")

    evaluated = mem_info_available or handle_stream_available
    if not evaluated:
        coverage_status = "not_evaluated"
    elif not handle_stream_available or skipped_size or read_failed or budget_exhausted:
        coverage_status = "partial"
    else:
        coverage_status = "complete"
    findings["coverage_status"]  = coverage_status
    findings["coverage_reasons"] = coverage_reasons

    if coverage_status == "not_evaluated":
        status = NOT_EVALUATED
    elif score > 0:
        status = DETECTED
    elif coverage_status == "partial":
        # The PRIMARY (scored) check may not have run at all (no
        # HandleDataStream) or ran incompletely — a negative score here
        # must not be read the same as "checked and clean".
        status = INCONCLUSIVE
    else:
        status = NOT_DETECTED_IN_SCANNED_SCOPE
    findings["status"] = status
    findings["confidence"] = overall_confidence(findings_list, score)

    if not evaluated:
        verdict = _status_text(NOT_EVALUATED, "MemoryInfoListStream and HandleDataStream both missing from this dump")
    elif not handle_stream_available:
        verdict = _status_text(INCONCLUSIVE,
            "HandleDataStream not in this dump (needs MiniDumpWithHandleData) — the "
            "primary, scored pipe-handle check could not run; only unscored string "
            "leads are available above")
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
                   GREEN("CLEAN — no handle-confirmed C2 pipe indicators"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/3 — handle-anchored; string leads "
          f"shown above are informational only)\n")

    if not verbose and (private_pipes or handle_pipe_hits):
        print(DIM("  Use --verbose to expand handle list, pipe names, and C2 strings.\n"))

    return findings

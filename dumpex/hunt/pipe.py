"""Named pipe C2 hunter."""
import os
import re
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.rules_pkg.loader import get_rules, SUSPICIOUS_PROTS
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, addr_to_module, va_to_file_offset, prot_str,
    read_region, _extract_strings_from_data)
from dumpex.hunt._ui import _print_hunt_header, _print_check

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
        "private_pipes":   [],   # (region, offset, name)
        "c2_context":      [],   # (region, pipe_name, c2_strings)
        "framework_pipes": [],   # (region, pipe_name, pattern)
        "unbacked_in_rgn": [],   # (thread_info, region)
        "score": 0,
    }

    _print_hunt_header("Named Pipe C2 / Lateral Movement")

    # ── Collect all pipe name occurrences ────────────────────────────
    private_pipes = []   # (region, offset, decoded_name)
    image_pipes   = []   # (region, mod_name, decoded_name)

    for r in regions:
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        mtype = prot_str(r.Type)
        mod   = addr_to_module(r.BaseAddress, modules)

        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue

        def _extract_pipe_name(data, m, is_utf16):
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
                try:
                    return raw.decode("utf-16-le", errors="replace")
                except Exception:
                    return repr(raw)
            else:
                while end < len(data) and 32 <= data[end] < 127:
                    end += 1
                raw = data[m.start():end]
                try:
                    return raw.decode("ascii", errors="replace")
                except Exception:
                    return repr(raw)

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

        for m in PIPE_PAT_ASCII.finditer(data):
            name = _extract_pipe_name(data, m, is_utf16=False)
            if "MEM_IMAGE" in mtype and _is_system_dll(mod):
                image_pipes.append((r, os.path.basename(mod.name), name))
            else:
                private_pipes.append((r, m.start(), name))

        for m in PIPE_PAT_UTF16.finditer(data):
            name = _extract_pipe_name(data, m, is_utf16=True)
            if "MEM_IMAGE" in mtype and _is_system_dll(mod):
                image_pipes.append((r, os.path.basename(mod.name), name))
            else:
                private_pipes.append((r, m.start(), name))

    # Deduplicate private pipes by (region_base, name)
    seen_private = set()
    deduped = []
    for r, off, name in private_pipes:
        key = (r.BaseAddress, name.strip())
        if key not in seen_private:
            seen_private.add(key)
            deduped.append((r, off, name))
    private_pipes = deduped

    # ── Check 1: Pipe names outside trusted system DLLs ──────────────
    if private_pipes:
        detail = f"{len(private_pipes)} pipe name(s) in non-system memory"
        if verbose:
            for r, off, name in private_pipes:
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
                detail += (f"\n          VA (process)   0x{abs_va:016x}{rwx}{backer}"
                           f"\n          File offset    {fo_str}"
                           f"\n          Region base    0x{r.BaseAddress:016x}"
                           f"\n          Pipe name: {name.strip()}")
        _print_check("Pipe names outside trusted system DLLs",
                     RED("SUSPICIOUS — pipe name found in non-system memory"),
                     detail)
        findings["private_pipes"] = private_pipes
        findings["score"] += 1
    else:
        _print_check("Pipe names outside trusted system DLLs",
                     GREEN("CLEAN — all pipe name references are in known system modules"))

    if image_pipes and verbose:
        mod_names = sorted({n for _, n, _ in image_pipes})
        print(DIM(f"  [·] {len(image_pipes)} pipe reference(s) in system DLLs "
                  f"({', '.join(mod_names)}) — expected, skipped\n"))

    # ── Check 2: C2 artifacts near private pipe names ─────────────────
    c2_hits = []
    for r, off, pipe_name in private_pipes:
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue
        # Scan strings in the whole region for C2 patterns
        strings = _extract_strings_from_data(data, min_len=6)
        c2_strings = [s for _, _, s in strings if C2_PAT.search(s)]
        if c2_strings:
            c2_hits.append((r, pipe_name.strip(), c2_strings))

    if c2_hits:
        detail = f"{len(c2_hits)} region(s) with pipe name + C2 artifacts"
        if verbose:
            for r, pipe_name, c2s in c2_hits:
                detail += f"\n          Region 0x{r.BaseAddress:x}  pipe: {pipe_name}"
                for s in c2s[:3]:
                    detail += f"\n            C2: {s}"
                if len(c2s) > 3:
                    detail += f"\n            ... and {len(c2s)-3} more"
        _print_check("C2 artifacts co-located with pipe name",
                     RED("SUSPICIOUS — C2 IP/URL in same region as private pipe name"),
                     detail)
        findings["c2_context"] = c2_hits
        findings["score"] += 1
    else:
        _print_check("C2 artifacts near pipe names",
                     GREEN("CLEAN — no C2 patterns found near private pipe names"))

    # ── Check 3: Known framework patterns with attribution ───────────
    framework_hits = []  # (region, full_pipe_name, framework, technique, mitre_id)
    for r, off, name in private_pipes:
        clean = name.strip()
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
        _print_check("Known C2 framework pipe naming pattern",
                     RED(f"SUSPICIOUS — {framework_hits[0][2]} pipe pattern identified"),
                     detail)
        findings["framework_pipes"] = framework_hits
        findings["score"] += 1
    else:
        _print_check("Known C2 framework pipe naming pattern",
                     DIM("CLEAN — no known framework patterns (note: custom names evade this check)"))

    # ── Check 4: Unbacked threads in same region as pipe name ─────────
    pipe_regions = {r.BaseAddress for r, _, _ in private_pipes}
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
    verdict = (RED("HIGH CONFIDENCE C2 PIPE / LATERAL MOVEMENT") if score >= 3 else
               YELLOW("LIKELY C2 PIPE")                           if score == 2 else
               YELLOW("POSSIBLE C2 PIPE")                         if score == 1 else
               GREEN("CLEAN — no named pipe C2 indicators"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/4 checks flagged)\n")

    if not verbose and private_pipes:
        print(DIM("  Use --verbose to expand pipe names, C2 strings, and thread details.\n"))

    return findings


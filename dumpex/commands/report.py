"""--report command."""
import os
import re
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, addr_to_module, va_to_file_offset, prot_str,
    read_region, parse_hex_or_int, INDICATOR_DIMS,
    _get_region_at, _extract_strings_from_data,
    _hexdump_context, _verdict, _search_string_in_memory)
from dumpex.rules_pkg.loader import SUSPICIOUS_PROTS

def _get_region_at(addr: int, regions: list):
    """Find the memory region containing addr."""
    for r in regions:
        if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
            return r
    return None


def _extract_strings_from_data(data: bytes, min_len: int = 6) -> list:
    """\n    Extract ASCII and UTF-16LE strings.\n    Returns list of (offset, enc, string).\n    UTF-16LE covers Windows API names, registry paths, and wide-char C2\n    configs that pure ASCII scans miss entirely.\n    """
    results = []
    pat_ascii = rb'[ -~]{' + str(min_len).encode() + rb',}'
    results += [(m.start(), "ASCII", m.group().decode("ascii", errors="replace"))
                for m in re.finditer(pat_ascii, data)]
    pat_uni = rb'(?:[ -~]\x00){' + str(min_len).encode() + rb',}'
    results += [(m.start(), "UTF16", m.group().decode("utf-16-le", errors="replace"))
                for m in re.finditer(pat_uni, data)]
    results.sort(key=lambda x: x[0])
    return results


def _hexdump_context(data: bytes, offset: int, region_base: int,
                     before: int = 128, after: int = 128) -> str:
    """\n    Hex+ASCII mixed dump of bytes surrounding offset within data.\n    Used for context-aware IOC display (e.g. UA string near C2 IP/port).\n    """
    start     = max(0, offset - before)
    end       = min(len(data), offset + after)
    chunk     = data[start:end]
    hit_rel   = offset - start

    lines = []
    for i in range(0, len(chunk), 16):
        row     = chunk[i:i+16]
        addr    = region_base + start + i
        hex_col = " ".join(f"{b:02x}" for b in row).ljust(48)
        asc_col = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        if i <= hit_rel < i + 16:
            lines.append(f"    {YELLOW(f'0x{addr:016x}')}  {YELLOW(hex_col)}  {YELLOW(asc_col)}")
        else:
            lines.append(f"    {DIM(f'0x{addr:016x}')}  {hex_col}  {DIM(asc_col)}")
    return "\n".join(lines)


def _verdict(dims: dict) -> str:
    score = len(dims)
    if score == 0:
        return GREEN("CLEAN — no suspicious indicators found")
    if score == 1:
        return YELLOW("SUSPICIOUS — 1 independent indicator")
    if score == 2:
        return YELLOW("LIKELY MALICIOUS — 2 independent indicators")
    return RED(f"HIGH CONFIDENCE MALICIOUS — {score} independent indicators")


def _search_string_in_memory(mf: MinidumpFile, needle: str) -> list:
    """\n    Search all committed memory regions for needle (ASCII and UTF-16LE).\n    Returns list of (region, offset, encoding) tuples, one per hit region\n    (deduplicated by region base so we report each region once).\n    """
    regions  = get_memory_regions(mf)
    hits     = []
    seen     = set()
    needle_b = needle.encode("ascii", errors="replace")
    needle_w = needle.encode("utf-16-le")

    for r in regions:
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        if r.BaseAddress in seen:
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue

        off_a = data.find(needle_b)
        if off_a != -1:
            hits.append((r, off_a, "ASCII"))
            seen.add(r.BaseAddress)
            continue

        off_w = data.find(needle_w)
        if off_w != -1:
            hits.append((r, off_w, "UTF16"))
            seen.add(r.BaseAddress)

    return hits


def cmd_report(mf: MinidumpFile, report_tid: str = None, report_addr: str = None,
              report_string: str = None, extract_to: str = None, min_len: int = 6):
    """\n    Alert triage card: given a TID, address, or string from an EDR alert / TI feed,\n    correlate thread, memory, and string evidence into a structured verdict.\n    Verdict uses MECE dimensions — each dimension scored at most once.\n\n    --report-string: search all memory for the string, then run triage on each\n                    matching region. Useful when the anchor is a C2 IP, domain,\n                    or known malware string from threat intelligence.\n    """
    # ── String search mode: find regions, then triage each one ───────
    if report_string and not report_addr:
        modules_list = get_modules(mf)

        print(f"\n{BOLD('Searching memory for:')} {CYAN(repr(report_string))}")
        print("─" * 55)
        hits = _search_string_in_memory(mf, report_string)
        if not hits:
            print(RED(f"  [!] String not found in any committed memory region."))
            print(DIM("      Try --strings with a broader address range to verify."))
            return

        # Split into actionable (MEM_PRIVATE / no module) vs noise (MEM_IMAGE in known module)
        private_hits = []
        image_hits   = []
        for r, off, enc in hits:
            mtype  = prot_str(r.Type)
            mod    = addr_to_module(r.BaseAddress, modules_list)
            if "MEM_IMAGE" in mtype and mod:
                image_hits.append((r, off, enc, mod))
            else:
                private_hits.append((r, off, enc))

        # Summary line
        print(GREEN(f"  [+] Found in {len(hits)} region(s):"))
        for r, off, enc in private_hits:
            abs_addr = r.BaseAddress + off
            fo_abs   = va_to_file_offset(mf, abs_addr)
            fo_str   = f"0x{fo_abs:x}" if fo_abs is not None else "(not captured)"
            p        = prot_str(r.Protect)
            t        = prot_str(r.Type)
            rwx_tag  = RED(" ◄ RWX") if any(s in p for s in SUSPICIOUS_PROTS) else ""
            print(f"    {RED('►')} [{enc}]  {p}  {t}{rwx_tag}")
            print(f"      VA  = region base 0x{r.BaseAddress:016x}  +  offset 0x{off:x}  =  0x{abs_addr:016x}")
            print(f"      DMP = file offset {fo_str}")
        if image_hits:
            mod_names = sorted({os.path.basename(m.name) for _, _, _, m in image_hits})
            print(DIM(f"    [·] {len(image_hits)} hit(s) in known MEM_IMAGE modules "
                      f"({', '.join(mod_names)}) — skipped (expected content)"))
        print()

        if not private_hits:
            print(DIM("  [·] All hits are in known system modules — no actionable regions to triage."))
            return

        # Run full triage only on private/unregistered hits
        for i, (r, off, enc) in enumerate(private_hits, 1):
            if len(private_hits) > 1:
                print(BOLD(f"{'═'*55}"))
                print(BOLD(f"  Triaging hit {i}/{len(private_hits)} — region 0x{r.BaseAddress:x}"))
                print(BOLD(f"{'═'*55}"))
            cmd_report(mf,
                      report_tid=report_tid,
                      report_addr=hex(r.BaseAddress),
                      report_string=None,   # prevent recursion
                      extract_to=extract_to,
                      min_len=min_len)
        return

    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    infos   = get_thread_infos(mf)
    tid_map = {ti.ThreadId: ti for ti in infos}

    tid_int  = parse_hex_or_int(report_tid)  if report_tid  else None
    addr_int = parse_hex_or_int(report_addr) if report_addr else None

    dims: dict  = {}          # MECE verdict dimensions
    target_addr = addr_int
    region      = None        # resolved in section 2, reused throughout

    IOC_PATTERNS = re.compile(
        r'https?://|cmd\.exe|powershell|CreateRemoteThread'
        r'|VirtualAlloc|WriteProcessMemory|WinExec|\\pipe\\'
        r'|base64|decode|payload|shellcode|beacon|cobalt'
        r'|LoadLibrary|GetProcAddress|InternetOpen|WSASocket',
        re.IGNORECASE
    )
    NET_PATTERNS = re.compile(
        r'https?://|User-Agent|Content-Type|Host:|Accept:|POST |GET '
        r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|:\d{2,5}$',
        re.IGNORECASE
    )

    print(f"\n{BOLD('══════════════════════════════════════════')}")
    print(f"{BOLD('  dumpex TRIAGE REPORT')}")
    print(f"{BOLD('══════════════════════════════════════════')}")
    print(f"  File : {os.path.basename(mf.filename)}")
    if report_tid:  print(f"  TID  : {report_tid}")
    if report_addr: print(f"  Addr : {report_addr}")
    print()

    # ── 1. Thread analysis ────────────────────────────────────────────
    if tid_int is not None:
        print(BOLD("[ 1 ] THREAD ANALYSIS"))
        print("─" * 50)
        thread_info = tid_map.get(tid_int)
        if not thread_info:
            print(RED(f"  [!] TID 0x{tid_int:x} not found in dump."))
            print(DIM("      Thread may have exited before dump was taken."))
        else:
            sa  = thread_info.StartAddress or 0
            mod = addr_to_module(sa, modules)
            print(f"  {'TID':<22} 0x{thread_info.ThreadId:x}")
            print(f"  {'Start Address':<22} 0x{sa:x}")
            print(f"  {'Kernel Time':<22} {thread_info.KernelTime}")
            print(f"  {'User Time':<22} {thread_info.UserTime}")
            if mod:
                print(f"  {'Backed By':<22} {GREEN(mod.name)}")
                print(f"  {'Module Range':<22} 0x{mod.baseaddress:x} — 0x{mod.endaddress:x}")
            else:
                print(f"  {'Backed By':<22} {RED('NOT IN ANY MODULE ⚠')}")
                dims['unbacked_thread'] = (
                    f"TID 0x{thread_info.ThreadId:x} start addr 0x{sa:x} "
                    f"has no module backing"
                )
            if target_addr is None:
                target_addr = sa
        print()

    # ── 2. Memory region ─────────────────────────────────────────────
    if target_addr is not None:
        print(BOLD("[ 2 ] MEMORY REGION AT TARGET ADDRESS"))
        print("─" * 50)
        region = _get_region_at(target_addr, regions)
        if not region:
            print(RED(f"  [!] No committed region found at 0x{target_addr:x}"))
            print(DIM("      Address may not be in a page captured by this dump."))
        else:
            p          = prot_str(region.Protect)
            mtype      = prot_str(region.Type)
            rmod       = addr_to_module(region.BaseAddress, modules)
            is_rwx     = any(s in p for s in SUSPICIOUS_PROTS)
            is_private = "MEM_PRIVATE" in mtype

            fo_reg = va_to_file_offset(mf, region.BaseAddress)
            fo_reg_str = f"0x{fo_reg:x}" if fo_reg is not None else "(not captured in dump)"
            print(f"  {'Region base (VA)':<24} 0x{region.BaseAddress:016x}  {DIM('← process virtual address')}")
            print(f"  {'Region base (file offset)':<24} {fo_reg_str}  {DIM('← byte offset inside .dmp')}")
            print(f"  {'Physical addr (RAM)':<24} {DIM('not recorded in minidumps')}")
            print(f"  {'IOC addr = base + offset':<24} {DIM('see formula per string below')}")
            print(f"  {'Region Size':<24} 0x{region.RegionSize:x}  ({region.RegionSize // 1024} KB)")
            print(f"  {'Protection':<22} {RED(p) if is_rwx else p}")
            print(f"  {'Type':<22} {mtype}")
            print(f"  {'Module Owner':<22} "
                  f"{DIM(rmod.name) if rmod else RED('none — unregistered private memory')}")

            if is_rwx and is_private:
                print(f"\n  {RED('[!] RWX + MEM_PRIVATE — classic shellcode/injection marker')}")
                dims['rwx_private'] = (
                    f"Region 0x{region.BaseAddress:x} is "
                    f"PAGE_EXECUTE_READWRITE + MEM_PRIVATE"
                )
            elif is_rwx:
                print(f"\n  {YELLOW('[~] PAGE_EXECUTE_READWRITE (module-backed — notable but less suspicious)')}")

            try:
                header = read_region(mf, region.BaseAddress, min(64, region.RegionSize))
                if header[:2] == b'MZ' and not rmod:
                    print(f"  {RED('[!] MZ header — injected PE in unregistered private memory')}")
                    dims['injected_pe'] = (
                        f"MZ header at 0x{region.BaseAddress:x} in unregistered private memory"
                    )
                elif header[:2] == b'MZ':
                    print(f"  {DIM('[·] MZ header (known module — expected)')}")
            except Exception:
                pass
        print()

    # ── 3. Other threads in same region ──────────────────────────────
    if region is not None:
        sharing = [ti for ti in infos
                   if region.BaseAddress <= (ti.StartAddress or 0)
                   < region.BaseAddress + region.RegionSize]
        if sharing:
            print(BOLD("[ 3 ] THREADS EXECUTING IN THIS REGION"))
            print("─" * 50)
            for ti in sharing:
                mod    = addr_to_module(ti.StartAddress or 0, modules)
                backed = DIM(os.path.basename(mod.name)) if mod else RED("NOT IN ANY MODULE ⚠")
                tag    = DIM(" ← report TID") if ti.ThreadId == tid_int else ""
                print(f"  TID=0x{ti.ThreadId:<8x}  "
                      f"StartAddr=0x{ti.StartAddress or 0:x}  {backed}{tag}")
                # Merge into unbacked_thread dimension — same phenomenon
                if not mod and 'unbacked_thread' not in dims:
                    dims['unbacked_thread'] = (
                        f"TID 0x{ti.ThreadId:x} in region 0x{region.BaseAddress:x} "
                        f"has no module backing"
                    )
            print()

    # ── 4. Strings + context-aware IOC display ────────────────────────
    if region is not None:
        print(BOLD("[ 4 ] STRINGS IN REGION"))
        print("─" * 50)
        print(DIM(f"  Scanning {region.RegionSize // 1024} KB  "
                  f"(ASCII + UTF-16LE, min_len={min_len})"))
        print()
        try:
            data    = read_region(mf, region.BaseAddress, region.RegionSize)
            strings = _extract_strings_from_data(data, min_len=min_len)

            ioc_hits = [(off, enc, s) for off, enc, s in strings
                        if IOC_PATTERNS.search(s)]
            net_offs = {off for off, enc, s in ioc_hits if NET_PATTERNS.search(s)}
            notable  = [(off, enc, s) for off, enc, s in strings
                        if not IOC_PATTERNS.search(s) and len(s) > 20][:20]

            if ioc_hits:
                print(f"  {RED(f'[!] {len(ioc_hits)} IOC match(es):')}")
                for off, enc, s in ioc_hits:
                    abs_addr   = region.BaseAddress + off
                    fo_abs     = va_to_file_offset(mf, abs_addr)
                    fo_abs_str = f"0x{fo_abs:x}" if fo_abs is not None else "(not captured)"
                    print(RED(f"    {CYAN(f'[{enc}]'):<14} {s}"))
                    print(RED(f"      VA  = region base 0x{region.BaseAddress:016x}  +  offset 0x{off:x}  =  0x{abs_addr:016x}"))
                    print(RED(f"      DMP = file offset {fo_abs_str}"))
                    if off in net_offs:
                        print(YELLOW("    ↳ Network pattern — ±128 byte context:"))
                        print(_hexdump_context(data, off, region.BaseAddress))
                        print()
                dims['ioc_strings'] = (
                    f"{len(ioc_hits)} IOC pattern(s) matched "
                    f"({len(net_offs)} network-protocol hit(s))"
                )
            else:
                print(f"  {DIM('[·] No IOC patterns matched.')}")

            if notable:
                print(f"\n  {BOLD('Other notable strings (len > 20, top 20):')}")
                for off, enc, s in notable:
                    abs_addr   = region.BaseAddress + off
                    fo_abs     = va_to_file_offset(mf, abs_addr)
                    fo_abs_str = f"0x{fo_abs:x}" if fo_abs is not None else "?"
                    print(f"    {CYAN(f'[{enc}]'):<14} {s}")
                    print(DIM(f"      VA  = 0x{region.BaseAddress:016x} + 0x{off:x} = 0x{abs_addr:016x}  DMP = {fo_abs_str}"))

            n_ascii = sum(1 for _, e, _ in strings if e == 'ASCII')
            n_utf16 = sum(1 for _, e, _ in strings if e == 'UTF16')
            print(DIM(f"\n  Total: {len(strings)} strings  "
                      f"(ASCII: {n_ascii}  UTF-16LE: {n_utf16})"))
        except Exception as e:
            print(RED(f"  [!] Could not read region: {e}"))
        print()

    # ── Verdict (MECE) ────────────────────────────────────────────────
    print(BOLD("[ VERDICT ]"))
    print("─" * 50)
    print(f"  {_verdict(dims)}\n")
    if dims:
        for key, detail in dims.items():
            label = INDICATOR_DIMS.get(key, key)
            print(f"  {BOLD('►')} {YELLOW(label)}")
            print(f"    {DIM(detail)}")

    # ── Optional extract ──────────────────────────────────────────────
    if extract_to and region is not None:
        print()
        try:
            data = read_region(mf, region.BaseAddress, region.RegionSize)
            Path(extract_to).write_bytes(data)
            print(GREEN(f"[+] Region extracted → {extract_to}  ({len(data)} bytes)"))
        except Exception as e:
            print(RED(f"[!] Extract failed: {e}"))
    print()


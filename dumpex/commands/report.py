"""--report command."""
import os
import re
from pathlib import Path
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, addr_to_module, va_to_file_offset, prot_str,
    read_region, parse_hex_or_int, INDICATOR_DIMS, MAX_REGION_READ,
    _get_region_at, _extract_strings_from_data,
    _hexdump_context, _search_string_in_memory, verdict_for,
    VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_LIKELY_MALICIOUS)
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.pe_utils import _duration_100ns_to_str
from dumpex.core.safe_io import write_output_bytes
from dumpex.output.records import (
    ReportThreadInfo, ReportRegionInfo, TriageCardRecord, StringRecord, Diagnostic,
    SEVERITY_WARNING, hex_address,
    TRIAGE_ANCHOR_TID, TRIAGE_ANCHOR_ADDRESS, TRIAGE_ANCHOR_STRING_HIT,
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
)
from dumpex.output.coverage import (
    LimitationCode, build_coverage_report, combine_coverage_reports,
    SourceRequirement, observe_source,
)
from dumpex.output.command_result import CommandResult
from dumpex.commands.extract import build_extract_artifact

# _get_region_at, _extract_strings_from_data, _hexdump_context,
# _search_string_in_memory, and verdict_for all come from the core.memory
# import above. They used to be duplicated here (a leftover that shadowed
# the imports -- meaning fixes made to the shared core.memory versions,
# like _search_string_in_memory's MAX_REGION_READ cap, silently never
# applied to --report-string). Do not redefine them locally again.

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


def _module_context_for(mod, modules_available: bool) -> str:
    if mod:
        return MODULE_CONTEXT_RESOLVED
    return MODULE_CONTEXT_UNREGISTERED if modules_available else MODULE_CONTEXT_UNAVAILABLE


def _collect_triage_card(mf, *, tid=None, addr=None, anchor_source: str, min_len: int,
                          extract_to: "str | None", force: bool, suspicious_prots,
                          modules: list, regions: list, infos: list, tid_map: dict,
                          modules_available: bool, string_hit_tuple=None):
    """Sections 1-4 + verdict + optional extract from today's single-shot
    cmd_report, unchanged in logic (including the exact MECE
    reconciliation rule for tid_unbacked_detail) -- just building a
    TriageCardRecord instead of printing directly. Returns (record,
    CoverageReport, list[Diagnostic], Artifact | None). `string_hit_tuple`
    is (offset, encoding) when anchor_source == TRIAGE_ANCHOR_STRING_HIT
    (addr is already that hit region's own base address in that case) --
    carried through only so the record can reproduce the exact matched
    location the string search itself found (see TriageCardRecord.
    string_hit's own docstring for why this isn't re-derived from
    notable_strings)."""
    tid_int  = tid
    addr_int = addr

    dims: dict = {}
    target_addr = addr_int
    region = None
    diagnostics = []
    artifact = None
    artifact_id = None

    thread_record = None
    other_threads = []
    notable_strings = []
    ioc_strings = []
    string_scan = None
    string_scan_error = None
    region_record = None
    thread_region_correlation_excluded = False
    extract_read_clamped = None

    string_hit_dict = None
    if string_hit_tuple is not None:
        off, enc = string_hit_tuple
        string_hit_dict = {"offset": off, "address": hex_address(addr_int + off), "encoding": enc}

    # ── 1. Thread analysis ────────────────────────────────────────────
    # tid_unbacked_detail is held back rather than written straight into
    # dims: if the caller also gave an independent target address, this
    # thread's own StartAddress has no established relationship to that
    # address until section 2 resolves a region and we can check whether
    # this thread actually executes inside it. Merging it unconditionally
    # would combine two unrelated facts (an unrelated unbacked thread +
    # an unrelated flagged region) into one MECE verdict.
    tid_unbacked_detail = None
    tid_start_addr      = None
    addr_was_independent = addr_int is not None
    if tid_int is not None:
        thread_info = tid_map.get(tid_int)
        if not thread_info:
            diagnostics.append(Diagnostic(SEVERITY_WARNING,
                f"TID 0x{tid_int:x} not found in dump.", code="REPORT_TID_NOT_FOUND"))
        else:
            sa  = thread_info.StartAddress or 0
            tid_start_addr = sa
            mod = addr_to_module(sa, modules)
            module_context = _module_context_for(mod, modules_available)
            backing_module = mod.name if mod else None
            backing_module_base = hex_address(mod.baseaddress) if mod else None
            backing_module_end  = hex_address(mod.endaddress) if mod else None
            if not mod and modules_available:
                tid_unbacked_detail = (
                    f"TID 0x{thread_info.ThreadId:x} start addr 0x{sa:x} "
                    f"has no module backing"
                )
            thread_record = ReportThreadInfo(
                tid=thread_info.ThreadId, start_address=hex_address(sa),
                backing_module=backing_module, module_context=module_context,
                kernel_time_100ns=thread_info.KernelTime, user_time_100ns=thread_info.UserTime,
                backing_module_base=backing_module_base, backing_module_end=backing_module_end)
            if target_addr is None:
                target_addr = sa

    # ── 2. Memory region ─────────────────────────────────────────────
    if target_addr is not None:
        region = _get_region_at(target_addr, regions)
        if not region:
            diagnostics.append(Diagnostic(SEVERITY_WARNING,
                f"No committed region found at 0x{target_addr:x}", code="REPORT_REGION_NOT_FOUND"))
        else:
            p          = prot_str(region.Protect)
            mtype      = prot_str(region.Type)
            rmod       = addr_to_module(region.BaseAddress, modules)
            protection_suspicious = any(s in p for s in suspicious_prots)
            is_private = "MEM_PRIVATE" in mtype
            is_rwx_private = bool(protection_suspicious and is_private)

            fo_reg = va_to_file_offset(mf, region.BaseAddress)
            has_injected_pe = False
            if is_rwx_private:
                dims['rwx_private'] = (
                    f"Region 0x{region.BaseAddress:x} is "
                    f"PAGE_EXECUTE_READWRITE + MEM_PRIVATE"
                )
            try:
                header = read_region(mf, region.BaseAddress, min(64, region.RegionSize))
                if header[:2] == b'MZ' and not rmod:
                    has_injected_pe = True
                    dims['injected_pe'] = (
                        f"MZ header at 0x{region.BaseAddress:x} in unregistered private memory"
                    )
            except Exception:
                pass

            region_record = ReportRegionInfo(
                base_address=hex_address(region.BaseAddress), size=region.RegionSize,
                protect=p, type=mtype, module_owner=(rmod.name if rmod else None),
                file_offset=fo_reg, is_rwx_private=is_rwx_private,
                has_injected_pe=has_injected_pe, protection_suspicious=protection_suspicious)

    # ── Reconcile TID evidence against the resolved region ─────────────
    # Only fold the TID's own "unbacked thread" fact into the combined
    # verdict when it is actually about the same location as the region
    # analyzed above -- either the region address itself came from this
    # TID's StartAddress (no independent target address was given), or
    # the TID's StartAddress happens to fall inside the independently-
    # resolved region. Otherwise it is two unrelated facts about two
    # unrelated locations and must not be combined into one confidence
    # score.
    if tid_unbacked_detail is not None:
        tid_correlated = (not addr_was_independent) or (
            region is not None and tid_start_addr is not None and
            region.BaseAddress <= tid_start_addr < region.BaseAddress + region.RegionSize
        )
        if tid_correlated:
            dims['unbacked_thread'] = tid_unbacked_detail
        else:
            thread_region_correlation_excluded = True
            diagnostics.append(Diagnostic(SEVERITY_WARNING,
                f"TID's unbacked-thread status is NOT correlated with the region at "
                f"0x{target_addr:x} (different, unrelated location) — excluded from the "
                f"combined verdict.", code="REPORT_THREAD_NOT_CORRELATED_WITH_REGION"))

    # ── 3. Other threads in same region ──────────────────────────────
    if region is not None:
        for ti in infos:
            sa2 = ti.StartAddress or 0
            if not (region.BaseAddress <= sa2 < region.BaseAddress + region.RegionSize):
                continue
            mod = addr_to_module(sa2, modules)
            module_context = _module_context_for(mod, modules_available)
            other_threads.append(ReportThreadInfo(
                tid=ti.ThreadId, start_address=hex_address(sa2),
                backing_module=(mod.name if mod else None), module_context=module_context,
                kernel_time_100ns=ti.KernelTime, user_time_100ns=ti.UserTime))
            if not mod and 'unbacked_thread' not in dims:
                dims['unbacked_thread'] = (
                    f"TID 0x{ti.ThreadId:x} in region 0x{region.BaseAddress:x} "
                    f"has no module backing"
                )

    # ── 4. Strings + context-aware IOC display ────────────────────────
    if region is not None:
        read_size = min(region.RegionSize, MAX_REGION_READ)
        try:
            data    = read_region(mf, region.BaseAddress, read_size)
            strings = _extract_strings_from_data(data, min_len=min_len)

            ioc_hits = [(off, enc, s) for off, enc, s in strings
                        if IOC_PATTERNS.search(s)]
            net_offs = {off for off, enc, s in ioc_hits if NET_PATTERNS.search(s)}
            notable  = [(off, enc, s) for off, enc, s in strings
                        if not IOC_PATTERNS.search(s) and len(s) > 20][:20]

            for off, enc, s in ioc_hits:
                abs_addr = region.BaseAddress + off
                ioc_strings.append({
                    "offset": off, "address": hex_address(abs_addr), "encoding": enc,
                    "text": s, "matched_grep": None, "is_network_pattern": off in net_offs,
                })
            if ioc_hits:
                dims['ioc_strings'] = (
                    f"{len(ioc_hits)} IOC pattern(s) matched "
                    f"({len(net_offs)} network-protocol hit(s))"
                )

            for off, enc, s in notable:
                abs_addr = region.BaseAddress + off
                notable_strings.append(StringRecord(
                    offset=off, address=hex_address(abs_addr), encoding=enc, text=s,
                    matched_grep=None))

            n_ascii = sum(1 for _, e, _ in strings if e == 'ASCII')
            n_utf16 = sum(1 for _, e, _ in strings if e == 'UTF16')
            string_scan = {
                "scanned_bytes": read_size, "clamped": read_size < region.RegionSize,
                "total": len(strings), "ascii_count": n_ascii, "utf16_count": n_utf16,
            }
        except Exception as e:
            string_scan_error = str(e)

    # ── Verdict (MECE) ────────────────────────────────────────────────
    verdict = verdict_for(dims)
    findings = list(dims.keys())
    finding_details = dict(dims)

    # ── Optional extract ──────────────────────────────────────────────
    if extract_to and region is not None:
        read_size = min(region.RegionSize, MAX_REGION_READ)
        extract_read_clamped = read_size < region.RegionSize
        try:
            data = read_region(mf, region.BaseAddress, read_size)
            artifact = build_extract_artifact(
                f"report_extract_0x{region.BaseAddress:x}", "report_extracted_region",
                extract_to, data,
                description=f"Bytes extracted from triage card at 0x{region.BaseAddress:x}")
            write_output_bytes(extract_to, data, mf.filename, force, "--output file")
            artifact_id = artifact.id
        except Exception as e:
            diagnostics.append(Diagnostic(SEVERITY_WARNING, f"Extract failed: {e}",
                                            code="REPORT_EXTRACT_FAILED"))
            artifact = None

    record = TriageCardRecord(
        anchor_tid=tid_int,
        anchor_address=hex_address(target_addr) if target_addr is not None else None,
        anchor_source=anchor_source, thread=thread_record, region=region_record,
        string_hit=string_hit_dict, other_threads_in_region=other_threads,
        notable_strings=notable_strings, ioc_strings=ioc_strings,
        string_scan=string_scan, string_scan_error=string_scan_error,
        thread_region_correlation_excluded=thread_region_correlation_excluded,
        findings=findings, finding_details=finding_details, verdict=verdict,
        artifact_id=artifact_id, extract_read_clamped=extract_read_clamped)

    sources = {
        "thread_info": observe_source("thread_info", present=bool(mf.thread_info), items=infos),
        "modules":     observe_source("modules", present=modules_available, items=modules),
        "memory_info": observe_source("memory_info", present=bool(mf.memory_info), items=regions),
    }
    coverage = build_coverage_report(
        sources,
        evaluation_sources=("thread_info", "modules", "memory_info"),
        completeness_checks=[
            SourceRequirement("modules", absent_code=LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE),
            "thread_info", "memory_info",
        ],
    )
    return record, coverage, diagnostics, artifact


def collect_report(mf, report_tid: "str | None" = None, report_addr: "str | None" = None,
                    report_string: "str | None" = None, extract_to: "str | None" = None,
                    min_len: int = 6, force: bool = False) -> CommandResult:
    """Outer orchestrator: string mode loops over each private string hit
    calling _collect_triage_card() once per hit in a flat loop (never
    recursion, unlike today's cmd_report) -- tid=None is always passed
    into those calls (report_tid has no established relationship to any
    specific hit region, see the diagnostic emitted below when it was
    also given). tid/addr mode calls it exactly once. Results are
    combined via combine_coverage_reports(), already used in production
    by comparison.py for the identical "N independently-built
    CoverageReports over the same mf -> one combined report" shape."""
    suspicious_prots = get_rules()["suspicious_protections"]

    modules_available = bool(mf.modules)
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    infos   = get_thread_infos(mf)
    tid_map = {ti.ThreadId: ti for ti in infos}

    def fallback_coverage():
        sources = {
            "thread_info": observe_source("thread_info", present=bool(mf.thread_info), items=infos),
            "modules":     observe_source("modules", present=modules_available, items=modules),
            "memory_info": observe_source("memory_info", present=bool(mf.memory_info), items=regions),
        }
        return build_coverage_report(
            sources, evaluation_sources=("thread_info", "modules", "memory_info"),
            completeness_checks=[
                SourceRequirement("modules", absent_code=LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE),
                "thread_info", "memory_info",
            ])

    # ── String search mode: find regions, then triage each one ───────
    if report_string and not report_addr:
        hits, skipped = _search_string_in_memory(mf, report_string)
        if not hits:
            diagnostics = [Diagnostic(SEVERITY_WARNING,
                "String not found in any committed memory region.",
                code="REPORT_STRING_NOT_FOUND")]
            if skipped:
                diagnostics.append(Diagnostic(SEVERITY_WARNING,
                    f"{skipped} region(s) could not be read during the string scan and were "
                    f"skipped.", code="REPORT_STRING_SCAN_REGIONS_SKIPPED"))
            return CommandResult(kind="report", records=[], coverage=fallback_coverage(),
                summary={"mode": "string", "card_count": 0, "query_string": report_string,
                         "query_tid": report_tid, "query_addr": None, "total_hits": 0,
                         "hits_private": 0, "hits_image": 0, "image_hit_modules": [],
                         "skipped_unreadable_regions": skipped},
                diagnostics=diagnostics)

        private_hits = []
        image_hits   = []
        for r, off, enc in hits:
            mtype = prot_str(r.Type)
            mod   = addr_to_module(r.BaseAddress, modules)
            if "MEM_IMAGE" in mtype and mod:
                image_hits.append((r, off, enc, mod))
            else:
                private_hits.append((r, off, enc))

        diagnostics = []
        if skipped:
            diagnostics.append(Diagnostic(SEVERITY_WARNING,
                f"{skipped} region(s) could not be read during the string scan and were "
                f"skipped.", code="REPORT_STRING_SCAN_REGIONS_SKIPPED"))
        if report_tid:
            diagnostics.append(Diagnostic(SEVERITY_WARNING,
                "--report-tid was also given, but a TID has no established relationship to "
                "any specific string hit region -- it is not carried into the per-region "
                "triage.", code="REPORT_TID_NOT_CORRELATED_WITH_STRING_HITS"))

        image_hit_modules = sorted({os.path.basename(m.name) for _, _, _, m in image_hits})
        summary = {
            "mode": "string", "query_string": report_string, "query_tid": report_tid,
            "query_addr": None, "total_hits": len(hits), "hits_private": len(private_hits),
            "hits_image": len(image_hits), "image_hit_modules": image_hit_modules,
            "skipped_unreadable_regions": skipped,
        }

        if not private_hits:
            diagnostics.append(Diagnostic(SEVERITY_WARNING,
                "All hits are in known system modules -- no actionable regions to triage.",
                code="REPORT_STRING_HITS_ALL_IMAGE"))
            summary["card_count"] = 0
            return CommandResult(kind="report", records=[], coverage=fallback_coverage(),
                                  summary=summary, diagnostics=diagnostics)

        records = []
        coverages = []
        artifacts = []
        for i, (r, off, enc) in enumerate(private_hits, 1):
            # Multiple hit regions must not all extract to the same
            # literal path -- disambiguate per region, same as today.
            this_extract_to = extract_to
            if extract_to and len(private_hits) > 1:
                ep = Path(extract_to)
                this_extract_to = str(ep.with_name(f"{ep.stem}_0x{r.BaseAddress:x}{ep.suffix}"))
            record, coverage, card_diagnostics, artifact = _collect_triage_card(
                mf, tid=None, addr=r.BaseAddress, anchor_source=TRIAGE_ANCHOR_STRING_HIT,
                min_len=min_len, extract_to=this_extract_to, force=force,
                suspicious_prots=suspicious_prots, modules=modules, regions=regions,
                infos=infos, tid_map=tid_map, modules_available=modules_available,
                string_hit_tuple=(off, enc))
            records.append(record)
            coverages.append(coverage)
            diagnostics.extend(card_diagnostics)
            if artifact is not None:
                artifacts.append(artifact)

        summary["card_count"] = len(records)
        return CommandResult(kind="report", records=records,
                              coverage=combine_coverage_reports(coverages),
                              summary=summary, diagnostics=diagnostics, artifacts=artifacts)

    # ── TID/address mode: exactly one card ────────────────────────────
    tid_int  = parse_hex_or_int(report_tid)  if report_tid  else None
    addr_int = parse_hex_or_int(report_addr) if report_addr else None
    anchor_source = TRIAGE_ANCHOR_ADDRESS if addr_int is not None else TRIAGE_ANCHOR_TID

    record, coverage, diagnostics, artifact = _collect_triage_card(
        mf, tid=tid_int, addr=addr_int, anchor_source=anchor_source, min_len=min_len,
        extract_to=extract_to, force=force, suspicious_prots=suspicious_prots,
        modules=modules, regions=regions, infos=infos, tid_map=tid_map,
        modules_available=modules_available)

    mode_parts = []
    if tid_int is not None:
        mode_parts.append("tid")
    if addr_int is not None:
        mode_parts.append("addr")
    summary = {
        "mode": "_".join(mode_parts), "card_count": 1, "query_string": None,
        "query_tid": report_tid, "query_addr": report_addr, "total_hits": None,
        "hits_private": None, "hits_image": None, "image_hit_modules": [],
        "skipped_unreadable_regions": 0,
    }
    return CommandResult(kind="report", records=[record], coverage=coverage,
                          summary=summary, diagnostics=diagnostics,
                          artifacts=([artifact] if artifact is not None else []))


def _print_card_banner(mf, card, query_tid, query_addr) -> None:
    print(f"\n{BOLD('══════════════════════════════════════════')}")
    print(f"{BOLD('  dumpex TRIAGE REPORT')}")
    print(f"{BOLD('══════════════════════════════════════════')}")
    print(f"  File : {os.path.basename(mf.filename)}")
    if card.anchor_tid is not None and query_tid is not None:
        print(f"  TID  : {query_tid}")
    if card.anchor_source == TRIAGE_ANCHOR_ADDRESS and query_addr is not None:
        print(f"  Addr : {query_addr}")
    elif card.anchor_source == TRIAGE_ANCHOR_STRING_HIT and card.anchor_address is not None:
        print(f"  Addr : 0x{int(card.anchor_address, 16):x}")
    print()


def _render_card(mf, card, min_len: int) -> None:
    # ── 1. Thread analysis ────────────────────────────────────────────
    if card.anchor_tid is not None:
        print(BOLD("[ 1 ] THREAD ANALYSIS"))
        print("─" * 50)
        if card.thread is None:
            print(RED(f"  [!] TID 0x{card.anchor_tid:x} not found in dump."))
            print(DIM("      Thread may have exited before dump was taken."))
        else:
            t = card.thread
            sa = int(t.start_address, 16)
            print(f"  {'TID':<22} 0x{t.tid:x}")
            print(f"  {'Start Address':<22} 0x{sa:x}")
            print(f"  {'Kernel Time':<22} {_duration_100ns_to_str(t.kernel_time_100ns)}")
            print(f"  {'User Time':<22} {_duration_100ns_to_str(t.user_time_100ns)}")
            if t.module_context == MODULE_CONTEXT_RESOLVED:
                print(f"  {'Backed By':<22} {GREEN(t.backing_module)}")
                print(f"  {'Module Range':<22} 0x{int(t.backing_module_base, 16):x} — "
                      f"0x{int(t.backing_module_end, 16):x}")
            else:
                print(f"  {'Backed By':<22} {RED('NOT IN ANY MODULE ⚠')}")
        print()

    # ── 2. Memory region ──────────────────────────────────────────────
    if card.anchor_address is not None:
        print(BOLD("[ 2 ] MEMORY REGION AT TARGET ADDRESS"))
        print("─" * 50)
        target_addr = int(card.anchor_address, 16)
        if card.region is None:
            print(RED(f"  [!] No committed region found at 0x{target_addr:x}"))
            print(DIM("      Address may not be in a page captured by this dump."))
        else:
            r = card.region
            base = int(r.base_address, 16)
            fo_reg_str = f"0x{r.file_offset:x}" if r.file_offset is not None else "(not captured in dump)"
            print(f"  {'Region base (VA)':<24} 0x{base:016x}  {DIM('← process virtual address')}")
            print(f"  {'Region base (file offset)':<24} {fo_reg_str}  {DIM('← byte offset inside .dmp')}")
            print(f"  {'Physical addr (RAM)':<24} {DIM('not recorded in minidumps')}")
            print(f"  {'IOC addr = base + offset':<24} {DIM('see formula per string below')}")
            print(f"  {'Region Size':<24} 0x{r.size:x}  ({r.size // 1024} KB)")
            print(f"  {'Protection':<22} {RED(r.protect) if r.protection_suspicious else r.protect}")
            print(f"  {'Type':<22} {r.type}")
            print(f"  {'Module Owner':<22} "
                  f"{DIM(r.module_owner) if r.module_owner else RED('none — unregistered private memory')}")

            if r.is_rwx_private:
                print(f"\n  {RED('[!] RWX + MEM_PRIVATE — classic shellcode/injection marker')}")
            elif r.protection_suspicious:
                print(f"\n  {YELLOW('[~] PAGE_EXECUTE_READWRITE (module-backed — notable but less suspicious)')}")
            if r.has_injected_pe:
                print(f"  {RED('[!] MZ header — injected PE in unregistered private memory')}")
        print()

        if card.thread_region_correlation_excluded:
            print(YELLOW(
                f"  [~] TID's unbacked-thread status is NOT correlated with the region at "
                f"0x{target_addr:x} (different, unrelated location) — excluded from the "
                f"combined verdict below.\n"))

    # ── 3. Other threads in same region ──────────────────────────────
    if card.region is not None and card.other_threads_in_region:
        print(BOLD("[ 3 ] THREADS EXECUTING IN THIS REGION"))
        print("─" * 50)
        for t in card.other_threads_in_region:
            sa2 = int(t.start_address, 16)
            backed = (DIM(os.path.basename(t.backing_module)) if t.module_context == MODULE_CONTEXT_RESOLVED
                      else RED("NOT IN ANY MODULE ⚠"))
            tag = DIM(" ← report TID") if t.tid == card.anchor_tid else ""
            print(f"  TID=0x{t.tid:<8x}  StartAddr=0x{sa2:x}  {backed}{tag}")
        print()

    # ── 4. Strings + context-aware IOC display ────────────────────────
    if card.region is not None:
        print(BOLD("[ 4 ] STRINGS IN REGION"))
        print("─" * 50)
        if card.string_scan is not None:
            ss = card.string_scan
            print(DIM(f"  Scanning {ss['scanned_bytes'] // 1024} KB  "
                      f"(ASCII + UTF-16LE, min_len={min_len})"))
            if ss["clamped"]:
                print(YELLOW(f"  [~] Region is {card.region.size // 1024} KB — "
                             f"clamped to {MAX_REGION_READ // (1024*1024)} MB for this scan"))
            print()
            if card.ioc_strings:
                print(f"  {RED(f'[!] {len(card.ioc_strings)} IOC match(es):')}")
                base = int(card.region.base_address, 16)
                # Re-reads the exact bytes Section 4 already scanned
                # (ss['scanned_bytes'], the same read_size collect used)
                # purely to reproduce _hexdump_context()'s byte-level
                # display for network-pattern hits -- that raw content is
                # deliberately never persisted onto the record (it would
                # bloat JSON with megabytes of memory content), so this is
                # the one place render legitimately touches `mf` for more
                # than the dump's filename.
                context_data = None
                if any(s["is_network_pattern"] for s in card.ioc_strings):
                    try:
                        context_data = read_region(mf, base, ss["scanned_bytes"])
                    except Exception:
                        context_data = None
                for s in card.ioc_strings:
                    enc, off, text = s["encoding"], s["offset"], s["text"]
                    abs_addr = int(s["address"], 16)
                    fo_abs = None if card.region.file_offset is None else card.region.file_offset + off
                    fo_abs_str = f"0x{fo_abs:x}" if fo_abs is not None else "(not captured)"
                    enc_col = f"[{enc}]"
                    print(RED(f"    {CYAN(enc_col):<14} {text}"))
                    print(RED(f"      VA  = region base 0x{base:016x}  +  offset 0x{off:x}  =  "
                              f"0x{abs_addr:016x}"))
                    print(RED(f"      DMP = file offset {fo_abs_str}"))
                    if s["is_network_pattern"] and context_data is not None:
                        print(YELLOW("    ↳ Network pattern — ±128 byte context:"))
                        print(_hexdump_context(context_data, off, base))
                        print()
            else:
                print(f"  {DIM('[·] No IOC patterns matched.')}")

            if card.notable_strings:
                print(f"\n  {BOLD('Other notable strings (len > 20, top 20):')}")
                base = int(card.region.base_address, 16)
                for s in card.notable_strings:
                    abs_addr = int(s.address, 16)
                    off = abs_addr - base
                    fo_abs = None if card.region.file_offset is None else card.region.file_offset + off
                    fo_abs_str = f"0x{fo_abs:x}" if fo_abs is not None else "?"
                    enc_col = f"[{s.encoding}]"
                    print(f"    {CYAN(enc_col):<14} {s.text}")
                    print(DIM(f"      VA  = 0x{base:016x} + 0x{off:x} = 0x{abs_addr:016x}  DMP = {fo_abs_str}"))

            print(DIM(f"\n  Total: {ss['total']} strings  "
                      f"(ASCII: {ss['ascii_count']}  UTF-16LE: {ss['utf16_count']})"))
        elif card.string_scan_error is not None:
            print(RED(f"  [!] Could not read region: {card.string_scan_error}"))
        print()

    # ── Verdict (MECE) ────────────────────────────────────────────────
    print(BOLD("[ VERDICT ]"))
    print("─" * 50)
    print(f"  {_render_verdict_text(card.verdict, len(card.findings))}\n")
    if card.findings:
        for key in card.findings:
            label = INDICATOR_DIMS.get(key, key)
            print(f"  {BOLD('►')} {YELLOW(label)}")
            print(f"    {DIM(card.finding_details[key])}")


def _render_verdict_text(verdict: str, score: int) -> str:
    """`score` (len(card.findings)) reproduces today's `_verdict(dims)`
    text exactly -- `verdict` alone only carries the four-tier
    VERDICT_* classification, not the literal count HIGH_CONFIDENCE_
    MALICIOUS's own sentence interpolates (findings can be 3 or 4, since
    INDICATOR_DIMS has exactly four possible keys)."""
    if verdict == VERDICT_CLEAN:
        return GREEN("CLEAN — no suspicious indicators found")
    if verdict == VERDICT_SUSPICIOUS:
        return YELLOW("SUSPICIOUS — 1 independent indicator")
    if verdict == VERDICT_LIKELY_MALICIOUS:
        return YELLOW("LIKELY MALICIOUS — 2 independent indicators")
    return RED(f"HIGH CONFIDENCE MALICIOUS — {score} independent indicators")


def render_report_console(records, coverage, diagnostics, artifacts, summary, mf, min_len: int) -> None:
    """Reproduces today's exact, pre-migration console text -- see
    dumpex.commands.report's own git history / the Phase E plan's capture
    script for the byte-for-byte ground truth this was built against.
    Takes `mf` (unlike every other render_*_console in this package) only
    to read `mf.filename` for the per-card banner's "File : ..." line --
    no coverage/business-logic decision here depends on the dump itself,
    only that one already-known display string."""
    for reason in coverage.reasons:
        print(YELLOW(f"  [~] {reason}"))

    if summary["mode"] == "string":
        print(f"\n{BOLD('Searching memory for:')} {CYAN(repr(summary['query_string']))}")
        print("─" * 55)
        if summary["card_count"] == 0 and summary["total_hits"] == 0:
            print(RED(f"  [!] String not found in any committed memory region."))
            print(DIM("      Try --strings with a broader address range to verify."))
            return

        print(GREEN(f"  [+] Found in {summary['total_hits']} region(s):"))
        for card in records:
            r = card.region
            base = int(r.base_address, 16)
            off = card.string_hit["offset"]
            enc = card.string_hit["encoding"]
            abs_addr = int(card.string_hit["address"], 16)
            fo_str = (f"0x{r.file_offset + off:x}" if r.file_offset is not None else "(not captured)")
            rwx_tag = RED(" ◄ RWX") if r.protection_suspicious else ""
            print(f"    {RED('►')} [{enc}]  {r.protect}  {r.type}{rwx_tag}")
            print(f"      VA  = region base 0x{base:016x}  +  offset 0x{off:x}  =  0x{abs_addr:016x}")
            print(f"      DMP = file offset {fo_str}")
        if summary["hits_image"]:
            mods = ", ".join(summary["image_hit_modules"])
            print(DIM(f"    [·] {summary['hits_image']} hit(s) in known MEM_IMAGE modules "
                      f"({mods}) — skipped (expected content)"))
        print()

        if summary["card_count"] == 0:
            print(DIM("  [·] All hits are in known system modules — no actionable regions to triage."))
            return

        if summary["query_tid"]:
            print(DIM(f"  [·] --report-tid 0x{summary['query_tid']} was also given, but a TID has no "
                      f"established relationship to any specific string hit region — "
                      f"it is not carried into the per-region triage below.\n"))

        for i, card in enumerate(records, 1):
            if len(records) > 1:
                print(BOLD(f"{'═'*55}"))
                print(BOLD(f"  Triaging hit {i}/{len(records)} — region 0x{int(card.region.base_address, 16):x}"))
                print(BOLD(f"{'═'*55}"))
            _print_card_banner(mf, card, None, None)
            _render_card(mf, card, min_len)
            _print_extract_result(records, artifacts, card)
            print()   # unconditional trailing blank line -- matches today's
                       # cmd_report, which ends every single-shot invocation
                       # (each recursive sub-call, pre-flatten) with a bare
                       # print() after the extract block, extract or not
        return

    # tid/addr mode -- exactly one card
    card = records[0]
    _print_card_banner(mf, card, summary["query_tid"], summary["query_addr"])
    _render_card(mf, card, min_len)
    _print_extract_result(records, artifacts, card)
    print()


def _print_extract_result(records, artifacts, card) -> None:
    if card.artifact_id is None:
        return
    artifact = next(a for a in artifacts if a.id == card.artifact_id)
    print()
    if card.extract_read_clamped:
        print(YELLOW(f"  [~] Region is {card.region.size // 1024} KB — "
                     f"clamped to {MAX_REGION_READ // (1024*1024)} MB "
                     f"(use --extract with an explicit --size for more)"))
    summary_text = f"{artifact.size_bytes} bytes  sha256={artifact.sha256}"
    print(GREEN(f"[+] Region extracted → {artifact.path}  ({summary_text})"))


def cmd_report(mf: MinidumpFile, report_tid: str = None, report_addr: str = None,
               report_string: str = None, extract_to: str = None, min_len: int = 6,
               force: bool = False) -> CommandResult:
    """\n    Alert triage card: given a TID, address, or string from an EDR alert / TI feed,\n    correlate thread, memory, and string evidence into a structured verdict.\n    Verdict uses MECE dimensions — each dimension scored at most once.\n\n    --report-string: search all memory for the string, then run triage on each\n                    matching region. Useful when the anchor is a C2 IP, domain,\n                    or known malware string from threat intelligence.\n    """
    result = collect_report(mf, report_tid=report_tid, report_addr=report_addr,
                             report_string=report_string, extract_to=extract_to,
                             min_len=min_len, force=force)
    render_report_console(result.records, result.coverage, result.diagnostics,
                           result.artifacts, result.summary, mf, min_len)
    return result

"""--report command."""
import ntpath
import os
import re
from pathlib import Path
from typing import NamedTuple
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN, console_safe
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, get_thread_contexts, addr_to_module, va_to_file_offset, prot_str,
    read_region, parse_hex_or_int, INDICATOR_DIMS, MAX_REGION_READ,
    _get_region_at, _extract_strings_from_data,
    _hexdump_context, _search_string_in_memory, StringSearchStats, verdict_for,
    VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_LIKELY_MALICIOUS)
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.pe_utils import _duration_100ns_to_str
from dumpex.core.safe_io import write_output_bytes
from dumpex.output.records import (
    ReportThreadInfo, ReportRegionInfo, ReportIocString, TriageCardRecord, StringRecord, Diagnostic,
    SEVERITY_WARNING, hex_address,
    TRIAGE_ANCHOR_TID, TRIAGE_ANCHOR_ADDRESS, TRIAGE_ANCHOR_STRING_HIT,
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
)
from dumpex.output.coverage import (
    LimitationCode, build_coverage_report, combine_coverage_reports,
    SourceRequirement, SourceObservation, SourceState, CoverageLimitation, observe_source,
    EXECUTION_COMPLETED, EXECUTION_PARTIAL,
)
from dumpex.output.command_result import CommandResult
from dumpex.commands.extract import build_extract_artifact
from dumpex.commands.report_enrichment import (
    CONSOLE_BRANCH_TARGETS, CONSOLE_CORRELATED_HANDLES, CONSOLE_HANDLE_TYPE_ROWS,
    CONSOLE_IAT_ROWS, CONSOLE_INSTRUCTION_ROWS, CONSOLE_NEIGHBOR_REGIONS,
    CONSOLE_PE_CONFLICTS, CONSOLE_STRING_CONTEXT, collect_allocation_neighborhood,
    collect_anchor_pe_context, collect_exception_context, collect_handle_correlation,
    collect_instruction_context, collect_iat_correlation, collect_pe_context,
    collect_process_enrichment, collect_string_context, HandleSegmentIndex,
    MAX_REPORT_CARDS, MAX_REPORT_SCAN_BYTES, PeProfileCache, RegionEvidence,
)
from dumpex.output.records import (
    ENRICHMENT_COMPLETE, ENRICHMENT_MISSING, ENRICHMENT_PARTIAL,
)

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


class ContentScanResult(NamedTuple):
    """Region-independent result of a bounded content read and scan.

    The caller supplies the exact target base, which may be a memory segment with
    no MemoryInfo entry. Results keep string counts, IOC context, notable strings,
    and the MZ/injected-PE tri-state. Caller-relative clamping is intentionally
    excluded.

    A read exception is captured as string_scan_error. Exceptions in analysis of
    successfully returned bytes propagate as programming failures rather than
    being mislabeled as unreadable evidence.

    `strings` is every (offset, encoding, text) triple the one content read
    produced, and `ioc_offsets` the offsets among them that matched
    IOC_PATTERNS. Both stay in-process: they exist so an enrichment
    projection can re-select over the SAME extraction rather than read or
    scan the range a second time, and neither is serialized -- ioc_strings
    and notable_strings remain the published subsets.
    """
    mz_header_detected: "bool | None"
    has_injected_pe: "bool | None"
    ioc_strings: tuple
    notable_strings: tuple
    string_scan: "dict | None"
    string_scan_error: "str | None"
    strings: tuple = ()
    ioc_offsets: frozenset = frozenset()


def _scan_content_range(mf, *, base_address: int, requested_size: int, min_len: int,
                         module_context: str) -> ContentScanResult:
    """The read + string/IOC/MZ analysis itself -- see `ContentScanResult`'s
    own docstring for why this takes a bare `base_address`/`requested_size`
    rather than a resolved MemoryInfo region. `module_context` (one of
    MODULE_CONTEXT_RESOLVED/UNREGISTERED/UNAVAILABLE) is supplied by the
    caller from the region's module ownership before `has_injected_pe` can
    be decided, so it is not re-derived here."""
    # Scoped to ONLY the read itself -- see this function's own docstring
    # for why the analysis below must NOT be inside this try/except.
    try:
        data = read_region(mf, base_address, requested_size)
    except Exception as e:
        return ContentScanResult(
            mz_header_detected=None, has_injected_pe=None,
            ioc_strings=(), notable_strings=(),
            string_scan=None, string_scan_error=str(e))

    # Fewer than 2 bytes is not enough to rule out "MZ" -- must stay
    # unconfirmed (None), not silently read as a confirmed non-match.
    mz_header_detected = (data[:2] == b'MZ') if len(data) >= 2 else None
    strings = _extract_strings_from_data(data, min_len=min_len)

    ioc_hits = [(off, enc, s) for off, enc, s in strings
                if IOC_PATTERNS.search(s)]
    net_offs = {off for off, enc, s in ioc_hits if NET_PATTERNS.search(s)}
    notable  = [(off, enc, s) for off, enc, s in strings
                if not IOC_PATTERNS.search(s) and len(s) > 20][:20]

    ioc_strings = []
    for off, enc, s in ioc_hits:
        abs_addr = base_address + off
        is_net = off in net_offs
        context_hex = context_base_address = context_hit_offset = None
        if is_net:
            ctx_start = max(0, off - 128)
            ctx_end   = min(len(data), off + 128)
            chunk     = data[ctx_start:ctx_end]
            context_hex = chunk.hex()
            context_base_address = hex_address(base_address + ctx_start)
            context_hit_offset = off - ctx_start
        ioc_strings.append(ReportIocString(
            offset=off, address=hex_address(abs_addr), encoding=enc, text=s,
            is_network_pattern=is_net, context_hex=context_hex,
            context_base_address=context_base_address,
            context_hit_offset=context_hit_offset))

    notable_strings = []
    for off, enc, s in notable:
        abs_addr = base_address + off
        notable_strings.append(StringRecord(
            offset=off, address=hex_address(abs_addr), encoding=enc, text=s,
            matched_grep=None))

    n_ascii = sum(1 for _, e, _ in strings if e == 'ASCII')
    n_utf16 = sum(1 for _, e, _ in strings if e == 'UTF16')
    string_scan = {
        "requested_bytes": requested_size, "bytes_read": len(data),
        "truncated": len(data) < requested_size,
        "total": len(strings), "ascii_count": n_ascii, "utf16_count": n_utf16,
    }

    has_injected_pe = None
    if mz_header_detected is False:
        has_injected_pe = False
    elif mz_header_detected is True:
        if module_context == MODULE_CONTEXT_UNREGISTERED:
            has_injected_pe = True
        elif module_context == MODULE_CONTEXT_RESOLVED:
            has_injected_pe = False
        else:   # unavailable -- found something suspicious-shaped, can't confirm
            has_injected_pe = None

    return ContentScanResult(
        mz_header_detected=mz_header_detected, has_injected_pe=has_injected_pe,
        ioc_strings=tuple(ioc_strings), notable_strings=tuple(notable_strings),
        string_scan=string_scan, string_scan_error=None,
        strings=tuple(strings), ioc_offsets=frozenset(off for off, _enc, _s in ioc_hits))


def _collect_triage_card(mf, *, tid=None, addr=None, anchor_source: str, min_len: int,
                          extract_to: "str | None", force: bool, suspicious_prots,
                          modules: list, regions: list, infos: list, tid_map: dict,
                          modules_available: bool, string_hit_tuple=None,
                          handle_records=(), handle_summary=None, query=None,
                          region_evidence=None, handle_index=None, resolved_region=None,
                          pe_cache=None):
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
    notable_strings).

    Section 4's string/IOC scan and the optional `--output` extraction are
    capped by the current module-level `MAX_REGION_READ` value.

    `handle_records`/`handle_summary` are the process-wide handle
    collection this run already performed (see collect_report), reused for
    this card's own bounded correlation rather than collected again per
    card. `query` is the --report-string needle for a string_hit card, so
    the searched text and the exact captured string stay distinguishable
    in the card's string context. Every enrichment section built below is
    captured context only: none of them touches `dims`, `findings`, the
    verdict, the coverage report, or the exit code."""
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
    extract_read_truncated = None

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
        # `resolved_region` is the region the caller already resolved this
        # anchor to. Re-resolving it here would be a second, independent
        # decision over an overlapping region table -- `_get_region_at`
        # answers with the FIRST region covering an address, which need
        # not be the one the caller measured, budgeted, and rebased the
        # hit offset against. One anchor gets one region.
        region = (resolved_region if resolved_region is not None
                  else _get_region_at(target_addr, regions))
        if not region:
            diagnostics.append(Diagnostic(SEVERITY_WARNING,
                f"No committed region found at 0x{target_addr:x}", code="REPORT_REGION_NOT_FOUND"))
        else:
            p          = prot_str(region.Protect)
            mtype      = prot_str(region.Type)
            rmod       = addr_to_module(region.BaseAddress, modules)
            region_module_context = _module_context_for(rmod, modules_available)
            protection_suspicious = any(s in p for s in suspicious_prots)
            is_private = "MEM_PRIVATE" in mtype
            is_rwx_private = bool(protection_suspicious and is_private)

            fo_reg = va_to_file_offset(mf, region.BaseAddress)
            if is_rwx_private:
                dims['rwx_private'] = (
                    f"Region 0x{region.BaseAddress:x} is "
                    f"PAGE_EXECUTE_READWRITE + MEM_PRIVATE"
                )
            # mz_header_detected/has_injected_pe/region_record itself are
            # deferred to Section 4 below, which derives them from that
            # SAME content read rather than a second, independent small
            # peek read -- a header-only read that fails on its own while
            # Section 4's larger read of the identical starting address
            # succeeds right after used to leave mz_header_detected stuck
            # at None even though the bytes needed were right there (see
            # RevFix2-P1b). One read now serves both facts, and a failure
            # of that one read means BOTH are appropriately undetermined
            # together, correctly captured by the SAME aggregate
            # "region read failed" coverage fact below (see
            # _build_aggregate_coverage_report) -- no separate limitation
            # needed for the injected-PE dimension specifically.

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
            # Same guard as Section 1's own tid_unbacked_detail: a thread
            # confirmed NOT backed by any module (modules_available AND no
            # match) is a real signal; ModuleListStream simply being
            # absent is not -- must not silently produce the same
            # unbacked_thread finding either way.
            if not mod and modules_available and 'unbacked_thread' not in dims:
                dims['unbacked_thread'] = (
                    f"TID 0x{ti.ThreadId:x} in region 0x{region.BaseAddress:x} "
                    f"has no module backing"
                )

    # ── 4. Strings + context-aware IOC display (also derives the MZ/
    #      injected-PE tri-state from this same content read -- see
    #      Section 2's own note on why there is no separate header peek) ──
    if region is not None:
        read_size = min(region.RegionSize, MAX_REGION_READ)
        scan = _scan_content_range(mf, base_address=region.BaseAddress, requested_size=read_size,
                                    min_len=min_len, module_context=region_module_context)
        mz_header_detected = scan.mz_header_detected
        has_injected_pe = scan.has_injected_pe
        ioc_strings = list(scan.ioc_strings)
        notable_strings = list(scan.notable_strings)
        string_scan_error = scan.string_scan_error
        string_scan = None
        if scan.string_scan is not None:
            # `clamped` is region-relative (this SPECIFIC region's own
            # RegionSize vs. what was actually requested) -- a fact only
            # this caller can add; _scan_content_range() itself has no
            # region to compare against (see its own docstring).
            string_scan = dict(scan.string_scan)
            string_scan["clamped"] = read_size < region.RegionSize
        if ioc_strings:
            net_count = sum(1 for s in ioc_strings if s.is_network_pattern)
            dims['ioc_strings'] = (
                f"{len(ioc_strings)} IOC pattern(s) matched "
                f"({net_count} network-protocol hit(s))"
            )
        if has_injected_pe:
            dims['injected_pe'] = (
                f"MZ header at 0x{region.BaseAddress:x} in unregistered private memory"
            )

        region_record = ReportRegionInfo(
            base_address=hex_address(region.BaseAddress), size=region.RegionSize,
            protect=p, type=mtype, module_owner=(rmod.name if rmod else None),
            file_offset=fo_reg, is_rwx_private=is_rwx_private,
            module_context=region_module_context, mz_header_detected=mz_header_detected,
            has_injected_pe=has_injected_pe, protection_suspicious=protection_suspicious)

    # ── Verdict (MECE) ────────────────────────────────────────────────
    verdict = verdict_for(dims)
    findings = list(dims.keys())
    finding_details = dict(dims)

    # ── Optional extract ──────────────────────────────────────────────
    if extract_to and region is not None:
        read_size = min(region.RegionSize, MAX_REGION_READ)
        try:
            data = read_region(mf, region.BaseAddress, read_size)
            # Both computed here, together, only on a successful read --
            # a failed read (except branch below) means neither is
            # actually known, so both stay None rather than reporting a
            # clamp/truncation verdict about bytes that were never read.
            extract_read_clamped = read_size < region.RegionSize
            extract_read_truncated = len(data) < read_size
            artifact = build_extract_artifact(
                f"report_extract_0x{region.BaseAddress:x}", "report_extracted_region",
                extract_to, data,
                description=f"Bytes extracted from triage card at 0x{region.BaseAddress:x}")
            write_output_bytes(extract_to, data, mf.filename, force, "--output file")
            artifact_id = artifact.id
            # The artifact is still written even when the read itself came
            # up short (read_region() returned real, if incomplete, bytes)
            # -- but that must never be silent: a diagnostic makes the gap
            # visible in JSON/console, and _execution_status_for below
            # folds extract_read_truncated into execution_status=partial.
            if extract_read_truncated:
                diagnostics.append(Diagnostic(SEVERITY_WARNING,
                    f"Extract came up short: wrote {len(data)} of {read_size} requested byte(s) "
                    f"-- the written artifact is incomplete.", code="REPORT_EXTRACT_TRUNCATED"))
        except Exception as e:
            diagnostics.append(Diagnostic(SEVERITY_WARNING, f"Extract failed: {e}",
                                            code="REPORT_EXTRACT_FAILED"))
            artifact = None

    # ── Card enrichment (bounded, evidence-only) ──────────────────────
    scanned_strings = scan.strings if (region is not None and string_scan is not None) else None
    exception_context = collect_exception_context(
        mf, anchor_tid=tid_int,
        region_base=(region.BaseAddress if region is not None else None),
        region_size=(region.RegionSize if region is not None else 0),
        region_evidence=region_evidence, modules=modules)
    allocation_neighborhood = collect_allocation_neighborhood(
        region_evidence, anchor_address=target_addr, modules=modules)
    content_partial = bool(string_scan and string_scan["truncated"])
    content_clamped = bool(string_scan and string_scan["clamped"])
    handle_correlation = (
        collect_handle_correlation(handle_index, scanned_strings,
                                    handle_summary=handle_summary,
                                    content_partial=content_partial,
                                    content_clamped=content_clamped)
        if handle_summary is not None and handle_index is not None else None)
    string_context = collect_string_context(
        anchor_address=target_addr,
        region_base=(region.BaseAddress if region is not None else None),
        region_size=(region.RegionSize if region is not None else 0),
        string_scan=string_scan, scanned_strings=scanned_strings,
        ioc_offsets=(scan.ioc_offsets if region is not None else frozenset()),
        query=query, string_hit=string_hit_dict)

    # ── Card enrichment: PE, instruction, and IAT correlation ─────────
    anchor_pe_context = instruction_context = iat_correlation = None
    if pe_cache is not None:
        anchor_pe_context = collect_anchor_pe_context(
            pe_cache, anchor_address=target_addr, region_evidence=region_evidence)

        # Approved anchor sources for the instruction window, highest
        # priority first, each admitted only when it is correlated with
        # THIS card: a faulting RIP only when its exception relates to the
        # anchor thread or the anchor region (never the dump's own
        # process-wide crash record), the live thread RIP and the thread
        # StartAddress only for the card's anchor thread, then the card's
        # own anchor. When the card carries an explicit user-supplied
        # address, that anchor is what the analyst pointed at and leads --
        # only a correlated fault outranks it.
        thread_ip = thread_ip_reg = wow64_hint = None
        if tid_int is not None:
            for ctx in get_thread_contexts(mf):
                if ctx.get("ThreadId") == tid_int:
                    thread_ip = ctx.get("ip")
                    thread_ip_reg = ctx.get("ip_reg")
                    wow64_hint = ctx.get("is_wow64")
                    break
        exception_rip = None
        if exception_context is not None and exception_context.entries:
            first = exception_context.entries[0]
            if (first.exception_address is not None
                    and first.selection_reason in ("anchor_thread", "anchor_region")):
                exception_rip = int(first.exception_address, 16)
        _order = (("exception_rip", exception_rip), ("card_anchor", target_addr),
                  ("thread_rip", thread_ip), ("thread_start_address", tid_start_addr)) \
            if addr_was_independent else \
            (("exception_rip", exception_rip), ("thread_rip", thread_ip),
             ("thread_start_address", tid_start_addr), ("card_anchor", target_addr))
        candidates = [(name, addr) for name, addr in _order
                      if isinstance(addr, int) and addr > 0]

        # The instruction window, its architecture, its IAT-directory
        # range, and the IAT it is correlated against all belong to the
        # module that owns the CHOSEN anchor address -- not necessarily
        # the module the card's own anchor is in.
        instruction_slot_vas = ()
        instruction_module = instruction_module_base = None
        if candidates and target_addr is not None:
            _name, instruction_anchor = candidates[0]
            instruction_module = addr_to_module(instruction_anchor, modules)
            instruction_module_base = getattr(instruction_module, "baseaddress", None)
            if not isinstance(instruction_module_base, int):
                instruction_module, instruction_module_base = None, None
            instruction_iat = (pe_cache.iat_at_base(instruction_module_base)
                               if instruction_module_base is not None else None)
            instruction_context, instruction_slot_vas = collect_instruction_context(
                pe_cache, mf=mf, anchor_candidates=candidates,
                region_evidence=region_evidence, iat_raw=instruction_iat,
                instruction_module_base=instruction_module_base,
                instruction_module_profile=(
                    pe_cache.profile_at_base(instruction_module_base)
                    if instruction_module_base is not None else None),
                thread_ip_reg=thread_ip_reg, wow64_hint=wow64_hint)

        # IAT correlation is about the same module the window is in when
        # there is one, so an instruction-correlated slot is never checked
        # against a different image's table; otherwise it falls back to
        # the card anchor's own module to still surface unusual thunks.
        iat_module = instruction_module
        iat_module_base = instruction_module_base
        if iat_module_base is None and target_addr is not None:
            iat_module = addr_to_module(target_addr, modules)
            candidate_base = getattr(iat_module, "baseaddress", None)
            iat_module_base = candidate_base if isinstance(candidate_base, int) else None
            if iat_module_base is None:
                iat_module = None
        if iat_module_base is not None:
            iat_correlation = collect_iat_correlation(
                pe_cache, anchor_module=iat_module, anchor_module_base=iat_module_base,
                iat_raw=pe_cache.iat_at_base(iat_module_base),
                region_evidence=region_evidence,
                instruction_slot_vas=instruction_slot_vas)

    record = TriageCardRecord(
        anchor_tid=tid_int,
        anchor_address=hex_address(target_addr) if target_addr is not None else None,
        anchor_source=anchor_source, thread=thread_record, region=region_record,
        string_hit=string_hit_dict, other_threads_in_region=other_threads,
        notable_strings=notable_strings, ioc_strings=ioc_strings,
        string_scan=string_scan, string_scan_error=string_scan_error,
        thread_region_correlation_excluded=thread_region_correlation_excluded,
        findings=findings, finding_details=finding_details, verdict=verdict,
        artifact_id=artifact_id, extract_read_clamped=extract_read_clamped,
        extract_read_truncated=extract_read_truncated,
        exception_context=exception_context,
        allocation_neighborhood=allocation_neighborhood,
        handle_correlation=handle_correlation, string_context=string_context,
        anchor_pe_context=anchor_pe_context, instruction_context=instruction_context,
        iat_correlation=iat_correlation)

    sources = {
        "thread_info": observe_source("thread_info", present=bool(mf.thread_info), items=infos),
        "modules":     observe_source("modules", present=modules_available, items=modules),
        "memory_info": observe_source("memory_info", present=bool(mf.memory_info), items=regions),
    }
    coverage = build_coverage_report(
        sources,
        evaluation_sources=("thread_info", "modules", "memory_info"),
        completeness_checks=[
            SourceRequirement("modules", absent_code=LimitationCode.REPORT_MODULE_CONTEXT_UNAVAILABLE),
            "thread_info", "memory_info",
        ],
    )
    return record, coverage, diagnostics, artifact


def _fallback_coverage(mf, modules_available, modules, infos, regions):
    sources = {
        "thread_info": observe_source("thread_info", present=bool(mf.thread_info), items=infos),
        "modules":     observe_source("modules", present=modules_available, items=modules),
        "memory_info": observe_source("memory_info", present=bool(mf.memory_info), items=regions),
    }
    return build_coverage_report(
        sources, evaluation_sources=("thread_info", "modules", "memory_info"),
        completeness_checks=[
            SourceRequirement("modules", absent_code=LimitationCode.REPORT_MODULE_CONTEXT_UNAVAILABLE),
            "thread_info", "memory_info",
        ])


_NO_SEARCH_STATS = StringSearchStats(skipped=0, clamped=0, truncated=0)


def _build_aggregate_coverage_report(records, search_stats: StringSearchStats):
    """Whole-run facts no single per-card CoverageReport can express: (a)
    at least one triage card's own target-region content read failed or
    came up short, aggregated under one synthetic "requested_region"
    source (never a real dict key any individual card's own coverage
    used -- see REGION_READ_TRUNCATED's own enum comment for why reusing
    that exact code/source pair across many cards is safe here), and (b)
    _search_string_in_memory()'s own memory-wide scan either skipped
    regions it could not read at all, or only partially read others --
    two distinct facts about the SEARCH itself (see StringSearchStats'
    own docstring), with no per-card home at all. `search_stats.clamped`
    is deliberately NOT folded in here: a self-imposed MAX_REGION_READ
    policy cap is an execution_status fact, not an evidence-completeness
    one (see _execution_status_for). Returns None when nothing applies
    (the common case), so the caller only combines it in when there is
    something to combine."""
    attempted = [r for r in records if r.region is not None]
    failed_count = sum(1 for r in attempted if r.string_scan_error is not None)
    # A card's own target-region read can come up short via either Section
    # 4's scan (string_scan["truncated"]) or its optional --output extract
    # (extract_read_truncated) -- the SAME underlying fact (the dump
    # doesn't back that much data at this address), so both fold into one
    # shared "at least one region read came up short" count rather than
    # two separate limitations for what is really one evidence gap.
    truncated_count = sum(1 for r in attempted
                           if (r.string_scan and r.string_scan["truncated"])
                           or r.extract_read_truncated)

    sources = {}
    completeness_checks = []

    if attempted:
        sources["requested_region"] = SourceObservation(
            name="requested_region",
            state=SourceState.FAILED if failed_count else SourceState.PRESENT,
            record_count=None if failed_count else len(attempted),
            detail=(f"{failed_count} of {len(attempted)} triage card region read(s) failed"
                    if failed_count else None))
        completeness_checks.append("requested_region")
        if truncated_count:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.REGION_READ_TRUNCATED, source="requested_region"))

    if search_stats.skipped or search_stats.truncated:
        sources["string_search"] = SourceObservation(
            name="string_search", state=SourceState.PRESENT, record_count=1)
        if search_stats.skipped:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.REPORT_STRING_SCAN_INCOMPLETE, source="string_search",
                affected_count=search_stats.skipped))
        if search_stats.truncated:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.REPORT_STRING_SCAN_TRUNCATED, source="string_search",
                affected_count=search_stats.truncated))

    if not sources:
        return None
    return build_coverage_report(sources, evaluation_sources=(), completeness_checks=completeness_checks)


def _combine_with_aggregate(coverages: list, records: list, search_stats: StringSearchStats):
    aggregate = _build_aggregate_coverage_report(records, search_stats)
    all_reports = list(coverages) + ([aggregate] if aggregate is not None else [])
    return combine_coverage_reports(all_reports)


def _execution_status_for(records, diagnostics, search_stats: StringSearchStats = _NO_SEARCH_STATS,
                           budget_skipped: int = 0):
    """MAX_REGION_READ clamping (a self-imposed scan-budget cutoff, at
    either the per-card Section 4 scan level or the whole-run
    --report-string search level), a per-card --output extract write
    failure, and the invocation budget leaving hits untriaged are all
    about whether THIS COMMAND finished its own intended work, not about
    whether the evidence it looked at was complete -- see
    OUTPUT_SCHEMA.md's own three-concepts-separate rule. Distinct from
    coverage.status, which `_build_aggregate_coverage_report` above
    governs instead (a short/failed read is an evidence gap; a deliberate
    policy clamp or a write failure is not)."""
    any_scan_clamped = any(r.string_scan and r.string_scan["clamped"] for r in records)
    any_extract_clamped = any(r.extract_read_clamped for r in records)
    any_extract_failed = any(d.code == "REPORT_EXTRACT_FAILED" for d in diagnostics)
    if (any_scan_clamped or any_extract_clamped or any_extract_failed
            or search_stats.clamped or budget_skipped):
        return EXECUTION_PARTIAL
    return EXECUTION_COMPLETED


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
    CoverageReports over the same mf -> one combined report" shape --
    _combine_with_aggregate() additionally folds in the whole-run facts
    _build_aggregate_coverage_report() derives, which no single per-card
    report can express on its own."""
    suspicious_prots = get_rules()["suspicious_protections"]

    # One process-wide enrichment per invocation, and one handle
    # collection shared by every card built below -- the scope split the
    # sections themselves declare. Collecting it per card would repeat the
    # same process/handle work N times for --report-string and publish N
    # copies of one process-wide fact.
    process_enrichment, handle_records = collect_process_enrichment(mf)
    handle_summary = process_enrichment.handles
    region_evidence = RegionEvidence.from_dump(mf)
    handle_index = HandleSegmentIndex.from_records(handle_records)
    # The main-image PE profile, its correlation, and each anchor module's
    # parsed IAT are collected once here and reused by every card.
    pe_cache = PeProfileCache.from_dump(mf, process_enrichment.image_base_address)
    pe_context = collect_pe_context(pe_cache)

    modules_available = bool(mf.modules)
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    infos   = get_thread_infos(mf)
    tid_map = {ti.ThreadId: ti for ti in infos}

    # ── String search mode: find regions, then triage each one ───────
    if report_string and not report_addr:
        hits, search_stats = _search_string_in_memory(mf, report_string)
        if not hits:
            incomplete = search_stats.skipped or search_stats.truncated or search_stats.clamped
            scan_note = ""
            if incomplete:
                scan_note = (
                    f" (scan was incomplete: {search_stats.skipped} region(s) could not be read "
                    f"at all, {search_stats.truncated} region(s) were only partially read, "
                    f"{search_stats.clamped} region(s) exceeded the per-region scan cap -- "
                    f"a needle in one of those would have been missed; see coverage/"
                    f"execution_status for detail)")
            diagnostics = [Diagnostic(SEVERITY_WARNING,
                f"String not found in the memory regions that could be scanned.{scan_note}",
                code="REPORT_STRING_NOT_FOUND")]
            coverage = _combine_with_aggregate(
                [_fallback_coverage(mf, modules_available, modules, infos, regions)], [], search_stats)
            return CommandResult(kind="report", records=[], coverage=coverage,
                execution_status=_execution_status_for([], diagnostics, search_stats),
                summary={"mode": "string", "card_count": 0, "query_string": report_string,
                         "query_tid": report_tid, "query_addr": None, "total_hits": 0,
                         "hits_private": 0, "hits_image": 0, "image_hit_modules": [],
                         "skipped_unreadable_regions": search_stats.skipped,
                         "truncated_regions": search_stats.truncated,
                         "clamped_regions": search_stats.clamped,
                         "cards_skipped_for_budget": 0, "hits_skipped_for_budget": 0,
                         "hits_sharing_a_region": 0,
                         "process_enrichment": process_enrichment.to_dict(),
                         "pe_context": pe_context.to_dict()},
                diagnostics=diagnostics)

        # The search reports a hit against the region it read. Everything
        # downstream -- whether the hit is actionable, which region is
        # budgeted, which region is carded -- is about the region that
        # actually covers the hit ADDRESS, and on an overlapping region
        # table those are different regions. Resolving once, here, is what
        # keeps the summary's own classification and the card it produces
        # from describing two different regions.
        resolved_hits = []
        for r, off, enc in hits:
            hit_va = r.BaseAddress + off
            final = _get_region_at(hit_va, regions) or r
            resolved_hits.append((final, hit_va - final.BaseAddress, enc))

        private_hits = []
        image_hits   = []
        for final, off, enc in resolved_hits:
            mtype = prot_str(final.Type)
            mod   = addr_to_module(final.BaseAddress, modules)
            if "MEM_IMAGE" in mtype and mod:
                image_hits.append((final, off, enc, mod))
            else:
                private_hits.append((final, off, enc))

        # One card per covering region: a second hit inside a region
        # already carded would read and triage the same bytes again under
        # a different anchor. Grouping happens before the budget and
        # counting after it, because whether a hit is "already covered by
        # a card" is only knowable once it is known which groups got one.
        hit_groups = []          # [final region, anchor offset, encoding, hit count]
        group_of_base = {}
        for final, off, enc in private_hits:
            position = group_of_base.get(final.BaseAddress)
            if position is None:
                group_of_base[final.BaseAddress] = len(hit_groups)
                hit_groups.append([final, off, enc, 1])
            else:
                hit_groups[position][3] += 1

        diagnostics = []
        if report_tid:
            diagnostics.append(Diagnostic(SEVERITY_WARNING,
                "--report-tid was also given, but a TID has no established relationship to "
                "any specific string hit region -- it is not carried into the per-region "
                "triage.", code="REPORT_TID_NOT_CORRELATED_WITH_STRING_HITS"))

        # Module names come from a Windows minidump even when dumpex runs
        # on Linux/macOS.  Use Windows path semantics so backslash-separated
        # paths collapse to the same basename on every analysis host.
        image_hit_modules = sorted({ntpath.basename(m.name) for _, _, _, m in image_hits})
        summary = {
            "mode": "string", "query_string": report_string, "query_tid": report_tid,
            "query_addr": None, "total_hits": len(hits), "hits_private": len(private_hits),
            "hits_image": len(image_hits), "image_hit_modules": image_hit_modules,
            "skipped_unreadable_regions": search_stats.skipped,
            "truncated_regions": search_stats.truncated,
            "clamped_regions": search_stats.clamped,
            "cards_skipped_for_budget": 0,
            "hits_skipped_for_budget": 0,
            "hits_sharing_a_region": 0,
            "process_enrichment": process_enrichment.to_dict(),
            "pe_context": pe_context.to_dict(),
        }

        if not hit_groups:
            diagnostics.append(Diagnostic(SEVERITY_WARNING,
                "All hits are in known system modules -- no actionable regions to triage.",
                code="REPORT_STRING_HITS_ALL_IMAGE"))
            summary["card_count"] = 0
            coverage = _combine_with_aggregate(
                [_fallback_coverage(mf, modules_available, modules, infos, regions)], [], search_stats)
            return CommandResult(kind="report", records=[], coverage=coverage,
                                  execution_status=_execution_status_for([], diagnostics, search_stats),
                                  summary=summary, diagnostics=diagnostics)

        records = []
        coverages = []
        artifacts = []
        # How many groups there are is the dump's to decide, so the loop
        # carries the run's own budget: the per-card caps bound one card
        # and say nothing about how many there are. A hit left untriaged
        # is reported as exactly that -- never folded into the hit counts,
        # which keep naming everything the search found.
        scan_bytes_used = 0
        carded_groups = 0
        for final, off, enc, _hit_count in hit_groups:
            # Exactly what this card will ask read_region() for: its
            # content scan, plus the same span again when --output makes
            # it extract. Charging the search's own region here instead
            # would let a small region's size pay for a large one's read.
            projected = min(final.RegionSize, MAX_REGION_READ) * (2 if extract_to else 1)
            if records and (len(records) >= MAX_REPORT_CARDS
                            or scan_bytes_used + projected > MAX_REPORT_SCAN_BYTES):
                break
            scan_bytes_used += projected
            carded_groups += 1
            # Multiple hit regions must not all extract to the same
            # literal path -- disambiguate per region, same as today.
            this_extract_to = extract_to
            if extract_to and len(hit_groups) > 1:
                ep = Path(extract_to)
                this_extract_to = str(
                    ep.with_name(f"{ep.stem}_0x{final.BaseAddress:x}{ep.suffix}"))
            record, coverage, card_diagnostics, artifact = _collect_triage_card(
                mf, tid=None, addr=final.BaseAddress, anchor_source=TRIAGE_ANCHOR_STRING_HIT,
                min_len=min_len, extract_to=this_extract_to, force=force,
                suspicious_prots=suspicious_prots, modules=modules, regions=regions,
                infos=infos, tid_map=tid_map, modules_available=modules_available,
                string_hit_tuple=(off, enc), handle_records=handle_records,
                handle_summary=handle_summary, query=report_string,
                region_evidence=region_evidence, handle_index=handle_index,
                resolved_region=final, pe_cache=pe_cache)
            records.append(record)
            coverages.append(coverage)
            diagnostics.extend(card_diagnostics)
            if artifact is not None:
                artifacts.append(artifact)

        # A hit is "covered by another hit's card" only when its group
        # actually got one. A group the budget skipped covers nothing, so
        # every hit in it is unanalyzed -- counting those as shared would
        # tell an analyst they are already represented somewhere.
        carded = hit_groups[:carded_groups]
        skipped = hit_groups[carded_groups:]
        merged_hits = sum(count - 1 for *_rest, count in carded)
        skipped_hits = sum(count for *_rest, count in skipped)

        summary["card_count"] = len(records)
        summary["cards_skipped_for_budget"] = len(skipped)
        summary["hits_skipped_for_budget"] = skipped_hits
        summary["hits_sharing_a_region"] = merged_hits
        if merged_hits:
            diagnostics.append(Diagnostic(SEVERITY_WARNING,
                f"{merged_hits} hit(s) fall inside a region another hit is already carded "
                f"for -- this dump's region table overlaps, and each region is triaged once.",
                code="REPORT_STRING_HITS_SHARE_A_REGION"))
        if skipped:
            diagnostics.append(Diagnostic(SEVERITY_WARNING,
                f"{len(skipped)} actionable hit region(s) covering {skipped_hits} hit(s) were "
                f"not triaged: this invocation reached its own budget of {MAX_REPORT_CARDS} "
                f"card(s) / {MAX_REPORT_SCAN_BYTES // (1024 * 1024)} MB of content reads. "
                f"Re-run with --report-addr against a specific region to triage one of them.",
                code="REPORT_CARD_BUDGET_REACHED"))
        return CommandResult(kind="report", records=records,
                              coverage=_combine_with_aggregate(coverages, records, search_stats),
                              execution_status=_execution_status_for(
                                  records, diagnostics, search_stats, len(skipped)),
                              summary=summary, diagnostics=diagnostics, artifacts=artifacts)

    # ── TID/address mode: exactly one card ────────────────────────────
    tid_int  = parse_hex_or_int(report_tid)  if report_tid  else None
    addr_int = parse_hex_or_int(report_addr) if report_addr else None
    anchor_source = TRIAGE_ANCHOR_ADDRESS if addr_int is not None else TRIAGE_ANCHOR_TID

    record, coverage, diagnostics, artifact = _collect_triage_card(
        mf, tid=tid_int, addr=addr_int, anchor_source=anchor_source, min_len=min_len,
        extract_to=extract_to, force=force, suspicious_prots=suspicious_prots,
        modules=modules, regions=regions, infos=infos, tid_map=tid_map,
        modules_available=modules_available, handle_records=handle_records,
        handle_summary=handle_summary, region_evidence=region_evidence,
        handle_index=handle_index, pe_cache=pe_cache)

    mode_parts = []
    if tid_int is not None:
        mode_parts.append("tid")
    if addr_int is not None:
        mode_parts.append("addr")
    summary = {
        "mode": "_".join(mode_parts), "card_count": 1, "query_string": None,
        "query_tid": report_tid, "query_addr": report_addr, "total_hits": None,
        "hits_private": None, "hits_image": None, "image_hit_modules": [],
        "skipped_unreadable_regions": 0, "truncated_regions": 0, "clamped_regions": 0,
        "cards_skipped_for_budget": 0,
        "hits_skipped_for_budget": 0,
        "hits_sharing_a_region": 0,
        "process_enrichment": process_enrichment.to_dict(),
        "pe_context": pe_context.to_dict(),
    }
    return CommandResult(kind="report", records=[record],
                          coverage=_combine_with_aggregate([coverage], [record], _NO_SEARCH_STATS),
                          execution_status=_execution_status_for([record], diagnostics),
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


def _backed_by_text(module_context: str, backing_module: "str | None") -> str:
    if module_context == MODULE_CONTEXT_RESOLVED:
        return DIM(ntpath.basename(backing_module))
    if module_context == MODULE_CONTEXT_UNREGISTERED:
        return RED("NOT IN ANY MODULE ⚠")
    return YELLOW("module classification unavailable")


def _render_card(mf, card, min_len: int, verbose: bool = False) -> None:
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
                # ModuleListStream string -- escaped before the colour
                # helper, per console_safe()'s own contract.
                print(f"  {'Backed By':<22} {GREEN(console_safe(t.backing_module))}")
                print(f"  {'Module Range':<22} 0x{int(t.backing_module_base, 16):x} — "
                      f"0x{int(t.backing_module_end, 16):x}")
            else:
                print(f"  {'Backed By':<22} {_backed_by_text(t.module_context, None)}")
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
            if r.module_owner:
                owner_text = DIM(r.module_owner)
            elif r.module_context == MODULE_CONTEXT_UNAVAILABLE:
                owner_text = YELLOW('unknown — module classification unavailable')
            else:
                owner_text = RED('none — unregistered private memory')
            print(f"  {'Module Owner':<22} {owner_text}")

            if r.is_rwx_private:
                print(f"\n  {RED('[!] RWX + MEM_PRIVATE — classic shellcode/injection marker')}")
            elif r.protection_suspicious:
                print(f"\n  {YELLOW('[~] PAGE_EXECUTE_READWRITE (module-backed — notable but less suspicious)')}")

            if r.mz_header_detected is None:
                print(f"  {YELLOW('[~] Could not read region header — injected-PE check skipped')}")
            elif r.has_injected_pe:
                print(f"  {RED('[!] MZ header — injected PE in unregistered private memory')}")
            elif r.mz_header_detected and r.module_context == MODULE_CONTEXT_RESOLVED:
                print(f"  {DIM('[·] MZ header (known module — expected)')}")
            elif r.mz_header_detected and r.module_context == MODULE_CONTEXT_UNAVAILABLE:
                print("  " + YELLOW(
                    "[~] MZ header found, but module classification is unavailable "
                    "(ModuleListStream absent) — cannot confirm this is an injected PE"
                ))
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
            backed = _backed_by_text(t.module_context, t.backing_module)
            tag = DIM(" ← report TID") if t.tid == card.anchor_tid else ""
            print(f"  TID=0x{t.tid:<8x}  StartAddr=0x{sa2:x}  {backed}{tag}")
        print()

    # ── 4. Strings + context-aware IOC display ────────────────────────
    if card.region is not None:
        print(BOLD("[ 4 ] STRINGS IN REGION"))
        print("─" * 50)
        if card.string_scan is not None:
            ss = card.string_scan
            print(DIM(f"  Scanning {ss['requested_bytes'] // 1024} KB  "
                      f"(ASCII + UTF-16LE, min_len={min_len})"))
            if ss["clamped"]:
                print(YELLOW(f"  [~] Region is {card.region.size // 1024} KB — "
                             f"clamped to {MAX_REGION_READ // (1024*1024)} MB for this scan"))
            if ss["truncated"]:
                print(YELLOW(f"  [~] Region read came up short: got {ss['bytes_read']} of "
                             f"{ss['requested_bytes']} requested byte(s) — coverage partial"))
            print()
            if card.ioc_strings:
                print(f"  {RED(f'[!] {len(card.ioc_strings)} IOC match(es):')}")
                base = int(card.region.base_address, 16)
                for s in card.ioc_strings:
                    abs_addr = int(s.address, 16)
                    fo_abs = None if card.region.file_offset is None else card.region.file_offset + s.offset
                    fo_abs_str = f"0x{fo_abs:x}" if fo_abs is not None else "(not captured)"
                    enc_col = f"[{s.encoding}]"
                    print(RED(f"    {CYAN(enc_col):<14} {console_safe(s.text)}"))
                    print(RED(f"      VA  = region base 0x{base:016x}  +  offset 0x{s.offset:x}  =  "
                              f"0x{abs_addr:016x}"))
                    print(RED(f"      DMP = file offset {fo_abs_str}"))
                    if s.is_network_pattern and s.context_hex is not None:
                        print(YELLOW("    ↳ Network pattern — ±128 byte context:"))
                        context_bytes = bytes.fromhex(s.context_hex)
                        print(_hexdump_context(context_bytes, s.context_hit_offset,
                                                int(s.context_base_address, 16),
                                                before=len(context_bytes), after=len(context_bytes)))
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
                    print(f"    {CYAN(enc_col):<14} {console_safe(s.text)}")
                    print(DIM(f"      VA  = 0x{base:016x} + 0x{off:x} = 0x{abs_addr:016x}  DMP = {fo_abs_str}"))

            print(DIM(f"\n  Total: {ss['total']} strings  "
                      f"(ASCII: {ss['ascii_count']}  UTF-16LE: {ss['utf16_count']})"))
        elif card.string_scan_error is not None:
            print(RED(f"  [!] Could not read region: {card.string_scan_error}"))
        print()

    # ── 5-8. Card enrichment ──────────────────────────────────────────
    if card.exception_context is not None:
        _render_exception_context(card.exception_context, verbose)
    if card.allocation_neighborhood is not None:
        _render_allocation_neighborhood(card.allocation_neighborhood, verbose)
    if card.handle_correlation is not None:
        _render_handle_correlation(card.handle_correlation, verbose)
    if card.string_context is not None:
        _render_string_context(card.string_context, verbose)
    if card.anchor_pe_context is not None:
        _render_anchor_pe_context(card.anchor_pe_context, verbose)
    if card.instruction_context is not None:
        _render_instruction_context(card.instruction_context, verbose)
    if card.iat_correlation is not None:
        _render_iat_correlation(card.iat_correlation, verbose)

    # ── Verdict (MECE) ────────────────────────────────────────────────
    print(BOLD("[ VERDICT ]"))
    print("─" * 50)
    print(f"  {_render_verdict_text(card.verdict, len(card.findings))}\n")
    if card.findings:
        for key in card.findings:
            label = INDICATOR_DIMS.get(key, key)
            print(f"  {BOLD('►')} {YELLOW(label)}")
            print(f"    {DIM(card.finding_details[key])}")


# ── Enrichment console projection ─────────────────────────────────────
# Every block below renders from the same records and summary dict the
# JSON document carries -- no console-only derivation, and no enrichment
# fact structured output does not also publish. A console preview is
# smaller than the retained set on purpose; whenever it is, the omission
# is printed, and it is worded differently from a data-level truncation so
# the two stay distinguishable.
#
# `verbose` selects between two projections of that one retained set and
# nothing else. The default keeps each block to what an analyst acts on:
# the anchor facts, every incomplete evidence state, every actionable
# conflict, and a bounded preview of each populated section. Verbose
# prints every retained row plus the per-section envelope and the
# selection reasons behind it. Neither level reads the dump again, calls a
# collector, or widens a retention cap: what verbose shows was already
# retained, and what a cap dropped no level can show.

_ENRICHMENT_STATE_TEXT = {
    ENRICHMENT_MISSING:  "not evaluated",
    ENRICHMENT_PARTIAL:  "partial",
    ENRICHMENT_COMPLETE: "complete",
}

# Whether the process image base could be placed in the captured module
# list. "resolved" is the routine positive; the other two are results an
# analyst acts on, and neither is implied by the process section's own
# evidence state -- a dump with a PEB path and a start time evaluates
# completely whether or not it carried a module list to match against.
_MODULE_MATCH_RESOLVED = "resolved"


def _module_match_text(state: str) -> str:
    """One module-match state as a console phrase. An unrecognized state
    prints as itself rather than as nothing: the value came from the
    identity snapshot, and dropping it would report an unknown answer as
    no answer."""
    if state == _MODULE_MATCH_RESOLVED:
        return GREEN("resolved") + DIM(" — the image base is in a captured module")
    if state == "unregistered":
        return RED("unregistered — the image base is in no captured module")
    if state == "unavailable":
        return YELLOW("unavailable — no usable module list to match against")
    return console_safe(state)


def _print_section_state(section: dict, *, indent: str = "  ", verbose: bool = False) -> None:
    """The state line every enrichment block closes with, plus each
    limitation the section recorded.

    Verbose states the full envelope: scope, evidence state, counts, cap,
    and the streams the section was built from. The default states only
    what an analyst has to act on -- which evidence state this is, and how
    much it kept -- because scope and cap are properties of the section's
    own definition, not of this dump. A completed evaluation that found
    nothing eligible states nothing at all: the block's own sentence above
    it is already the completed-negative result, and a `kept: 0 of 0` line
    under it only repeats that. Truncation and limitations print at both
    levels: an incomplete evidence state is never a detail."""
    state = _ENRICHMENT_STATE_TEXT[section["status"]]
    counts = str(section["included"])
    if section["total"] is not None:
        counts = f"{section['included']} of {section['total']}"
    cap = section["cap"] if section["cap"] is not None else "none"
    routine_negative = (section["status"] == ENRICHMENT_COMPLETE
                        and section["included"] == 0 and not section["truncated"])
    if verbose:
        print(indent + DIM(f"scope: {section['scope']}   evidence: {state}   "
                           f"kept: {counts}   cap: {cap}"))
        if section["provenance"]:
            print(indent + DIM("built from: "
                               + ", ".join(console_safe(p) for p in section["provenance"])))
    elif section["status"] == ENRICHMENT_MISSING:
        print(indent + DIM(f"evidence: {state}"))
    elif not routine_negative:
        print(indent + DIM(f"evidence: {state}   kept: {counts}"))
    if section["truncated"]:
        print(indent + YELLOW(_truncation_text(section)))
    for limitation in section["limitations"]:
        print(indent + YELLOW("[~] " + console_safe(limitation)))


def _truncation_text(section: dict) -> str:
    """A collection cut, worded so it can never be read as a console
    preview. What the cap dropped was never retained: no detail level and
    no structured document can produce it, and only a differently bounded
    run could."""
    cap = section["cap"] if section["cap"] is not None else "none"
    total = section["total"]
    if total is None:
        return (f"[~] retained set cut at the cap of {cap} — the eligible entries beyond "
                f"it were not retained and are in neither the console nor --json")
    dropped = total - section["included"]
    entries = "entry" if dropped == 1 else "entries"
    return (f"[~] retained set cut at the cap of {cap}: kept {section['included']} of "
            f"{total} eligible — {dropped} eligible {entries} were not retained and are "
            f"in neither the console nor --json")


# The cut point a capped value carries when it sits in a packed line with
# no room for a bracketed mark. Written where the retained text ends, so
# it names which of several values on one line was cut.
CAP_ELLIPSIS = "…"


def _cap_mark(*fields) -> str:
    """The mark a rendered value that reached the retained-text cap
    carries, naming which field was cut when a line renders more than one
    dump-derived value. A capped value is a prefix of what the dump held;
    unmarked, it reads as the whole thing.

    `fields` are (label, truncated) pairs in the order they appear on the
    line."""
    cut = [label for label, truncated in fields if truncated]
    if not cut:
        return ""
    return DIM(" [truncated: " + ", ".join(cut) + "]")


def _print_console_omission(shown: int, kept: int, indent: str = "  ") -> None:
    """A console preview shorter than the retained set. Every omitted row
    is still retained, so both --verbose and --json can produce it."""
    if kept > shown:
        print(indent + DIM(f"[·] console shows {shown} of {kept} retained entries "
                           f"— use --verbose for all of them; --json carries the same "
                           f"retained set"))


def _render_process_enrichment(enrichment: dict, verbose: bool = False) -> None:
    # This block owns its own leading blank line, so suppressing the whole
    # function leaves the surrounding output exactly as it would be
    # without any enrichment at all -- which is what the compatibility
    # freeze suite relies on to compare the frozen surface.
    print()
    print(BOLD("[ P ] PROCESS CONTEXT"))
    print("─" * 50)
    section = enrichment["section"]
    if section["status"] == ENRICHMENT_MISSING:
        print(DIM("  [·] No process identity evidence in this dump."))
    else:
        pid = enrichment["pid"]
        pid_text = str(pid) if pid is not None else DIM("(not captured)")
        print(f"  {'PID':<22} {pid_text}")
        name = enrichment["process_name"]
        name_text = console_safe(name) if name else DIM("(not captured)")
        if name and enrichment["process_name_truncated"]:
            name_text += DIM(" [truncated]")
        print(f"  {'Process':<22} {name_text}")
        path = enrichment["process_path"]
        if path:
            source = enrichment["path_source"]
            cut = DIM(" [truncated]") if enrichment["process_path_truncated"] else ""
            print(f"  {'Path':<22} {console_safe(path)}{cut}  {DIM('← from ' + source)}")
        command_line = enrichment["command_line"]
        if command_line:
            cut = DIM(" [truncated]") if enrichment["command_line_truncated"] else ""
            print(f"  {'Command Line':<22} {console_safe(command_line)}{cut}")
        match_state = enrichment["module_match_state"]
        if match_state is not None and (verbose or match_state != _MODULE_MATCH_RESOLVED):
            print(f"  {'Module match':<22} {_module_match_text(match_state)}")
        # Run metadata rather than identity: neither carries a
        # completeness flag of its own, so folding them into the verbose
        # level hides no incomplete evidence state.
        if verbose:
            started = enrichment["process_start_utc"]
            if started:
                print(f"  {'Started (UTC)':<22} {started}")
            base = enrichment["image_base_address"]
            if base:
                print(f"  {'Image Base':<22} 0x{int(base, 16):016x}")
    # Printed apart from the section's own limitations: a source
    # disagreement is not a coverage gap, and rendering the two in one
    # list would invite reading it as one.
    conflicts = enrichment["identity_conflicts"]
    if conflicts:
        print("  " + BOLD("Identity conflicts (captured sources disagree)"))
        for conflict in conflicts:
            print("    " + YELLOW("[!] " + console_safe(conflict["message"])))
            if verbose:
                print("        " + DIM(conflict["code"]))
        hidden = enrichment["identity_conflicts_total"] - len(conflicts)
        if hidden > 0:
            print(DIM(f"    [·] {hidden} further conflict(s) are reported by --process"))
    _print_section_state(section, verbose=verbose)
    print()

    environment = enrichment["environment"]
    print("  " + BOLD("Session (allowlisted environment)"))
    if environment["entries"]:
        if verbose:
            for entry in environment["entries"]:
                mark = DIM(" [truncated]") if entry["truncated"] else ""
                print(f"    {entry['name']:<24} {console_safe(entry['value'])}{mark}")
        else:
            # Which variables were captured places the session; their
            # values are routine session strings that lengthen every run.
            # The count of shortened values travels with the names, so a
            # value that hit the retained-text cap stays visible without
            # printing any value at all.
            names = "  ".join(entry["name"] for entry in environment["entries"])
            print(f"    {'Captured':<24} {names}")
            cut = sum(1 for entry in environment["entries"] if entry["truncated"])
            if cut:
                print(DIM(f"    [~] {cut} captured value(s) reached the retained-text cap"))
            print(DIM("    [·] values not shown — use --verbose for them; --json "
                      "carries the same retained set"))
    elif environment["section"]["status"] == ENRICHMENT_MISSING:
        print(DIM("    [·] Environment block not read — see the note below."))
    else:
        print(DIM("    [·] No allowlisted variable was captured in this block."))
    _print_section_state(environment["section"], indent="    ", verbose=verbose)
    print()

    handles = enrichment["handles"]
    print("  " + BOLD("Handles"))
    if handles["section"]["status"] == ENRICHMENT_MISSING:
        print(DIM("    [·] No handle evidence — see the note below."))
    else:
        rows = handles["by_type"]
        shown = rows if verbose else rows[:CONSOLE_HANDLE_TYPE_ROWS]
        # The census packs its names onto one line, so a capped name
        # carries its own cut point instead of a bracketed mark: the
        # trailing "…" sits exactly where the retained text ends, which
        # also says WHICH name was cut when several share the line.
        census = "  ".join(console_safe(row["type_name"])
                           + (CAP_ELLIPSIS if row["type_name_truncated"] else "")
                           + "=" + str(row["count"])
                           for row in shown)
        print(f"    {'Total':<24} {handles['total_handles']}")
        print(f"    {'By type':<24} {census if census else DIM('(none)')}")
        # Two separate facts. A cut name on the line above is a prefix an
        # analyst is reading right now; a cut name among the rows this
        # level does not print is retained but never displayed, so
        # claiming it is "shown" as a prefix would describe output that
        # is not on screen.
        shown_capped = sum(1 for row in shown if row["type_name_truncated"])
        hidden_capped = sum(1 for row in rows[len(shown):] if row["type_name_truncated"])
        if shown_capped:
            print(YELLOW(f"    [~] {shown_capped} type name(s) above reached the "
                         f"retained-text cap — a trailing {CAP_ELLIPSIS} marks each one"))
        if hidden_capped:
            print(YELLOW(f"    [~] {hidden_capped} retained type name(s) not shown here "
                         f"also reached the retained-text cap"))
        _print_console_omission(len(shown), len(rows), indent="    ")
    _print_section_state(handles["section"], indent="    ", verbose=verbose)
    print()

    token = enrichment["token"]
    print("  " + BOLD("Token"))
    print(f"    {'Capability':<24} {token['status']}")
    # The capability status is the actionable fact -- whether this dump
    # can say anything about the token at all. Which stream declared it
    # and how the parser fared explain that status rather than add to it.
    if verbose:
        parser_state = token["parser_state"]
        stream_text = "declared" if token["stream_present"] else "not declared"
        if parser_state:
            stream_text += DIM("  (parser: " + parser_state + ")")
        print(f"    {'Stream':<24} {stream_text}")
    print("    " + DIM(console_safe(token["detail"])))
    print()


def _address_context_text(context) -> str:
    """One resolved address as a single console phrase. An address the
    region table does not describe says so rather than rendering blanks
    that read as "no protection"."""
    mark = _cap_mark(("module owner", context.module_owner_truncated))
    if context.region_base is None:
        owner = context.module_owner
        if owner:
            return "in " + console_safe(owner) + mark + ", no captured region describes it"
        return "no captured region describes this address"
    parts = [f"region 0x{int(context.region_base, 16):x}"]
    if context.protection:
        parts.append(context.protection)
    if context.type:
        parts.append(context.type)
    parts.append(console_safe(context.module_owner) + mark if context.module_owner
                 else "no module owner")
    return "  ".join(parts)


def _render_exception_context(context, verbose: bool = False) -> None:
    print(BOLD("[ 5 ] EXCEPTION CONTEXT"))
    print("─" * 50)
    section = context.section.to_dict()
    if not context.entries:
        if section["status"] == ENRICHMENT_MISSING:
            print(DIM("  [·] No exception evidence was evaluated."))
        else:
            print(DIM("  [·] No exception record relates to this anchor."))
    for entry in context.entries:
        name = entry.exception_code_name or DIM("(code not recognized by the parser)")
        code = entry.exception_code or DIM("(no usable code captured)")
        print(f"  {RED('►')} {code}  {name}")
        tid_text = f"0x{entry.thread_id:x}" if entry.thread_id is not None else "(not captured)"
        address = entry.exception_address
        address_text = f"0x{int(address, 16):016x}" if address else "(not captured)"
        print(f"      TID={tid_text}  Address={address_text}")
        if verbose and entry.address_context is not None:
            print("      " + DIM("at: " + _address_context_text(entry.address_context)))
        if entry.access_type is not None or entry.referenced_address is not None:
            access = entry.access_type or "access type not decodable"
            referenced = (f"0x{int(entry.referenced_address, 16):016x}"
                          if entry.referenced_address else "(not captured)")
            print(f"      Tried to {access} {referenced}")
            if verbose and entry.referenced_context is not None:
                print("      " + DIM("that address: "
                                     + _address_context_text(entry.referenced_context)))
        if verbose:
            print("      " + DIM("selected: " + entry.selection_reason))
        if entry.parameters:
            more = " …" if entry.parameters_truncated else ""
            print("      " + DIM("Information: " + ", ".join(entry.parameters) + more))
    print(DIM("  Exception state is execution evidence, not a maliciousness finding."))
    _print_section_state(section, verbose=verbose)
    print()


def _render_allocation_neighborhood(neighborhood, verbose: bool = False) -> None:
    print(BOLD("[ 6 ] ALLOCATION NEIGHBORHOOD"))
    print("─" * 50)
    section = neighborhood.section.to_dict()
    if not neighborhood.entries:
        if section["status"] == ENRICHMENT_MISSING:
            print(DIM("  [·] No region table was evaluated."))
        else:
            print(DIM("  [·] No region in the table contains this anchor."))
    else:
        base = neighborhood.allocation_base
        base_text = f"0x{int(base, 16):016x}" if base else DIM("(not recorded)")
        print(f"  {'Allocation base':<22} {base_text}")
        shown = (list(neighborhood.entries) if verbose
                 else neighborhood.entries[:CONSOLE_NEIGHBOR_REGIONS])
        for entry in shown:
            marker = RED("►") if entry.relation == "anchor" else " "
            gap = "adjacent" if entry.distance == 0 else f"gap {entry.distance:#x}"
            protection = entry.protection or "?"
            mem_type = entry.type or "?"
            print(f"  {marker} 0x{int(entry.base_address, 16):016x}  "
                  f"{entry.size // 1024:>7} KB  {protection:<24} {mem_type:<14} "
                  f"{DIM(entry.relation)} {DIM(gap)}")
            # A neighbour's owning module is verbose detail, and only a
            # resolved owner earns a line even there. An unowned region is
            # the common case for a dump with no module list, and
            # repeating that for every row would double the block for no
            # evidence; the null is in --json either way.
            if verbose and entry.module_owner:
                print("      " + DIM("owner: " + console_safe(entry.module_owner))
                      + _cap_mark(("module owner", entry.module_owner_truncated)))
        _print_console_omission(len(shown), len(neighborhood.entries))
        print(DIM("  Adjacency is memory layout, not a relationship to the anchor."))
    _print_section_state(section, verbose=verbose)
    print()


def _hex_or_none(value) -> "str | None":
    return None if value is None else f"0x{value:x}"


def _render_handle_correlation(correlation, verbose: bool = False) -> None:
    print(BOLD("[ 7 ] CORRELATED HANDLES"))
    print("─" * 50)
    section = correlation.section.to_dict()
    if not correlation.entries:
        if section["status"] == ENRICHMENT_MISSING:
            print(DIM("  [·] No handle evidence was evaluated for this card."))
        else:
            print(DIM("  [·] No handle object name appears in this card's captured text."))
    else:
        shown = (list(correlation.entries) if verbose
                 else correlation.entries[:CONSOLE_CORRELATED_HANDLES])
        for entry in shown:
            type_text = console_safe(entry.type_name) if entry.type_name else "(unnamed type)"
            # One mark for the whole row, naming each field it applies to:
            # two bare marks on a line carrying two dump-derived values
            # could not say which value was cut.
            cut = _cap_mark(("type name", entry.type_name_truncated),
                            ("object name", entry.object_name_truncated))
            print(f"  ►  {entry.handle}  {type_text:<16} "
                  f"{console_safe(entry.object_name)}{cut}")
            if verbose:
                counters = "  ".join(
                    f"{label}={value}" for label, value in
                    (("access", _hex_or_none(entry.granted_access)),
                     ("attributes", _hex_or_none(entry.attributes)),
                     ("handles", entry.handle_count), ("pointers", entry.pointer_count))
                    if value is not None)
                if counters:
                    print("      " + DIM(counters))
                print("      " + DIM("selected: " + entry.selection_reason))
        _print_console_omission(len(shown), len(correlation.entries))
        print(DIM("  A shared name is two captures of the same text, not proof of use."))
    print(DIM("  Full inventory: --handles"))
    _print_section_state(section, verbose=verbose)
    print()


def _render_string_context(context, verbose: bool = False) -> None:
    print(BOLD("[ 8 ] STRING CONTEXT AROUND THE ANCHOR"))
    print("─" * 50)
    section = context.section.to_dict()
    # The read line prints at both detail levels: `bytes_read` short of
    # `requested_bytes` is a partial read, and a partial read is an
    # evidence state rather than a detail.
    print(DIM(f"  Examined 0x{int(context.examined_base_address, 16):x} "
              f"+ {context.bytes_read} of {context.requested_bytes} requested byte(s); "
              f"{context.total_strings} string(s) extracted"))
    if verbose:
        print(DIM(f"  Distances measured from "
                  f"0x{int(context.distance_anchor_address, 16):x}"))
    if context.query_text is not None:
        print(DIM("  Searched for: " + console_safe(context.query_text)))
    if not context.entries:
        print(DIM("  [·] No string was retained from the examined range."))
    else:
        shown = (list(context.entries) if verbose
                 else context.entries[:CONSOLE_STRING_CONTEXT])
        for entry in shown:
            distance = "anchor" if entry.distance is None else f"distance {entry.distance:#x}"
            mark = DIM(" [truncated]") if entry.text_truncated else ""
            encoding = CYAN("[" + entry.encoding + "]")
            reason = (entry.selection_reason + " ") if verbose else ""
            print(f"    {encoding:<14} 0x{int(entry.address, 16):016x}  "
                  f"{DIM(reason + distance)}")
            print(f"      {console_safe(entry.text)}{mark}")
        _print_console_omission(len(shown), len(context.entries))
    print(DIM("  Proximity is layout: an adjacent string is not a reference to the anchor."))
    _print_section_state(section, verbose=verbose)
    print()


def _render_pe_context(pe_context: dict, verbose: bool = False) -> None:
    print()
    print(BOLD("[ PE ] MAIN IMAGE PE CONTEXT"))
    print("─" * 50)
    section = pe_context["section"]
    if section["status"] == ENRICHMENT_MISSING:
        print(DIM("  [·] The main image PE header was not read."))
        _print_section_state(section, verbose=verbose)
        print()
        return
    base = pe_context["image_base"]
    if base:
        print(f"  {'Image base':<20} 0x{int(base, 16):016x}")
    machine = pe_context["machine_name"] or (
        hex(pe_context["machine"]) if pe_context["machine"] is not None else None)
    if machine:
        print(f"  {'Machine':<20} {console_safe(str(machine))}")
    if verbose:
        preferred = pe_context["preferred_image_base"]
        if preferred:
            print(f"  {'Preferred base':<20} 0x{int(preferred, 16):016x}")
        if pe_context["time_date_stamp"] is not None:
            print(f"  {'TimeDateStamp':<20} 0x{pe_context['time_date_stamp']:08x}")
        if pe_context["size_of_image"] is not None:
            print(f"  {'SizeOfImage':<20} 0x{pe_context['size_of_image']:x}")
        entry_va = pe_context["entry_point_va"]
        if entry_va:
            print(f"  {'Entry point':<20} 0x{int(entry_va, 16):016x}")
    match = pe_context["module_match"]
    if match is not None and (verbose or match != _MODULE_MATCH_RESOLVED):
        print(f"  {'Module list match':<20} {_module_match_text(match)}")
    print(f"  {'Correlation':<20} "
          + DIM(f"{pe_context['consistent_count']} consistent  "
                f"{pe_context['conflict_count']} conflict  "
                f"{pe_context['unavailable_count']} unavailable"))
    conflicts = pe_context["observations"]
    if conflicts:
        print("  " + BOLD("Structural conflicts (captured facts disagree)"))
        shown = conflicts if verbose else conflicts[:CONSOLE_PE_CONFLICTS]
        for observation in shown:
            print("    " + YELLOW("[!] " + console_safe(observation["name"]) + " — "
                                  + console_safe(observation["reason"])))
        _print_console_omission(len(shown), len(conflicts), indent="    ")
    print(DIM("  A structural conflict is a lead for review, not a maliciousness finding."))
    _print_section_state(section, verbose=verbose)
    print()


def _render_anchor_pe_context(context, verbose: bool = False) -> None:
    print(BOLD("[ 9 ] ANCHOR IN THE PE IMAGE"))
    print("─" * 50)
    section = context.section.to_dict()
    if section["status"] == ENRICHMENT_MISSING:
        print(DIM("  [·] No module or region places this anchor."))
        _print_section_state(section, verbose=verbose)
        print()
        return
    owner = console_safe(context.module_owner) if context.module_owner else "(no module)"
    cut = _cap_mark(("module owner", context.module_owner_truncated),
                    ("section name", context.section_name_truncated))
    location = context.classification
    if context.section_name:
        location += f" in {console_safe(context.section_name)}"
    print(f"  {'Placement':<18} {location}{cut}")
    print(f"  {'Owning module':<18} {owner}   {DIM(context.registration)}")
    if context.module_rva is not None:
        print(f"  {'Module RVA':<18} 0x{context.module_rva:x}")
    if context.live_protection or context.declared_executable is not None:
        declared = "".join(letter for letter, flag in (
            ("R", context.declared_readable), ("W", context.declared_writable),
            ("X", context.declared_executable)) if flag) or "?"
        live = context.live_protection or "?"
        match = context.protection_matches_declared
        note = ("" if match is None
                else DIM("  (matches declared)") if match
                else YELLOW("  [!] live protection differs from the declared section bits"))
        print(f"  {'Protection':<18} declared {declared}   live {live}{note}")
    print(DIM("  A protection mismatch is a lead for review, not a verdict."))
    _print_section_state(section, verbose=verbose)
    print()


def _render_instruction_context(context, verbose: bool = False) -> None:
    print(BOLD("[ 10 ] INSTRUCTION CONTEXT"))
    print("─" * 50)
    section = context.section.to_dict()
    if context.anchor_address:
        print(DIM(f"  Window at 0x{int(context.anchor_address, 16):016x} "
                  f"({context.anchor_source}, {context.architecture or '?'}); "
                  f"{context.bytes_read} byte(s) read; decoder: {context.decoder_state}"))
    if not context.instructions:
        if section["status"] == ENRICHMENT_MISSING:
            print(DIM("  [·] No bytes were captured at this anchor."))
        else:
            print(DIM("  [·] No instruction was decoded."))
    else:
        shown = (list(context.instructions) if verbose
                 else context.instructions[:CONSOLE_INSTRUCTION_ROWS])
        for insn in shown:
            marker = RED("►") if insn.is_anchor else " "
            mark = DIM(" [truncated]") if insn.text_truncated else ""
            print(f"  {marker} 0x{int(insn.address, 16):016x}  "
                  f"{console_safe(insn.text)}{mark}")
        _print_console_omission(len(shown), len(context.instructions))
    if context.branch_targets:
        print("  " + BOLD("Branch targets"))
        shown = (list(context.branch_targets) if verbose
                 else context.branch_targets[:CONSOLE_BRANCH_TARGETS])
        for target in shown:
            owner = console_safe(target.module_owner) if target.module_owner else "?"
            dest = target.resolved_target_address or target.target_address
            dest_text = f"0x{int(dest, 16):016x}" if dest else "(unresolved)"
            symbol = (f"  {console_safe(target.iat_symbol)}"
                      if target.iat_symbol else "")
            kind = target.kind + ("?" if target.iat_classification_uncertain else "")
            print(f"    {DIM(kind):<20} {dest_text}  {owner}{symbol}")
        _print_console_omission(len(shown), len(context.branch_targets), indent="    ")
    print(DIM("  Instruction context names no function, argument, or call stack."))
    _print_section_state(section, verbose=verbose)
    print()


def _render_iat_correlation(correlation, verbose: bool = False) -> None:
    print(BOLD("[ 11 ] IAT CORRELATION"))
    print("─" * 50)
    section = correlation.section.to_dict()
    owner = (console_safe(correlation.module_owner) if correlation.module_owner
             else "(module unknown)")
    if section["status"] == ENRICHMENT_MISSING:
        print(DIM(f"  [·] {owner}: its import table could not be read."))
        _print_section_state(section, verbose=verbose)
        print()
        return
    counts = []
    if correlation.dll_count is not None:
        counts.append(f"{correlation.dll_count} DLL(s)")
    if correlation.entry_count is not None:
        counts.append(f"{correlation.entry_count} import(s)")
    print(f"  {owner}   " + DIM(", ".join(counts) if counts else "no import summary"))
    if not correlation.entries:
        print(DIM("  [·] No import slot is instruction-correlated or unusual."))
    else:
        shown = (list(correlation.entries) if verbose
                 else correlation.entries[:CONSOLE_IAT_ROWS])
        for entry in shown:
            name = console_safe(entry.symbol or entry.dll or "(unnamed)")
            target = entry.resolved_target_va
            target_text = f"→ 0x{int(target, 16):016x}" if target else ""
            owner_text = (console_safe(entry.target_module_owner)
                          if entry.target_module_owner else entry.target_registration or "?")
            print(f"  ► {name}  {DIM(entry.selection_reason)}")
            print(f"      {target_text}  {owner_text}")
        _print_console_omission(len(shown), len(correlation.entries))
    print(DIM("  An unusual thunk target is an investigation lead, not a verdict."))
    _print_section_state(section, verbose=verbose)
    print()


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


def render_report_console(records, coverage, diagnostics, artifacts, summary, mf,
                          min_len: int, verbose: bool = False) -> None:
    """Reproduces today's exact, pre-migration console text -- see
    dumpex.commands.report's own git history / the Phase E plan's capture
    script for the byte-for-byte ground truth this was built against.
    Takes `mf` (unlike every other render_*_console in this package) only
    to read `mf.filename` for the per-card banner's "File : ..." line --
    no coverage/business-logic decision here depends on the dump itself,
    and the network-pattern hexdump context is read from each
    ReportIocString's own bounded context_hex, never re-read from `mf`
    (see _collect_triage_card's own note on why that's computed once at
    collect time).

    `verbose` is presentation only: it selects how much of the already
    collected `records`/`summary` the enrichment blocks project, and
    changes no finding, verdict, coverage, diagnostic, artifact, or exit
    code. Sections 1-4 and the verdict block render identically at both
    levels."""
    for reason in coverage.reasons:
        print(YELLOW(f"  [~] {reason}"))

    # One process-wide block per invocation, before any card: its scope is
    # the whole dump, so repeating it per card would publish one fact N
    # times and invite an analyst to read it as card-specific.
    if summary.get("process_enrichment") is not None:
        _render_process_enrichment(summary["process_enrichment"], verbose)
    if summary.get("pe_context") is not None:
        _render_pe_context(summary["pe_context"], verbose)

    if summary["mode"] == "string":
        print(f"\n{BOLD('Searching memory for:')} {CYAN(repr(summary['query_string']))}")
        print("─" * 55)
        if summary["card_count"] == 0 and summary["total_hits"] == 0:
            print(RED(f"  [!] String not found in the memory regions that could be scanned."))
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
            # ntpath.basename() of ModuleListStream names (see the summary
            # builder above) -- dump strings, escaped for the console while
            # summary/--json keep the exact values.
            mods = ", ".join(console_safe(m) for m in summary["image_hit_modules"])
            print(DIM(f"    [·] {summary['hits_image']} hit(s) in known MEM_IMAGE modules "
                      f"({mods}) — skipped (expected content)"))
        print()

        if summary["card_count"] == 0:
            print(DIM("  [·] All hits are in known system modules — no actionable regions to triage."))
            return

        if summary.get("cards_skipped_for_budget"):
            print(YELLOW(
                f"  [~] {summary['cards_skipped_for_budget']} actionable hit region(s) "
                f"covering {summary['hits_skipped_for_budget']} hit(s) were not triaged — "
                f"this run reached its own card/read budget. Use --report-addr on a specific "
                f"region to triage one of them.\n"))

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
            _render_card(mf, card, min_len, verbose)
            _print_extract_result(records, artifacts, card)
            print()   # unconditional trailing blank line -- matches today's
                       # cmd_report, which ends every single-shot invocation
                       # (each recursive sub-call, pre-flatten) with a bare
                       # print() after the extract block, extract or not
        return

    # tid/addr mode -- exactly one card
    card = records[0]
    _print_card_banner(mf, card, summary["query_tid"], summary["query_addr"])
    _render_card(mf, card, min_len, verbose)
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
    if card.extract_read_truncated:
        print(RED(f"  [!] Read came up short of what was requested -- the written artifact "
                  f"is INCOMPLETE (see coverage for detail)"))
    summary_text = f"{artifact.size_bytes} bytes  sha256={artifact.sha256}"
    print(GREEN(f"[+] Region extracted → {artifact.path}  ({summary_text})"))


def cmd_report(mf: MinidumpFile, report_tid: str = None, report_addr: str = None,
               report_string: str = None, extract_to: str = None, min_len: int = 6,
               force: bool = False, verbose: bool = False) -> CommandResult:
    """\n    Alert triage card: given a TID, address, or string from an EDR alert / TI feed,\n    correlate thread, memory, and string evidence into a structured verdict.\n    Verdict uses MECE dimensions — each dimension scored at most once.\n\n    --report-string: search all memory for the string, then run triage on each\n                    matching region. Useful when the anchor is a C2 IP, domain,\n                    or known malware string from threat intelligence.\n\n    verbose expands the console projection of the enrichment this run already\n    retained; collection, caps, records, and the exit code are the same either\n    way.\n    """
    result = collect_report(mf, report_tid=report_tid, report_addr=report_addr,
                             report_string=report_string, extract_to=extract_to,
                             min_len=min_len, force=force)
    render_report_console(result.records, result.coverage, result.diagnostics,
                           result.artifacts, result.summary, mf, min_len, verbose)
    return result

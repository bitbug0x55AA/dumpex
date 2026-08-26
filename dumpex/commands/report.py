"""--report command."""
import ntpath
import os
import re
from pathlib import Path
from typing import NamedTuple
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN, console_safe
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_infos, addr_to_module, va_to_file_offset, prot_str,
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
    """
    mz_header_detected: "bool | None"
    has_injected_pe: "bool | None"
    ioc_strings: tuple
    notable_strings: tuple
    string_scan: "dict | None"
    string_scan_error: "str | None"


def _scan_content_range(mf, *, base_address: int, requested_size: int, min_len: int,
                         module_context: str) -> ContentScanResult:
    """The read + string/IOC/MZ analysis itself -- see `ContentScanResult`'s
    own docstring for why this takes a bare `base_address`/`requested_size`
    rather than a resolved MemoryInfo region. `module_context` (one of
    MODULE_CONTEXT_RESOLVED/UNREGISTERED/UNAVAILABLE) is supplied by the
    caller -- both callers already have to resolve it their own way
    (--report via the region's own module ownership, deep triage via
    `addr_to_module(target.base_address, modules)` directly) before they
    can decide `has_injected_pe`, so it is not re-derived here."""
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
        string_scan=string_scan, string_scan_error=None)


def _collect_triage_card(mf, *, tid=None, addr=None, anchor_source: str, min_len: int,
                          extract_to: "str | None", force: bool, suspicious_prots,
                          modules: list, regions: list, infos: list, tid_map: dict,
                          modules_available: bool, string_hit_tuple=None,
                          max_region_read: "int | None" = None):
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

    `max_region_read` caps ONLY Section 4's string/IOC scan read
    (`read_size` below) -- `None` (the default) resolves to the CURRENT
    value of the module-level MAX_REGION_READ at call time (not a value
    bound once at import time), so every existing --report caller
    (collect_report()) is byte-for-byte unchanged, including tests that
    monkeypatch MAX_REGION_READ itself. dumpex.hunt._deep_triage's own
    opt-in `--triage-skipped`
    budgeted deep-content triage (issue #19 Phase 2) is the one caller
    that passes a smaller, explicit per-target budget here instead of
    silently reusing --report's own 256 MiB default across every skipped
    target -- see that module's own docstring. The optional `--output`
    extract branch below is untouched (still reads up to MAX_REGION_READ):
    it is unreachable from deep triage, which never passes `extract_to`."""
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
        region = _get_region_at(target_addr, regions)
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
        effective_max_region_read = MAX_REGION_READ if max_region_read is None else max_region_read
        read_size = min(region.RegionSize, effective_max_region_read)
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
        extract_read_truncated=extract_read_truncated)

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


def _execution_status_for(records, diagnostics, search_stats: StringSearchStats = _NO_SEARCH_STATS):
    """MAX_REGION_READ clamping (a self-imposed scan-budget cutoff, at
    either the per-card Section 4 scan level or the whole-run
    --report-string search level) and a per-card --output extract write
    failure are all about whether THIS COMMAND finished its own intended
    work, not about whether the evidence it looked at was complete -- see
    OUTPUT_SCHEMA.md's own three-concepts-separate rule. Distinct from
    coverage.status, which `_build_aggregate_coverage_report` above
    governs instead (a short/failed read is an evidence gap; a deliberate
    policy clamp or a write failure is not)."""
    any_scan_clamped = any(r.string_scan and r.string_scan["clamped"] for r in records)
    any_extract_clamped = any(r.extract_read_clamped for r in records)
    any_extract_failed = any(d.code == "REPORT_EXTRACT_FAILED" for d in diagnostics)
    if (any_scan_clamped or any_extract_clamped or any_extract_failed
            or search_stats.clamped):
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
                         "clamped_regions": search_stats.clamped},
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
        }

        if not private_hits:
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
                              coverage=_combine_with_aggregate(coverages, records, search_stats),
                              execution_status=_execution_status_for(records, diagnostics, search_stats),
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
        "skipped_unreadable_regions": 0, "truncated_regions": 0, "clamped_regions": 0,
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
    and the network-pattern hexdump context is read from each
    ReportIocString's own bounded context_hex, never re-read from `mf`
    (see _collect_triage_card's own note on why that's computed once at
    collect time)."""
    for reason in coverage.reasons:
        print(YELLOW(f"  [~] {reason}"))

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
    if card.extract_read_truncated:
        print(RED(f"  [!] Read came up short of what was requested -- the written artifact "
                  f"is INCOMPLETE (see coverage for detail)"))
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

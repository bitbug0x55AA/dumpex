"""`--process` command -- issue #40's collect/render/command vertical
slice over the frozen contract in
docs/developer/recon_process_sysinfo_handles_contract.md §3.

`collect_process()` runs exactly one collection pass: it builds the
shared process-identity snapshot (dumpex.core.process_info, issue #38),
which itself reads the PEB-reported main image's PE header exactly once
-- this module reuses that same `MainImagePeClaim.pe_facts` for the
standard Import Address Table walk (dumpex.core.pe_utils.parse_iat,
issue #39) rather than re-reading/re-parsing the header a second time.
`render_process_console()` projects only the already-collected
ProcessRecord/CoverageReport -- it never touches `mf` at all (its
signature has no `mf` parameter), matching the contract's "rendering
must use only the collected ProcessRecord, coverage, and diagnostics"
rule (§3.8).

`cmd_process()` is the one call that collects and renders in the usual
command shape; #43 wired it into argparse.

Issue #98 changed the VERBOSE CONSOLE PROJECTION only: the import table
gained column headers and a legend for the slot/target address pair, and
the old `Evidence Matrix` became an `Identity Verification` block that
states one investigator-facing conclusion per identity check instead of
printing the internal claim vocabulary. No record shape, coverage
meaning, limitation code, diagnostic, or exit code moved with it -- the
v2.13 JSON is byte-identical across that change.
"""
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.minidumpfile import MinidumpFile

from dumpex.core.memory import observe_stream, clamped_reader
from dumpex.core.pe_utils import parse_iat
from dumpex.core.process_info import (
    build_process_identity_snapshot, classify_process_create_time,
)
from dumpex.output.coverage import (
    build_coverage_report, observe_source, EvaluationRequirement, SourceRequirement,
    SourceObservation, SourceState, CoverageLimitation, LimitationCode,
)
from dumpex.output.command_result import CommandResult
from dumpex.output.records import (
    ProcessRecord, IatRecord, ImportEntryRecord, ProcessDiagnosticRecord, hex_address,
)
from dumpex.ui.colors import BOLD, console_safe
from dumpex.ui.console_layout import column_width


# ── §3.5.4/§6.1 -- IAT diagnostic `details` keys that carry addresses ────
# dumpex.core.pe_utils.IatDiagnostic.details is built with raw ints (that
# module has no address-formatting convention of its own); this is the
# ONE place those get turned into the contract's fixed-width hex strings
# (§1.3) before they reach the record. Keys not listed here stay whatever
# plain value pe_utils already put there (e.g. table_size, a plain int).
_IAT_DIAGNOSTIC_ADDRESS_KEYS = {
    "IAT_BOUNDS_CHECK_UNAVAILABLE": frozenset({"import_directory_va"}),
    "IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS": frozenset({"table_va", "first_out_of_bounds_slot_va"}),
}


def _format_iat_diagnostic_details(code: str, details: dict) -> dict:
    address_keys = _IAT_DIAGNOSTIC_ADDRESS_KEYS.get(code, frozenset())
    return {k: (hex_address(v) if k in address_keys else v) for k, v in details.items()}


def _select_iat_source_state(image_available: bool, import_present, entry_count: int) -> str:
    """§3.7.4's reference selector, reproduced verbatim: `iat`'s own
    coverage source state is read from `import_directory_present` alone
    once an image was actually available to walk -- `import_present is
    False` short-circuits to "present_empty" on its own, so an
    accompanying `table_present is null` can never pull this down to
    "absent"."""
    if not image_available:
        return "absent"
    if import_present is None:
        return "absent"
    if import_present is False or entry_count == 0:
        return "present_empty"
    return "present"


def _select_console_branch(has_entries: bool, import_directory_present, partial_iat_limitation: bool) -> str:
    """§3.8's reference selector, reproduced verbatim. Every nullable
    boolean is compared with `is True`/`is False`, never bare truthiness
    -- `not import_directory_present` would be True for both False and
    None, which would misreport an undetermined result as a positive "no
    imports" claim."""
    if has_entries is True:
        return "count"
    if import_directory_present is False:
        return "no_imports"
    if import_directory_present is True and has_entries is False and not partial_iat_limitation:
        return "present_empty"
    return "unavailable"


_EMPTY_IAT_RECORD = IatRecord(
    table_present=None, table_va=None, table_size=None,
    import_directory_present=None, import_directory_va=None, import_directory_size=None,
    has_entries=False, dll_count=0, entry_count=0, entries=(), diagnostics=())


def _classify_main_image_state(image_base: "int | None", main_image_pe) -> "str | None":
    """-> one of None/"read_failed"/"short_read"/"pe_invalid"/"ok",
    derived entirely from dumpex.core.process_info's already-built
    MainImagePeClaim (§3.4.4) -- no second read or parse of the main
    image happens here.

      None           -- no normalized image base at all, nothing to check
      "read_failed"  -- an image base exists but MainImagePeClaim.checked
                        is False (nothing was captured there, or the read
                        itself failed)
      "short_read"   -- parse_pe_header()'s own `insufficient_data` flag
                        (dumpex.core.pe_utils, copied onto
                        MainImagePeFacts) says the rejection was a
                        genuine capture-length gap -- some structurally
                        required offset ran past what was captured.
                        Deciding this ALSO on whether the full
                        MAIN_IMAGE_PE_READ_MAX budget was reached would be
                        wrong: MAIN_IMAGE_PE_READ_MAX is dumpex's OWN read
                        budget, not a fact about the image, and a header
                        that is genuinely fully present in the dump but
                        merely structurally LARGER than that budget (e.g.
                        a section table that needs more than 4096 bytes
                        to finish) would then be misreported as PE_INVALID
                        -- a real structural-defect claim -- and silently
                        drop the entire IAT walk for an image with nothing
                        wrong with it. `insufficient_data` alone is the
                        complete, correct signal.
                        Never decided by pattern-matching parse_pe_header()'s
                        free-text `reason`: that string is not a closed
                        vocabulary, and several data-starved rejections
                        (e.g. a DOS header shorter than 0x40 bytes) would
                        otherwise need to be told apart from a
                        DETERMINISTIC rejection reached from bytes that
                        were all present (a genuinely wrong signature at
                        a fully-captured offset) by matching free text --
                        only the structural `insufficient_data` bit does
                        this reliably.
      "pe_invalid"   -- parse_pe_header() rejected the header for a
                        deterministic structural reason (bad signature/
                        Machine/NumberOfSections/Magic) that more data
                        would not have changed -- a genuine structural
                        defect, not a capture gap
      "ok"           -- parse_pe_header() validated the header
    """
    if image_base is None:
        return None
    if not main_image_pe.checked:
        return "read_failed"
    if main_image_pe.valid:
        return "ok"
    if main_image_pe.pe_facts.insufficient_data:
        return "short_read"
    return "pe_invalid"


def collect_process(mf: MinidumpFile, *, verbose: bool = False) -> CommandResult:
    """Pure data, no printing. One collection pass: builds the shared
    process-identity snapshot (which itself reads the PEB-reported main
    image's PE header exactly once) and walks its standard IAT at most
    once, then reduces every source into one CoverageReport. Always
    returns exactly one ProcessRecord, even when every field is null
    (§3: "summary is {'count': 1} -- one record, always emitted")."""
    snapshot = build_process_identity_snapshot(mf)

    pid_available = snapshot.misc_info_claim.pid is not None
    start_time_available = snapshot.misc_info_claim.process_create_time_utc is not None
    image_base_available = snapshot.peb_claim.image_base_address is not None
    command_line_available = snapshot.peb_claim.command_line is not None
    path_available = snapshot.selected_process_path is not None
    available_flags = (pid_available, start_time_available, image_base_available,
                        command_line_available, path_available)
    n_available = sum(1 for f in available_flags if f)

    process_identity_obs = SourceObservation(
        name="process_identity",
        state=(SourceState.PRESENT if n_available else SourceState.ABSENT),
        record_count=(n_available if n_available else None))

    misc_info_obs = observe_stream(
        mf, "misc_info", MINIDUMP_STREAM_TYPE.MiscInfoStream, mf.misc_info,
        [mf.misc_info] if mf.misc_info else [])
    peb_obs = observe_source("peb", present=mf.peb is not None, items=[mf.peb] if mf.peb is not None else [])
    modules_list = list(getattr(getattr(mf, "modules", None), "modules", None) or [])
    modules_obs = observe_stream(
        mf, "modules", MINIDUMP_STREAM_TYPE.ModuleListStream, mf.modules, modules_list)

    completeness_checks = []

    completeness_checks.append(SourceRequirement(
        source="misc_info", absent_code=LimitationCode.PROCESS_MISC_INFO_UNAVAILABLE))
    if misc_info_obs.state == SourceState.PRESENT:
        if snapshot.misc_info_claim.pid is None:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.PROCESS_PID_UNAVAILABLE, source="misc_info"))
        if snapshot.misc_info_claim.process_create_time_utc is None:
            raw_time = getattr(mf.misc_info, "ProcessCreateTime", None)
            if classify_process_create_time(raw_time) == "unset":
                completeness_checks.append(CoverageLimitation(
                    code=LimitationCode.PROCESS_START_TIME_UNSET, source="misc_info"))
            else:
                completeness_checks.append(CoverageLimitation(
                    code=LimitationCode.PROCESS_START_TIME_INVALID, source="misc_info"))

    completeness_checks.append(SourceRequirement(
        source="peb", absent_code=LimitationCode.PROCESS_PEB_UNAVAILABLE))
    fallback_was_needed = False
    if peb_obs.state == SourceState.PRESENT:
        if snapshot.peb_claim.command_line is None:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.PROCESS_COMMAND_LINE_UNAVAILABLE, source="peb"))
        if snapshot.peb_claim.image_base_address is None:
            if snapshot.peb_claim.raw_image_base_address is not None:
                completeness_checks.append(CoverageLimitation(
                    code=LimitationCode.PROCESS_IMAGE_BASE_INVALID, source="peb"))
            else:
                completeness_checks.append(CoverageLimitation(
                    code=LimitationCode.PROCESS_IMAGE_BASE_UNAVAILABLE, source="peb"))
        if snapshot.selected_process_path is None:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.PROCESS_PATH_UNAVAILABLE, source="peb"))
        peb_path_unavailable = snapshot.peb_claim.image_path is None
        fallback_was_needed = peb_path_unavailable and snapshot.peb_claim.image_base_address is not None
        if fallback_was_needed:
            completeness_checks.append(SourceRequirement(
                source="modules", absent_code=LimitationCode.PROCESS_MODULE_FALLBACK_UNAVAILABLE))

    image_base = snapshot.peb_claim.image_base_address
    main_image_pe = snapshot.main_image_pe
    main_image_state = _classify_main_image_state(image_base, main_image_pe)

    if main_image_state == "read_failed":
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PROCESS_MAIN_IMAGE_READ_FAILED, source="main_image"))
    elif main_image_state == "short_read":
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PROCESS_MAIN_IMAGE_SHORT_READ, source="main_image"))
    elif main_image_state == "pe_invalid":
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PROCESS_MAIN_IMAGE_PE_INVALID, source="main_image"))

    iat_result = None
    if main_image_state in ("ok", "short_read"):
        facts = main_image_pe.pe_facts
        # parse_iat() only ever reads these three keys via dict.get() --
        # reconstructing this small dict from the already-hashable,
        # already-immutable MainImagePeFacts is cheap and keeps parse_iat()'s
        # own (issue #39, frozen) dict-shaped signature untouched.
        pe_for_iat = {
            "data_directories": facts.data_directories,
            "declared_directory_count": facts.declared_directory_count,
            "is_pe32_plus": facts.is_pe32_plus,
        }
        iat_result = parse_iat(clamped_reader(mf), image_base, pe_for_iat)

        if iat_result.directory_table_incomplete:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE, source="iat",
                affected_count=iat_result.directory_incomplete_affected_count))
        if iat_result.directory_read_failed:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.IAT_DIRECTORY_READ_FAILED, source="iat"))
        if iat_result.directory_short_read:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.IAT_DIRECTORY_SHORT_READ, source="iat"))
        if iat_result.descriptor_read_failed_count:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.IAT_DESCRIPTOR_READ_FAILED, source="iat",
                affected_count=iat_result.descriptor_read_failed_count))
        if iat_result.descriptor_short_read_count:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.IAT_DESCRIPTOR_SHORT_READ, source="iat",
                affected_count=iat_result.descriptor_short_read_count))
        if iat_result.thunk_read_failed_count:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.IAT_THUNK_READ_FAILED, source="iat",
                affected_count=iat_result.thunk_read_failed_count))
        if iat_result.thunk_short_read_count:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.IAT_THUNK_SHORT_READ, source="iat",
                affected_count=iat_result.thunk_short_read_count))
        if iat_result.name_read_failed_count:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.IAT_NAME_READ_FAILED, source="iat",
                affected_count=iat_result.name_read_failed_count))
        if iat_result.unterminated_table:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.IAT_UNTERMINATED_TABLE, source="iat"))
        if iat_result.cycle_detected:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.IAT_CYCLE_DETECTED, source="iat"))
        if iat_result.bounds_exceeded:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.IAT_BOUNDS_EXCEEDED, source="iat"))
        if iat_result.truncation:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.IAT_ENTRIES_TRUNCATED, source="iat",
                scope=iat_result.truncation.scope,
                budget_limit=iat_result.truncation.budget_limit,
                budget_consumed=iat_result.truncation.budget_consumed))

    if image_base is None or main_image_state == "read_failed":
        main_image_obs = SourceObservation(name="main_image", state=SourceState.ABSENT)
    elif main_image_state == "ok":
        main_image_obs = SourceObservation(name="main_image", state=SourceState.PRESENT, record_count=1)
    else:   # "short_read" or "pe_invalid" -- attempted, no valid image found
        main_image_obs = SourceObservation(name="main_image", state=SourceState.PRESENT_EMPTY, record_count=0)

    iat_image_available = iat_result is not None
    iat_import_present = iat_result.import_directory_present if iat_result else None
    iat_entry_count = iat_result.entry_count if iat_result else 0
    iat_state = _select_iat_source_state(iat_image_available, iat_import_present, iat_entry_count)
    if iat_state == "absent":
        iat_obs = SourceObservation(name="iat", state=SourceState.ABSENT)
    elif iat_state == "present_empty":
        iat_obs = SourceObservation(name="iat", state=SourceState.PRESENT_EMPTY, record_count=0)
    else:
        iat_obs = SourceObservation(name="iat", state=SourceState.PRESENT, record_count=iat_entry_count)

    sources = {
        "process_identity": process_identity_obs,
        "misc_info": misc_info_obs,
        "peb": peb_obs,
        "modules": modules_obs,
        "main_image": main_image_obs,
        "iat": iat_obs,
    }

    coverage = build_coverage_report(
        sources,
        evaluation_sources=EvaluationRequirement(
            sources=("process_identity",), all_absent_code=LimitationCode.PROCESS_SOURCES_ABSENT),
        completeness_checks=completeness_checks,
        retain_completeness_checks_when_not_evaluated=True)

    record = _build_process_record(snapshot, iat_result, mf, verbose)
    return CommandResult(kind="process", records=[record], coverage=coverage, summary={"count": 1})


def _module_reference_dict(ref) -> "dict | None":
    if ref is None:
        return None
    return {"base_address": hex_address(ref.base_address), "name": ref.name, "path": ref.path}


def _build_identity_evidence(snapshot) -> dict:
    """Projects `snapshot` (dumpex.core.process_info.ProcessIdentitySnapshot)
    into §3.4's wire shape -- including `main_image_pe`, which is copied
    directly from `snapshot.main_image_pe` rather than rebuilt from a
    second read/parse, so the JSON can never disagree with the single
    read `collect_process()` actually performed."""
    mi = snapshot.misc_info_claim
    peb = snapshot.peb_claim
    mod = snapshot.module_claim
    main_pe = snapshot.main_image_pe

    diagnostics = tuple(
        ProcessDiagnosticRecord(code=d.code, severity=d.severity, message=d.message,
                                 affected_count=d.affected_count, details=dict(d.details))
        for d in snapshot.diagnostics)

    return {
        "misc_info_claim": {
            "pid": mi.pid,
            "process_create_time_utc": mi.process_create_time_utc,
            "raw_pid": mi.raw_pid,
            "raw_process_create_time": mi.raw_process_create_time,
        },
        "peb_claim": {
            "image_base_address": hex_address(peb.image_base_address),
            "image_path": peb.image_path,
            "name": peb.name,
            "raw_image_base_address": peb.raw_image_base_address,
            "raw_image_path": peb.raw_image_path,
            "raw_command_line": peb.raw_command_line,
        },
        "module_claim": {
            "match_state": mod.match_state,
            "base_address": hex_address(mod.base_address),
            "name": mod.name,
            "path": mod.path,
            "name_matched_candidate": _module_reference_dict(mod.name_matched_candidate),
            "name_matched_candidate_ambiguous": mod.name_matched_candidate_ambiguous,
        },
        "main_image_pe": {
            "checked": main_pe.checked,
            "valid": main_pe.valid,
            "reason": main_pe.reason,
        },
        "selected_path_source": snapshot.selected_path_source,
        "diagnostics": [d.to_dict() for d in diagnostics],
    }


def _build_iat_record(iat_result) -> IatRecord:
    if iat_result is None:
        return _EMPTY_IAT_RECORD
    entries = tuple(
        ImportEntryRecord(
            dll=e.dll, import_by=e.import_by, symbol=e.symbol, ordinal=e.ordinal,
            iat_slot_va=hex_address(e.iat_slot_va), resolved_target_va=hex_address(e.resolved_target_va),
            slot_in_bounds=e.slot_in_bounds)
        for e in iat_result.entries)
    diagnostics = tuple(
        ProcessDiagnosticRecord(
            code=d.code, severity=d.severity, message=d.message, affected_count=d.affected_count,
            details=_format_iat_diagnostic_details(d.code, d.details))
        for d in iat_result.diagnostics)
    return IatRecord(
        table_present=iat_result.table_present,
        table_va=hex_address(iat_result.table_va),
        table_size=iat_result.table_size,
        import_directory_present=iat_result.import_directory_present,
        import_directory_va=hex_address(iat_result.import_directory_va),
        import_directory_size=iat_result.import_directory_size,
        has_entries=iat_result.has_entries,
        dll_count=iat_result.dll_count,
        entry_count=iat_result.entry_count,
        entries=entries,
        diagnostics=diagnostics)


def _build_peb_extended(mf: MinidumpFile) -> dict:
    """§3.6: the seven retired `--peb`-only fields, retained under
    `--process --verbose`. All seven are null when the PEB is
    unavailable; presence of the KEY depends only on the flag (handled by
    the caller), never on this dict's own contents.

    Direct attribute access, matching v2.12's now-retired
    dumpex.commands.peb.collect_peb() convention for the same seven
    fields -- a real PEB object is guaranteed to carry every one of them
    (they are not conditionally populated the way stream-backed evidence
    is), so a rename/removal upstream should raise loudly here rather
    than silently rendering every field null and indistinguishable from
    "PEB unavailable"."""
    peb = mf.peb
    if peb is None:
        return {
            "peb_address": None, "being_debugged": None, "window_title": None,
            "dll_path": None, "standard_input": None, "standard_output": None,
            "standard_error": None,
        }
    return {
        "peb_address": hex_address(peb.address),
        "being_debugged": peb.being_debugged,
        "window_title": peb.window_title or None,
        "dll_path": peb.dll_path or None,
        "standard_input": hex_address(peb.standard_input) if peb.standard_input is not None else None,
        "standard_output": hex_address(peb.standard_output) if peb.standard_output is not None else None,
        "standard_error": hex_address(peb.standard_error) if peb.standard_error is not None else None,
    }


def _build_process_record(snapshot, iat_result, mf, verbose: bool) -> ProcessRecord:
    return ProcessRecord(
        process_name=snapshot.selected_process_name,
        pid=snapshot.pid,
        process_path=snapshot.selected_process_path,
        command_line=snapshot.command_line,
        process_start_utc=snapshot.process_start_utc,
        image_base_address=hex_address(snapshot.image_base_address),
        iat=_build_iat_record(iat_result),
        identity_evidence=_build_identity_evidence(snapshot),
        peb_extended=(_build_peb_extended(mf) if verbose else None))


def _print_diagnostics(diagnostics) -> None:
    """Shared by both diagnostic arrays on the console (§3.5.5's
    iat.diagnostics and §3.4.4's identity_evidence.diagnostics) -- takes
    an iterable of the ONE common dict shape ({"severity", "message",
    ...}) so the two call sites never diverge on rendering, regardless
    of which typed/untyped form each array happens to be stored in on
    the record."""
    for d in diagnostics:
        prefix = "[!]" if d["severity"] == "warning" else "[i]"
        print(f"    {prefix} {d['message']}")


def render_process_console(record: ProcessRecord, coverage, *, verbose: bool = False) -> None:
    """Rendering uses only the already-collected ProcessRecord/coverage --
    this function has no `mf` parameter at all, so it is structurally
    incapable of re-reading or re-computing evidence (§3.8's own rule)."""
    print(f"\n{BOLD('═══ PROCESS ═══')}")
    for reason in coverage.reasons:
        print(f"  [~] {reason}")

    pid_str = f"{record.pid} (0x{record.pid:x})" if record.pid is not None else "(unknown)"
    print()
    # Name/path/command line are PEB (or ModuleListStream) strings -- dump
    # bytes, therefore attacker-controlled. Escaped for the console only;
    # the record and --json keep the exact decoded values.
    print(f"  {'Process Name':<22} {console_safe(record.process_name) or '(unknown)'}")
    print(f"  {'PID':<22} {pid_str}")
    print(f"  {'Path':<22} {console_safe(record.process_path) or '(unknown)'}")
    print(f"  {'Command Line':<22} {console_safe(record.command_line) or '(unknown)'}")
    print(f"  {'Start Time (UTC)':<22} {record.process_start_utc or '(unknown)'}")
    print(f"  {'Image Base':<22} {record.image_base_address or '(unknown)'}")

    print(f"\n  {BOLD('Import Address Table')}")
    partial_iat_limitation = any(lim.code.value.startswith("IAT_") for lim in coverage.limitations)
    branch = _select_console_branch(
        record.iat.has_entries, record.iat.import_directory_present, partial_iat_limitation)
    if branch == "count":
        print(f"    {record.iat.entry_count} import(s) across {record.iat.dll_count} DLL(s)")
    elif branch == "no_imports":
        print("    (none -- this image declares no imports)")
    elif branch == "present_empty":
        print("    (none -- import directory present, zero entries)")
    else:
        print("    (unavailable -- see coverage below)")

    # IAT diagnostics (§3.5.5) are not limitations -- they never appear in
    # coverage.reasons -- but a warning-severity one (an out-of-bounds
    # IAT slot) is exactly the kind of actionable anomaly the default
    # console is supposed to surface, mirroring how the Identity block
    # below prints identity_evidence.diagnostics unconditionally.
    _print_diagnostics(d.to_dict() for d in record.iat.diagnostics)

    if verbose and record.iat.entries:
        _render_iat_entries(record.iat.entries)

    print(f"\n  {BOLD('Identity')}")
    _print_diagnostics(record.identity_evidence.get("diagnostics") or [])

    if verbose:
        _render_identity_verification(record)
        if record.peb_extended is not None:
            _render_extended_peb(record.peb_extended)


# ── #98: verbose IAT table ──────────────────────────────────────────────
# The pre-#98 rendering was `<address_1> -> <address_2>` with no headers
# and no legend, which is ambiguous in exactly the way that matters: the
# two addresses are not interchangeable, and reading them the wrong way
# round inverts the question ("where is the pointer stored" vs "where
# does it point"). The headers and the one legend line below are the
# whole fix; no new evidence is read, and the v2.13 record shape is
# untouched.
# Sized to the widest value each column actually holds in this render,
# floored at the minimum and capped above -- the same
# dumpex.ui.console_layout.column_width() rule the --handles table uses,
# for the same reason: a fixed minimum is not truncation, so one long DLL
# or API name shifted that ONE row's remaining columns right and left the
# table ragged below its own header. `dll` and `symbol` come out of the
# dumped image and are attacker-controlled, so the caps stop one hostile
# name from padding every row.
_IAT_DLL_COLUMN_MIN_WIDTH = 24
_IAT_DLL_COLUMN_MAX_WIDTH = 48
_IAT_SYMBOL_COLUMN_MIN_WIDTH = 28
_IAT_SYMBOL_COLUMN_MAX_WIDTH = 64
# Slot/target are hex_address()'s fixed 18 characters (§1.3) or
# "(unknown)"; the header itself is the widest thing in the column.
_IAT_ADDRESS_COLUMN_MIN_WIDTH = 20

# Pre-wrapped rather than wrapped at print time: dumpex's own text, at a
# fixed width, so the block is byte-identical on every terminal.
_IAT_LEGEND_LINES = (
    "Each row reads IAT Slot VA -> Resolved Target VA.",
    "The slot is the address where the import pointer is stored; the target is the",
    "address stored in that slot in the captured process memory.",
)

# `slot_in_bounds is False` is an OBSERVATION (§3.5.5 files it as a
# diagnostic, never a limitation), so it is surfaced as a per-row marker
# with a footnote rather than as a verdict, a coverage failure, or a
# claim about hooking -- a target inside another module is ordinary for
# forwarded exports and API-set resolution.
_IAT_OUT_OF_BOUNDS_MARKER = " *"
_IAT_OUT_OF_BOUNDS_NOTE_LINES = (
    "* the IAT slot lies outside the recorded import directory bounds -- an",
    "  observation about this dump's directory framing, not a verdict about the import",
)


def _import_symbol_text(entry: ImportEntryRecord) -> str:
    """§3.5.3's three import states, each kept distinct: a named import,
    an ordinal-only import, and one whose name/ordinal could not be
    recovered at all (OriginalFirstThunk already overwritten). Read from
    `import_by`, never inferred from whether `symbol` happens to be
    null."""
    if entry.import_by == "name":
        return entry.symbol or "(unknown)"
    if entry.import_by == "ordinal":
        return f"ordinal #{entry.ordinal}"
    return "(unavailable)"


def _render_iat_entries(entries) -> None:
    """`dll`/`symbol` are strings read out of the dumped image, so they
    are attacker-controlled exactly like a handle's object name -- both
    go through console_safe() here, while the record and --json keep the
    exact decoded value."""
    print()
    for line in _IAT_LEGEND_LINES:
        print(f"    {line}")
    print()

    # Cells first, widths second, printing third -- the widths are
    # measured on the ESCAPED strings that actually reach the terminal,
    # since console_safe() can expand a name past its raw length.
    rows = [(console_safe(e.dll) or "(unknown)",
             console_safe(_import_symbol_text(e)),
             e.iat_slot_va or "(unknown)",
             e.resolved_target_va or "(unknown)",
             _IAT_OUT_OF_BOUNDS_MARKER if e.slot_in_bounds is False else "")
            for e in entries]
    dll_w = column_width("DLL", [r[0] for r in rows],
                           minimum=_IAT_DLL_COLUMN_MIN_WIDTH, cap=_IAT_DLL_COLUMN_MAX_WIDTH)
    symbol_w = column_width("Imported API", [r[1] for r in rows],
                              minimum=_IAT_SYMBOL_COLUMN_MIN_WIDTH,
                              cap=_IAT_SYMBOL_COLUMN_MAX_WIDTH)
    slot_w = column_width("IAT Slot VA", [r[2] for r in rows],
                            minimum=_IAT_ADDRESS_COLUMN_MIN_WIDTH)

    # `Resolved Target VA` is the last column and is never padded --
    # padding it would only add invisible trailing whitespace (and would
    # separate the out-of-bounds marker from the value it marks).
    print(f"    {'DLL':<{dll_w}}  {'Imported API':<{symbol_w}}  "
          f"{'IAT Slot VA':<{slot_w}}  Resolved Target VA")
    for dll_text, symbol_text, slot_va, target_va, marker in rows:
        print(f"    {dll_text:<{dll_w}}  {symbol_text:<{symbol_w}}  "
              f"{slot_va:<{slot_w}}  {target_va}{marker}")
    if any(row[4] for row in rows):
        for line in _IAT_OUT_OF_BOUNDS_NOTE_LINES:
            print(f"    {line}")


# ── #98: Identity Verification (was "Evidence Matrix") ──────────────────
# The matrix printed the internal claim vocabulary (`peb`, `resolved`,
# `unregistered`, `ambiguous=False`) in fixed-width columns and left the
# reader to translate it. Worse, its `Selected` column printed the SOURCE
# NAME ("peb") where a reader expects the selected VALUE. This block
# leads with the selected value and its provenance, then states one
# investigator-facing conclusion per check.
#
# Every check is an OBSERVATION. A conflict is rendered as a conflict and
# never as a maliciousness verdict, never as a command failure, and never
# as a `peb_trusted` boolean -- disagreement between the PEB and
# ModuleListStream has ordinary benign causes, and the coverage status,
# the limitation codes and the exit code are all unchanged by anything
# printed here.
_CHECK_OK = "[OK]"
_CHECK_CONFLICT = "[!!]"
_CHECK_UNAVAILABLE = "[--]"

# Display names for §3.4's `selected_path_source`, so this block never
# prints an internal source key at an analyst.
_PATH_SOURCE_DISPLAY = {
    "peb": "PEB (ProcessParameters.ImagePathName)",
    "module": "ModuleListStream (module registered at the PEB image base)",
}


def _print_check(state: str, text: str, detail: "str | None" = None) -> None:
    print(f"    {state} {text}")
    if detail:
        print(f"         {detail}")


def _module_registration_check(mod_claim: dict) -> tuple:
    """§3.4.3's three `match_state` values, each turned into the question
    an analyst is actually asking: is the image the PEB points at
    registered in the loader's own module list?"""
    state = mod_claim["match_state"]
    if state == "resolved":
        return (_CHECK_OK, "PEB image base is registered in ModuleList",
                f"{mod_claim['base_address']} -> "
                f"{console_safe(mod_claim['name']) or '(unnamed)'}")
    if state == "unregistered":
        candidate = mod_claim["name_matched_candidate"]
        detail = None
        if candidate is not None:
            detail = (f"a module named {console_safe(candidate['name']) or '(unnamed)'} is "
                      f"registered at {candidate['base_address']} instead")
        return (_CHECK_CONFLICT, "no module is registered at the PEB image base", detail)
    return (_CHECK_UNAVAILABLE,
            "PEB image base could not be compared with ModuleList",
            "ModuleListStream is absent or failed, or no image base normalized")


def _name_agreement_check(peb_claim: dict, mod_claim: dict) -> tuple:
    """Compared case-insensitively: Windows filesystem and module names
    are case-insensitive, so a case difference alone is not a conflict an
    analyst should be sent to chase."""
    peb_name, mod_name = peb_claim["name"], mod_claim["name"]
    if peb_name is None or mod_name is None:
        return (_CHECK_UNAVAILABLE,
                "PEB and ModuleList process names could not be compared",
                "one of the two names was not recovered")
    if peb_name.casefold() == mod_name.casefold():
        return (_CHECK_OK, "PEB and ModuleList process names agree", None)
    return (_CHECK_CONFLICT, "PEB and ModuleList process names differ",
            f"PEB: {console_safe(peb_name)} | ModuleList: {console_safe(mod_name)}")


def _pe_header_check(main_pe: dict) -> tuple:
    """`checked`/`valid`/`reason` exactly as §3.4.4 defines them --
    `checked is False` is "the question could not be asked", which is a
    different answer from "asked, and the header is not a PE"."""
    if not main_pe["checked"]:
        return (_CHECK_UNAVAILABLE,
                "the PEB image base was not checked for a PE header",
                "no image base normalized, or nothing was captured there")
    if main_pe["valid"]:
        return (_CHECK_OK, "a valid PE header was found at the PEB image base", None)
    return (_CHECK_CONFLICT, "no valid PE header at the PEB image base",
            console_safe(main_pe["reason"]) or "(no reason recorded)")


def _corroboration_check(mod_claim: dict) -> tuple:
    """The ambiguity leg of §3.4.3: more than one module sharing the
    selected name means only the first was reported, which an analyst has
    to know before treating either of the checks above as decisive."""
    if mod_claim["name_matched_candidate_ambiguous"]:
        return (_CHECK_CONFLICT,
                "more than one module shares this process name; only the first is reported",
                "compare --modules for every module carrying this name")
    if mod_claim["match_state"] == "unavailable":
        return (_CHECK_UNAVAILABLE,
                "no ModuleList corroboration was available for this identity", None)
    return (_CHECK_OK, "no competing module shares this process name", None)


def _render_identity_verification(record: ProcessRecord) -> None:
    """Leads with the selected values and where they came from, then one
    line per independent check. The raw per-source claims stay available
    underneath (bounded, three lines), so nothing the old matrix showed
    is lost -- those values simply stop being the first thing a reader
    has to decode.

    Every dump-derived string here -- both paths, both names, and the PE
    rejection reason -- goes through console_safe(), the same projection
    the default block above already used for the same values."""
    ev = record.identity_evidence
    peb_claim = ev["peb_claim"]
    mod_claim = ev["module_claim"]
    main_pe = ev["main_image_pe"]
    source = ev["selected_path_source"]

    print(f"\n  {BOLD('Identity Verification')}                            [--verbose only]")
    print(f"    {'Selected path':<16} {console_safe(record.process_path) or '(unknown)'}")
    print(f"    {'Selected name':<16} {console_safe(record.process_name) or '(unknown)'}")
    print(f"    {'Source':<16} {_PATH_SOURCE_DISPLAY.get(source, '(no path source selected)')}")
    print(f"    {'Image base':<16} {record.image_base_address or '(unknown)'} (source: PEB)")
    print()
    for check in (_module_registration_check(mod_claim),
                  _name_agreement_check(peb_claim, mod_claim),
                  _pe_header_check(main_pe),
                  _corroboration_check(mod_claim)):
        _print_check(*check)

    print(f"\n    {'Raw claims':<16} {'PEB':<32} ModuleList")
    print(f"    {'path':<16} {(console_safe(peb_claim['image_path']) or '(none)'):<32} "
          f"{console_safe(mod_claim['path']) or '(none)'}")
    print(f"    {'name':<16} {(console_safe(peb_claim['name']) or '(none)'):<32} "
          f"{console_safe(mod_claim['name']) or '(none)'}")
    print(f"    {'image base':<16} {(peb_claim['image_base_address'] or '(none)'):<32} "
          f"{mod_claim['base_address'] or '(none)'} ({mod_claim['match_state']})")


def _render_extended_peb(peb_extended: dict) -> None:
    print(f"\n  {BOLD('Extended PEB')}")
    print(f"    {'PEB Address':<18} {peb_extended['peb_address'] or '(unknown)'}")
    print(f"    {'BeingDebugged':<18} {peb_extended['being_debugged']}")
    # WindowTitle/DllPath are PEB strings -- dump bytes, therefore
    # attacker-controlled, exactly like the path/command line the default
    # block above already escapes (#98). The record and --json keep the
    # exact decoded value.
    print(f"    {'WindowTitle':<18} {console_safe(peb_extended['window_title']) or '(none)'}")
    print(f"    {'DllPath':<18} {console_safe(peb_extended['dll_path']) or '(none)'}")
    print(f"    {'StandardInput':<18} {peb_extended['standard_input'] or '(unknown)'}")
    print(f"    {'StandardOutput':<18} {peb_extended['standard_output'] or '(unknown)'}")
    print(f"    {'StandardError':<18} {peb_extended['standard_error'] or '(unknown)'}")


def cmd_process(mf: MinidumpFile, *, verbose: bool = False) -> CommandResult:
    result = collect_process(mf, verbose=verbose)
    render_process_console(result.records[0], result.coverage, verbose=verbose)
    return result

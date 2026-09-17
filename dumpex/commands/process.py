"""Collect and render process identity evidence from the minidump.

Collection builds one attributed identity snapshot and reuses its main-image PE
facts for Import Address Table analysis. Conflicting MiscInfo, PEB, and module
claims remain independently visible. Rendering consumes only the collected
record, coverage, and diagnostics.
"""
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.minidumpfile import MinidumpFile

from dumpex.core.memory import (
    observe_stream, clamped_reader, get_modules, has_stream_directory, stream_failure,
)
from dumpex.core.pe_correlation import ModuleListImage, correlate_main_image
from dumpex.core.pe_profile import (
    PEB_SOURCE_IDENTITY, ModuleIdentity, PeStage, SourceKind, collect_pe_image_profile,
)
from dumpex.core.pe_utils import parse_iat
from dumpex.core.process_info import (
    MAIN_IMAGE_PE_READ_MAX, build_process_identity_snapshot, classify_process_create_time,
)
from dumpex.core.va_range import (
    VirtualRange, enumerate_captured_regions, enumerate_captured_segments, slice_captured,
)
from dumpex.output.coverage import (
    build_coverage_report, observe_source, EvaluationRequirement, SourceRequirement,
    SourceObservation, SourceState, CoverageLimitation, LimitationCode,
)
from dumpex.output.command_result import CommandResult
from dumpex.output.records import (
    ProcessRecord, IatRecord, ImportEntryRecord, ProcessDiagnosticRecord,
    PeObservationRecord, ProcessPeAcquisitionRecord, ProcessPeDirectoryRecord,
    ProcessPeEntryPointRecord, ProcessPeRecord, ProcessPeSectionRecord, hex_address,
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


# ── §3.10 -- the canonical main-image PE profile ────────────────────────
# One immutable dumpex.core.pe_profile.PeImageProfile at the PEB-reported
# image base, and one dumpex.core.pe_correlation.MainImageCorrelation over
# it, built here and consumed once. Nothing downstream re-reads a byte:
# the projection below and the console take every value from these two
# objects, so --process, --report, and a later PEB consumer cannot
# disagree about the same dump.
#
# This evidence is optional and self-contained. It adds no coverage
# source, no limitation code, and no exit-code path: an image whose header
# is unreadable leaves `pe_image.collected` false and every process
# identity fact beside it exactly as the MiscInfo/PEB/ModuleList claims
# established it. The legacy `identity_evidence.main_image_pe`
# checked/valid/reason triple keeps its own meaning and its own
# PROCESS_MAIN_IMAGE_* limitations (§3.4.4), which stay the sole authority
# over coverage and the exit code.


def _stream_table_state(mf: MinidumpFile, stream_type, parsed) -> "str | None":
    """`"absent"` or `"failed"` when the dump supplies no usable table for
    `stream_type`, `None` when there is one to walk.

    An enumeration cannot answer this on its own: a stream that is not in
    the dump and a stream that parsed and carries no entries both reduce
    to an empty list, and an empty table answers a question ("nothing in
    this table covers that address") that an absent one cannot. The
    dump's own directory is what tells them apart, exactly as §2.4
    already separates an uncaptured stream from a captured one that
    failed."""
    if stream_failure(mf, stream_type) is not None:
        return "failed"
    if parsed is not None:
        return None
    # Nothing parsed. The directory says whether there was anything to
    # parse: a stream the dump never carried is absent, and one it
    # carried that yielded nothing is a failure whatever the loader
    # recorded.
    return "failed" if has_stream_directory(mf, stream_type) else "absent"


def _captured_enumeration(mf: MinidumpFile, stream_types, parsed, enumerate_table):
    """`(enumeration, state)` for one of the dump's own tables, where
    `state` is one of §3.10.5's five and the enumeration is `None` for
    every state in which the table establishes nothing.

    `None` is what the correlation layer already means by "not usable
    evidence": every observation that needed the table is `unavailable`
    and every per-address context drawn from it is withheld. Handing it an
    empty table instead would turn "there is no table" into "the table
    covers nothing", which is a claim the dump never made. `state` is what
    keeps the cause attributable either way."""
    states = [state for stream_type, obj in zip(stream_types, parsed)
              if (state := _stream_table_state(mf, stream_type, obj)) is not None]
    # A segment table has two candidate streams, and one usable stream is
    # enough: only a table with no usable stream at all is unusable, and
    # then a recorded failure outranks a plain absence.
    if len(states) == len(stream_types):
        return None, ("failed" if "failed" in states else "absent")
    try:
        enumeration = enumerate_table()
    except Exception:
        return None, "unreadable"
    return enumeration, ("lossy" if enumeration.skipped else "enumerated")


def _capture_for(image_base: int, segments, segment_table: str, read_bytes: int):
    """The `CapturedSlice` the profile may resolve its byte facts against,
    or `None` when no table in hand can bound the run already read.

    A capture slice is a ceiling: the collector decodes nothing past
    `captured_bytes`. Handing it a slice built from a table dumpex could
    only partly represent would clamp the acquisition to less than the
    bytes the snapshot already read and parsed -- the profile would report
    a truncation dumpex imposed on itself, contradict
    `identity_evidence.main_image_pe` about the same run, and blame the
    image for it. So a table that is not whole supplies no slice at all,
    and `captured_bytes` is `null`: the provenance was not established,
    which is the one thing that is true.

    The final check is the invariant itself. A slice that accounts for
    fewer bytes than the read returned describes a different dump from the
    one the run came out of, whatever its `skipped` count says, so it is
    refused the same way."""
    if segments is None or segment_table != "enumerated":
        return None
    try:
        capture = slice_captured(VirtualRange(image_base, MAIN_IMAGE_PE_READ_MAX),
                                 segments.views)
    except Exception:
        return None
    if capture.captured_bytes < read_bytes:
        return None
    return capture


def _header_reader(base: int, data: bytes):
    """A `read(addr, size)` callback over one already-read header run.

    The snapshot's own main-image read is the only read of these bytes
    this command performs: the canonical profile decodes that same run
    rather than issuing a second read at the same base, so the two
    parsers can never disagree about what was there and the dump is
    touched once. A request past the run returns nothing, exactly as a
    reader reaching the end of the contiguous captured segments does."""
    def read(addr, size):
        offset = addr - base
        if offset < 0 or size <= 0:
            return b""
        return data[offset:offset + size]
    return read


def _collect_main_image_pe(mf: MinidumpFile, image_base: "int | None", main_image_pe,
                            module_match: str, peb_image_path: "str | None") -> ProcessPeRecord:
    """Build the main image's profile and correlation once, and project
    them into §3.10's record.

    `image_base` is the normalized PEB image base -- the only base a main
    image has (§3.3.4), so no base is no image to profile.
    `main_image_pe` is the snapshot's already-built
    dumpex.core.process_info.MainImagePeClaim, whose `header_bytes` are
    the run this profile is decoded from: `checked is False` is a base
    with nothing readable at it, which is no profile rather than an empty
    one.

    `module_match` is §3.4.3's `module_claim.match_state`, passed in
    rather than re-derived. "Is a module registered at this image base"
    is one question with one answer, and the identity boundary already
    answered it against the stream's own availability: a ModuleListStream
    that parsed and legitimately holds zero modules confirms that nothing
    is registered there ("unregistered"), which is a finding an analyst
    acts on -- deriving it a second time from whether the module list is
    non-empty would report that confirmed absence as "unavailable" and
    contradict `identity_evidence` inside one record."""
    if image_base is None:
        return ProcessPeRecord.uncollected("no_image_base")
    if not main_image_pe.checked:
        return ProcessPeRecord.uncollected("header_unreadable")

    segments, segment_table = _captured_enumeration(
        mf,
        (MINIDUMP_STREAM_TYPE.Memory64ListStream, MINIDUMP_STREAM_TYPE.MemoryListStream),
        (mf.memory_segments_64, mf.memory_segments),
        lambda: enumerate_captured_segments(mf))
    regions, region_table = _captured_enumeration(
        mf,
        (MINIDUMP_STREAM_TYPE.MemoryInfoListStream,),
        (mf.memory_info,),
        lambda: enumerate_captured_regions(mf))

    # The profile asks for exactly the span the snapshot's own read asked
    # for. Requesting a longer one would make the retained run look like a
    # short read of a longer request, which is a read failure this command
    # did not have.
    header_bytes = main_image_pe.header_bytes
    capture = _capture_for(image_base, segments, segment_table, len(header_bytes))
    try:
        profile = collect_pe_image_profile(
            _header_reader(image_base, header_bytes),
            image_base,
            source_kind=SourceKind.PEB_IMAGE_BASE,
            source_identity=PEB_SOURCE_IDENTITY,
            module_identity=ModuleIdentity.of(peb_image_path, "path"),
            requested_bytes=MAIN_IMAGE_PE_READ_MAX,
            capture=capture,
            requested_stage=PeStage.SECTIONS)
    except Exception:
        # The collector never raises for hostile or truncated image bytes;
        # only a caller error does. That is a defect in dumpex, and naming
        # it as one keeps it out of the two tokens that are claims about
        # the dump.
        return ProcessPeRecord.uncollected("collection_failed")

    try:
        # The loader's own record for this image, when one is registered
        # at exactly this base: the second attributable source the size,
        # timestamp and checksum observations compare against.
        module_list_image = ModuleListImage.at_base(get_modules(mf), profile.actual_base)
        correlation = correlate_main_image(
            profile, regions=regions, segments=segments,
            module_list_image=module_list_image)
    except Exception:
        # Same boundary, same reading: the correlation layer never raises
        # over established facts. `correlated` is what says the layer did
        # not run, so an empty tally can never be read as a clean image.
        correlation = None

    return _project_main_image_pe(profile, correlation, module_match,
                                  segment_table=segment_table, region_table=region_table)


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

    pe_record = _collect_main_image_pe(mf, image_base, main_image_pe,
                                       snapshot.module_claim.match_state,
                                       snapshot.peb_claim.image_path)

    record = _build_process_record(snapshot, iat_result, pe_record, mf, verbose)
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


def _state_value(state) -> "str | None":
    """One ComponentState (or `None`) as its wire token. `None` stays
    `None`: a component outside the requested stage was never asked
    about, which is not the same answer as one that came back
    `unavailable`."""
    return None if state is None else state.value


def _pe_section_records(profile, correlation) -> tuple:
    """The decoded section table, in section-table order. The header's own
    fields come from the profile; the mapped range, capture state, and
    live protections are the correlation's, and stay null when no
    correlation was produced."""
    correlated = {c.section_index: c for c in correlation.sections} if correlation else {}
    records = []
    for section in profile.sections:
        link = correlated.get(section.section_index)
        mapped = link.mapped_range if link is not None else None
        records.append(ProcessPeSectionRecord(
            section_index=section.section_index,
            name=section.name,
            virtual_address=section.virtual_address,
            virtual_size=section.virtual_size,
            size_of_raw_data=section.size_of_raw_data,
            characteristics=section.characteristics,
            declared_readable=section.is_readable,
            declared_writable=section.is_writable,
            declared_executable=section.is_executable,
            mapped_base_address=(hex_address(mapped.base_address) if mapped else None),
            mapped_size=(mapped.size if mapped else None),
            capture_state=(link.capture_state if link is not None else None),
            live_protections=(link.live_protections if link is not None else ())))
    return tuple(records)


def _pe_directory_records(profile, correlation) -> tuple:
    """All sixteen data-directory descriptors, in index order -- the
    descriptor's own decoded fields and state from the profile, the
    containing section and capture state from the correlation."""
    correlated = {c.index: c for c in correlation.directories} if correlation else {}
    records = []
    for descriptor in profile.directories:
        link = correlated.get(descriptor.index)
        records.append(ProcessPeDirectoryRecord(
            index=descriptor.index,
            name=descriptor.name,
            value=descriptor.value,
            value_kind=descriptor.value_kind,
            size=descriptor.size,
            bytes_read=descriptor.bytes_read,
            present=descriptor.present,
            descriptor_state=descriptor.state.value,
            containing_section_index=(link.containing_section_index
                                       if link is not None else None),
            capture_state=(link.capture_state if link is not None else None)))
    return tuple(records)


def _pe_entry_point_record(profile, correlation) -> ProcessPeEntryPointRecord:
    """The entry point and its memory context. Without a correlation only
    the header's own RVA is established: the VA, the containing section,
    and the region facts are all comparisons or resolutions the
    correlation performs, and none of them is recomputed here."""
    if correlation is None:
        return ProcessPeEntryPointRecord(
            rva=profile.address_of_entry_point, va=None, va_overflow=False,
            section_index=None, section_name=None, capture_state=None,
            region_state=None, region_type=None, region_protection=None)
    entry = correlation.entry_point
    section_name = None
    if entry.containing_section_index is not None:
        section_name = profile.sections[entry.containing_section_index].name
    return ProcessPeEntryPointRecord(
        rva=entry.entry_point_rva,
        va=hex_address(entry.entry_point_va),
        va_overflow=entry.va_overflow,
        section_index=entry.containing_section_index,
        section_name=section_name,
        capture_state=entry.capture_state,
        region_state=entry.region_state,
        region_type=entry.region_type,
        region_protection=entry.region_protection)


def _pe_acquisition_record(profile, *, segment_table: str,
                            region_table: str) -> ProcessPeAcquisitionRecord:
    stop = profile.bounded_stop
    capture = profile.capture
    return ProcessPeAcquisitionRecord(
        requested_stage=profile.requested_stage.name.lower(),
        highest_completed_stage=(profile.highest_completed_stage.name.lower()
                                  if profile.highest_completed_stage is not None else None),
        requested_bytes=profile.requested.size,
        captured_bytes=(capture.captured_bytes if capture is not None else None),
        read_bytes=profile.read_bytes,
        read_target_bytes=profile.read_target_bytes,
        target_io_short=profile.target_io_short,
        bounded_stop=(None if stop is None else {
            "scope": stop.scope,
            "budget_limit": stop.budget_limit,
            "budget_consumed": stop.budget_consumed}),
        components={
            "dos_header": _state_value(profile.components.dos_header),
            "coff_header": _state_value(profile.components.coff_header),
            "optional_header": _state_value(profile.components.optional_header),
            "directory_array": _state_value(profile.components.directory_array),
            "directory_descriptors": _state_value(profile.components.directory_descriptors),
            "section_table": _state_value(profile.components.section_table),
        },
        segment_table=segment_table,
        region_table=region_table,
        capture_overlapping=(capture.overlapping if capture is not None else None),
        unexamined=tuple({"base_address": hex_address(span.base_address), "size": span.size}
                          for span in profile.unexamined))


def _project_main_image_pe(profile, correlation, module_match: str, *,
                            segment_table: str, region_table: str) -> ProcessPeRecord:
    """§3.10's record, built from one already-collected profile and its
    correlation. Every value is copied or formatted; none is recomputed,
    and no memory is read here."""
    observations = tuple(
        PeObservationRecord(
            name=observation.name, state=observation.state.value, reason=observation.reason,
            sources=tuple(observation.sources),
            operands={key: value for key, value in observation.operands.items()})
        for observation in (correlation.all_observations() if correlation is not None else ()))
    tally = correlation.coverage if correlation is not None else None
    identity = profile.module_identity
    relocation = profile.relocation
    return ProcessPeRecord(
        collected=True,
        correlated=correlation is not None,
        unavailable_reason=None,
        source_kind=profile.source_kind.value,
        module_identity={"value": identity.value, "form": identity.form,
                          "truncated": identity.truncated},
        actual_base=hex_address(profile.actual_base),
        preferred_image_base=hex_address(profile.preferred_image_base),
        format=(None if profile.is_pe32_plus is None
                else ("PE32+" if profile.is_pe32_plus else "PE32")),
        machine=profile.machine,
        machine_name=profile.machine_name,
        time_date_stamp=profile.time_date_stamp,
        checksum=profile.checksum,
        subsystem=profile.subsystem,
        dll_characteristics=profile.dll_characteristics,
        coff_characteristics=profile.coff_characteristics,
        size_of_image=profile.size_of_image,
        size_of_headers=profile.size_of_headers,
        section_alignment=profile.section_alignment,
        file_alignment=profile.file_alignment,
        declared_section_count=profile.number_of_sections,
        decoded_section_count=len(profile.sections),
        structural_state=profile.state.value,
        relocation={
            "delta": relocation.relocation_delta,
            "relocs_stripped": relocation.relocs_stripped,
            "dynamic_base": relocation.dynamic_base,
            "basereloc_present": relocation.basereloc_present,
            "basereloc_descriptor_state": relocation.basereloc_descriptor_state.value,
        },
        entry_point=_pe_entry_point_record(profile, correlation),
        acquisition=_pe_acquisition_record(profile, segment_table=segment_table,
                                            region_table=region_table),
        directory_summary={
            "declared_count": profile.declared_directory_count,
            "declared_count_raw": profile.declared_directory_count_raw,
            "readable_count": profile.readable_directory_count,
            "unprojected_count": profile.unprojected_directory_count,
        },
        module_match=module_match,
        observation_coverage={
            "total": tally.total if tally is not None else 0,
            "consistent": tally.consistent if tally is not None else 0,
            "conflict": tally.conflict if tally is not None else 0,
            "unavailable": tally.unavailable if tally is not None else 0,
            "not_applicable": tally.not_applicable if tally is not None else 0,
        },
        sections=_pe_section_records(profile, correlation),
        directories=_pe_directory_records(profile, correlation),
        observations=observations)


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


def _build_process_record(snapshot, iat_result, pe_record, mf, verbose: bool) -> ProcessRecord:
    return ProcessRecord(
        process_name=snapshot.selected_process_name,
        pid=snapshot.pid,
        process_path=snapshot.selected_process_path,
        command_line=snapshot.command_line,
        process_start_utc=snapshot.process_start_utc,
        image_base_address=hex_address(snapshot.image_base_address),
        iat=_build_iat_record(iat_result),
        identity_evidence=_build_identity_evidence(snapshot),
        # The complete collected record regardless of `verbose`: verbosity
        # selects what the console prints, never what was collected.
        pe_image=pe_record,
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

    _render_main_image_pe(record.pe_image, verbose=verbose)

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

    # A heading over nothing reads as output that was cut off, or as
    # identity collection that failed without saying so. The identity
    # checks themselves are `--verbose`, and they carry their own
    # heading, so this one exists only for the diagnostics.
    diagnostics = record.identity_evidence.get("diagnostics") or []
    if diagnostics:
        print(f"\n  {BOLD('Identity')}")
        _print_diagnostics(diagnostics)

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
# One marker per meaning, across every check this console prints. The
# two that withhold an answer are not the same answer: `[??]` is evidence
# this dump does not carry, and `[--]` is a check the established facts
# leave no subject for. Reading the second as the first turns an ordinary
# PE layout into an evidence gap.
_CHECK_OK = "[OK]"
_CHECK_CONFLICT = "[!!]"
_CHECK_UNAVAILABLE = "[??]"
_CHECK_NOT_APPLICABLE = "[--]"

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


# ── §3.10: the Main Image PE console block ──────────────────────────────
# The default block is the image an analyst has to know about before
# reading anything else: what it is, where it is against where it wanted
# to be, how far it reaches, where execution begins, and every
# disagreement between two captured facts. The section table, the sixteen
# descriptors, the complete consistency list, and the byte provenance are
# density decisions deferred to --verbose -- hidden, never absent, and
# never abbreviated in `--json`, which carries the whole record either
# way.
#
# Nothing printed here is a verdict. A conflict is a disagreement between
# two captured facts, an unavailable check is a question the captured
# evidence does not answer, and neither moves the coverage status, the
# limitations, or the exit code.

# Every reason token dumpex.core.pe_correlation can attach to an
# observation, as the sentence an analyst reads instead of the token. The
# set is closed on that module's side, so a token with no entry here is a
# missing rendering rather than a new vocabulary.
_PE_REASON_TEXT = {
    # shared
    "size_of_image_null": "the header's SizeOfImage was not decoded, so there is no declared "
                          "extent to compare",
    "section_alignment_null": "the header's SectionAlignment was not decoded, so the documented "
                              "rounding cannot be applied",
    "profile_field_null": "a header field this comparison needs was not decoded",
    # base_vs_preferred
    "delta_recorded": "the load address and the preferred base are both recorded",
    "preferred_image_base_null": "the header's preferred ImageBase was not decoded",
    # relocation_expected. The check weighs two header declarations
    # against the two bases and nothing else, so these sentences stay at
    # the declaration level: a declared directory is not captured
    # relocation data, and saying it is would contradict the Relocation
    # Evidence block, which is where how much of it the dump holds is
    # reported.
    "zero_delta": "the image is loaded at its preferred base, so no relocation was needed",
    "relocation_delta_null": "the distance from the preferred base is not established",
    "relocation_conflict": "the image sits away from its preferred base although it declares "
                           "relocations stripped, or declares no base-relocation directory",
    "relocation_undetermined": "the image sits away from its preferred base and the relocation "
                               "evidence needed to judge that is not captured",
    "relocation_consistent": "the image sits away from its preferred base, and the header's own "
                             "declarations allow that -- relocations are not stripped and a "
                             "base-relocation directory is declared",
    # machine_vs_format
    "machine_null": "the header's Machine was not decoded",
    "format_null": "the optional header's 32/64-bit format was not decoded",
    "machine_has_no_width": "this Machine value fixes no 32/64-bit format",
    "unconstrained_machine": "EFI byte code ships in both formats, so either is legitimate",
    "format_matches_machine": "the header format is the one this architecture fixes",
    "format_contradicts_machine": "the header format is not the one this architecture fixes",
    # entry_point_in_section
    "entry_point_null": "the header's AddressOfEntryPoint was not decoded",
    "zero_entry_point": "the image declares no entry point",
    "entry_point_in_decoded_section": "the entry point falls inside a decoded section",
    "entry_point_outside_every_section": "the entry point falls outside every section the table "
                                         "declares",
    "entry_point_table_incomplete": "the section table is incomplete, so where the entry point "
                                    "falls is undetermined",
    # size_vs_image_extent
    "regions_unavailable": "no usable memory region table, so the mapping this image "
                           "occupies could not be established",
    "regions_lossy": "the memory region table dropped a descriptor, so the mapping is not usable "
                     "evidence",
    "base_not_in_region": "no captured region contains the image base",
    "base_not_reservation_start": "the image base is not the start of its own memory reservation",
    "reservation_not_contiguous": "the reservation holding the image is not contiguous",
    "segments_unavailable": "no usable memory segment table, so how much of the mapping was "
                            "captured could not be established",
    "segments_lossy": "the memory segment table dropped a descriptor, so the captured extent is "
                      "not usable evidence",
    "segments_overlap_in_extent": "two segments claim the same address inside the mapping, so "
                                  "the captured extent is contradictory",
    "short_capture": "the dump captured only part of the mapping, so the declared size cannot be "
                     "compared against it",
    "size_within_base_region": "the declared image size fits inside the region holding the image "
                               "base",
    "size_within_reservation": "the declared image size fits inside the reservation holding the "
                               "image",
    "size_exceeds_reservation": "the declared image size reaches past the memory reserved for "
                                "the image",
    # size_vs_modulelist
    "no_modulelist_entry": "no loader module record was matched at this image base (see the "
                           "loader record line above for whether one could be)",
    "modulelist_size_null": "the loader's module record carries no size",
    "size_matches_modulelist": "the declared image size matches the loader's own record",
    "size_matches_modulelist_aligned": "the declared image size matches the loader's own record "
                                       "once section alignment is applied",
    "size_contradicts_modulelist": "the declared image size differs from the loader's own record",
    # size_vs_section_extent
    "no_decoded_sections": "no section was decoded, so the table describes no extent",
    "section_table_incomplete": "the section table is incomplete, so the extent it describes is "
                                "a lower bound",
    "size_covers_section_extent": "every decoded section fits inside the declared image size",
    "section_extent_exceeds_size": "a decoded section reaches past the declared image size",
    # identity_*
    "no_second_source": "no loader module record was matched at this image base to compare "
                        "against",
    "operand_null": "one of the two values was not recorded",
    "identity_matches": "the header value and the loader's own record agree",
    "identity_contradicts": "the header value and the loader's own record differ",
    "header_checksum_absent": "the header carries no checksum, which is ordinary for a linked "
                              "image",
    "machine_no_independent_source": "the dump carries no second source for this image's "
                                     "architecture",
    # section_*
    "section_range_representable": "the section's address range is representable at this load "
                                   "address",
    "section_range_overflows_address_space": "the section's address range runs past the end of "
                                             "the address space",
    "section_within_image_bound": "the section fits inside the declared image size",
    "section_escapes_image_bound": "the section reaches past the declared image size",
    "section_disjoint_from_others": "the section shares no address with another section",
    "section_overlaps_another": "the section shares addresses with another section",
    "section_overlap_undetermined": "the section table is incomplete, so an overlap with an "
                                    "undecoded section cannot be ruled out",
    "section_field_null": "a section field this comparison needs was not decoded",
    # directory_image_bound
    "directory_declared_absent": "the image declares this directory absent",
    "directory_presence_unknown": "the descriptor was not read far enough to say whether the "
                                  "directory is declared",
    "descriptor_partial": "only part of the descriptor was read",
    "file_offset_semantics": "this directory is addressed by file offset, not by image RVA, so "
                             "it is not part of the mapping",
    "directory_within_image_bound": "the directory fits inside the declared image size",
    "directory_escapes_image_bound": "the directory reaches past the declared image size",
}

# What each observation is about, in an analyst's terms. The per-section
# and per-descriptor families are named from their own operands instead,
# so a row says which section or which descriptor it is about.
_PE_OBSERVATION_SUBJECT = {
    "base_vs_preferred": "load address vs. preferred base",
    "relocation_expected": "relocation evidence",
    "machine_vs_format": "architecture vs. header format",
    "entry_point_in_section": "entry point placement",
    "size_vs_image_extent": "image size vs. mapped memory",
    "size_vs_modulelist": "image size vs. loader record",
    "size_vs_section_extent": "image size vs. section table",
    "identity_time_date_stamp": "timestamp vs. loader record",
    "identity_check_sum": "checksum vs. loader record",
    "identity_machine": "architecture vs. a second source",
}

# The evidence tokens an observation names, as the stream or structure an
# analyst would go and look at. A token with no entry prints as itself:
# an unnamed source is still provenance, and dropping it would hide which
# evidence a check rested on.
_PE_SOURCE_TEXT = {
    "profile.dos_header": "the image's DOS header",
    "profile.coff_header": "the image's COFF header",
    "profile.optional_header": "the image's optional header",
    "profile.directory_array": "the image's data directory array",
    "profile.directory_descriptors": "the image's data directory descriptors",
    "profile.section_table": "the image's section table",
    "profile.source:peb_image_base": "the PEB-reported image base",
    "profile.source:module_list_entry": "the module list's own base address",
    "profile.source:memory_candidate": "a scanned memory candidate's base address",
    "module_list": "the loader's module list",
    "memory_info": "the dump's memory region table",
    "memory_segments": "the dump's memory segment table",
}

_PE_OBSERVATION_MARKER = {
    "consistent": _CHECK_OK,
    "conflict": _CHECK_CONFLICT,
    "unavailable": _CHECK_UNAVAILABLE,
    "not_applicable": _CHECK_NOT_APPLICABLE,
}

# The word that opens a withheld answer, so the row says which of the two
# it is without the reader having to know the marker legend. A decided
# observation opens with its own sentence and takes no qualifier.
_PE_OBSERVATION_QUALIFIER = {
    "unavailable": "unavailable",
    "not_applicable": "not applicable",
}

# Why no profile exists, in the analyst's terms. `collection_failed` is
# dumpex's own defect and says so: the bytes were there, and a token that
# blamed the image for them would be a false claim about the dump.
_PE_UNCOLLECTED_TEXT = {
    "no_image_base": "(unavailable -- no image base to profile; see coverage above)",
    "header_unreadable": "(unavailable -- the header at the image base could not be read)",
    "collection_failed": "(unavailable -- dumpex could not build a profile from the captured "
                         "header; this is a dumpex defect, not a fact about the image)",
}

# What the loader's own module list says about this image base. The
# distinction is the record's, not this block's: a module list that parsed
# and registers nothing here has confirmed an absence, while one that is
# not there has confirmed nothing.
_PE_MODULE_MATCH_TEXT = {
    "resolved": "a module is registered at this image base",
    "unregistered": "no module is registered at this image base (the loader's list was read)",
    "unavailable": "the loader's module list could not be compared with this image base",
    None: "(unknown)",
}

# What happened to a table, as the sentence that attributes the gap to
# that table rather than to the image. `enumerated` needs no line:
# nothing was lost, whatever the table then turned out to contain.
_PE_TABLE_NAME = {
    "segment_table": "the dump's memory segment table",
    "region_table": "the dump's memory region table",
}

_PE_TABLE_STATE_TEXT = {
    "absent": "is not in this dump",
    "failed": "is in this dump and yielded nothing usable",
    "lossy": "dropped a descriptor",
    "unreadable": "could not be walked",
}

_PE_TABLE_CONSEQUENCE = {
    "segment_table": "the header's byte provenance and any check that needed the table are "
                     "withheld, not decided",
    "region_table": "any check or context that needed the table is withheld, not decided",
}


# How completely one of the dump's own tables could be walked, as the
# statement rather than the state token. `enumerated` is the healthy
# outcome and still says what it means: the walk reached the end, whether
# or not the table then carried anything.
_PE_TABLE_WALK_TEXT = {
    "absent": "not in this dump",
    "failed": "in this dump, and yielded nothing usable",
    "enumerated": "walked in full",
    "lossy": "walked, with a descriptor dropped",
    "unreadable": "could not be walked",
}

# The stage ladder's rungs (§6.1) as the structure each one ends at, so
# the console says what was parsed instead of naming dumpex's own rung.
_PE_STAGE_TEXT = {
    "dos": "the DOS header",
    "coff": "the COFF header",
    "optional": "the optional header",
    "sections": "the section table",
}

# The six header components (§1.2) as an analyst names them.
_PE_COMPONENT_NAME = {
    "dos_header": "DOS header",
    "coff_header": "COFF header",
    "optional_header": "optional header",
    "directory_array": "directory array",
    "directory_descriptors": "directory descriptors",
    "section_table": "section table",
}

# What became of a component. `None` is the one that is not a state of
# the component at all: the requested stage never covered it, so nothing
# was asked of it and nothing came back.
_PE_COMPONENT_STATE_TEXT = {
    "complete": "read in full",
    "partial": "read only in part",
    "unavailable": "could not be read",
    "malformed": "structurally defective",
    "declared_absent": "declared absent by the image",
    None: "outside the requested stage",
}

# A descriptor's own state (§4.3) and its addressing mode, as the console
# says them. The wire keeps the tokens; a column is not the place to make
# a reader translate one.
_PE_DESCRIPTOR_STATE_TEXT = {
    "complete": "complete",
    "partial": "partial",
    "unavailable": "unread",
    "malformed": "malformed",
    "declared_absent": "declared absent",
}

_PE_VALUE_KIND_TEXT = {
    "rva": "image RVA",
    "file_offset": "file offset",
}


def _pe_table_losses(acquisition) -> "tuple[str, ...]":
    """The tables that are not `enumerated`, in the fixed order they are
    declared."""
    if acquisition is None:
        return ()
    return tuple(
        field_name for field_name in _PE_TABLE_NAME
        if getattr(acquisition, field_name) != "enumerated")


def _pe_table_loss_lines(acquisition) -> "tuple[str, ...]":
    """One full sentence per table that yielded less than a whole one --
    what happened to it, and what is withheld because of it."""
    return tuple(
        f"{_PE_TABLE_NAME[field_name]} "
        f"{_PE_TABLE_STATE_TEXT[getattr(acquisition, field_name)]}: "
        f"{_PE_TABLE_CONSEQUENCE[field_name]}"
        for field_name in _pe_table_losses(acquisition))


def _pe_table_loss_summary(acquisition, *, pointer: bool) -> "tuple[str, ...]":
    """What happened to each table, without the consequence clause.

    The default block lists the checks that went unanswered directly
    above this, so repeating what is withheld would say the same thing
    twice; what this adds is which table, and which of the four things
    happened to it. `pointer` sends a `--verbose` reader to the block
    that states it in full rather than printing that sentence twice in
    one render."""
    suffix = " -- see Header Acquisition below" if pointer else ""
    return tuple(
        f"{_PE_TABLE_NAME[field_name]} "
        f"{_PE_TABLE_STATE_TEXT[getattr(acquisition, field_name)]}{suffix}"
        for field_name in _pe_table_losses(acquisition))


# What every result in this block is, and is not, evidence of. Printed
# unconditionally beside the tally: a block of agreeing structural checks
# reads as a clean process to anyone who does not already know that the
# checks only ever covered this one image's own headers, mapping, loader
# record, and captured extent. It is a statement of scope, not a verdict,
# a confidence, or an investigation policy. Pre-wrapped at a fixed width,
# so the block is byte-identical on every terminal.
_PE_SCOPE_LINES = (
    f"{'Scope':<16} structural main-image checks only; this does not establish",
    f"{'':<16} that the process is benign",
)

_PE_STRUCTURAL_STATE_TEXT = {
    "complete": "every header structure was read in full",
    "partial": "a header structure was read only in part",
    "unavailable": "a header structure could not be read at all",
    "malformed": "a header structure is structurally defective",
    "declared_absent": "the image positively declares this structure absent",
}

# How many observation rows the default block prints before folding the
# rest into a count. A hostile image can declare 96 sections, each
# carrying three observations of its own, and the default console is a
# summary.
_PE_DEFAULT_OBSERVATION_ROWS = 8

# The `unavailable` reasons the default block shows beside the conflicts.
# An unevaluated check is worth an analyst's attention when knowing WHY
# it could not be answered changes what they do next -- collect the dump
# again with the missing stream, look at a truncated structure, find a
# second source. Every other `unavailable` is routine structure: a
# directory the image declares absent, a header field that was never
# decoded (the `Structure` line above already says so), a comparison with
# no second source that no dump can ever supply. Listing those would bury
# the ones that matter, so the default block counts them and `--verbose`
# lists them all.
#
# Membership is the question "would an analyst act on this?", not "is it
# unavailable?" -- which is why this is an allowlist and not a filter.
_PE_ACTIONABLE_UNAVAILABLE_REASONS = frozenset({
    # the dump's own tables could not support the check
    "regions_unavailable",
    "regions_lossy",
    "segments_unavailable",
    "segments_lossy",
    "segments_overlap_in_extent",
    "short_capture",
    # the image is not laid out where the region table says it should be
    "base_not_in_region",
    "base_not_reservation_start",
    "reservation_not_contiguous",
    # a structure was captured only in part, so a real question went
    # unanswered rather than being asked and settled
    "entry_point_table_incomplete",
    "section_table_incomplete",
    "section_overlap_undetermined",
    "descriptor_partial",
    "relocation_undetermined",
    # no second source to corroborate against
    "no_modulelist_entry",
})

# Section names are eight attacker-controlled bytes and a directory name
# is dumpex's own, so only the first needs escaping -- both go through
# console_safe() anyway, for the same reason the IAT table does: one
# projection for every dump-derived string on this console.
_PE_SECTION_NAME_COLUMN_MIN_WIDTH = 10
_PE_SECTION_NAME_COLUMN_MAX_WIDTH = 24
_PE_PROTECTION_COLUMN_MIN_WIDTH = 22
_PE_PROTECTION_COLUMN_MAX_WIDTH = 48
_PE_DIRECTORY_NAME_COLUMN_MIN_WIDTH = 16


def _pe_section_label(pe_record, index: "int | None") -> str:
    """`section N (.text)` for a decoded section, `section N` for an index
    the decoded table does not reach."""
    if index is None:
        return "section"
    if 0 <= index < len(pe_record.sections):
        name = console_safe(pe_record.sections[index].name)
        if name:
            return f"section {index} ({name})"
    return f"section {index}"


def _pe_observation_subject(pe_record, observation) -> str:
    if observation.name == "directory_image_bound":
        index = observation.operands.get("index")
        if isinstance(index, int) and 0 <= index < len(pe_record.directories):
            return f"directory {index} ({pe_record.directories[index].name})"
        return "directory"
    if "section_index" in observation.operands:
        return _pe_section_label(pe_record, observation.operands.get("section_index"))
    return _PE_OBSERVATION_SUBJECT.get(observation.name, observation.name)


def _pe_observation_line(pe_record, observation) -> str:
    """One observation as `[marker] subject: what the evidence says`,
    unindented -- each caller adds its own. A withheld answer names which
    of the two it is first. The dumpex-authored reason token never
    reaches the console: it stays in `--json`, where a consumer keys on
    it."""
    marker = _PE_OBSERVATION_MARKER[observation.state]
    text = _PE_REASON_TEXT.get(observation.reason, observation.reason)
    qualifier = _PE_OBSERVATION_QUALIFIER.get(observation.state)
    if qualifier is not None:
        text = f"{qualifier} -- {text}"
    return f"{marker} {_pe_observation_subject(pe_record, observation)}: {text}"


def _pe_evidence_text(observation) -> str:
    return ", ".join(_PE_SOURCE_TEXT.get(source, source)
                      for source in observation.sources) or "(none recorded)"


def _pe_relocation_line(pe_record) -> str:
    """Whether this image was relocated, as the conclusion drawn from the
    two bases printed above it. The distance is stated beside the answer
    and never in place of it: a reader deciding whether relocation applies
    must not have to subtract two addresses to find out."""
    delta = pe_record.relocation["delta"]
    if delta is None:
        if pe_record.preferred_image_base is None:
            return "undetermined -- the preferred base was not decoded"
        return "undetermined -- the distance from the preferred base is not established"
    if delta == 0:
        return "not required -- loaded at the preferred base"
    direction = "above" if delta > 0 else "below"
    return (f"required -- loaded 0x{abs(delta):x} {direction} the preferred base")


# What the image says about relocation beside the fact that it was (or
# was not) relocated. Each line is one decoded fact, never a judgement
# folded out of several: the consistency check above is where they are
# weighed against each other.
_PE_RELOCS_STRIPPED_TEXT = {
    True: "the header declares relocations stripped",
    False: "the header does not declare relocations stripped",
    None: "(not decoded)",
}

_PE_DYNAMIC_BASE_TEXT = {
    True: "the header opts in to being loaded anywhere",
    False: "the header does not opt in to being loaded anywhere",
    None: "(not decoded)",
}

_PE_BASERELOC_PRESENT_TEXT = {
    True: "the image declares a base-relocation directory",
    False: "the image declares no base-relocation directory",
    None: "(not established)",
}

# How much of the base-relocation directory the dump actually holds --
# the difference between an image that declares relocation data and one
# whose relocation data was captured.
_PE_RELOCATION_CAPTURE_TEXT = {
    "complete": "the dump holds every byte the directory declares",
    "partial": "the dump holds only part of what the directory declares",
    "none": "the dump holds none of what the directory declares",
    None: "(not established -- no capture claim was resolved)",
}

_PE_BASERELOC_INDEX = 5


def _pe_architecture_line(pe_record) -> str:
    machine = pe_record.machine_name or (
        f"machine 0x{pe_record.machine:x}" if pe_record.machine is not None else "(unknown)")
    return f"{console_safe(machine)} / {pe_record.format or '(format unknown)'}"


def _pe_extent_line(pe_record) -> str:
    size = pe_record.size_of_image
    size_text = "(unknown)" if size is None else f"0x{size:x} ({size} bytes)"
    declared = pe_record.declared_section_count
    decoded = pe_record.decoded_section_count
    if declared is None:
        sections = f"{decoded} section(s) decoded"
    elif declared == decoded:
        sections = f"{decoded} section(s)"
    else:
        # The header's own count and what the table actually yielded are
        # different facts; a single number would hide a table that was
        # cut short.
        sections = f"{decoded} of {declared} section(s) decoded"
    return f"{size_text}, {sections}"


def _pe_entry_point_line(entry_point) -> str:
    if entry_point.rva is None:
        return "(unknown)"
    if entry_point.rva == 0:
        return "none declared"
    text = f"RVA 0x{entry_point.rva:x}"
    if entry_point.va_overflow:
        return f"{text} -- past the end of the address space at this load address"
    if entry_point.va:
        text += f" -> {entry_point.va}"
    context = []
    if entry_point.section_name:
        context.append(console_safe(entry_point.section_name))
    elif entry_point.section_index is not None:
        context.append(f"section {entry_point.section_index}")
    if entry_point.region_protection:
        context.append(entry_point.region_protection)
    if entry_point.capture_state:
        context.append(f"capture {entry_point.capture_state}")
    return f"{text} ({'; '.join(context)})" if context else text


def _render_main_image_pe(pe_record, *, verbose: bool) -> None:
    """The default Main Image PE block, and -- under `--verbose` -- the
    bounded section, descriptor, relocation, consistency, and provenance
    detail."""
    print(f"\n  {BOLD('Main Image PE')}")
    if not pe_record.collected:
        print(f"    {_PE_UNCOLLECTED_TEXT[pe_record.unavailable_reason]}")
        return

    print(f"    {'Architecture':<16} {_pe_architecture_line(pe_record)}")
    print(f"    {'Actual Base':<16} {pe_record.actual_base or '(unknown)'}")
    print(f"    {'Preferred Base':<16} {pe_record.preferred_image_base or '(not decoded)'}")
    print(f"    {'Relocation':<16} {_pe_relocation_line(pe_record)}")
    print(f"    {'Image Size':<16} {_pe_extent_line(pe_record)}")
    print(f"    {'Entry Point':<16} {_pe_entry_point_line(pe_record.entry_point)}")
    print(f"    {'Loader Record':<16} {_PE_MODULE_MATCH_TEXT[pe_record.module_match]}")
    state = pe_record.structural_state
    print(f"    {'Structure':<16} {state} -- {_PE_STRUCTURAL_STATE_TEXT.get(state, '')}".rstrip())
    if not pe_record.correlated:
        # An empty tally with no cause beside it reads exactly like a
        # clean image, which is the one thing it must never read as.
        print(f"    {'Consistency':<16} not produced -- dumpex could not correlate this image "
              f"with the dump's memory evidence")
    else:
        # Four counts, never three: an evidence gap and a check this
        # image gives no subject are different facts, and summing them
        # would report an ordinary PE layout as unexamined evidence.
        tally = pe_record.observation_coverage
        print(f"    {'Consistency':<16} {tally['consistent']} consistent, {tally['conflict']} "
              f"conflicting, {tally['unavailable']} unavailable, "
              f"{tally['not_applicable']} not applicable")
    for line in _PE_SCOPE_LINES:
        print(f"    {line}")

    # Conflicts first and unconditionally: a disagreement between two
    # captured facts is the stronger result, and an unevaluated check can
    # never displace one out of the row budget.
    rows = [o for o in pe_record.observations if o.state == "conflict"]
    rows += [o for o in pe_record.observations
             if o.state == "unavailable"
             and o.reason in _PE_ACTIONABLE_UNAVAILABLE_REASONS]
    for observation in rows[:_PE_DEFAULT_OBSERVATION_ROWS]:
        print(f"    {_pe_observation_line(pe_record, observation)}")
    omitted = len(rows) - _PE_DEFAULT_OBSERVATION_ROWS
    if omitted > 0:
        print(f"    ... and {omitted} further conflicting or unanswered check(s) "
              f"-- see --verbose")
    # Which of the dump's own tables is behind those unanswered checks,
    # and what happened to it. This keeps the gap attributed to the
    # table instead of leaving it to read as a property of the image;
    # what is withheld because of it is stated once, in the verbose
    # provenance block.
    for line in _pe_table_loss_summary(pe_record.acquisition, pointer=verbose):
        print(f"    {_CHECK_UNAVAILABLE} {line}")

    if verbose:
        _render_pe_sections(pe_record)
        _render_pe_directories(pe_record)
        _render_pe_relocation_evidence(pe_record)
        _render_pe_observations(pe_record)
        _render_pe_provenance(pe_record)
    else:
        print("    (use --verbose for the section table, the directory descriptors, the "
              "relocation evidence, and every consistency check)")


# Row counts here are structural, not arbitrary: a profile carries at
# most _MAX_SECTIONS sections and exactly sixteen descriptors, and each
# section contributes three observations and each descriptor one, so
# every table below is bounded by the image's own declared shape.

def _render_pe_sections(pe_record) -> None:
    print(f"\n    {BOLD('Sections')}                                     [--verbose only]")
    if not pe_record.sections:
        print("      (none decoded)")
        return
    rows = []
    for section in pe_record.sections:
        declared = "".join((
            "R" if section.declared_readable else "-",
            "W" if section.declared_writable else "-",
            "X" if section.declared_executable else "-"))
        rows.append((
            str(section.section_index),
            console_safe(section.name) or "(unnamed)",
            f"0x{section.virtual_address:x}+0x{section.virtual_size:x}",
            section.mapped_base_address or "(unmapped)",
            declared,
            ", ".join(section.live_protections) or "(none recorded)",
            section.capture_state or "(unknown)"))
    name_w = column_width("Name", [r[1] for r in rows],
                           minimum=_PE_SECTION_NAME_COLUMN_MIN_WIDTH,
                           cap=_PE_SECTION_NAME_COLUMN_MAX_WIDTH)
    rva_w = column_width("RVA+Size", [r[2] for r in rows], minimum=18)
    base_w = column_width("Mapped At", [r[3] for r in rows], minimum=20)
    protection_w = column_width("Live Protection", [r[5] for r in rows],
                                 minimum=_PE_PROTECTION_COLUMN_MIN_WIDTH,
                                 cap=_PE_PROTECTION_COLUMN_MAX_WIDTH)
    print(f"      {'#':<3} {'Name':<{name_w}}  {'RVA+Size':<{rva_w}}  {'Mapped At':<{base_w}}  "
          f"{'R/W/X':<5}  {'Live Protection':<{protection_w}}  Capture")
    for index, name, rva, base, declared, protection, capture in rows:
        print(f"      {index:<3} {name:<{name_w}}  {rva:<{rva_w}}  {base:<{base_w}}  "
              f"{declared:<5}  {protection:<{protection_w}}  {capture}")
    print("      R/W/X is what the section header declares; Live Protection is what the dump "
          "recorded")
    print("      for the memory it is mapped over. PAGE_EXECUTE_WRITECOPY is ordinary loader "
          "context.")


def _render_pe_directories(pe_record) -> None:
    print(f"\n    {BOLD('Data Directories')}                             [--verbose only]")
    if not pe_record.directories:
        print("      (none read)")
        return
    rows = []
    for descriptor in pe_record.directories:
        if descriptor.present is None:
            presence = "(undetermined)"
        elif descriptor.present:
            presence = "declared"
        else:
            presence = "absent"
        value = "(unread)" if descriptor.value is None else f"0x{descriptor.value:x}"
        size = "(unread)" if descriptor.size is None else f"0x{descriptor.size:x}"
        rows.append((
            str(descriptor.index), descriptor.name, presence,
            f"{value}+{size}", _PE_VALUE_KIND_TEXT[descriptor.value_kind],
            _PE_DESCRIPTOR_STATE_TEXT[descriptor.descriptor_state],
            descriptor.capture_state or "(n/a)"))
    name_w = column_width("Directory", [r[1] for r in rows],
                           minimum=_PE_DIRECTORY_NAME_COLUMN_MIN_WIDTH)
    value_w = column_width("Value+Size", [r[3] for r in rows], minimum=18)
    kind_w = column_width("Addressing", [r[4] for r in rows], minimum=11)
    state_w = column_width("Descriptor", [r[5] for r in rows], minimum=16)
    print(f"      {'#':<3} {'Directory':<{name_w}}  {'Presence':<14}  {'Value+Size':<{value_w}}  "
          f"{'Addressing':<{kind_w}}  {'Descriptor':<{state_w}}  Capture")
    for index, name, presence, value, kind, state, capture in rows:
        print(f"      {index:<3} {name:<{name_w}}  {presence:<14}  {value:<{value_w}}  "
              f"{kind:<{kind_w}}  {state:<{state_w}}  {capture}")
    print("      Value+Size is the descriptor's own declaration; Addressing says whether that "
          "value is")
    print("      an image RVA or a file offset. Descriptor is how much of the descriptor itself "
          "was read.")


def _pe_relocation_distance_text(delta) -> str:
    if delta is None:
        return "(not established)"
    if delta == 0:
        return "none -- loaded at the preferred base"
    direction = "above" if delta > 0 else "below"
    return f"0x{abs(delta):x} {direction} the preferred base"


def _render_pe_relocation_evidence(pe_record) -> None:
    """What the image declares about relocation, and how much of it the
    dump holds. Each line is one decoded fact: whether the image was
    relocated is the default block's `Relocation` line, and whether the
    two agree is the `relocation evidence` consistency check -- neither
    is re-derived here."""
    relocation = pe_record.relocation
    print(f"\n    {BOLD('Relocation Evidence')}                          [--verbose only]")
    print(f"      {'Distance':<24} {_pe_relocation_distance_text(relocation['delta'])}")
    print(f"      {'Stripped':<24} {_PE_RELOCS_STRIPPED_TEXT[relocation['relocs_stripped']]}")
    print(f"      {'Dynamic base':<24} {_PE_DYNAMIC_BASE_TEXT[relocation['dynamic_base']]}")
    print(f"      {'Directory':<24} "
          f"{_PE_BASERELOC_PRESENT_TEXT[relocation['basereloc_present']]}")
    print(f"      {'Descriptor':<24} "
          f"{_PE_DESCRIPTOR_STATE_TEXT[relocation['basereloc_descriptor_state']]}")
    # A capture claim about a directory the image does not declare would
    # describe bytes the image never named.
    descriptor = pe_record.directories[_PE_BASERELOC_INDEX]
    if descriptor.present:
        print(f"      {'Directory bytes':<24} "
              f"{_PE_RELOCATION_CAPTURE_TEXT[descriptor.capture_state]}")


def _render_pe_observations(pe_record) -> None:
    print(f"\n    {BOLD('Consistency Checks')}                           [--verbose only]")
    if not pe_record.observations:
        print("      (none evaluated)")
        return
    for observation in pe_record.observations:
        print(f"      {_pe_observation_line(pe_record, observation)}")
        print(f"           evidence: {_pe_evidence_text(observation)}")


def _pe_captured_text(acquisition) -> str:
    """The capture line, which is a byte count or the reason there is
    none. It measures the requested window and nothing beyond it --
    `captured_bytes` cannot exceed what was asked for -- so it is stated
    as how much of that window the dump holds, never as how much of the
    image the dump holds. `captured_bytes` is null for four different
    reasons, and naming the wrong one is the same class of false
    provenance statement as claiming a table is absent."""
    captured = acquisition.captured_bytes
    if captured is not None:
        return f"0x{captured:x} bytes"
    state = acquisition.segment_table
    if state != "enumerated":
        return f"(not resolved -- the segment table {_PE_TABLE_STATE_TEXT[state]})"
    # The table enumerated whole and still could not account for the run
    # that was read: `_capture_for`'s own invariant check refused it, and
    # there is no table state to attribute that to.
    return "(not resolved -- the segment table accounts for fewer bytes than were read)"


# Why the bytes parsing needed did not all arrive, once dumpex's own
# budget is ruled out. The judgement that they did not is one fact and
# the cause is another: bytes the dump never held and bytes it holds that
# the read did not return have different remedies, and a line that named
# only one of them would state the wrong one half the time.
_PE_SHORTFALL_CAUSE = {
    True: "the dump holds bytes this read did not return",
    False: "the dump holds no more than was read",
    None: "no segment table says which of the two applies",
}

# A budget is checked first and answers on its own: `target_io_short`
# compares the read against the captured prefix, and a stopped read has
# always taken every byte it asked for, so it is False in every
# bounded-stop run. Reading that as an answer about the dump would blame
# the dump for a limit of this tool -- the §6.2 rule inverted.
#
# Which budget fired decides how much may then be said. A byte budget
# exonerates the dump outright: the window it asked for arrived whole,
# and only dumpex's ceiling kept parsing from reaching further. A
# read-count budget settles nothing of the kind -- a header spread across
# enough captured segments costs one read per segment, so the layout this
# dump carries can reach that limit as readily as a trickling reader can
# -- and an `e_lfanew` stop is a fact about what the image declared. Only
# the first may deny the dump a part in it.
_PE_BUDGET_SHORTFALL_CAUSE = {
    "pe_header_bytes": "dumpex's own byte budget stopped the read, not the dump",
    "pe_header_read_operations": "dumpex's own read-count budget stopped the read",
    "e_lfanew": "the image declares its PE header past dumpex's own budget",
}

_PE_BUDGET_SHORTFALL_DEFAULT = "one of dumpex's own budgets stopped the read"


def _pe_required_bytes_lines(acquisition) -> "tuple[str, ...]":
    """Whether parsing got every byte it asked for, and -- when it did
    not -- what stands behind the shortfall. A staged acquisition asks
    for far less than the window it requested, so this is the line that
    says a structure was cut short; the byte counts above it are not a
    comparison a reader should have to make."""
    if acquisition.read_bytes >= acquisition.read_target_bytes:
        return ("yes",)
    shortfall = (f"no -- 0x{acquisition.read_bytes:x} of "
                 f"0x{acquisition.read_target_bytes:x} bytes were read")
    stop = acquisition.bounded_stop
    if stop is not None:
        return (shortfall, _PE_BUDGET_SHORTFALL_CAUSE.get(
            stop["scope"], _PE_BUDGET_SHORTFALL_DEFAULT))
    return (shortfall, _PE_SHORTFALL_CAUSE[acquisition.target_io_short])


# Which of dumpex's own budgets ended the acquisition, as the sentence
# that names it. The scope token is dumpex's own identifier and never
# reaches the console; an unlisted scope falls back to a sentence that
# still names no token, because the set of budgets is deliberately not
# frozen by the profile contract (§6.2).
_PE_BOUNDED_SCOPE_TEXT = {
    "pe_header_bytes": "dumpex's own header byte budget stopped the read",
    "pe_header_read_operations": "dumpex's own header read-count budget stopped the read",
    "e_lfanew": "the declared PE header offset is past dumpex's own budget",
}

_PE_BOUNDED_SCOPE_DEFAULT = "one of dumpex's own budgets stopped the read"


def _pe_bounded_stop_lines(stop: dict) -> "tuple[str, ...]":
    """The budget that ended the acquisition, and its two numbers. The
    numbers are stated apart from the sentence because `budget_consumed`
    is above the limit for one scope and at it for the others, and one
    sentence covering both would have to be vague about which."""
    return (_PE_BOUNDED_SCOPE_TEXT.get(stop["scope"], _PE_BOUNDED_SCOPE_DEFAULT),
            f"limit {stop['budget_limit']}, consumed {stop['budget_consumed']}")


def _pe_parsing_line(acquisition) -> str:
    """How far up the stage ladder the acquisition got, in the structures
    a reader can point at rather than the ladder's own rung names."""
    requested = _PE_STAGE_TEXT[acquisition.requested_stage]
    completed = acquisition.highest_completed_stage
    if completed is None:
        return f"no structure completed; the read asked for {requested}"
    if completed == acquisition.requested_stage:
        return f"completed through {requested}, as requested"
    return (f"completed through {_PE_STAGE_TEXT[completed]}; "
            f"the read asked for {requested}")


def _pe_component_lines(acquisition) -> "tuple[str, ...]":
    """The six header components grouped by what became of each, in the
    contract's own component order and with one group per line. A
    component outside the requested stage is named as out of scope, never
    as one that came back empty."""
    grouped = {}
    for name, state in acquisition.components.items():
        grouped.setdefault(state, []).append(_PE_COMPONENT_NAME[name])
    return tuple(
        f"{_PE_COMPONENT_STATE_TEXT[state]}: {', '.join(names)}"
        for state, names in grouped.items())


def _render_pe_provenance(pe_record) -> None:
    """The bytes behind everything above: the window that was asked for,
    how much of it the dump actually holds, and how much of it parsing
    needed. A staged acquisition stops once its ladder is satisfied, so
    needing far fewer bytes than the dump holds is the normal outcome for
    a healthy image. What says a structure was cut short is `Required
    bytes present`, never a comparison between the first two lines."""
    acquisition = pe_record.acquisition
    print(f"\n    {BOLD('Header Acquisition')}                           [--verbose only]")
    print(f"      {'Requested window':<24} 0x{acquisition.requested_bytes:x} bytes at the "
          f"image base")
    print(f"      {'Captured in that window':<24} {_pe_captured_text(acquisition)}")
    print(f"      {'Required for parsing':<24} 0x{acquisition.read_target_bytes:x} bytes")
    for index, line in enumerate(_pe_required_bytes_lines(acquisition)):
        print(f"      {'Required bytes present' if index == 0 else '':<24} {line}")
    overlapping = acquisition.capture_overlapping
    print(f"      {'Segment table':<24} {_PE_TABLE_WALK_TEXT[acquisition.segment_table]}"
          f"{' (two segments claim one address)' if overlapping else ''}")
    print(f"      {'Region table':<24} {_PE_TABLE_WALK_TEXT[acquisition.region_table]}")
    # The consequence of the two lines above, said beside them rather
    # than left for a reader to derive from the state tokens.
    for line in _pe_table_loss_lines(acquisition):
        print(f"      {' ' * 24} {line}")
    print(f"      {'Parsing':<24} {_pe_parsing_line(acquisition)}")
    stop = acquisition.bounded_stop
    if stop is not None:
        for index, line in enumerate(_pe_bounded_stop_lines(stop)):
            print(f"      {'Bounded stop' if index == 0 else '':<24} {line}")
    for index, line in enumerate(_pe_component_lines(acquisition)):
        print(f"      {'Header components' if index == 0 else '':<24} {line}")
    if acquisition.unexamined:
        spans = ", ".join(f"{span['base_address']}+0x{span['size']:x}"
                           for span in acquisition.unexamined)
        print(f"      {'Unexamined':<24} {spans}")
        print("      Unexamined names bytes nothing looked at -- neither intact nor damaged "
              "there.")
    identity = pe_record.module_identity
    if identity["value"] is not None:
        # The shortened marker sits outside the value, never inside it: a
        # name ending in an ellipsis the image itself carries must not be
        # indistinguishable from one dumpex cut short.
        marker = " [shortened]" if identity["truncated"] else ""
        source = _PE_SOURCE_TEXT.get(f"profile.source:{pe_record.source_kind}",
                                      pe_record.source_kind)
        print(f"      {'Named as':<24} {console_safe(identity['value'])}{marker} "
              f"({identity['form']} from {source})")


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

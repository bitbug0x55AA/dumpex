"""Bounded enrichment collectors for `--report`.

One process-wide result per invocation, and four card-scoped projections
per triage card. Every collector here reuses an existing canonical
collector or primitive -- the process-identity boundary, the handle
collector, the captured-region model, and the card's own single content
read -- and adds no report-only process, handle, or memory-range policy
of its own.

Everything produced here is captured evidence and navigation context. No
collector in this module contributes to a card's findings, finding
details, verdict, or the process exit code, and none of them adds a
limitation to the command's own coverage report: an enrichment section
carries its own missing/partial/complete state instead, so an absent
stream never turns into a process-wide negative.

Every section is bounded by a cap declared in this module. A section
reports the eligible population it selected from, what it kept, and why
each retained item was kept, so a short subset is always explainable
without re-reading the dump.
"""
import bisect
import heapq
from dataclasses import dataclass

from minidump.constants import MINIDUMP_STREAM_TYPE

from dumpex.commands.handles import collect_handles, summarize_handles_by_type
from dumpex.core.disasm import (
    MAX_DECODE_BYTES, MAX_DECODE_INSNS, MAX_INSTRUCTION_LENGTH, BranchKind,
    DisasmAvailability, decode_window,
)
from dumpex.core.memory import (
    addr_to_module, clamped_reader, get_modules, get_thread_contexts,
    handle_stream_evidence, has_stream_directory, read_region_spanning, stream_failure,
)
from dumpex.core.pe_correlation import ModuleListImage, ObservationState, correlate_main_image
from dumpex.core.pe_profile import (
    PE_HEADER_READ_MAX, ComponentState, PeStage, SourceKind, collect_pe_image_profile,
)
from dumpex.core.pe_utils import parse_iat
from dumpex.core.process_info import (
    build_process_identity_snapshot, parse_environment_entries, walk_environment_block,
)
from dumpex.core.va_location import resolve_va_location
from dumpex.core.va_range import (
    VirtualRange, capture_of, enumerate_captured_regions, enumerate_captured_segments,
    region_containing,
)
from dumpex.output.coverage import COVERAGE_COMPLETE
from dumpex.output.records import (
    ENRICHMENT_COMPLETE, ENRICHMENT_MISSING, ENRICHMENT_PARTIAL,
    ENRICHMENT_SCOPE_CARD, ENRICHMENT_SCOPE_PROCESS, ENRICHMENT_TEXT_CAP,
    MODULE_CONTEXT_UNAVAILABLE, EnrichmentSection, ReportAddressContext,
    ReportAnchorPeContext, ReportBranchTarget, ReportDecodedInstruction,
    ReportIdentityConflict, ReportAllocationNeighborhood, ReportCorrelatedHandle,
    ReportEnvironmentSummary, ReportEnvironmentValue, ReportExceptionContext,
    ReportExceptionEntry, ReportHandleCorrelation, ReportHandleSummary,
    ReportHandleTypeCount, ReportIatCorrelatedEntry, ReportIatCorrelation,
    ReportInstructionContext, ReportNeighborRegion, ReportPeContext, ReportPeObservation,
    ReportProcessEnrichment, ReportStringContext, ReportStringContextEntry,
    ReportTokenCapability, StreamParserState, hex_address,
)

# ── Caps ────────────────────────────────────────────────────────────────
# Every bounded selection in this module names its cap here, so the whole
# per-report enrichment budget is readable in one place. A cap bounds
# retained records; the console previews below are separately, and more
# tightly, bounded.
MAX_HANDLE_TYPE_ROWS       = 12    # per-type census rows kept process-wide
MAX_CORRELATED_HANDLES     = 8     # handles correlated with one card's own text
MAX_EXCEPTION_ENTRIES      = 4     # exception records kept per card
MAX_EXCEPTION_PARAMETERS   = 4     # ExceptionInformation values kept per record
MAX_NEIGHBOR_REGIONS       = 9     # regions kept per card, anchor included
MAX_NEIGHBOR_SIDE_REGIONS  = 2     # out-of-allocation regions kept on each side of the anchor
MAX_NEIGHBOR_SCAN          = 1024  # table positions walked per side looking for those
MAX_STRING_CONTEXT_ENTRIES = 12    # strings kept per card
MAX_IDENTITY_CONFLICTS     = 4     # source disagreements carried into the process section
MAX_PE_CONFLICTS           = 16    # main-image correlation conflicts kept process-wide
MAX_INSTRUCTION_WINDOW     = MAX_DECODE_INSNS  # decoded instructions kept per card
MAX_BRANCH_TARGETS         = 16    # resolved branch targets kept per card
MAX_IAT_CORRELATED_ENTRIES = 16    # unusual/correlated IAT slots kept per card
MAX_MODULE_PROFILES        = 8     # distinct module PE profiles built per invocation

# ── Invocation budget ───────────────────────────────────────────────────
# The caps above bound one card. --report-string builds one card per
# private-memory hit, and the number of hits is a property of the dump, so
# per-card bounds alone leave a run's total cost unbounded: a dump with
# many large matching regions costs hits x MAX_REGION_READ to read and
# every string in all of them to enrich.
#
# These two bound the run itself. The first card is always built, however
# large -- a budget that could produce no card at all would answer a
# direct question with nothing.
MAX_REPORT_CARDS      = 32                 # triage cards one invocation will build
MAX_REPORT_SCAN_BYTES = 256 * 1024 * 1024  # cumulative content bytes those cards may request

# The one identity-diagnostic family that reports missing evidence rather
# than contradictory evidence: the preferred path source was unavailable
# and a fallback supplied the value. Every other code names two captured
# sources that disagree, which leaves the evaluation complete.
_IDENTITY_COMPLETENESS_CODES = frozenset({"PROCESS_PATH_SOURCE_FALLBACK"})

# Console previews. Structured output keeps the full retained set; the
# console shows a prefix of it, and says so whenever it shows less.
CONSOLE_HANDLE_TYPE_ROWS   = 6
CONSOLE_CORRELATED_HANDLES = 4
CONSOLE_NEIGHBOR_REGIONS   = 5
CONSOLE_STRING_CONTEXT     = 5
CONSOLE_PE_CONFLICTS       = 4
CONSOLE_INSTRUCTION_ROWS   = 8
CONSOLE_BRANCH_TARGETS     = 5
CONSOLE_IAT_ROWS           = 5

# The shortest object-name segment a handle correlation will match on.
# Below this length a segment matches too much captured text to mean
# anything.
MIN_CORRELATION_SEGMENT_LEN = 4


# ── Environment allowlist ───────────────────────────────────────────────
# The report is a stored, shareable triage product, so it publishes only
# the session-context variables an investigator needs to say who and where
# the process ran -- never the whole block, and never a value carrying a
# user profile path or a secret. The complete environment inventory
# remains `--sysinfo`, which this summary points at rather than
# reproduces. Names are matched case-insensitively; a name off this list
# is not counted as eligible and never reaches the record.
ENVIRONMENT_ALLOWLIST = (
    "COMPUTERNAME",
    "USERDOMAIN",
    "USERNAME",
    "SESSIONNAME",
    "OS",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
)
_ALLOWLIST_LOOKUP = {name.upper(): name for name in ENVIRONMENT_ALLOWLIST}

# walk_environment_block() states that mean the block was never read at
# all: no entry was eligible because nothing was evaluated.
_ENV_NOT_EVALUATED_STATES = frozenset({
    "unsupported", "architecture_unsupported", "pointer_unreadable", "unparseable",
})


def _bounded_optional(value: "str | None") -> "tuple[str | None, bool]":
    """_bounded_text for a value that may be absent. None stays None and
    is not a truncation."""
    if value is None:
        return None, False
    return _bounded_text(value)


def _bounded_text(value: str) -> "tuple[str, bool]":
    """(text, truncated) for one dump-derived string, cut to
    ENRICHMENT_TEXT_CAP characters. The text is kept exactly as captured
    up to the cap; escaping belongs to the console boundary."""
    if len(value) > ENRICHMENT_TEXT_CAP:
        return value[:ENRICHMENT_TEXT_CAP], True
    return value, False


# ── Process-wide enrichment ─────────────────────────────────────────────

def _collect_environment(mf) -> ReportEnvironmentSummary:
    state, raw_entries, detail = walk_environment_block(mf)
    if state in _ENV_NOT_EVALUATED_STATES:
        limitation = (f"environment block not read ({state}"
                      + (f": {detail}" if detail else "") + ")")
        return ReportEnvironmentSummary(
            section=EnrichmentSection(
                name="environment", scope=ENRICHMENT_SCOPE_PROCESS,
                status=ENRICHMENT_MISSING, total=None, included=0,
                cap=len(ENVIRONMENT_ALLOWLIST), truncated=False,
                provenance=("environment_block",),
                limitations=(_bounded_text(limitation)[0],)))

    # First occurrence wins: the block's own order is the process's own
    # order, and a duplicate name is the same variable seen twice, not a
    # second eligible entry.
    seen = {}
    for entry in parse_environment_entries(raw_entries):
        key = entry.name.upper()
        canonical = _ALLOWLIST_LOOKUP.get(key)
        if canonical is None or canonical in seen:
            continue
        seen[canonical] = entry.value

    values = []
    for name in ENVIRONMENT_ALLOWLIST:
        if name not in seen:
            continue
        text, truncated = _bounded_text(seen[name])
        values.append(ReportEnvironmentValue(name=name, value=text, truncated=truncated))

    status = ENRICHMENT_PARTIAL if state == "partial" else ENRICHMENT_COMPLETE
    limitations = ()
    if state == "partial":
        limitations = (_bounded_text(
            "environment block walk stopped early"
            + (f" ({detail})" if detail else "")
            + ": an allowlisted variable past that point was not read")[0],)
    return ReportEnvironmentSummary(
        section=EnrichmentSection(
            name="environment", scope=ENRICHMENT_SCOPE_PROCESS, status=status,
            total=len(values), included=len(values), cap=len(ENVIRONMENT_ALLOWLIST),
            truncated=False, provenance=("environment_block",), limitations=limitations),
        entries=tuple(values))


def _collect_handle_summary(mf) -> "tuple[ReportHandleSummary, tuple]":
    """(summary, handle_records). The collected `--handles` records travel
    back with the summary so each card's own correlation pass reuses this
    one collection instead of running the handle collector again."""
    state, _parsed, failure_detail = handle_stream_evidence(mf)
    if state == "absent":
        return ReportHandleSummary(
            section=EnrichmentSection(
                name="handles", scope=ENRICHMENT_SCOPE_PROCESS, status=ENRICHMENT_MISSING,
                total=None, included=0, cap=MAX_HANDLE_TYPE_ROWS, truncated=False,
                provenance=("handles",),
                limitations=("the dump carries no HandleDataStream: no handle was evaluated",)),
            total_handles=None), ()
    if state == "failed":
        limitation = _bounded_text(
            f"HandleDataStream could not be parsed: {failure_detail}"
            if failure_detail else "HandleDataStream could not be parsed")[0]
        return ReportHandleSummary(
            section=EnrichmentSection(
                name="handles", scope=ENRICHMENT_SCOPE_PROCESS, status=ENRICHMENT_MISSING,
                total=None, included=0, cap=MAX_HANDLE_TYPE_ROWS, truncated=False,
                provenance=("handles",), limitations=(limitation,)),
            total_handles=None), ()

    result = collect_handles(mf)
    records = tuple(result.records)
    census = summarize_handles_by_type(records)
    rows = [ReportHandleTypeCount(type_name=_bounded_text(name)[0], count=count,
                                  type_name_truncated=_bounded_text(name)[1])
            for name, count in census.items()]
    kept = rows[:MAX_HANDLE_TYPE_ROWS]
    limitations = tuple(_bounded_text(reason)[0] for reason in result.coverage.reasons)
    status = (ENRICHMENT_COMPLETE if result.coverage.status == COVERAGE_COMPLETE
              else ENRICHMENT_PARTIAL)
    return ReportHandleSummary(
        section=EnrichmentSection(
            name="handles", scope=ENRICHMENT_SCOPE_PROCESS, status=status,
            total=len(rows), included=len(kept), cap=MAX_HANDLE_TYPE_ROWS,
            truncated=len(kept) < len(rows), provenance=("handles",),
            limitations=limitations),
        total_handles=len(records), by_type=tuple(kept)), records


def _collect_token_capability(mf) -> ReportTokenCapability:
    """dumpex registers no TokenStream parser, so a captured TokenStream
    is `unparsed`: its privilege and impersonation evidence is present in
    the dump and unreadable here. Saying that explicitly is the point --
    a silent omission would read as "the process had no token evidence"."""
    if not has_stream_directory(mf, MINIDUMP_STREAM_TYPE.TokenStream):
        return ReportTokenCapability(
            stream_present=False, parser_state=None, status="unavailable",
            detail="the dump declares no TokenStream: no token or privilege evidence was "
                   "captured")
    failure = stream_failure(mf, MINIDUMP_STREAM_TYPE.TokenStream)
    if failure is not None:
        return ReportTokenCapability(
            stream_present=True, parser_state=StreamParserState.FAILED.value,
            status="unavailable",
            detail=_bounded_text(f"the dump's TokenStream failed to parse: {failure}")[0])
    return ReportTokenCapability(
        stream_present=True, parser_state=StreamParserState.UNPARSED.value,
        status="unavailable",
        detail="the dump declares a TokenStream, but dumpex registers no parser for it: its "
               "token evidence is captured and unread")


def collect_process_enrichment(mf) -> "tuple[ReportProcessEnrichment, tuple]":
    """The one process-wide enrichment of a `--report` run, plus the
    handle records its per-card correlation reuses.

    Identity comes from the canonical process-identity snapshot, so this
    section and `--process` can never disagree about the same dump."""
    snapshot = build_process_identity_snapshot(mf)
    environment = _collect_environment(mf)
    handles, handle_records = _collect_handle_summary(mf)
    token = _collect_token_capability(mf)

    provenance = ("misc_info", "peb", "modules")
    limitations = []
    if snapshot.pid is None:
        limitations.append("no process id resolved from MiscInfoStream")
    if snapshot.selected_process_path is None:
        limitations.append("no process path resolved from the PEB or the module list")
    if snapshot.process_start_utc is None:
        limitations.append("no process start time resolved from MiscInfoStream")

    # Every claim this record publishes counts as evidence, not just the
    # three the limitations above name: a section reporting `missing` while
    # carrying a command line and an image base would contradict itself,
    # and the console's own missing branch would hide values the document
    # does hold. A module match state of "unavailable" is the absence of
    # that evidence, so it does not count.
    # A diagnostic that says a PREFERRED SOURCE WAS UNAVAILABLE is a
    # completeness fact and belongs with the limitations that drive this
    # section's evidence state. One that says two AVAILABLE SOURCES
    # DISAGREE is not: both were captured and both were read, so the
    # evaluation is complete and only its subject is contradictory.
    # Folding the second kind into limitations would report a fully
    # captured conflict as a collection gap.
    conflicts = []
    for diagnostic in snapshot.diagnostics:
        if diagnostic.code in _IDENTITY_COMPLETENESS_CODES:
            limitations.append(_bounded_text(f"{diagnostic.code}: {diagnostic.message}")[0])
        else:
            conflicts.append(diagnostic)
    kept_conflicts = tuple(
        ReportIdentityConflict(code=_bounded_text(d.code)[0], severity=d.severity,
                               message=_bounded_text(d.message)[0])
        for d in conflicts[:MAX_IDENTITY_CONFLICTS])

    resolved = [snapshot.pid, snapshot.selected_process_path, snapshot.process_start_utc,
                snapshot.command_line, snapshot.image_base_address,
                (snapshot.module_claim.match_state
                 if snapshot.module_claim.match_state != MODULE_CONTEXT_UNAVAILABLE else None)]
    if all(value is None for value in resolved):
        status = ENRICHMENT_MISSING
        section = EnrichmentSection(
            name="process", scope=ENRICHMENT_SCOPE_PROCESS, status=status,
            total=None, included=0, cap=1, truncated=False,
            provenance=provenance, limitations=tuple(limitations))
    else:
        status = ENRICHMENT_COMPLETE if not limitations else ENRICHMENT_PARTIAL
        section = EnrichmentSection(
            name="process", scope=ENRICHMENT_SCOPE_PROCESS, status=status,
            total=1, included=1, cap=1, truncated=False,
            provenance=provenance, limitations=tuple(limitations))

    process_path, path_truncated = _bounded_optional(snapshot.selected_process_path)
    command_line, command_truncated = _bounded_optional(snapshot.command_line)
    # A name is the basename of a path, and a path with no separator in it
    # is its own basename -- so this is a dump-derived string of unbounded
    # length like the other two, not a short field derived from them.
    process_name, name_truncated = _bounded_optional(snapshot.selected_process_name)
    return ReportProcessEnrichment(
        section=section,
        pid=snapshot.pid,
        process_name=process_name,
        process_name_truncated=name_truncated,
        identity_conflicts=kept_conflicts,
        identity_conflicts_total=len(conflicts),
        process_path=process_path,
        path_source=(snapshot.selected_path_source
                     if snapshot.selected_process_path is not None else None),
        process_path_truncated=path_truncated,
        command_line=command_line,
        command_line_truncated=command_truncated,
        process_start_utc=snapshot.process_start_utc,
        image_base_address=hex_address(snapshot.image_base_address),
        module_match_state=snapshot.module_claim.match_state,
        environment=environment, handles=handles, token=token), handle_records


# ── Card-scoped: exception context ──────────────────────────────────────

def _exception_code_fields(record) -> "tuple[str | None, str | None, int | None]":
    """(raw code as '0x' hex, decoded name, raw int) for one parsed
    exception record.

    The parser files an unrecognized code under its own placeholder
    member, which is not a decoded name and is reported as None. A
    captured value that is not usable as a code yields None rather than
    "0x0": 0 is EXCEPTION_NONE, a real code, and substituting it would
    publish invented evidence."""
    raw = getattr(record, "ExceptionCode_raw", None)
    decoded = getattr(record, "ExceptionCode", None)
    name = getattr(decoded, "name", None)
    if name == "EXCEPTION_UNKNOWN":
        name = None
    if raw is None:
        raw = getattr(decoded, "value", None)
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 0:
        return None, name, None
    return f"0x{raw:08x}", name, raw


# The two codes whose ExceptionInformation is defined as
# (access type, referenced address). Every other code's parameters are
# code-specific and are published raw rather than guessed at.
_ACCESS_VIOLATION_CODE = 0xC0000005
_IN_PAGE_ERROR_CODE = 0xC0000006
_ACCESS_TYPE_BY_PARAMETER = {0: "read", 1: "write", 8: "execute"}
_ADDRESS_SPACE = 1 << 64


def _decode_access_violation(raw_code, raw_parameters) -> "tuple[str | None, int | None]":
    """(access type, referenced address) for an access-violation or
    in-page-error record.

    Both are read positionally out of the captured parameters, which is
    what those two codes define them to be. A first parameter outside the
    documented vocabulary yields no access type rather than a guess, and a
    record of any other code yields neither value."""
    if raw_code not in (_ACCESS_VIOLATION_CODE, _IN_PAGE_ERROR_CODE):
        return None, None
    if len(raw_parameters) < 2:
        return None, None
    kind, referenced = raw_parameters[0], raw_parameters[1]
    access_type = (_ACCESS_TYPE_BY_PARAMETER.get(kind)
                   if isinstance(kind, int) and not isinstance(kind, bool) else None)
    if not (isinstance(referenced, int) and not isinstance(referenced, bool)
            and 0 <= referenced < _ADDRESS_SPACE):
        referenced = None
    return access_type, referenced


def _address_context(address, regions, modules) -> "ReportAddressContext | None":
    """One address resolved against the region table and module list the
    card already holds, so an exception address and the card's own region
    can never disagree. None when there is no address to resolve."""
    if address is None:
        return None
    region = region_containing(address, regions) if regions else None
    owner, owner_truncated = _bounded_optional(_module_owner_for(address, modules))
    return ReportAddressContext(
        address=hex_address(address),
        region_base=hex_address(region.base_address) if region else None,
        region_size=region.size if region else None,
        protection=region.protection if region else None,
        type=region.type if region else None,
        module_owner=owner, module_owner_truncated=owner_truncated)


# The dump represents no collector or capture reason for an exception
# record, so every retained entry's capture provenance is unknown. Stating
# that is the contract: a breakpoint a debugger injected and a fault the
# process took reach this section identically.
_EXCEPTION_CAPTURE_PROVENANCE = (
    "capture reason unknown: the dump does not represent which collector or event produced "
    "this exception record")


def collect_exception_context(mf, *, anchor_tid, region_base, region_size,
                              region_evidence=None, modules=()) -> ReportExceptionContext:
    """This card's bounded view of the dump's ExceptionStream.

    A record is retained when its thread is this card's anchor thread,
    when its faulting address falls inside this card's resolved region,
    or -- for the stream's first record only -- as the process's own crash
    context. An access violation additionally decodes into its access type
    and referenced address, and both that address and the faulting address
    are resolved against `region_evidence`/`modules`, the same views the
    card itself uses.

    Address resolution is only as complete as the region view behind it:
    when that view dropped a descriptor and an address here failed to
    resolve, the address may live in exactly the span that went missing,
    so the section reports `partial` rather than claiming the address is
    outside every captured region.

    An exception is execution state: nothing here claims that the anchor
    caused it or that either is malicious."""
    section_kwargs = dict(name="exception", scope=ENRICHMENT_SCOPE_CARD,
                          cap=MAX_EXCEPTION_ENTRIES, provenance=("exception",))
    regions = region_evidence.views if region_evidence is not None else ()
    region_view_incomplete = (region_evidence.incomplete
                              if region_evidence is not None else False)
    failure = stream_failure(mf, MINIDUMP_STREAM_TYPE.ExceptionStream)
    stream = getattr(mf, "exception", None)
    records = getattr(stream, "exception_records", None) if stream is not None else None

    if records is None:
        # A declared stream with neither a parsed object nor a recorded
        # failure was captured and lost on the way through the loader.
        # That is failed evidence, not a dump collected without exception
        # data, and the two send an analyst to different places.
        declared = has_stream_directory(mf, MINIDUMP_STREAM_TYPE.ExceptionStream)
        if failure is not None:
            limitation = _bounded_text(f"ExceptionStream could not be parsed: {failure}")[0]
        elif declared:
            limitation = ("the dump declares an ExceptionStream but no parsed stream is "
                          "available: it was captured and could not be read")
        elif stream is None:
            limitation = "the dump carries no ExceptionStream: no exception was evaluated"
        else:
            limitation = "the parsed ExceptionStream carries no readable record list"
        return ReportExceptionContext(section=EnrichmentSection(
            status=ENRICHMENT_MISSING, total=None, included=0, truncated=False,
            limitations=(limitation,), **section_kwargs))

    selected = []
    for index, record in enumerate(records):
        detail = getattr(record, "ExceptionRecord", None)
        thread_id = getattr(record, "ThreadId", None)
        address = getattr(detail, "ExceptionAddress", None) if detail is not None else None
        in_region = (region_base is not None and isinstance(address, int)
                     and region_base <= address < region_base + region_size)
        if anchor_tid is not None and thread_id == anchor_tid:
            reason = "anchor_thread"
        elif in_region:
            reason = "anchor_region"
        elif index == 0:
            reason = "process_exception"
        else:
            continue
        selected.append((index, record, detail, thread_id, address, reason))

    # anchor_thread first, then anchor_region, then the process record --
    # the most specific relationship to this card's anchor is the one an
    # investigator reads first. Stream order breaks every tie.
    priority = {"anchor_thread": 0, "anchor_region": 1, "process_exception": 2}
    selected.sort(key=lambda item: (priority[item[5]], item[0]))
    kept = selected[:MAX_EXCEPTION_ENTRIES]

    entries = []
    unusable_codes = 0
    for index, _record, detail, thread_id, address, reason in kept:
        code, code_name, raw_code = _exception_code_fields(detail)
        if code is None:
            unusable_codes += 1
        raw_parameters = list(getattr(detail, "ExceptionInformation", None) or ())
        # Position carries meaning here -- parameter 0 is the access type
        # and parameter 1 the referenced address -- so an unusable element
        # is published as unknown in place. Dropping it would shift every
        # following value one slot left and relabel it as something else.
        parameters = tuple(
            f"0x{p:x}" if isinstance(p, int) and not isinstance(p, bool) and p >= 0
            else "0x?" for p in raw_parameters[:MAX_EXCEPTION_PARAMETERS])
        access_type, referenced = _decode_access_violation(raw_code, raw_parameters)
        flags = getattr(detail, "ExceptionFlags", None)
        entries.append(ReportExceptionEntry(
            index=index,
            thread_id=thread_id if isinstance(thread_id, int) and thread_id >= 0 else None,
            exception_code=code, exception_code_name=code_name,
            exception_flags=flags if isinstance(flags, int) and not isinstance(flags, bool)
                            else None,
            exception_address=hex_address(address) if isinstance(address, int) else None,
            parameters=parameters,
            parameters_truncated=len(raw_parameters) > MAX_EXCEPTION_PARAMETERS,
            selection_reason=reason,
            access_type=access_type,
            referenced_address=hex_address(referenced),
            address_context=(_address_context(address, regions, modules)
                             if isinstance(address, int) else None),
            referenced_context=_address_context(referenced, regions, modules)))

    limitations = [_EXCEPTION_CAPTURE_PROVENANCE] if entries else []
    if unusable_codes:
        limitations.append(
            f"{unusable_codes} retained record(s) carry no usable exception code")

    status = ENRICHMENT_COMPLETE
    unresolved = any(context is not None and context.region_base is None
                     for entry in entries
                     for context in (entry.address_context, entry.referenced_context))
    if region_view_incomplete and unresolved:
        status = ENRICHMENT_PARTIAL
        limitations.append(
            "an address here resolved to no captured region while descriptor(s) were dropped "
            "from the region view: it may lie in one of them")

    return ReportExceptionContext(
        section=EnrichmentSection(
            status=status, total=len(selected), included=len(entries),
            truncated=len(entries) < len(selected), limitations=tuple(limitations),
            **section_kwargs),
        entries=tuple(entries))


# ── Card-scoped: allocation neighborhood ────────────────────────────────

def _gap_between(region, anchor) -> int:
    if region.end_address <= anchor.base_address:
        return anchor.base_address - region.end_address
    if region.base_address >= anchor.end_address:
        return region.base_address - anchor.end_address
    return 0


@dataclass(frozen=True)
class RegionEvidence:
    """The dump's region table as one `--report` invocation reads it.

    Built once per invocation and shared by every card. It carries three
    things a per-card collector must not re-derive: the enumerated views,
    how many descriptors the region model could not represent, and whether
    the stream was absent, unparseable, or parsed at all.

    `by_allocation` maps an allocation base to the ascending positions of
    its members in `views`, and `position_of` maps a region base to its own
    position. Together they turn "the rest of this allocation, nearest
    first" into a bounded walk around one index instead of a scan of the
    whole table per card.

    A base address identifies a region here, so `views` holds at most one
    descriptor per base. A malformed or hostile dump can declare the same
    base twice; keeping both would make one region its own neighbour and
    give the index two answers for one key."""
    views:         tuple
    skipped:       int
    state:         str            # "parsed" | "failed" | "absent"
    failure:       "str | None"
    by_allocation: dict
    position_of:   dict
    duplicates:    int = 0        # descriptors dropped for repeating a base already seen

    @classmethod
    def from_dump(cls, mf) -> "RegionEvidence":
        failure = stream_failure(mf, MINIDUMP_STREAM_TYPE.MemoryInfoListStream)
        declared = has_stream_directory(mf, MINIDUMP_STREAM_TYPE.MemoryInfoListStream)
        if not getattr(mf, "memory_info", None):
            # A declared stream with neither a parsed object nor a recorded
            # failure was captured and lost on the way through the loader.
            # "Captured and unreadable" and "never collected" send an
            # analyst to different places, so they never collapse here.
            state = "failed" if (failure is not None or declared) else "absent"
            return cls(views=(), skipped=0, state=state, failure=failure,
                       by_allocation={}, position_of={})

        enumeration = enumerate_captured_regions(mf)

        # Views arrive ordered by (base, end), so descriptors repeating a
        # base are adjacent and the first one kept is the narrowest --
        # deterministic for the same dump, and never dependent on the
        # order the table happened to be written in.
        views = []
        duplicates = 0
        for region in enumeration.views:
            if views and views[-1].base_address == region.base_address:
                duplicates += 1
                continue
            views.append(region)

        by_allocation = {}
        position_of = {}
        for position, region in enumerate(views):
            position_of[region.base_address] = position
            if region.allocation_base is not None:
                by_allocation.setdefault(region.allocation_base, []).append(position)
        return cls(views=tuple(views), skipped=enumeration.skipped, state="parsed",
                   failure=failure,
                   by_allocation={base: tuple(members)
                                  for base, members in by_allocation.items()},
                   position_of=position_of, duplicates=duplicates)

    def absence_limitation(self) -> str:
        if self.failure is not None:
            return _bounded_text(
                f"MemoryInfoListStream could not be parsed: {self.failure}")[0]
        if self.state == "failed":
            return ("the dump declares a MemoryInfoListStream but no parsed stream is "
                    "available: it was captured and could not be read")
        return "the dump carries no MemoryInfoListStream: no region was evaluated"

    def skipped_limitation(self) -> "tuple[str, ...]":
        """What this region view could not carry. Both cases remove a
        descriptor the dump declared, so both make a section reading this
        view `partial` rather than letting it claim a complete map."""
        limitations = ()
        if self.skipped:
            limitations += (
                f"{self.skipped} region descriptor(s) could not be represented and are "
                f"absent from this region view",)
        if self.duplicates:
            limitations += (
                f"{self.duplicates} region descriptor(s) repeated a base address already "
                f"seen and were dropped as one region",)
        return limitations

    @property
    def incomplete(self) -> bool:
        return bool(self.skipped or self.duplicates)


@dataclass(frozen=True)
class HandleSegmentIndex:
    """The collected handle inventory keyed by the segment that identifies
    each object.

    Built once per invocation. Correlating one card is then a lookup per
    captured segment rather than a pass over every handle, so the work a
    run does is bounded by the text its cards examined and not by cards
    multiplied by handles."""
    by_segment:       dict
    total:            int
    unreadable_names: int

    @classmethod
    def from_records(cls, handle_records) -> "HandleSegmentIndex":
        by_segment = {}
        unreadable = 0
        for record in handle_records:
            if record.object_name_status == "unreadable":
                unreadable += 1
                continue
            if record.object_name_status != "ok" or not record.object_name:
                continue
            segment = _identifying_segment(record.object_name)
            if segment is None:
                continue
            by_segment.setdefault(segment, []).append(record)
        return cls(by_segment={segment: tuple(records)
                               for segment, records in by_segment.items()},
                   total=len(handle_records), unreadable_names=unreadable)


def _module_owner_for(address: int, modules) -> "str | None":
    """The name of the loaded module whose range holds `address`, or None.

    Resolution goes through the same addr_to_module the rest of the report
    uses, so a neighbour region and the card's own region can never
    disagree about who owns an address."""
    if not modules:
        return None
    module = addr_to_module(address, modules)
    return module.name if module else None


def collect_allocation_neighborhood(region_evidence, *, anchor_address, modules=()
                                    ) -> ReportAllocationNeighborhood:
    """The bounded region layout around this card's anchor: the anchor's
    own region, the rest of its allocation, and the nearest regions
    outside the allocation on either side.

    `region_evidence` is the RegionEvidence the run built once (see
    collect_report), and `modules` resolves each neighbour's owning
    module. Selection walks outward from the anchor's own position in the
    table and in its allocation, so the work one card does is bounded by
    the caps below rather than by the size of the region table.

    Neighbors are layout, not causation -- a neighboring region is a place
    to look next, never evidence of a relationship to the anchor."""
    section_kwargs = dict(name="allocation", scope=ENRICHMENT_SCOPE_CARD,
                          cap=MAX_NEIGHBOR_REGIONS, provenance=("memory_info",))
    if anchor_address is None or region_evidence is None or region_evidence.state != "parsed":
        limitation = ("no anchor address to place in the region table"
                      if anchor_address is None
                      else (region_evidence.absence_limitation()
                            if region_evidence is not None
                            else "no region table was collected for this run"))
        return ReportAllocationNeighborhood(
            section=EnrichmentSection(status=ENRICHMENT_MISSING, total=None, included=0,
                                      truncated=False, limitations=(limitation,),
                                      **section_kwargs),
            allocation_base=None)

    # A descriptor the region model cannot represent is dropped from the
    # table, which silently removes its span from this neighborhood -- so
    # the count of dropped descriptors decides the section's own state.
    # Reading only the surviving views would report a hole in the memory
    # map as a completed evaluation.
    regions = region_evidence.views
    skipped_limitations = region_evidence.skipped_limitation()
    status = ENRICHMENT_PARTIAL if region_evidence.incomplete else ENRICHMENT_COMPLETE

    anchor = region_containing(anchor_address, regions)
    if anchor is None:
        return ReportAllocationNeighborhood(
            section=EnrichmentSection(
                status=status, total=0, included=0, truncated=False,
                limitations=("no region in the table contains the anchor address",)
                            + skipped_limitations,
                **section_kwargs),
            allocation_base=None)

    index = region_evidence.position_of[anchor.base_address]

    # Regions are in ascending address order and do not overlap, so index
    # distance within an allocation IS gap distance: the nearest siblings
    # are the ones bracketing the anchor's own position. Walking outward
    # from there costs the cap, while the allocation's full size is still
    # known from the index and counted in `total`.
    members = region_evidence.by_allocation.get(anchor.allocation_base, ())
    sibling_total = max(len(members) - 1, 0)
    siblings = []
    if members:
        here = bisect.bisect_left(members, index)
        left, right = here - 1, here + 1
        while len(siblings) < MAX_NEIGHBOR_REGIONS and (left >= 0 or right < len(members)):
            left_gap = (_gap_between(regions[members[left]], anchor)
                        if left >= 0 else None)
            right_gap = (_gap_between(regions[members[right]], anchor)
                         if right < len(members) else None)
            if right_gap is None or (left_gap is not None and left_gap <= right_gap):
                siblings.append(regions[members[left]])
                left -= 1
            else:
                siblings.append(regions[members[right]])
                right += 1

    # What a private allocation abuts is the neighborhood's most
    # decision-relevant fact -- a protection transition, an unregistered
    # mapping, an image boundary. The walk therefore steps OVER the
    # anchor's own allocation rather than stopping at it: a multi-page
    # reservation whose immediate index neighbours are its own subregions
    # would otherwise hide every region outside it. Membership is tested
    # against the allocation base, so the whole reservation is stepped
    # over however few of its members were materialized above.
    side_regions = {"preceding": [], "following": []}
    side_scan_exhausted = False
    for step, relation in ((-1, "preceding"), (1, "following")):
        position = index + step
        scanned = 0
        while (0 <= position < len(regions)
                and len(side_regions[relation]) < MAX_NEIGHBOR_SIDE_REGIONS):
            if scanned >= MAX_NEIGHBOR_SCAN:
                side_scan_exhausted = True
                break
            scanned += 1
            region = regions[position]
            position += step
            if (region.base_address == anchor.base_address
                    or (anchor.allocation_base is not None
                        and region.allocation_base == anchor.allocation_base)):
                continue
            side_regions[relation].append(region)

    # The cap reserves the out-of-allocation neighbours before the
    # allocation's own subregions. A large reservation can otherwise
    # supply every retained row and crowd out the boundary the section
    # exists to show; its own subregions are the more numerous and the
    # more interchangeable evidence.
    reserved = ([(anchor, "anchor")]
                + [(region, "preceding") for region in side_regions["preceding"]]
                + [(region, "following") for region in side_regions["following"]])[
                    :MAX_NEIGHBOR_REGIONS]
    kept = reserved + [(region, "same_allocation")
                       for region in siblings[:MAX_NEIGHBOR_REGIONS - len(reserved)]]
    kept.sort(key=lambda item: item[0].base_address)

    # Every region the selection considered, whether or not it survived --
    # `truncated` is only honest about the cap when `total` counts the
    # population the cap cut from. The allocation's own size comes from
    # the index, so counting it costs nothing even when only the nearest
    # members were looked at.
    eligible = 1 + sibling_total + sum(len(group) for group in side_regions.values())

    limitations = skipped_limitations
    if side_scan_exhausted:
        status = ENRICHMENT_PARTIAL
        limitations += (
            f"the walk for a neighbouring region outside this allocation stopped after "
            f"{MAX_NEIGHBOR_SCAN} table position(s)",)

    entries = []
    for region, relation in kept:
        owner, owner_truncated = _bounded_optional(
            _module_owner_for(region.base_address, modules))
        entries.append(ReportNeighborRegion(
            base_address=hex_address(region.base_address), size=region.size,
            state=region.state, type=region.type, protection=region.protection,
            allocation_base=hex_address(region.allocation_base),
            module_owner=owner, module_owner_truncated=owner_truncated,
            relation=relation,
            distance=0 if relation == "anchor" else _gap_between(region, anchor)))

    return ReportAllocationNeighborhood(
        section=EnrichmentSection(
            status=status, total=eligible, included=len(entries),
            truncated=len(entries) < eligible, limitations=limitations,
            **section_kwargs),
        allocation_base=hex_address(anchor.allocation_base), entries=tuple(entries))


# ── Card-scoped: handle correlation ─────────────────────────────────────

_SEGMENT_SEPARATORS = "\\/:"


def _name_segments(text: str) -> list:
    """The lowercased path/name segments of one captured string, in order,
    with any segment too short to identify an object dropped."""
    normalized = text
    for separator in _SEGMENT_SEPARATORS:
        normalized = normalized.replace(separator, "\n")
    return [segment.strip().lower() for segment in normalized.split("\n")
            if len(segment.strip()) >= MIN_CORRELATION_SEGMENT_LEN]


def _identifying_segment(object_name: str) -> "str | None":
    """The one segment of a handle's object name that identifies the
    object itself -- its last.

    A handle object name and the text a process keeps in memory rarely
    agree character for character (`\\Device\\NamedPipe\\x` against
    `\\\\.\\pipe\\x`), but their final segment does. Only that segment is
    eligible to match: a namespace prefix (`Device`, `BaseNamedObjects`,
    `REGISTRY`) is shared by thousands of unrelated objects, so matching
    on any segment would correlate a named pipe with an unrelated file
    path and let that noise fill the retained subset ahead of a real
    correlation."""
    segments = _name_segments(object_name)
    return segments[-1] if segments else None


def collect_handle_correlation(handle_index, scanned_strings, *, handle_summary,
                               content_partial: bool = False,
                               content_clamped: bool = False) -> ReportHandleCorrelation:
    """The handles whose named object also appears in the text this card
    examined.

    `scanned_strings` is the card's own already-extracted string list --
    no region is read or scanned again here -- and `handle_index` is the
    HandleSegmentIndex the run built once. The match is textual: the final
    segment of the handle's object name occurs as a segment of a captured
    string. That is two independent captures of the same name in one dump,
    not proof that the anchor uses the handle.

    Matching is a lookup per captured segment rather than a pass over the
    inventory, so a run's total correlation work follows the text its
    cards examined instead of cards multiplied by handles. Every collected
    handle is still reachable: a prefix cut would be a biased one, since
    the collector orders records by ascending handle value, which on
    Windows is roughly the order the process opened them.

    This section rests on two bodies of evidence, and is only `complete`
    when both are: the handle inventory it selects from, and the card's
    own captured text it matches against. An unread handle name or a short
    region read means a non-match may be a non-read, so `content_partial`
    (the card's own read came up short) and a partial handle summary each
    make the result `partial` -- otherwise an empty subset would claim
    every handle was checked against every captured byte. `content_clamped`
    (the card's own scan cap, not the dump, ended the read) stays
    `complete` under this repository's clamp-versus-truncation rule but is
    always stated: the compared range is smaller than the region either
    way."""
    section_kwargs = dict(name="handle_correlation", scope=ENRICHMENT_SCOPE_CARD,
                          cap=MAX_CORRELATED_HANDLES, provenance=("handles",))
    if handle_summary.section.status == ENRICHMENT_MISSING:
        return ReportHandleCorrelation(section=EnrichmentSection(
            status=ENRICHMENT_MISSING, total=None, included=0, truncated=False,
            limitations=handle_summary.section.limitations, **section_kwargs))
    if scanned_strings is None:
        return ReportHandleCorrelation(section=EnrichmentSection(
            status=ENRICHMENT_MISSING, total=None, included=0, truncated=False,
            limitations=("this card examined no content: no handle name could be correlated",),
            **section_kwargs))

    captured_segments = set()
    for _offset, _encoding, text in scanned_strings:
        captured_segments.update(_name_segments(text))

    limitations = []
    unreadable_names = handle_index.unreadable_names
    matched = []
    for segment in captured_segments:
        matched.extend(handle_index.by_segment.get(segment, ()))

    # Deterministic, and independent of handle-table order: the same dump
    # always produces the same retained subset under the same cap.
    matched.sort(key=lambda r: (r.object_name.lower(), r.handle))

    # A handle value is a record's whole identity, and a malformed dump can
    # declare the same one twice. Two descriptors sharing an identity are
    # one object, so the second is dropped here rather than reaching a
    # record type that refuses to hold both.
    deduplicated = []
    seen_handles = set()
    for record in matched:
        if record.handle in seen_handles:
            continue
        seen_handles.add(record.handle)
        deduplicated.append(record)
    if len(deduplicated) < len(matched):
        limitations.append(
            f"{len(matched) - len(deduplicated)} correlated handle(s) repeated a handle value "
            f"already seen and were dropped as one object")
    matched = deduplicated
    kept = matched[:MAX_CORRELATED_HANDLES]

    entries = []
    for record in kept:
        object_name, object_truncated = _bounded_text(record.object_name)
        type_name, type_truncated = _bounded_optional(record.type_name)
        entries.append(ReportCorrelatedHandle(
            handle=record.handle, type_name=type_name,
            type_name_truncated=type_truncated,
            object_name=object_name, object_name_truncated=object_truncated,
            granted_access=record.granted_access, attributes=record.attributes,
            handle_count=record.handle_count, pointer_count=record.pointer_count,
            selection_reason="object_name_in_anchor_strings"))
    entries = tuple(entries)

    status = ENRICHMENT_COMPLETE
    if handle_summary.section.status == ENRICHMENT_PARTIAL:
        status = ENRICHMENT_PARTIAL
        limitations.extend(handle_summary.section.limitations)
    if unreadable_names:
        status = ENRICHMENT_PARTIAL
        limitations.append(
            f"{unreadable_names} handle(s) have an object name that could not be read and "
            f"could not be matched against this card's text")
    if content_partial:
        status = ENRICHMENT_PARTIAL
        limitations.append(
            "this card's region read came up short: a handle named only in the unread bytes "
            "could not be matched")
    if content_clamped:
        limitations.append(
            "the text compared against is the card's own scan cap, not the whole region: a "
            "handle named only past that cap could not be matched")

    return ReportHandleCorrelation(
        section=EnrichmentSection(
            status=status, total=len(matched), included=len(entries),
            truncated=len(entries) < len(matched),
            limitations=tuple(_bounded_text(text)[0] for text in limitations),
            **section_kwargs),
        entries=entries)


# ── Card-scoped: anchor-aware string context ────────────────────────────

def _encoded_span(text: str, encoding: str) -> int:
    """How many bytes of the examined range one extracted string occupies:
    two per character for UTF-16LE, one for ASCII."""
    return len(text) * (2 if encoding == "UTF16" else 1)


def _string_enclosing_hit(scanned_strings, hit_offset: int):
    """The (offset, encoding, text) triple whose captured bytes contain
    `hit_offset`, or None.

    A search hit is a byte position; the string extraction that runs over
    the same bytes may have captured it inside a longer string (an
    embedded needle) or not captured it at all (a run shorter than the
    extraction's own minimum length). Finding the enclosing capture is
    what lets one entry carry both the hit and the exact captured text."""
    for offset, encoding, text in scanned_strings:
        if not text:
            continue
        if offset <= hit_offset < offset + _encoded_span(text, encoding):
            return (offset, encoding, text)
    return None


def _string_candidate_keys(*, scanned_strings, bytes_read, region_base, distance_anchor,
                           ioc_offsets, match, counted):
    """Every eligible string as a lightweight sort key, yielded one at a
    time.

    A key is a plain tuple -- `(rank, distance, address, offset, encoding,
    text, selection_reason)` -- ordered so tuple comparison alone gives
    the selection order: the query hit, then IOC-pattern matches, then
    remaining strings by absolute distance from the anchor, with the
    virtual address as the stable tie-breaker.

    Streaming keys rather than building records is what keeps this pass
    bounded: a card may read up to MAX_REGION_READ bytes, so the string
    list behind it can be very large, and only the cap's worth of keys is
    ever held at once. `counted` receives every yielded key so the caller
    knows the eligible population without a second pass.

    IOC membership is read off `ioc_offsets`, the set the card's own
    content scan already produced with the same pattern over the same
    strings. Re-running the pattern here would be a second full regex pass
    for an answer already in hand."""
    if match is not None:
        counted()
        offset, encoding, text = match
        yield (0, 0, region_base + offset, offset, encoding, text, "query_match")

    for offset, encoding, text in scanned_strings:
        if not text or offset >= bytes_read:
            continue
        if match is not None and offset == match[0]:
            # Already published as the query match. The string enclosing
            # the hit is the anchor, not context adjacent to it.
            continue
        counted()
        address = region_base + offset
        reason = "ioc_pattern" if offset in ioc_offsets else "adjacent_to_anchor"
        yield (1 if reason == "ioc_pattern" else 2, abs(address - distance_anchor),
               address, offset, encoding, text, reason)


def collect_string_context(*, anchor_address, region_base, region_size, string_scan,
                           scanned_strings, ioc_offsets, query, string_hit
                           ) -> "ReportStringContext | None":
    """The card's own strings, re-selected around its anchor.

    Selection order is the query hit, then existing IOC-pattern matches,
    then remaining strings by absolute distance from the anchor, with the
    virtual address as the stable tie-breaker. Everything comes from the
    single content read the card already performed: no second scan, no
    report-only string parser, and no entry outside the declared examined
    range.

    Selection streams over the card's strings and keeps only the cap's
    worth of candidates, so the work is bounded by the cap rather than by
    how many strings the region happens to hold; a record is built only
    for a string that survives.

    Returns None when the card examined no content at all -- there is no
    range to describe, which is distinct from a range that was examined
    and yielded nothing."""
    if string_scan is None or scanned_strings is None or anchor_address is None:
        return None

    bytes_read = string_scan["bytes_read"]
    distance_anchor = anchor_address
    if string_hit is not None:
        hit_offset = string_hit["offset"]
        if 0 <= hit_offset < bytes_read:
            distance_anchor = region_base + hit_offset

    # The one entry that stands for the search hit: the string actually
    # captured around it where the extraction produced one, and the needle
    # itself where it did not.
    match = None
    query_text = None
    if string_hit is not None and query:
        hit_offset = string_hit["offset"]
        if 0 <= hit_offset < bytes_read:
            query_text = _bounded_text(query)[0]
            match = (_string_enclosing_hit(scanned_strings, hit_offset)
                     or (hit_offset, string_hit["encoding"], query))

    eligible = 0

    def counted():
        nonlocal eligible
        eligible += 1

    kept_keys = heapq.nsmallest(MAX_STRING_CONTEXT_ENTRIES, _string_candidate_keys(
        scanned_strings=scanned_strings, bytes_read=bytes_read, region_base=region_base,
        distance_anchor=distance_anchor, ioc_offsets=ioc_offsets, match=match,
        counted=counted))

    kept = []
    for _rank, distance, address, offset, encoding, text, reason in kept_keys:
        bounded, truncated = _bounded_text(text)
        kept.append(ReportStringContextEntry(
            address=hex_address(address), offset=offset, encoding=encoding,
            text=bounded, text_truncated=truncated, selection_reason=reason,
            distance=None if reason == "query_match" else distance))

    limitations = []
    if string_scan["clamped"]:
        limitations.append(
            "the examined range is the card's own scan cap, not the whole region")
    if string_scan["truncated"]:
        limitations.append(
            f"the region read came up short: {bytes_read} of "
            f"{string_scan['requested_bytes']} requested byte(s) were read")

    status = ENRICHMENT_PARTIAL if string_scan["truncated"] else ENRICHMENT_COMPLETE
    return ReportStringContext(
        section=EnrichmentSection(
            name="string_context", scope=ENRICHMENT_SCOPE_CARD, status=status,
            total=eligible, included=len(kept), cap=MAX_STRING_CONTEXT_ENTRIES,
            truncated=len(kept) < eligible, provenance=("report_content_scan",),
            limitations=tuple(_bounded_text(text)[0] for text in limitations)),
        anchor_address=hex_address(anchor_address),
        distance_anchor_address=hex_address(distance_anchor), query_text=query_text,
        examined_base_address=hex_address(region_base), examined_size=region_size,
        requested_bytes=string_scan["requested_bytes"], bytes_read=bytes_read,
        total_strings=string_scan["total"], entries=tuple(kept))


# ── PE, instruction, and IAT correlation ───────────────────────────────
# One process-wide pe_context per invocation, and three card-scoped
# projections -- anchor_pe_context, instruction_context, iat_correlation.
# Every one consumes a canonical collector (collect_pe_image_profile,
# correlate_main_image, parse_iat) rather than a report-only PE or IAT
# parser, and every one is captured evidence only: none reaches findings,
# verdict, coverage status, or the exit code.

_UNSET = object()

# capstone resolves a relative branch to its absolute target already, so a
# direct target is a fixed address. A memory-operand slot address is fixed
# by the instruction; the pointer in it is read separately.
_IMPORT_DIRECTORY_INDEX = 1
_IAT_DIRECTORY_INDEX = 12
_BASERELOC_DIRECTORY_INDEX = 5

_PE_OBS_STATE_WIRE = {
    ObservationState.CONSISTENT: "consistent",
    ObservationState.CONFLICT:   "conflict",
    ObservationState.UNAVAILABLE: "unavailable",
}


class PeProfileCache:
    """The PE evidence a `--report` invocation reads once and shares.

    Built once by collect_report and passed to every card. It holds the
    main image's :class:`~dumpex.core.pe_profile.PeImageProfile` and its
    :class:`~dumpex.core.pe_correlation.MainImageCorrelation`, and lazily
    builds and caches the profile and parsed IAT of each non-main module a
    card's anchor lands in. The distinct-profile count is bounded by
    MAX_MODULE_PROFILES, so a run over many cards never re-parses the same
    image and never parses an unbounded number of them.
    """

    def __init__(self, mf, *, main_base):
        self._mf = mf
        self.main_base = main_base
        self._modules = get_modules(mf)
        self._regions = enumerate_captured_regions(mf)
        self._segments = enumerate_captured_segments(mf)
        self._iat_reader = None
        self._profiles = {}          # base -> PeImageProfile | None
        self._iat = {}               # base -> IatParseResult | None
        self._main_correlation = _UNSET
        # Why a profile is absent, keyed by base: "cap_reached" (the
        # per-invocation profile budget was spent before this module) or
        # "unreadable" (the header could not be read or decoded). A base
        # with a profile is absent from this map.
        self._absent_reason = {}
        # VA -> (VaLocation, section_cap_reached), memoised across every
        # card's branch-target and IAT-thunk resolution -- most thunks of
        # one DLL land in the same handful of modules, and the same
        # `iat_raw` is reused by every card in the main image. The cache is
        # valid only against the RegionEvidence it was built with;
        # `_memo_region` pins that, and the memo is dropped if a different
        # one is ever passed.
        self._location_memo = {}
        self._memo_region = None

    @classmethod
    def from_dump(cls, mf, image_base_hex: "str | None") -> "PeProfileCache":
        base = None
        if image_base_hex:
            try:
                base = int(image_base_hex, 16)
            except (TypeError, ValueError):
                base = None
        return cls(mf, main_base=base)

    @property
    def modules(self):
        return self._modules

    @property
    def region_views(self):
        return self._regions.views

    @property
    def regions_lossy(self) -> bool:
        return bool(self._regions.skipped)

    @property
    def segments_lossy(self) -> bool:
        return bool(self._segments.skipped)

    def _span_read(self, addr: int, size: int) -> bytes:
        return read_region_spanning(self._mf, addr, size)

    def _build_profile(self, base: int, *, source_kind, source_identity):
        requested = VirtualRange(base, PE_HEADER_READ_MAX)
        try:
            capture = capture_of(self._mf, requested)
        except Exception:
            capture = None
        try:
            return collect_pe_image_profile(
                self._span_read, base, source_kind=source_kind,
                source_identity=source_identity, capture=capture,
                requested_stage=PeStage.SECTIONS)
        except Exception:
            return None

    def main_profile(self):
        if self.main_base is None:
            return None
        if self.main_base not in self._profiles:
            self._profiles[self.main_base] = self._build_profile(
                self.main_base, source_kind=SourceKind.PEB_IMAGE_BASE,
                source_identity="peb")
        return self._profiles[self.main_base]

    def main_correlation(self):
        if self._main_correlation is _UNSET:
            profile = self.main_profile()
            self._main_correlation = None
            if profile is not None:
                try:
                    module_list_image = ModuleListImage.at_base(
                        self._modules, profile.actual_base)
                    self._main_correlation = correlate_main_image(
                        profile, regions=self._regions, segments=self._segments,
                        module_list_image=module_list_image)
                except Exception:
                    self._main_correlation = None
        return self._main_correlation

    def profile_at_base(self, base: "int | None"):
        if base is None:
            return None
        if base == self.main_base:
            profile = self.main_profile()
            if profile is None:
                self._absent_reason.setdefault(base, "unreadable")
            return profile
        if base in self._profiles:
            return self._profiles[base]
        if len(self._profiles) >= MAX_MODULE_PROFILES:
            self._absent_reason.setdefault(base, "cap_reached")
            return None
        index = None
        for position, module in enumerate(self._modules):
            if getattr(module, "baseaddress", None) == base:
                index = position
                break
        self._profiles[base] = self._build_profile(
            base, source_kind=SourceKind.MODULE_LIST_ENTRY,
            source_identity=index if index is not None else 0)
        if self._profiles[base] is None:
            self._absent_reason.setdefault(base, "unreadable")
        return self._profiles[base]

    def profile_absent_reason(self, base: "int | None") -> "str | None":
        """Why the module at ``base`` has no PE profile: ``"cap_reached"``
        (the per-invocation profile budget was spent first) or
        ``"unreadable"`` (its header could not be read or decoded).
        ``None`` when a profile is available or ``base`` was never asked
        for."""
        if base is not None and base in self._profiles and self._profiles[base] is not None:
            return None
        return self._absent_reason.get(base)

    def module_at(self, addr: "int | None"):
        """``(module, base, profile)`` for the loaded module whose range
        holds ``addr``, or ``(None, None, None)``."""
        if addr is None or not self._modules:
            return None, None, None
        module = addr_to_module(addr, self._modules)
        if module is None:
            return None, None, None
        base = getattr(module, "baseaddress", None)
        if not isinstance(base, int):
            return module, None, None
        return module, base, self.profile_at_base(base)

    def iat_at_base(self, base: "int | None"):
        if base is None:
            return None
        if base in self._iat:
            return self._iat[base]
        profile = self.profile_at_base(base)
        if profile is None:
            self._iat[base] = None
            return None
        directories = tuple(
            (descriptor.value if descriptor.value is not None else 0,
             descriptor.size if descriptor.size is not None else 0)
            for descriptor in profile.directories)
        pe_for_iat = {
            "data_directories": directories,
            "declared_directory_count": profile.declared_directory_count,
            "is_pe32_plus": profile.is_pe32_plus,
        }
        if self._iat_reader is None:
            self._iat_reader = clamped_reader(self._mf)
        try:
            self._iat[base] = parse_iat(self._iat_reader, base, pe_for_iat)
        except Exception:
            self._iat[base] = None
        return self._iat[base]

    def iat_directory_range(self, base: "int | None") -> "tuple[int, int] | None":
        """The mapped ``[start, end)`` VA span of the IAT data directory of
        the module at ``base``, or ``None`` when it is not decodable -- the
        bound an indirect memory slot must fall in to be a proven IAT
        call."""
        profile = self.profile_at_base(base)
        if profile is None:
            return None
        descriptor = profile.directory(_IAT_DIRECTORY_INDEX)
        if descriptor.value is None or not descriptor.size:
            return None
        start = base + descriptor.value
        return start, start + descriptor.size


# ── process-wide: pe_context ───────────────────────────────────────────

def collect_pe_context(pe_cache: PeProfileCache) -> ReportPeContext:
    """The main image's identity and the correlation layer's tally and
    conflicts -- one per `--report` invocation.

    Identity is the canonical PE profile's own decoded values, and every
    observation is the pure correlation layer's, so a report and
    `--process` can never disagree about the same dump. A `conflict`
    observation is a disagreement between two captured facts and never a
    maliciousness finding."""
    section_kwargs = dict(name="pe_context", scope=ENRICHMENT_SCOPE_PROCESS,
                          cap=MAX_PE_CONFLICTS,
                          provenance=("pe_profile", "pe_correlation"))
    profile = pe_cache.main_profile()
    decoded = profile is not None and any(value is not None for value in (
        profile.machine, profile.size_of_image, profile.address_of_entry_point,
        profile.time_date_stamp))
    if not decoded:
        limitation = ("no image base resolved from the PEB: the main image was not located"
                      if pe_cache.main_base is None
                      else "the main image PE header could not be read from captured memory")
        return ReportPeContext(
            section=EnrichmentSection(status=ENRICHMENT_MISSING, total=None, included=0,
                                      truncated=False, limitations=(limitation,),
                                      **section_kwargs),
            image_base=hex_address(pe_cache.main_base), preferred_image_base=None,
            machine=None, machine_name=None, time_date_stamp=None, size_of_image=None,
            entry_point_rva=None, entry_point_va=None, section_count=None,
            pe32_plus=None, module_match=None,
            consistent_count=0, conflict_count=0, unavailable_count=0)

    correlation = pe_cache.main_correlation()
    limitations = []
    if profile.state != ComponentState.COMPLETE:
        limitations.append(_bounded_text(
            f"the PE header acquisition is {profile.state.value}: not every header "
            f"structure was fully read")[0])
    if pe_cache.regions_lossy or pe_cache.segments_lossy:
        limitations.append(
            "the region or segment table dropped a descriptor: a correlation "
            "observation that would have needed it is unavailable rather than decided")

    conflicts = correlation.conflicts() if correlation is not None else ()
    kept = conflicts[:MAX_PE_CONFLICTS]
    observations = tuple(
        ReportPeObservation(
            name=observation.name, state="conflict", reason=observation.reason,
            sources=tuple(observation.sources),
            operands={key: value for key, value in observation.operands.items()})
        for observation in kept)
    coverage = correlation.coverage if correlation is not None else None
    consistent_count = coverage.consistent if coverage is not None else 0
    conflict_count = coverage.conflict if coverage is not None else 0
    unavailable_count = coverage.unavailable if coverage is not None else 0

    if correlation is None:
        limitations.append(
            "the main image could not be correlated with process memory evidence")
        status = ENRICHMENT_PARTIAL
    else:
        status = ENRICHMENT_COMPLETE if not limitations else ENRICHMENT_PARTIAL

    module_match = None
    if correlation is not None:
        if ModuleListImage.at_base(pe_cache.modules, profile.actual_base) is not None:
            module_match = "resolved"
        elif pe_cache.modules:
            module_match = "unregistered"
        else:
            module_match = "unavailable"

    machine_name = _bounded_optional(profile.machine_name)[0]
    entry_va = (hex_address(correlation.entry_point.entry_point_va)
                if correlation is not None else None)
    return ReportPeContext(
        section=EnrichmentSection(
            status=status, total=conflict_count, included=len(observations),
            truncated=len(observations) < conflict_count,
            limitations=tuple(limitations), **section_kwargs),
        image_base=hex_address(profile.actual_base),
        preferred_image_base=hex_address(profile.preferred_image_base),
        machine=profile.machine, machine_name=machine_name,
        time_date_stamp=profile.time_date_stamp, size_of_image=profile.size_of_image,
        entry_point_rva=profile.address_of_entry_point, entry_point_va=entry_va,
        section_count=profile.number_of_sections, pe32_plus=profile.is_pe32_plus,
        module_match=module_match, consistent_count=consistent_count,
        conflict_count=conflict_count, unavailable_count=unavailable_count,
        observations=observations)


# ── card-scoped: anchor_pe_context ─────────────────────────────────────

def _classify_anchor(loc, profile) -> "tuple[str, bool]":
    """``(classification, needed_a_missing_profile)`` for one resolved
    anchor location. The bool is True only when the anchor is inside a
    loaded module whose PE profile was not available to place it finer."""
    if not loc.in_module:
        if loc.in_region:
            return "private", False
        return "unresolved", False
    rva = loc.module_rva
    if profile is None or rva is None:
        return "module", True
    size_of_headers = profile.size_of_headers
    size_of_image = profile.size_of_image
    if size_of_headers is not None and rva < size_of_headers:
        return "headers", False
    for index in (_IMPORT_DIRECTORY_INDEX, _IAT_DIRECTORY_INDEX):
        descriptor = profile.directory(index)
        if (descriptor.value is not None and descriptor.size
                and descriptor.value <= rva < descriptor.value + descriptor.size):
            return "import_iat", False
    reloc = profile.directory(_BASERELOC_DIRECTORY_INDEX)
    if (reloc.value is not None and reloc.size
            and reloc.value <= rva < reloc.value + reloc.size):
        return "relocation", False
    if loc.section_index is not None:
        return ("code" if loc.section_executable else "data"), False
    if size_of_image is not None and rva >= size_of_image:
        return "outside_image", False
    return "unmapped", False


def collect_anchor_pe_context(pe_cache: PeProfileCache, *, anchor_address,
                              region_evidence) -> "ReportAnchorPeContext | None":
    """This card's anchor placed against the PE image that owns it:
    headers, code, data, import/IAT, relocation, unmapped, or -- when no
    module owns it -- private or unresolved. A section's declared R/W/X
    versus the live region protection is surfaced as an observation, never
    a verdict."""
    if anchor_address is None:
        return None
    section_kwargs = dict(name="anchor_pe_context", scope=ENRICHMENT_SCOPE_CARD,
                          cap=1, provenance=("pe_profile", "modules", "memory_info"))
    region_views = region_evidence.views if region_evidence is not None else ()
    _module, module_base, profile = pe_cache.module_at(anchor_address)
    loc = resolve_va_location(anchor_address, modules=pe_cache.modules,
                              region_views=region_views, module_profile=profile)
    classification, needed_profile = _classify_anchor(loc, profile)

    if classification == "unresolved":
        return ReportAnchorPeContext(
            section=EnrichmentSection(
                status=ENRICHMENT_MISSING, total=None, included=0, truncated=False,
                limitations=("no loaded module and no captured region place this anchor",),
                **section_kwargs),
            anchor_address=hex_address(anchor_address),
            classification="unresolved", registration=loc.registration)

    module_owner, module_owner_cut = _bounded_optional(loc.module_name)
    section_name, section_name_cut = _bounded_optional(loc.section_name)
    declared_x = loc.section_executable
    live = loc.region_protection
    matches = None
    if declared_x is not None and live is not None:
        matches = declared_x == ("EXECUTE" in live)

    limitations = []
    status = ENRICHMENT_COMPLETE
    if needed_profile:
        status = ENRICHMENT_PARTIAL
        if pe_cache.profile_absent_reason(module_base) == "cap_reached":
            limitations.append(
                f"the owning module was not among the first {MAX_MODULE_PROFILES} whose "
                f"PE profile this run built: the anchor could not be placed within a "
                f"section")
        else:
            limitations.append(
                "the owning module's PE header could not be read: the anchor could not "
                "be placed within a section")
    if (region_evidence is not None and region_evidence.incomplete
            and loc.region_base is None):
        status = ENRICHMENT_PARTIAL
        limitations += list(region_evidence.skipped_limitation())

    return ReportAnchorPeContext(
        section=EnrichmentSection(
            status=status, total=1, included=1, truncated=False,
            limitations=tuple(limitations), **section_kwargs),
        anchor_address=hex_address(anchor_address),
        classification=classification, registration=loc.registration,
        module_owner=module_owner, module_owner_truncated=module_owner_cut,
        module_base=hex_address(loc.module_base), module_rva=loc.module_rva,
        section_index=loc.section_index, section_name=section_name,
        section_name_truncated=section_name_cut,
        declared_readable=loc.section_readable, declared_writable=loc.section_writable,
        declared_executable=loc.section_executable, live_protection=live,
        protection_matches_declared=matches,
        region_base=hex_address(loc.region_base), region_type=loc.region_type)


# ── card-scoped: instruction_context ───────────────────────────────────

# COFF ``Machine`` to the instruction set this module decodes. Only the
# two x86 widths are here: an ``I386`` or ``AMD64`` image fixes the
# decoder unambiguously. A concrete non-x86 machine is a determined
# "cannot decode"; a machine that is absent or unknown leaves the
# architecture undetermined and other signals are consulted.
_MACHINE_TO_ARCH = {0x014C: "x86", 0x8664: "x64"}


def _sysinfo_arch(mf) -> "str | None":
    sysinfo = getattr(mf, "sysinfo", None)
    raw = getattr(sysinfo, "ProcessorArchitecture", None) if sysinfo is not None else None
    name = getattr(raw, "name", None)
    if name == "AMD64":
        return "x64"
    if name == "INTEL":
        return "x86"
    return None


def _instruction_arch(*, module_profile, thread_ip_reg, mf, main_profile,
                      wow64_hint) -> "tuple[str | None, bool]":
    """``(architecture, machine_is_non_x86)`` for the code at the chosen
    anchor.

    Signals are consulted strongest first:

    1. the owning module's COFF ``Machine`` -- a direct statement of this
       code's width; a concrete non-x86 value (ARM, ARMNT, ARM64, IA64,
       EBC) sets ``machine_is_non_x86``, a determined "cannot decode";
    2. a WOW64 thread context -- 32-bit user code whatever the host is;
    3. the **main image** ``Machine`` -- the process's own code width. It
       is checked before the dump SystemInfo, which reports the *host*
       architecture: a WOW64 process on an x64 host has an ``I386`` main
       image and an ``AMD64`` SystemInfo, and the process runs x86;
    4. the chosen anchor thread's context flavour (``RIP`` vs ``EIP``);
    5. the dump SystemInfo.

    The PE32/PE32+ format width is never consulted; an ARM64 image is
    PE32+."""
    module_machine = (getattr(module_profile, "machine", None)
                      if module_profile is not None else None)
    if module_machine in _MACHINE_TO_ARCH:
        return _MACHINE_TO_ARCH[module_machine], False
    if isinstance(module_machine, int) and module_machine != 0:
        return None, True
    if wow64_hint is True:
        return "x86", False
    main_machine = (getattr(main_profile, "machine", None)
                    if main_profile is not None else None)
    if main_machine in _MACHINE_TO_ARCH:
        return _MACHINE_TO_ARCH[main_machine], False
    if isinstance(main_machine, int) and main_machine != 0:
        return None, True
    if thread_ip_reg == "RIP":
        return "x64", False
    if thread_ip_reg == "EIP":
        return "x86", False
    sysinfo_arch = _sysinfo_arch(mf)
    if sysinfo_arch is not None:
        return sysinfo_arch, False
    return None, False


def _deref_slot(mf, slot: "int | None", arch: "str | None") -> "int | None":
    if slot is None:
        return None
    width = 4 if arch == "x86" else 8
    data = read_region_spanning(mf, slot, width)
    if not data or len(data) < width:
        return None
    return int.from_bytes(data[:width], "little")


def _iat_slot_symbols(iat_raw) -> dict:
    """``{slot_va: (dll, symbol)}`` for every parsed IAT entry that has a
    slot address -- the cross-link an instruction-window IAT call carries
    for its human-readable name."""
    symbols = {}
    if iat_raw is None:
        return symbols
    for entry in iat_raw.entries:
        if entry.iat_slot_va is not None and entry.iat_slot_va not in symbols:
            symbols[entry.iat_slot_va] = (entry.dll, entry.symbol)
    return symbols


# How many distinct target VAs one invocation memoises. A run touches a
# few thousand at most (thunk targets, branch destinations); past this
# the memo stops growing and later lookups resolve uncached rather than
# retain an unbounded map.
_LOCATION_MEMO_CAP = 8192


def _resolve_target(pe_cache: PeProfileCache, va: "int | None", region_evidence):
    """``(VaLocation | None, section_cap_reached)`` for one target VA,
    memoised on ``pe_cache`` across every card. The bool is True when the
    target is inside a loaded module whose PE profile was not built
    because the per-invocation profile budget was already spent -- so its
    section could not be resolved."""
    if va is None:
        return None, False
    memo = pe_cache._location_memo
    if pe_cache._memo_region is None:
        pe_cache._memo_region = region_evidence
    elif pe_cache._memo_region is not region_evidence:
        # A different region view invalidates every cached resolution.
        memo.clear()
        pe_cache._memo_region = region_evidence
    cached = memo.get(va)
    if cached is not None:
        return cached
    _module, base, profile = pe_cache.module_at(va)
    region_views = region_evidence.views if region_evidence is not None else ()
    loc = resolve_va_location(va, modules=pe_cache.modules,
                              region_views=region_views, module_profile=profile)
    capped = (loc.in_module and loc.section_index is None
              and pe_cache.profile_absent_reason(base) == "cap_reached")
    result = (loc, capped)
    if len(memo) < _LOCATION_MEMO_CAP:
        memo[va] = result
    return result


def _branch_target_record(insn_address: int, kind: str, target: "int | None",
                          resolved: "int | None", loc, symbol,
                          iat_uncertain: bool = False) -> ReportBranchTarget:
    module_owner, module_owner_cut = _bounded_optional(loc.module_name if loc else None)
    section_name, section_name_cut = _bounded_optional(loc.section_name if loc else None)
    iat_symbol = None
    iat_symbol_cut = False
    if kind == "iat_slot" and symbol is not None:
        dll, name = symbol
        iat_symbol, iat_symbol_cut = _bounded_optional(name or dll)
    return ReportBranchTarget(
        instruction_address=hex_address(insn_address), kind=kind,
        target_address=hex_address(target),
        resolved_target_address=(hex_address(resolved) if kind != "direct" else None),
        module_owner=module_owner, module_owner_truncated=module_owner_cut,
        section_name=section_name, section_name_truncated=section_name_cut,
        region_type=(loc.region_type if loc else None),
        registration=(loc.registration if loc else None),
        iat_symbol=iat_symbol, iat_symbol_truncated=bool(iat_symbol_cut),
        iat_classification_uncertain=bool(iat_uncertain and kind == "indirect_memory"))


def collect_instruction_context(pe_cache: PeProfileCache, *, mf, anchor_candidates,
                                region_evidence, iat_raw, instruction_module_base,
                                instruction_module_profile, thread_ip_reg, wow64_hint
                                ) -> "tuple[ReportInstructionContext | None, tuple]":
    """``(record, all_iat_slot_vas)`` for this card's bounded instruction
    window and its resolved branch targets.

    `anchor_candidates` is ``[(source_name, address), ...]`` in priority
    order, already filtered to anchors correlated with this card. The
    window is read at the first, and its IAT-directory range and
    imported-symbol names come from `instruction_module_profile` /
    `iat_raw` -- the module that owns that anchor address -- so the window
    and the IAT it is checked against are the same image. The decode
    architecture is that module's `Machine` where it has one, falling
    back to the anchor thread's context flavour (`thread_ip_reg`), then
    the dump SystemInfo, then the main image -- so an anchor in unbacked
    private code is still decoded on an x64 dump.

    The second element is every IAT slot a window branch targets, bounded
    by the instruction cap but taken before the branch-target retention
    cap, so `collect_iat_correlation` never misses an
    instruction-correlated slot the public `branch_targets` list dropped.

    `decoder_state` is `decoded`, `not_run` (no captured bytes),
    `unavailable` (no decoder installed), `unsupported_arch` (a determined
    non-x86 machine), `arch_undetermined` (no signal fixed the
    architecture), or `decode_error` (an invalid opcode mid-stream); every
    value but `decoded` makes the section `partial`. A window the byte cap
    or the end of the capture cut short is also `partial`, with `total`
    null. A direct branch resolves to its destination; an indirect branch
    through a fixed memory slot resolves the slot and the pointer in it;
    an indirect branch through a register is reported unresolved. Nothing
    here names a function, an argument, or a call stack."""
    if not anchor_candidates:
        return None, ()
    section_kwargs = dict(name="instruction_context", scope=ENRICHMENT_SCOPE_CARD,
                          cap=MAX_INSTRUCTION_WINDOW,
                          provenance=("report_content_scan", "disasm", "pe_profile"))
    source_name, anchor = anchor_candidates[0]
    arch, non_x86_machine = _instruction_arch(
        module_profile=instruction_module_profile, thread_ip_reg=thread_ip_reg, mf=mf,
        main_profile=pe_cache.main_profile(), wow64_hint=wow64_hint)
    # The window is MAX_DECODE_BYTES; the extra bytes are lookahead so a
    # legitimate instruction the byte cap cuts can be told apart from an
    # invalid opcode, and so the region-has-more case can be distinguished
    # from a window that exactly fills the cap.
    raw = read_region_spanning(mf, anchor, MAX_DECODE_BYTES + MAX_INSTRUCTION_LENGTH)
    window_len = min(len(raw), MAX_DECODE_BYTES)
    region_has_more = len(raw) > MAX_DECODE_BYTES

    if not raw:
        record = ReportInstructionContext(
            section=EnrichmentSection(
                status=ENRICHMENT_MISSING, total=None, included=0, truncated=False,
                limitations=(_bounded_text(
                    f"no bytes were captured at the {source_name} anchor "
                    f"0x{anchor:x}")[0],), **section_kwargs),
            anchor_source=source_name, anchor_address=hex_address(anchor),
            architecture=arch, decoder_state="not_run", window_base=hex_address(anchor),
            bytes_read=0)
        return record, ()

    result = decode_window(code=raw, base_va=anchor, architecture=arch,
                           input_truncated=region_has_more)
    if result.availability is DisasmAvailability.UNAVAILABLE:
        decoder_state = "unavailable"
    elif arch is None:
        decoder_state = "unsupported_arch" if non_x86_machine else "arch_undetermined"
    elif result.stopped_reason == "decode_error":
        decoder_state = "decode_error"
    elif result.stopped_reason == "undecoded_tail":
        decoder_state = "undecoded_tail"
    else:
        decoder_state = "decoded"

    instructions = []
    anchor_marked = False
    for insn in result.instructions:
        is_anchor = (not anchor_marked
                     and insn.address <= anchor < insn.address + insn.size)
        anchor_marked = anchor_marked or is_anchor
        text = (insn.mnemonic + (" " + insn.operands if insn.operands else "")).strip()
        bounded, cut = _bounded_text(text or "(undecoded)")
        instructions.append(ReportDecodedInstruction(
            address=hex_address(insn.address), size=insn.size,
            text=bounded, text_truncated=bool(
                cut or insn.mnemonic_truncated or insn.operands_truncated),
            is_call=insn.is_call, is_jump=insn.is_jump, is_return=insn.is_return,
            is_anchor=is_anchor, branch_kind=insn.branch_kind.value))

    iat_range = pe_cache.iat_directory_range(instruction_module_base)
    slot_symbols = _iat_slot_symbols(iat_raw)
    # Whether a slot NOT in the parsed set can be shown to be outside the
    # IAT: the module's IAT directory descriptor was fully read (its
    # bounds are known, even if empty) or a parsed range is in hand.
    # Parsed entries prove membership one slot at a time -- a partial IAT
    # walk names some slots without bounding the table -- so `slot_symbols`
    # is NOT evidence of the bounds.
    iat_descriptor_state = (
        instruction_module_profile.directory(_IAT_DIRECTORY_INDEX).state
        if instruction_module_profile is not None else None)
    iat_bounds_known = (iat_range is not None
                        or iat_descriptor_state in (ComponentState.COMPLETE,
                                                    ComponentState.DECLARED_ABSENT))
    all_targets = []
    all_iat_slot_vas = []
    target_section_capped = False
    iat_classification_uncertain = False
    for insn in result.instructions:
        kind = insn.branch_kind
        if kind is BranchKind.DIRECT:
            loc, capped = _resolve_target(pe_cache, insn.direct_target_va, region_evidence)
            target_section_capped = target_section_capped or capped
            all_targets.append(_branch_target_record(
                insn.address, "direct", insn.direct_target_va, None, loc, None))
        elif kind is BranchKind.INDIRECT_SLOT:
            slot = insn.slot_target_va
            pointer = _deref_slot(mf, slot, arch)
            in_iat = (slot in slot_symbols
                      or (iat_range is not None and iat_range[0] <= slot < iat_range[1]))
            slot_uncertain = (not in_iat and not iat_bounds_known
                              and instruction_module_base is not None)
            iat_classification_uncertain = iat_classification_uncertain or slot_uncertain
            target_kind = "iat_slot" if in_iat else "indirect_memory"
            if in_iat:
                all_iat_slot_vas.append(slot)
            loc, capped = _resolve_target(pe_cache, pointer, region_evidence)
            target_section_capped = target_section_capped or capped
            symbol = slot_symbols.get(slot) if target_kind == "iat_slot" else None
            all_targets.append(_branch_target_record(
                insn.address, target_kind, slot, pointer, loc, symbol,
                iat_uncertain=slot_uncertain))
        elif kind is BranchKind.INDIRECT_REGISTER and (insn.is_call or insn.is_jump):
            all_targets.append(ReportBranchTarget(
                instruction_address=hex_address(insn.address), kind="indirect_register"))

    kept_targets = tuple(all_targets[:MAX_BRANCH_TARGETS])

    limitations = []
    if target_section_capped:
        limitations.append(
            f"a branch target's owning module was not among the first "
            f"{MAX_MODULE_PROFILES} whose PE profile this run built, so its section "
            f"could not be resolved")
    if iat_classification_uncertain:
        limitations.append(
            "the owning module's IAT directory bounds and import table could not be "
            "read: an indirect memory branch here is not confirmed to be outside the IAT")
    if decoder_state == "unavailable":
        limitations.append(
            "no disassembler is installed (pip install dumpex[disasm]): the instruction "
            "window was not decoded")
    elif decoder_state == "unsupported_arch":
        machine = getattr(instruction_module_profile, "machine", None)
        machine_name = getattr(instruction_module_profile, "machine_name", None)
        if machine_name:
            named = f" (machine {machine_name})"
        elif isinstance(machine, int):
            named = f" (machine 0x{machine:x})"
        else:
            named = ""
        limitations.append(
            f"the owning image's architecture{named} is not x86 or x64: the window was "
            f"not decoded")
    elif decoder_state == "arch_undetermined":
        limitations.append(
            "the instruction-set architecture could not be determined: the anchor is in "
            "no PE image and the dump carries no usable thread context or SystemInfo")
    elif decoder_state == "decode_error":
        tail = result.window_bytes - result.bytes_decoded
        if region_has_more and 0 < tail < MAX_DECODE_BYTES:
            limitations.append(_bounded_text(
                f"the last {tail} byte(s) before the {MAX_DECODE_BYTES}-byte cap did not "
                f"decode: an invalid opcode, or an instruction the cap cut short")[0])
        else:
            limitations.append(_bounded_text(
                f"the decoder stopped at an invalid opcode {result.bytes_decoded} byte(s) "
                f"into the window")[0])

    # The window did not cover every available byte: the byte cap, or a
    # final instruction the window cut short. The count of instructions
    # past it is unknown, so `total` is null and the section is `partial`
    # -- the same honest treatment as the instruction cap.
    window_cut = region_has_more or result.window_truncated
    if result.stopped_reason == "undecoded_tail":
        limitations.append(_bounded_text(
            f"the last {result.window_bytes - result.bytes_decoded} byte(s) of the "
            f"captured run did not decode: an invalid opcode, or an instruction the "
            f"capture cut short")[0])
    elif region_has_more:
        limitations.append(
            f"the region holds more than the {MAX_DECODE_BYTES}-byte decode window: "
            f"instructions past it were not evaluated")
    elif window_len < MAX_DECODE_BYTES:
        limitations.append(_bounded_text(
            f"the captured run ended after {window_len} byte(s): the window is the whole "
            f"of it")[0])

    if result.stopped_reason == "insn_cap":
        total, truncated, status = None, False, ENRICHMENT_PARTIAL
        limitations.append(
            f"the instruction window stopped at the cap of {MAX_INSTRUCTION_WINDOW} "
            f"instruction(s)")
    elif decoder_state != "decoded" or window_cut:
        # Nothing decoded, an incomplete decode, or a window the byte cap
        # or end of capture cut -- the eligible instruction count is not
        # determinable.
        total, truncated, status = None, False, ENRICHMENT_PARTIAL
    else:
        total, truncated = len(instructions), False
        status = (ENRICHMENT_COMPLETE
                  if (not target_section_capped and not iat_classification_uncertain)
                  else ENRICHMENT_PARTIAL)

    record = ReportInstructionContext(
        section=EnrichmentSection(
            status=status, total=total, included=len(instructions),
            truncated=truncated, limitations=tuple(limitations), **section_kwargs),
        anchor_source=source_name, anchor_address=hex_address(anchor),
        architecture=arch, decoder_state=decoder_state,
        window_base=hex_address(anchor), bytes_read=window_len,
        branch_targets_total=len(all_targets),
        branch_targets_truncated=len(kept_targets) < len(all_targets),
        instructions=tuple(instructions), branch_targets=kept_targets)
    return record, tuple(dict.fromkeys(all_iat_slot_vas))


# ── card-scoped: iat_correlation ───────────────────────────────────────

_IAT_REASON_PRIORITY = (
    "instruction_correlated", "slot_out_of_bounds",
    "target_private_executable", "target_unregistered",
)


def _primary_iat_reason(reasons) -> str:
    for candidate in _IAT_REASON_PRIORITY:
        if candidate in reasons:
            return candidate
    return reasons[0]


def collect_iat_correlation(pe_cache: PeProfileCache, *, anchor_module, anchor_module_base,
                            iat_raw, region_evidence, instruction_slot_vas
                            ) -> "ReportIatCorrelation | None":
    """This card's bounded view of the anchor module's import address
    table: the module summary, plus only the slots that a branch in this
    card's instruction window targets or whose live thunk target is
    unusual enough to be an investigation lead. A private, unregistered,
    or out-of-bounds thunk target is a lead, never a verdict dimension."""
    if anchor_module_base is None:
        return None
    section_kwargs = dict(name="iat_correlation", scope=ENRICHMENT_SCOPE_CARD,
                          cap=MAX_IAT_CORRELATED_ENTRIES, provenance=("pe_profile", "iat"))
    module_owner, module_owner_cut = _bounded_optional(
        getattr(anchor_module, "name", None) if anchor_module is not None else None)

    if iat_raw is None:
        return ReportIatCorrelation(
            section=EnrichmentSection(
                status=ENRICHMENT_MISSING, total=None, included=0, truncated=False,
                limitations=("the anchor module's PE profile or import table could not "
                             "be read",), **section_kwargs),
            module_owner=module_owner, module_owner_truncated=module_owner_cut,
            module_base=hex_address(anchor_module_base), dll_count=None, entry_count=None,
            import_directory_present=None, iat_directory_present=None)

    # Three independent kinds of incompleteness:
    #  - population_incomplete: a descriptor/thunk read failed, the table
    #    was unterminated or cyclic, or a walk cap was hit -- slots may be
    #    unenumerated, so the eligible count is not determinable;
    #  - metadata_incomplete: only an import symbol NAME could not be read,
    #    which happens after the slot, thunk, and target are resolved -- no
    #    slot is missed and the eligible count is exact;
    #  - directory_array_incomplete: the data-directory array itself was
    #    not fully read, leaving only the IAT directory BOUNDS undetermined.
    population_incomplete = any((
        iat_raw.directory_read_failed, iat_raw.directory_short_read,
        iat_raw.descriptor_read_failed_count, iat_raw.descriptor_short_read_count,
        iat_raw.thunk_read_failed_count, iat_raw.thunk_short_read_count,
        iat_raw.unterminated_table, iat_raw.cycle_detected,
        iat_raw.bounds_exceeded, iat_raw.truncation is not None))
    metadata_incomplete = bool(iat_raw.name_read_failed_count)
    directory_array_incomplete = bool(iat_raw.directory_table_incomplete)
    incomplete = population_incomplete or metadata_incomplete or directory_array_incomplete
    limitations = []

    # `import_directory_present` is three-valued: True (present), False
    # (positively absent), None (the directory array itself was not
    # readable, so presence is undetermined).
    if iat_raw.import_directory_present is False and not iat_raw.entries:
        # A module with no import directory has no slots to walk or to
        # miss -- only the IAT directory bounds may still be undetermined.
        directory_note = (["the data-directory array was not fully read: the IAT "
                           "directory bounds are undetermined"]
                          if directory_array_incomplete else [])
        return ReportIatCorrelation(
            section=EnrichmentSection(
                status=ENRICHMENT_COMPLETE, total=0, included=0, truncated=False,
                limitations=tuple(["the module declares no import directory"]
                                  + directory_note),
                **section_kwargs),
            module_owner=module_owner, module_owner_truncated=module_owner_cut,
            module_base=hex_address(anchor_module_base),
            dll_count=iat_raw.dll_count, entry_count=iat_raw.entry_count,
            import_directory_present=iat_raw.import_directory_present,
            iat_directory_present=iat_raw.table_present)

    if iat_raw.import_directory_present is None and not iat_raw.entries:
        return ReportIatCorrelation(
            section=EnrichmentSection(
                status=ENRICHMENT_PARTIAL, total=None, included=0, truncated=False,
                limitations=("the import directory array was not readable: whether the "
                             "module declares imports is undetermined",),
                **section_kwargs),
            module_owner=module_owner, module_owner_truncated=module_owner_cut,
            module_base=hex_address(anchor_module_base),
            dll_count=iat_raw.dll_count, entry_count=iat_raw.entry_count,
            import_directory_present=None, iat_directory_present=iat_raw.table_present)

    if population_incomplete:
        limitations.append(
            "the IAT walk did not complete: an unusual slot named only in the unread "
            "part could not be evaluated")
    if metadata_incomplete:
        limitations.append(
            f"{iat_raw.name_read_failed_count} import symbol name(s) could not be read: "
            f"the slot and its target are resolved, only the name is missing")
    if directory_array_incomplete:
        limitations.append(
            "the data-directory array was not fully read: the IAT directory bounds are "
            "undetermined")

    slot_set = set(instruction_slot_vas or ())
    eligible = []
    seen_slots = set()
    target_section_capped = False
    for entry in iat_raw.entries:
        if entry.iat_slot_va is not None and entry.iat_slot_va in seen_slots:
            continue
        loc, capped = _resolve_target(pe_cache, entry.resolved_target_va, region_evidence)
        target_section_capped = target_section_capped or capped
        reasons = []
        if entry.iat_slot_va is not None and entry.iat_slot_va in slot_set:
            reasons.append("instruction_correlated")
        if entry.slot_in_bounds is False:
            reasons.append("slot_out_of_bounds")
        if loc is not None:
            protection = loc.region_protection or ""
            region_type = loc.region_type or ""
            if (loc.registration != "registered" and "PRIVATE" in region_type
                    and "EXECUTE" in protection):
                reasons.append("target_private_executable")
            if loc.registration == "unregistered" and "target_private_executable" not in reasons:
                reasons.append("target_unregistered")
        if not reasons:
            continue
        if entry.iat_slot_va is not None:
            seen_slots.add(entry.iat_slot_va)
        eligible.append((entry, loc, reasons))

    kept = eligible[:MAX_IAT_CORRELATED_ENTRIES]
    entries = []
    for entry, loc, reasons in kept:
        primary = _primary_iat_reason(reasons)
        also = tuple(reason for reason in dict.fromkeys(reasons) if reason != primary)
        dll, dll_cut = _bounded_optional(entry.dll)
        symbol, symbol_cut = _bounded_optional(entry.symbol)
        target_owner, target_owner_cut = _bounded_optional(loc.module_name if loc else None)
        target_section, target_section_cut = _bounded_optional(
            loc.section_name if loc else None)
        entries.append(ReportIatCorrelatedEntry(
            import_by=entry.import_by, selection_reason=primary, also_selected_for=also,
            dll=dll, dll_truncated=dll_cut, symbol=symbol, symbol_truncated=symbol_cut,
            ordinal=entry.ordinal, iat_slot_va=hex_address(entry.iat_slot_va),
            resolved_target_va=hex_address(entry.resolved_target_va),
            target_module_owner=target_owner,
            target_module_owner_truncated=target_owner_cut,
            target_section_name=target_section,
            target_section_name_truncated=target_section_cut,
            target_region_type=(loc.region_type if loc else None),
            target_registration=(loc.registration if loc else None)))

    if target_section_capped:
        limitations.append(
            f"a thunk target's owning module was not among the first "
            f"{MAX_MODULE_PROFILES} whose PE profile this run built, so its section "
            f"could not be resolved")
    # The eligible count is undeterminable when slots may be unenumerated
    # (`population_incomplete`) or when the IAT directory bounds are
    # unreadable (`directory_array_incomplete`) -- a slot whose
    # `slot_in_bounds` could not be checked might belong in the set via
    # `slot_out_of_bounds`. An unread symbol name and an unresolved target
    # section leave the count exact. When `total` is null, the known set
    # overrunning the cap still proves the retention cap dropped at least
    # that many, so `truncated` stays honest either way.
    total = (None if (population_incomplete or directory_array_incomplete)
             else len(eligible))
    truncated = len(entries) < len(eligible)
    status = (ENRICHMENT_PARTIAL if (incomplete or target_section_capped)
              else ENRICHMENT_COMPLETE)
    return ReportIatCorrelation(
        section=EnrichmentSection(
            status=status, total=total, included=len(entries), truncated=truncated,
            limitations=tuple(limitations), **section_kwargs),
        module_owner=module_owner, module_owner_truncated=module_owner_cut,
        module_base=hex_address(anchor_module_base),
        dll_count=iat_raw.dll_count, entry_count=iat_raw.entry_count,
        import_directory_present=iat_raw.import_directory_present,
        iat_directory_present=iat_raw.table_present, entries=tuple(entries))

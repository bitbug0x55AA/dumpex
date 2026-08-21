"""`--handles` command -- issue #42's collect/render/command vertical
slice over the frozen contract in
docs/recon_process_sysinfo_handles_contract.md §5.

Reports the handles a dump RECORDED AT CAPTURE TIME, read from its
`HandleDataStream`. Nothing here opens a process, queries a PID, or
touches live system state, and no console/JSON string may imply that it
does (§5.7).

`collect_handles()` reads the full `ParsedHandleDataStream` off
`mf.handles` rather than going through
`dumpex.core.memory.get_handles()`: that convenience view returns only
`.handles` (the list) and discards `.header`, and with it
`NumberOfDescriptors` -- the one value `HANDLE_STREAM_TRUNCATED`'s
`affected_count` is derived from (§5.1.1 rule 5). A record builder
written against `get_handles()` could not emit that limitation at all,
so a dump whose descriptor array was cut short would silently report
fewer handles with a `complete` verdict.

`render_handles_console()` projects only the already-collected records
and CoverageReport -- it never touches `mf` (its signature has no `mf`
parameter), matching every other recon renderer's rule.

`cmd_handles()` is the one call that collects and renders in the usual
command shape; #43 wired it into argparse, and #98 wired `--verbose`
through to it.

Console verbosity is a PROJECTION and nothing else (#98): the
CommandResult `collect_handles()` returns is byte-identical whatever
`verbose` is, so `--json` always carries the complete normalized
inventory. The default console folds the low-context anonymous rows
listed in `_FOLDABLE_ANONYMOUS_TYPES` into per-type counts and says
exactly how many it folded; `--verbose` renders every record. Nothing is
ever removed from the records, the summary, or `by_type`.
"""
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.minidumpfile import MinidumpFile

from dumpex.core.memory import stream_failure, has_stream_directory
from dumpex.output.coverage import (
    build_coverage_report, EvaluationRequirement, SourceObservation, SourceState,
    CoverageLimitation, LimitationCode,
)
from dumpex.output.command_result import CommandResult
from dumpex.output.records import (
    HandleRecord, handle_name_display, hex_address,
)
from dumpex.ui.colors import BOLD, DIM, YELLOW, console_safe


_HANDLE_STREAM = MINIDUMP_STREAM_TYPE.HandleDataStream

_UINT64_MAX = 0xFFFFFFFFFFFFFFFF

# §5.5's five states, collapsed to the three the stream itself can be in
# (the other two are decided one level up, by how many descriptors
# normalized). Paired with the LimitationCode each one contributes if --
# and only if -- `handle_records` ends up ABSENT, so the state and the
# code it implies are chosen in exactly one place and can never drift
# apart. In the "parsed" state the only way the evaluation group can fire
# is case 3's total loss, which is why that state maps to
# HANDLES_ALL_DESCRIPTORS_INVALID.
_ABSENT_CODE_FOR_STREAM_STATE = {
    "absent": LimitationCode.HANDLES_UNAVAILABLE,
    "failed": LimitationCode.HANDLES_PARSE_FAILED,
    "parsed": LimitationCode.HANDLES_ALL_DESCRIPTORS_INVALID,
}

# The detail text for the one "failed" sub-case that has no parser
# exception behind it (see _stream_evidence below). Written here rather
# than composed at the call site so the two failure paths' wording stays
# side by side.
_UNPARSED_STREAM_DETAIL = (
    "the dump declares a HandleDataStream but no parsed stream is available")



def _stream_evidence(mf: MinidumpFile) -> "tuple[str, object, str | None]":
    """-> (state, parsed_stream_or_None, failure_detail_or_None) where
    state is "absent" (§5.5 case 1), "failed" (case 2), or "parsed"
    (cases 3-5).

    Absence of `mf.handles` alone cannot decide this: it is None both for
    a dump that never carried the stream and for one whose stream raised
    during `open_dump()`'s per-stream isolation. The recorded parser
    failure is consulted FIRST (a stream that raised is failed evidence
    even if something else later attached an object to `mf.handles` --
    presenting records built from it as a clean result is exactly the
    "do not present a clean zero-handle result" case #42 forbids), then
    the parsed object, and only then the dump's own directory table.

    That last check is what keeps case 1 a positive claim rather than an
    inference: a directory entry with neither a parsed stream nor a
    recorded failure means the stream was captured but never made it
    through the loader -- unreachable through today's `open_dump()`, but
    if it ever happens it is failed evidence, not "this dump was not
    captured with handle data". The two send an analyst to different next
    steps (§5.5 case 2), so this fails closed toward the honest one."""
    detail = stream_failure(mf, _HANDLE_STREAM)
    if detail is not None:
        return "failed", None, detail
    parsed = getattr(mf, "handles", None)
    if parsed is not None:
        return "parsed", parsed, None
    if has_stream_directory(mf, _HANDLE_STREAM):
        return "failed", None, _UNPARSED_STREAM_DETAIL
    return "absent", None, None


def _normalize_handle_value(raw) -> "int | None":
    """§5.2.2: the ONE field whose failure discards a descriptor. `bool`
    is rejected explicitly (it is an `int` subclass, so `True` would
    otherwise become handle 0x...01), as is anything outside `uint64` --
    a handle is the record's only identity and §5.4's sort key, and a
    record keyed by nothing identifies nothing."""
    if isinstance(raw, bool) or not isinstance(raw, int):
        return None
    if not 0 <= raw <= _UINT64_MAX:
        return None
    return raw


def _normalize_counter(raw) -> "int | None":
    """§5.2.2's "record kept" rule for the four fixed-width numeric
    fields: anything not a plain non-negative int becomes `null` in place
    rather than discarding the descriptor. These are read from the same
    fixed-size descriptor as the handle itself, so in practice they fail
    only together with the whole descriptor -- the mapping exists so no
    unusable value can reach the record (and so no implementation invents
    a discard path for them)."""
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        return None
    return raw


def _name_state(rva, value) -> "tuple[str | None, str]":
    """§5.2.1's per-field discriminator, computed from that ONE field's
    own RVA and read result -- never shared between the type and object
    names, which are separate RVAs and separate bounded reads.

      rva == 0                -> ("unnamed")   the dump positively
                                 records no name; nothing was lost
      value is None           -> ("unreadable") a name should be there
                                 but the bounded read/decode failed
      value == ""             -> ("unnamed")   a successful read of a
                                 zero-length name: §1.4 forbids "" on the
                                 wire, but nothing was lost either, so
                                 "ok" (which promises a non-null value)
                                 and "unreadable" would both be wrong
      otherwise               -> ("ok")

    A descriptor that carries no `*Rva` attribute at all (not something
    dumpex's own parser produces -- see ParsedHandleDescriptor) leaves
    `rva` None: "unnamed" is then unprovable, so a missing name falls
    through to "unreadable" rather than claiming the dump recorded none.

    A name that is not a `str` is treated exactly like a failed read, for
    the same reason _normalize_handle_value()/_normalize_counter() reject
    an unusable number: this module reads a descriptor's attributes
    defensively throughout, so the one field that skipped that check
    would otherwise raise out of HandleRecord's own validation and abort
    the whole command -- a crash instead of the exit-4-with-a-reason
    result every other unusable-evidence path produces. dumpex's own
    parser only ever yields `str`/`None` here, so this is unreachable
    through open_dump(); it exists so the asymmetry cannot become one."""
    if rva == 0:
        return None, "unnamed"
    if not isinstance(value, str):
        return None, "unreadable"
    if value == "":
        # Only reachable with a real, non-zero RVA -- an absent RVA
        # attribute (rva is None) cannot prove the read succeeded.
        return (None, "unnamed") if rva is not None else (None, "unreadable")
    return value, "ok"


def _normalize_descriptors(descriptors) -> "tuple[list, int, int]":
    """-> (records, invalid_count, string_failed_count).

    One `HandleRecord` per descriptor whose `Handle` normalizes (§5.2.2),
    sorted per §5.4: numeric ascending by raw handle value, ties keeping
    the stream's own order. The sort key is the raw integer paired with
    the descriptor's source index, and Python's sort is stable, so equal
    handle values (which only a malformed dump produces) can never be
    reordered relative to each other.

    `string_failed_count` counts DESCRIPTORS, not fields (§5.2.1): a
    handle that lost both names counts once. Only descriptors that
    actually became records are counted -- a discarded one is already
    accounted for by `invalid_count`, and counting it twice would inflate
    two limitations from a single fact."""
    invalid_count = 0
    string_failed_count = 0
    keyed = []
    for index, descriptor in enumerate(descriptors):
        handle_value = _normalize_handle_value(getattr(descriptor, "Handle", None))
        if handle_value is None:
            invalid_count += 1
            continue
        type_name, type_status = _name_state(
            getattr(descriptor, "TypeNameRva", None), getattr(descriptor, "TypeName", None))
        object_name, object_status = _name_state(
            getattr(descriptor, "ObjectNameRva", None), getattr(descriptor, "ObjectName", None))
        if "unreadable" in (type_status, object_status):
            string_failed_count += 1
        keyed.append((handle_value, index, HandleRecord(
            handle=hex_address(handle_value),
            type_name=type_name, type_name_status=type_status,
            object_name=object_name, object_name_status=object_status,
            attributes=_normalize_counter(getattr(descriptor, "Attributes", None)),
            granted_access=_normalize_counter(getattr(descriptor, "GrantedAccess", None)),
            handle_count=_normalize_counter(getattr(descriptor, "HandleCount", None)),
            pointer_count=_normalize_counter(getattr(descriptor, "PointerCount", None)),
        )))
    keyed.sort(key=lambda item: item[0])
    return [record for _, _, record in keyed], invalid_count, string_failed_count


def _truncated_descriptor_count(parsed, kept: int) -> int:
    """§5.1.1 rule 5's `affected_count`:
    `header.NumberOfDescriptors - len(handles)`, read off the parser's
    own returned object.

    Deliberately NOT recomputed from §5.1.1 rule 4's
    `min(NumberOfDescriptors, MAX_HANDLE_DESCRIPTORS, (DataSize -
    SizeOfHeader) // SizeOfDescriptor)` formula: the parser bounds
    `usable` by a FOURTH term the formula omits (how many bytes the file
    actually had left -- issue #86), so recomputing would report a
    SMALLER gap than reality on exactly the truncated-file case this
    limitation exists for.

    `kept` is the descriptor count the parser returned, not the record
    count: descriptors discarded by normalization are a different fact,
    counted by HANDLE_DESCRIPTOR_INVALID, and folding them in here would
    claim they were never read."""
    declared = getattr(getattr(parsed, "header", None), "NumberOfDescriptors", None)
    if isinstance(declared, bool) or not isinstance(declared, int):
        return 0
    return max(0, declared - kept)


def summarize_handles_by_type(records) -> dict:
    """§5.6's `summary.by_type`, also used verbatim for the console's
    "By type:" line so the two can never disagree. Keyed by `type_name`,
    with a null one bucketed as "(unnamed)" or "(unreadable)" according
    to `type_name_status` ALONE -- `object_name_status` never affects
    bucketing, so a handle with an unreadable object name still counts
    under its own (readable) type. Ordered count-descending, then type
    name ascending (case-sensitive, §1.5), never by dict insertion or
    hash order.

    Counting is keyed by `(status, type_name)`, NOT by the display label:
    §5.6's two placeholder labels live in the same string space as
    captured type names, so a dump carrying a type literally named
    "(unnamed)" would otherwise be summed into the null-name bucket and
    silently inflate it -- a crafted dump could park handles in the one
    bucket an analyst is least likely to look through. Labels are
    projected only afterwards, through the same handle_name_display() the
    console table uses, so a handle's type can never read one way in the
    table and another in the summary. The record layer is unaffected
    either way -- `type_name` and `type_name_status` there are already
    unambiguous."""
    counts = {}
    for record in records:
        # ("ok", name) vs (status, None): a captured name and a missing
        # one can never land in the same bucket, whatever the name says.
        key = ((record.type_name_status, record.type_name)
                if record.type_name_status == "ok" else (record.type_name_status, None))
        counts[key] = counts.get(key, 0) + 1

    # handle_name_display() is injective (see its own docstring), so
    # distinct buckets always project to distinct labels -- no
    # cross-bucket uniqueness pass is needed, and none may be added: a
    # local uniqueness fixup here is precisely what made the summary
    # disagree with the console table, which has no such pass and cannot
    # have one (it renders one row at a time). It also kept this function
    # quadratic in the number of distinct type names, which the frozen
    # MAX_HANDLE_DESCRIPTORS budget allows to reach 65,536.
    labels = {key: handle_name_display(key[1], key[0]) for key in counts}

    # §1.5's frozen output order, applied to the FINAL keys: sorting on
    # the pre-projection name instead would emit keys that are not in
    # ascending order once a suffix has been appended to one of them.
    return {labels[key]: count for key, count in
            sorted(counts.items(), key=lambda item: (-item[1], labels[item[0]]))}


def collect_handles(mf: MinidumpFile) -> CommandResult:
    """Pure data, no printing. Returns a CommandResult[HandleRecord] over
    the dump's captured `HandleDataStream` (§5).

    Coverage distinguishes all five §5.5 states, and the two `partial`
    drivers that compose with them without costing a record:

      1. no HandleDataStream directory entry  -> not_evaluated, exit 4,
         HANDLES_UNAVAILABLE
      2. present but the parse raised          -> not_evaluated, exit 4,
         HANDLES_PARSE_FAILED + a SOURCE_FAILED carrying the parser's own
         error text (the group-derived code cannot carry a `detail`)
      3. parsed, some/all descriptors unusable -> partial + HANDLE_
         DESCRIPTOR_INVALID when at least one record survives;
         not_evaluated + HANDLES_ALL_DESCRIPTORS_INVALID when none do
      4. parsed, zero descriptors              -> complete, exit 0, zero
         records (a present-empty stream is an answer, not a failure)
      5. parsed, every descriptor normalizes   -> complete, exit 0

      + HANDLE_STREAM_TRUNCATED (§5.1.1) and HANDLE_STRING_READ_FAILED
        (§5.2.1), each `partial` on its own and retained even under
        not_evaluated -- they say what went wrong with the descriptors
        that the aggregate codes only count.

    `handle_records` (the derived source: the usable normalized records)
    is the sole evaluation source, because the reducer's not_evaluated
    branch fires only when every group member is ABSENT -- a failed
    stream or an all-unusable one would otherwise be unable to reach
    exit 4 at all. `handles` (the stream itself) is declared as a bare
    completeness check, whose only effect is to surface case 2's
    SOURCE_FAILED detail."""
    state, parsed, failure_detail = _stream_evidence(mf)

    descriptors = list(getattr(parsed, "handles", None) or []) if state == "parsed" else []
    records, invalid_count, string_failed_count = _normalize_descriptors(descriptors)
    truncated_count = _truncated_descriptor_count(parsed, len(descriptors)) if state == "parsed" else 0

    if state == "absent":
        handles_obs = SourceObservation(name="handles", state=SourceState.ABSENT)
    elif state == "failed":
        handles_obs = SourceObservation(name="handles", state=SourceState.FAILED,
                                         detail=failure_detail)
    elif descriptors:
        handles_obs = SourceObservation(name="handles", state=SourceState.PRESENT,
                                         record_count=len(descriptors))
    else:
        handles_obs = SourceObservation(name="handles", state=SourceState.PRESENT_EMPTY,
                                         record_count=0)

    if records:
        records_obs = SourceObservation(name="handle_records", state=SourceState.PRESENT,
                                         record_count=len(records))
    elif state == "parsed" and not descriptors:
        records_obs = SourceObservation(name="handle_records", state=SourceState.PRESENT_EMPTY,
                                         record_count=0)
    else:
        # Cases 1, 2, and 3-all-invalid: nothing usable to report. The
        # evaluation group below turns this into exit 4 with the code
        # _ABSENT_CODE_FOR_STREAM_STATE pairs with this same state.
        records_obs = SourceObservation(name="handle_records", state=SourceState.ABSENT)

    # Frozen order, outermost evidence layer first: the stream itself,
    # then what the stream did not deliver (truncation), then which
    # delivered descriptors were lost (normalization), then which
    # surviving records lost a field (names). coverage.limitations and
    # the console's [~] lines both follow it.
    completeness_checks = ["handles"]
    if truncated_count:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.HANDLE_STREAM_TRUNCATED, source="handles",
            affected_count=truncated_count))
    if invalid_count and records:
        # No HANDLE_DESCRIPTOR_INVALID when nothing survived: that is
        # case 3's total loss, which HANDLES_ALL_DESCRIPTORS_INVALID
        # already states as a whole (§5.5 case 3), and the descriptor
        # count stays readable on coverage.sources["handles"].
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.HANDLE_DESCRIPTOR_INVALID, source="handles",
            affected_count=invalid_count))
    if string_failed_count:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.HANDLE_STRING_READ_FAILED, source="handles",
            affected_count=string_failed_count))

    coverage = build_coverage_report(
        {"handles": handles_obs, "handle_records": records_obs},
        evaluation_sources=EvaluationRequirement(
            sources=("handle_records",),
            all_absent_code=_ABSENT_CODE_FOR_STREAM_STATE[state]),
        completeness_checks=completeness_checks,
        # §5.5: an exit-4 result must still carry HANDLE_STREAM_TRUNCATED
        # and HANDLE_STRING_READ_FAILED if they fired -- they say what
        # went wrong with descriptors the aggregate code only counts.
        retain_completeness_checks_when_not_evaluated=True)

    return CommandResult(kind="handles", records=records, coverage=coverage,
                          summary={"count": len(records),
                                   "by_type": summarize_handles_by_type(records)})


def _headline(records, coverage) -> str:
    """§5.6's mutually exclusive headline branches, derived from the
    coverage report alone (never from a raw stream state the renderer
    would have to be handed separately). Every string describes CAPTURED
    evidence -- none may imply a live process was consulted (§5.7)."""
    codes = {limitation.code for limitation in coverage.limitations}
    if LimitationCode.HANDLES_UNAVAILABLE in codes:
        return "HandleDataStream not present in this dump"
    if LimitationCode.HANDLES_PARSE_FAILED in codes:
        # The parser's own error text follows in the [~] lines below,
        # carried by the companion SOURCE_FAILED limitation.
        return "HandleDataStream is present in this dump but could not be parsed"
    if LimitationCode.HANDLES_ALL_DESCRIPTORS_INVALID in codes:
        descriptor_count = coverage.sources["handles"].record_count
        return f"0 handles usable -- {descriptor_count} descriptor(s) failed to normalize"
    return f"{len(records)} handle(s) captured"


def _access_display(record: HandleRecord) -> str:
    """§5.6: the mask is rendered `0x%08x` in the console while staying a
    plain integer in JSON (§1.3). Raw and undecoded either way -- its
    meaning is object-type-specific, and a wrong decode is worse than a
    number.

    When §5.2's deferred type-specific decoding lands and this starts
    returning names like "FILE_ALL_ACCESS", the table's column widths do
    NOT need revisiting: every column is followed by two literal spaces,
    and tests/unit/test_handles_cmd.py::
    test_no_column_fuses_into_the_next_however_wide_its_value already
    parametrizes this function's output over decoded-width strings to
    keep that true."""
    if record.granted_access is None:
        return "(unknown)"
    return f"0x{record.granted_access:08x}"


def _count_display(value) -> str:
    return "?" if value is None else str(value)


# Every column in §5.6's table is followed by two LITERAL spaces, so a
# value that outgrows its column pushes the rest of the row right but
# stays readable. A width alone does not do that: `{name:<16}` is a
# MINIMUM width, not a truncation, so a 16-character type name left zero
# separation and rendered as e.g. "ActivationObject0x00000002" -- one
# unsplittable token in the exact place an analyst reads the granted-
# access mask. Windows has many such types (WaitCompletionPacket,
# FilterConnectionPort, DxgkSharedSyncObject, IoCompletionReserve, ...),
# so that was ordinary output, not an edge case. Truncating a value would
# destroy evidence; each column is narrowed by exactly its two spaces
# instead, which keeps §5.6's sample rows byte-identical (their widest
# values are "(unreadable)" and "0x0012019f") while making the separator
# structural.
#
# The Access column is included even though `_access_display()` cannot
# exceed 10 characters today: §5.2 defers type-specific permission
# decoding to a later feature, and a decoded "FILE_ALL_ACCESS" beside a
# 3-digit handle count would otherwise reproduce the exact same fusion
# one column over.
_TYPE_COLUMN_WIDTH = 14
_ACCESS_COLUMN_WIDTH = 10


# ── #98: console folding, kept strictly a projection ────────────────────
# The default console folds ONLY the anonymous rows of these types into
# per-type counts. Two independent conditions have to hold before a row
# is folded, and neither is sufficient alone:
#
#   1. `object_name_status == "unnamed"` -- the descriptor positively
#      records no object name (§5.2.1). An "unreadable" name is EVIDENCE
#      LOSS and is never folded: folding it would hide the one row an
#      analyst needs to see to know something was lost.
#   2. the captured type is on this explicitly approved list.
#
# Condition 2 exists because condition 1 alone is far too aggressive: an
# anonymous Process, Thread, Token, Section, or Job handle is exactly the
# kind of evidence a cross-process-access question turns on, and none of
# those appear below. The list is an ALLOW list, so a type nobody has
# considered (including a type name a dump invents) stays visible by
# default -- the failure mode of a new Windows object type is a slightly
# longer table, never a hidden handle.
#
# Every type here is a synchronization/scheduling primitive whose
# anonymous instances carry no name, no path, and no cross-process
# reference: with no object name there is nothing left in the descriptor
# to investigate beyond the per-type count the fold line prints.
_FOLDABLE_ANONYMOUS_TYPES = frozenset({
    "Event",
    "EtwRegistration",
    "IoCompletion",
    "IoCompletionReserve",
    "IRTimer",
    "Mutant",
    "Semaphore",
    "Timer",
    "TpWorkerFactory",
    "WaitCompletionPacket",
})

# Frozen, per-name explanations for NT Object Manager names an analyst
# meets routinely and cannot tell from a filesystem path. Keyed by
# (type_name, object_name) so a note is only attached to a handle whose
# TYPE agrees with it -- a File handle a dump chooses to name
# `\KnownDlls` gets no note at all rather than a false one.
#
# Every string is OBSERVATIONAL and describes only what THIS descriptor
# recorded. None may claim the directory's contents were enumerated:
# nothing in this command reads the Object Manager namespace, and #98's
# resource rules forbid expanding a Directory handle from the analysis
# host (which would describe the wrong machine anyway).
_NT_NAMESPACE_NOTES = {
    ("Directory", r"\KnownDlls"): (
        "NT Object Manager directory of pre-mapped system DLL sections. This",
        "descriptor records the directory name only -- the section objects inside",
        "it are not captured by it.",
    ),
    ("Directory", r"\KnownDlls32"): (
        "NT Object Manager directory of pre-mapped 32-bit system DLL sections on a",
        "64-bit system. This descriptor records the directory name only.",
    ),
    ("Directory", r"\BaseNamedObjects"): (
        "NT Object Manager directory holding session-wide named objects. This",
        "descriptor records the directory name only -- the named objects inside it",
        "are not captured by it.",
    ),
    ("Directory", r"\RPC Control"): (
        "NT Object Manager directory holding RPC/ALPC endpoint names. This",
        "descriptor records the directory name only.",
    ),
    ("Directory", r"\GLOBAL??"): (
        "NT Object Manager directory of DOS device symbolic links (C:,",
        "PhysicalDrive0, ...). This descriptor records the directory name only.",
    ),
}

# The one note emitted for any OTHER captured Directory name, so an
# unlisted directory is still explained without this table having to
# enumerate a namespace. Bounded by construction: at most one such entry,
# however many Directory handles a dump carries.
_GENERIC_DIRECTORY_NOTE = (
    "Directory handles name an NT Object Manager namespace directory. A",
    "directory's child objects are not captured by its own descriptor.",
)

_FOLD_HINT = ("These rows are captured evidence and are complete in structured "
              "output -- use --verbose to show all.")

_NAME_STATUS_LEGEND = (
    "(unnamed) = the descriptor records no name; "
    "(unreadable) = a name was recorded but the bounded read failed")


def _is_foldable(record: HandleRecord) -> bool:
    """One record in, one bool out -- no cross-row state, so folding is
    deterministic and linear in the record count however the table is
    ordered. Both name statuses are read as themselves (never as bare
    truthiness of the name): "unnamed" and "unreadable" are different
    facts (§5.2.1) and only the first is ever foldable."""
    return (record.object_name_status == "unnamed"
            and record.type_name_status == "ok"
            and record.type_name in _FOLDABLE_ANONYMOUS_TYPES)


def _partition_for_console(records, verbose: bool) -> "tuple[list, dict]":
    """-> (rows_to_print, {type_name: folded_count}).

    `verbose` folds nothing at all. The folded counts are ordered by
    §1.5's frozen rule (count descending, then type name ascending) so
    two runs over the same dump print the same line."""
    if verbose:
        return list(records), {}
    shown = []
    folded = {}
    for record in records:
        if _is_foldable(record):
            folded[record.type_name] = folded.get(record.type_name, 0) + 1
        else:
            shown.append(record)
    return shown, dict(sorted(folded.items(), key=lambda item: (-item[1], item[0])))


def _namespace_notes(records) -> list:
    """The bounded semantic notes for §5.6's Object column, derived from
    ALL collected records (never only the printed ones -- a folded row is
    still captured evidence, and its note would otherwise disappear with
    it).

    Bounded by `len(_NT_NAMESPACE_NOTES) + 1` regardless of how many
    handles a dump carries: named entries are de-duplicated, and every
    other captured Directory name contributes to ONE generic line rather
    than a line of its own. A dump carrying 65,536 distinct Directory
    names therefore cannot turn this block into the output."""
    seen = {}
    other_directory = False
    for record in records:
        if record.type_name_status != "ok" or record.object_name_status != "ok":
            continue
        key = (record.type_name, record.object_name)
        note = _NT_NAMESPACE_NOTES.get(key)
        if note is not None:
            seen[key] = note
        elif record.type_name == "Directory":
            other_directory = True
    lines = [(f"{name} ({type_name})", note)
             for (type_name, name), note in sorted(seen.items(), key=lambda i: (i[0][1], i[0][0]))]
    if other_directory:
        lines.append(("Directory", _GENERIC_DIRECTORY_NOTE))
    return lines


def render_handles_console(records, coverage, *, verbose: bool = False) -> None:
    """Projects ONLY the collected records and CoverageReport -- it never
    re-reads `mf.handles`, so console and JSON can never describe two
    different reads of the same dump.

    Every string that came out of the dump -- both names, and the
    `by_type` keys derived from the type names -- goes through
    console_safe() on its way to the terminal (§5.7 is about not implying
    live state; this is about a name not being able to forge dumpex's own
    output at all). The records and the summary keep the exact decoded
    values, so `--json` is unaffected.

    `verbose` (#98) selects between two PROJECTIONS of the same records
    and changes nothing else: the headline, `By type:` (which always
    counts the complete inventory, folded rows included), the
    limitations, and the coverage reasons are identical either way. The
    default view folds the approved low-context anonymous rows into
    per-type counts and states, in the output itself, how many rows were
    folded and how to see them; `--verbose` prints every record."""
    print(f"\n{BOLD('═══ HANDLES ═══')}")
    print(f"  {_headline(records, coverage)}")

    by_type = summarize_handles_by_type(records)
    if by_type:
        # Only when records are non-empty -- an empty "By type:" line
        # would read as a claim about handles that were never captured.
        listed = ", ".join(f"{console_safe(name)} {count}" for name, count in by_type.items())
        print(f"  By type: {listed}")

    # §5.6's partial-loss line. Deliberately NOT a substitute for the
    # limitation's own [~] line below (the layout shows both): this one
    # sits with the counts an analyst reads first and points at where the
    # machine-readable fact lives, the [~] line is the fact itself.
    invalid = next((l for l in coverage.limitations
                     if l.code == LimitationCode.HANDLE_DESCRIPTOR_INVALID), None)
    if invalid is not None:
        text = (f"{invalid.affected_count} descriptor(s) could not be normalized "
                f"-- see coverage.limitations")
        print(f"  {YELLOW(text)}")

    shown, folded = _partition_for_console(records, verbose)
    folded_total = sum(folded.values())

    if shown:
        header = (f"{'Handle':<18}  {'Type':<{_TYPE_COLUMN_WIDTH}}  "
                  f"{'Access':<{_ACCESS_COLUMN_WIDTH}}  {'Cnt':>3}  {'Ptr':>3}  Object")
        print()
        print(f"  {DIM(header)}")
        for record in shown:
            type_display = console_safe(
                handle_name_display(record.type_name, record.type_name_status))
            object_display = console_safe(
                handle_name_display(record.object_name, record.object_name_status))
            print(f"  {record.handle:<18}  {type_display:<{_TYPE_COLUMN_WIDTH}}  "
                  f"{_access_display(record):<{_ACCESS_COLUMN_WIDTH}}  "
                  f"{_count_display(record.handle_count):>3}  "
                  f"{_count_display(record.pointer_count):>3}  {object_display}")

    # The two null-name labels are dumpex's own vocabulary and mean two
    # different things (§5.2.1); printed only when one of them is
    # actually on screen, so the legend never describes rows that are not
    # there. Read off the PRINTED rows, not the record list.
    if any(record.type_name_status != "ok" or record.object_name_status != "ok"
            for record in shown):
        print(f"  {DIM(_NAME_STATUS_LEGEND)}")

    # #98: exactly how many rows the default view folded, in per-type
    # counts, with the way to see them. Every folded row is still a
    # collected record -- it is in `by_type` above, in `summary.count`,
    # and in --json -- so this line says "not shown", never "not
    # captured".
    if folded_total:
        listed = ", ".join(f"{console_safe(name)} {count}" for name, count in folded.items())
        print()
        print(f"  {folded_total} anonymous handle(s) of routine low-context type(s) "
              f"not shown: {listed}")
        print(f"  {DIM(_FOLD_HINT)}")

    notes = _namespace_notes(records)
    if notes:
        print()
        print(f"  {BOLD('Object name notes')}")
        for label, note_lines in notes:
            print(f"    {console_safe(label)}")
            for line in note_lines:
                print(f"      {line}")

    for reason in coverage.reasons:
        # Frozen dumpex text in every case except SOURCE_FAILED's detail,
        # which is a parser exception message -- escaped too rather than
        # trusted to stay free of dump-derived text as the parser evolves.
        print(f"\n  {YELLOW('[~]')} {console_safe(reason)}")

    print()


def cmd_handles(mf: MinidumpFile, *, verbose: bool = False) -> CommandResult:
    """`verbose` reaches the RENDERER only. `collect_handles()` takes no
    verbosity at all, which is what makes "console filtering never
    removes a record from --json" a structural property rather than a
    rule someone has to remember (#98)."""
    result = collect_handles(mf)
    render_handles_console(result.records, result.coverage, verbose=verbose)
    return result

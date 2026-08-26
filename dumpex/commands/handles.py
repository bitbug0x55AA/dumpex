"""Collect and render handles recorded in a minidump at capture time.

Collection retains the HandleDataStream's declared descriptor count so
truncation cannot be mistaken for a complete shorter list. No live state is
queried. Console verbosity changes presentation only; structured output keeps
the complete inventory. Access masks remain raw integers, while type-specific
decoded rights are derived display text and never a verdict.
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
from dumpex.ui.access_rights import (
    NO_RIGHTS_TEXT, RIGHTS_CONTINUED_SUFFIX, RIGHTS_SEPARATOR,
    access_right_groups, alias_names_in, alias_provenance, canonical_type_name,
    decode_access_mask, expand_alias, unconfirmed_names,
    unconfirmed_names_in_alias,
    is_undecoded_token, wrap_rights,
)
from dumpex.ui.colors import BOLD, DIM, YELLOW, console_safe
from dumpex.ui.console_layout import column_width, resolve_width, wrap_text


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
    plain integer in JSON (§1.3). Raw in the COLUMN either way -- it is
    the authoritative captured value, and it is what a reader compares
    against a reference or pastes into a ticket.

    #102's type-specific decoding is deliberately NOT applied here: it
    reads the same mask against the row's recorded type and prints the
    resulting rights on the row's own `Rights` line (§5.6.4), because a
    decoded mask is far too wide for a middle column that every other row
    has to line up with. This column therefore stays the single printed
    copy of the captured value, and the derived reading never repeats it.
    A null mask is `(unknown)` -- absent evidence, which §1.4 keeps
    distinct from a captured mask granting nothing, and which is why the
    `(unknown)` case has no `Rights` line to contradict it.

    Should a future feature nevertheless put a decoded value in this
    column, the table's widths do not need revisiting: the Access column
    is measured from the values this function actually returns (see
    column_width), and tests/unit/test_handles_cmd.py::
    test_no_column_fuses_into_the_next_however_wide_its_value already
    parametrizes this function's output over decoded-width strings to
    keep that true."""
    if record.granted_access is None:
        return "(unknown)"
    return f"0x{record.granted_access:08x}"


def _count_display(value) -> str:
    return "?" if value is None else str(value)


# Every column in §5.6's table is followed by two LITERAL spaces, and
# every column is sized to the WIDEST VALUE IT ACTUALLY HOLDS in this
# render, floored at the minimum below and capped above.
#
# See dumpex.ui.console_layout.column_width() for why a fixed width
# separates a table without aligning it, and for what the cap protects
# against. Windows carries plenty of 16-to-20-character type names
# (WaitCompletionPacket, FilterConnectionPort, IoCompletionReserve, ...),
# so a ragged Type column was ordinary output rather than an edge case.
#
# The minimums keep an ordinary table's shape stable across dumps -- a
# dump whose type names are all short still renders at the familiar
# width rather than collapsing. The caps sit far above any real Windows
# object type name, so only a dump-crafted one ever reaches them.
_TYPE_COLUMN_MIN_WIDTH = 14
_TYPE_COLUMN_MAX_WIDTH = 40
# _access_display() cannot exceed 10 characters today: #102's decoded
# rights are printed under the table (§5.6.4), not in this column. The
# cap is kept anyway, so a future decoded value in the column cannot pad
# every row to its own width.
_ACCESS_COLUMN_MIN_WIDTH = 10
_ACCESS_COLUMN_MAX_WIDTH = 32
# `Cnt`/`Ptr` are right-aligned uint32 counters -- 10 digits at the very
# most, so they need no cap of their own.
_COUNT_COLUMN_MIN_WIDTH = 3

# A handle is always hex_address()'s fixed 18 characters (§1.3), so this
# one is a constant rather than a measurement.
_HANDLE_COLUMN_WIDTH = 18


# ── #98: console folding, kept strictly a projection ────────────────
# A real dump's handle table is dominated by rows whose Object column is
# `(unnamed)`, and they bury the handles an investigation turns on. The
# default console therefore folds an anonymous row into a per-type count
# UNLESS one of two things holds:
#
#   1. the row lost evidence. `object_name_status == "unreadable"` (a
#      name should have been there and the bounded read failed) is a
#      different fact from `"unnamed"` (the descriptor positively records
#      none) -- §5.2.1 -- and so is an unreadable TYPE name. Folding
#      either would hide the one row that says something was lost.
#
#      Note what this does NOT require: that the type name READ. A
#      descriptor with no type name at all (`TypeNameRva == 0`) is
#      "unnamed", not a read failure, and a row with neither a type nor
#      an object name is the lowest-context row the table can hold.
#      Whole real handle streams are written that way, so demanding a
#      captured type name here disables the fold on exactly those dumps.
#   2. the type is on the retain list below.
#
# Condition 2 is why `object_name_status == "unnamed"` is not the sole
# suppression rule: an anonymous Process, Thread, Token, Section, or Job
# handle is exactly the evidence a cross-process-access question turns
# on. Those five stay visible however many of them a dump carries.
#
# This is a RETAIN list, not an allow-to-fold list. That direction is
# deliberate and it is the opposite of the first cut of this feature: an
# allow list left every unlisted type visible, so the default console
# still printed the wall of anonymous rows it exists to collapse, and it
# would have quietly regressed again with every new Windows object type.
# The cost of the retain direction is that a new type is folded rather
# than shown -- bounded, because the fold line names the type and its
# exact count, `summary.by_type` counts it, and `--verbose` prints it.
_RETAINED_ANONYMOUS_TYPES = frozenset({
    "Job",
    "Process",
    "Section",
    "Thread",
    "Token",
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
    ordered.

    Both name statuses are read as THEMSELVES, never as bare truthiness
    of the name: "unnamed" and "unreadable" are different facts (§5.2.1),
    and only the first is ever a fold candidate. The type is tested for
    `!= "unreadable"` rather than `== "ok"`, and the difference is not
    cosmetic -- requiring "ok" was the defect this predicate shipped
    with. A descriptor whose `TypeNameRva` is 0 has NO type name and
    therefore status "unnamed", which is not a read failure and not
    evidence loss; it is the LOWEST-context row the table can hold (no
    type, no object name, nothing left to investigate). Real dump writers
    produce whole handle streams in exactly that shape, and requiring
    "ok" pinned every one of those rows on screen -- i.e. it disabled the
    fold precisely on the dumps that need it most, while the synthetic
    fixtures (which all carry type names) kept passing.

    An UNREADABLE name in either field still blocks folding, in both
    directions: that is the one row an analyst needs in order to know
    something was lost."""
    if record.object_name_status != "unnamed":
        return False
    if record.type_name_status == "unreadable":
        return False
    # `type_name` is None for the no-type-name case above; `None` is not
    # in the retain list, so such a row folds.
    return record.type_name not in _RETAINED_ANONYMOUS_TYPES


def _partition_for_console(records, verbose: bool) -> "tuple[list, list]":
    """-> (rows_to_print, rows_folded). `verbose` folds nothing at all.

    Returns the folded RECORDS rather than a count per type name, so the
    fold line can be built by summarize_handles_by_type() -- the same
    projection `By type:` and `summary.by_type` use. Counting here
    instead would key the line on the raw `type_name`, which merges a
    null type into whatever a dump chose to call itself and loses §1.5's
    ordering and handle_name_display()'s injective disambiguation."""
    if verbose:
        return list(records), []
    shown, folded = [], []
    for record in records:
        (folded if _is_foldable(record) else shown).append(record)
    return shown, folded


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


# ── #102: type-specific decoding of the Access column ───────────────
# The Access column keeps §5.6's raw `0x%08x` mask, and keeps it as the
# ONLY copy of that value on screen: it is the authoritative captured
# evidence, it is aligned for a column-wise scan, and it is what a reader
# compares against a reference or pastes into a ticket. What it does NOT
# do is say what the handle permits, which is the question an analyst
# actually has, so every printed row is followed by its own indented
# `Rights` line naming what that mask grants for that row's recorded
# type. Derived reading directly under captured value, once each.
#
# Attached to the row rather than collected into a block under the table,
# and that is a correction of the first cut of this feature. A block
# de-duplicated by (type, mask) is shorter, but it puts the answer
# somewhere else: the reader has to carry `Key`+`0x00020019` from the row
# down to a second, differently-ordered table and find it there -- which
# is the manual lookup #102 exists to remove, performed inside dumpex's
# own output. It also breaks the one order an investigation actually
# follows, handle by handle down the table.
#
# The cost of attaching is that the printed table roughly doubles in
# height. That is the trade the row-local reading is worth: the rows are
# already folded to the ones that carry evidence (#98), and a rights line
# is indented under its row rather than competing with it.
#
# Not IN the Access column, though: a fully decoded File mask is ~110
# characters and §5.6 sizes every column to the widest value it holds, so
# an inline decode would either pad every row to 110 columns or (with
# §5.6's cap) push every File row's remaining columns right. The
# continuation line wraps instead, and truncation never enters into it.
# The rights sit under their row behind a drawn branch, so a glance can
# tell "this belongs to the handle above" from "this is another handle"
# without reading either line. Indented four columns past the row (which
# is itself printed at two), and the branch is dimmed, so the names are
# what the eye lands on.
_RIGHTS_LINE_INDENT = 4
_RIGHTS_BRANCH = "└─ "
_RIGHTS_BRANCH_BLANK = " " * len(_RIGHTS_BRANCH)

# One label column, wide enough for the longest of the three labels, so
# the names all start in the same place whichever shape a row takes.
_RIGHTS_LABEL_WIDTH = 8
_RIGHTS_ALL_LABEL = "Rights"
_RIGHTS_TYPE_LABEL = "Type"
_RIGHTS_STANDARD_LABEL = "Standard"

# What the names are indented to, once the row indent, the branch, the
# label column and its trailing space are accounted for. Continuation
# lines of a wrapped group align here.
_RIGHTS_TEXT_INDENT = (_RIGHTS_LINE_INDENT + len(_RIGHTS_BRANCH)
                        + _RIGHTS_LABEL_WIDTH + 1)

# One caption, printed once under the table whenever any rights line was
# printed. It carries the three things a reader has to know to read those
# lines correctly, and §1.6 requires the last: the rights are
# type-dependent, the two labels mean different halves of the mask, and
# the whole thing is an observation rather than a finding.
_RIGHTS_LEGEND = (
    "Rights decode each row's own Access mask against its recorded object type -- the "
    "same bit means different things for a File, a Process and a Token. A long list "
    "splits into Type (rights that object type defines) and Standard (the rights every "
    "type shares). They are an observation about what the handle permitted, never "
    "evidence that it was used.")

# A single right NAME can carry the same confirmed/unconfirmed split an
# alias can (`unconfirmed_names()` in dumpex.ui.access_rights): `Semaphore`
# `0x1` decodes to `QueryState`, and no Microsoft header or reference page
# names `SEMAPHORE_QUERY_STATE` -- unlike `TIMER_QUERY_STATE`, which
# `winnt.h` defines, and which decodes to the SAME display word on a
# `Timer` row. Printing both without distinction told a reader they were
# equally checkable. The mark is short, unlike the alias block's
# `[source unconfirmed]`, because a Rights line can carry a dozen names on
# one row and a per-name marker has to survive being one of them, not the
# only thing on the line.
_RIGHTS_UNCONFIRMED_MARK = "[?]"
_RIGHTS_UNCONFIRMED_NOTE = (
    "Names marked [?] map to a constant no Microsoft header or reference page could "
    "be found for; the decoded bits are unaffected.")

# #102: a composite is short and recognisable, which is what makes it
# worth printing on every row -- but the capabilities inside it stop
# being visible, and `TokenWrite` contains `AdjustPrivileges`. An
# investigator scanning a transcript for that word has to be able to find
# it, so every composite the table actually used is expanded once,
# underneath it. Once, not per row: repeating five component names on
# every row is the wall the composites exist to collapse.
#
# Each entry is labelled with the OBJECT TYPE as well as the name,
# because `AllAccess` stands for a different constant on every type --
# reading a Process `AllAccess` and an Event `AllAccess` as the same
# capability is exactly the cross-type mistake this decoder exists to
# prevent.
_ALIAS_BLOCK_HEADING = "Aliases used"

# The names on the left are dumpex DISPLAY FORMS, not header spellings:
# `KeyRead` maps to `KEY_READ`, `AllAccess` to the recorded type's own
# `*_ALL_ACCESS`. Saying "the SDK's own name" (as this line first did)
# would send a reader looking for `AllAccess` in a header that has no
# such symbol, and it would also mis-attribute two of the aliases:
# `DIRECTORY_ALL_ACCESS` and `SYMBOLIC_LINK_ALL_ACCESS` are WDK
# definitions, not Win32 SDK ones.
#
# The note stays at the header-FAMILY level rather than naming one header
# per object type, and that is deliberate on two counts.
#
# `dumpex.ui.access_rights` tracks the defining header PER CONSTANT,
# because a type can draw on more than one: an `IoCompletion` row's
# `AllAccess` is `IO_COMPLETION_ALL_ACCESS`, a `winnt.h` constant, even
# though the same type's `QueryState` bit is not one. A caption assigning
# a single header to each type would be wrong here.
#
# And the two WDK aliases do not share a header either --
# `DIRECTORY_ALL_ACCESS` is documented under `ntifs.h`, while for
# `SYMBOLIC_LINK_ALL_ACCESS` only the ROUTINE is documented (`wdm.h`) and
# the constant spelling is unconfirmed. Both objects are Object Manager
# objects, so the family wording is true of both; a specific header here
# would not be. The per-constant record, with its evidence, lives in
# access_rights.py and tests/unit/test_access_rights.py.
_ALIAS_BLOCK_NOTE = (
    "Each display name maps to one Windows SDK, WDK or native constant, and what "
    "that constant contains depends on the object type it was read against.")

# Appended to any expansion whose constant has no confirmed Microsoft
# source, because the block must not describe `SYMBOLIC_LINK_ALL_ACCESS`
# in the same words as `KEY_READ`. An investigator reads "documented" as
# "I can go and check this", and for the unconfirmed names they cannot:
# no Microsoft page names them. Saying so on the line is cheaper than a
# reader discovering it by failing to find the symbol.
_ALIAS_UNCONFIRMED_MARK = "[source unconfirmed]"
_ALIAS_UNCONFIRMED_NOTE = (
    "Names marked [source unconfirmed] map to a constant no Microsoft header or "
    "reference page could be found for; the decoded bits are unaffected.")

# Printed only when an expansion actually carries an UnknownBits token,
# so the caveat never explains something that is not on screen. A
# remainder means something different here than on a Rights line: the
# bits are not undecodable, they are covered BY the constant and simply
# have no individually documented right name.
_ALIAS_UNKNOWN_BITS_NOTE = (
    "UnknownBits in an alias expansion are included by that Windows constant but have "
    "no individually documented right name in this definition set.")
_ALIAS_BLOCK_INDENT = 4


def _paint_rights(line: str) -> str:
    """Colour ONE already-wrapped rights line: separators dimmed so they
    do not compete with the names, and a remainder token in yellow --
    it is the one piece on the line that says something was NOT read.

    Applied after wrapping, never before: the widths are measured on the
    plain text, and colouring first would spend them on escape
    sequences."""
    body, suffix = ((line[:-len(RIGHTS_CONTINUED_SUFFIX)], RIGHTS_CONTINUED_SUFFIX)
                     if line.endswith(RIGHTS_CONTINUED_SUFFIX) else (line, ""))
    painted = DIM(RIGHTS_SEPARATOR).join(
        YELLOW(piece) if is_undecoded_token(piece) else piece
        for piece in body.split(RIGHTS_SEPARATOR))
    return painted + DIM(suffix)


def _alias_entries(records, width: int, os_major=None) -> list:
    """-> [(label, [expansion lines]), ...] for §5.6.4's `Aliases used`
    block: one entry per distinct (registry type, composite) pair the
    PRINTED rows actually used, ordered by type label then alias name
    (§1.5).

    Bounded twice over: by the rows on screen, and by the registry -- a
    type defines at most three composites, so a 65,536-row dump whose
    handles are all Files contributes four lines here, not 65,536.

    Keyed by `(canonical_type_name(record.type_name), alias)`, and
    labelled with that same CANONICAL spelling ("Process", "SymbolicLink",
    ...) rather than the record's raw `type_name`. Both halves of that
    choice matter, and both were bugs before it: `alias_names_in()` (and
    `decode_access_mask()` underneath it) already normalize a type name
    case- and whitespace-insensitively before looking it up, so `"Process"`,
    `"  process  "` and a raw descriptor field padded with whitespace
    around `"Process"` are ONE registry entry and decode identically.
    Keying on the raw text produced one entry PER SPELLING instead of one
    per fact -- the same `AllAccess` expansion printed two or three times
    -- and echoing that raw text back as the label let one crafted or
    corrupted `type_name` (attacker-controlled, and up to
    `MAX_HANDLE_STRING_BYTES` -- 4096 bytes, see
    dumpex/core/memory.py -- of it, not merely a few extra spaces) blow
    the type column out to its own width, dragging every OTHER entry's
    column out with it, because `column_width()` sizes one shared column
    across the whole block. The canonical spelling comes from a fixed,
    short, dumpex-owned set (`SUPPORTED_OBJECT_TYPES`), so neither
    failure mode has anything left to act on: same key for every
    spelling of one type, and a label no dump can make long.

    A record whose type does not resolve to a registry entry contributes
    no alias at all (`alias_names_in()` returns `()` for it), so
    `canonical_type_name()` is never called on that None-producing input
    here -- this function only ever sees names it already knows are
    keyable."""
    seen = set()
    for record in records:
        decoded = decode_access_mask(record.granted_access, record.type_name,
                                      os_major=os_major)
        if decoded is None:
            continue
        canonical = canonical_type_name(record.type_name)
        if canonical is None:
            continue
        for alias in alias_names_in(decoded, record.type_name):
            seen.add((canonical, alias))

    entries = sorted(seen)
    if not entries:
        return []

    # Two measured columns, so the types line up, the composite names
    # line up under each other, and every `=` sits in the same place --
    # the block reads as a table rather than as ragged prose. No cap is
    # needed here (contrast the main table's Type column): every value is
    # a canonical registry spelling, so the widest possible one
    # ("WindowStation") already bounds this regardless of what any dump
    # contains.
    type_w = column_width("", [type_name for type_name, _alias in entries])
    alias_w = column_width("", [alias for _type_name, alias in entries])
    label_width = type_w + 2 + alias_w
    lines = []
    for type_name, alias in entries:
        label = f"{type_name:<{type_w}}  {alias}"
        expansion = expand_alias(alias, type_name, os_major=os_major)

        # Two independent questions, both marked, because they can and do
        # disagree: is the ALIAS's own combination constant confirmed
        # (`IoCompletion AllAccess` -- yes, `IO_COMPLETION_ALL_ACCESS` is
        # winnt.h's own), and is each COMPONENT the expansion names
        # confirmed on its own (`QueryState` inside that same expansion
        # -- no). Marking only the first would print `QueryState` next to
        # `Delete`/`ReadControl` with nothing to tell a reader the first
        # has no Microsoft source and the rest do.
        component_unconfirmed = unconfirmed_names_in_alias(alias, type_name,
                                                             os_major=os_major)
        if component_unconfirmed:
            expansion = _mark_unconfirmed(expansion, component_unconfirmed)
        provenance = alias_provenance(alias, type_name)
        if provenance is not None and not provenance.confirmed:
            expansion = f"{expansion}{RIGHTS_SEPARATOR}{_ALIAS_UNCONFIRMED_MARK}"

        indent = _ALIAS_BLOCK_INDENT + label_width + 3   # "<label> = "
        for index, line in enumerate(wrap_rights(expansion, width - 2 - indent)):
            head = (f"{' ' * _ALIAS_BLOCK_INDENT}{label:<{label_width}} {DIM('=')} "
                     if index == 0 else " " * indent)
            lines.append((head, _paint_rights(line)))
    return lines


def _mark_unconfirmed(text: str, unconfirmed: frozenset) -> str:
    """Append `_RIGHTS_UNCONFIRMED_MARK` to every piece of an already
    RIGHTS_SEPARATOR-joined string whose bare name is in `unconfirmed`,
    and leave every other piece -- including a remainder token like
    `UnknownBits(0x...)`, which is not a name at all -- untouched.

    Splits and rejoins on RIGHTS_SEPARATOR rather than editing the
    DecodedAccess names before formatting, so format_access_rights() and
    access_right_groups() stay pure projections of the decode and this
    stays a console-only concern: nothing about --json or the decode
    itself changes because a mark was added or not. wrap_rights() then
    sees "QueryState [?]" as ONE piece, so the mark can never be split
    from its name across a wrapped line -- the same guarantee that
    already protects every right name."""
    pieces = text.split(RIGHTS_SEPARATOR)
    marked = [f"{piece} {_RIGHTS_UNCONFIRMED_MARK}" if piece in unconfirmed else piece
              for piece in pieces]
    return RIGHTS_SEPARATOR.join(marked)


def _rights_lines(record: HandleRecord, width: int, os_major=None) -> list:
    """The finished, indented, coloured rights lines for ONE record, or
    [] when there is nothing to decode.

    A null `granted_access` returns no lines at all: that is absent
    evidence (§5.2.2), the row's Access column already says `(unknown)`,
    and `(unknown)` stays that column's word alone -- a rights line for a
    mask that was never captured would turn a missing value into one. A
    captured mask of zero DOES get a line, because "this handle was
    granted nothing" is a fact the dump recorded.

    One `Rights` line while the whole decode fits; `Type` + `Standard`
    once it does not. The split is not cosmetic -- a wrapped run of
    thirteen names mixes rights that mean something only for THIS object
    type with rights that mean the same thing for every type, and the
    reader cannot see where one ends and the other begins. It is taken
    only when both halves exist, so a mask with no standard bits stays
    one labelled line rather than gaining an empty one.

    `width` is the full console width; everything this function prints in
    front of the names is subtracted here, so the caller cannot get the
    two out of step.

    `os_major` is the dump's Windows major version when it could be read,
    and reaches decode_access_mask() unchanged -- see there for the one
    thing it changes (`AllAccess` on a Process or Thread predates Vista's
    widening of those two constants)."""
    decoded = decode_access_mask(record.granted_access, record.type_name,
                                  os_major=os_major)
    if decoded is None:
        return []

    # `standard_names` can never contain an unconfirmed name --
    # `_STANDARD_RIGHTS`/`_GENERIC_RIGHTS` are `winnt.h` in full -- so
    # only the TYPE half of the text is ever marked.
    unconfirmed = unconfirmed_names(decoded, record.type_name, os_major=os_major)

    text_width = width - 2 - _RIGHTS_TEXT_INDENT
    type_text, standard_text = access_right_groups(decoded)
    if unconfirmed:
        type_text = _mark_unconfirmed(type_text, unconfirmed)
    single = RIGHTS_SEPARATOR.join(part for part in (type_text, standard_text) if part) \
        or NO_RIGHTS_TEXT
    if len(single) <= text_width or not (type_text and standard_text):
        groups = ((_RIGHTS_ALL_LABEL, single),)
    else:
        groups = ((_RIGHTS_TYPE_LABEL, type_text),
                   (_RIGHTS_STANDARD_LABEL, standard_text))

    lines = []
    for group_index, (label, text) in enumerate(groups):
        # Only the first group carries the branch: the second is part of
        # the same handle's answer, not a new one.
        branch = _RIGHTS_BRANCH if group_index == 0 else _RIGHTS_BRANCH_BLANK
        head = (f"{' ' * _RIGHTS_LINE_INDENT}{DIM(branch)}"
                 f"{DIM(f'{label:<{_RIGHTS_LABEL_WIDTH}}')} ")
        for line_index, line in enumerate(wrap_rights(text, text_width)):
            prefix = head if line_index == 0 else " " * _RIGHTS_TEXT_INDENT
            lines.append(f"{prefix}{_paint_rights(line)}")
    return lines


def render_handles_console(records, coverage, *, verbose: bool = False,
                            os_major=None) -> None:
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
    folded and how to see them; `--verbose` prints every record.

    #102's `Rights` lines decode the mask of every row this view prints,
    with the same rules in both views (§5.6.4). They are derived text:
    they cannot change which records exist, which rows print, `by_type`,
    the limitations or the exit code, and they never state a verdict
    about a handle."""
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

    width = resolve_width()
    # Set while the table prints, read by the Rights caption below: a row
    # whose mask is absent contributes no line, so "any record has a
    # mask" is not the same question.
    rights_lines_printed = False
    # Set inside the same loop, the same way: whether any printed Rights
    # line actually carried an unconfirmed-name mark, so the caveat below
    # is never printed when nothing on screen needed it.
    unconfirmed_rights_printed = False

    if shown:
        # Cells are built once, up front, so the column widths below are
        # measured on exactly the strings that get printed (escaped, and
        # projected through handle_name_display()) rather than on the raw
        # record values -- an escape expands a name, and a column sized
        # on the unescaped value would be too narrow for its own row.
        rows = [(record.handle,
                 console_safe(handle_name_display(record.type_name, record.type_name_status)),
                 _access_display(record),
                 _count_display(record.handle_count),
                 _count_display(record.pointer_count),
                 console_safe(handle_name_display(record.object_name, record.object_name_status)))
                for record in shown]
        type_w = column_width("Type", [r[1] for r in rows],
                                minimum=_TYPE_COLUMN_MIN_WIDTH, cap=_TYPE_COLUMN_MAX_WIDTH)
        access_w = column_width("Access", [r[2] for r in rows],
                                  minimum=_ACCESS_COLUMN_MIN_WIDTH, cap=_ACCESS_COLUMN_MAX_WIDTH)
        cnt_w = column_width("Cnt", [r[3] for r in rows], minimum=_COUNT_COLUMN_MIN_WIDTH)
        ptr_w = column_width("Ptr", [r[4] for r in rows], minimum=_COUNT_COLUMN_MIN_WIDTH)

        # `Object` is the last column and is never padded: padding a
        # trailing column only adds invisible trailing whitespace.
        header = (f"{'Handle':<{_HANDLE_COLUMN_WIDTH}}  {'Type':<{type_w}}  "
                  f"{'Access':<{access_w}}  {'Cnt':>{cnt_w}}  {'Ptr':>{ptr_w}}  Object")
        print()
        print(f"  {DIM(header)}")
        # #102: each row is immediately followed by what its mask
        # permits, indented under it. Zipped against `shown` rather than
        # re-derived, so a row and its rights can never come from
        # different records.
        for record, (handle, type_display, access, count, pointers, object_display) in zip(
                shown, rows):
            print(f"  {handle:<{_HANDLE_COLUMN_WIDTH}}  {type_display:<{type_w}}  "
                  f"{access:<{access_w}}  {count:>{cnt_w}}  {pointers:>{ptr_w}}  "
                  f"{object_display}")
            for line in _rights_lines(record, width, os_major):
                print(f"  {line}")
                rights_lines_printed = True
                if _RIGHTS_UNCONFIRMED_MARK in line:
                    unconfirmed_rights_printed = True

    # #102: what each composite on screen stands for, once. Derived from
    # the printed rows, so it never explains a name that is not there.
    #
    # Computed here, ahead of the Rights caption below, because the `[?]`
    # mark can now appear inside an alias's own expansion (a COMPONENT of
    # `AllAccess`, not `AllAccess` itself) even on a row whose `Rights`
    # line carried no mark at all -- an `IoCompletion` row that decoded to
    # a bare `AllAccess` is exactly this case. The caption explaining what
    # `[?]` means has to know about both places it can show up, or it
    # would go unprinted while the mark it explains sits on screen further
    # down.
    alias_lines = _alias_entries(shown, width, os_major)
    if any(_RIGHTS_UNCONFIRMED_MARK in text for _head, text in alias_lines):
        unconfirmed_rights_printed = True

    # The two null-name labels are dumpex's own vocabulary and mean two
    # different things (§5.2.1); printed only when one of them is
    # actually on screen, so the legend never describes rows that are not
    # there. Read off the PRINTED rows, not the record list.
    if any(record.type_name_status != "ok" or record.object_name_status != "ok"
            for record in shown):
        print(f"  {DIM(_NAME_STATUS_LEGEND)}")

    # #102's one shared caption for the Rights lines above -- printed
    # only when at least one of them was, so it never explains something
    # that is not on screen.
    if rights_lines_printed:
        for line in wrap_text(_RIGHTS_LEGEND, width - 2):
            print(f"  {DIM(line)}")
        # Same rule as the alias block's own caveats: printed only when a
        # marked name is actually on screen, in EITHER place `[?]` can
        # appear -- see where `unconfirmed_rights_printed` is widened
        # above.
        if unconfirmed_rights_printed:
            for line in wrap_text(_RIGHTS_UNCONFIRMED_NOTE, width - 2):
                print(f"  {DIM(line)}")

    if alias_lines:
        print()
        print(f"  {BOLD(_ALIAS_BLOCK_HEADING)}")
        for line in wrap_text(_ALIAS_BLOCK_NOTE, width - 4):
            print(f"    {DIM(line)}")
        for head, text in alias_lines:
            print(f"  {head}{text}")
        if any("UnknownBits(" in text for _head, text in alias_lines):
            for line in wrap_text(_ALIAS_UNKNOWN_BITS_NOTE, width - 4):
                print(f"    {DIM(line)}")
        # Same rule: printed only when a marked name is actually on
        # screen, so the caveat never explains something absent.
        if any(_ALIAS_UNCONFIRMED_MARK in text for _head, text in alias_lines):
            for line in wrap_text(_ALIAS_UNCONFIRMED_NOTE, width - 4):
                print(f"    {DIM(line)}")

    # #98: exactly how many rows the default view folded, in per-type
    # counts, with the way to see them. Every folded row is still a
    # collected record -- it is in `by_type` above, in `summary.count`,
    # and in --json -- so this line says "not shown", never "not
    # captured".
    if folded:
        # summarize_handles_by_type(), so the fold line names a type
        # exactly as `By type:` and `summary.by_type` do -- including a
        # folded row that has no type name at all, which buckets as
        # "(unnamed)" rather than under some other type.
        listed = ", ".join(f"{console_safe(name)} {count}"
                            for name, count in summarize_handles_by_type(folded).items())
        print()
        print(f"  {len(folded)} anonymous handle(s) not shown "
              f"(no object name recorded): {listed}")
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


def _dump_os_major(mf: MinidumpFile) -> "int | None":
    """The dump's Windows MAJOR version from its SYSTEM_INFO stream, or
    None when there is no usable one.

    Read here rather than in collect_handles() because it changes nothing
    about the records: `granted_access` is the same integer either way,
    `--json` is untouched, and the version affects only which composite
    NAME the console prints for a Process or Thread mask. Keeping it out
    of HandleRecord is what leaves the v2.13 schema alone.

    None on anything unusable, including a version this reads as a
    non-int -- decode_access_mask() then uses the modern constants, which
    is the safe direction (see _registry_for)."""
    major = getattr(getattr(mf, "sysinfo", None), "MajorVersion", None)
    if isinstance(major, bool) or not isinstance(major, int) or major < 0:
        return None
    return major


def cmd_handles(mf: MinidumpFile, *, verbose: bool = False) -> CommandResult:
    """`verbose` reaches the RENDERER only. `collect_handles()` takes no
    verbosity at all, which is what makes "console filtering never
    removes a record from --json" a structural property rather than a
    rule someone has to remember (#98).

    The dump's OS major version reaches the renderer the same way and for
    the same reason: it selects a display NAME, never a record."""
    result = collect_handles(mf)
    render_handles_console(result.records, result.coverage, verbose=verbose,
                            os_major=_dump_os_major(mf))
    return result

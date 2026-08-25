"""`--profile` command -- issue #95's collect/render/command vertical
slice over docs/developer/recon_profile_contract.md.

Reports what evidence a process minidump CONTAINS and what kinds of
analysis that captured evidence can support -- an evidence-capability
map, never a detector:

    Profile describes what evidence exists. Hunters interpret that
    evidence.

Nothing here produces a malicious/clean verdict, a confidence score, an
ATT&CK mapping, or duplicates any hunter's own detection logic; nothing
here opens a process, queries a PID, or touches live system state. A
capability being "unavailable" means dumpex could not gather the evidence
that capability's own real collector/hunter needs -- never a claim that
the underlying activity is absent (discussion #94's own worked example:
a missing HandleDataStream means handle-based analysis is unavailable,
never that no suspicious handles existed).

Per #95's own v2.13 delivery boundary, `--profile` is not wired into
argparse and CURRENT_SCHEMA is not touched here -- #43 owns that atomic
cutover, together with `--process` and `--handles`. `cmd_profile()` exists
so a future CLI wiring (and this module's own tests) has one call that
collects and renders in the usual command shape.
"""
from typing import NamedTuple

from minidump.constants import MINIDUMP_STREAM_TYPE, MINIDUMP_TYPE
from minidump.minidumpfile import MinidumpFile

from dumpex.core.memory import (
    stream_failure, has_stream_directory, directory_truncated_count,
    DISPATCHED_STREAM_TYPES, STREAM_ATTR_NAMES,
)
from dumpex.output.coverage import (
    build_coverage_report, EvaluationRequirement, SourceRequirement, SourceObservation,
    SourceState, CoverageLimitation, LimitationCode,
)
from dumpex.output.command_result import CommandResult
from dumpex.output.records import (
    ProfileRecord, ProfileStreamEntry, ProfileMemoryCapture, ProfileCapabilityEntry,
    CapabilityLimitation, CapabilityStatus, CapabilityLimitationCode, StreamParserState,
    CAPABILITY_IDS, CAPABILITY_BY_ID, render_capability_limitation,
)
from dumpex.ui.colors import BOLD, DIM, GREEN, YELLOW, console_safe


# ── Stream inventory ────────────────────────────────────────────────────
# Which sub-attribute of a successfully-parsed stream object holds its own
# collection, for the ONE thing the raw parsed object alone can't tell
# apart: "parsed with content" vs. "parsed, verified empty" (§ stream
# semantics -- "present and successfully parsed" vs. "present and verified
# empty" are different facts). Deliberately closed and static -- this is
# not a new parser (the objects are already fully parsed by open_dump()
# before this module ever sees them), just naming which existing
# attribute each one already exposes. "sysinfo"/"misc_info" are
# intentionally absent: both are singular, non-collection streams, so
# "empty" isn't a meaningful state for either -- a present sysinfo/
# misc_info is always PARSED, never present_empty.
_COLLECTION_ACCESSORS = {
    "threads":            lambda obj: obj.threads,
    "modules":             lambda obj: obj.modules,
    "memory_segments":      lambda obj: obj.memory_segments,
    "memory_segments_64":    lambda obj: obj.memory_segments,
    "threads_ex":             lambda obj: obj.threads,
    "unloaded_modules":        lambda obj: obj.modules,
    "memory_info":              lambda obj: obj.infos,
    "thread_info":                lambda obj: obj.infos,
    "handles":                     lambda obj: obj.handles,
    "exception":                    lambda obj: obj.exception_records,
    "comment_a":                     lambda obj: obj.data,
    "comment_w":                      lambda obj: obj.data,
}

_DUPLICATE_STREAM_DETAIL_TEMPLATE = (
    "stream type {stream_type_id} appears at {count} directory index(es): {index_text}; "
    "dumpex retains only one shared parse outcome per stream type, so which entry it "
    "reflects cannot be determined")

# The displayed-index cap _build_stream_inventory's own detail text uses --
# see that function's own docstring for why this is a fixed slice of a
# precomputed list rather than an unbounded re-scan.
_MAX_DISPLAYED_DUPLICATE_INDEXES = 5

_UNPARSED_ATTR_STREAM_DETAIL = (
    "the dump declares this stream but no parsed stream object is available")

_TRUNCATED_STREAM_DETAIL_TEMPLATE = (
    "this stream declares {declared} item(s) but dumpex actually read {actual}; the "
    "shortfall was not read (and was not silently discarded)")


def _declared_item_count(attr_name: str, obj) -> "int | None":
    """The stream's OWN declared item count, independent of how many
    dumpex actually parsed -- None for every stream type except
    HandleDataStream, whose ParsedHandleDataStream retains `.header.
    NumberOfDescriptors` specifically so a truncation shortfall can be
    recovered (dumpex.core.memory.ParsedHandleDataStream's own
    docstring: "the caller can always recover how many were truncated as
    header.NumberOfDescriptors - len(handles)"). Not a new parser: this
    reads an attribute the real parser already exposes, the same "just
    naming which existing attribute" rule _collection_item_count's own
    docstring already follows for the item COUNT itself."""
    if attr_name != "handles":
        return None
    declared = getattr(getattr(obj, "header", None), "NumberOfDescriptors", None)
    if isinstance(declared, bool) or not isinstance(declared, int) or declared < 0:
        return None
    return declared


def _collection_item_count(attr_name: str, obj) -> "int | None":
    """None for a singular (non-collection) stream, or when the accessor
    itself can't be applied (defensive -- unreachable through today's
    open_dump(), whose own parse functions always populate the attribute
    the accessor reads); 0/positive-int for a collection stream's own item
    count, read off the SAME attribute dumpex.core.memory's existing
    per-stream helpers (get_modules/get_thread_infos/get_memory_regions/
    get_handles) already read for the streams that have one. A comment
    stream's `.data` is a plain string, not a list -- a non-empty one
    counts as one item, an empty/None one as zero, so "captured a comment"
    and "captured an empty comment" stay distinguishable the same way
    every other collection stream's own present/present_empty split is."""
    accessor = _COLLECTION_ACCESSORS.get(attr_name)
    if accessor is None:
        return None
    try:
        items = accessor(obj)
    except AttributeError:
        return None
    if items is None:
        return 0
    if isinstance(items, str):
        return 1 if items else 0
    try:
        return len(items)
    except TypeError:
        return None


def _build_stream_inventory(mf: MinidumpFile) -> "tuple[tuple, int, frozenset, frozenset]":
    """-> (streams, ambiguous_type_count, ambiguous_types, truncated_source_names).

    `truncated_source_names` (source names -- e.g. "handles" -- matching
    the same keys _capability_source_observations()'s own dict uses, per
    STREAM_ATTR_NAMES) is returned alongside the inventory for the exact
    same anti-drift reason `ambiguous_types` is: the capability registry
    must gate on the SAME truncation fact this function's own per-entry
    `detail` note already establishes, never recompute it independently
    (which is how a stream's row could end up saying "declares more
    items than dumpex read" while its capability entry stays silently
    `available`).

    `ambiguous_types` (the raw `StreamType` keys -- MINIDUMP_STREAM_TYPE
    members or plain ints for an unrecognized type -- with 2+ directory
    entries apiece) is returned alongside the inventory so the capability
    registry (_capability_source_observations/_memory_content_observation
    below) can refuse to treat that SAME stream type's mf.<attr>/
    stream_failure() state as trustworthy either -- see
    _stream_source_observation's own docstring for why silently trusting
    it there would let a capability read "available"/"limited" right next
    to a stream row that says its own state is indeterminate.

    `streams` is one ProfileStreamEntry per `mf.directories` entry, in
    directory order -- every entry, including duplicates and stream types
    this build's minidump library has never heard of.

    A stream type appearing at 2+ directory indexes is a real, if rare,
    property open_dump() cannot resolve unambiguously: Phase 2's parse
    loop (dumpex.core.memory.open_dump) keeps exactly ONE
    mf.<attr>/`_dumpex_stream_failures` pair PER STREAM TYPE, overwritten
    by whichever duplicate entry's own setattr() ran last -- and a LATER
    entry that raises does not clear an EARLIER entry's own successful
    mf.<attr> value, so a failure recorded for the type does not even
    guarantee mf.<attr> reflects a failed parse. There is no way, from
    outside that loop, to recover which physical directory entry the
    surviving mf.<attr>/failure state actually belongs to -- so every
    entry sharing an ambiguous type is reported as `parser_state
    ="indeterminate"` rather than guessing, and the command's own coverage
    is downgraded to `partial` (LimitationCode.PROFILE_STREAM_STATE_
    AMBIGUOUS) rather than silently presenting a confident answer built on
    a coin flip."""
    directories = list(getattr(mf, "directories", None) or [])
    # One O(N) pass building {stype: [directory_index, ...]} -- the single
    # source both the per-entry ambiguity check AND the displayed index
    # list below read from. Deliberately NOT an O(N) count pass plus a
    # per-entry O(k) re-scan of `directories` (an earlier version of this
    # function did exactly that): for a dump whose NumberOfStreams claims
    # many directory entries sharing one stream type -- a small, easy to
    # craft file, since NumberOfStreams/StreamType are both attacker-
    # controlled header fields -- a per-entry re-scan is O(k) work times k
    # ambiguous entries of that type, i.e. O(k^2) total, an easy
    # algorithmic-complexity DoS this single precomputed dict avoids.
    type_indexes: dict = {}
    for i, d in enumerate(directories):
        stype = getattr(d, "StreamType", None)
        type_indexes.setdefault(stype, []).append(i)

    entries = []
    ambiguous_types = set()
    truncated_source_names = set()
    for index, d in enumerate(directories):
        stype = getattr(d, "StreamType", None)
        is_recognized = isinstance(stype, MINIDUMP_STREAM_TYPE)
        stream_type_id = stype.value if is_recognized else int(stype)
        stream_type_name = stype.name if is_recognized else None

        # Dispatch is checked BEFORE duplicate-entry ambiguity: "which
        # entry does the shared mf.<attr>/failure state belong to" is
        # only a real question for a stream type dumpex actually
        # dispatches to a parser at all. A stream type with no
        # _STREAM_DISPATCH entry (e.g. FunctionTableStream) has no
        # mf.<attr> and no _dumpex_stream_failures slot for open_dump()'s
        # Phase 2 to entangle in the first place -- duplicate entries of
        # such a type are each independently, unambiguously "dumpex has
        # no parser for this", not "indeterminate" (which would falsely
        # claim something was lost to entanglement, and would falsely
        # downgrade command-level coverage to partial via
        # PROFILE_STREAM_STATE_AMBIGUOUS for a fact that isn't actually
        # ambiguous at all).
        if stype not in DISPATCHED_STREAM_TYPES:
            entries.append(ProfileStreamEntry(
                directory_index=index, stream_type_id=stream_type_id,
                stream_type_name=stream_type_name,
                parser_state=StreamParserState.UNPARSED.value, record_count=None, detail=None))
            continue

        sibling_indexes = type_indexes[stype]
        if len(sibling_indexes) > 1:
            # A fixed-size slice of the PRECOMPUTED list -- O(1), not a
            # second O(k) filter of `directories` -- so this stays cheap
            # even when one stream type is duplicated thousands of times.
            # Self-inclusive (simpler than filtering `index` out, and
            # accurate either way: the point is "this many entries share
            # this type", not "here are the OTHER ones").
            shown = sibling_indexes[:_MAX_DISPLAYED_DUPLICATE_INDEXES]
            more = len(sibling_indexes) - len(shown)
            index_text = str(shown) + (f" (+{more} more)" if more else "")
            entries.append(ProfileStreamEntry(
                directory_index=index, stream_type_id=stream_type_id,
                stream_type_name=stream_type_name,
                parser_state=StreamParserState.INDETERMINATE.value, record_count=None,
                detail=_DUPLICATE_STREAM_DETAIL_TEMPLATE.format(
                    stream_type_id=stream_type_id, count=len(sibling_indexes),
                    index_text=index_text)))
            ambiguous_types.add(stype)
            continue

        failure = stream_failure(mf, stype)
        if failure is not None:
            entries.append(ProfileStreamEntry(
                directory_index=index, stream_type_id=stream_type_id,
                stream_type_name=stream_type_name,
                parser_state=StreamParserState.FAILED.value, record_count=None, detail=failure))
            continue

        attr_name = STREAM_ATTR_NAMES[stype]
        obj = getattr(mf, attr_name, None)
        if obj is None:
            # Present in the directory, dumpex has a parser registered for
            # it, and no failure was recorded -- yet nothing parsed. Same
            # defensive "unreachable through today's open_dump(), fail
            # closed" shape as dumpex.commands.handles's own
            # _UNPARSED_STREAM_DETAIL case.
            entries.append(ProfileStreamEntry(
                directory_index=index, stream_type_id=stream_type_id,
                stream_type_name=stream_type_name,
                parser_state=StreamParserState.FAILED.value, record_count=None,
                detail=_UNPARSED_ATTR_STREAM_DETAIL))
            continue

        count = _collection_item_count(attr_name, obj)
        if count is None:
            entries.append(ProfileStreamEntry(
                directory_index=index, stream_type_id=stream_type_id,
                stream_type_name=stream_type_name,
                parser_state=StreamParserState.PARSED.value, record_count=None, detail=None))
        else:
            # Truncation is checked BEFORE deciding present_empty vs parsed:
            # a stream that declares 100 items and yields 0 is not "verified
            # empty", it is "100 items unread" -- see
            # _declared_item_count's own docstring for why HandleDataStream
            # is the one collection whose own declared count is available
            # to catch this at all. count == 0 only falls through to
            # PRESENT_EMPTY when nothing was ever declared (or the stream
            # type has no declared-count signal), i.e. the collection is
            # genuinely, verifiably empty rather than truncated to zero.
            declared = _declared_item_count(attr_name, obj)
            is_truncated = declared is not None and declared > count
            if count == 0 and not is_truncated:
                entries.append(ProfileStreamEntry(
                    directory_index=index, stream_type_id=stream_type_id,
                    stream_type_name=stream_type_name,
                    parser_state=StreamParserState.PRESENT_EMPTY.value, record_count=0,
                    detail=None))
            else:
                detail = None
                if is_truncated:
                    detail = _TRUNCATED_STREAM_DETAIL_TEMPLATE.format(
                        declared=declared, actual=count)
                    truncated_source_names.add(attr_name)
                entries.append(ProfileStreamEntry(
                    directory_index=index, stream_type_id=stream_type_id,
                    stream_type_name=stream_type_name,
                    parser_state=StreamParserState.PARSED.value, record_count=count,
                    detail=detail))

    return (tuple(entries), len(ambiguous_types), frozenset(ambiguous_types),
            frozenset(truncated_source_names))


# ── MINIDUMP_TYPE flags ─────────────────────────────────────────────────

def _decode_flags(header) -> "tuple[int | None, tuple, int | None]":
    """-> (raw_flags, recognized_flags, unrecognized_flag_bits).

    `header.Flags` (dumpex.core.memory._correct_header_union's own
    output) is None when the header's own trailing union+Flags bytes were
    truncated, a MINIDUMP_TYPE (possibly composite) instance when they
    decoded cleanly, or a plain int when the raw value didn't decode into
    that enum at all -- `int(flags)` handles all three uniformly rather
    than branching on which one it is. Iterates MINIDUMP_TYPE in its own
    declaration order (not alphabetical, not by bit value) so
    `recognized_flags` reads the same way MINIDUMP_TYPE itself is
    documented, and is fully deterministic."""
    if header is None:
        return None, (), None
    flags = getattr(header, "Flags", None)
    if flags is None:
        return None, (), None
    raw = int(flags)
    recognized = []
    accounted = 0
    for member in MINIDUMP_TYPE:
        if member.value and (raw & member.value) == member.value:
            recognized.append(member.name)
            accounted |= member.value
    return raw, tuple(recognized), raw & ~accounted


def _build_memory_capture(mf: MinidumpFile, raw_flags: "int | None",
                           memory64_present: bool, memory_present: bool,
                           resolution: "_MemoryContentResolution") -> ProfileMemoryCapture:
    """§5.3.2: `full_memory_flag_set` is read ONLY from `raw_flags`;
    `captured_segment_count`/`captured_bytes_total` are read ONLY from
    `resolution.segments` -- the SAME resolved segment table
    `_memory_content_observation()` derives its own state from (see
    `_resolve_memory_content()`), so the two can never disagree about
    which segments were actually captured.

    `memory64_list_present`/`memory_list_present` stay pure directory-
    presence facts regardless of ambiguity -- the entries genuinely
    exist, whether one or several."""
    if resolution.state in (SourceState.PRESENT, SourceState.PRESENT_EMPTY):
        captured_segment_count = len(resolution.segments)
        captured_bytes_total = sum(int(getattr(s, "size", None) or 0) for s in resolution.segments)
    else:
        captured_segment_count = None
        captured_bytes_total = None

    full_memory_flag_set = (None if raw_flags is None
                             else bool(raw_flags & MINIDUMP_TYPE.MiniDumpWithFullMemory.value))
    return ProfileMemoryCapture(
        full_memory_flag_set=full_memory_flag_set,
        memory64_list_present=memory64_present, memory_list_present=memory_present,
        captured_segment_count=captured_segment_count, captured_bytes_total=captured_bytes_total)


# ── Analysis-capability registry ────────────────────────────────────────
# The closed, frozen (source, required/optional, label) rule for each of
# #95's six first-release capability ids now lives in
# dumpex.output.records.CAPABILITY_REGISTRY/CAPABILITY_BY_ID -- the
# SINGLE place it is defined, cross-validated at ProfileCapabilityEntry
# construction time (records.py's own __post_init__) so a mismatch here
# can never silently produce a self-consistent-but-wrong record. See that
# module for the full per-capability rationale (which real collector/
# hunter each id mirrors, and why each one's required sources form an
# OR-group or a hard requirement).


_AMBIGUOUS_SOURCE_DETAIL = (
    "this stream type has duplicate directory entries; its parse outcome cannot be "
    "attributed with confidence -- see the stream inventory's own \"indeterminate\" entries")


class _MemoryContentResolution(NamedTuple):
    """-> the ONE place "which stream actually backs memory_content, and
    is it trustworthy" is decided -- shared by _memory_content_observation()
    (state/detail) and _build_memory_capture() (segments), so the two can
    never derive a different answer to the same question (the earlier,
    now-fixed bug this type exists to prevent: an ambiguous MemoryListStream
    that was never even consulted, because Memory64ListStream already had
    valid data, used to null out that perfectly good Memory64 evidence
    anyway)."""
    state: SourceState
    segments: tuple
    detail: "str | None"


def _stream_segments(mf: MinidumpFile, attr_name: str) -> "list | None":
    """The raw `.memory_segments` list off `mf.<attr_name>` (memory_
    segments_64 or memory_segments), or None when that stream never
    parsed at all -- distinguishing "never parsed" (None) from "parsed,
    zero segments" ([]) is exactly what lets _resolve_memory_content()
    tell present_empty apart from absent below, the same distinction
    dumpex.core.memory._memory_segments() itself collapses (by design,
    for read_region()'s own purposes, which only cares whether there is
    anything to read) but --profile's own evidence reporting must not."""
    obj = getattr(mf, attr_name, None)
    if obj is None:
        return None
    return list(getattr(obj, "memory_segments", None) or [])


def _resolve_memory_content(mf: MinidumpFile, ambiguous_types: frozenset) -> _MemoryContentResolution:
    """Applies dumpex.core.memory.get_memory_segments()'s own Memory64-
    preferred-over-MemoryList order, but evaluates ambiguity/failure ONLY
    for whichever stream is ACTUALLY selected by that order -- never for
    the other one. This mirrors §4.3's own "an unsatisfied OR-group
    sibling/fallback must never erase already-available preferred
    evidence" rule, applied to memory segments instead of a capability
    source: MemoryListStream having duplicate directory entries is
    irrelevant when Memory64ListStream itself already supplied real,
    unambiguous data (get_memory_segments() would never even look at
    MemoryListStream in that case), and the reverse is equally true.

    Memory64ListStream itself being ambiguous is a DIFFERENT case, not
    "fall through to MemoryListStream regardless": if a duplicate
    Memory64ListStream entry actually succeeded, mf.memory_segments_64
    holds real data and get_memory_segments() would use IT, never
    reaching MemoryListStream at all -- but WHICH duplicate entry
    produced that surviving state is exactly what §2.4 says cannot be
    known. Falling back to MemoryListStream's own (possibly quite
    different) data in that situation would risk reporting evidence that
    CONTRADICTS what read_region()/--extract/every hunter will actually
    resolve to when they call get_memory_segments() themselves -- so this
    fails closed to indeterminate instead, deliberately not falling
    through, even when MemoryListStream itself is perfectly healthy."""
    if MINIDUMP_STREAM_TYPE.Memory64ListStream in ambiguous_types:
        return _MemoryContentResolution(SourceState.FAILED, (), _AMBIGUOUS_SOURCE_DETAIL)

    memory64_segments = _stream_segments(mf, "memory_segments_64")
    if memory64_segments:
        # Memory64ListStream is unambiguous and supplied real data -- it
        # IS the selected source; MemoryListStream's own state (failed,
        # ambiguous, whatever) was never consulted and is irrelevant.
        return _MemoryContentResolution(SourceState.PRESENT, tuple(memory64_segments), None)

    # Memory64ListStream is unambiguous but supplied nothing (never
    # captured, present-empty, or genuinely failed) -- fall through to
    # MemoryListStream, matching _memory_segments()'s own preference
    # order exactly.
    if MINIDUMP_STREAM_TYPE.MemoryListStream in ambiguous_types:
        return _MemoryContentResolution(SourceState.FAILED, (), _AMBIGUOUS_SOURCE_DETAIL)

    memory_list_segments = _stream_segments(mf, "memory_segments")
    if memory_list_segments:
        # A genuine fallback: Memory64ListStream supplied nothing, so
        # MemoryListStream's own real data is what get_memory_segments()
        # actually resolves to. If Memory64ListStream's own absence is a
        # genuine parse FAILURE (not merely "never captured"), that fact
        # rides along as `detail` -- surfaced at the command level via
        # PROFILE_MEMORY_CONTENT_FALLBACK (collect_profile()) rather than
        # staying silent, even though the fallback's own numbers are
        # real and are still reported, not nulled.
        return _MemoryContentResolution(
            SourceState.PRESENT, tuple(memory_list_segments),
            stream_failure(mf, MINIDUMP_STREAM_TYPE.Memory64ListStream))

    # Neither stream supplied any segments. A genuine parse FAILURE on
    # either stream is checked BEFORE concluding present_empty: even a
    # present-and-verified-empty MemoryListStream does not prove the
    # PREFERRED Memory64ListStream would also have been empty had it
    # parsed successfully -- reporting an established zero in that case
    # would claim more confidence than the evidence actually supports
    # (the exact "silence is not defensible" reasoning
    # PROFILE_MEMORY_CONTENT_FALLBACK already applies one branch up,
    # applied here to the "nothing captured at all" case instead of the
    # "fallback produced real data" case).
    failure = (stream_failure(mf, MINIDUMP_STREAM_TYPE.Memory64ListStream)
               or stream_failure(mf, MINIDUMP_STREAM_TYPE.MemoryListStream))
    if failure is not None:
        return _MemoryContentResolution(SourceState.FAILED, (), failure)

    if memory64_segments is not None or memory_list_segments is not None:
        # At least one stream parsed (its own attribute is not None,
        # neither stream failed) but ended up with zero segments either
        # way -- present_empty, not "never parsed at all".
        return _MemoryContentResolution(SourceState.PRESENT_EMPTY, (), None)
    if (has_stream_directory(mf, MINIDUMP_STREAM_TYPE.Memory64ListStream)
            or has_stream_directory(mf, MINIDUMP_STREAM_TYPE.MemoryListStream)):
        return _MemoryContentResolution(SourceState.PRESENT_EMPTY, (), None)
    return _MemoryContentResolution(SourceState.ABSENT, (), None)


def _memory_content_observation(resolution: _MemoryContentResolution) -> SourceObservation:
    """A DERIVED source (neither a single real MINIDUMP_STREAM_TYPE, per
    §2.4's "a derived source never has a FAILED state reported through
    stream_failure() directly" shape) representing "captured memory bytes
    are actually readable", independent of the stream-inventory rows for
    Memory64ListStream/MemoryListStream themselves -- derived entirely
    from `resolution` (see _resolve_memory_content()), never recomputed
    here, so this and _build_memory_capture() can never disagree about
    which stream actually backs the evidence."""
    if resolution.state == SourceState.PRESENT:
        return SourceObservation(name="memory_content", state=SourceState.PRESENT,
                                  record_count=len(resolution.segments), detail=resolution.detail)
    if resolution.state == SourceState.PRESENT_EMPTY:
        return SourceObservation(name="memory_content", state=SourceState.PRESENT_EMPTY,
                                  record_count=0)
    if resolution.state == SourceState.FAILED:
        return SourceObservation(name="memory_content", state=SourceState.FAILED,
                                  detail=resolution.detail)
    return SourceObservation(name="memory_content", state=SourceState.ABSENT)


def _stream_source_observation(mf: MinidumpFile, name: str, stream_type, obj,
                                items: list, ambiguous_types: frozenset) -> SourceObservation:
    """The ABSENT/PRESENT_EMPTY/PRESENT/FAILED inference for a capability's
    own evidence source -- deliberately NOT dumpex.core.memory.
    observe_stream(), whose own ABSENT branch is a bare `if not obj`
    check that never consults the directory table at all. That shortcut is
    safe for observe_stream()'s own callers (every one of them reads a
    stream this SAME command also lists as one of its own primary
    sources, so a directory-present-but-object-None stream is already
    surfaced as failed evidence somewhere else in that command's own
    coverage), but --profile's stream inventory (_build_stream_inventory
    above) already resolves that exact ambiguity itself, one layer down,
    by falling back to has_stream_directory() before calling a
    directory-present, object-None stream ABSENT. Using observe_stream()
    here instead would let a capability's own required/optional gating
    disagree with the SAME stream's own inventory row -- "HandleDataStream:
    present (parse failed)" in `streams` next to a handle_analysis
    limitation reading "HandleDataStream is not present" would be exactly
    the kind of console/JSON self-contradiction #95's own correctness
    requirements forbid. This function and _build_stream_inventory's own
    per-entry resolution are kept side by side so they can never drift.

    `ambiguous_types` is checked FIRST, before `mf.<attr>`/
    stream_failure() are consulted at all: when a stream type has 2+
    directory entries, `mf.<attr>` and `_dumpex_stream_failures` reflect
    an ENTANGLED history across all of them (§2.4), so even a stream that
    currently reads as a clean PRESENT object may in fact be the surviving
    remnant of one succeeding duplicate sitting behind another's recorded
    failure, or vice versa -- there is no way to tell from here which.
    Reporting PRESENT (or even FAILED, which asserts a specific negative
    fact this function cannot actually back either) in that situation
    would let a capability read "available"/"limited" right next to a
    stream row that says its own state is "indeterminate" -- the same
    self-contradiction this function's very existence prevents for the
    directory-present-object-None case above. Both fold into the SAME
    FAILED state here (there is no dedicated "ambiguous" capability
    status/limitation code -- see docs/developer/recon_profile_contract.md §4.5):
    FAILED is the conservative, fail-closed choice matching every other
    "evidence exists but cannot be trusted" case this module already
    treats as required-source-failed."""
    if stream_type in ambiguous_types:
        return SourceObservation(name=name, state=SourceState.FAILED, detail=_AMBIGUOUS_SOURCE_DETAIL)
    failure = stream_failure(mf, stream_type)
    if failure is not None:
        return SourceObservation(name=name, state=SourceState.FAILED, detail=failure)
    if obj is not None:
        items = items or []
        if not items:
            return SourceObservation(name=name, state=SourceState.PRESENT_EMPTY, record_count=0)
        return SourceObservation(name=name, state=SourceState.PRESENT, record_count=len(items))
    if has_stream_directory(mf, stream_type):
        return SourceObservation(name=name, state=SourceState.FAILED, detail=_UNPARSED_ATTR_STREAM_DETAIL)
    return SourceObservation(name=name, state=SourceState.ABSENT)


def _capability_source_observations(mf: MinidumpFile, sysinfo_obs: SourceObservation,
                                     ambiguous_types: frozenset,
                                     memory_content_resolution: _MemoryContentResolution) -> dict:
    """The SourceObservation for every source ANY capability's own
    required_sources/optional_sources can name -- built once via
    _stream_source_observation() above, and shared by every
    _build_capability_entry() call below so a dump's "is HandleDataStream
    present" answer can never differ between handle_analysis and
    injector_handle_assessment."""
    modules_obj = getattr(mf, "modules", None)
    modules_obs = _stream_source_observation(
        mf, "modules", MINIDUMP_STREAM_TYPE.ModuleListStream, modules_obj,
        list(getattr(modules_obj, "modules", None) or []) if modules_obj is not None else [],
        ambiguous_types)

    threads_obj = getattr(mf, "threads", None)
    threads_obs = _stream_source_observation(
        mf, "threads", MINIDUMP_STREAM_TYPE.ThreadListStream, threads_obj,
        list(getattr(threads_obj, "threads", None) or []) if threads_obj is not None else [],
        ambiguous_types)

    thread_info_obj = getattr(mf, "thread_info", None)
    thread_info_obs = _stream_source_observation(
        mf, "thread_info", MINIDUMP_STREAM_TYPE.ThreadInfoListStream, thread_info_obj,
        list(getattr(thread_info_obj, "infos", None) or []) if thread_info_obj is not None else [],
        ambiguous_types)

    memory_info_obj = getattr(mf, "memory_info", None)
    memory_info_obs = _stream_source_observation(
        mf, "memory_info", MINIDUMP_STREAM_TYPE.MemoryInfoListStream, memory_info_obj,
        list(getattr(memory_info_obj, "infos", None) or []) if memory_info_obj is not None else [],
        ambiguous_types)

    handles_obj = getattr(mf, "handles", None)
    handles_obs = _stream_source_observation(
        mf, "handles", MINIDUMP_STREAM_TYPE.HandleDataStream, handles_obj,
        list(getattr(handles_obj, "handles", None) or []) if handles_obj is not None else [],
        ambiguous_types)

    return {
        "sysinfo":        sysinfo_obs,
        "modules":        modules_obs,
        "threads":        threads_obs,
        "thread_info":    thread_info_obs,
        "memory_info":    memory_info_obs,
        "handles":        handles_obs,
        "memory_content": _memory_content_observation(memory_content_resolution),
    }


# The real MINIDUMP_STREAM_TYPE backing each single-stream capability
# source name -- used ONLY to independently re-check ambiguity in
# _build_capability_entry below (§4.5's "never disagree with the stream
# inventory" rule), never to re-derive a SourceObservation a second time.
# "memory_content" is intentionally absent: unlike every other source
# here, it is DERIVED from TWO stream types with a preference order
# (Memory64ListStream over MemoryListStream), so "is memory_content
# ambiguous" is not a flat OR of the two streams' own ambiguity -- it
# depends on WHICH one was actually selected (see _resolve_memory_
# content()'s own docstring: a duplicated, never-consulted fallback must
# not override an already-selected, trustworthy preferred stream). That
# selection is resolved exactly once, by _resolve_memory_content(), and
# _member_effective_state() below reads its answer directly off
# sources["memory_content"] rather than re-deriving a second, coarser one
# here -- an earlier version of this function DID special-case
# "memory_content" with a flat two-stream OR, which silently reintroduced
# the exact bug _resolve_memory_content() exists to prevent (a capability
# limitation reading INDETERMINATE for memory_content while coverage.
# sources["memory_content"] itself reads PRESENT).
_SOURCE_STREAM_TYPES = {
    "sysinfo":     MINIDUMP_STREAM_TYPE.SystemInfoStream,
    "modules":     MINIDUMP_STREAM_TYPE.ModuleListStream,
    "threads":     MINIDUMP_STREAM_TYPE.ThreadListStream,
    "thread_info": MINIDUMP_STREAM_TYPE.ThreadInfoListStream,
    "memory_info": MINIDUMP_STREAM_TYPE.MemoryInfoListStream,
    "handles":     MINIDUMP_STREAM_TYPE.HandleDataStream,
}


def _source_is_ambiguous(name: str, ambiguous_types: frozenset) -> bool:
    """True when `name`'s own underlying stream type has a duplicate
    directory entry (§2.4) -- checked independently of whatever
    `sources[name].state` says, so _build_capability_entry can tell
    "genuinely failed to parse" apart from "ambiguous, may have parsed
    fine" even though _stream_source_observation() folds both into the
    same SourceState.FAILED for coverage.sources' own purposes (see that
    function's own docstring for why collapsing them there is still the
    right, conservative call -- this is the SEPARATE check that keeps the
    CAPABILITY LIMITATION's own wording from asserting a parse failure
    that may never have happened). Never called for "memory_content" --
    see _SOURCE_STREAM_TYPES' own comment on why that source's ambiguity
    is resolved differently, by _member_effective_state() reading
    _resolve_memory_content()'s own answer directly instead."""
    stream_type = _SOURCE_STREAM_TYPES.get(name)
    return stream_type is not None and stream_type in ambiguous_types


_REQUIRED_CODE_FOR_EFFECTIVE_STATE = {
    "absent":        CapabilityLimitationCode.REQUIRED_SOURCE_ABSENT.value,
    "failed":        CapabilityLimitationCode.REQUIRED_SOURCE_FAILED.value,
    "indeterminate": CapabilityLimitationCode.REQUIRED_SOURCE_INDETERMINATE.value,
}
_OPTIONAL_CODE_FOR_EFFECTIVE_STATE = {
    "absent":        CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value,
    "failed":        CapabilityLimitationCode.OPTIONAL_SOURCE_FAILED.value,
    "indeterminate": CapabilityLimitationCode.OPTIONAL_SOURCE_INDETERMINATE.value,
    "truncated":     CapabilityLimitationCode.OPTIONAL_SOURCE_TRUNCATED.value,
}
_GROUP_MEMBER_CODE_FOR_EFFECTIVE_STATE = {
    "absent":        CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_ABSENT.value,
    "failed":        CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_FAILED.value,
    "indeterminate": CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_INDETERMINATE.value,
}
# "ok" and "truncated" both SATISFY a required group (real, examinable
# data exists either way) -- "truncated" additionally emits its own
# REQUIRED_SOURCE_TRUNCATED/OPTIONAL_SOURCE_TRUNCATED limitation, which
# is why it is handled as its own branch in _build_capability_entry
# rather than folded into "ok" or routed through _GROUP_MEMBER_CODE_FOR_
# EFFECTIVE_STATE (a truncated source is not an unsatisfied sibling --
# it may be the SOLE, satisfying member of a single-member group, which
# REQUIRED_GROUP_MEMBER_* is explicitly forbidden to describe).
_SATISFYING_STATES = ("ok", "truncated")


def _member_effective_state(name: str, sources: dict, ambiguous_types: frozenset,
                             truncated_source_names: frozenset) -> str:
    """-> "ok" | "truncated" | "absent" | "failed" | "indeterminate" for
    one named source, ambiguity (§2.4) checked before `sources[name].
    state` for the same reason _source_is_ambiguous() itself exists: an
    ambiguous source's SourceObservation already reads FAILED (the
    conservative fold _stream_source_observation() applies for
    coverage.sources' own purposes), but the CAPABILITY LIMITATION built
    from it must use the dedicated INDETERMINATE code -- not FAILED,
    whose fixed template asserts "could not be parsed", a specific
    factual claim that is not always true here (every duplicate entry
    may have parsed cleanly; dumpex simply cannot attribute the
    surviving state to one of them). "ok"/"truncated" both cover PRESENT
    and PRESENT_EMPTY -- a present-empty stream is examinable evidence,
    not a gap (§4.3's "present_empty satisfies a required source" rule,
    matching --handles' own case-4 philosophy); "truncated" is the same
    PRESENT/PRESENT_EMPTY state additionally flagged in
    `truncated_source_names` (§ _build_stream_inventory's own
    truncation detection -- shared, never recomputed independently, so
    a capability can never disagree with that same stream's own row).

    "memory_content" is handled as its own branch, reading `sources[
    "memory_content"]` DIRECTLY rather than through `_source_is_
    ambiguous()`: that source's own ambiguity-vs-failure-vs-present
    distinction is already fully resolved by _resolve_memory_content()
    (which stream was actually SELECTED, per the Memory64-preferred-
    over-MemoryList order), and re-deriving it here from the raw
    `ambiguous_types` set (a flat OR over both underlying streams,
    regardless of which one was actually used) would let this function
    disagree with the very SourceObservation it is supposed to be
    describing -- exactly the "capability limitation contradicts
    coverage.sources" bug this whole record family exists to prevent."""
    if name == "memory_content":
        obs = sources["memory_content"]
        if obs.state in (SourceState.PRESENT, SourceState.PRESENT_EMPTY):
            return "ok"
        if obs.state == SourceState.FAILED:
            return "indeterminate" if obs.detail == _AMBIGUOUS_SOURCE_DETAIL else "failed"
        return "absent"

    if _source_is_ambiguous(name, ambiguous_types):
        return "indeterminate"
    state = sources[name].state
    if state in (SourceState.PRESENT, SourceState.PRESENT_EMPTY):
        return "truncated" if name in truncated_source_names else "ok"
    if state == SourceState.FAILED:
        return "failed"
    return "absent"


def _build_capability_entry(capability_id: str, sources: dict,
                             ambiguous_types: frozenset,
                             truncated_source_names: frozenset) -> ProfileCapabilityEntry:
    """Applies §4.3's rule: for each REQUIRED GROUP (an OR-group of one or
    more alternative source names -- see dumpex.output.records.
    CAPABILITY_REGISTRY's own comment), the capability is unavailable
    unless AT LEAST ONE member is usable. A single-member group is an
    ordinary hard requirement,
    unchanged from before OR-groups existed. When a group IS satisfied by
    one member, every OTHER, unsatisfied member of that SAME group
    degrades to a REQUIRED_GROUP_MEMBER_* limitation (contributing to
    `limited` rather than `unavailable`) -- this is what lets
    thread_analysis read `limited` rather than `unavailable` when only
    ThreadListStream (not ThreadInfoListStream) is present, matching
    dumpex.commands.threads' own real "still produces records, but
    degraded" behavior for the exact same input (§4.2).

    Deliberately NOT an OPTIONAL_SOURCE_* limitation for that sibling:
    the source is still a genuine member of a required OR-group (it
    lives in `required_sources`, not `optional_sources`), so calling its
    own gap "optional corroborating evidence" would publish a false
    statement about the record's own required/optional shape --
    ProfileCapabilityEntry.__post_init__ rejects that combination
    outright (§4.5).

    A capability is never checked against its own optional sources (nor
    an unsatisfied group's siblings, once ANY group has failed) when a
    DIFFERENT required group has already failed -- an unavailable
    capability's limitations name only what actually blocks it, per
    HANDLE_DESCRIPTOR_INVALID's own "no redundant fact once the aggregate
    one already explains the loss" precedent."""
    definition = CAPABILITY_BY_ID[capability_id]
    required_groups, optional = definition.required_source_groups, definition.optional_sources
    limitations = []
    required_ok = True
    for group in required_groups:
        member_states = [(name, _member_effective_state(name, sources, ambiguous_types,
                                                          truncated_source_names))
                          for name in group]
        if any(state in _SATISFYING_STATES for _, state in member_states):
            for name, state in member_states:
                if state == "truncated":
                    limitations.append(CapabilityLimitation(
                        code=CapabilityLimitationCode.REQUIRED_SOURCE_TRUNCATED.value, source=name))
                elif state != "ok":
                    limitations.append(CapabilityLimitation(
                        code=_GROUP_MEMBER_CODE_FOR_EFFECTIVE_STATE[state], source=name))
        else:
            required_ok = False
            for name, state in member_states:
                limitations.append(CapabilityLimitation(
                    code=_REQUIRED_CODE_FOR_EFFECTIVE_STATE[state], source=name))

    if not required_ok:
        status = CapabilityStatus.UNAVAILABLE.value
    else:
        for name in optional:
            state = _member_effective_state(name, sources, ambiguous_types, truncated_source_names)
            if state != "ok":
                limitations.append(CapabilityLimitation(
                    code=_OPTIONAL_CODE_FOR_EFFECTIVE_STATE[state], source=name))
        status = CapabilityStatus.LIMITED.value if limitations else CapabilityStatus.AVAILABLE.value

    return ProfileCapabilityEntry(capability_id=capability_id, status=status,
                                   required_source_groups=required_groups,
                                   required_sources=definition.required_sources,
                                   optional_sources=optional,
                                   limitations=tuple(limitations))


def _capability_status_counts(capabilities: tuple) -> dict:
    counts = {status.value: 0 for status in CapabilityStatus}
    for entry in capabilities:
        counts[entry.status] += 1
    return counts


# ── Collector ────────────────────────────────────────────────────────────

def collect_profile(mf: MinidumpFile) -> CommandResult:
    """Pure data, no printing. Returns a CommandResult[ProfileRecord]
    describing the dump's own directory table, MINIDUMP_TYPE flags,
    memory-capture facts, and the closed six-capability matrix (§ command
    coverage and exit semantics):

      - `complete` / exit 0  -- the directory/header facts needed to
        evaluate the profile were read successfully, even when one or
        more capabilities are unavailable because streams were never
        captured (a capability being unavailable is a fact ABOUT the
        dump, not a profiling failure -- it never downgrades coverage by
        itself).
      - `partial` / exit 3   -- a usable profile is produced but the raw
        MINIDUMP_TYPE flags or the architecture could not be read
        (PROFILE_FLAGS_UNAVAILABLE / PROFILE_ARCHITECTURE_UNAVAILABLE); a
        present stream's own parser state could not be determined
        accurately because of a duplicate directory entry
        (PROFILE_STREAM_STATE_AMBIGUOUS); the dump's own header declared
        more directory entries than the file actually holds
        (PROFILE_DIRECTORY_TRUNCATED); or captured memory content came
        from the MemoryListStream fallback because the preferred, richer
        Memory64ListStream genuinely failed to parse
        (PROFILE_MEMORY_CONTENT_FALLBACK) -- see docs/recon_profile_
        contract.md §5/§6.1 for the complete, authoritative list.
      - `not_evaluated` / exit 4 -- no defensible capability profile can
        be constructed at all (PROFILE_DIRECTORY_UNAVAILABLE: the header
        itself never parsed -- unreachable through today's open_dump(),
        which already aborts with exit 1 in that case, but handled here
        the same "fail closed for a state that could occur if internals
        changed" way handles.py's own case 1 is)."""
    header = getattr(mf, "header", None)
    if header is None:
        # No defensible capability profile can be constructed at all --
        # every OTHER computation below (stream inventory, capability
        # gating, memory-capture resolution) is skipped entirely rather
        # than derived from state that, by definition, cannot be trusted
        # enough to build a ProfileRecord from. Computing (and
        # publishing) a real capability_summary here would let a stray
        # leftover mf.<attr> -- reachable on a hand-built/test `mf`, or
        # any `mf` not assembled by open_dump() itself -- assert
        # "capability X is available" in the very same result that says
        # "no defensible profile could be constructed": a direct
        # self-contradiction between `coverage.status` and `summary`
        # that no consumer could resolve. Unreachable through today's
        # open_dump() (a header that fails to parse aborts the whole
        # dump open with exit 1 before any command runs), but this is
        # profile's own not_evaluated floor if that ever changes -- see
        # handles.py's own case 1 for the same "fail closed for a state
        # that could occur if internals changed" shape.
        directory_obs = SourceObservation(name="profile_directory", state=SourceState.ABSENT)
        coverage = build_coverage_report(
            {"profile_directory": directory_obs},
            evaluation_sources=EvaluationRequirement(
                sources=("profile_directory",),
                all_absent_code=LimitationCode.PROFILE_DIRECTORY_UNAVAILABLE))
        return CommandResult(kind="profile", records=[], coverage=coverage,
                              summary={"stream_count": 0,
                                       "capability_summary": _capability_status_counts(())})

    raw_flags, recognized_flags, unrecognized_flag_bits = _decode_flags(header)

    # Computed FIRST: every other per-source observation below (sysinfo,
    # the capability registry's modules/threads/.../memory_content) must
    # be able to check "is my own stream type ambiguous" before trusting
    # mf.<attr>/stream_failure() at all -- see _stream_source_observation's
    # own docstring for the console/JSON self-contradiction that omitting
    # this check produces.
    streams, ambiguous_count, ambiguous_types, truncated_source_names = _build_stream_inventory(mf)

    sysinfo = getattr(mf, "sysinfo", None)
    sysinfo_ambiguous = MINIDUMP_STREAM_TYPE.SystemInfoStream in ambiguous_types
    architecture = (sysinfo.ProcessorArchitecture.name
                     if not sysinfo_ambiguous and sysinfo is not None
                     and getattr(sysinfo, "ProcessorArchitecture", None) is not None
                     else None)
    sysinfo_obs = _stream_source_observation(
        mf, "sysinfo", MINIDUMP_STREAM_TYPE.SystemInfoStream, sysinfo,
        [sysinfo] if sysinfo is not None else [], ambiguous_types)

    memory64_present = has_stream_directory(mf, MINIDUMP_STREAM_TYPE.Memory64ListStream)
    memory_present = has_stream_directory(mf, MINIDUMP_STREAM_TYPE.MemoryListStream)
    memory_content_resolution = _resolve_memory_content(mf, ambiguous_types)
    memory_capture = _build_memory_capture(mf, raw_flags, memory64_present, memory_present,
                                            memory_content_resolution)

    capability_sources = _capability_source_observations(
        mf, sysinfo_obs, ambiguous_types, memory_content_resolution)
    capabilities = tuple(_build_capability_entry(cid, capability_sources, ambiguous_types,
                                                  truncated_source_names)
                          for cid in CAPABILITY_IDS)

    # header is not None past this point (the None case already returned
    # above), so there is always exactly one record and profile_directory
    # is always PRESENT.
    records = [ProfileRecord(
        architecture=architecture, raw_flags=raw_flags, recognized_flags=recognized_flags,
        unrecognized_flag_bits=unrecognized_flag_bits, memory_capture=memory_capture,
        streams=streams, capabilities=capabilities)]

    directory_obs = SourceObservation(name="profile_directory", state=SourceState.PRESENT,
                                       record_count=1)

    completeness_checks = [
        "profile_directory",
        SourceRequirement(source="sysinfo", absent_code=LimitationCode.PROFILE_ARCHITECTURE_UNAVAILABLE),
    ]
    if raw_flags is None:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PROFILE_FLAGS_UNAVAILABLE, source="profile_directory"))
    if ambiguous_count:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PROFILE_STREAM_STATE_AMBIGUOUS, source="profile_directory",
            affected_count=ambiguous_count))
    truncated_count = directory_truncated_count(mf)
    if truncated_count:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PROFILE_DIRECTORY_TRUNCATED, source="profile_directory",
            affected_count=truncated_count))
    # capability_sources["memory_content"].detail is set (by
    # _memory_content_observation, above) in TWO different situations that
    # must not be conflated: a genuine PRESENT-with-fallback (real segment
    # data came from the MemoryListStream fallback because the preferred
    # Memory64ListStream failed to parse) and the AMBIGUOUS-fold FAILED
    # case (§2.4), which already carries its own, differently-worded
    # detail and is not "could not be parsed" at all. Only the PRESENT
    # case is this specific coverage gap -- guarding on `state` (not just
    # a non-empty `detail`) is what keeps the two from being reported as
    # the same fact.
    memory_content_obs = capability_sources["memory_content"]
    if memory_content_obs.state == SourceState.PRESENT and memory_content_obs.detail:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PROFILE_MEMORY_CONTENT_FALLBACK, source="memory_content",
            detail=memory_content_obs.detail))

    # profile_directory is always PRESENT here (the header-is-None,
    # not_evaluated case already returned above, before any of the
    # per-stream/per-capability work below ever ran) -- this coverage
    # report can only ever resolve to complete or partial, never
    # not_evaluated. evaluation_sources is still declared, for the same
    # reason PROFILE_DIRECTORY_UNAVAILABLE itself is still a real code in
    # the registry (§ its own docstring): a defensive floor for if
    # open_dump()'s own contract ever changes, not a live branch today.
    coverage = build_coverage_report(
        {**capability_sources, "profile_directory": directory_obs},
        evaluation_sources=EvaluationRequirement(
            sources=("profile_directory",),
            all_absent_code=LimitationCode.PROFILE_DIRECTORY_UNAVAILABLE),
        completeness_checks=completeness_checks)

    return CommandResult(kind="profile", records=records, coverage=coverage,
                          summary={"stream_count": len(streams),
                                   "capability_summary": _capability_status_counts(capabilities)})


# ── Console renderer ────────────────────────────────────────────────────
# Capability labels come from dumpex.output.records.CAPABILITY_BY_ID
# (each definition's own `label`) -- not hand-duplicated here, so the
# console can never show a different name than the registry that also
# defines that capability's own source rule.

_CAPABILITY_STATUS_DISPLAY = {
    CapabilityStatus.AVAILABLE.value:   (GREEN, "available"),
    CapabilityStatus.LIMITED.value:     (YELLOW, "limited"),
    CapabilityStatus.UNAVAILABLE.value: (YELLOW, "unavailable"),
}

_PARSER_STATE_DISPLAY = {
    StreamParserState.PARSED.value:        "parsed",
    StreamParserState.PRESENT_EMPTY.value: "present (empty)",
    StreamParserState.UNPARSED.value:      "present (not parsed by dumpex)",
    StreamParserState.FAILED.value:        "present (parse failed)",
    StreamParserState.INDETERMINATE.value: "present (ambiguous -- duplicate entry)",
}


def _headline(record: "ProfileRecord | None") -> str:
    if record is None:
        return "no defensible capability profile could be constructed"
    return f"{len(record.streams)} directory entr{'y' if len(record.streams) == 1 else 'ies'} inventoried"


def render_profile_console(records, coverage) -> None:
    """Projects ONLY the collected records and CoverageReport -- never
    re-reads `mf`, matching every other recon renderer's rule (§ this
    module's own header comment: "reuse existing normalized source
    observations ... do not re-open the dump or re-parse evidence in the
    renderer"). Names/strings that came from the dump go through
    console_safe() -- today that is only ProfileStreamEntry.detail
    (parser exception text) and record.architecture (a raw enum name, but
    escaped defensively like every other dump-derived string this
    codebase prints)."""
    record = records[0] if records else None
    print(f"\n{BOLD('═══ PROFILE ═══')}")
    print(f"  {_headline(record)}")

    if record is not None:
        print(f"\n  {BOLD('Basic')}")
        print(f"    {'Architecture':<24} {console_safe(record.architecture) or '(unknown)'}")
        mc = record.memory_capture
        full_mem = {True: "yes", False: "no", None: "(unknown)"}[mc.full_memory_flag_set]
        print(f"    {'Full memory (flag)':<24} {full_mem}")
        # null ("could not be established" -- neither memory stream ever
        # parsed, or the preferred one is ambiguous/failed) and 0
        # ("established: captured, and verified empty") must never render
        # the same way -- §1's own "the two are never conflated" rule,
        # applied to the one field this renderer previously collapsed
        # into a single "(none captured)" string for both.
        captured = ("(unknown)" if mc.captured_segment_count is None
                    else f"{mc.captured_segment_count} segment(s), "
                         f"{mc.captured_bytes_total} byte(s)")
        print(f"    {'Captured memory content':<24} {captured}")
        if record.raw_flags is not None:
            print(f"    {'Raw MINIDUMP_TYPE flags':<24} 0x{record.raw_flags:x}")
            flags_text = ", ".join(record.recognized_flags) if record.recognized_flags else "(none)"
            print(f"    {'Recognized flags':<24} {flags_text}")

        print(f"\n  {BOLD('Streams')}")
        for entry in record.streams:
            name = entry.stream_type_name or f"(unknown type {entry.stream_type_id})"
            state_text = _PARSER_STATE_DISPLAY[entry.parser_state]
            count_text = f" [{entry.record_count}]" if entry.record_count is not None else ""
            print(f"    {name:<28} {state_text}{count_text}")
            if entry.detail is not None:
                # A parser exception's own text (FAILED) or this module's
                # own explanation of which other directory index(es) it
                # conflicts with (INDETERMINATE) -- console_safe() either
                # way, the same as coverage.reasons below: a parser
                # exception can embed bytes read from the dump (e.g. a
                # struct.error interpolating a malformed length or a
                # decoded fragment), so it is never trusted to stay free
                # of terminal-control text just because it came from
                # Python's own exception machinery rather than a named
                # dump field.
                print(f"        {DIM(console_safe(entry.detail))}")

        print(f"\n  {BOLD('Analysis capabilities')}")
        for entry in record.capabilities:
            color, text = _CAPABILITY_STATUS_DISPLAY[entry.status]
            label = CAPABILITY_BY_ID[entry.capability_id].label
            print(f"    {label:<32} {color(text)}")
            for limitation in entry.limitations:
                # render_capability_limitation() -- the SAME function
                # CapabilityLimitation.to_dict()'s own `detail` field
                # calls -- so the console line and the JSON `detail`
                # can never read two different sentences for the same
                # (code, source) pair (the raw code constant alone,
                # printed here in an earlier draft, was far less
                # informative and NOT what to_dict() actually reports).
                text = render_capability_limitation(limitation.code, limitation.source)
                print(f"        {YELLOW('-')} {console_safe(text)}")

    for reason in coverage.reasons:
        print(f"\n  {YELLOW('[~]')} {console_safe(reason)}")

    print()


def cmd_profile(mf: MinidumpFile) -> CommandResult:
    result = collect_profile(mf)
    render_profile_console(result.records, result.coverage)
    return result

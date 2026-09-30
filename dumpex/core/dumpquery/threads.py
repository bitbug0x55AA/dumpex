"""Thread records and thread contexts: the DumpFlags vocabulary, the
standing of a recorded StartAddress, the captured current instruction
pointer, and the joins between the two streams that carry them.

A thread's ThreadInfoListStream record (where it began, and what its
producer says about that record) and its ThreadListStream CONTEXT (where
it is executing now) are independent facts from independent streams. The
functions here interpret each one and join them per TID; they never
substitute one for the other.

The interpretations take the record-presence test and the DumpFlags
reader as arguments, and the join takes its stream readers and per-thread
interpretations as arguments; the bound entry points in
`dumpex.core.memory` (`dump_flags_state`, `dump_flags_tags`,
`recorded_start_address`, `ip_context_conflict_for` and
`enriched_thread_contexts`) pass the legacy module's own names.
"""
from minidump.minidumpfile import MinidumpFile


DUMP_FLAG_ERROR_THREAD    = 0x00000001   # placeholder record: only ThreadId is valid
DUMP_FLAG_WRITING_THREAD  = 0x00000002
DUMP_FLAG_EXITED_THREAD   = 0x00000004
DUMP_FLAG_INVALID_INFO    = 0x00000008   # thread information could not be retrieved
DUMP_FLAG_INVALID_CONTEXT = 0x00000010
DUMP_FLAG_INVALID_TEB     = 0x00000020

# Bit order, so a combined value renders as a stable, reproducible tag
# list. The tag strings are the vocabulary `--threads` renders (bracketed
# there: `[NO_CTX]`).
_DUMP_FLAG_TAGS = (
    (DUMP_FLAG_ERROR_THREAD,    "ERROR"),
    (DUMP_FLAG_WRITING_THREAD,  "DUMPER"),
    (DUMP_FLAG_EXITED_THREAD,   "EXITED"),
    (DUMP_FLAG_INVALID_INFO,    "NO_INFO"),
    (DUMP_FLAG_INVALID_CONTEXT, "NO_CTX"),
    (DUMP_FLAG_INVALID_TEB,     "NO_TEB"),
)

# The flags that make everything in a MINIDUMP_THREAD_INFO record EXCEPT
# ThreadId meaningless: ERROR_THREAD is documented as "a placeholder
# thread due to an error accessing the thread -- no thread information
# exists beyond the thread identifier", and INVALID_INFO as "thread
# information could not be retrieved". StartAddress in such a record is
# an unwritten field, not an address the process ever had.
_DUMP_FLAGS_INFO_INVALID = DUMP_FLAG_ERROR_THREAD | DUMP_FLAG_INVALID_INFO

# `dump_flags_state`: can this record's DumpFlags value be established?
DUMP_FLAGS_RESOLVED   = "resolved"     # value known (0 == genuinely no flags set)
DUMP_FLAGS_UNRESOLVED = "unresolved"   # record exists, its value could not be read
DUMP_FLAGS_ABSENT     = "absent"       # no ThreadInfoListStream record for this TID

# `recorded_start_address`: what standing does this record's StartAddress have?
START_ADDRESS_RECORDED   = "recorded"     # flags known and not invalidating, field present
START_ADDRESS_INVALID    = "invalid"      # flags mark the record's own info invalid
START_ADDRESS_UNVERIFIED = "unverified"   # field present, its validity unestablished
START_ADDRESS_ABSENT     = "absent"       # no address was recorded for this thread


class RawThreadInfo:
    """
    Stand-in for a MINIDUMP_THREAD_INFO record, for a TID that exists in
    the base ThreadListStream but has no entry in the optional
    ThreadInfoListStream (that whole stream may be absent, or just this
    one TID may be missing from an otherwise-present stream).
    StartAddress/CreateTime/ExitTime/KernelTime/UserTime/ExitStatus/
    DumpFlags don't exist on the raw MINIDUMP_THREAD structure, so they
    stay None here rather than being guessed at -- this TID's CONTEXT
    (see get_thread_contexts) is unaffected and independently available.

    Shared by dumpex.commands.threads (--threads) and dumpex.commands.
    report (--report): both need the identical "this TID is real, but
    ThreadInfoListStream never covered it" placeholder, and a TID present
    only in the base stream must be reported the same way -- start
    address unknown, current IP independently available -- by either
    command.
    """
    __slots__ = ("ThreadId", "StartAddress", "CreateTime", "ExitTime",
                 "KernelTime", "UserTime", "ExitStatus", "DumpFlags",
                 "RawDumpFlags")

    def __init__(self, tid):
        self.ThreadId     = tid
        self.StartAddress = None
        self.CreateTime    = None
        self.ExitTime      = None
        self.KernelTime    = None
        self.UserTime      = None
        self.ExitStatus    = None
        self.DumpFlags     = None
        # No ThreadInfoListStream record means no raw DumpFlags value to
        # read either -- see dumpex.core.memory.parse_thread_info_stream.
        self.RawDumpFlags  = None


def get_thread_infos(mf: MinidumpFile) -> list:
    if mf.thread_info and mf.thread_info.infos:
        return mf.thread_info.infos
    return []


def get_thread_contexts(mf: MinidumpFile) -> list:
    """
    Return the CURRENT instruction pointer per thread, as recorded in
    ThreadListStream's per-thread CONTEXT/WOW64_CONTEXT at the moment the
    dump was taken -- the register state actually in flight, unlike
    ThreadInfoListStream.StartAddress (where the thread BEGAN, which says
    nothing about where it is executing right now).

    dumpex.core.memory.open_dump() parses each thread's context into
    thread.ContextObject; this extracts the one field hunt modules need in
    a uniform shape, handling both native x64 (CONTEXT.Rip) and WOW64
    32-bit-on-64-bit (WOW64_CONTEXT.Eip) -- distinguished via hasattr, NOT
    via "is the value zero", since a genuinely-zero RIP/EIP is
    indistinguishable from "attribute absent" once read through
    getattr(..., default=0).

    Returns list of {"ThreadId": int, "ip": int, "ip_reg": "RIP"|"EIP",
    "is_wow64": bool} -- one entry per thread whose context was actually
    parsed. A thread with no ContextObject (context stream missing/
    unparseable for that thread) is omitted, not defaulted to 0 -- callers
    treat "not in this list" as "no live IP available", not "IP is 0".
    """
    out = []
    if not (mf.threads and mf.threads.threads):
        return out
    for th in mf.threads.threads:
        ctx = getattr(th, 'ContextObject', None)
        if ctx is None:
            continue
        if hasattr(ctx, 'Rip'):
            out.append({"ThreadId": th.ThreadId, "ip": ctx.Rip, "ip_reg": "RIP", "is_wow64": False})
        elif hasattr(ctx, 'Eip'):
            out.append({"ThreadId": th.ThreadId, "ip": ctx.Eip, "ip_reg": "EIP", "is_wow64": True})
    return out


def _is_real_thread_info(thread_info) -> bool:
    """True only for an actual ThreadInfoListStream record. A missing
    record is either None (the caller's own lookup came up empty) or a
    RawThreadInfo placeholder, and the two mean the same thing: this TID
    has no ThreadInfoListStream entry to read anything off."""
    return thread_info is not None and not isinstance(thread_info, RawThreadInfo)


def dump_flags_value(thread_info) -> "int | None":
    """This record's DumpFlags as a raw bit mask, or None when the value
    cannot be established -- the single derivation every DumpFlags
    consumer goes through, so "no flags set" and "value unknown" cannot
    diverge between them.

    Prefers `.RawDumpFlags` (see dumpex.core.memory.parse_thread_info_stream).
    Falls back to a `.DumpFlags` enum's own `.value`, which IS the exact
    on-disk value wherever that single-member lookup succeeded at all. A
    record with neither reports None: 0x0 and an unrepresentable
    combination are indistinguishable at that point, and only one of them
    is harmless."""
    raw = getattr(thread_info, "RawDumpFlags", None)
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    value = getattr(getattr(thread_info, "DumpFlags", None), "value", None)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def thread_dump_flags_state(thread_info, *, is_recorded, flags_value) -> str:
    """One of DUMP_FLAGS_RESOLVED / _UNRESOLVED / _ABSENT for this record
    -- the fact that tells a consumer whether an empty `dump_flags_tags`
    list means "this thread carries no flags" or "nothing is known about
    this thread's flags".

    `is_recorded(thread_info)` says whether a real ThreadInfoListStream
    record is present and is asked first; `flags_value(thread_info)` reads
    its DumpFlags only when it is."""
    if not is_recorded(thread_info):
        return DUMP_FLAGS_ABSENT
    return (DUMP_FLAGS_RESOLVED if flags_value(thread_info) is not None
            else DUMP_FLAGS_UNRESOLVED)


def thread_dump_flags_tags(thread_info, *, flags_value) -> list:
    """Every DumpFlags bit set on this record, as the short tags
    `--threads` renders, in bit order -- a combined value yields one tag
    per bit rather than collapsing to a single name or to nothing. Empty
    for a record whose value `flags_value(thread_info)` cannot establish;
    a caller distinguishing that from a genuinely flagless thread reads
    `dump_flags_state`."""
    value = flags_value(thread_info)
    if value is None:
        return []
    return [tag for bit, tag in _DUMP_FLAG_TAGS if value & bit]


def thread_start_address(thread_info, *, is_recorded, flags_value) -> tuple:
    """`(start_address, state)` for one thread -- the single derivation
    every command and hunter reads a thread's StartAddress through, so a
    start address that its own record disowns, or never carried, cannot
    be trusted by one consumer and rejected by another.

    `is_recorded(thread_info)` says whether a real ThreadInfoListStream
    record is present; `flags_value(thread_info)` reads its DumpFlags and
    is asked only for a present record.

    `state` is one of START_ADDRESS_RECORDED / _INVALID / _UNVERIFIED /
    _ABSENT:

    * _RECORDED -- a real record whose DumpFlags are known and carry
      neither ERROR_THREAD nor INVALID_INFO, and which actually carried
      a StartAddress field. The address is evidence.
    * _INVALID -- the record's own DumpFlags say only ThreadId is valid
      (see _DUMP_FLAGS_INFO_INVALID). `start_address` is None: a field
      the producer never filled in is missing evidence, and reporting
      its zero bytes as address 0x0 would manufacture a confirmed "not
      in any module" finding out of that absence.
    * _UNVERIFIED -- a real record that carried an address, but whose
      DumpFlags value could not be established. The address is returned
      unchanged -- it is real data and discarding it would lose evidence
      -- but nothing establishes that the producer stood behind it, so it
      must not feed a confirmed finding on its own.
    * _ABSENT -- no start address was recorded for this thread at all:
      no ThreadInfoListStream record (see RawThreadInfo), or one whose
      own declared record size stopped short of the StartAddress field
      (see dumpex.core.memory.parse_thread_info_stream). Readable
      DumpFlags say nothing about whether the address field was captured,
      so they never promote this case. `start_address` is None, never
      coerced to 0.

    A thread's own captured current IP is an independent fact from an
    independent stream and is neither consulted nor substituted here;
    see get_thread_contexts."""
    if not is_recorded(thread_info):
        return None, START_ADDRESS_ABSENT
    value = flags_value(thread_info)
    if value is not None and value & _DUMP_FLAGS_INFO_INVALID:
        return None, START_ADDRESS_INVALID
    address = getattr(thread_info, "StartAddress", None)
    if address is None:
        return None, START_ADDRESS_ABSENT
    if value is None:
        return address, START_ADDRESS_UNVERIFIED
    return address, START_ADDRESS_RECORDED


def thread_context_conflict(ip: "int | None", thread_info, *, is_recorded,
                            flags_value) -> "bool | None":
    """Tri-state join of a thread's captured CONTEXT (`ip`, from the base
    ThreadListStream/get_thread_contexts) against its own
    ThreadInfoListStream record's DumpFlags -- the single derivation
    dumpex.commands.threads (--threads) and dumpex.commands.report
    (--report) both consume, so a TID's dispute status cannot read
    differently between the two commands.

    `thread_info` is the record this TID resolved to: a real
    ThreadInfoListStream entry, or None/a RawThreadInfo placeholder when
    the stream never covered it; `is_recorded(thread_info)` tells the two
    apart, and `flags_value(thread_info)` is asked for the DumpFlags of a
    present record only.

    False when `ip` is None: there is no captured value to dispute,
    regardless of whether ThreadInfoListStream covers this TID at all.

    Otherwise None -- undeterminable, never a confirmed False -- in both
    states where the join cannot actually be performed:

    * no ThreadInfoListStream entry for this TID at all (see
      RawThreadInfo): there is nothing to join `ip` against, and
    * an entry whose DumpFlags value could not be established (see
      dump_flags_value): a value that cannot be read disputes nothing
      and clears nothing.

    Only when a real record's flags are actually known is the join
    performed: True exactly when MINIDUMP_THREAD_INFO_INVALID_CONTEXT is
    among them (the `[NO_CTX]` tag --threads renders), which a combined
    flag value satisfies the same as a lone one."""
    if ip is None:
        return False
    flags = flags_value(thread_info) if is_recorded(thread_info) else None
    if flags is None:
        return None
    return bool(flags & DUMP_FLAG_INVALID_CONTEXT)


def join_thread_contexts(mf: MinidumpFile, *, thread_infos, thread_contexts,
                         start_address, context_conflict) -> list:
    """`thread_contexts(mf)`'s dicts, each augmented with this same TID's
    own ThreadInfoListStream-sourced `"start_address"`/
    `"start_address_state"` (`start_address(record)`) and tri-state
    `"ip_context_conflict"` (`context_conflict(ip, record)`) -- the single
    join `dumpex.commands.threads`, `dumpex.commands.report`, and every
    `--hunt` hunter that reads a thread's current RIP/EIP (injection,
    stomping, pipe) share, so the SAME TID's start address and dispute
    status cannot read differently across commands or across hunters.
    The context dicts' own keys (`"ip"`, `"ip_reg"`, `"ThreadId"`,
    `"is_wow64"`) are kept unchanged; only these three are added.

    `thread_infos(mf)` is read first and indexed by ThreadId; a TID it
    does not cover is joined against None. `"start_address"` is the
    record's own address only where that record stands behind it: a
    record whose DumpFlags mark its thread information invalid contributes
    None here, exactly like a TID the stream never covered, and
    `"start_address_state"` says which of the two it was."""
    infos_by_tid = {ti.ThreadId: ti for ti in thread_infos(mf)}
    out = []
    for c in thread_contexts(mf):
        ti = infos_by_tid.get(c["ThreadId"])
        address, address_state = start_address(ti)
        out.append({
            **c,
            "start_address": address,
            "start_address_state": address_state,
            "ip_context_conflict": context_conflict(c["ip"], ti),
        })
    return out

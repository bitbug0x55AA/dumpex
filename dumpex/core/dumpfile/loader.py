"""Minidump opening: the header union correction, the file-size-bounded
directory walk, per-stream parse isolation, thread-context and PEB
phases, and the loader facts recorded on the returned `MinidumpFile`
(stream parse failures and the directory shortfall).

Nothing here prints or exits: a file that is missing or is not a usable
minidump raises `DumpFileNotFoundError` or `DumpFormatError`, and
`dumpex.core.memory.open_dump` reports either on stdout and exits 1. That
entry point also supplies the stream dispatch table and the context and
PEB parsers from the legacy module's namespace.
"""
import os

from minidump.minidumpfile import MinidumpFile
from minidump.header import MinidumpHeader
from minidump.directory import MINIDUMP_DIRECTORY
from minidump.common_structs import MINIDUMP_LOCATION_DESCRIPTOR
from minidump.constants import MINIDUMP_STREAM_TYPE, MINIDUMP_TYPE
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE


# ── MINIDUMP_HEADER's union: an installed-library layout misread ──────────
# The real MINIDUMP_HEADER (dbghelp.h) is 32 bytes and declares
# Reserved/TimeDateStamp as a UNION -- the SAME four bytes at offset 0x14 --
# followed by a ULONG64 Flags:
#
#   0x00 Signature            0x04 Version + ImplementationVersion
#   0x08 NumberOfStreams      0x0C StreamDirectoryRva      0x10 CheckSum
#   0x14 union { ULONG32 Reserved; ULONG32 TimeDateStamp; }
#   0x18 ULONG64 Flags
#
# The installed library (.venv/Lib/site-packages/minidump/header.py,
# MinidumpHeader.parse) reads the union as two CONSECUTIVE UINT32s and
# Flags as a UINT32, so its fields still total exactly 32 bytes -- the
# parse succeeds, the signature check passes, nothing raises -- but every
# field from 0x14 on lands one slot too late:
#   header.Reserved      <- 0x14: the REAL TimeDateStamp
#   header.TimeDateStamp <- 0x18: Flags's low 32 bits
#   header.Flags         <- 0x1C: Flags's high 32 bits (0 for every
#                                 currently-defined MINIDUMP_TYPE bit)
# Left uncorrected, --sysinfo's `dump_time_utc` (§4.2.2) renders a dump's
# TYPE FLAGS as epoch seconds: a small, constant, producer-dependent 1970
# date (0x00021826 -> 1970-01-02) that reads as real evidence and is wrong
# for every dump ever written. The fix-up below re-reads those trailing 12
# bytes at their true offsets, so `header.TimeDateStamp` means what its
# name says for every `mf` that came from open_dump().

_HEADER_UNION_OFFSET = 0x14    # union { Reserved, TimeDateStamp }
_HEADER_UNION_SIZE   = 4       # ULONG32 Reserved / TimeDateStamp
_HEADER_FLAGS_SIZE   = 8       # ULONG64 Flags
_HEADER_TAIL_SIZE    = _HEADER_UNION_SIZE + _HEADER_FLAGS_SIZE


def _correct_header_union(header, file_handle) -> None:
    """Re-read MINIDUMP_HEADER's trailing 12 bytes at their REAL offsets
    and write them back onto an already-parsed `header`, in place (see the
    block comment above for the upstream misread this compensates for).
    TimeDateStamp and Reserved are set to the same value BECAUSE they are
    one union -- not a copy of one field into another.

    A field whose bytes are not ALL present is set to the value
    MinidumpHeader.__init__ gives it before any parse (0 for the union,
    None for Flags), never left holding what the upstream parse put there:
    a file truncated inside the header still parses successfully upstream
    (int.from_bytes(b'') is 0, and MINIDUMP_TYPE(0) is a valid
    MiniDumpNormal), so "the header parsed" is no proof that 32 bytes were
    there to read -- and the shifted value sitting in TimeDateStamp is
    precisely the flags-as-a-1970-date artifact this whole fix-up exists
    to stop publishing. The two fields are decided independently: bytes
    0x14-0x17 being present is the only thing the timestamp depends on, so
    a header truncated inside Flags still yields a real dump time.

    Flags is corrected too, not just the field --sysinfo reads: half-fixing
    a shifted layout leaves the other half as a landmine for the next
    caller, who would have no reason to suspect the field is a high dword.
    A mask the enum cannot decode is kept as the plain int rather than
    dropped -- the raw value is still the most faithful thing available,
    and this fix-up exists to make header fields MORE accurate, never to
    turn an odd one into a parse failure."""
    file_handle.seek(_HEADER_UNION_OFFSET, 0)
    tail = file_handle.read(_HEADER_TAIL_SIZE)

    if len(tail) >= _HEADER_UNION_SIZE:
        time_date_stamp = int.from_bytes(
            tail[:_HEADER_UNION_SIZE], byteorder="little", signed=False)
    else:
        time_date_stamp = 0
    header.TimeDateStamp = time_date_stamp
    header.Reserved = time_date_stamp

    if len(tail) != _HEADER_TAIL_SIZE:
        header.Flags = None
        return
    flags = int.from_bytes(tail[_HEADER_UNION_SIZE:], byteorder="little", signed=False)
    try:
        header.Flags = MINIDUMP_TYPE(flags)
    except Exception:
        header.Flags = flags


def _parse_directory_entry(file_handle):
    """Parse one directory entry while preserving unknown stream ids.

    Recognized stream ids remain enum members. Unrecognized and user-stream ids
    remain raw integers, and their Location descriptor is still parsed, so
    inventory commands retain RVA and DataSize instead of dropping the entry.
    Unknown ids therefore bypass stream dispatch without aborting an otherwise
    readable dump. This function never returns None.
    """
    raw_value = MINIDUMP_DIRECTORY.get_stream_type_value(file_handle)
    is_recognized = raw_value in MINIDUMP_STREAM_TYPE._value2member_map_
    d = MINIDUMP_DIRECTORY()
    d.StreamType = MINIDUMP_STREAM_TYPE(raw_value) if is_recognized else raw_value
    d.Location = MINIDUMP_LOCATION_DESCRIPTOR.parse(file_handle)
    return d


class DumpFileNotFoundError(Exception):
    """`path` does not exist. `.path` is the path as given."""

    def __init__(self, path):
        super().__init__(path)
        self.path = path


class DumpFormatError(Exception):
    """`path` exists but its header or directory table cannot be read:
    the file is not a usable minidump at all, so there is no per-stream
    evidence to salvage. `.path` is the path as given and `.cause` the
    exception the header/directory phase raised (also `__cause__`)."""

    def __init__(self, path, cause):
        super().__init__(path, cause)
        self.path = path
        self.cause = cause


# ── Loader: per-stream isolation ──────────────────────────────────────────
# Mirrors MinidumpFile._parse()'s three phases (.venv/Lib/site-packages/
# minidump/minidumpfile.py) using the library's own PUBLIC parser classes,
# with each stream individually guarded -- not a fork of the installed
# package. A parse exception in one stream is recorded against that
# stream and costs no other stream and not the dump-open call; see the
# contract's §2.4 for the per-command consequence matrix.


def load_minidump(path: str, *, stream_dispatch, context, wow64_context, peb) -> MinidumpFile:
    """Open `path` and parse it into a MinidumpFile.

    `stream_dispatch` maps each parsed MINIDUMP_STREAM_TYPE to
    `(mf attribute name, parse(directory, file_handle))`; a stream type it
    does not map is skipped. `context`/`wow64_context` parse an AMD64/x86
    thread's CONTEXT and `peb.from_minidump(mf)` builds the PEB.
    dumpex.core.memory.open_dump binds all four.

    Raises DumpFileNotFoundError when `path` does not exist and
    DumpFormatError when its header or directory table cannot be read.
    Beyond that nothing raises: a stream whose parse raises is recorded
    in `mf._dumpex_stream_failures` and its attribute stays None, and a
    failure in the thread-context or PEB phase is swallowed exactly as
    the library's own parse swallows it. The returned MinidumpFile owns
    its open `file_handle`; the caller closes it. A handle already opened
    when DumpFormatError is raised is not closed here."""
    # Phase 0 -- the path must exist.
    if not os.path.exists(path):
        raise DumpFileNotFoundError(path)

    mf = MinidumpFile()
    mf.filename = path

    # Phase 1 -- header + directory table. Identical to
    # MinidumpFile.__parse_header(): reads only each directory entry's
    # StreamType/Rva/DataSize, so no per-stream parser runs here. A
    # failure in this phase means the file is not a usable minidump AT
    # ALL -- there is no per-stream evidence to salvage.
    try:
        mf.file_handle = open(path, "rb")
        mf.header = MinidumpHeader.parse(mf.file_handle)
        # Before anything reads a header field: the parse above lands
        # TimeDateStamp/Reserved/Flags on the wrong bytes (see
        # _correct_header_union). The directory walk below seeks
        # absolutely, so the file position this leaves behind is
        # irrelevant to it.
        _correct_header_union(mf.header, mf.file_handle)
        # header.NumberOfStreams is an attacker-controlled uint32 with no
        # relationship enforced to the file's real size -- a directory
        # entry is a fixed 12 bytes (StreamType(4) + Location(8)), so a
        # file of size S can back at most (S - StreamDirectoryRva) // 12
        # of them, however large NumberOfStreams claims to be. Walking
        # past that bound reads past EOF, where file.read(n) silently
        # returns FEWER than n bytes (b'' at the very end) rather than
        # raising -- and int.from_bytes(b'', ...) is 0, a real,
        # recognized MINIDUMP_STREAM_TYPE.UnusedStream value. Unbounded,
        # this fabricates one plausible-looking directory entry per
        # missing byte range out of a file that may be only tens of
        # bytes long: a trivially small, easily crafted input claiming a
        # near-uint32-max stream count turns into minutes of CPU time and
        # a directories list sized to match, none of which the file
        # actually contains. Bounding the walk here -- BEFORE any entry
        # is read, not by catching a short read afterwards -- is what
        # keeps a corrupted/truncated/adversarial directory table a
        # cheap, bounded fact instead of a DoS.
        file_size = os.fstat(mf.file_handle.fileno()).st_size
        max_readable_entries = max(0, (file_size - mf.header.StreamDirectoryRva) // 12)
        walkable_streams = min(mf.header.NumberOfStreams, max_readable_entries)
        # The declared count itself is not separately cached -- it is
        # already directly readable as mf.header.NumberOfStreams, so a
        # second copy here would be redundant state with nothing to keep
        # it in sync. Only the DERIVED shortfall (declared - readable) is
        # worth caching, since directory_truncated_count() is the one
        # fact callers actually need and recomputing it inline at every
        # call site would risk two different subtractions drifting apart.
        mf._dumpex_directory_truncated_count = mf.header.NumberOfStreams - walkable_streams
        for i in range(walkable_streams):
            mf.file_handle.seek(mf.header.StreamDirectoryRva + i * 12, 0)
            d = _parse_directory_entry(mf.file_handle)
            if d:   # never actually falsy any more (see that function's own
                     # docstring) -- kept as a defensive guard, not a live branch
                mf.directories.append(d)
    except Exception as e:
        raise DumpFormatError(path, e) from e

    # Phase 2 -- each stream's own parse is individually guarded: one
    # stream raising records a failure for that stream and aborts
    # neither any other stream's parse nor the dump-open call.
    stream_failures = {}   # {MINIDUMP_STREAM_TYPE: "ExcType: message"}
    for d in mf.directories:
        entry = stream_dispatch.get(d.StreamType)
        if entry is None:
            continue   # unrecognized / not-yet-implemented stream type -- the
                       # same silent skip __parse_directories()'s own unhandled
                       # branches take, not a failure.
        attr_name, parse = entry
        try:
            setattr(mf, attr_name, parse(d, mf.file_handle))
        except Exception as e:
            stream_failures[d.StreamType] = f"{type(e).__name__}: {e}"
            # mf.<attr_name> stays at its MinidumpFile.__init__ default
            # (None) -- isolated; every OTHER branch still runs.

    # Phase 3a -- thread contexts. Reproduces
    # MinidumpFile.__parse_thread_context() exactly, including its guard,
    # so thread.ContextObject consumers (get_thread_contexts(), and
    # through it the stomping/pipe/cs-beacon hunters) do not regress.
    try:
        if mf.sysinfo and mf.threads:
            for thread in mf.threads.threads:
                mf.file_handle.seek(thread.ThreadContext.Rva)
                if mf.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
                    thread.ContextObject = context.parse(mf.file_handle)
                elif mf.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL:
                    thread.ContextObject = wow64_context.parse(mf.file_handle)
    except Exception:
        pass   # same swallow-and-continue as the library's own guard

    # Phase 3b -- PEB. Same precondition and same swallow as
    # __parse_peb()/_parse().
    try:
        if mf.sysinfo and mf.threads:
            mf.peb = peb.from_minidump(mf)
    except Exception:
        pass

    mf._dumpex_stream_failures = stream_failures
    return mf


def stream_failure(mf: MinidumpFile, stream_type) -> "str | None":
    """The failure detail for `stream_type` (an entry in
    mf._dumpex_stream_failures), or None when that stream parsed (or was
    never present). The single place any command asks "did this stream
    fail to parse?" -- an `mf` built by a test/fixture that never went
    through open_dump() has no `_dumpex_stream_failures` attribute at
    all, so a missing attribute is treated as "no failures" rather than
    raising."""
    failures = getattr(mf, "_dumpex_stream_failures", None) or {}
    return failures.get(stream_type)


def has_stream_directory(mf: MinidumpFile, stream_type) -> bool:
    """True when the dump's own directory table carries an entry for
    `stream_type` -- i.e. the stream WAS captured, whatever later became
    of parsing it. The complement of stream_failure() for a command that
    must tell "this dump was never captured with that stream" apart from
    "it was captured and something went wrong with it": mf.<attr> is None
    in BOTH cases, so absence of the parsed object alone cannot decide it.

    Reads mf.directories (populated by open_dump()'s phase 1, before any
    per-stream parser runs, so it is unaffected by phase 2's isolation).
    An `mf` assembled by a test/fixture without a directories list at all
    is treated as declaring no streams rather than raising -- the same
    missing-attribute tolerance stream_failure() applies."""
    directories = getattr(mf, "directories", None) or ()
    return any(getattr(d, "StreamType", None) == stream_type for d in directories)


def directory_truncated_count(mf: MinidumpFile) -> int:
    """How many directory entries `mf.header.NumberOfStreams` declared
    that open_dump()'s Phase 1 walk could not actually read from the
    file (see open_dump()'s own file-size bound, next to where this
    attribute is set) -- 0 for a dump whose declared count and real size
    agree, or whenever `mf` was never built by open_dump() at all (a
    test/fixture `mf` is treated as declaring no shortfall, the same
    missing-attribute tolerance stream_failure()/has_stream_directory()
    apply)."""
    return getattr(mf, "_dumpex_directory_truncated_count", 0) or 0

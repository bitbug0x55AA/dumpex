"""Type-specific decoding of a captured `GrantedAccess` mask into
investigator-readable right names -- issue #102, deferred out of #42/#98
by docs/recon_process_sysinfo_handles_contract.md §5.2.

A PRESENTATION projection and nothing else. `HandleRecord.granted_access`
stays the raw integer it has always been on the wire (§1.3), the v2.13
schema is untouched, and every name produced here is derived from that
one already-normalized integer plus the record's own recorded type name.
Nothing in this module opens a handle, queries a live process, reads the
analysis host's ACLs, re-reads the dump, or infers a right from an object
NAME -- the low 16 bits of an access mask mean different things for
different object TYPES, and nothing else decides them.

Why a type registry rather than one global bit table: bit 0x0001 is
`FILE_READ_DATA` on a File, `PROCESS_TERMINATE` on a Process,
`THREAD_TERMINATE` on a Thread, `TOKEN_ASSIGN_PRIMARY` on a Token and
`SECTION_QUERY` on a Section. A single table would therefore be wrong for
every type but one, and confidently wrong is worse than a raw number --
which is exactly why §5.2 shipped the raw mask and deferred this.

Three rules keep a decode honest:

  1. **Nothing is invented.** Bits with no documented right for the
     recorded type stay visible at their own raw value
     (`UnknownBits(0x0000c000)`), and a type this registry does not carry
     decodes only the type-INDEPENDENT bits, with the whole type-specific
     remainder shown as captured
     (`TypeSpecificUnavailable(0x0000019f)`). The console prints this
     text directly under the row whose `Access` column holds the exact
     captured mask, so the derived reading and the evidence it came from
     are always one line apart.
  2. **Nothing is double-reported.** A composite alias consumes its own
     bits, so `AllAccess` and the fourteen component names it stands for
     can never both appear for the same mask.
  3. **Nothing is a verdict.** `AllAccess` on a Process handle is
     evidence worth reading, not proof that anything was done with it.
     No name here scores, ranks, or accuses; §1.6's observation rule
     covers the derived text exactly as it covers the record.

Names are the Windows constant with its object-type prefix dropped and
the remainder CamelCased (`FILE_READ_DATA` -> `ReadData`,
`PROCESS_QUERY_LIMITED_INFORMATION` -> `QueryLimitedInformation`): the
type is already on the row this text sits under, and repeating it in
every one of nine names costs the width that makes the rights readable
at all.
Each table below carries the authoritative constant next to the short
name so the mapping can be re-checked against the SDK headers rather than
taken on trust.

Kept a leaf module -- it imports nothing from dumpex -- so the renderer
that needs it cannot pull a command package into `dumpex.ui`.
"""
from dataclasses import dataclass

__all__ = [
    "DecodedAccess", "decode_access_mask", "format_access_rights",
    "wrap_rights", "SUPPORTED_OBJECT_TYPES",
]


_UINT32_MASK = 0xFFFFFFFF

# Standard rights (winnt.h), identical across every object type.
_STANDARD_RIGHTS = (
    (0x00010000, "Delete"),              # DELETE
    (0x00020000, "ReadControl"),         # READ_CONTROL
    (0x00040000, "WriteDac"),            # WRITE_DAC
    (0x00080000, "WriteOwner"),          # WRITE_OWNER
    (0x00100000, "Synchronize"),         # SYNCHRONIZE
    (0x01000000, "AccessSystemSecurity"),  # ACCESS_SYSTEM_SECURITY
    (0x02000000, "MaximumAllowed"),      # MAXIMUM_ALLOWED
)

# Generic rights are reported EXACTLY as captured and are never expanded
# through an assumed per-type GENERIC_MAPPING: the mapping lives in the
# kernel object type, the dump does not record it, and the mask a handle
# was actually opened with has normally already been mapped by the object
# manager. A generic bit still set in `GrantedAccess` is itself the fact
# worth showing.
_GENERIC_RIGHTS = (
    (0x10000000, "GenericAll"),          # GENERIC_ALL
    (0x20000000, "GenericExecute"),      # GENERIC_EXECUTE
    (0x40000000, "GenericWrite"),        # GENERIC_WRITE
    (0x80000000, "GenericRead"),         # GENERIC_READ
)

# ── Per-type specific rights ────────────────────────────────────────────
# Bits 0-15 of any access mask are the object type's OWN rights; every
# bit above them means the same thing for every type (winnt.h), which is
# why only this half of the mask needs a table per type.
#
# Keyed by the CASEFOLDED type name the dump recorded (§5.2's `type_name`
# is the NT object type, e.g. "File", "SymbolicLink"). Each entry is
# (specific-bit table, composite aliases).
#
# Only one composite alias per type is emitted, the type's own
# `*_ALL_ACCESS`. The `FILE_GENERIC_READ`/`KEY_READ` family is
# deliberately NOT aliased: those names differ from the GENERIC_* bits by
# one word while meaning something entirely different, and a reader who
# saw `Read` next to `(0x00120089)` could not tell which of the two the
# dump captured. `*_ALL_ACCESS` has no such twin, and it is the one case
# where the component list (fourteen names for a Process) is long enough
# to bury the rest of the row.

_FILE_RIGHTS = (
    # FILE_LIST_DIRECTORY/FILE_ADD_FILE/FILE_ADD_SUBDIRECTORY/
    # FILE_TRAVERSE are the same four bits under their directory names.
    # The descriptor does not record whether the object is a directory,
    # so the file-semantics name is used for all four rather than a
    # guess; both readings are the same captured bit.
    (0x0001, "ReadData"),                # FILE_READ_DATA
    (0x0002, "WriteData"),               # FILE_WRITE_DATA
    (0x0004, "AppendData"),              # FILE_APPEND_DATA
    (0x0008, "ReadEa"),                  # FILE_READ_EA
    (0x0010, "WriteEa"),                 # FILE_WRITE_EA
    (0x0020, "Execute"),                 # FILE_EXECUTE
    (0x0040, "DeleteChild"),             # FILE_DELETE_CHILD
    (0x0080, "ReadAttributes"),          # FILE_READ_ATTRIBUTES
    (0x0100, "WriteAttributes"),         # FILE_WRITE_ATTRIBUTES
)

_PROCESS_RIGHTS = (
    (0x0001, "Terminate"),               # PROCESS_TERMINATE
    (0x0002, "CreateThread"),            # PROCESS_CREATE_THREAD
    (0x0004, "SetSessionId"),            # PROCESS_SET_SESSIONID
    (0x0008, "VmOperation"),             # PROCESS_VM_OPERATION
    (0x0010, "VmRead"),                  # PROCESS_VM_READ
    (0x0020, "VmWrite"),                 # PROCESS_VM_WRITE
    (0x0040, "DupHandle"),               # PROCESS_DUP_HANDLE
    (0x0080, "CreateProcess"),           # PROCESS_CREATE_PROCESS
    (0x0100, "SetQuota"),                # PROCESS_SET_QUOTA
    (0x0200, "SetInformation"),          # PROCESS_SET_INFORMATION
    (0x0400, "QueryInformation"),        # PROCESS_QUERY_INFORMATION
    (0x0800, "SuspendResume"),           # PROCESS_SUSPEND_RESUME
    (0x1000, "QueryLimitedInformation"),  # PROCESS_QUERY_LIMITED_INFORMATION
    (0x2000, "SetLimitedInformation"),   # PROCESS_SET_LIMITED_INFORMATION
)

_THREAD_RIGHTS = (
    (0x0001, "Terminate"),               # THREAD_TERMINATE
    (0x0002, "SuspendResume"),           # THREAD_SUSPEND_RESUME
    (0x0004, "Alert"),                   # THREAD_ALERT
    (0x0008, "GetContext"),              # THREAD_GET_CONTEXT
    (0x0010, "SetContext"),              # THREAD_SET_CONTEXT
    (0x0020, "SetInformation"),          # THREAD_SET_INFORMATION
    (0x0040, "QueryInformation"),        # THREAD_QUERY_INFORMATION
    (0x0080, "SetThreadToken"),          # THREAD_SET_THREAD_TOKEN
    (0x0100, "Impersonate"),             # THREAD_IMPERSONATE
    (0x0200, "DirectImpersonation"),     # THREAD_DIRECT_IMPERSONATION
    (0x0400, "SetLimitedInformation"),   # THREAD_SET_LIMITED_INFORMATION
    (0x0800, "QueryLimitedInformation"),  # THREAD_QUERY_LIMITED_INFORMATION
    (0x1000, "Resume"),                  # THREAD_RESUME
)

_TOKEN_RIGHTS = (
    (0x0001, "AssignPrimary"),           # TOKEN_ASSIGN_PRIMARY
    (0x0002, "Duplicate"),               # TOKEN_DUPLICATE
    (0x0004, "Impersonate"),             # TOKEN_IMPERSONATE
    (0x0008, "Query"),                   # TOKEN_QUERY
    (0x0010, "QuerySource"),             # TOKEN_QUERY_SOURCE
    (0x0020, "AdjustPrivileges"),        # TOKEN_ADJUST_PRIVILEGES
    (0x0040, "AdjustGroups"),            # TOKEN_ADJUST_GROUPS
    (0x0080, "AdjustDefault"),           # TOKEN_ADJUST_DEFAULT
    (0x0100, "AdjustSessionId"),         # TOKEN_ADJUST_SESSIONID
)

_SECTION_RIGHTS = (
    (0x0001, "Query"),                   # SECTION_QUERY
    (0x0002, "MapWrite"),                # SECTION_MAP_WRITE
    (0x0004, "MapRead"),                 # SECTION_MAP_READ
    (0x0008, "MapExecute"),              # SECTION_MAP_EXECUTE
    (0x0010, "ExtendSize"),              # SECTION_EXTEND_SIZE
    (0x0020, "MapExecuteExplicit"),      # SECTION_MAP_EXECUTE_EXPLICIT
)

_JOB_RIGHTS = (
    (0x0001, "AssignProcess"),           # JOB_OBJECT_ASSIGN_PROCESS
    (0x0002, "SetAttributes"),           # JOB_OBJECT_SET_ATTRIBUTES
    (0x0004, "Query"),                   # JOB_OBJECT_QUERY
    (0x0008, "Terminate"),               # JOB_OBJECT_TERMINATE
    (0x0010, "SetSecurityAttributes"),   # JOB_OBJECT_SET_SECURITY_ATTRIBUTES
    (0x0020, "Impersonate"),             # JOB_OBJECT_IMPERSONATE
)

_DIRECTORY_RIGHTS = (
    (0x0001, "Query"),                   # DIRECTORY_QUERY
    (0x0002, "Traverse"),                # DIRECTORY_TRAVERSE
    (0x0004, "CreateObject"),            # DIRECTORY_CREATE_OBJECT
    (0x0008, "CreateSubdirectory"),      # DIRECTORY_CREATE_SUBDIRECTORY
)

_SYMBOLIC_LINK_RIGHTS = (
    (0x0001, "Query"),                   # SYMBOLIC_LINK_QUERY
    (0x0002, "Set"),                     # SYMBOLIC_LINK_SET
)

_EVENT_RIGHTS = (
    (0x0001, "QueryState"),              # EVENT_QUERY_STATE
    (0x0002, "ModifyState"),             # EVENT_MODIFY_STATE
)

_MUTANT_RIGHTS = (
    (0x0001, "QueryState"),              # MUTANT_QUERY_STATE
)

_SEMAPHORE_RIGHTS = (
    (0x0001, "QueryState"),              # SEMAPHORE_QUERY_STATE
    (0x0002, "ModifyState"),             # SEMAPHORE_MODIFY_STATE
)

_TIMER_RIGHTS = (
    (0x0001, "QueryState"),              # TIMER_QUERY_STATE
    (0x0002, "ModifyState"),             # TIMER_MODIFY_STATE
)

# Not in #102's own list, but the type a real handle table carries as
# often as File, and the one whose mask (`0x00020019`, KEY_READ) an
# analyst is most likely to meet on a persistence question. The registry
# is designed to be extended exactly this way -- a table and a key, with
# no change to the collector, the record, or the schema.
_KEY_RIGHTS = (
    (0x0001, "QueryValue"),              # KEY_QUERY_VALUE
    (0x0002, "SetValue"),                # KEY_SET_VALUE
    (0x0004, "CreateSubKey"),            # KEY_CREATE_SUB_KEY
    (0x0008, "EnumerateSubKeys"),        # KEY_ENUMERATE_SUB_KEYS
    (0x0010, "Notify"),                  # KEY_NOTIFY
    (0x0020, "CreateLink"),              # KEY_CREATE_LINK
)

# Three more types every real handle table carries. `Desktop` and
# `WindowStation` in particular are why this list is not the issue's list
# verbatim: a station/desktop handle is how one session's process reaches
# another's input queue, clipboard and screen, and a row that could only
# say "unknown type-specific bits" for it answered nothing at all.
#
# Neither has an `*_ALL_ACCESS` constant that includes the standard
# rights (`WINSTA_ALL_ACCESS` is the specific bits alone, and winuser.h
# defines no `DESKTOP_ALL_ACCESS`), so neither gets an alias: displaying
# `AllAccess` for one and meaning something different by it than on a
# File would be worse than listing what the mask actually grants.
_DESKTOP_RIGHTS = (
    (0x0001, "ReadObjects"),             # DESKTOP_READOBJECTS
    (0x0002, "CreateWindow"),            # DESKTOP_CREATEWINDOW
    (0x0004, "CreateMenu"),              # DESKTOP_CREATEMENU
    (0x0008, "HookControl"),             # DESKTOP_HOOKCONTROL
    (0x0010, "JournalRecord"),           # DESKTOP_JOURNALRECORD
    (0x0020, "JournalPlayback"),         # DESKTOP_JOURNALPLAYBACK
    (0x0040, "Enumerate"),               # DESKTOP_ENUMERATE
    (0x0080, "WriteObjects"),            # DESKTOP_WRITEOBJECTS
    (0x0100, "SwitchDesktop"),           # DESKTOP_SWITCHDESKTOP
)

_WINDOW_STATION_RIGHTS = (
    (0x0001, "EnumDesktops"),            # WINSTA_ENUMDESKTOPS
    (0x0002, "ReadAttributes"),          # WINSTA_READATTRIBUTES
    (0x0004, "AccessClipboard"),         # WINSTA_ACCESSCLIPBOARD
    (0x0008, "CreateDesktop"),           # WINSTA_CREATEDESKTOP
    (0x0010, "WriteAttributes"),         # WINSTA_WRITEATTRIBUTES
    (0x0020, "AccessGlobalAtoms"),       # WINSTA_ACCESSGLOBALATOMS
    (0x0040, "ExitWindows"),             # WINSTA_EXITWINDOWS
    (0x0100, "Enumerate"),               # WINSTA_ENUMERATE
    (0x0200, "ReadScreen"),              # WINSTA_READSCREEN
)

_IO_COMPLETION_RIGHTS = (
    (0x0001, "QueryState"),              # IO_COMPLETION_QUERY_STATE
    (0x0002, "ModifyState"),             # IO_COMPLETION_MODIFY_STATE
)

# (specific rights, ((alias value, alias name), ...)) per casefolded NT
# type name. Every alias value is the SDK's own `*_ALL_ACCESS` constant;
# an alias fires only when the mask carries ALL of its bits.
#
# `symboliclink` is the one type whose `*_ALL_ACCESS` does NOT cover its
# whole specific table: `SYMBOLIC_LINK_ALL_ACCESS` is
# `STANDARD_RIGHTS_REQUIRED | SYMBOLIC_LINK_QUERY` (0x000F0001) and
# predates `SYMBOLIC_LINK_SET` (0x0002), which was never folded into it.
# The alias value is left at what the constant actually is, so
# `0x000F0003` reads `AllAccess|Set` -- which is the honest decomposition
# (`Set` is a right the constant does not contain, and this table's job
# is to report what the SDK defines, not to tidy up its history).
# Widening the alias would instead report `AllAccess` for a mask that is
# not `SYMBOLIC_LINK_ALL_ACCESS`, and would hide the `Set` bit entirely.
_TYPE_REGISTRY = {
    "file":         (_FILE_RIGHTS,          ((0x001F01FF, "AllAccess"),)),
    "process":      (_PROCESS_RIGHTS,       ((0x001FFFFF, "AllAccess"),)),
    "thread":       (_THREAD_RIGHTS,        ((0x001FFFFF, "AllAccess"),)),
    "token":        (_TOKEN_RIGHTS,         ((0x000F01FF, "AllAccess"),)),
    "section":      (_SECTION_RIGHTS,       ((0x000F001F, "AllAccess"),)),
    "job":          (_JOB_RIGHTS,           ((0x001F003F, "AllAccess"),)),
    "directory":    (_DIRECTORY_RIGHTS,     ((0x000F000F, "AllAccess"),)),
    "symboliclink": (_SYMBOLIC_LINK_RIGHTS, ((0x000F0001, "AllAccess"),)),
    "event":        (_EVENT_RIGHTS,         ((0x001F0003, "AllAccess"),)),
    "mutant":       (_MUTANT_RIGHTS,        ((0x001F0001, "AllAccess"),)),
    "semaphore":    (_SEMAPHORE_RIGHTS,     ((0x001F0003, "AllAccess"),)),
    "timer":        (_TIMER_RIGHTS,         ((0x001F0003, "AllAccess"),)),
    "key":          (_KEY_RIGHTS,           ((0x000F003F, "AllAccess"),)),
    "iocompletion": (_IO_COMPLETION_RIGHTS, ((0x001F0003, "AllAccess"),)),
    # No alias -- see the two tables' own comment above.
    "desktop":      (_DESKTOP_RIGHTS,       ()),
    "windowstation": (_WINDOW_STATION_RIGHTS, ()),
}

# Types a real handle table also carries in quantity and this registry
# deliberately does NOT decode: `TpWorkerFactory`, `WaitCompletionPacket`,
# `ALPC Port`, `EtwRegistration`, `IRTimer`. Their access rights have no
# authoritative public definition (they live in reverse-engineered
# headers, or the object reuses another type's rights by convention
# only), and a guess presented as a decoded permission is exactly what
# §5.2 refused to ship. They decode their type-INDEPENDENT bits and
# report the rest as unknown type-specific bits, which is the honest
# answer and is visibly different from a decoded row.

# The type names this module decodes, in the spelling a dump records
# them with -- for documentation and tests, never for a lookup (lookups
# go through _normalize_type(), which is case-insensitive).
SUPPORTED_OBJECT_TYPES = frozenset({
    "Desktop", "Directory", "Event", "File", "IoCompletion", "Job", "Key",
    "Mutant", "Process", "Section", "Semaphore", "SymbolicLink", "Thread",
    "Timer", "Token", "WindowStation",
})

# What a mask with no bits at all says, spelled out. A zero
# `GrantedAccess` is a POSITIVE fact -- the descriptor recorded a mask
# and it granted nothing -- and must not read like the `(unknown)` an
# absent mask prints (§5.2's null rule).
NO_RIGHTS_TEXT = "(no rights)"

# The two undecoded remainders. Each names its own kind and carries its
# own raw value, so a reader can tell an undocumented BIT from an
# undecodable TYPE without a legend under the table -- an earlier cut
# wrote them as bare `+0x...`/`?0x...` markers and needed one.
#
# They read as a single token on purpose: the surrounding text is a list
# of right NAMES, and a remainder is one more item in that list rather
# than a sentence interrupting it.
_UNKNOWN_BITS_FORMAT = "UnknownBits(0x{:08x})"
_UNAVAILABLE_TYPE_FORMAT = "TypeSpecificUnavailable(0x{:08x})"

# Right names are separated by a padded pipe: the line is prose sitting
# under a table row, not a column an `awk` reads, and ` | ` is what makes
# a nine-name list scannable. It is also the ONLY place a `|` appears in
# the text, which is what lets wrap_rights() find its break points.
_SEPARATOR = " | "


@dataclass(frozen=True)
class DecodedAccess:
    """One decoded mask. `mask` is the authoritative captured value and
    is carried through unchanged; everything else is derived from it.

    `names` is in canonical order (see decode_access_mask) and never
    contains the residual -- `undecoded_bits` keeps that as a number, so
    a caller can tell "nothing was left over" from "0x0000c000 was" at
    the type level rather than by parsing a string.

    `type_supported` is False both when the record carried no usable type
    name and when the recorded type is not in this registry: in both
    cases the type-SPECIFIC bits are undecodable, which is one fact, and
    the type name itself is already displayed in the row's Type column."""
    mask:            int
    type_supported:  bool
    names:           tuple
    undecoded_bits:  int


def _normalize_type(type_name) -> "str | None":
    """The registry key for a recorded type name, or None when there is
    no usable one. Case- and whitespace-insensitive, because the name is
    a dump-recorded string and this is a display projection; anything
    that is not a non-empty string (including §5.2.1's null for an
    unnamed or unreadable type) has no key at all."""
    if not isinstance(type_name, str):
        return None
    key = type_name.strip().casefold()
    return key or None


def decode_access_mask(mask, type_name) -> "DecodedAccess | None":
    """Decode one `granted_access` value against one recorded type name.
    Returns None for a null/unusable mask -- absent evidence stays absent
    and is never decoded into "no rights" (§1.4).

    Canonical order, frozen so the same mask always reads the same way:

      1. composite aliases that fired, in registry order;
      2. the type's own specific rights, by ascending bit value;
      3. standard rights, by ascending bit value (Delete, ReadControl,
         WriteDac, WriteOwner, Synchronize, AccessSystemSecurity,
         MaximumAllowed);
      4. generic rights, by ascending bit value.

    Ordering by BIT VALUE rather than alphabetically keeps a right in the
    same position across every type and every mask, so two rows can be
    compared by eye. Every bit a name consumes is removed from the
    working value, so an alias and its components can never both appear
    and no bit is reported twice; whatever survives is `undecoded_bits`.

    A pure function of its two arguments: no host state, no live query,
    and a bounded walk over at most 14 + 7 + 4 table entries."""
    if isinstance(mask, bool) or not isinstance(mask, int) or mask < 0:
        return None

    remaining = mask & _UINT32_MASK
    registry = _TYPE_REGISTRY.get(_normalize_type(type_name))
    names = []

    if registry is not None:
        specific, aliases = registry
        for value, name in aliases:
            if value and remaining & value == value:
                names.append(name)
                remaining &= ~value
        for bit, name in specific:
            if remaining & bit:
                names.append(name)
                remaining &= ~bit

    for bit, name in _STANDARD_RIGHTS + _GENERIC_RIGHTS:
        if remaining & bit:
            names.append(name)
            remaining &= ~bit

    return DecodedAccess(mask=mask & _UINT32_MASK, type_supported=registry is not None,
                          names=tuple(names), undecoded_bits=remaining)


def format_access_rights(decoded: DecodedAccess) -> str:
    """The DERIVED text for one decoded mask -- the rights, then whatever
    was left undecoded:

        ReadData | WriteData | Synchronize
        AllAccess
        (no rights)
        Delete | ReadControl | TypeSpecificUnavailable(0x0000037f)

    The captured mask is deliberately NOT repeated here. It is printed
    once, in the row's own `Access` column directly above this text,
    which is the evidence anchor a reader scans, compares and copies; a
    second copy one line below it says nothing new and costs the width
    the right names need. The remainder tokens carry their own value
    because that value is a PART of the mask, not the mask.

    Three rules, none of them silent:

      * a mask with no bits at all is NO_RIGHTS_TEXT, never "" -- a
        captured mask granting nothing is a positive fact, and it is
        different from the `(unknown)` an absent mask prints in the
        column (§1.4);
      * bits with no documented right for a type this registry carries
        are reported as `UnknownBits(0x%08x)`, so an undocumented or
        future bit stays auditable at its own raw value instead of being
        guessed at or dropped;
      * every undecoded bit of a mask whose type this registry does NOT
        carry is reported as `TypeSpecificUnavailable(0x%08x)` instead,
        which is a different fact: nothing is wrong with the bit, dumpex
        simply has no type to read it against."""
    parts = list(decoded.names)
    if decoded.undecoded_bits:
        template = (_UNKNOWN_BITS_FORMAT if decoded.type_supported
                     else _UNAVAILABLE_TYPE_FORMAT)
        parts.append(template.format(decoded.undecoded_bits))
    return _SEPARATOR.join(parts) if parts else NO_RIGHTS_TEXT


def wrap_rights(text: str, width: int) -> list:
    """Wrap `format_access_rights()`'s output to `width` columns, always
    breaking AFTER a `|` so no right name is split across two lines and a
    continuation line can never be mistaken for a new entry.

    console_layout.wrap_text() cannot do this: it wraps on WHITESPACE,
    and every name here is one token by construction, so its only break
    points would be the separators -- which it would then drop, leaving
    a continued line that reads as a finished list. Here the separators
    are the break points and they stay on the line they continue.

    A single piece wider than `width` is placed alone on its own line and
    allowed to overflow rather than being cut -- the same rule
    wrap_text() applies to an over-long word, and the reason #102 forbids
    silent truncation."""
    # Two columns are reserved so the ` |` that marks a continued line
    # cannot itself push that line past `width`.
    budget = max(1, width - 2)
    lines = []
    current = ""
    for piece in text.split(_SEPARATOR):
        if not current:
            current = piece
        elif len(current) + len(_SEPARATOR) + len(piece) > budget:
            lines.append(current + " |")
            current = piece
        else:
            current += _SEPARATOR + piece
    lines.append(current)
    return lines

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
  2. **Nothing is double-reported.** A composite alias claims its own
     bits, so `AllAccess` and the fourteen component names it stands for
     can never both appear for the same mask, and no later name repeats
     what an earlier one already accounted for.
  3. **Nothing is a verdict.** `AllAccess` on a Process handle is
     evidence worth reading, not proof that anything was done with it.
     No name here scores, ranks, or accuses; §1.6's observation rule
     covers the derived text exactly as it covers the record.

Every name printed here is a dumpex DISPLAY FORM that maps precisely to
one Windows SDK, WDK or native constant -- it is not the constant's own
spelling, and "maps to a constant" is not the same claim as "maps to a
constant Microsoft documents": `Provenance` (below) records which of the
two is true for each one, and a handful -- `SYMBOLIC_LINK_*`,
`THREAD_ALERT`, `SEMAPHORE_QUERY_STATE`, `IO_COMPLETION_QUERY_STATE` --
have no confirmed header at all. The mapping drops the object-type
prefix and CamelCases the remainder
(`FILE_READ_DATA` -> `ReadData`, `THREAD_QUERY_LIMITED_INFORMATION` ->
`QueryLimitedInformation`, `KEY_READ` -> `KeyRead`, each type's
`*_ALL_ACCESS` -> `AllAccess`), because the type is already on the row
this text sits under and repeating it in every one of nine names costs
the width that makes the rights readable at all.

Source tracking here is PER CONSTANT, never per object type. An object
type is not a header, and treating it as one is how this module got a
fact wrong: `IoCompletion` was filed whole under the WDK, when in truth
`winnt.h` defines `IO_COMPLETION_MODIFY_STATE` and
`IO_COMPLETION_ALL_ACCESS` and only `IO_COMPLETION_QUERY_STATE` comes
from outside the Win32 SDK. `Thread` has the same shape (every right but
`THREAD_ALERT` is `winnt.h`), and so do `Event` and `Semaphore`. So every
entry below carries its OWN source, a type's sources are DERIVED from the
constants it actually uses (`object_type_sources`), and a type with more
than one is mixed-source and says so rather than being rounded to
whichever header most of it came from.

Per-constant means per constant CHECKED, not per constant listed. The
first pass at this fix moved three `*_QUERY_STATE` bits into "no
Microsoft header names it" as a group, because they have the same value,
the same display name and the same relationship to their type's
`*_ALL_ACCESS`. Microsoft documents one of the three
(`EVENT_QUERY_STATE`, `ntifs.h`), so grouping by resemblance had simply
reproduced the original defect at a smaller scale. Every source below is
established for that constant alone.

The provenances in use, each established for the specific constants it
covers rather than for an object family. A source is recorded together
with its EVIDENCE, and `Provenance.header` -- the only thing
`constant_source()` will return -- stays None until something confirms
one, so a lead can never be handed back as a fact:

  * `PROV_WINNT_H` -- Win32 SDK `winnt.h`, verified by grepping an
    installed SDK: the standard and generic rights, and the great
    majority of the per-type ones;
  * `PROV_WINUSER_H` -- Win32 SDK `winuser.h`, likewise verified:
    `DESKTOP_*` and `WINSTA_*`;
  * `PROV_NTIFS_H` -- WDK `ntifs.h`, named in a Microsoft reference page:
    `EVENT_QUERY_STATE` (the `ZwCreateEvent` reference) and the whole
    `DIRECTORY_*` set including `DIRECTORY_ALL_ACCESS` (the
    `ZwOpenDirectoryObject` reference). Both pages state `ntifs.h` under
    Requirements. These two sets share a HEADER, not an object family --
    an Event is not an Object Manager object -- so this must never be
    widened to "the Object Manager headers";
  * `PROV_WDM_H_ROUTINE_ONLY` -- **no confirmed header**, attributed to
    WDK `wdm.h`: `SYMBOLIC_LINK_*`. Microsoft documents the ROUTINE
    `ZwOpenSymbolicLinkObject` under `wdm.h`, but that page names no
    `SYMBOLIC_LINK_*` constant at all, so the header is a lead;
  * `PROV_NTDDK_H_ATTRIBUTED` -- **no confirmed header**, attributed to
    WDK `ntddk.h`: `THREAD_ALERT`, inherited from the original table
    rather than confirmed against a Microsoft page;
  * `PROV_NATIVE_UNCONFIRMED` -- **no confirmed header** and no
    attribution worth recording: `SEMAPHORE_QUERY_STATE` and
    `IO_COMPLETION_QUERY_STATE`, each checked on its OWN.
    `EVENT_QUERY_STATE` was briefly filed here too, purely because the
    three bits look alike, and Microsoft documents it. Grouping by
    resemblance is the mistake.

Every entry carries the authoritative constant AND its provenance beside
the display name, so a mapping is re-checked against the right header
rather than taken on trust, and `CONSTANT_PROVENANCE` exposes the same
fact keyed by constant for anything that needs to ask -- including the
console, which marks an unconfirmed composite rather than describing it
in the same words as `KEY_READ`. tests/unit/test_access_rights.py pins
every composite -- display name, value and full expansion -- against a
hand-written table that is not derived from this file, pins every
non-`winnt.h` provenance with the evidence for it, and re-greps the real
`winnt.h`/`winuser.h` on any machine that has a Windows SDK installed.

One constant PAIR has two values rather than two sources.
`PROCESS_ALL_ACCESS` and `THREAD_ALL_ACCESS` were widened by Vista, and
`winnt.h` still carries both definitions behind an `NTDDI_VERSION`
guard. `decode_access_mask()` takes an optional `os_major` for that and
nothing else; see `_registry_for`.

Kept a leaf module -- it imports nothing from dumpex -- so the renderer
that needs it cannot pull a command package into `dumpex.ui`.
"""
from dataclasses import dataclass

__all__ = [
    "DecodedAccess", "decode_access_mask", "format_access_rights",
    "access_right_groups", "expand_alias", "alias_names_in", "wrap_rights",
    "is_undecoded_token",
    "RIGHTS_SEPARATOR", "RIGHTS_CONTINUED_SUFFIX", "NO_RIGHTS_TEXT",
    "SUPPORTED_OBJECT_TYPES", "canonical_type_name",
    "CONSTANT_PROVENANCE", "Provenance", "constant_provenance",
    "constant_source", "object_type_sources", "alias_provenance",
    "unconfirmed_names", "unconfirmed_names_in_alias",
    "WINNT_H", "WINUSER_H", "NTIFS_H",
    "PROV_WINNT_H", "PROV_WINUSER_H", "PROV_NTIFS_H",
    "PROV_WDM_H_ROUTINE_ONLY", "PROV_NTDDK_H_ATTRIBUTED",
    "PROV_NATIVE_UNCONFIRMED",
    "VERIFIED_HEADER", "MICROSOFT_DOCUMENTATION", "RELATED_API_HEADER",
    "UNCONFIRMED_NATIVE", "CONFIRMED_EVIDENCE",
]


_UINT32_MASK = 0xFFFFFFFF

# ── Constant provenance ─────────────────────────────────────────────────
# What is recorded for each constant is not just a header but the
# EVIDENCE for that header, because the two are not the same claim and
# collapsing them is how a guess starts reading like a fact.
#
# `SYMBOLIC_LINK_QUERY` naming `wdm.h` looked exactly like
# `DIRECTORY_QUERY` naming `ntifs.h` while both were plain strings -- yet
# Microsoft's ZwOpenDirectoryObject page names DIRECTORY_QUERY outright,
# and no Microsoft page names SYMBOLIC_LINK_QUERY at all; `wdm.h` is
# merely where the related ROUTINE is documented. A model that can only
# say "the header is X" has to either overstate the second case or throw
# away the useful part of it.
#
# So `header` is the CONFIRMED defining header and is None until it is
# confirmed; `attributed_header` carries the unconfirmed attribution
# without dignifying it; `evidence` says which of the two a reader is
# looking at; and `label` is what any human-facing surface prints, so an
# unconfirmed source cannot be displayed in the same words as a
# confirmed one.
VERIFIED_HEADER = "verified_header"
MICROSOFT_DOCUMENTATION = "microsoft_documentation"
RELATED_API_HEADER = "related_api_header"
UNCONFIRMED_NATIVE = "unconfirmed_native"

CONFIRMED_EVIDENCE = frozenset({VERIFIED_HEADER, MICROSOFT_DOCUMENTATION})

# Header names, for the confirmed cases and for the code that needs to
# spell one.
WINNT_H = "Win32 SDK winnt.h"
WINUSER_H = "Win32 SDK winuser.h"
NTIFS_H = "WDK ntifs.h"


@dataclass(frozen=True)
class Provenance:
    """Where ONE constant comes from, and how well that is known.

    `header` is the confirmed defining header or None. `constant_source()`
    returns exactly this, so a caller asking "which header defines this"
    gets an answer only when there is one -- never a plausible guess
    wearing the same clothes as a verified fact."""
    evidence:           str
    header:             "str | None" = None
    attributed_header:  "str | None" = None
    label:              str = ""
    note:               str = ""

    @property
    def confirmed(self) -> bool:
        return self.evidence in CONFIRMED_EVIDENCE


# Verified by grepping an installed Windows SDK; test_access_rights.py
# re-greps the real headers on any machine that has one.
PROV_WINNT_H = Provenance(
    evidence=VERIFIED_HEADER, header=WINNT_H, label=WINNT_H)
PROV_WINUSER_H = Provenance(
    evidence=VERIFIED_HEADER, header=WINUSER_H, label=WINUSER_H)

# Named outright in a Microsoft reference page that states `ntifs.h` under
# Requirements: `ZwOpenDirectoryObject` for the whole `DIRECTORY_*` set,
# `ZwCreateEvent` for `EVENT_QUERY_STATE`. These two sets share a HEADER,
# not an object family -- an Event is not an Object Manager object -- so
# this must never be relabelled "the Object Manager headers".
PROV_NTIFS_H = Provenance(
    evidence=MICROSOFT_DOCUMENTATION, header=NTIFS_H, label=NTIFS_H,
    note="named in a Microsoft reference page stating this header")

# `SYMBOLIC_LINK_*`. Microsoft documents the ROUTINE
# ZwOpenSymbolicLinkObject under wdm.h, but that page names no
# SYMBOLIC_LINK_* constant -- it tells callers to pass GENERIC_READ -- and
# neither does the user-mode NtOpenSymbolicLinkObject note. The routine's
# header is a lead, not a definition site, so `header` stays None.
PROV_WDM_H_ROUTINE_ONLY = Provenance(
    evidence=RELATED_API_HEADER, attributed_header="WDK wdm.h",
    label="unconfirmed (related routine documented in WDK wdm.h)",
    note="ZwOpenSymbolicLinkObject is documented under wdm.h, but no "
         "Microsoft page names a SYMBOLIC_LINK_* constant")

# `THREAD_ALERT`. Attributed to ntddk.h by the table this registry grew
# from; absent from winnt.h, and no Microsoft page naming it was located.
PROV_NTDDK_H_ATTRIBUTED = Provenance(
    evidence=UNCONFIRMED_NATIVE, attributed_header="WDK ntddk.h",
    label="unconfirmed (commonly attributed to WDK ntddk.h)",
    note="inherited from the original table, not confirmed against a "
         "Microsoft source")

# `SEMAPHORE_QUERY_STATE`, `IO_COMPLETION_QUERY_STATE`. Asserted PER
# CONSTANT after checking that constant, never as a blanket claim about a
# group -- `EVENT_QUERY_STATE` was wrongly put in this class exactly that
# way, purely because the three bits look alike. Neither has a Microsoft
# reference page; the IoCompletion spelling was located only in
# third-party native header sets. The BITS are not in doubt: winnt.h's
# SEMAPHORE_ALL_ACCESS and IO_COMPLETION_ALL_ACCESS are both
# STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3, so 0x0001 is a defined
# type-specific right of each. Only the names are unsourced.
PROV_NATIVE_UNCONFIRMED = Provenance(
    evidence=UNCONFIRMED_NATIVE,
    label="unconfirmed (native NT headers; no Microsoft source located)",
    note="the bit is corroborated by winnt.h's *_ALL_ACCESS for the same "
         "type; the name is not")

# Standard rights, identical across every object type.
_STANDARD_RIGHTS = (
    (0x00010000, "Delete", "DELETE", PROV_WINNT_H),
    (0x00020000, "ReadControl", "READ_CONTROL", PROV_WINNT_H),
    (0x00040000, "WriteDac", "WRITE_DAC", PROV_WINNT_H),
    (0x00080000, "WriteOwner", "WRITE_OWNER", PROV_WINNT_H),
    (0x00100000, "Synchronize", "SYNCHRONIZE", PROV_WINNT_H),
    (0x01000000, "AccessSystemSecurity", "ACCESS_SYSTEM_SECURITY", PROV_WINNT_H),
    (0x02000000, "MaximumAllowed", "MAXIMUM_ALLOWED", PROV_WINNT_H),
)

# Generic rights are reported EXACTLY as captured and are never expanded
# through an assumed per-type GENERIC_MAPPING: the mapping lives in the
# kernel object type, the dump does not record it, and the mask a handle
# was actually opened with has normally already been mapped by the object
# manager. A generic bit still set in `GrantedAccess` is itself the fact
# worth showing.
_GENERIC_RIGHTS = (
    (0x10000000, "GenericAll", "GENERIC_ALL", PROV_WINNT_H),
    (0x20000000, "GenericExecute", "GENERIC_EXECUTE", PROV_WINNT_H),
    (0x40000000, "GenericWrite", "GENERIC_WRITE", PROV_WINNT_H),
    (0x80000000, "GenericRead", "GENERIC_READ", PROV_WINNT_H),
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
# Composite aliases are the display forms of documented combination
# CONSTANTS -- the `*_ALL_ACCESS` of each type plus the
# `FILE_GENERIC_*`/`KEY_READ`/`TOKEN_READ` family. They are what
# collapses a wall of repeated names into the thing an analyst already
# recognises: `0x00020019` on a Key is `KEY_READ`, printed `KeyRead`, and
# spelling out its four components on several hundred rows says less, not
# more.
#
# Every alias name is TYPE-QUALIFIED wherever the bare word would be
# ambiguous (`FileGenericRead`, not `Read`): `GENERIC_READ` is a real,
# different bit (0x80000000), and a reader who saw `GenericRead` next to
# a File row could not tell which of the two the dump captured.
#
# `AllAccess` is the one unqualified name, and only because it has no
# such twin -- NOT because it means the same thing everywhere. It names
# the recorded object type's own `*_ALL_ACCESS` constant, and what that
# constant contains is entirely type-dependent: on a Process it includes
# terminating it, writing its memory and creating threads in it; on an
# Event it is querying and setting the event; on a Token it is querying,
# duplicating and adjusting privileges and groups. Reading two
# `AllAccess` rows of different types as the same capability is exactly
# the cross-type mistake this whole decoder exists to prevent, which is
# why the console prints the row's type beside every alias it expands
# (see the `Aliases used` block in dumpex/commands/handles.py).
#
# An alias is tested against the WHOLE captured mask, not against what
# earlier names left over, because two SDK composites legitimately
# overlap: `FILE_GENERIC_READ` and `FILE_GENERIC_WRITE` share
# `READ_CONTROL|SYNCHRONIZE`, and `0x0012019f` is exactly their union.
# Consuming greedily would let the first one swallow the shared bits and
# silently disqualify the second. A later alias that adds NO bit the
# earlier ones did not already claim is dropped instead (see
# decode_access_mask), so `AllAccess` never appears beside the composites
# it contains. Aliases are therefore listed widest-first.

# Each entry is (bit, display name, constant, source). The constant and
# its source travel WITH the bit rather than sitting in a heading over
# the table, so a table can hold constants from two headers without
# either being mislabelled -- which is exactly what went wrong while the
# source was tracked per object type.
_FILE_RIGHTS = (
    # FILE_LIST_DIRECTORY/FILE_ADD_FILE/FILE_ADD_SUBDIRECTORY/
    # FILE_TRAVERSE are the same four bits under their directory names.
    # The descriptor does not record whether the object is a directory,
    # so the file-semantics name is used for all four rather than a
    # guess; both readings are the same captured bit.
    (0x0001, "ReadData", "FILE_READ_DATA", PROV_WINNT_H),
    (0x0002, "WriteData", "FILE_WRITE_DATA", PROV_WINNT_H),
    (0x0004, "AppendData", "FILE_APPEND_DATA", PROV_WINNT_H),
    (0x0008, "ReadEa", "FILE_READ_EA", PROV_WINNT_H),
    (0x0010, "WriteEa", "FILE_WRITE_EA", PROV_WINNT_H),
    (0x0020, "Execute", "FILE_EXECUTE", PROV_WINNT_H),
    (0x0040, "DeleteChild", "FILE_DELETE_CHILD", PROV_WINNT_H),
    (0x0080, "ReadAttributes", "FILE_READ_ATTRIBUTES", PROV_WINNT_H),
    (0x0100, "WriteAttributes", "FILE_WRITE_ATTRIBUTES", PROV_WINNT_H),
)

_PROCESS_RIGHTS = (
    (0x0001, "Terminate", "PROCESS_TERMINATE", PROV_WINNT_H),
    (0x0002, "CreateThread", "PROCESS_CREATE_THREAD", PROV_WINNT_H),
    (0x0004, "SetSessionId", "PROCESS_SET_SESSIONID", PROV_WINNT_H),
    (0x0008, "VmOperation", "PROCESS_VM_OPERATION", PROV_WINNT_H),
    (0x0010, "VmRead", "PROCESS_VM_READ", PROV_WINNT_H),
    (0x0020, "VmWrite", "PROCESS_VM_WRITE", PROV_WINNT_H),
    (0x0040, "DupHandle", "PROCESS_DUP_HANDLE", PROV_WINNT_H),
    (0x0080, "CreateProcess", "PROCESS_CREATE_PROCESS", PROV_WINNT_H),
    (0x0100, "SetQuota", "PROCESS_SET_QUOTA", PROV_WINNT_H),
    (0x0200, "SetInformation", "PROCESS_SET_INFORMATION", PROV_WINNT_H),
    (0x0400, "QueryInformation", "PROCESS_QUERY_INFORMATION", PROV_WINNT_H),
    (0x0800, "SuspendResume", "PROCESS_SUSPEND_RESUME", PROV_WINNT_H),
    (0x1000, "QueryLimitedInformation",
             "PROCESS_QUERY_LIMITED_INFORMATION", PROV_WINNT_H),
    (0x2000, "SetLimitedInformation",
             "PROCESS_SET_LIMITED_INFORMATION", PROV_WINNT_H),
)

# A mixed-source table, and one reason the source is per constant:
# `THREAD_ALERT` is a WDK-side right (`ntddk.h`) that winnt.h does not
# define, while the other twelve are winnt.h's.
_THREAD_RIGHTS = (
    (0x0001, "Terminate", "THREAD_TERMINATE", PROV_WINNT_H),
    (0x0002, "SuspendResume", "THREAD_SUSPEND_RESUME", PROV_WINNT_H),
    (0x0004, "Alert", "THREAD_ALERT", PROV_NTDDK_H_ATTRIBUTED),
    (0x0008, "GetContext", "THREAD_GET_CONTEXT", PROV_WINNT_H),
    (0x0010, "SetContext", "THREAD_SET_CONTEXT", PROV_WINNT_H),
    (0x0020, "SetInformation", "THREAD_SET_INFORMATION", PROV_WINNT_H),
    (0x0040, "QueryInformation", "THREAD_QUERY_INFORMATION", PROV_WINNT_H),
    (0x0080, "SetThreadToken", "THREAD_SET_THREAD_TOKEN", PROV_WINNT_H),
    (0x0100, "Impersonate", "THREAD_IMPERSONATE", PROV_WINNT_H),
    (0x0200, "DirectImpersonation", "THREAD_DIRECT_IMPERSONATION", PROV_WINNT_H),
    (0x0400, "SetLimitedInformation",
             "THREAD_SET_LIMITED_INFORMATION", PROV_WINNT_H),
    (0x0800, "QueryLimitedInformation",
             "THREAD_QUERY_LIMITED_INFORMATION", PROV_WINNT_H),
    (0x1000, "Resume", "THREAD_RESUME", PROV_WINNT_H),
)

_TOKEN_RIGHTS = (
    (0x0001, "AssignPrimary", "TOKEN_ASSIGN_PRIMARY", PROV_WINNT_H),
    (0x0002, "Duplicate", "TOKEN_DUPLICATE", PROV_WINNT_H),
    (0x0004, "Impersonate", "TOKEN_IMPERSONATE", PROV_WINNT_H),
    (0x0008, "Query", "TOKEN_QUERY", PROV_WINNT_H),
    (0x0010, "QuerySource", "TOKEN_QUERY_SOURCE", PROV_WINNT_H),
    (0x0020, "AdjustPrivileges", "TOKEN_ADJUST_PRIVILEGES", PROV_WINNT_H),
    (0x0040, "AdjustGroups", "TOKEN_ADJUST_GROUPS", PROV_WINNT_H),
    (0x0080, "AdjustDefault", "TOKEN_ADJUST_DEFAULT", PROV_WINNT_H),
    (0x0100, "AdjustSessionId", "TOKEN_ADJUST_SESSIONID", PROV_WINNT_H),
)

_SECTION_RIGHTS = (
    (0x0001, "Query", "SECTION_QUERY", PROV_WINNT_H),
    (0x0002, "MapWrite", "SECTION_MAP_WRITE", PROV_WINNT_H),
    (0x0004, "MapRead", "SECTION_MAP_READ", PROV_WINNT_H),
    (0x0008, "MapExecute", "SECTION_MAP_EXECUTE", PROV_WINNT_H),
    (0x0010, "ExtendSize", "SECTION_EXTEND_SIZE", PROV_WINNT_H),
    (0x0020, "MapExecuteExplicit", "SECTION_MAP_EXECUTE_EXPLICIT", PROV_WINNT_H),
)

_JOB_RIGHTS = (
    (0x0001, "AssignProcess", "JOB_OBJECT_ASSIGN_PROCESS", PROV_WINNT_H),
    (0x0002, "SetAttributes", "JOB_OBJECT_SET_ATTRIBUTES", PROV_WINNT_H),
    (0x0004, "Query", "JOB_OBJECT_QUERY", PROV_WINNT_H),
    (0x0008, "Terminate", "JOB_OBJECT_TERMINATE", PROV_WINNT_H),
    (0x0010, "SetSecurityAttributes",
             "JOB_OBJECT_SET_SECURITY_ATTRIBUTES", PROV_WINNT_H),
    (0x0020, "Impersonate", "JOB_OBJECT_IMPERSONATE", PROV_WINNT_H),
)

# No Win32 SDK header defines any of these, and Microsoft names all four
# -- plus DIRECTORY_ALL_ACCESS -- in the ZwOpenDirectoryObject reference,
# whose Requirements state ntifs.h:
# learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwopendirectoryobject
# They were previously filed under a combined `wdm.h`/`ntifs.h` label,
# which offered a header Microsoft does not point at for them.
_DIRECTORY_RIGHTS = (
    (0x0001, "Query", "DIRECTORY_QUERY", PROV_NTIFS_H),
    (0x0002, "Traverse", "DIRECTORY_TRAVERSE", PROV_NTIFS_H),
    (0x0004, "CreateObject", "DIRECTORY_CREATE_OBJECT", PROV_NTIFS_H),
    (0x0008, "CreateSubdirectory", "DIRECTORY_CREATE_SUBDIRECTORY", PROV_NTIFS_H),
)

# Weaker evidence than the DIRECTORY_* set above, and the difference is
# recorded rather than smoothed over. Microsoft documents the ROUTINE
# ZwOpenSymbolicLinkObject under wdm.h, but that page names no
# SYMBOLIC_LINK_* constant -- it tells callers to pass GENERIC_READ -- and
# neither does the user-mode NtOpenSymbolicLinkObject note. So wdm.h is
# where the routine lives, and these spellings stay unconfirmed.
_SYMBOLIC_LINK_RIGHTS = (
    (0x0001, "Query", "SYMBOLIC_LINK_QUERY", PROV_WDM_H_ROUTINE_ONLY),
    (0x0002, "Set", "SYMBOLIC_LINK_SET", PROV_WDM_H_ROUTINE_ONLY),
)

# Mixed source, and BOTH halves have a named header. winnt.h defines
# EVENT_MODIFY_STATE and EVENT_ALL_ACCESS. EVENT_QUERY_STATE is absent
# from winnt.h but is documented by Microsoft in the ZwCreateEvent
# reference, whose Requirements state ntifs.h:
# learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwcreateevent
# It was briefly filed as "named by no Microsoft header", which was
# false -- and false in the more damaging direction, since it understated
# what an investigator can go and check.
_EVENT_RIGHTS = (
    (0x0001, "QueryState", "EVENT_QUERY_STATE", PROV_NTIFS_H),
    (0x0002, "ModifyState", "EVENT_MODIFY_STATE", PROV_WINNT_H),
)

_MUTANT_RIGHTS = (
    (0x0001, "QueryState", "MUTANT_QUERY_STATE", PROV_WINNT_H),
)

# Mixed source, but NOT by analogy with _EVENT_RIGHTS -- re-checked on
# its own, because assuming the three `*_QUERY_STATE` bits shared a
# provenance is what got EVENT_QUERY_STATE wrong. SEMAPHORE_MODIFY_STATE
# and SEMAPHORE_ALL_ACCESS are winnt.h's. SEMAPHORE_QUERY_STATE is in no
# Windows SDK header on this machine and no Microsoft page naming it was
# located: there is no published ZwCreateSemaphore/ZwOpenSemaphore
# reference to correspond to ZwCreateEvent's. winnt.h's
# SEMAPHORE_ALL_ACCESS is STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3, so
# the SDK does establish 0x0001 as a real semaphore right without ever
# naming it. Revisit if a Microsoft reference turns up.
_SEMAPHORE_RIGHTS = (
    (0x0001, "QueryState", "SEMAPHORE_QUERY_STATE", PROV_NATIVE_UNCONFIRMED),
    (0x0002, "ModifyState", "SEMAPHORE_MODIFY_STATE", PROV_WINNT_H),
)

# NOT mixed: winnt.h names both timer rights, unlike the three tables
# that otherwise look identical to this one. Per-constant sourcing is
# what makes that difference visible instead of guessable.
_TIMER_RIGHTS = (
    (0x0001, "QueryState", "TIMER_QUERY_STATE", PROV_WINNT_H),
    (0x0002, "ModifyState", "TIMER_MODIFY_STATE", PROV_WINNT_H),
)

# Not in #102's own list, but the type a real handle table carries as
# often as File, and the one whose mask (`0x00020019`, KEY_READ) an
# analyst is most likely to meet on a persistence question. The registry
# is designed to be extended exactly this way -- a table and a key, with
# no change to the collector, the record, or the schema.
_KEY_RIGHTS = (
    (0x0001, "QueryValue", "KEY_QUERY_VALUE", PROV_WINNT_H),
    (0x0002, "SetValue", "KEY_SET_VALUE", PROV_WINNT_H),
    (0x0004, "CreateSubKey", "KEY_CREATE_SUB_KEY", PROV_WINNT_H),
    (0x0008, "EnumerateSubKeys", "KEY_ENUMERATE_SUB_KEYS", PROV_WINNT_H),
    (0x0010, "Notify", "KEY_NOTIFY", PROV_WINNT_H),
    (0x0020, "CreateLink", "KEY_CREATE_LINK", PROV_WINNT_H),
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
    (0x0001, "ReadObjects", "DESKTOP_READOBJECTS", PROV_WINUSER_H),
    (0x0002, "CreateWindow", "DESKTOP_CREATEWINDOW", PROV_WINUSER_H),
    (0x0004, "CreateMenu", "DESKTOP_CREATEMENU", PROV_WINUSER_H),
    (0x0008, "HookControl", "DESKTOP_HOOKCONTROL", PROV_WINUSER_H),
    (0x0010, "JournalRecord", "DESKTOP_JOURNALRECORD", PROV_WINUSER_H),
    (0x0020, "JournalPlayback", "DESKTOP_JOURNALPLAYBACK", PROV_WINUSER_H),
    (0x0040, "Enumerate", "DESKTOP_ENUMERATE", PROV_WINUSER_H),
    (0x0080, "WriteObjects", "DESKTOP_WRITEOBJECTS", PROV_WINUSER_H),
    (0x0100, "SwitchDesktop", "DESKTOP_SWITCHDESKTOP", PROV_WINUSER_H),
)

_WINDOW_STATION_RIGHTS = (
    (0x0001, "EnumDesktops", "WINSTA_ENUMDESKTOPS", PROV_WINUSER_H),
    (0x0002, "ReadAttributes", "WINSTA_READATTRIBUTES", PROV_WINUSER_H),
    (0x0004, "AccessClipboard", "WINSTA_ACCESSCLIPBOARD", PROV_WINUSER_H),
    (0x0008, "CreateDesktop", "WINSTA_CREATEDESKTOP", PROV_WINUSER_H),
    (0x0010, "WriteAttributes", "WINSTA_WRITEATTRIBUTES", PROV_WINUSER_H),
    (0x0020, "AccessGlobalAtoms", "WINSTA_ACCESSGLOBALATOMS", PROV_WINUSER_H),
    (0x0040, "ExitWindows", "WINSTA_EXITWINDOWS", PROV_WINUSER_H),
    (0x0100, "Enumerate", "WINSTA_ENUMERATE", PROV_WINUSER_H),
    (0x0200, "ReadScreen", "WINSTA_READSCREEN", PROV_WINUSER_H),
)

# THE table this module got wrong while it tracked sources per type.
# `IO_COMPLETION_MODIFY_STATE` (0x0002) and `IO_COMPLETION_ALL_ACCESS`
# (0x001F0003, in the registry below) are Win32 SDK constants, defined in
# winnt.h under "I/O Completion Specific Access Rights"; only the 0x0001
# spelling is not. Filing the whole type under the WDK sent anyone
# re-checking `IO_COMPLETION_MODIFY_STATE` to a header that does not
# contain it. test_access_rights.py pins both of them, by constant.
#
# IO_COMPLETION_QUERY_STATE was likewise re-checked on its own rather
# than by analogy with EVENT_QUERY_STATE: unlike that one it has no
# Microsoft reference page (there is no published ZwCreateIoCompletion),
# and the spelling was located only in third-party native header sets --
# System Informer's phnt `ntioapi.h`, ntinternals.net and ReactOS. As
# with the semaphore, winnt.h's IO_COMPLETION_ALL_ACCESS (...|0x3)
# establishes 0x0001 as a real IoCompletion right without naming it.
_IO_COMPLETION_RIGHTS = (
    (0x0001, "QueryState", "IO_COMPLETION_QUERY_STATE", PROV_NATIVE_UNCONFIRMED),
    (0x0002, "ModifyState", "IO_COMPLETION_MODIFY_STATE", PROV_WINNT_H),
)

# (specific rights, ((alias value, display name, constant, source), ...))
# per casefolded NT type name. An alias fires only when the mask carries
# ALL of its bits.
#
# Every alias value MUST map to an explicit combination constant Windows
# actually defines, and carries that constant and its Provenance in the
# entry itself -- the same per-constant rule the tables above follow.
# "Explicit constant" is not the same claim as "confirmed header":
# `SYMBOLIC_LINK_ALL_ACCESS` genuinely is
# `STANDARD_RIGHTS_REQUIRED | SYMBOLIC_LINK_QUERY`, a real combination,
# even though no Microsoft page was found confirming which header defines
# it -- which is exactly what its PROV_WDM_H_ROUTINE_ONLY entry says.
# Today the permitted set is each type's `*_ALL_ACCESS` plus
# `FILE_GENERIC_READ`/`_WRITE`/`_EXECUTE`, `KEY_READ`/`KEY_WRITE` and
# `TOKEN_READ`/`TOKEN_WRITE`. dumpex must never invent a grouping of its
# own, however convenient: a combination Windows does not define cannot
# be checked against Windows, and an analyst who looked up the constant
# behind the display name would find nothing.
# tests/unit/test_access_rights.py pins every one of them against a
# hand-written table that is NOT derived from this file.
#
# Note that every `*_ALL_ACCESS` below except the two Object Manager ones
# is a `winnt.h` constant -- `IO_COMPLETION_ALL_ACCESS` included, though
# its type's 0x0001 bit is not. That split is precisely why an alias
# records its own source instead of inheriting its type's.
#
# `symboliclink` is the one type whose `*_ALL_ACCESS` does NOT cover its
# whole specific table: `SYMBOLIC_LINK_ALL_ACCESS` is
# `STANDARD_RIGHTS_REQUIRED | SYMBOLIC_LINK_QUERY` (0x000F0001) and
# predates `SYMBOLIC_LINK_SET` (0x0002), which was never folded into it.
# The alias value is left at what the constant actually is, so
# `0x000F0003` reads `AllAccess · Set` -- which is the honest decomposition
# (`Set` is a right the constant does not contain, and this table's job
# is to report what the SDK defines, not to tidy up its history).
# Widening the alias would instead report `AllAccess` for a mask that is
# not `SYMBOLIC_LINK_ALL_ACCESS`, and would hide the `Set` bit entirely.
_TYPE_REGISTRY = {
    "file":         (_FILE_RIGHTS,
                     ((0x001F01FF, "AllAccess", "FILE_ALL_ACCESS", PROV_WINNT_H),
                      # Each FILE_GENERIC_* carries READ_CONTROL|
                      # SYNCHRONIZE of its own.
                      (0x00120089, "FileGenericRead",
                       "FILE_GENERIC_READ", PROV_WINNT_H),
                      (0x00120116, "FileGenericWrite",
                       "FILE_GENERIC_WRITE", PROV_WINNT_H),
                      (0x001200A0, "FileGenericExecute",
                       "FILE_GENERIC_EXECUTE", PROV_WINNT_H))),
    "process":      (_PROCESS_RIGHTS,
                     ((0x001FFFFF, "AllAccess",
                       "PROCESS_ALL_ACCESS", PROV_WINNT_H),)),
    "thread":       (_THREAD_RIGHTS,
                     ((0x001FFFFF, "AllAccess",
                       "THREAD_ALL_ACCESS", PROV_WINNT_H),)),
    "token":        (_TOKEN_RIGHTS,
                     ((0x000F01FF, "AllAccess", "TOKEN_ALL_ACCESS", PROV_WINNT_H),
                      # TOKEN_EXECUTE is STANDARD_RIGHTS_EXECUTE alone --
                      # one bit, already named `ReadControl` -- so it is
                      # not a third alias here.
                      (0x000200E0, "TokenWrite", "TOKEN_WRITE", PROV_WINNT_H),
                      (0x00020008, "TokenRead", "TOKEN_READ", PROV_WINNT_H))),
    "section":      (_SECTION_RIGHTS,
                     ((0x000F001F, "AllAccess",
                       "SECTION_ALL_ACCESS", PROV_WINNT_H),)),
    "job":          (_JOB_RIGHTS,
                     ((0x001F003F, "AllAccess",
                       "JOB_OBJECT_ALL_ACCESS", PROV_WINNT_H),)),
    "directory":    (_DIRECTORY_RIGHTS,
                     # Named on the same ntifs.h page as the four bits.
                     ((0x000F000F, "AllAccess",
                       "DIRECTORY_ALL_ACCESS", PROV_NTIFS_H),)),
    "symboliclink": (_SYMBOLIC_LINK_RIGHTS,
                     ((0x000F0001, "AllAccess",
                       "SYMBOLIC_LINK_ALL_ACCESS", PROV_WDM_H_ROUTINE_ONLY),)),
    "event":        (_EVENT_RIGHTS,
                     ((0x001F0003, "AllAccess", "EVENT_ALL_ACCESS", PROV_WINNT_H),)),
    "mutant":       (_MUTANT_RIGHTS,
                     ((0x001F0001, "AllAccess",
                       "MUTANT_ALL_ACCESS", PROV_WINNT_H),)),
    "semaphore":    (_SEMAPHORE_RIGHTS,
                     ((0x001F0003, "AllAccess",
                       "SEMAPHORE_ALL_ACCESS", PROV_WINNT_H),)),
    "timer":        (_TIMER_RIGHTS,
                     ((0x001F0003, "AllAccess", "TIMER_ALL_ACCESS", PROV_WINNT_H),)),
    # KEY_EXECUTE is defined as KEY_READ's own value, so it is not a
    # second alias: it would name the same bits twice.
    "key":          (_KEY_RIGHTS,
                     ((0x000F003F, "AllAccess", "KEY_ALL_ACCESS", PROV_WINNT_H),
                      (0x00020019, "KeyRead", "KEY_READ", PROV_WINNT_H),
                      (0x00020006, "KeyWrite", "KEY_WRITE", PROV_WINNT_H))),
    "iocompletion": (_IO_COMPLETION_RIGHTS,
                     ((0x001F0003, "AllAccess",
                       "IO_COMPLETION_ALL_ACCESS", PROV_WINNT_H),)),
    # No alias -- see the two tables' own comment above.
    "desktop":      (_DESKTOP_RIGHTS, ()),
    "windowstation": (_WINDOW_STATION_RIGHTS, ()),
}

# Every constant this module maps, keyed by constant, valued by the
# header it is defined in -- the per-constant source record in the form
# anything outside this module should ask it in. Derived from the tables
# so the two can never drift apart; a test pins its size against the
# tables, because a duplicated constant name would otherwise be swallowed
# silently by the dict.
# PROCESS_ALL_ACCESS and THREAD_ALL_ACCESS are the two constants whose
# VALUE depends on the Windows version the mask was captured on, and
# winnt.h says so itself:
#
#     #if (NTDDI_VERSION >= NTDDI_VISTA)
#     #define PROCESS_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0xFFFF)
#     #else
#     #define PROCESS_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0xFFF)
#     #endif
#
# Vista widened both (Microsoft states this in "Process Security and
# Access Rights" and "Thread Security and Access Rights"), so a full
# handle on XP/Server 2003 carries 0x001F0FFF, not 0x001FFFFF -- and on
# a thread, 0x001F03FF.
#
# The registry above holds the Vista+ values, which is what an unknown or
# modern dump gets. `os_major` selects these instead when the caller
# knows the dump came from something older. Adding them to the main table
# unconditionally would be a correctness REGRESSION, not a convenience:
# 0x001F0FFF on a Vista+ dump is a partial mask, and printing `AllAccess`
# for it would claim a capability the handle does not have.
_LEGACY_ALIASES = {
    "process": ((0x001F0FFF, "AllAccess", "PROCESS_ALL_ACCESS", PROV_WINNT_H),),
    "thread":  ((0x001F03FF, "AllAccess", "THREAD_ALL_ACCESS", PROV_WINNT_H),),
}

# The first Windows major version with the widened constants (Vista and
# Server 2008 are 6.0).
_ALL_ACCESS_WIDENED_IN_MAJOR = 6

# Every constant this module maps, keyed by constant. Derived from the
# tables so the two can never drift apart; a test pins its size against
# the tables, because a duplicated constant name would otherwise be
# swallowed silently by the dict. `_LEGACY_ALIASES` is deliberately NOT
# folded in: it re-uses the same two constant names with different
# values, and both values have the same provenance.
CONSTANT_PROVENANCE = {
    constant: provenance
    for entries in (_STANDARD_RIGHTS, _GENERIC_RIGHTS,
                    *(specific for specific, _aliases in _TYPE_REGISTRY.values()),
                    *(aliases for _specific, aliases in _TYPE_REGISTRY.values()))
    for _bit, _display, constant, provenance in entries
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

# Right names are separated by a padded middle dot. The line is prose
# sitting under a table row, not a column an `awk` reads, so the
# separator's whole job is to be legible without competing with the names
# for attention -- and a run of `|` between thirteen names does compete
# (a review of the shipped output called the result "debug output"). The
# console additionally dims it, so on a real terminal the names are what
# the eye lands on.
#
# It is also the ONLY place this character appears in the text, which is
# what lets wrap_rights() find its break points, and no right name
# contains a space (asserted in the tests), so a piece can never be split
# by accident.
RIGHTS_SEPARATOR = " · "

# What a wrapped line ends with, so it reads as "continues below".
RIGHTS_CONTINUED_SUFFIX = " ·"


@dataclass(frozen=True)
class DecodedAccess:
    """One decoded mask. `mask` is the authoritative captured value and
    is carried through unchanged; everything else is derived from it.

    The names are kept in TWO tuples rather than one, because the
    console prints them as two groups once a mask is too wide for a
    single line: `type_names` are the rights this object type defines
    (its composite aliases and its own bits), `standard_names` are the
    ones every type shares (standard, special and generic). Splitting
    here rather than in the renderer keeps the grouping a property of
    the decode -- the renderer cannot put `Synchronize` under `Type` by
    accident -- and `names` still yields the single canonical sequence.

    Neither tuple contains the residual: `undecoded_bits` keeps that as a
    number, so a caller can tell "nothing was left over" from
    "0x0000c000 was" at the type level rather than by parsing a string.

    `type_supported` is False both when the record carried no usable type
    name and when the recorded type is not in this registry: in both
    cases the type-SPECIFIC bits are undecodable, which is one fact, and
    the type name itself is already displayed in the row's Type column."""
    mask:            int
    type_supported:  bool
    type_names:      tuple
    standard_names:  tuple
    undecoded_bits:  int

    @property
    def names(self) -> tuple:
        """The canonical single sequence: this type's own rights first,
        then the ones every type shares."""
        return self.type_names + self.standard_names


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


def constant_provenance(constant_name) -> "Provenance | None":
    """Everything known about where one CONSTANT comes from -- the
    confirmed header if there is one, the unconfirmed attribution if
    there is only that, and which of the two this is. None for a name
    this module does not map."""
    if not isinstance(constant_name, str):
        return None
    return CONSTANT_PROVENANCE.get(constant_name)


def constant_source(constant_name) -> "str | None":
    """The header one CONSTANT is CONFIRMED to be defined in, or None.

    None means one of two different things, and the caller that needs to
    tell them apart should ask constant_provenance(): either this module
    does not map the name at all, or it maps it but nothing establishes a
    defining header. `SYMBOLIC_LINK_QUERY` and `THREAD_ALERT` are in that
    second class -- they carry an ATTRIBUTED header, not a confirmed one,
    and returning it here would hand a caller a specific WDK header that
    nobody has verified the constant is defined in.

    The per-constant question, asked by constant:
    `IO_COMPLETION_MODIFY_STATE` answers `winnt.h` even though
    `IO_COMPLETION_QUERY_STATE` answers None -- the distinction a
    per-type answer cannot express, and got wrong."""
    provenance = constant_provenance(constant_name)
    return provenance.header if provenance is not None else None


def object_type_sources(type_name) -> tuple:
    """Every distinct Provenance behind ONE recorded object type's
    constants, in the order the type's own tables introduce them.

    DERIVED, never declared: a type has whatever provenance its constants
    have. That is the whole point -- a type is not a header, and several
    draw on more than one source:

        [p.label for p in object_type_sources("File")]
            -> ["Win32 SDK winnt.h"]
        [p.label for p in object_type_sources("Directory")]
            -> ["WDK ntifs.h"]
        [p.label for p in object_type_sources("Thread")]
            -> ["Win32 SDK winnt.h",
                "unconfirmed (commonly attributed to WDK ntddk.h)"]
        [p.label for p in object_type_sources("IoCompletion")]
            -> ["unconfirmed (native NT headers; no Microsoft source located)",
                "Win32 SDK winnt.h"]

    A type with more than one entry is MIXED-SOURCE and must be described
    as such: `IoCompletion` takes `IO_COMPLETION_MODIFY_STATE` and
    `IO_COMPLETION_ALL_ACCESS` from `winnt.h` and only its 0x0001 bit
    from outside the Win32 SDK, so calling it a WDK type is false for two
    of its three constants. Returns () for a type this registry does not
    carry -- it decodes no type-specific constant, so it draws on no
    source for one."""
    registry = _TYPE_REGISTRY.get(_normalize_type(type_name))
    if registry is None:
        return ()
    specific, aliases = registry
    sources = []
    for _bit, _display, _constant, provenance in tuple(specific) + tuple(aliases):
        if provenance not in sources:
            sources.append(provenance)
    return tuple(sources)


_CANONICAL_TYPE_SPELLING = {name.casefold(): name for name in SUPPORTED_OBJECT_TYPES}


def canonical_type_name(type_name) -> "str | None":
    """The registry's own spelling for one recorded type name (`"Process"`
    for `"process"`, `" PROCESS "`, `"PrOcEsS"`, ...), or None when the
    normalized name is not in this registry.

    Exists so a renderer that groups or labels output BY TYPE can use a
    short, bounded, attacker-INdependent string instead of the raw
    dump-recorded text. `_normalize_type()` is deliberately permissive --
    case- and whitespace-insensitive, because it is a lookup key -- which
    means two rows spelled `"Process"` and `"  Process  " * 40` (or any
    other pile of whitespace a crafted or corrupted descriptor carries)
    both resolve to the same registry entry and the same decode. A
    renderer that echoes the raw text back for EACH of them prints the
    same fact twice under two different-looking (and, at any real
    padding, grotesquely wide) labels; using this instead prints it once,
    under the one spelling the registry itself uses.

    Returns None for a type this registry does not carry, or for
    anything `_normalize_type()` cannot key at all -- there is no
    registry spelling to substitute for either."""
    key = _normalize_type(type_name)
    if key is None:
        return None
    return _CANONICAL_TYPE_SPELLING.get(key)


def alias_provenance(alias_name: str, type_name) -> "Provenance | None":
    """Where the constant behind one COMPOSITE comes from, or None for a
    name this type does not define.

    The console needs this to avoid describing every alias with the same
    confidence: `KeyRead` maps to a `winnt.h` constant anyone can look
    up, while `AllAccess` on a `SymbolicLink` maps to a name no Microsoft
    source was found for. Printing both under one word -- "documented" --
    told an investigator the second was checkable when it is not."""
    registry = _TYPE_REGISTRY.get(_normalize_type(type_name))
    if registry is None:
        return None
    _specific, aliases = registry
    for _value, name, _constant, provenance in aliases:
        if name == alias_name:
            return provenance
    return None


def unconfirmed_names(decoded: DecodedAccess, type_name, *, os_major=None) -> frozenset:
    """The subset of `decoded.names` whose backing constant has no
    CONFIRMED provenance -- printed as an ordinary right name, but
    resting on an attribution (or on nothing) rather than a verified
    header or a Microsoft page.

    Exists because the confirmed/unconfirmed split that `Provenance`
    carries is invisible on a `Rights` line otherwise: `decode_access_mask`
    returns bare strings, so `QueryState` on a `Semaphore` (unconfirmed --
    no Microsoft source names `SEMAPHORE_QUERY_STATE`) is typographically
    identical to `QueryState` on a `Timer` (`winnt.h`'s own
    `TIMER_QUERY_STATE`) unless a caller asks this question and marks the
    answer itself.

    Always a subset of `decoded.type_names`: `_STANDARD_RIGHTS` and
    `_GENERIC_RIGHTS` are `winnt.h` in full, so nothing in
    `decoded.standard_names` is ever unconfirmed, and this never needs to
    look there. An alias name (`AllAccess`) is checked by ITS OWN
    provenance, not by the bits' -- `IoCompletion`'s `AllAccess` is
    `IO_COMPLETION_ALL_ACCESS`, a confirmed `winnt.h` constant, even
    though the bare `QueryState` bit that same type can decode on its own
    is not; collapsing the two would either wrongly clear the alias or
    wrongly mark it.

    `os_major` must match whatever was passed to decode_access_mask() for
    this same `decoded`, so the two ask the same registry (only
    `Process`/`Thread` `AllAccess` differs by version, and both eras are
    `winnt.h`-confirmed, so this rarely matters in practice -- but a
    mismatched call is asking the wrong table's question).

    Returns frozenset() for a type this registry does not carry: there is
    no per-constant provenance to doubt for a type that was never
    decoded against one."""
    registry = _registry_for(type_name, os_major)
    if registry is None:
        return frozenset()
    specific, aliases = registry
    provenance_by_name = {name: provenance for _bit, name, _c, provenance in specific}
    provenance_by_name.update(
        {name: provenance for _v, name, _c, provenance in aliases})
    return frozenset(
        name for name in decoded.type_names
        if (provenance := provenance_by_name.get(name)) is not None
        and not provenance.confirmed)


def _registry_for(type_name, os_major=None):
    """The (specific rights, aliases) pair for one recorded type name, or
    None -- with the aliases chosen for the Windows version the mask was
    captured on.

    Only `Process` and `Thread` differ, and only in their `*_ALL_ACCESS`:
    Vista widened both from 0x001F0FFF/0x001F03FF to 0x001FFFFF, and
    winnt.h still carries the pre-Vista values under `#else`. A caller
    that knows the dump's major version gets the right composite for it;
    a caller that does not gets the modern one.

    `os_major` is trusted only when it is a plain non-negative int. A
    string, a bool or a None -- which is what an absent or unparsable
    SYSTEM_INFO stream yields -- selects the modern values, because
    guessing "old" from missing evidence would print `AllAccess` for a
    partial mask on every dump whose version could not be read."""
    registry = _TYPE_REGISTRY.get(_normalize_type(type_name))
    if registry is None:
        return None
    specific, aliases = registry
    if (not isinstance(os_major, bool) and isinstance(os_major, int)
            and 0 <= os_major < _ALL_ACCESS_WIDENED_IN_MAJOR):
        legacy = _LEGACY_ALIASES.get(_normalize_type(type_name))
        if legacy is not None:
            return specific, legacy
    return specific, aliases


def decode_access_mask(mask, type_name, *, os_major=None) -> "DecodedAccess | None":
    """Decode one `granted_access` value against one recorded type name.
    Returns None for a null/unusable mask -- absent evidence stays absent
    and is never decoded into "no rights" (§1.4).

    Canonical order, frozen so the same mask always reads the same way:

      1. composite aliases that fired, in registry order (widest first);
      2. the type's own specific rights, by ascending bit value;
         -- those two make up `type_names` --
      3. standard rights, by ascending bit value (Delete, ReadControl,
         WriteDac, WriteOwner, Synchronize, AccessSystemSecurity,
         MaximumAllowed);
      4. generic rights, by ascending bit value.
         -- those two make up `standard_names` --

    Ordering by BIT VALUE rather than alphabetically keeps a right in the
    same position across every type and every mask, so two rows can be
    compared by eye.

    Aliases are matched against the WHOLE mask and only then have their
    bits claimed, because two SDK composites legitimately overlap:
    `FILE_GENERIC_READ` and `FILE_GENERIC_WRITE` share
    `READ_CONTROL|SYNCHRONIZE`, and `0x0012019f` is exactly their union,
    so claiming greedily would let the first swallow the shared bits and
    disqualify the second. What that cannot become is double-reporting: a
    name is emitted only if it accounts for at least one bit no earlier
    name did, which is also what keeps `AllAccess` from appearing beside
    the composites and single rights it contains. Single bits are then
    matched against what is left, so an alias and its own components can
    never both appear; whatever survives is `undecoded_bits`.

    `os_major` is the Windows major version the dump was captured on,
    when the caller knows it. It changes exactly one thing: which value
    `AllAccess` stands for on a `Process` or a `Thread`. Vista widened
    `PROCESS_ALL_ACCESS` from 0x001F0FFF to 0x001FFFFF and
    `THREAD_ALL_ACCESS` from 0x001F03FF to 0x001FFFFF, so a full handle
    in an XP or Server 2003 dump carries the narrower value -- which,
    read against the modern constant, decodes correctly but reads as a
    twelve-name list instead of the one word that says the same thing.
    Omitted or unreadable, the modern values are used: they are what
    almost every dump needs, and treating "version unknown" as "old"
    would print `AllAccess` for masks that are genuinely partial.

    Still a pure function of its arguments: no host state, no live query,
    and a bounded walk over at most 14 + 4 + 7 + 4 table entries."""
    if isinstance(mask, bool) or not isinstance(mask, int) or mask < 0:
        return None

    mask &= _UINT32_MASK
    registry = _registry_for(type_name, os_major)
    claimed = 0
    type_names = []

    if registry is not None:
        _specific, aliases = registry
        for value, name, _constant, _source in aliases:
            # `value & ~claimed`: an alias wholly contained in one already
            # emitted adds no fact and is dropped.
            if mask & value == value and value & ~claimed:
                type_names.append(name)
                claimed |= value

    bit_type_names, standard_names, claimed = _decompose_bits(mask, registry, claimed)

    return DecodedAccess(mask=mask, type_supported=registry is not None,
                          type_names=tuple(type_names + bit_type_names),
                          standard_names=tuple(standard_names),
                          undecoded_bits=mask & ~claimed)


def _decompose_bits(mask: int, registry, claimed: int = 0) -> tuple:
    """-> (type-specific names, shared names, bits claimed) for the SINGLE
    bits of `mask` that `claimed` does not already account for.

    Shared by decode_access_mask() (after its aliases have claimed what
    they cover) and by expand_alias() (which has no aliases to apply --
    expanding one INTO another would defeat the point). Keeping one walk
    means a composite's expansion can never name a right differently
    from the row that spells the same bits out."""
    type_names = []
    standard_names = []
    if registry is not None:
        specific, _aliases = registry
        for bit, name, _constant, _source in specific:
            if mask & bit and not claimed & bit:
                type_names.append(name)
                claimed |= bit
    for bit, name, _constant, _source in _STANDARD_RIGHTS + _GENERIC_RIGHTS:
        if mask & bit and not claimed & bit:
            standard_names.append(name)
            claimed |= bit
    return type_names, standard_names, claimed


def alias_names_in(decoded: DecodedAccess, type_name) -> tuple:
    """The composite names this decode used, in the order it printed
    them. A caller listing what an alias stands for needs to know which
    ones are on screen, and only the registry can say which of a decode's
    names are composites."""
    # No os_major: the alias NAME is `AllAccess` in either era, so the
    # set this checks against is version-independent.
    registry = _registry_for(type_name)
    if registry is None:
        return ()
    _specific, aliases = registry
    alias_names = {name for _value, name, _constant, _source in aliases}
    return tuple(name for name in decoded.type_names if name in alias_names)


def expand_alias(alias_name: str, type_name, *, os_major=None) -> str:
    """What one composite stands for, as display text -- the rights it
    contains, spelled out, for THAT object type.

    A composite is short and recognisable, which is what makes it worth
    printing on every row; the cost is that the capabilities inside it
    stop being visible. `TokenWrite` contains `AdjustPrivileges`, and an
    investigator scanning for that word must be able to find it. The
    console prints this expansion once, under the table, for every alias
    it actually used (§5.6.4).

    Aliases are NOT applied while expanding: expanding one composite into
    another would answer the question with the thing that was asked
    about. Returns "" for a name this type does not define.

    `os_major` selects the same composite the decode used, and must be
    the value passed to decode_access_mask() for the same row: expanding
    a pre-Vista `AllAccess` against the modern constant would list four
    rights the handle never had."""
    registry = _registry_for(type_name, os_major)
    if registry is None:
        return ""
    _specific, aliases = registry
    value = next((v for v, name, _c, _s in aliases if name == alias_name), None)
    if value is None:
        return ""
    type_names, standard_names, claimed = _decompose_bits(value, registry)
    parts = type_names + standard_names
    # A constant may cover bits this registry has no name for --
    # PROCESS_ALL_ACCESS is defined over the whole specific range,
    # including two bits Windows documents no right for. Saying so is the
    # point of the expansion.
    if value & ~claimed:
        parts.append(_remainder_token(value & ~claimed, True))
    return RIGHTS_SEPARATOR.join(parts)


def unconfirmed_names_in_alias(alias_name: str, type_name, *, os_major=None) -> frozenset:
    """The subset of one alias's own EXPANSION whose backing constant has
    no confirmed provenance -- a DIFFERENT question from
    `alias_provenance(alias_name, type_name).confirmed`, which is about
    the alias's own combination constant.

    The two can and do disagree. `IO_COMPLETION_ALL_ACCESS` is itself a
    confirmed `winnt.h` constant -- `alias_provenance("AllAccess",
    "IoCompletion").confirmed` is True, and the `Rights` line correctly
    prints a bare `AllAccess` with no mark at all. But expanding it lists
    `QueryState`, which comes from the single bit
    `IO_COMPLETION_QUERY_STATE`, and NO Microsoft source was found for
    that name. A console that marked only the alias's own confirmation
    status would print that expansion with every component looking
    equally solid, which is exactly the false impression an investigator
    reading `TokenWrite`'s or `AllAccess`'s expansion for the specific
    right it stands for must not get. `SymbolicLink`'s `AllAccess` is the
    case where BOTH questions say unconfirmed at once -- the alias itself
    (`SYMBOLIC_LINK_ALL_ACCESS`) has no confirmed header, AND its `Query`
    component (`SYMBOLIC_LINK_QUERY`) does not either -- and both facts
    are reported, independently, because they answer different questions.

    Only the TYPE-specific half of an expansion can appear here: the
    standard/generic rights an `*_ALL_ACCESS` also covers
    (`_decompose_bits`'s `standard_names`) are `_STANDARD_RIGHTS`/
    `_GENERIC_RIGHTS`, `winnt.h` in full, never unconfirmed. Aliases are
    not reapplied while decomposing (`expand_alias`'s own rule), so this
    checks the SPECIFIC-bits table only, never the aliases table --
    exactly what the expansion itself is built from.

    Returns frozenset() for a name this type does not define, the same
    as expand_alias() returns "" for it."""
    registry = _registry_for(type_name, os_major)
    if registry is None:
        return frozenset()
    specific, aliases = registry
    value = next((v for v, name, _c, _s in aliases if name == alias_name), None)
    if value is None:
        return frozenset()
    type_names, _standard_names, _claimed = _decompose_bits(value, registry)
    provenance_by_name = {name: provenance for _bit, name, _c, provenance in specific}
    return frozenset(
        name for name in type_names
        if (provenance := provenance_by_name.get(name)) is not None
        and not provenance.confirmed)


def _remainder_token(bits: int, type_supported: bool) -> str:
    """One remainder, named for its own kind and carrying its own value.

    `bits` is always a PART of the mask that no name accounts for -- never
    the mask itself -- so `TypeSpecificUnavailable(0x000f037f)` can never
    be printed for a mask whose four standard rights were just named."""
    template = _UNKNOWN_BITS_FORMAT if type_supported else _UNAVAILABLE_TYPE_FORMAT
    return template.format(bits)


def access_right_groups(decoded: DecodedAccess) -> "tuple[str, str]":
    """-> (type text, standard text), either of which may be "".

    The two groups the console prints under `Type` and `Standard` once a
    mask is too wide for one line. Splitting them is not cosmetic: a
    thirteen-name run mixes rights that mean something only for THIS
    object type with rights that mean the same thing for every type, and
    an analyst reading a wrapped run cannot tell where one ends and the
    other begins. `EnumDesktops` is a window-station capability;
    `WriteOwner` is not.

    The remainder is split the same way and by the same rule the decoder
    uses, so each half lands with the rights it belongs to: bits 0-15 are
    type-specific (and are `TypeSpecificUnavailable` when the type is one
    this registry does not carry), everything above them is not."""
    type_remainder = decoded.undecoded_bits & 0x0000FFFF
    standard_remainder = decoded.undecoded_bits & ~0x0000FFFF

    type_parts = list(decoded.type_names)
    if type_remainder:
        type_parts.append(_remainder_token(type_remainder, decoded.type_supported))

    standard_parts = list(decoded.standard_names)
    if standard_remainder:
        # Above bit 15 nothing is type-specific, so an undecoded bit here
        # is an undocumented/reserved one whatever the recorded type was.
        standard_parts.append(_remainder_token(standard_remainder, True))

    return RIGHTS_SEPARATOR.join(type_parts), RIGHTS_SEPARATOR.join(standard_parts)


def format_access_rights(decoded: DecodedAccess) -> str:
    """The DERIVED text for one decoded mask on ONE line -- every right,
    then whatever was left undecoded:

        KeyRead
        FileGenericRead · FileGenericWrite
        AllAccess
        (no rights)
        Delete · ReadControl · TypeSpecificUnavailable(0x0000037f)

    The captured mask is deliberately NOT repeated here. It is printed
    once, in the row's own `Access` column directly above this text,
    which is the evidence anchor a reader scans, compares and copies; a
    second copy one line below it says nothing new and costs the width
    the right names need. A remainder token carries its own value because
    that value is a PART of the mask, not the mask.

    Three rules, none of them silent:

      * a mask with no bits at all is NO_RIGHTS_TEXT, never "" -- a
        captured mask granting nothing is a positive fact, and it is
        different from the `(unknown)` an absent mask prints in the
        column (§1.4);
      * bits with no documented right for a type this registry carries
        are reported as `UnknownBits(0x%08x)`, so an undocumented or
        future bit stays auditable at its own raw value instead of being
        guessed at or dropped;
      * every undecoded type-specific bit of a mask whose type this
        registry does NOT carry is reported as
        `TypeSpecificUnavailable(0x%08x)` instead, which is a different
        fact: nothing is wrong with the bit, dumpex simply has no type to
        read it against."""
    groups = [group for group in access_right_groups(decoded) if group]
    return RIGHTS_SEPARATOR.join(groups) if groups else NO_RIGHTS_TEXT


def is_undecoded_token(piece: str) -> bool:
    """Is this one separated piece a remainder rather than a right name?
    The console colours the two differently -- a remainder is the one
    thing on the line that says something was NOT read -- and this keeps
    the two token shapes named in exactly one place."""
    return piece.startswith(("UnknownBits(", "TypeSpecificUnavailable("))


def wrap_rights(text: str, width: int) -> list:
    """Wrap one group's text to `width` columns, always breaking AFTER a
    separator so no right name is split across two lines and a
    continuation line can never be mistaken for a new entry.

    console_layout.wrap_text() cannot do this: it wraps on WHITESPACE,
    and every name here is one token by construction, so its only break
    points would be the separators -- which it would then drop, leaving a
    continued line that reads as a finished list. Here the separators are
    the break points and they stay on the line they continue.

    A single piece wider than `width` is placed alone on its own line and
    allowed to overflow rather than being cut -- the same rule
    wrap_text() applies to an over-long word, and the reason #102 forbids
    silent truncation."""
    # Two columns are reserved so the separator that marks a continued
    # line cannot itself push that line past `width`.
    budget = max(1, width - len(RIGHTS_CONTINUED_SUFFIX))
    lines = []
    current = ""
    for piece in text.split(RIGHTS_SEPARATOR):
        if not current:
            current = piece
        elif len(current) + len(RIGHTS_SEPARATOR) + len(piece) > budget:
            lines.append(current + RIGHTS_CONTINUED_SUFFIX)
            current = piece
        else:
            current += RIGHTS_SEPARATOR + piece
    lines.append(current)
    return lines

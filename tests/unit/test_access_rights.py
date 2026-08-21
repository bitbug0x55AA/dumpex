"""Unit tests for dumpex.ui.access_rights -- issue #102's type-specific
decoding of a captured `GrantedAccess` mask.

The decoder is a pure function of (mask, recorded type name), so almost
everything here is checked as an INVARIANT over the frozen registry
rather than as a golden string per type: a table with thirteen object
types and ~70 rights is exactly the shape where hand-written expectations
cover the three entries someone thought of and leave the rest unguarded.
The invariants are the properties #102 turns on --

  * every bit a name claims is actually set in the captured mask;
  * every bit of the mask is either claimed by exactly one name or left
    visible as the residual (nothing invented, nothing dropped, nothing
    reported twice);
  * the same bit decodes DIFFERENTLY per recorded type;
  * an unsupported or missing type still decodes the type-independent
    bits and never guesses the type-specific ones;

-- and the few literal expectations that remain are the masks an analyst
actually meets (`0x001fffff` on a Process, `0x00020019` on a Key), which
are worth pinning by value.
"""
import os
import pathlib
import re

import pytest

from dumpex.ui.access_rights import (
    CONSTANT_PROVENANCE, DecodedAccess, MICROSOFT_DOCUMENTATION,
    NO_RIGHTS_TEXT, NTIFS_H, PROV_NATIVE_UNCONFIRMED,
    PROV_NTDDK_H_ATTRIBUTED, PROV_NTIFS_H, PROV_WDM_H_ROUTINE_ONLY,
    PROV_WINNT_H, PROV_WINUSER_H, RELATED_API_HEADER, RIGHTS_SEPARATOR,
    SUPPORTED_OBJECT_TYPES, UNCONFIRMED_NATIVE, VERIFIED_HEADER, WINNT_H,
    WINUSER_H,
    access_right_groups, alias_names_in, alias_provenance,
    canonical_type_name, constant_provenance, constant_source,
    decode_access_mask, expand_alias, format_access_rights,
    is_undecoded_token, object_type_sources, unconfirmed_names,
    unconfirmed_names_in_alias, wrap_rights,
    _GENERIC_RIGHTS, _STANDARD_RIGHTS, _TYPE_REGISTRY,
)


_STANDARD_BY_NAME = {name: bit
                     for bit, name, _c, _s in _STANDARD_RIGHTS + _GENERIC_RIGHTS}

# One mask per interesting shape, reused across the invariant tests.
_MASKS = [
    0x00000000, 0x00000001, 0x00000002, 0x00000003, 0x0000000F, 0x000001FF,
    0x0000143A, 0x00020019, 0x00100001, 0x0012019F, 0x001F0003, 0x001FFFFF,
    0x000F01FF, 0x02000000, 0x10000000, 0x80000000, 0xC0000000, 0xFFFFFFFF,
]


def _bits_for(type_name: str) -> dict:
    """name -> bit for one recorded type: its own specific rights, its
    aliases, and the type-independent rights every type shares."""
    specific, aliases = _TYPE_REGISTRY[type_name.casefold()]
    return ({name: bit for bit, name, _c, _s in specific}
            | {name: value for value, name, _c, _s in aliases}
            | _STANDARD_BY_NAME)


# ── Registry integrity ──────────────────────────────────────────────────

def test_supported_types_and_the_registry_describe_the_same_set():
    """SUPPORTED_OBJECT_TYPES is what the docs and the console tests read;
    a type added to one and not the other would document a decode that
    does not happen (or hide one that does)."""
    assert {name.casefold() for name in SUPPORTED_OBJECT_TYPES} == set(_TYPE_REGISTRY)


def test_every_type_covers_the_object_types_the_issue_named():
    for type_name in ("File", "Process", "Thread", "Token", "Section", "Job",
                       "Directory", "SymbolicLink", "Event", "Mutant",
                       "Semaphore", "Timer"):
        assert type_name in SUPPORTED_OBJECT_TYPES


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
def test_specific_rights_are_single_bits_inside_the_type_specific_range(type_name):
    """Bits 16 and up are standard/generic rights and mean the same thing
    for every object type -- a type table that claimed one would decode
    the same bit twice, under two different names."""
    specific, _aliases = _TYPE_REGISTRY[type_name]
    seen = set()
    for bit, name, _constant, _source in specific:
        assert 0 < bit <= 0x0000FFFF, f"{type_name}: {name} is outside the specific range"
        assert bit & (bit - 1) == 0, f"{type_name}: {name} is not a single bit"
        assert bit not in seen, f"{type_name}: bit {bit:#x} is listed twice"
        seen.add(bit)


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
def test_specific_rights_are_listed_in_ascending_bit_order(type_name):
    """Canonical output order is the table's order, so the table itself
    is what freezes it."""
    specific, _aliases = _TYPE_REGISTRY[type_name]
    assert [bit for bit, *_ in specific] == sorted(bit for bit, *_ in specific)


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
def test_no_name_collides_with_a_type_independent_right(type_name):
    """A per-type name equal to `Synchronize` or `GenericRead` would make
    one displayed name mean two different bits depending on the row's
    type -- the exact confusion this decoder exists to remove."""
    specific, aliases = _TYPE_REGISTRY[type_name]
    for _bit, name, _c, _s in specific:
        assert name not in _STANDARD_BY_NAME, f"{type_name}: {name} shadows a standard right"
    for _value, name, _c, _s in aliases:
        assert name not in _STANDARD_BY_NAME, f"{type_name}: {name} shadows a standard right"


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
def test_names_never_contain_the_separator_they_are_joined_with(type_name):
    specific, aliases = _TYPE_REGISTRY[type_name]
    for _value, name, _c, _s in specific + aliases:
        assert name and "|" not in name and " " not in name


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
def test_every_alias_is_a_composite_of_more_than_one_bit(type_name):
    """A single-bit "alias" would just be a second name for a right the
    specific table already carries."""
    _specific, aliases = _TYPE_REGISTRY[type_name]
    for value, name, _c, _s in aliases:
        assert bin(value).count("1") > 1, f"{type_name}: {name} aliases one bit"


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
def test_aliases_are_listed_widest_first(type_name):
    """A narrower alias listed BEFORE one that contains it would claim
    the wider one's bits first, and the wider name -- the one that says
    more -- would then be dropped as adding nothing."""
    _specific, aliases = _TYPE_REGISTRY[type_name]
    for index, (value, name, _c, _s) in enumerate(aliases):
        for later_value, later_name, _lc, _ls in aliases[index + 1:]:
            assert value & later_value != value or value == later_value, (
                f"{type_name}: {name} is contained in {later_name}, which is listed after it")


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
def test_no_two_aliases_name_the_same_bits(type_name):
    """`KEY_EXECUTE` is defined as `KEY_READ`'s own value: listing both
    would print one capability under two names."""
    _specific, aliases = _TYPE_REGISTRY[type_name]
    values = [value for value, _name, _c, _s in aliases]
    assert len(set(values)) == len(values)


# ── Constant provenance ─────────────────────────────────────────────────
# The module records, per constant, both a header and the EVIDENCE for
# it, so these tests pin both -- against the header or the Microsoft page
# that actually establishes it, never against a second copy of the
# module's own opinion.
#
# Three defects are on record here, each one a smaller version of the
# last, which is why this section keeps getting stricter.
#
#   1. `IoCompletion` was filed whole under the WDK, because the source
#      was a property of the object TYPE. That mis-attributed
#      `IO_COMPLETION_MODIFY_STATE` and `IO_COMPLETION_ALL_ACCESS`, which
#      `winnt.h` defines under "I/O Completion Specific Access Rights".
#   2. Fixing (1) moved three `*_QUERY_STATE` bits into "no Microsoft
#      header names this" as a GROUP -- they share a value, a display
#      name and a relationship to their type's `*_ALL_ACCESS`, so they
#      looked alike. Microsoft documents one of the three:
#      `EVENT_QUERY_STATE` is named in the `ZwCreateEvent` reference,
#      whose Requirements state `ntifs.h`.
#   3. Fixing (2) still returned a definite WDK header for constants
#      nothing had confirmed. `SYMBOLIC_LINK_QUERY` answered "WDK wdm.h"
#      in the same breath as `DIRECTORY_QUERY` answering "WDK ntifs.h",
#      although only the second is named on a Microsoft page -- `wdm.h`
#      is merely where the related ROUTINE is documented. A caller could
#      not tell a verified header from a plausible one.
#
# So the model separates `header` (confirmed) from `attributed_header`
# (not), `constant_source()` returns only the former, and every row below
# records which kind it is.
_MS_EVENT_DOC = ("learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/"
                  "nf-ntifs-zwcreateevent")
_MS_DIRECTORY_DOC = ("learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/"
                      "nf-ntifs-zwopendirectoryobject")

# constant -> (confirmed header or None, evidence class). Every constant
# this module maps whose provenance is not plain winnt.h. Hand-written;
# nothing here is derived from dumpex/ui/access_rights.py.
_PROVENANCE_KNOWN_ANSWERS = {
    # Win32 SDK winuser.h. winnt.h carries no desktop or window-station
    # right; winuser.h carries all nineteen.
    "DESKTOP_READOBJECTS": (WINUSER_H, VERIFIED_HEADER),
    "DESKTOP_CREATEWINDOW": (WINUSER_H, VERIFIED_HEADER),
    "DESKTOP_CREATEMENU": (WINUSER_H, VERIFIED_HEADER),
    "DESKTOP_HOOKCONTROL": (WINUSER_H, VERIFIED_HEADER),
    "DESKTOP_JOURNALRECORD": (WINUSER_H, VERIFIED_HEADER),
    "DESKTOP_JOURNALPLAYBACK": (WINUSER_H, VERIFIED_HEADER),
    "DESKTOP_ENUMERATE": (WINUSER_H, VERIFIED_HEADER),
    "DESKTOP_WRITEOBJECTS": (WINUSER_H, VERIFIED_HEADER),
    "DESKTOP_SWITCHDESKTOP": (WINUSER_H, VERIFIED_HEADER),
    "WINSTA_ENUMDESKTOPS": (WINUSER_H, VERIFIED_HEADER),
    "WINSTA_READATTRIBUTES": (WINUSER_H, VERIFIED_HEADER),
    "WINSTA_ACCESSCLIPBOARD": (WINUSER_H, VERIFIED_HEADER),
    "WINSTA_CREATEDESKTOP": (WINUSER_H, VERIFIED_HEADER),
    "WINSTA_WRITEATTRIBUTES": (WINUSER_H, VERIFIED_HEADER),
    "WINSTA_ACCESSGLOBALATOMS": (WINUSER_H, VERIFIED_HEADER),
    "WINSTA_EXITWINDOWS": (WINUSER_H, VERIFIED_HEADER),
    "WINSTA_ENUMERATE": (WINUSER_H, VERIFIED_HEADER),
    "WINSTA_READSCREEN": (WINUSER_H, VERIFIED_HEADER),

    # WDK ntifs.h, per _MS_DIRECTORY_DOC, which names all four bits AND
    # DIRECTORY_ALL_ACCESS in its DesiredAccess table and states ntifs.h
    # under Requirements.
    "DIRECTORY_QUERY": (NTIFS_H, MICROSOFT_DOCUMENTATION),
    "DIRECTORY_TRAVERSE": (NTIFS_H, MICROSOFT_DOCUMENTATION),
    "DIRECTORY_CREATE_OBJECT": (NTIFS_H, MICROSOFT_DOCUMENTATION),
    "DIRECTORY_CREATE_SUBDIRECTORY": (NTIFS_H, MICROSOFT_DOCUMENTATION),
    "DIRECTORY_ALL_ACCESS": (NTIFS_H, MICROSOFT_DOCUMENTATION),

    # WDK ntifs.h, per _MS_EVENT_DOC, which names EVENT_QUERY_STATE in
    # its DesiredAccess table and states ntifs.h under Requirements. This
    # is the row defect (2) got wrong. It shares a header with the
    # DIRECTORY_* set and nothing else: an Event is not an Object Manager
    # object.
    "EVENT_QUERY_STATE": (NTIFS_H, MICROSOFT_DOCUMENTATION),

    # No confirmed header. Microsoft documents the ROUTINE
    # ZwOpenSymbolicLinkObject under wdm.h, but neither that page nor the
    # user-mode NtOpenSymbolicLinkObject note names a SYMBOLIC_LINK_*
    # constant -- both tell callers to pass GENERIC_READ. This is the row
    # defect (3) got wrong: wdm.h is a lead, not a definition site.
    "SYMBOLIC_LINK_QUERY": (None, RELATED_API_HEADER),
    "SYMBOLIC_LINK_SET": (None, RELATED_API_HEADER),
    "SYMBOLIC_LINK_ALL_ACCESS": (None, RELATED_API_HEADER),

    # No confirmed header. Attributed to ntddk.h by the table this
    # registry grew from; absent from winnt.h, and no Microsoft page
    # naming it was located.
    "THREAD_ALERT": (None, UNCONFIRMED_NATIVE),

    # No confirmed header, and checked individually -- NOT as a pair with
    # EVENT_QUERY_STATE. Neither has a Microsoft reference page: there is
    # no published ZwCreateSemaphore or ZwCreateIoCompletion to
    # correspond to ZwCreateEvent, and the IoCompletion spelling was
    # located only in third-party native header sets (System Informer's
    # phnt `ntioapi.h`, ntinternals.net, ReactOS). The BITS are not in
    # doubt: winnt.h's SEMAPHORE_ALL_ACCESS and IO_COMPLETION_ALL_ACCESS
    # are both STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3, so 0x0001 is a
    # defined type-specific right of each. Only the names are unsourced.
    "SEMAPHORE_QUERY_STATE": (None, UNCONFIRMED_NATIVE),
    "IO_COMPLETION_QUERY_STATE": (None, UNCONFIRMED_NATIVE),
}


def test_constant_source_never_returns_an_unconfirmed_header():
    """Defect (3). `constant_source()` answers "which header defines
    this", so it may not answer for a constant nothing has been confirmed
    about. `SYMBOLIC_LINK_QUERY` has an ATTRIBUTED header and no
    confirmed one; handing `wdm.h` back would make a lead indistinguishable
    from the verified answer `KEY_READ` gets."""
    for constant in ("SYMBOLIC_LINK_QUERY", "SYMBOLIC_LINK_SET",
                      "SYMBOLIC_LINK_ALL_ACCESS", "THREAD_ALERT",
                      "SEMAPHORE_QUERY_STATE", "IO_COMPLETION_QUERY_STATE"):
        assert constant_source(constant) is None, (
            f"{constant} has no confirmed defining header, so "
            f"constant_source() must not name one")

        # The attribution is not thrown away -- it is just not mistaken
        # for a fact.
        provenance = constant_provenance(constant)
        assert provenance is not None
        assert provenance.confirmed is False
        assert provenance.header is None
        assert provenance.label.startswith("unconfirmed")

    assert constant_provenance("SYMBOLIC_LINK_QUERY").attributed_header == "WDK wdm.h"
    assert constant_provenance("THREAD_ALERT").attributed_header == "WDK ntddk.h"


def test_a_confirmed_constant_answers_with_its_header():
    """The other half: where there IS an answer, it is returned plainly
    and is not hedged into uselessness."""
    assert constant_source("KEY_READ") == WINNT_H
    assert constant_source("DESKTOP_READOBJECTS") == WINUSER_H
    assert constant_source("DIRECTORY_QUERY") == NTIFS_H
    assert constant_provenance("KEY_READ").confirmed is True
    assert constant_provenance("DIRECTORY_QUERY").evidence == MICROSOFT_DOCUMENTATION


def test_event_query_state_is_the_ntifs_h_constant_microsoft_documents():
    """Defect (2). Microsoft's `ZwCreateEvent` reference names
    `EVENT_QUERY_STATE` in its DesiredAccess table and states `ntifs.h`
    under Requirements, so an investigator CAN look this one up. Calling
    it "named by no Microsoft header" was wrong, and wrong in the
    direction that quietly devalues a right name the reader could have
    verified.

    It is `ntifs.h` because that page says so -- not because
    `DIRECTORY_*` is also `ntifs.h`. The two share a header, not an
    object family."""
    assert constant_source("EVENT_QUERY_STATE") == NTIFS_H
    assert constant_provenance("EVENT_QUERY_STATE").confirmed is True
    assert _PROVENANCE_KNOWN_ANSWERS["EVENT_QUERY_STATE"] == (
        NTIFS_H, MICROSOFT_DOCUMENTATION)


def test_the_io_completion_constants_are_never_filed_as_wdk_only_again():
    """Defect (1), stated as bluntly as it can be: `winnt.h` defines
    `IO_COMPLETION_MODIFY_STATE` and `IO_COMPLETION_ALL_ACCESS`. Neither
    is a WDK constant, neither is a native-header constant, and no
    per-type shorthand may round them into one."""
    assert constant_source("IO_COMPLETION_MODIFY_STATE") == WINNT_H
    assert constant_source("IO_COMPLETION_ALL_ACCESS") == WINNT_H

    for constant in ("IO_COMPLETION_MODIFY_STATE", "IO_COMPLETION_ALL_ACCESS"):
        assert constant_provenance(constant).evidence == VERIFIED_HEADER
        assert constant not in _PROVENANCE_KNOWN_ANSWERS, (
            f"{constant} is a plain winnt.h constant and must not appear "
            f"among the exceptions")

    # Only the third one is outside the Win32 SDK, and it is the reason
    # the type cannot be labelled winnt.h wholesale either.
    assert constant_source("IO_COMPLETION_QUERY_STATE") is None


def test_the_three_query_state_bits_are_not_treated_as_one_group():
    """Defect (2) again, from the other side. The three constants share a
    value, a display name and the same relationship to their type's
    `*_ALL_ACCESS`, and exactly one of them is documented by Microsoft.
    Any future change that gives all three the same provenance has
    stopped checking them individually."""
    provenances = {constant: constant_provenance(constant) for constant in (
        "EVENT_QUERY_STATE", "SEMAPHORE_QUERY_STATE",
        "IO_COMPLETION_QUERY_STATE")}

    assert provenances["EVENT_QUERY_STATE"].header == NTIFS_H
    assert len(set(provenances.values())) > 1, (
        "all three *_QUERY_STATE constants share one provenance again -- "
        "they were checked as a group, and one of them is documented")

    # And the fourth lookalike is not in the class at all: winnt.h names
    # both timer rights.
    assert constant_source("TIMER_QUERY_STATE") == WINNT_H


def test_io_completion_is_a_mixed_source_type():
    """Two of its three constants are winnt.h's and one is not, so any
    single-header description of the type is false about something."""
    assert set(object_type_sources("IoCompletion")) == {
        PROV_WINNT_H, PROV_NATIVE_UNCONFIRMED}


@pytest.mark.parametrize("type_name,expected", [
    ("IoCompletion", {PROV_WINNT_H, PROV_NATIVE_UNCONFIRMED}),
    ("Event", {PROV_WINNT_H, PROV_NTIFS_H}),
    ("Semaphore", {PROV_WINNT_H, PROV_NATIVE_UNCONFIRMED}),
    ("Thread", {PROV_WINNT_H, PROV_NTDDK_H_ATTRIBUTED}),
    # Single-source types, including the timer that only LOOKS like Event
    # and Semaphore.
    ("File", {PROV_WINNT_H}),
    ("Timer", {PROV_WINNT_H}),
    ("Mutant", {PROV_WINNT_H}),
    ("Directory", {PROV_NTIFS_H}),
    ("SymbolicLink", {PROV_WDM_H_ROUTINE_ONLY}),
    ("Desktop", {PROV_WINUSER_H}),
    ("WindowStation", {PROV_WINUSER_H}),
])
def test_a_types_sources_are_derived_from_the_constants_it_uses(type_name, expected):
    """A type is not a header. Its provenance is whatever its own
    constants have -- which is how a mixed type stays visibly mixed
    instead of being rounded to whichever header most of it came from."""
    assert set(object_type_sources(type_name)) == expected


def test_a_type_this_registry_does_not_carry_claims_no_source():
    """It decodes no type-specific constant, so it draws on no header for
    one -- which is different from claiming winnt.h."""
    assert object_type_sources("TpWorkerFactory") == ()
    assert object_type_sources(None) == ()
    assert constant_provenance("TPWORKERFACTORY_ALL_ACCESS") is None
    assert constant_source(None) is None


def test_every_constant_that_is_not_plain_winnt_h_is_pinned_by_hand():
    """Both directions at once: a winnt.h constant re-labelled shows up
    here, and a non-SDK constant labelled winnt.h vanishes from here."""
    actual = {constant: (provenance.header, provenance.evidence)
              for constant, provenance in CONSTANT_PROVENANCE.items()
              if provenance != PROV_WINNT_H}
    assert actual == _PROVENANCE_KNOWN_ANSWERS


def test_an_unconfirmed_provenance_never_carries_a_confirmed_header():
    """The invariant the model exists to enforce. A row cannot be both
    "nothing establishes this" and "the header is X"."""
    for constant, provenance in CONSTANT_PROVENANCE.items():
        if provenance.confirmed:
            assert provenance.header, f"{constant}: confirmed with no header"
            assert provenance.attributed_header is None
        else:
            assert provenance.header is None, (
                f"{constant}: unconfirmed yet names a defining header")
            assert provenance.label.startswith("unconfirmed"), (
                f"{constant}: unconfirmed but does not say so in its label")


def test_no_constant_is_lost_to_a_duplicated_name():
    """CONSTANT_PROVENANCE is built from the tables by comprehension, so
    two entries claiming one constant name would silently collapse into
    one and take a provenance with them."""
    entries = [_STANDARD_RIGHTS, _GENERIC_RIGHTS]
    for specific, aliases in _TYPE_REGISTRY.values():
        entries += [specific, aliases]
    total = sum(len(table) for table in entries)

    assert len(CONSTANT_PROVENANCE) == total


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
def test_every_entry_names_a_constant_and_a_known_provenance(type_name):
    """A table entry with no constant, or with a provenance invented on
    the spot rather than taken from the module's own set, is how the
    per-constant record would rot back into a per-type one."""
    specific, aliases = _TYPE_REGISTRY[type_name]
    for _bit, display, constant, provenance in specific + aliases:
        assert constant and constant.isupper(), (
            f"{type_name}: {display} names no constant")
        assert provenance in (PROV_WINNT_H, PROV_WINUSER_H, PROV_NTIFS_H,
                              PROV_WDM_H_ROUTINE_ONLY,
                              PROV_NTDDK_H_ATTRIBUTED,
                              PROV_NATIVE_UNCONFIRMED), (
            f"{type_name}: {constant} has an unrecognised provenance")
        assert CONSTANT_PROVENANCE[constant] == provenance


def test_a_display_name_is_never_mistaken_for_the_constant_it_maps_to():
    """`AllAccess` and `KeyRead` are dumpex spellings; the constant beside
    them is the header's. Keeping both in the entry is what makes a
    mapping re-checkable, and they must never be the same string."""
    for specific, aliases in _TYPE_REGISTRY.values():
        for _bit, display, constant, _provenance in specific + aliases:
            assert display != constant


def test_alias_provenance_lets_a_renderer_tell_the_two_kinds_apart():
    """The console needs this to stop describing every composite with one
    word. `KeyRead` maps to a constant anyone can look up; `AllAccess` on
    a SymbolicLink does not."""
    assert alias_provenance("KeyRead", "Key").confirmed is True
    assert alias_provenance("AllAccess", "Directory").confirmed is True
    assert alias_provenance("AllAccess", "SymbolicLink").confirmed is False
    assert alias_provenance("AllAccess", "IoCompletion").confirmed is True

    assert alias_provenance("KeyRead", "File") is None
    assert alias_provenance("AllAccess", "TpWorkerFactory") is None


# ── Constant provenance, checked against a real SDK ─────────────────────
# Everything above compares dumpex's claim to a hand-written claim. These
# two compare it to the headers themselves, on any machine that has a
# Windows SDK installed, and skip where there is none (CI on Linux, a
# checkout without the SDK). That is the only check here that can catch
# both copies being wrong together -- which is exactly what happened when
# `IO_COMPLETION_MODIFY_STATE` was filed under the WDK.
#
# Only the two Win32 SDK headers can be checked this way: the WDK is a
# separate install and is usually absent, and a Microsoft reference PAGE
# is not greppable offline. Those rows are what the hand-written answers
# above are for.

def _installed_sdk_headers() -> dict:
    """{"winnt.h": text, "winuser.h": text} from the newest installed
    Windows SDK, or {} if there is none on this machine."""
    roots = sorted(pathlib.Path(
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        "Windows Kits", "10", "Include").glob("*"), reverse=True) \
        if os.name == "nt" else []
    for root in roots:
        headers = {name: root / "um" / name
                   for name in ("winnt.h", "winuser.h")}
        if all(path.is_file() for path in headers.values()):
            return {name: path.read_text(encoding="utf-8", errors="replace")
                    for name, path in headers.items()}
    return {}


_SDK_HEADERS = _installed_sdk_headers()
_needs_sdk = pytest.mark.skipif(
    not _SDK_HEADERS, reason="no Windows SDK installed on this machine")


def _defines(header: str, constant: str) -> bool:
    return re.search(rf"^\s*#\s*define\s+{re.escape(constant)}\b",
                      _SDK_HEADERS[header], re.M) is not None


@_needs_sdk
@pytest.mark.parametrize("constant", sorted(
    constant for constant, provenance in CONSTANT_PROVENANCE.items()
    if provenance.header in (WINNT_H, WINUSER_H)))
def test_a_win32_sdk_claim_is_true_of_the_installed_header(constant):
    """The claim, checked against the authority rather than against a
    second dictionary."""
    header = ("winnt.h" if CONSTANT_PROVENANCE[constant].header == WINNT_H
              else "winuser.h")
    assert _defines(header, constant), (
        f"{constant} is recorded as {CONSTANT_PROVENANCE[constant].header} "
        f"but the installed {header} does not define it")


@_needs_sdk
@pytest.mark.parametrize("constant", sorted(_PROVENANCE_KNOWN_ANSWERS))
def test_a_non_sdk_claim_is_absent_from_the_installed_sdk(constant):
    """The other direction, and the one that would have caught the
    original defect: a constant filed under the WDK or the native headers
    must NOT turn out to be sitting in winnt.h. `IO_COMPLETION_MODIFY_STATE`
    was, for as long as the label was per object type.

    winuser.h rows are exempt from the winuser.h half of the check, since
    that is where they are supposed to be."""
    header, _evidence = _PROVENANCE_KNOWN_ANSWERS[constant]
    assert not _defines("winnt.h", constant), (
        f"{constant} is not recorded as a winnt.h constant, but the "
        f"installed winnt.h defines it")
    if header != WINUSER_H:
        assert not _defines("winuser.h", constant), (
            f"{constant} is not recorded as a winuser.h constant, but the "
            f"installed winuser.h defines it")


@_needs_sdk
@pytest.mark.parametrize("constant,legacy,modern", [
    ("PROCESS_ALL_ACCESS", 0x001F0FFF, 0x001FFFFF),
    ("THREAD_ALL_ACCESS", 0x001F03FF, 0x001FFFFF),
])
def test_both_all_access_values_are_the_ones_winnt_h_defines(constant, legacy,
                                                              modern):
    """The two version-dependent constants, read off the real header.
    winnt.h guards them with `#if (NTDDI_VERSION >= NTDDI_VISTA)` and
    keeps the pre-Vista value under `#else`, both as
    `STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | <hex>`; this checks the two
    hex tails dumpex encodes are the two the header actually carries."""
    body = re.search(
        rf"#if \(NTDDI_VERSION >= NTDDI_VISTA\)\s*"
        rf"#define {constant}.*?#else\s*#define {constant}.*?#endif",
        _SDK_HEADERS["winnt.h"], re.S)
    assert body, f"winnt.h no longer guards {constant} by NTDDI_VERSION"

    standard_and_sync = 0x000F0000 | 0x00100000
    tails = [int(tail, 16) for tail in re.findall(r"0x([0-9A-Fa-f]+)\)",
                                                   body.group(0))]
    assert [standard_and_sync | tail for tail in tails] == [modern, legacy]


# ── The two decode invariants ───────────────────────────────────────────

@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
@pytest.mark.parametrize("mask", _MASKS)
def test_a_decode_accounts_for_every_bit_and_every_name_adds_one(type_name, mask):
    """The whole evidence claim in one assertion:

      * no name claims a bit the captured mask does not have (nothing
        invented);
      * the names plus the residual reconstruct the mask exactly
        (nothing dropped);
      * every name accounts for at least one bit no earlier name did
        (nothing double-reported).

    That last one is deliberately not "no two names share a bit": two SDK
    composites legitimately overlap -- `FILE_GENERIC_READ` and
    `FILE_GENERIC_WRITE` both carry `READ_CONTROL|SYNCHRONIZE`, and
    `0x0012019f` is exactly their union. What must never happen is a name
    that says nothing new, which is what would put `AllAccess` beside the
    rights it contains."""
    decoded = decode_access_mask(mask, type_name)
    bits = _bits_for(type_name)

    claimed = 0
    for name in decoded.names:
        value = bits[name]
        assert value & mask == value, f"{name} claims bits not in {mask:#010x}"
        assert value & ~claimed, f"{name} adds nothing an earlier name did not claim"
        claimed |= value

    assert claimed & decoded.undecoded_bits == 0
    assert claimed | decoded.undecoded_bits == mask
    assert len(set(decoded.names)) == len(decoded.names)


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
@pytest.mark.parametrize("mask", _MASKS)
def test_the_two_groups_partition_the_names_and_the_remainder(type_name, mask):
    """`Type` is what this object type defines, `Standard` is what every
    type shares, and the console prints them as two labelled groups. The
    split has to be exhaustive in both directions -- a name in neither
    group would vanish from the console, and a name in both would print
    twice."""
    decoded = decode_access_mask(mask, type_name)
    type_text, standard_text = access_right_groups(decoded)

    def pieces(text):
        return [p for p in text.split(RIGHTS_SEPARATOR) if p]

    named = [p for p in pieces(type_text) + pieces(standard_text)
              if not is_undecoded_token(p)]
    assert named == list(decoded.names)
    assert set(pieces(type_text)) & set(pieces(standard_text)) == set()

    # Every standard/generic name is in the shared group, and no
    # type-specific one is.
    assert all(name in _STANDARD_BY_NAME for name in pieces(standard_text)
                if not is_undecoded_token(name))
    assert not any(name in _STANDARD_BY_NAME for name in pieces(type_text)
                    if not is_undecoded_token(name))


@pytest.mark.parametrize("mask", _MASKS)
def test_an_unsupported_type_decodes_only_the_type_independent_bits(mask):
    """The standard/generic half of a mask means the same thing for every
    object type, so it is still decoded; the type-specific half is left
    as captured rather than read against a type dumpex does not have."""
    decoded = decode_access_mask(mask, "WaitCompletionPacket")

    assert decoded.type_supported is False
    claimed = 0
    for name in decoded.names:
        assert name in _STANDARD_BY_NAME
        claimed |= _STANDARD_BY_NAME[name]
    assert claimed | decoded.undecoded_bits == mask
    assert decoded.undecoded_bits & 0xFFFF == mask & 0xFFFF


# ── Type-specific decoding is the point ─────────────────────────────────

def test_the_same_low_order_bit_decodes_per_recorded_type():
    """Bit 0x0001 is a different right on every one of these types. One
    global bit table would be wrong for all but one of them, which is why
    §5.2 shipped the raw mask instead."""
    assert decode_access_mask(0x0001, "File").names == ("ReadData",)
    assert decode_access_mask(0x0001, "Process").names == ("Terminate",)
    assert decode_access_mask(0x0001, "Thread").names == ("Terminate",)
    assert decode_access_mask(0x0001, "Token").names == ("AssignPrimary",)
    assert decode_access_mask(0x0001, "Section").names == ("Query",)
    assert decode_access_mask(0x0001, "Job").names == ("AssignProcess",)
    assert decode_access_mask(0x0001, "Directory").names == ("Query",)
    assert decode_access_mask(0x0001, "SymbolicLink").names == ("Query",)
    assert decode_access_mask(0x0001, "Event").names == ("QueryState",)
    assert decode_access_mask(0x0001, "Mutant").names == ("QueryState",)
    assert decode_access_mask(0x0001, "Semaphore").names == ("QueryState",)
    assert decode_access_mask(0x0001, "Timer").names == ("QueryState",)
    assert decode_access_mask(0x0001, "Key").names == ("QueryValue",)


def test_masks_an_analyst_actually_meets():
    """Derived names only -- the captured mask is printed once, by the
    console's own Access column, and is never repeated here."""
    # PROCESS_ALL_ACCESS -- the composite, not its fourteen components.
    assert format_access_rights(decode_access_mask(0x001FFFFF, "Process")) == "AllAccess"
    # KEY_READ, the mask a dump repeats on every Key handle it has.
    assert format_access_rights(decode_access_mask(0x00020019, "Key")) == "KeyRead"
    assert (format_access_rights(decode_access_mask(0x0002001F, "Key"))
            == "KeyRead · KeyWrite")
    # FILE_GENERIC_READ|FILE_GENERIC_WRITE -- two SDK composites sharing
    # READ_CONTROL|SYNCHRONIZE, which is exactly this mask.
    assert (format_access_rights(decode_access_mask(0x0012019F, "File"))
            == "FileGenericRead · FileGenericWrite")
    assert format_access_rights(decode_access_mask(0x00120089, "File")) == "FileGenericRead"
    # Cross-process memory read on a Process handle.
    assert (format_access_rights(decode_access_mask(0x00000438, "Process"))
            == "VmOperation · VmRead · VmWrite · QueryInformation")
    # A remote thread context write.
    assert (format_access_rights(decode_access_mask(0x0000001A, "Thread"))
            == "SuspendResume · GetContext · SetContext")
    # A station handle -- the reason the registry is not #102's list
    # verbatim (WINSTA_ALL_ACCESS's own bits, spelled out).
    assert (format_access_rights(decode_access_mask(0x00000024, "WindowStation"))
            == "AccessClipboard · AccessGlobalAtoms")
    # ... and a desktop handle that can drive another session's input.
    assert (format_access_rights(decode_access_mask(0x00000102, "Desktop"))
            == "CreateWindow · SwitchDesktop")


def test_a_composite_alias_never_appears_beside_what_it_contains():
    """`FILE_ALL_ACCESS` contains both generic composites and all nine
    File rights; printing them together would report the same capability
    up to three times."""
    assert format_access_rights(decode_access_mask(0x001F01FF, "File")) == "AllAccess"
    assert format_access_rights(decode_access_mask(0x000F003F, "Key")) == "AllAccess"


def test_an_alias_name_is_type_qualified_wherever_the_bare_word_lies():
    """`GENERIC_READ` is a real, different bit. A File composite called
    `Read` beside it could not be told apart from the captured generic
    bit -- so the composite carries its type."""
    assert "FileGenericRead" in decode_access_mask(0x00120089, "File").names
    assert "GenericRead" not in decode_access_mask(0x00120089, "File").names
    assert decode_access_mask(0x80000000, "File").names == ("GenericRead",)


@pytest.mark.parametrize("type_name", ["File", "Process", "TpWorkerFactory", None])
@pytest.mark.parametrize("mask", _MASKS)
def test_the_derived_text_carries_no_value_but_its_own_remainder(type_name, mask):
    """The Access column is the one printed copy of the captured mask: it
    is aligned for a column-wise scan and it is what gets compared and
    copied. A second copy one line below says nothing new and costs the
    width the right names need.

    The one hexadecimal value the derived text may carry is the
    REMAINDER, because that value is a part of the mask that no name
    accounts for and it exists nowhere else on screen. (It equals the
    whole mask exactly when nothing at all decoded, which is that same
    fact, not a repetition.)"""
    decoded = decode_access_mask(mask, type_name)
    text = format_access_rights(decoded)

    # The remainder is reported in at most two pieces -- the
    # type-specific half and the shared half, which the console prints
    # under different labels -- and they always sum back to it.
    printed = [int(value, 16) for value in re.findall(r"0x[0-9a-f]+", text)]
    assert len(printed) <= 2
    assert sum(printed) == decoded.undecoded_bits
    for value in printed:
        assert value & decoded.undecoded_bits == value
    if decoded.undecoded_bits != mask:
        assert f"0x{mask:08x}" not in text


def test_type_matching_ignores_case_and_surrounding_space():
    """The type name is a dump-recorded string and this is a display
    projection -- `FILE` and `File` are the same object type."""
    for spelling in ("File", "file", "FILE", "  File  "):
        assert decode_access_mask(0x0001, spelling).names == ("ReadData",)


def test_an_unknown_type_name_is_never_decoded_against_some_other_type():
    for type_name in ("", "   ", "Filee", "Fil", "WaitCompletionPacket"):
        assert decode_access_mask(0x0001, type_name).type_supported is False


# ── Standard, generic, zero, absent, residual ───────────────────────────

def test_standard_rights_decode_for_every_type_including_unsupported_ones():
    standard = 0x001F0000
    expected = ("Delete", "ReadControl", "WriteDac", "WriteOwner", "Synchronize")
    for type_name in ("File", "Process", "WaitCompletionPacket", None):
        assert decode_access_mask(standard, type_name).names == expected


def test_generic_bits_are_reported_as_captured_and_never_expanded():
    """A GENERIC_* bit still set in GrantedAccess is itself the fact. The
    per-type GENERIC_MAPPING lives in the kernel object type and is not
    in the dump, so expanding it would be a guess presented as evidence."""
    decoded = decode_access_mask(0x80000000, "File")
    assert decoded.names == ("GenericRead",)
    assert decoded.undecoded_bits == 0
    # ... and specifically not the FILE_GENERIC_READ component rights.
    assert "ReadData" not in decoded.names


def test_a_zero_mask_is_no_rights_and_not_missing_evidence():
    decoded = decode_access_mask(0, "File")
    assert decoded == DecodedAccess(mask=0, type_supported=True, type_names=(),
                                     standard_names=(), undecoded_bits=0)
    assert decoded.names == ()
    assert access_right_groups(decoded) == ("", "")
    assert format_access_rights(decoded) == NO_RIGHTS_TEXT == "(no rights)"


def test_an_absent_mask_decodes_to_nothing_at_all():
    """`granted_access` is null when the descriptor's value did not
    normalize (§5.2.2). Absent evidence must not become "no rights"."""
    for value in (None, True, False, -1, 1.0, "0x1"):
        assert decode_access_mask(value, "File") is None


def test_bits_with_no_documented_right_stay_visible_at_their_raw_value():
    """0x8000 is not a documented File right. Guessing at it, or dropping
    it, would both leave an analyst unable to audit the captured mask."""
    decoded = decode_access_mask(0x00008001, "File")
    assert decoded.names == ("ReadData",)
    assert decoded.undecoded_bits == 0x00008000
    assert format_access_rights(decoded) == "ReadData · UnknownBits(0x00008000)"


def test_the_two_remainders_say_which_half_is_undecoded():
    """Each names its own kind and carries its own value, so a reader
    tells an undocumented BIT from an undecodable TYPE without a legend
    under the table."""
    known_type = format_access_rights(decode_access_mask(0x00008000, "File"))
    unknown_type = format_access_rights(decode_access_mask(0x00008000, "TpWorkerFactory"))
    assert known_type == "UnknownBits(0x00008000)"
    assert unknown_type == "TypeSpecificUnavailable(0x00008000)"


def test_a_remainder_reports_the_remainder_and_never_the_whole_mask():
    """`TypeSpecificUnavailable(0x000f037f)` would claim the standard
    rights this decode just named were undecodable too."""
    decoded = decode_access_mask(0x000F037F, "TpWorkerFactory")
    assert format_access_rights(decoded) == (
        "TypeSpecificUnavailable(0x0000037f) · Delete · ReadControl · WriteDac · WriteOwner")
    # ... and a type the registry does carry has no remainder at all.
    assert "Unavailable" not in format_access_rights(
        decode_access_mask(0x000F037F, "WindowStation"))


def test_each_half_of_a_remainder_is_reported_with_the_group_it_belongs_to():
    """Bits 0-15 are type-specific and belong with the type's own rights;
    everything above them is shared, so an undecoded bit up there is an
    undocumented one whatever the recorded type was."""
    type_text, standard_text = access_right_groups(
        decode_access_mask(0xFFFFFFFF, "TpWorkerFactory"))

    assert type_text == "TypeSpecificUnavailable(0x0000ffff)"
    assert standard_text.endswith("UnknownBits(0x0ce00000)")


def test_an_alias_and_its_components_never_both_appear():
    decoded = decode_access_mask(0x001F01FF, "File")
    assert decoded.names == ("AllAccess",)
    assert decoded.undecoded_bits == 0
    # One bit more than FILE_ALL_ACCESS: the alias still fires and the
    # extra bit is reported once, on its own.
    more = decode_access_mask(0x001F03FF, "File")
    assert more.names == ("AllAccess",)
    assert more.undecoded_bits == 0x00000200


def test_an_alias_needs_every_one_of_its_bits():
    """FILE_ALL_ACCESS minus one bit is not all access, and saying so
    would overstate what the dump captured. The narrower composites the
    remaining bits DO satisfy still fire."""
    decoded = decode_access_mask(0x001F01FF & ~0x0040, "File")
    assert "AllAccess" not in decoded.names
    assert "DeleteChild" not in decoded.names
    assert decoded.names[:2] == ("FileGenericRead", "FileGenericWrite")
    assert decoded.undecoded_bits == 0


def test_the_mask_is_carried_through_unchanged():
    for mask in _MASKS:
        assert decode_access_mask(mask, "File").mask == mask


def test_decoding_is_deterministic():
    first = decode_access_mask(0x0012019F, "File")
    for _ in range(5):
        assert decode_access_mask(0x0012019F, "File") == first


def test_order_is_alias_then_specific_then_standard_then_generic():
    """Frozen so a right sits in the same place in every row an analyst
    compares by eye -- and split into the two groups the console labels
    `Type` and `Standard`."""
    decoded = decode_access_mask(0x8002019F, "File")
    assert decoded.type_names == (
        "ReadData", "WriteData", "AppendData", "ReadEa", "WriteEa",
        "ReadAttributes", "WriteAttributes")     # specific, ascending
    assert decoded.standard_names == ("ReadControl", "GenericRead")
    assert decoded.names == decoded.type_names + decoded.standard_names

    # With SYNCHRONIZE set the two File composites cover the same bits,
    # and they lead the type group.
    composite = decode_access_mask(0x8012019F, "File")
    assert composite.names == ("FileGenericRead", "FileGenericWrite", "GenericRead")


# ── Composite aliases: a known-answer table, written by hand ────────────
# Every OTHER test in this file reads the expected values out of
# _TYPE_REGISTRY, which makes them invariant tests: they prove the decode
# is self-consistent, and they would keep passing if `TokenRead` and
# `TokenWrite` had each other's constant. The registry would still be
# internally coherent; it would simply be WRONG, and an investigator
# would read "TokenWrite" off a handle that can only query.
#
# This table is therefore transcribed from the Windows SDK headers rather
# than generated from production code -- name, value, and the full set of
# component rights the value expands to. Nothing below may be derived
# from dumpex, and a new alias has to be added here by hand or
# test_every_registered_alias_has_a_known_answer fails.
_ALIAS_KNOWN_ANSWERS = [
    # (type, alias name, value, component rights in canonical order)
    ("File", "AllAccess", 0x001F01FF,                    # FILE_ALL_ACCESS
     ("ReadData", "WriteData", "AppendData", "ReadEa", "WriteEa", "Execute",
      "DeleteChild", "ReadAttributes", "WriteAttributes",
      "Delete", "ReadControl", "WriteDac", "WriteOwner", "Synchronize")),
    ("File", "FileGenericRead", 0x00120089,              # FILE_GENERIC_READ
     ("ReadData", "ReadEa", "ReadAttributes", "ReadControl", "Synchronize")),
    ("File", "FileGenericWrite", 0x00120116,             # FILE_GENERIC_WRITE
     ("WriteData", "AppendData", "WriteEa", "WriteAttributes",
      "ReadControl", "Synchronize")),
    ("File", "FileGenericExecute", 0x001200A0,           # FILE_GENERIC_EXECUTE
     ("Execute", "ReadAttributes", "ReadControl", "Synchronize")),
    ("Process", "AllAccess", 0x001FFFFF,                 # PROCESS_ALL_ACCESS
     ("Terminate", "CreateThread", "SetSessionId", "VmOperation", "VmRead",
      "VmWrite", "DupHandle", "CreateProcess", "SetQuota", "SetInformation",
      "QueryInformation", "SuspendResume", "QueryLimitedInformation",
      "SetLimitedInformation",
      "Delete", "ReadControl", "WriteDac", "WriteOwner", "Synchronize",
      # PROCESS_ALL_ACCESS is defined over the whole specific range, and
      # Windows documents no right for bits 0x4000/0x8000.
      "UnknownBits(0x0000c000)")),
    ("Thread", "AllAccess", 0x001FFFFF,                  # THREAD_ALL_ACCESS
     ("Terminate", "SuspendResume", "Alert", "GetContext", "SetContext",
      "SetInformation", "QueryInformation", "SetThreadToken", "Impersonate",
      "DirectImpersonation", "SetLimitedInformation", "QueryLimitedInformation",
      "Resume",
      "Delete", "ReadControl", "WriteDac", "WriteOwner", "Synchronize",
      "UnknownBits(0x0000e000)")),
    ("Token", "AllAccess", 0x000F01FF,                   # TOKEN_ALL_ACCESS
     ("AssignPrimary", "Duplicate", "Impersonate", "Query", "QuerySource",
      "AdjustPrivileges", "AdjustGroups", "AdjustDefault", "AdjustSessionId",
      "Delete", "ReadControl", "WriteDac", "WriteOwner")),
    ("Token", "TokenWrite", 0x000200E0,                  # TOKEN_WRITE
     ("AdjustPrivileges", "AdjustGroups", "AdjustDefault", "ReadControl")),
    ("Token", "TokenRead", 0x00020008,                   # TOKEN_READ
     ("Query", "ReadControl")),
    ("Key", "AllAccess", 0x000F003F,                     # KEY_ALL_ACCESS
     ("QueryValue", "SetValue", "CreateSubKey", "EnumerateSubKeys", "Notify",
      "CreateLink", "Delete", "ReadControl", "WriteDac", "WriteOwner")),
    ("Key", "KeyRead", 0x00020019,                       # KEY_READ
     ("QueryValue", "EnumerateSubKeys", "Notify", "ReadControl")),
    ("Key", "KeyWrite", 0x00020006,                      # KEY_WRITE
     ("SetValue", "CreateSubKey", "ReadControl")),
    ("Section", "AllAccess", 0x000F001F,                 # SECTION_ALL_ACCESS
     ("Query", "MapWrite", "MapRead", "MapExecute", "ExtendSize",
      "Delete", "ReadControl", "WriteDac", "WriteOwner")),
    ("Job", "AllAccess", 0x001F003F,                     # JOB_OBJECT_ALL_ACCESS
     ("AssignProcess", "SetAttributes", "Query", "Terminate",
      "SetSecurityAttributes", "Impersonate",
      "Delete", "ReadControl", "WriteDac", "WriteOwner", "Synchronize")),
    ("Directory", "AllAccess", 0x000F000F,               # DIRECTORY_ALL_ACCESS
     ("Query", "Traverse", "CreateObject", "CreateSubdirectory",
      "Delete", "ReadControl", "WriteDac", "WriteOwner")),
    ("SymbolicLink", "AllAccess", 0x000F0001,            # SYMBOLIC_LINK_ALL_ACCESS
     ("Query", "Delete", "ReadControl", "WriteDac", "WriteOwner")),
    ("Event", "AllAccess", 0x001F0003,                   # EVENT_ALL_ACCESS
     ("QueryState", "ModifyState",
      "Delete", "ReadControl", "WriteDac", "WriteOwner", "Synchronize")),
    ("Mutant", "AllAccess", 0x001F0001,                  # MUTANT_ALL_ACCESS
     ("QueryState",
      "Delete", "ReadControl", "WriteDac", "WriteOwner", "Synchronize")),
    ("Semaphore", "AllAccess", 0x001F0003,               # SEMAPHORE_ALL_ACCESS
     ("QueryState", "ModifyState",
      "Delete", "ReadControl", "WriteDac", "WriteOwner", "Synchronize")),
    ("Timer", "AllAccess", 0x001F0003,                   # TIMER_ALL_ACCESS
     ("QueryState", "ModifyState",
      "Delete", "ReadControl", "WriteDac", "WriteOwner", "Synchronize")),
    ("IoCompletion", "AllAccess", 0x001F0003,            # IO_COMPLETION_ALL_ACCESS
     ("QueryState", "ModifyState",
      "Delete", "ReadControl", "WriteDac", "WriteOwner", "Synchronize")),
]

_ALIAS_IDS = [f"{type_name}-{alias}" for type_name, alias, _v, _c in _ALIAS_KNOWN_ANSWERS]


@pytest.mark.parametrize("type_name,alias,value,components",
                          _ALIAS_KNOWN_ANSWERS, ids=_ALIAS_IDS)
def test_each_alias_names_the_constant_the_sdk_defines(type_name, alias, value, components):
    """Name, value and expansion, each checked against a value this file
    states independently. A registry that swapped `TokenRead` with
    `TokenWrite` stays internally coherent and passes every invariant
    test in this file; it fails here."""
    _specific, aliases = _TYPE_REGISTRY[type_name.casefold()]
    assert (value, alias) in [(v, n) for v, n, _c, _s in aliases], (
        f"{type_name}: no alias {alias} = {value:#010x} in the registry")

    # The mask decodes to exactly that one name ...
    decoded = decode_access_mask(value, type_name)
    assert decoded.names == (alias,)
    assert decoded.undecoded_bits == 0
    assert alias_names_in(decoded, type_name) == (alias,)

    # ... and expanding it yields exactly the rights it stands for, in
    # the canonical order, with nothing invented and nothing dropped.
    assert expand_alias(alias, type_name) == RIGHTS_SEPARATOR.join(components)


@pytest.mark.parametrize("type_name,alias,value,components",
                          _ALIAS_KNOWN_ANSWERS, ids=_ALIAS_IDS)
def test_an_alias_expansion_covers_exactly_its_own_bits(type_name, alias, value, components):
    """The components are transcribed by hand, so this is where a typo in
    the table itself would hide: their bits must add up to the constant
    and to nothing else."""
    bits = _bits_for(type_name)
    covered = 0
    for name in components:
        if is_undecoded_token(name):
            covered |= int(name[name.index("(") + 1:-1], 16)
        else:
            covered |= bits[name]
    assert covered == value, f"{type_name} {alias}: components cover {covered:#010x}"


def test_every_registered_alias_has_a_known_answer():
    """A composite added to production without a hand-written expectation
    here would be checked only against itself."""
    registered = {(type_name, name)
                   for type_name, (_specific, aliases) in _TYPE_REGISTRY.items()
                   for _value, name, _c, _s in aliases}
    known = {(type_name.casefold(), alias)
              for type_name, alias, _value, _components in _ALIAS_KNOWN_ANSWERS}
    assert registered == known


def test_an_expansion_never_expands_into_another_alias():
    """Answering "what does AllAccess contain?" with a list containing
    `FileGenericRead` would answer the question with the thing that was
    asked about."""
    for type_name, alias, _value, _components in _ALIAS_KNOWN_ANSWERS:
        _specific, aliases = _TYPE_REGISTRY[type_name.casefold()]
        names = {name for _v, name, _c, _s in aliases}
        expansion = expand_alias(alias, type_name).split(RIGHTS_SEPARATOR)
        assert not names & set(expansion), f"{type_name} {alias} expands into a composite"


def test_expanding_something_this_type_does_not_define_says_nothing():
    assert expand_alias("KeyRead", "File") == ""
    assert expand_alias("AllAccess", "TpWorkerFactory") == ""
    assert expand_alias("AllAccess", None) == ""
    assert expand_alias("ReadData", "File") == ""      # a single right is not a composite


def test_alias_names_in_reports_only_composites_and_only_those_used():
    """The console lists what an alias stands for, and it may only list
    the ones actually on screen."""
    assert alias_names_in(decode_access_mask(0x0012019F, "File"), "File") == (
        "FileGenericRead", "FileGenericWrite")
    assert alias_names_in(decode_access_mask(0x00000001, "File"), "File") == ()
    assert alias_names_in(decode_access_mask(0x000F037F, "TpWorkerFactory"),
                           "TpWorkerFactory") == ()


# ── The Vista widening of PROCESS/THREAD_ALL_ACCESS ─────────────────────
# winnt.h defines both constants twice, guarded by NTDDI_VERSION, and
# Microsoft states the change in "Process Security and Access Rights" and
# "Thread Security and Access Rights". A full handle in an XP or
# Server 2003 dump therefore carries 0x001F0FFF (process) or 0x001F03FF
# (thread), not 0x001FFFFF.
#
# Both eras are pinned, and the point of pinning both is that the wrong
# one is not a crash or a lost bit -- it is a row that quietly stops
# saying `AllAccess` and starts reading as a twelve-name list, which is
# the readability this whole feature exists to provide.

def test_a_pre_vista_process_all_access_mask_reads_as_all_access():
    decoded = decode_access_mask(0x001F0FFF, "Process", os_major=5)
    assert decoded.names == ("AllAccess",)
    assert decoded.undecoded_bits == 0


def test_a_pre_vista_thread_all_access_mask_reads_as_all_access():
    decoded = decode_access_mask(0x001F03FF, "Thread", os_major=5)
    assert decoded.names == ("AllAccess",)
    assert decoded.undecoded_bits == 0


@pytest.mark.parametrize("type_name,legacy", [("Process", 0x001F0FFF),
                                               ("Thread", 0x001F03FF)])
def test_the_modern_constant_never_calls_a_pre_vista_mask_all_access(type_name,
                                                                      legacy):
    """The direction that would be a correctness regression rather than a
    readability one. On Vista and later, 0x001F0FFF on a Process is a
    PARTIAL mask -- the two `*_LIMITED_INFORMATION` rights are missing --
    and printing `AllAccess` for it would claim a capability the handle
    does not have. So the legacy value is used only when the caller says
    the dump is old."""
    for os_major in (None, 6, 10):
        decoded = decode_access_mask(legacy, type_name, os_major=os_major)
        assert "AllAccess" not in decoded.names
        assert decoded.undecoded_bits == 0        # still no bit is lost


@pytest.mark.parametrize("type_name", ["Process", "Thread"])
def test_a_modern_all_access_mask_still_reads_as_all_access(type_name):
    assert decode_access_mask(0x001FFFFF, type_name).names == ("AllAccess",)
    assert decode_access_mask(0x001FFFFF, type_name,
                               os_major=10).names == ("AllAccess",)


@pytest.mark.parametrize("type_name,extra,remainder", [
    ("Process", ("QueryLimitedInformation", "SetLimitedInformation"), 0xC000),
    ("Thread", ("SetLimitedInformation", "QueryLimitedInformation", "Resume"),
     0xE000),
])
def test_a_modern_mask_read_against_the_old_constant_names_the_extra_rights(
        type_name, extra, remainder):
    """The honest decomposition when a caller passes an old version for a
    mask that carries the newer bits: `AllAccess` for what the pre-Vista
    constant covers, then the rights it does not, each named -- and the
    bits that have no documented right at all left visible at their own
    value.

    That remainder is the interesting part. The MODERN `*_ALL_ACCESS` is
    defined over the whole low 16 bits, so it swallows the two or three
    undocumented ones and leaves nothing over; the pre-Vista constant
    stops at 0xFFF/0x3FF and does not. So the same mask honestly
    decodes to a different remainder under the two constants, because the
    two constants genuinely cover different bits. Neither reading loses a
    bit -- which is the invariant that actually matters."""
    decoded = decode_access_mask(0x001FFFFF, type_name, os_major=5)
    assert decoded.names[0] == "AllAccess"
    assert set(decoded.names[1:]) == set(extra)
    assert decoded.undecoded_bits == remainder

    # Nothing lost: what the names cover plus the remainder is the mask.
    bits = _bits_for(type_name)
    covered = 0
    for name in decoded.names:
        covered |= bits[name]
    assert covered | decoded.undecoded_bits == 0x001FFFFF


def test_an_expansion_follows_the_version_its_decode_used():
    """Expanding a pre-Vista `AllAccess` against the modern constant
    would list rights the handle never had."""
    legacy = expand_alias("AllAccess", "Process", os_major=5)
    modern = expand_alias("AllAccess", "Process")

    assert "QueryLimitedInformation" not in legacy
    assert "QueryLimitedInformation" in modern
    assert "Terminate" in legacy and "Synchronize" in legacy


@pytest.mark.parametrize("os_major", [None, 0, 5, 6, 10, -1, "6", True, 1.5])
def test_only_a_plain_old_int_selects_the_pre_vista_constants(os_major):
    """A dump whose SYSTEM_INFO stream is absent or unreadable yields
    None, and a hostile or malformed one could yield anything. Guessing
    "old" from missing evidence would print `AllAccess` for a partial
    mask on every such dump, so only a plain non-negative int below 6
    selects the narrower value."""
    decoded = decode_access_mask(0x001F0FFF, "Process", os_major=os_major)
    selects_legacy = (isinstance(os_major, int)
                       and not isinstance(os_major, bool)
                       and 0 <= os_major < 6)
    assert (decoded.names == ("AllAccess",)) is selects_legacy


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
@pytest.mark.parametrize("mask", _MASKS)
def test_the_version_changes_nothing_for_the_types_it_does_not_touch(type_name,
                                                                     mask):
    """`os_major` selects one composite on two types. On the other
    fourteen the decode must be byte-for-byte identical, so a caller
    passing a version cannot perturb a File or a Key row."""
    old = decode_access_mask(mask, type_name, os_major=5)
    new = decode_access_mask(mask, type_name, os_major=10)

    assert old.mask == new.mask == mask
    if type_name not in ("process", "thread"):
        assert old == new


@pytest.mark.parametrize("os_major", [None, 5, 6, 10])
@pytest.mark.parametrize("type_name", ["Process", "Thread"])
@pytest.mark.parametrize("mask", _MASKS)
def test_no_bit_is_ever_lost_whichever_constant_is_selected(type_name, mask,
                                                            os_major):
    """The invariant that holds across both eras, and the one worth
    holding: the remainder legitimately differs between the two
    constants, but every set bit is still either named or visible in
    `undecoded_bits`. A version that made a bit disappear would be the
    one failure mode this feature must not have."""
    decoded = decode_access_mask(mask, type_name, os_major=os_major)
    bits = _bits_for(type_name)

    covered = 0
    for name in decoded.names:
        covered |= bits[name]
    assert covered | decoded.undecoded_bits == mask
    assert covered & ~mask == 0        # and nothing is claimed that is absent


# ── canonical_type_name() ────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("Process", "Process"),
    ("process", "Process"),
    ("PROCESS", "Process"),
    ("  Process  ", "Process"),
    (" " * 200 + "Process" + " " * 200, "Process"),
    ("\t\nProcess\r\n", "Process"),
    ("SymbolicLink", "SymbolicLink"),
    ("symboliclink", "SymbolicLink"),
    ("WindowStation", "WindowStation"),
])
def test_canonical_type_name_normalizes_any_spelling_to_the_registry_one(raw, expected):
    """The fix for a padded or cased Type field: every spelling that
    `_normalize_type()` accepts must resolve to the SAME short, bounded
    string a renderer can safely use as a label or a dedup key."""
    assert canonical_type_name(raw) == expected


@pytest.mark.parametrize("raw", ["TpWorkerFactory", "", "   ", None, 42, b"Process"])
def test_canonical_type_name_is_none_for_anything_unkeyable_or_unsupported(raw):
    assert canonical_type_name(raw) is None


def test_canonical_type_name_is_bounded_regardless_of_input_length():
    """The actual bug: a 4096-byte padded Type value must not produce a
    4096-character label. The canonical spelling is drawn from
    SUPPORTED_OBJECT_TYPES, whose longest member is "WindowStation" (13
    chars), so this holds independent of what any dump contains."""
    huge = " " * 4096 + "process" + " " * 4096
    result = canonical_type_name(huge)
    assert result == "Process"
    assert len(result) <= max(len(name) for name in SUPPORTED_OBJECT_TYPES)


# ── unconfirmed_names() ──────────────────────────────────────────────────

@pytest.mark.parametrize("mask,type_name,expected", [
    # Semaphore: QueryState is unconfirmed, ModifyState is winnt.h.
    (0x0001, "Semaphore", {"QueryState"}),
    (0x0002, "Semaphore", set()),
    (0x0003, "Semaphore", {"QueryState"}),
    # IoCompletion: same shape as Semaphore for the bare bit ...
    (0x0001, "IoCompletion", {"QueryState"}),
    (0x0002, "IoCompletion", set()),
    # ... but AllAccess is its OWN (confirmed) constant, not the bits'.
    # A mixed-source TYPE does not make every alias on it unconfirmed.
    (0x001F0003, "IoCompletion", set()),
    # SymbolicLink: neither bit has a confirmed header.
    (0x0001, "SymbolicLink", {"Query"}),
    (0x0002, "SymbolicLink", {"Set"}),
    (0x0003, "SymbolicLink", {"Query", "Set"}),
    # Thread: THREAD_ALERT alone is unconfirmed among thirteen winnt.h rights.
    (0x0004, "Thread", {"Alert"}),
    (0x0001, "Thread", set()),
    (0x0005, "Thread", {"Alert"}),
    # Timer looks like Semaphore/Event from the outside and is NOT mixed:
    # winnt.h names both of its rights.
    (0x0001, "Timer", set()),
    (0x0003, "Timer", set()),
    # Event: QueryState is ntifs.h-confirmed (unlike Semaphore's).
    (0x0001, "Event", set()),
    # Directory: fully confirmed (ntifs.h).
    (0x000F000F, "Directory", set()),
    # A type this registry does not carry has nothing to doubt.
    (0x0001, "TpWorkerFactory", set()),
    (0x0001, None, set()),
])
def test_unconfirmed_names_matches_the_provenance_of_each_decoded_name(mask, type_name,
                                                                        expected):
    decoded = decode_access_mask(mask, type_name)
    assert unconfirmed_names(decoded, type_name) == frozenset(expected)


def test_unconfirmed_names_is_always_a_subset_of_type_names_never_standard():
    """_STANDARD_RIGHTS and _GENERIC_RIGHTS are winnt.h in full, so a
    standard or generic bit can never be in the result -- this is an
    invariant of the tables, not a coincidence of the masks tried above."""
    decoded = decode_access_mask(0xFFFFFFFF, "Semaphore")
    unconfirmed = unconfirmed_names(decoded, "Semaphore")
    assert unconfirmed <= set(decoded.type_names)
    assert not (unconfirmed & set(decoded.standard_names))


def test_unconfirmed_names_follows_the_same_os_major_the_decode_used():
    """Process/Thread AllAccess is winnt.h-confirmed in both eras, so this
    is mostly a non-event -- but the function must ask the SAME registry
    decode_access_mask() used, not silently default to the modern one."""
    decoded_legacy = decode_access_mask(0x001F0FFF, "Process", os_major=5)
    assert decoded_legacy.names == ("AllAccess",)
    assert unconfirmed_names(decoded_legacy, "Process", os_major=5) == frozenset()


# ── unconfirmed_names_in_alias(): components, not the alias itself ──────
# A DIFFERENT question from `alias_provenance(...).confirmed`: whether
# each right an alias EXPANDS TO has its own confirmed constant, which
# can disagree with whether the alias's own combination constant does.

@pytest.mark.parametrize("type_name,alias,expected", [
    # The alias itself is confirmed (winnt.h); one component is not.
    ("IoCompletion", "AllAccess", {"QueryState"}),
    ("Thread", "AllAccess", {"Alert"}),
    ("Semaphore", "AllAccess", {"QueryState"}),
    # The alias itself is ALSO unconfirmed -- both facts hold at once.
    ("SymbolicLink", "AllAccess", {"Query"}),
    # Every component confirmed: Directory (ntifs.h throughout), and the
    # two lookalikes that must NOT be swept in with Semaphore/IoCompletion.
    ("Directory", "AllAccess", set()),
    ("Event", "AllAccess", set()),
    ("Timer", "AllAccess", set()),
    # Confirmed throughout, unrelated family.
    ("Key", "KeyRead", set()),
    ("File", "AllAccess", set()),
])
def test_unconfirmed_names_in_alias_checks_the_expansion_not_the_alias(type_name, alias,
                                                                        expected):
    assert unconfirmed_names_in_alias(alias, type_name) == frozenset(expected)


def test_unconfirmed_names_in_alias_can_disagree_with_the_aliases_own_provenance():
    """The reason this is a SEPARATE function from `alias_provenance()`,
    stated as a single fact: `IO_COMPLETION_ALL_ACCESS` is itself a
    confirmed winnt.h constant, so the alias-level question says
    confirmed -- while the component-level question, asked here, finds
    `QueryState` unconfirmed inside that very expansion. Both are correct
    answers to two different questions."""
    assert alias_provenance("AllAccess", "IoCompletion").confirmed is True
    assert unconfirmed_names_in_alias("AllAccess", "IoCompletion") == {"QueryState"}


def test_unconfirmed_names_in_alias_never_reaches_into_the_standard_rights():
    """Only the specific-bit half of an expansion can appear here: the
    standard/generic rights an `*_ALL_ACCESS` also covers are
    `_STANDARD_RIGHTS`/`_GENERIC_RIGHTS`, `winnt.h` in full, so a
    `Semaphore`/`IoCompletion` `AllAccess` -- which DOES have an
    unconfirmed specific-bit component -- must still report nothing from
    its standard-rights half (`Delete`, `ReadControl`, `WriteDac`,
    `WriteOwner`, `Synchronize`, all of which its expansion also names)."""
    for type_name in ("Semaphore", "IoCompletion", "Thread", "SymbolicLink"):
        unconfirmed = unconfirmed_names_in_alias("AllAccess", type_name)
        assert not (unconfirmed & {"Delete", "ReadControl", "WriteDac",
                                    "WriteOwner", "Synchronize"})


def test_unconfirmed_names_in_alias_returns_empty_for_an_undefined_name():
    assert unconfirmed_names_in_alias("KeyRead", "File") == frozenset()
    assert unconfirmed_names_in_alias("AllAccess", "TpWorkerFactory") == frozenset()
    assert unconfirmed_names_in_alias("AllAccess", None) == frozenset()


def test_unconfirmed_names_in_alias_follows_the_same_os_major_the_decode_used():
    """Process/Thread AllAccess is winnt.h-confirmed in both eras and
    THREAD_ALERT is not part of either `*_ALL_ACCESS` composite (it is
    outside the 0x001F03FF/0x001FFFFF range's own bit, bit 0x0004 IS
    inside 0x3FF -- so pre-Vista Thread AllAccess still expands through
    `Alert`); both eras must therefore still find it unconfirmed."""
    assert unconfirmed_names_in_alias("AllAccess", "Thread", os_major=5) == {"Alert"}
    assert unconfirmed_names_in_alias("AllAccess", "Thread", os_major=10) == {"Alert"}


# ── Wrapping ────────────────────────────────────────────────────────────

def _rejoin(lines) -> str:
    """The inverse of the wrap: a continued line ends in ` |` and the
    next line carries on from there, so a single space re-joins them."""
    return " ".join(lines)


def test_wrapping_never_splits_a_right_name_and_never_drops_one():
    text = format_access_rights(decode_access_mask(0x0000143A, "Thread"))
    lines = wrap_rights(text, 24)

    assert len(lines) > 1
    assert _rejoin(lines) == text            # nothing added, nothing lost
    for line in lines[:-1]:
        assert line.endswith(" ·")           # reads as "continues below"
    # Every line fits, unless it is a single piece that cannot: an
    # over-wide piece overflows rather than being cut in half.
    for line in lines:
        assert len(line) <= 24 or RIGHTS_SEPARATOR not in line


def test_a_remainder_token_is_never_split_across_two_lines():
    """`TypeSpecificUnavailable(0x0000037f)` broken in half reads as two
    values, and whitespace wrapping would break it."""
    text = format_access_rights(decode_access_mask(0x000F037F, "TpWorkerFactory"))
    lines = wrap_rights(text, 46)

    assert lines == ["TypeSpecificUnavailable(0x0000037f) · Delete ·",
                     "ReadControl · WriteDac · WriteOwner"]
    assert _rejoin(lines) == text


def test_a_piece_wider_than_the_wrap_width_overflows_instead_of_truncating():
    lines = wrap_rights("QueryLimitedInformation · Terminate", 8)
    assert lines == ["QueryLimitedInformation ·", "Terminate"]


def test_wrapping_a_single_piece_is_one_line():
    assert wrap_rights("AllAccess", 40) == ["AllAccess"]
    assert wrap_rights(NO_RIGHTS_TEXT, 40) == [NO_RIGHTS_TEXT]


@pytest.mark.parametrize("width", [1, 0, -5])
def test_a_degenerate_width_still_returns_every_name(width):
    text = "ReadData · WriteData · Synchronize"
    assert _rejoin(wrap_rights(text, width)) == text


def test_symbolic_link_decodes_both_of_its_documented_rights():
    """`SYMBOLIC_LINK_SET` (0x0002) is defined alongside
    `SYMBOLIC_LINK_QUERY`; leaving it out reported an ordinary,
    documented right as an unknown bit."""
    assert decode_access_mask(0x0002, "SymbolicLink").names == ("Set",)
    assert decode_access_mask(0x0002, "SymbolicLink").undecoded_bits == 0
    assert decode_access_mask(0x0003, "SymbolicLink").names == ("Query", "Set")


def test_the_registry_carries_the_types_a_real_handle_table_is_full_of():
    """`Desktop` and `WindowStation` are why the registry is not #102's
    list verbatim: a station/desktop handle is how one session's process
    reaches another's input queue, clipboard and screen, and a row that
    could only say "unknown type-specific bits" for it answered
    nothing."""
    for type_name in ("Desktop", "WindowStation", "IoCompletion"):
        assert type_name in SUPPORTED_OBJECT_TYPES
        assert decode_access_mask(0x0001, type_name).type_supported is True

    assert decode_access_mask(0x0001, "Desktop").names == ("ReadObjects",)
    assert decode_access_mask(0x0001, "WindowStation").names == ("EnumDesktops",)
    assert decode_access_mask(0x0001, "IoCompletion").names == ("QueryState",)


def test_a_station_or_desktop_mask_is_never_reported_as_all_access():
    """Neither type has an `*_ALL_ACCESS` that includes the standard
    rights (`WINSTA_ALL_ACCESS` is the specific bits alone, and winuser.h
    defines no `DESKTOP_ALL_ACCESS`), so neither gets an alias: one name
    that meant "everything plus the standard rights" on a File and
    something narrower here would be worse than the list."""
    for type_name in ("Desktop", "WindowStation"):
        _specific, aliases = _TYPE_REGISTRY[type_name.casefold()]
        assert aliases == ()

    decoded = decode_access_mask(0x000F037F, "WindowStation")
    assert "AllAccess" not in decoded.names
    assert decoded.undecoded_bits == 0
    assert decoded.names == (
        "EnumDesktops", "ReadAttributes", "AccessClipboard", "CreateDesktop",
        "WriteAttributes", "AccessGlobalAtoms", "ExitWindows", "Enumerate",
        "ReadScreen", "Delete", "ReadControl", "WriteDac", "WriteOwner")


def test_types_with_no_authoritative_right_definitions_are_left_undecoded():
    """`TpWorkerFactory` and friends fill real handle tables, and their
    rights live in reverse-engineered headers only. Decoding them would
    be a guess presented as a permission -- the thing §5.2 refused to
    ship -- so they report their type-independent bits and say the rest
    is unknown."""
    for type_name in ("TpWorkerFactory", "WaitCompletionPacket", "ALPC Port",
                       "EtwRegistration", "IRTimer"):
        decoded = decode_access_mask(0x00100003, type_name)
        assert decoded.type_supported is False
        assert decoded.names == ("Synchronize",)
        assert decoded.undecoded_bits == 0x0003


def test_symbolic_link_all_access_is_the_constant_and_not_a_tidied_version():
    """`SYMBOLIC_LINK_ALL_ACCESS` is
    `STANDARD_RIGHTS_REQUIRED | SYMBOLIC_LINK_QUERY` and predates
    `SYMBOLIC_LINK_SET`, which was never folded into it. `AllAccess · Set`
    is therefore the honest decomposition of 0x000f0003: widening the
    alias would claim `AllAccess` for a mask that is not that constant,
    and would swallow the `Set` bit on the way."""
    decoded = decode_access_mask(0x000F0003, "SymbolicLink")
    assert format_access_rights(decoded) == "AllAccess · Set"
    assert decoded.undecoded_bits == 0
    # The constant itself still reads as exactly the constant.
    assert format_access_rights(decode_access_mask(0x000F0001, "SymbolicLink")) == "AllAccess"

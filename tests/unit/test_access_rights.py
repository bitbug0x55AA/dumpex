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
import re

import pytest

from dumpex.ui.access_rights import (
    DecodedAccess, NO_RIGHTS_TEXT, SUPPORTED_OBJECT_TYPES,
    decode_access_mask, format_access_rights, wrap_rights,
    _GENERIC_RIGHTS, _STANDARD_RIGHTS, _TYPE_REGISTRY,
)


_STANDARD_BY_NAME = {name: bit for bit, name in _STANDARD_RIGHTS + _GENERIC_RIGHTS}

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
    return ({name: bit for bit, name in specific}
            | {name: value for value, name in aliases}
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
    for bit, name in specific:
        assert 0 < bit <= 0x0000FFFF, f"{type_name}: {name} is outside the specific range"
        assert bit & (bit - 1) == 0, f"{type_name}: {name} is not a single bit"
        assert bit not in seen, f"{type_name}: bit {bit:#x} is listed twice"
        seen.add(bit)


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
def test_specific_rights_are_listed_in_ascending_bit_order(type_name):
    """Canonical output order is the table's order, so the table itself
    is what freezes it."""
    specific, _aliases = _TYPE_REGISTRY[type_name]
    assert [bit for bit, _ in specific] == sorted(bit for bit, _ in specific)


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
def test_no_name_collides_with_a_type_independent_right(type_name):
    """A per-type name equal to `Synchronize` or `GenericRead` would make
    one displayed name mean two different bits depending on the row's
    type -- the exact confusion this decoder exists to remove."""
    specific, aliases = _TYPE_REGISTRY[type_name]
    for _bit, name in specific:
        assert name not in _STANDARD_BY_NAME, f"{type_name}: {name} shadows a standard right"
    for _value, name in aliases:
        assert name not in _STANDARD_BY_NAME, f"{type_name}: {name} shadows a standard right"


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
def test_names_never_contain_the_separator_they_are_joined_with(type_name):
    specific, aliases = _TYPE_REGISTRY[type_name]
    for _value, name in specific + aliases:
        assert name and "|" not in name and " " not in name


@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
def test_every_alias_is_a_composite_of_more_than_one_bit(type_name):
    """A single-bit "alias" would just be a second name for a right the
    specific table already carries."""
    _specific, aliases = _TYPE_REGISTRY[type_name]
    for value, name in aliases:
        assert bin(value).count("1") > 1, f"{type_name}: {name} aliases one bit"


# ── The two decode invariants ───────────────────────────────────────────

@pytest.mark.parametrize("type_name", sorted(_TYPE_REGISTRY))
@pytest.mark.parametrize("mask", _MASKS)
def test_a_decode_accounts_for_every_bit_exactly_once(type_name, mask):
    """The whole evidence claim in one assertion: the names plus the
    residual reconstruct the captured mask exactly, and no bit is claimed
    by two names. A decode that invented a right, dropped one, or
    double-reported an alias and its components fails here."""
    decoded = decode_access_mask(mask, type_name)
    bits = _bits_for(type_name)

    claimed = 0
    for name in decoded.names:
        value = bits[name]
        assert value & mask == value, f"{name} claims bits not in {mask:#010x}"
        assert claimed & value == 0, f"{name} re-reports bits another name already claimed"
        claimed |= value

    assert claimed & decoded.undecoded_bits == 0
    assert claimed | decoded.undecoded_bits == mask
    assert len(set(decoded.names)) == len(decoded.names)


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
    # KEY_READ.
    assert (format_access_rights(decode_access_mask(0x00020019, "Key"))
            == "QueryValue | EnumerateSubKeys | Notify | ReadControl")
    # Cross-process memory read on a Process handle.
    assert (format_access_rights(decode_access_mask(0x00000438, "Process"))
            == "VmOperation | VmRead | VmWrite | QueryInformation")
    # A remote thread context write.
    assert (format_access_rights(decode_access_mask(0x0000001A, "Thread"))
            == "SuspendResume | GetContext | SetContext")
    # A station handle -- the reason the registry is not #102's list
    # verbatim (WINSTA_ALL_ACCESS's own bits, spelled out).
    assert (format_access_rights(decode_access_mask(0x00000024, "WindowStation"))
            == "AccessClipboard | AccessGlobalAtoms")
    # ... and a desktop handle that can drive another session's input.
    assert (format_access_rights(decode_access_mask(0x00000102, "Desktop"))
            == "CreateWindow | SwitchDesktop")


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

    printed = re.findall(r"0x[0-9a-f]+", text)
    assert printed == ([f"0x{decoded.undecoded_bits:08x}"] if decoded.undecoded_bits else [])
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
    assert decoded == DecodedAccess(mask=0, type_supported=True, names=(), undecoded_bits=0)
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
    assert format_access_rights(decoded) == "ReadData | UnknownBits(0x00008000)"


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
    text = format_access_rights(decode_access_mask(0x000F037F, "TpWorkerFactory"))
    assert text == ("Delete | ReadControl | WriteDac | WriteOwner | "
                    "TypeSpecificUnavailable(0x0000037f)")
    # ... and a type the registry does carry has no remainder at all.
    assert "Unavailable" not in format_access_rights(
        decode_access_mask(0x000F037F, "WindowStation"))


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
    would overstate what the dump captured."""
    decoded = decode_access_mask(0x001F01FF & ~0x0040, "File")
    assert "AllAccess" not in decoded.names
    assert "DeleteChild" not in decoded.names
    assert "ReadData" in decoded.names


def test_the_mask_is_carried_through_unchanged():
    for mask in _MASKS:
        assert decode_access_mask(mask, "File").mask == mask


def test_decoding_is_deterministic():
    first = decode_access_mask(0x0012019F, "File")
    for _ in range(5):
        assert decode_access_mask(0x0012019F, "File") == first


def test_order_is_specific_then_standard_then_generic():
    """Frozen so a right sits in the same place in every row an analyst
    compares by eye."""
    decoded = decode_access_mask(0x8012019F, "File")
    assert decoded.names == (
        "ReadData", "WriteData", "AppendData", "ReadEa", "WriteEa",
        "ReadAttributes", "WriteAttributes",     # specific, ascending
        "ReadControl", "Synchronize",            # standard, ascending
        "GenericRead")                           # generic, last


# ── Wrapping ────────────────────────────────────────────────────────────

def _rejoin(lines) -> str:
    """The inverse of the wrap: a continued line ends in ` |` and the
    next line carries on from there, so a single space re-joins them."""
    return " ".join(lines)


def test_wrapping_never_splits_a_right_name_and_never_drops_one():
    text = format_access_rights(decode_access_mask(0xFFFFFFFF, "Process"))
    lines = wrap_rights(text, 24)

    assert len(lines) > 1
    assert _rejoin(lines) == text            # nothing added, nothing lost
    for line in lines[:-1]:
        assert line.endswith(" |")           # reads as "continues below"
    # Every line fits, unless it is a single piece that cannot: an
    # over-wide piece overflows rather than being cut in half.
    for line in lines:
        assert len(line) <= 24 or " | " not in line


def test_a_remainder_token_is_never_split_across_two_lines():
    """`TypeSpecificUnavailable(0x0000037f)` broken in half reads as two
    values, and whitespace wrapping would break it."""
    text = format_access_rights(decode_access_mask(0x000F037F, "TpWorkerFactory"))
    lines = wrap_rights(text, 46)

    assert lines == ["Delete | ReadControl | WriteDac | WriteOwner |",
                     "TypeSpecificUnavailable(0x0000037f)"]
    assert _rejoin(lines) == text


def test_a_piece_wider_than_the_wrap_width_overflows_instead_of_truncating():
    lines = wrap_rights("QueryLimitedInformation | Terminate", 8)
    assert lines == ["QueryLimitedInformation |", "Terminate"]


def test_wrapping_a_single_piece_is_one_line():
    assert wrap_rights("AllAccess", 40) == ["AllAccess"]
    assert wrap_rights(NO_RIGHTS_TEXT, 40) == [NO_RIGHTS_TEXT]


@pytest.mark.parametrize("width", [1, 0, -5])
def test_a_degenerate_width_still_returns_every_name(width):
    text = "ReadData | WriteData | Synchronize"
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
    `SYMBOLIC_LINK_SET`, which was never folded into it. `AllAccess|Set`
    is therefore the honest decomposition of 0x000f0003: widening the
    alias would claim `AllAccess` for a mask that is not that constant,
    and would swallow the `Set` bit on the way."""
    decoded = decode_access_mask(0x000F0003, "SymbolicLink")
    assert format_access_rights(decoded) == "AllAccess | Set"
    assert decoded.undecoded_bits == 0
    # The constant itself still reads as exactly the constant.
    assert format_access_rights(decode_access_mask(0x000F0001, "SymbolicLink")) == "AllAccess"

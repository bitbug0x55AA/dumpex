"""Structure and consistency checks for the PE image profile contract.

The document is explanatory input for humans; behavior lives in production
code. These checks keep the frozen vocabulary, the offset tables, the
directory table, and the "available now" field list bound to the shipped
parser, so the contract cannot drift away from what `dumpex.core.pe_utils`
actually produces. Where the contract defines a rule no shipped code
implements yet, the rule is pinned by evaluating it as one function over
the document's own worked examples, so two rules that contradict each
other cannot both survive.
"""
from itertools import product
from pathlib import Path
import re
import struct

import pytest

from tests.fixtures.fakes import build_pe_header, TEXT_SECTION_RX

from dumpex.core.pe_utils import (
    parse_pe_header, _KNOWN_MACHINES, _MAX_SECTIONS,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_IAT,
    IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    MAX_IAT_DLLS, MAX_IAT_ENTRIES_PER_DLL, MAX_IAT_TOTAL_ENTRIES,
    MAX_IAT_NAME_LENGTH, MAX_IAT_BYTES_READ, MAX_IAT_READ_OPERATIONS,
)
from dumpex.core import va_range
from dumpex.commands.process import _classify_main_image_state
from dumpex.core.process_info import MAIN_IMAGE_PE_READ_MAX, MainImagePeFacts
from dumpex.hunt.encoding.models import PeHeaderInfo as EncodingPeHeaderInfo
from dumpex.hunt.injection.models import PeHeaderInfo as InjectionPeHeaderInfo
from dumpex.hunt.injection.config import PE_VALIDATE_READ_MAX as INJECTION_READ_MAX
from dumpex.hunt.stomping.config import PE_VALIDATE_READ_MAX as STOMPING_READ_MAX


_DOC_PATH = Path(__file__).parents[2] / "docs" / "developer" / \
    "pe_image_profile_contract.md"


@pytest.fixture(scope="module")
def doc() -> str:
    return _DOC_PATH.read_text(encoding="utf-8")


def _section(doc: str, start: str, end: str) -> str:
    """The document between two anchors, both of which must be there.

    A missing anchor is a failure, never a wider slice: an `end` that the
    document no longer contains would otherwise return everything after
    `start`, and every `in` assertion against that slice would keep
    passing while pinning nothing.
    """
    assert start in doc, f"section start anchor is gone: {start!r}"
    rest = doc.split(start, 1)[1]
    assert end in rest, f"section end anchor is gone after {start!r}: {end!r}"
    return rest.split(end, 1)[0]


def test_the_document_is_text():
    """`PE\\0\\0` and similar escapes are prose, not bytes. A real control
    character makes the file binary to grep, unreviewable in a diff, and
    liable to be dropped by whatever writes it next."""
    raw = _DOC_PATH.read_bytes()

    control = {byte for byte in raw if byte < 0x20} - {0x09, 0x0a, 0x0d}
    assert not control, sorted(hex(byte) for byte in control)

    text = raw.decode("utf-8")
    assert "PE\\0\\0" in text, "the signature constant is spelled as prose"


def test_a_stale_section_anchor_fails_instead_of_widening():
    """Every prose check in this module slices the document between two
    anchors. A stale anchor that silently widened the slice would leave
    each `in` assertion passing against text it was never aimed at, so
    the whole module would report green while pinning nothing."""
    doc = "alpha ONE beta TWO gamma"

    assert _section(doc, "ONE", "TWO") == " beta "

    with pytest.raises(AssertionError, match="section start anchor is gone"):
        _section(doc, "MISSING", "TWO")
    with pytest.raises(AssertionError, match="section end anchor is gone"):
        _section(doc, "ONE", "MISSING")
    # An `end` that appears only before `start` is behind the slice, not
    # in it, and is stale in exactly the same way.
    with pytest.raises(AssertionError, match="section end anchor is gone"):
        _section(doc, "TWO", "ONE")


def _source_kinds(doc: str) -> set:
    """§2.1's four `source_kind` values, from its own field table."""
    row = _section(doc, "### 2.1 Source identity", "#### 2.1.1")
    kinds = set(re.findall(r'`"([a-z_]+)"`', row))
    assert len(kinds) == 4, kinds
    return kinds


def _flat(text: str) -> str:
    """`text` with blockquote markers dropped and its line wrapping
    collapsed, so a prose assertion pins the sentence rather than the
    column the sentence happens to wrap at."""
    return re.sub(r"\s+", " ", re.sub(r"(?m)^\s*>\s?", "", text))


def _cells(row: str) -> list:
    """The cells of one Markdown table row, outer pipes stripped."""
    return [cell.strip() for cell in row.strip().strip("|").split("|")]


def _rows(section: str) -> list:
    """Every table BODY row in `section`.

    A rule row (`|---|---|`) discards the row above it, which is that
    table's header; everything else is body.
    """
    rows = []
    for line in section.splitlines():
        line = line.strip()          # a table nested in a list is indented
        if not line.startswith("|"):
            continue
        if re.fullmatch(r"\|[\s:|-]+\|", line):
            if rows:
                rows.pop()
            continue
        rows.append(_cells(line))
    return rows


# ── §1.2: the component-state vocabulary is closed ──────────────────────

_STATE_ROW_RE = re.compile(r"^\| `([a-z_]+)` \|", re.MULTILINE)

COMPONENT_STATES = ("complete", "partial", "unavailable", "malformed",
                    "declared_absent")

# A state cell is a whole cell holding one backticked token, in a column
# whose header names a state. Extraction is by POSITION, never by matching
# the known states -- an invented `truncated` or `missing` has to be
# caught, not silently skipped.
_STATE_CELL_RE = re.compile(r"^`([a-z][a-z_]*)`$")


def test_component_state_vocabulary_is_closed(doc):
    section = _section(doc, "Every component carries exactly one state",
                       "Three rules bind")
    assert tuple(_STATE_ROW_RE.findall(section)) == COMPONENT_STATES


def _state_tokens(text: str) -> set:
    """Every single-token cell sitting under a state-named column."""
    tokens = set()
    lines = [line.strip() for line in text.splitlines()
             if line.strip().startswith("|")]
    header = None
    for index, line in enumerate(lines):
        if re.fullmatch(r"\|[\s:|-]+\|", line.strip()):
            header = _cells(lines[index - 1]) if index else None
            continue
        if header is None:
            continue
        columns = [position for position, name in enumerate(header)
                   if "state" in name.lower()]
        for position in columns:
            cells = _cells(line)
            if position < len(cells):
                match = _STATE_CELL_RE.match(cells[position])
                if match:
                    tokens.add(match.group(1))
    return tokens


def test_every_state_valued_table_cell_uses_the_closed_vocabulary(doc):
    section = _section(doc, "## §4 Data directories", "## §7 Cache identity")
    used = _state_tokens(section)

    assert used == set(COMPONENT_STATES), used ^ set(COMPONENT_STATES)


def test_the_state_extraction_rejects_an_out_of_vocabulary_state():
    """The check above must be able to fail; a filter that only matched
    known states would pass silently over an invented one."""
    doctored = ("| Condition | State |\n|---|---|\n"
                "| something | `truncated` |\n")

    assert _state_tokens(doctored) == {"truncated"}


def test_the_state_extraction_ignores_columns_that_are_not_states():
    """Component NAMES are backticked single tokens too; only a
    state-named column may contribute."""
    doctored = ("| Stage | In-scope components |\n|---|---|\n"
                "| 0 | `dos_header` |\n")

    assert _state_tokens(doctored) == set()


# ── §1.5: the frozen-constant table matches shipped values ──────────────

_CONSTANT_ROW_RE = re.compile(r"^\| `([A-Z_][A-Za-z0-9_]*)` \| `(\d+)` \|",
                              re.MULTILINE)

_SHIPPED_CONSTANTS = {
    "MAIN_IMAGE_PE_READ_MAX": MAIN_IMAGE_PE_READ_MAX,
    "_MAX_SECTIONS": _MAX_SECTIONS,
    "MAX_IAT_DLLS": MAX_IAT_DLLS,
    "MAX_IAT_ENTRIES_PER_DLL": MAX_IAT_ENTRIES_PER_DLL,
    "MAX_IAT_TOTAL_ENTRIES": MAX_IAT_TOTAL_ENTRIES,
    "MAX_IAT_NAME_LENGTH": MAX_IAT_NAME_LENGTH,
    "MAX_IAT_BYTES_READ": MAX_IAT_BYTES_READ,
    "MAX_IAT_READ_OPERATIONS": MAX_IAT_READ_OPERATIONS,
}


@pytest.fixture(scope="module")
def documented_constants(doc) -> dict:
    section = _section(doc, "### 1.5 Frozen constants", "The two cumulative")
    rows = _CONSTANT_ROW_RE.findall(section)
    values = {name: int(value) for name, value in rows}
    assert len(values) == len(rows)
    return values


def test_documented_constants_match_shipped_values(documented_constants):
    for name, shipped in _SHIPPED_CONSTANTS.items():
        assert documented_constants[name] == shipped, name


def test_the_one_header_read_budget_is_the_same_everywhere(documented_constants):
    assert MAIN_IMAGE_PE_READ_MAX == INJECTION_READ_MAX == STOMPING_READ_MAX
    assert documented_constants["PE_VALIDATE_READ_MAX"] == STOMPING_READ_MAX


def _with_e_lfanew(value: int) -> bytes:
    """A structurally valid PE whose DOS header declares `value`, with the
    real header left where `build_pe_header()` put it."""
    header = bytearray(build_pe_header([TEXT_SECTION_RX]))
    struct.pack_into("<I", header, 0x3C, value)
    return bytes(header)


def test_documented_e_lfanew_budget_is_the_parsers_own_bound(documented_constants):
    """Bound from both sides: one past the documented limit is a range
    rejection, and the limit itself is not. A one-sided check stays green
    if the parser tightens its bound below the documented value."""
    limit = documented_constants["MAX_E_LFANEW"]

    # `insufficient_data` is what separates the two rejections: the parser
    # spells both with the same free-text reason.
    over = parse_pe_header(_with_e_lfanew(limit + 1))
    assert over["valid"] is False
    assert over["insufficient_data"] is False      # a deterministic rejection

    at_limit = parse_pe_header(_with_e_lfanew(limit))
    assert at_limit["valid"] is False
    assert at_limit["insufficient_data"] is True   # accepted, then out of bytes

    below_minimum = parse_pe_header(_with_e_lfanew(3))
    assert below_minimum["insufficient_data"] is False


def test_only_the_lower_e_lfanew_bound_is_documented_as_structural(doc):
    """The upper bound is dumpex's acquisition budget: a DOS stub may be
    arbitrarily long, so exceeding it is a bounded stop, not a defect."""
    section = _section(doc, "- `e_lfanew` must satisfy", "- `NumberOfSections`")

    assert "`e_lfanew >= 4`" in _flat(section)
    assert "There is **no** structural upper bound" in _flat(section)
    assert "is a bounded stop (§6.2)" in _flat(section)
    assert "malformed" in _flat(section).split("There is **no**")[0]


def test_an_over_budget_e_lfanew_yields_the_states_section_six_two_gives(
        doc, stage_components):
    """`e_lfanew` lives inside `dos_header`, which stage 0 read in full,
    so the stop lands before `coff_header`'s first byte -- §6.2's second
    row, not its first."""
    section = _flat(_section(doc, "- `e_lfanew` must satisfy",
                             "- `NumberOfSections`"))

    assert "`dos_header` stays `complete`" in section
    assert "every later component is `unavailable`" in section
    assert "the profile folds to `unavailable`" in section
    assert "must never produce is `malformed`" in section

    later = len(stage_components[3]) - 1
    assert _profile_state(["complete"] + ["unavailable"] * later) == "unavailable"


def test_the_state_bridge_agrees_about_the_over_budget_case(doc):
    """§11.6 must not still say `partial` for the case §2.6 now resolves
    to `unavailable`."""
    section = _flat(_section(doc, "One case diverges", "The\n`PROCESS_MAIN_IMAGE"))

    assert "the profile folds to `unavailable`" in section
    assert "neither answers `partial`" in section


def test_the_budget_constants_are_labelled_as_budgets(doc):
    section = _section(doc, "Neither is a format maximum",
                       "These constants are **four different kinds** of limit")

    assert "fixes neither" in _flat(section)
    assert "Reaching either is never evidence about the image" in _flat(section)

_OPT_SIZE_PE32_PLUS = 240      # 112 + 16 * 8: the array ends the header
_OPT_OFFSET = 0x80 + 4 + 20    # build_pe_header()'s e_lfanew, signature, COFF


def _with_directory_count(count: int, *, entries: int = 16) -> bytes:
    """A PE32+ image declaring `count` directories with `entries`
    descriptor slots captured.

    Built here rather than by patching `build_pe_header()`, whose 224-byte
    optional header is too short to hold a PE32+ directory array: writing
    one into it would overwrite the section table and make the truncation
    under test ambiguous.
    """
    opt = bytearray(_OPT_SIZE_PE32_PLUS)
    struct.pack_into("<H", opt, 0, 0x20b)
    struct.pack_into("<I", opt, 16, 0x1000)              # entry point
    struct.pack_into("<Q", opt, 24, 0x140000000)         # ImageBase
    struct.pack_into("<I", opt, 56, 0x5000)              # SizeOfImage
    struct.pack_into("<I", opt, 108, count)
    for index in range(min(entries, 16)):
        struct.pack_into("<II", opt, 112 + index * 8, 0x1000 + index, 0x40)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    section = bytearray(40)
    section[0:8] = b".text".ljust(8, b"\x00")
    struct.pack_into("<IIII", section, 8, 0x2000, 0x1000, 0x2000, 0x400)
    struct.pack_into("<I", section, 36, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)

    data = (bytes(dos) + b"PE\x00\x00"
            + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0,
                          _OPT_SIZE_PE32_PLUS, 0x0102)
            + bytes(opt) + bytes(section))
    if entries < 16:
        return data[:_OPT_OFFSET + 112 + entries * 8]
    return data


def test_documented_directory_cap_is_the_parsers_own_cap(documented_constants):
    cap = documented_constants["MAX_DIRECTORY_COUNT"]
    result = parse_pe_header(_with_directory_count(cap * 2))

    assert result["declared_directory_count"] == cap
    assert len(result["data_directories"]) == cap


# ── §2.4: the PE32/PE32+ offsets, bound by planting values at them ──────

_WIDTH_ROW_RE = re.compile(r"^\| (.+?) \| `([^`]+)` \| `([^`]+)` \|$",
                           re.MULTILINE)


@pytest.fixture(scope="module")
def width_table(doc) -> dict:
    section = _section(doc, "### 2.4 Pointer width", "RVAs, directory `Size`")
    table = {label: (pe32, pe32_plus)
             for label, pe32, pe32_plus in _WIDTH_ROW_RE.findall(section)}
    assert len(table) == 6
    return table


def test_documented_ordinal_flags_match_the_shipped_constants(width_table):
    pe32, pe32_plus = width_table["Ordinal flag"]

    assert int(pe32, 16) == IMAGE_ORDINAL_FLAG32
    assert int(pe32_plus, 16) == IMAGE_ORDINAL_FLAG64


def _offset(width_table, label: str, pe32_plus: bool) -> int:
    cell = width_table[label][1 if pe32_plus else 0]
    assert cell.startswith("+")
    return int(cell[1:])


def _build_at_documented_offsets(width_table, *, pe32_plus: bool,
                                 image_base: int, directory_count: int,
                                 first_directory: tuple) -> bytes:
    """A minimal PE whose ImageBase, NumberOfRvaAndSizes and directory
    array are written at the offsets §2.4 declares -- so a wrong offset in
    the document shows up as the parser reading back a different value."""
    base_width = int(width_table["`ImageBase` width in bytes"][1 if pe32_plus else 0])
    base_off = _offset(width_table, "`ImageBase` offset", pe32_plus)
    count_off = _offset(width_table, "`NumberOfRvaAndSizes` offset", pe32_plus)
    array_off = _offset(width_table, "Directory array offset", pe32_plus)

    opt_size = array_off + 16 * 8
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20b if pe32_plus else 0x10b)
    struct.pack_into("<I", opt, 16, 0x1000)                      # entry point
    struct.pack_into("<Q" if base_width == 8 else "<I", opt, base_off, image_base)
    struct.pack_into("<I", opt, 56, 0x5000)                      # SizeOfImage
    struct.pack_into("<I", opt, count_off, directory_count)
    struct.pack_into("<II", opt, array_off, *first_directory)

    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    section = bytearray(40)
    section[0:8] = b".text".ljust(8, b"\x00")
    struct.pack_into("<IIII", section, 8, 0x2000, 0x1000, 0x2000, 0x400)
    struct.pack_into("<I", section, 36, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)

    return (bytes(dos) + b"PE\x00\x00"
            + struct.pack("<HHIIIHH", 0x8664 if pe32_plus else 0x014c,
                          1, 0, 0, 0, opt_size, 0x0102)
            + bytes(opt) + bytes(section))


@pytest.mark.parametrize("pe32_plus", [False, True], ids=["pe32", "pe32_plus"])
def test_documented_optional_header_offsets_are_where_the_parser_reads(
        width_table, pe32_plus):
    image_base = 0x140000000 if pe32_plus else 0x10000000
    data = _build_at_documented_offsets(
        width_table, pe32_plus=pe32_plus, image_base=image_base,
        directory_count=16, first_directory=(0xABC000, 0x40))
    result = parse_pe_header(data)

    assert result["valid"] is True
    assert result["is_pe32_plus"] is pe32_plus
    assert result["image_base"] == image_base
    assert result["declared_directory_count"] == 16
    assert result["data_directories"][0] == (0xABC000, 0x40)


def test_the_two_formats_do_not_share_their_offsets(width_table):
    """A document that collapsed the PE32/PE32+ split would still satisfy
    the round-trips above; the split itself is the invariant."""
    for label in ("`ImageBase` offset", "`NumberOfRvaAndSizes` offset",
                  "Directory array offset"):
        assert _offset(width_table, label, False) != _offset(width_table, label, True)


# ── §3: the address-meaning vocabulary is closed and used ───────────────

_KIND_ROW_RE = re.compile(r"^\| `([A-Za-z/ ]+)` \|", re.MULTILINE)


@pytest.fixture(scope="module")
def address_kinds(doc) -> set:
    section = _section(doc, "Address meaning is one of exactly five kinds",
                       "### 3.1 DOS header")
    kinds = set(_KIND_ROW_RE.findall(section))
    assert len(kinds) == 5
    return kinds


def _kind_of(row: list) -> str:
    """A field row's address kind, with an explanatory tail dropped:
    `n/a (byte length)` and `VA, preferred only` name the kinds `n/a` and
    `VA`."""
    return row[3].split(" (")[0].split(",")[0].strip()


def test_every_field_matrix_row_uses_a_declared_address_kind(doc, address_kinds):
    section = _section(doc, "### 3.1 DOS header",
                       "### 3.5 Relocation context")
    used = {_kind_of(row) for row in _rows(section) if len(row) == 5}

    assert used, "no field rows found -- the extraction broke"
    assert used <= address_kinds, used - address_kinds


def test_e_lfanew_is_the_only_mapping_offset(doc):
    section = _section(doc, "### 3.1 DOS header",
                       "### 3.5 Relocation context")
    mapping = [row[0] for row in _rows(section)
               if len(row) == 5 and _kind_of(row) == "mapping offset"]

    assert mapping == ["`e_lfanew`"]


def test_the_pe_signature_belongs_to_a_named_component(doc):
    """Four bytes with no component would leave three questions with no
    answer: which component is `partial`, whether `coff_header` has read
    any bytes, and what the rollup gets."""
    span = _flat(_section(doc, "### 3.2 COFF file header",
                          "| Field | Offset |"))
    assert "**24 bytes at `e_lfanew`**" in span
    assert "then the twenty COFF bytes at `e_lfanew + 4`" in span
    assert "relative to `e_lfanew + 4`" in span

    rows = {row[0]: (row[1], row[2]) for row in _rows(
        _section(doc, "| The signature's four bytes | `coff_header` |",
                 "Row 3 is a **determined defect**"))}
    assert len(rows) == 4
    assert rows["None was read"] == ("`unavailable`", "`null`")
    assert rows["Read in part"][0].startswith("`partial`")
    assert rows["Read in part"][1] == "`null`"
    assert rows["Read in full, not `PE\\0\\0`"] == ("`malformed`", "`false`")
    assert rows["Read in full, `PE\\0\\0`"][1] == "`true`"

    # A wrong constant is a single-field impossibility, on the same terms
    # as `NumberOfSections` -- the registry must stay at two entries.
    closure = _flat(_section(doc, "Row 3 is a **determined defect**",
                             "It belongs to this component"))
    assert "the four bytes it rests on were all read" in closure
    assert "no PE image carries anything else there" in closure
    assert "decided at §5.3's step 3" in closure
    assert "ahead of any gap in the twenty bytes that follow" in closure


def test_the_signatures_component_choice_is_argued_from_the_stages(doc):
    section = _flat(_section(doc, "It belongs to this component rather than",
                             "`Machine` is retained as the raw"))

    assert "would add a member to §5.4.1's set at every stage" in section
    assert "change every count in §5.4.3" in section
    assert "exactly the signature plus the COFF header" in section
    assert "can never have different byte provenance" in section
    assert "`dos_header` is not the alternative" in section

    # §6.1's stage 1 really does read the component's own 24 bytes.
    stage_one, = [row for row in _rows(_section(
        doc, "| Stage | Reads | Yields | Enough for |", "The `Reads` column"))
        if row[0] == "1"]
    assert stage_one[1] == "through `e_lfanew + 24`"
    assert "coff_header" in stage_one[2]


# ── §3.2: naming a Machine value is projection scope, not validation ────

_MACHINE_RE = re.compile(r"`([A-Z0-9]+)` `(0x[0-9a-f]{4})`")

# Defined `IMAGE_FILE_MACHINE_*` values outside the set §3.2 names. A PE
# image may carry any of them, so none may reach `malformed`.
_UNNAMED_MACHINES = {
    0x0166: "R4000", 0x01c2: "THUMB", 0x01f0: "POWERPC",
    0x9041: "M32R", 0xc0ee: "CEE",
}


def test_the_named_machine_values_are_the_shipped_map(doc):
    """The names dumpex can supply today. This is a coverage fact about
    the projection, not the set of values a PE image may carry -- which
    is what the next test pins."""
    section = _section(doc, "`machine_name` is the frozen name for",
                       "**An unnamed `Machine` value is not `malformed`.**")
    documented = {int(value, 16): name for name, value in _MACHINE_RE.findall(section)}

    assert documented == _KNOWN_MACHINES
    assert not set(_UNNAMED_MACHINES) & set(_KNOWN_MACHINES)


def test_an_unnamed_machine_value_is_not_malformed(doc):
    """§1.2's `malformed` needs the decoded bytes to be structurally
    impossible. Absence from a name table is a limit of this contract,
    so it may not decide a component state."""
    rule = _flat(_section(doc, "**An unnamed `Machine` value is not",
                          "That list is **projection scope**"))

    assert "The raw value is reported, `machine_name` is `null`" in rule
    assert "`coff_header`'s state is decided by §5.3" in rule

    reasoning = _flat(_section(doc, "That list is **projection scope**",
                               "**This contract names no `Machine` value"))
    assert "not the set the PE format permits" in reasoning
    assert "§4.5's distinction applied to a different field" in reasoning
    assert "An unnamed machine value contradicts nothing" in reasoning
    assert "every machine type added after this contract was frozen" in reasoning
    assert "A parser's coverage would have been promoted to the format's " \
           "legal set" in reasoning

    # The document must name real values it declines to call malformed,
    # or the rule is untestable against anything.
    named = {int(value, 16) for _name, value in _MACHINE_RE.findall(reasoning)}
    assert set(_UNNAMED_MACHINES) <= named


def test_no_machine_value_is_declared_impossible(doc):
    """If a value ever is forbidden, it needs a format citation on
    §5.3.1's terms -- not an absence from the table above."""
    closing = _flat(_section(doc, "**This contract names no `Machine` value",
                             "`NumberOfSections` is the one COFF field"))

    assert "that a PE image may not carry" in closing
    assert "cites the format rule that forbids it" in closing
    assert "not an absence from the table above" in closing


def test_the_one_constrained_coff_field_cites_the_format(doc):
    """Dropping the `Machine` rule leaves §3.2 needing to say which COFF
    defect does reach `malformed`, or §3.5.1's rule 1 has no example and
    the component has no route to that state at all."""
    section = _flat(_section(doc, "`NumberOfSections` is the one COFF field",
                             "### 3.3 Optional header"))

    assert "outside `1..96` is one no image can carry" in section
    assert "`coff_header` is `malformed`" in section
    assert "this is the registry's second entry and §5.3's step 3 decides it" \
        in section
    assert "is `malformed`, not `partial`" in section
    assert "this constraint cites the format, while a missing name cites " \
           "only dumpex" in section

    # §1.5 already classifies the bound this cites, and it is the shipped
    # cap -- so the range in the prose is not a second, drifting number.
    assert _MAX_SECTIONS == 96
    kinds = _flat(_section(doc, "| Kind | Constants | Reaching it produces |",
                           "`_MAX_SECTIONS` belongs in the third row"))
    assert "**Structural constraint**" in kinds and "`_MAX_SECTIONS`" in kinds


def test_the_shipped_parser_still_rejects_an_unnamed_machine():
    """§11.7's divergence, executed: today's parser stops, and spells the
    stop as a deterministic rejection -- which §11.6 maps to
    `pe_invalid`. A consumer must not read that as the canonical state,
    which §3.2 leaves to the component's own bytes."""
    for value in _UNNAMED_MACHINES:
        data = bytearray(build_pe_header([TEXT_SECTION_RX]))
        struct.pack_into("<H", data, 0x80 + 4, value)
        result = parse_pe_header(bytes(data))

        assert result["machine"] == value
        assert result["machine_name"] is None
        assert result["valid"] is False
        assert result["insufficient_data"] is False
        assert "Machine" in result["reason"]


def test_the_divergence_is_named_as_new_work(doc):
    section = _flat(_section(doc, "### 11.7 Behaviour bridge",
                             "## §12 Compatibility"))

    assert "Aligning the shipped parser is new work" in section
    assert "must not promote this rejection to a canonical `malformed`" in section
    assert "a limit of dumpex's projection rather than a fact about the image" \
        in section
    assert "second named divergence" in section

    rows = {row[0]: row[1] for row in _rows(
        _section(doc, "| Today | Canonical |", "Until that work lands"))}
    assert any("`valid: False`" in today for today in rows)
    assert any("`unavailable`" in canonical for canonical in rows.values())


# ── §3.4: the decoded section characteristics are the shipped flags ─────

_FLAG_RE = re.compile(r"`(IMAGE_SCN_MEM_[A-Z]+)` `(0x[0-9a-f]+)`")


def test_section_characteristic_flags_match_the_shipped_constants(doc):
    section = _section(doc, "`is_executable`, `is_writable`", "so\nno consumer")
    documented = {name: int(value, 16) for name, value in _FLAG_RE.findall(section)}
    assert documented == {
        "IMAGE_SCN_MEM_EXECUTE": IMAGE_SCN_MEM_EXECUTE,
        "IMAGE_SCN_MEM_WRITE": IMAGE_SCN_MEM_WRITE,
        "IMAGE_SCN_MEM_READ": IMAGE_SCN_MEM_READ,
    }


# ── §4.2: all sixteen directory indices, exactly once each ──────────────

_DIRECTORY_ROW_RE = re.compile(
    r"^\| (\d+) \| `([A-Z_]+)` \| `(rva|file_offset)` \|", re.MULTILINE)


@pytest.fixture(scope="module")
def directory_rows(doc):
    section = _section(doc, "### 4.2 The sixteen indices", "Index 1 and index 12")
    return _DIRECTORY_ROW_RE.findall(section)


def test_every_directory_index_appears_exactly_once(directory_rows):
    indices = [int(index) for index, _name, _kind in directory_rows]
    assert indices == list(range(16))
    names = [name for _index, name, _kind in directory_rows]
    assert len(set(names)) == 16


def test_named_directory_indices_match_the_shipped_constants(directory_rows):
    by_name = {name: int(index) for index, name, _kind in directory_rows}
    assert by_name["IMPORT"] == IMAGE_DIRECTORY_ENTRY_IMPORT
    assert by_name["IAT"] == IMAGE_DIRECTORY_ENTRY_IAT
    assert by_name["BASERELOC"] == IMAGE_DIRECTORY_ENTRY_BASERELOC
    assert IMAGE_DIRECTORY_ENTRY_IMPORT != IMAGE_DIRECTORY_ENTRY_IAT


def test_the_security_directory_unreadability_is_scoped_by_source(doc):
    """Certificate bytes are unreachable from a memory mapping, but a
    `disk_reference` profile has the file open -- there the omission is a
    scope decision, not an impossibility."""
    section = _section(doc, "raised differs by source", "4. No field naming")
    reasons = {row[0]: row[1] for row in _rows(section)}

    assert "Not reachable at all" in reasons["Memory-sourced"]
    assert "Reachable" in reasons["`disk_reference`"]
    assert "does not parse directory contents (§0.2)" in reasons["`disk_reference`"]

    flat = _flat(section)
    assert "none could parse it from a memory-sourced one" in flat
    assert "would freeze an impossibility where only a scope decision exists" \
        in flat


def test_the_security_descriptor_state_follows_the_general_rule(doc):
    """Index 4 is not exempt from §4.3, owner-first rule included: the
    count can deny it before any of its own eight bytes are read. What
    stays true is that the certificate content never moves the state."""
    section = _flat(_section(doc, "3. Index 4's state is",
                             "| Source | The certificate bytes are |"))

    assert "decided by §4.3 in full, exactly like every other descriptor"         in section
    assert "the owner-first rule included" in section
    assert "makes index 4 `declared_absent` from the count's own bytes" in section
    assert "whether or not its eight bytes were read" in section
    assert "no read of it, and no failure to read it, raises or lowers the "            "descriptor's state" in section

    assert "exactly the state of its own eight descriptor bytes" not in doc

    # §4.3's owner-first rule really does deny index 4 at a count of four.
    assert _descriptor_state(declared=4, index=4, bytes_read=0)         == "declared_absent"
    assert _descriptor_state(declared=5, index=4, bytes_read=0)         == "unavailable"


def test_security_is_the_only_file_offset_directory(directory_rows):
    file_offset = [int(index) for index, _name, kind in directory_rows
                   if kind == "file_offset"]
    assert file_offset == [4]


# ── §4.3: a half-read descriptor is `partial`, never `unavailable` ──────

def _descriptor_state(*, declared, index, bytes_read):
    """§4.3's rows, as one function over per-descriptor byte coverage."""
    if declared is None:
        return "unavailable"
    if index >= declared:
        return "declared_absent"
    if bytes_read == 0:
        return "unavailable"
    if bytes_read < 8:
        return "partial"
    return "complete"      # or `declared_absent` on a zero value


def _component_state_steps(*, denied_by_captured_owner, bytes_read,
                           required_bytes_missing=False, impossible=False):
    """§5.3's five steps, in the order §5.3 gives them."""
    if denied_by_captured_owner:
        return "declared_absent"
    if bytes_read == 0:
        return "unavailable"
    if required_bytes_missing:
        return "partial"
    if impossible:
        return "malformed"
    return "complete"


def _coff_header_state(*, signature_bytes_read, signature_correct,
                       coff_bytes_read, number_of_sections=1):
    """§5.3's steps over §3.2's own component: four signature bytes then
    twenty COFF bytes, with §5.3.1's two `coff_header` defects."""
    if signature_bytes_read == 0:
        return "unavailable"
    if signature_bytes_read == 4 and not signature_correct:
        return "malformed"                      # step 3, registered defect
    if signature_bytes_read < 4:
        return "partial"
    if coff_bytes_read >= 4 and not 1 <= number_of_sections <= _MAX_SECTIONS:
        return "malformed"                      # step 3, the second defect
    if coff_bytes_read < 20:
        return "partial"                        # step 4
    return "complete"


def _dos_header_state(*, bytes_read, mz_correct):
    """§5.3's steps over §3.1's component: `e_magic` at `0x00`, then
    `e_lfanew` ending at `0x40`."""
    if bytes_read == 0:
        return "unavailable"
    if bytes_read >= 2 and not mz_correct:
        return "malformed"                      # step 3, registered defect
    if bytes_read < 0x40:
        return "partial"                        # step 4
    return "complete"


def _optional_header_state_with_magic(*, magic_bytes_read, magic_recognized,
                                      bytes_read, size_of_optional_header,
                                      pe32_plus):
    """§5.3's steps over §3.3's component, with both `optional_header`
    entries of §5.3.1: an unrecognized `Magic` (§2.4), then a declared
    size below the format's fixed portion (§3.3.1.1)."""
    if magic_bytes_read == 0 and bytes_read == 0:
        return "unavailable"
    if magic_bytes_read == 2 and not magic_recognized:
        return "malformed"                      # step 3, §2.4's entry
    if magic_bytes_read == 2 and \
            size_of_optional_header < _FIXED_PORTION_SIZE[pe32_plus]:
        return "malformed"                      # step 3, §3.3.1.1's entry
    if bytes_read < _FIXED_PORTION_SIZE[pe32_plus]:
        return "partial"                        # step 4
    return "complete"


@pytest.mark.parametrize("bytes_read, mz_ok, expected", [
    # The review's DOS pair.
    (2, False, "malformed"),        # bad MZ + short DOS header
    (2, True, "partial"),           # good MZ + short DOS header
    (0x40, False, "malformed"),
    (0x40, True, "complete"),
    (1, False, "partial"),          # the defect's own bytes are not in yet
    (0, False, "unavailable"),
])
def test_a_wrong_mz_is_malformed_however_little_followed_it(bytes_read, mz_ok,
                                                            expected):
    """`e_magic` is a format constant, so §5.3's step 3 decides it before
    the rest of the DOS header is missed at step 4."""
    assert _dos_header_state(bytes_read=bytes_read,
                             mz_correct=mz_ok) == expected


@pytest.mark.parametrize("magic_read, magic_ok, read, declared, expected", [
    # The review's optional-header pair, on PE32+.
    (2, False, 2, 240, "malformed"),      # bad Magic + missing tail
    (2, True, 2, 240, "partial"),         # good Magic + missing tail
    (2, False, 240, 240, "malformed"),
    (2, True, 240, 240, "complete"),
    (0, False, 0, 240, "unavailable"),
    # §3.3.1.1's entry still fires for a recognized `Magic`.
    (2, True, 2, 40, "malformed"),
])
def test_an_unrecognized_magic_is_malformed_before_the_tail_is_missed(
        magic_read, magic_ok, read, declared, expected):
    assert _optional_header_state_with_magic(
        magic_bytes_read=magic_read, magic_recognized=magic_ok,
        bytes_read=read, size_of_optional_header=declared,
        pe32_plus=True) == expected


def test_the_two_format_constants_are_stated_where_the_fields_are(doc):
    """Each registry entry needs a rule at the field, or the registry is
    the only place the defect exists."""
    dos = _flat(_section(doc, "`e_magic` is a constant the format fixes",
                         "### 3.2 COFF file header"))
    assert "holding anything but `MZ` make `dos_header` **`malformed`**" in dos
    assert "decided at §5.3's step 3" in dos
    assert "whether or not the rest of the header through `e_lfanew` arrived" \
        in dos
    assert "Two bytes short of that, nothing about `e_magic` is established" \
        in dos

    magic = _flat(_section(doc, "### 2.4 Pointer width", "It selects, for the"))
    assert "a determined defect (§5.3.1) on `Magic`'s own two bytes" in magic
    assert "does not wait for the rest of the optional header" in magic
    assert "A `Magic` this contract cannot read is a different thing" in magic


def test_a_missing_byte_still_cannot_create_a_malformed(doc):
    """Rule 1 has to keep both halves: uncaptured bytes never support a
    `malformed`, and never soften one already determined."""
    rule = _flat(_section(doc, "1. **Uncaptured bytes never support",
                          "2. **`declared_absent` requires"))

    assert "A component known only through missing bytes is `unavailable` " \
           "or `partial`" in rule
    assert "What a missing byte cannot do is *soften* a defect that was " \
           "already determined" in rule
    assert "A wrong `MZ` is a wrong `MZ` however little followed it" in rule


@pytest.mark.parametrize("sig_read, sig_ok, coff_read, sections, expected", [
    # The review's four combinations, in its order.
    (4, False, 20, 1, "malformed"),     # bad signature + complete COFF
    (4, False, 0, 1, "malformed"),      # bad signature + missing COFF
    (4, True, 0, 1, "partial"),         # good signature + missing COFF
    (4, True, 6, 200, "malformed"),     # bad NumberOfSections + missing tail
    # And the cases that keep step 3 from swallowing step 4.
    (0, False, 0, 1, "unavailable"),    # nothing read at all
    (2, False, 0, 1, "partial"),        # the defect's own bytes are not in
    (4, True, 20, 1, "complete"),
    (4, True, 6, 1, "partial"),         # a plausible count, tail missing
])
def test_a_determined_defect_outranks_a_gap_in_the_same_component(
        sig_read, sig_ok, coff_read, sections, expected):
    """§5.3's step 3 before step 4. The third row is the control: with no
    registered defect, a missing tail is still `partial`. The sixth is
    the other control: a defect whose own bytes are incomplete is not
    determined, so §1.2's rule 3 leaves it a gap."""
    assert _coff_header_state(
        signature_bytes_read=sig_read, signature_correct=sig_ok,
        coff_bytes_read=coff_read, number_of_sections=sections) == expected


def test_the_two_malformed_steps_are_distinguished(doc):
    steps = _flat(_section(doc, "### 5.3 Deriving a component's state",
                           "Three of those orderings are load-bearing"))

    assert "a **determined defect** applies" in steps
    assert "every byte it rests on read in full" in steps
    assert "the component's bytes are all present and decode to an " \
           "impossible value" in steps
    assert "`malformed` appears twice because two different things reach it" \
        in steps
    assert "it fires whether or not other bytes of the component are missing" \
        in steps

    ordering = _flat(_section(doc, "- **Step 3 precedes step 4.**",
                              "§4.3's descriptor table is these steps"))
    assert "bytes missing *elsewhere* in the component neither created it" \
        in ordering
    assert "wrong whether or not the twenty COFF bytes after it arrived" \
        in ordering
    assert "only a defect §5.3.1 has named may be decided on a partial " \
           "component" in ordering


def test_a_malformed_component_still_names_its_unread_bytes(doc):
    """A range is a fact about bytes; `partial` is the state that
    requires one, not the only state that can carry one."""
    section = _flat(_section(doc, "### 5.2 Unexamined ranges",
                             "The range type follows"))

    assert "`partial` is the state that requires a range" in section
    assert "the two are separate facts" in section
    assert "`malformed` under a registered defect (§5.3.1) and still has " \
           "unread bytes names them here too" in section


@pytest.mark.parametrize("declared, index, bytes_read", [
    (0, 0, 0),        # the review case: a captured zero count, nothing read
    (0, 15, 0),
    (3, 5, 0),        # denied by the count, its own bytes never reached
    (3, 5, 8),        # denied by the count, its own bytes present anyway
    (16, 5, 0),       # inside the count and unread -- a gap, not a denial
    (16, 5, 4),
    (16, 5, 8),
    (None, 0, 0),     # no owner captured, so no denial is possible
])
def test_the_descriptor_table_and_the_general_steps_agree(declared, index,
                                                          bytes_read):
    """§4.3 resolves a descriptor and §5.3 resolves any component. The
    same input must not get two answers -- which is what an `unavailable`
    step ahead of the `declared_absent` step would produce for a captured
    `NumberOfRvaAndSizes` of zero."""
    denied = declared is not None and index >= declared

    assert _descriptor_state(declared=declared, index=index,
                             bytes_read=bytes_read) \
        == _component_state_steps(denied_by_captured_owner=denied,
                                  bytes_read=bytes_read,
                                  required_bytes_missing=0 < bytes_read < 8)


def test_a_captured_denial_outranks_the_components_own_bytes(doc):
    section = _flat(_section(doc, "- **Step 1 precedes step 2.**",
                             "- **Step 3 precedes step 4.**"))

    assert "can neither add to that answer nor take it away" in section
    assert "`NumberOfRvaAndSizes = 0` with descriptor 0 unread `unavailable`" \
        in section
    assert "the distinction §1.2's rule 2 exists to keep" in section
    assert "can never fire on a gap" in section

    mapping = _flat(_section(doc, "§4.3's descriptor table is these steps",
                             "#### 5.3.1 Determined defects"))
    assert "`index >= declared` is step 1" in mapping
    assert "The first two conditions are disjoint" in mapping

    # And that disjointness is what makes §4.3's row order irrelevant.
    assert _descriptor_state(declared=None, index=0, bytes_read=0) \
        == "unavailable"
    assert _descriptor_state(declared=0, index=0, bytes_read=0) \
        == "declared_absent"


def test_descriptor_states_are_resolved_from_byte_coverage(doc):
    section = _section(doc, "### 4.3 Descriptor state resolution",
                       "A `partial` descriptor names")
    conditions = [row[0] for row in _rows(section)]

    assert "`bytes_read == 0`" in conditions
    assert "`0 < bytes_read < 8`" in conditions
    assert [row[1] for row in _rows(section)] == [
        "`unavailable`", "`declared_absent`", "`unavailable`", "`partial`",
        "`declared_absent`", "`complete`"]


@pytest.mark.parametrize("bytes_read, expected", [
    (0, "unavailable"), (1, "partial"), (4, "partial"), (7, "partial"),
    (8, "complete"),
])
def test_a_half_read_descriptor_is_partial(bytes_read, expected):
    """A descriptor whose `value` was read and whose `size` was not already
    carries a fact; §5.3 calls that `partial`, and §4.3 must agree."""
    assert _descriptor_state(declared=1, index=0,
                             bytes_read=bytes_read) == expected


# ── §2.1.1: module_identity is a typed value ────────────────────────────

def test_module_identity_has_a_frozen_shape(doc):
    """"The name or the path" is two fields, and §10.3.1's `truncated`
    flag has to live somewhere; both are decisions a bare string leaves
    to each implementer."""
    block = _section(doc, "```text\nmodule_identity: {", "}\n```")

    assert "value:     str | null" in block
    assert 'form:      "path" | "name" | null' in block
    assert "truncated: bool" in block

    rationale = _flat(_section(doc, "`form` says which of the two",
                               "Where `value` comes from"))
    assert "never has to guess from whether it contains a separator" in rationale
    assert "a profile can carry several identities" in rationale


def test_every_source_kind_says_where_its_identity_comes_from(doc):
    section = _section(doc, "Where `value` comes from, per source:",
                       "`value` is `null` and `form` is `null` together")
    documented = {row[0].strip("`") for row in _rows(section)}

    assert documented == _source_kinds(doc)

    forms = {row[0].strip("`"): row[2] for row in _rows(section)}
    assert forms["memory_candidate"] == "`null`"
    assert forms["disk_reference"] == '`"path"`'


def test_absence_has_exactly_one_encoding(doc):
    """A `null` object and an object holding a `null` value would be two
    legal encodings of one fact, which §1.4's canonical-representation
    rule forbids."""
    field_table = _section(doc, "### 2.1 Source identity", "#### 2.1.1")
    identity_row, = [row for row in _rows(field_table)
                     if row[0] == "`module_identity`"]

    assert "Always present as an object" in identity_row[1]
    assert "or `null`" not in identity_row[1]

    section = _flat(_section(doc, "**The object itself is never `null`.**",
                             "### 2.2"))
    assert "absence is `value: null` inside it" in section
    assert "is not the canonical representation §1.4 requires" in section


def test_a_null_value_is_not_an_empty_string(doc):
    section = _flat(_section(doc, "`value` is `null` and `form` is `null`",
                             "### 2.2"))

    assert "`truncated` is `false` whenever `value` is `null`" in section
    assert "different from something naming it `\"\"`" in section


# ── §3.5: relocation facts, derived and never folded ────────────────────

_RELOCATION_FACTS = ("preferred_image_base", "relocation_delta",
                     "relocs_stripped", "dynamic_base",
                     "basereloc_present", "basereloc_descriptor_state")

_ROLLUP_ORDER = ("malformed", "unavailable", "partial", "complete")


def _declaration_excludes(*, offset, width, size_of_optional_header) -> bool:
    """§3.3.1's bound. A field belongs to the optional header only if it
    fits inside the declared size; past it the bytes are section table, so
    no unexamined range can ever name them."""
    return offset + width > size_of_optional_header


def _most_dominant_fold(inputs) -> str:
    """The most dominant state any fold over these facts could return:
    `malformed` when one input is, `unavailable` only when all are,
    `partial` while any gap remains. A fold that cannot change the rollup
    at this strength cannot change it at any lesser one."""
    if "malformed" in inputs:
        return "malformed"
    if all(state == "unavailable" for state in inputs):
        return "unavailable"
    if any(state in ("unavailable", "partial") for state in inputs):
        return "partial"
    return "complete"


def test_the_relocation_context_is_not_a_component(doc):
    """§1.2's states are defined over a component's own bytes. These facts
    hold none, so the component set is the one place a state over them
    could live, and it is where the contract has to say no."""
    note = _flat(_section(doc, "A component holds bytes.",
                          "Every component carries exactly one state"))

    assert "it carries no state, and it is not in this set" in note
    assert "belongs to a component listed above" in note

    heading = _flat(_section(doc, "### 3.5 Relocation context", "#### 3.5.1"))
    assert "not a component" in heading
    assert "carries no state of its own" in heading
    assert "never enters §5.4's rollup" in heading


def test_the_component_table_does_not_list_it(doc, stage_components):
    section = _section(doc, "### 1.2 Component states",
                       "A component holds bytes.")
    declared = {row[0].strip("`") for row in _rows(section)}

    assert "relocation_context" not in declared
    assert declared == set(stage_components[3])


def test_each_fact_names_the_component_that_explains_its_null(doc):
    section = _section(doc, "| Field | Established when |",
                       "Four rules bind this")
    rows = {row[0].strip("`"): row[2] for row in _rows(section)}

    assert set(rows) == set(_RELOCATION_FACTS)
    assert rows["relocs_stripped"] == "`coff_header`"
    assert rows["dynamic_base"] == "`optional_header`"
    # A presence or state that index 5's own bytes can leave `null` must
    # cite the descriptor too: a `complete` array explains neither.
    for field in ("basereloc_present", "basereloc_descriptor_state"):
        assert "`directory_array`" in rows[field], field
        assert "descriptor" in rows[field], field
    assert "`optional_header`" in rows["relocation_delta"]
    assert "§2.1's source" in rows["relocation_delta"]


def test_a_defect_elsewhere_in_the_source_component_erases_nothing(doc):
    """A defect in one COFF field is not a defect of `Characteristics`,
    which sits in the same twenty bytes and decodes on its own."""
    section = _flat(_section(doc, "1. **Each fact is established or `null`",
                             "2. **The component's state is cited"))

    assert "defect elsewhere in the source component erases nothing" in section
    assert "a different field of the same twenty bytes, read in full" in section
    assert "so `relocs_stripped` is established" in section
    assert "§5.4.4 applied one level down" in section

    # The example has to be a real `coff_header` defect. A missing
    # `Machine` name is not one (§3.2), and 200 sections is.
    assert "`NumberOfSections` of `200`" in section
    assert "`Machine`" not in section
    assert 200 > _MAX_SECTIONS


def test_a_source_components_state_is_cited_never_copied(doc):
    section = _flat(_section(doc, "2. **The component's state is cited",
                             "3. **An unread flag is `null`"))

    assert "carry no state of their own to be weakened" in section
    assert "names `optional_header`'s state" in section
    assert "does not restate that state here" in section


def test_an_unread_flag_is_null_never_a_default(doc):
    section = _flat(_section(doc, "3. **An unread flag is `null`",
                             "#### 3.5.2"))

    assert "that flag is `null`" in section
    assert "Treating an unread bit as `false` would manufacture" in section
    assert "compare against a fact nobody established" in section


def test_no_state_in_the_vocabulary_fits_a_fold(doc):
    """The argument has to say what each of the five states would claim
    for these images, not merely assert that none applies."""
    section = _section(doc, "| Image | The facts | What §1.2 offers a fold |",
                       "In the first two rows")
    verdicts = [row[2] for row in _rows(section)]

    assert verdicts[:2] == ["Nothing fits", "Nothing fits"]
    assert verdicts[2].startswith("`complete`, over an image whose array is "
                                  "`malformed`")

    argument = _flat(_section(doc, "In the first two rows", "**And a fold"))
    assert "`partial` needs a byte-precise remainder" in argument
    assert "no unexamined range describes them and none may be invented" \
        in argument
    assert "`unavailable` means nothing was decoded, and something was" \
        in argument
    assert "`complete` is false" in argument
    assert "`malformed` would rest on bytes that were never read" in argument
    assert "A sixth state token invented for these rows" in argument


@pytest.mark.parametrize("size", [40, 1])
def test_the_misreporting_cases_have_no_range_to_name(size):
    """Both rows turn on the same arithmetic: every excluded byte is
    section table (§3.3.1), so no component can carry a range for it, and
    §4.4's first row -- not its `malformed` row -- decides the array."""
    array_offset = _DIRECTORY_ARRAY_OFFSET[True]

    assert _declaration_excludes(offset=70, width=2,
                                 size_of_optional_header=size)
    assert _declaration_excludes(offset=array_offset + 5 * 8, width=8,
                                 size_of_optional_header=size)
    assert _declaration_excludes(offset=array_offset - 4, width=4,
                                 size_of_optional_header=size)
    assert _directory_array_state(
        count_read=False, raw=0, decoded=0, declared=0) == "unavailable"

    # §3.3.1's own reading of the two sizes: one contradicts `Magic`, the
    # other is simply too small to have decoded anything.
    assert _optional_header_state(
        size_of_optional_header=size,
        pe32_plus=True if size >= 2 else None) == (
            "malformed" if size >= 2 else "unavailable")


def test_the_size_one_case_has_no_contradiction_to_rest_on(doc):
    """A `SizeOfOptionalHeader` of `1` is a small declaration, not an
    impossible one, so a `malformed` fold there would rest on nothing --
    and would be a third sub-field contradiction besides."""
    argument = _flat(_section(doc, "In the first two rows", "**And a fold"))

    assert "the second row has no contradiction anywhere to rest on" in argument
    assert "is a small declaration, not an impossible one" in argument
    assert "would also need a §5.3.1 entry" in argument
    assert "the registry could not have one" in argument
    assert "these facts hold none" in argument

    assert _optional_header_state(size_of_optional_header=1,
                                  pe32_plus=None) == "unavailable"


def test_the_registry_admits_no_derived_entry(doc):
    """Every registry entry names bytes of a component that holds them.
    §3.5's derived facts hold none, so no entry could cover them -- which
    is why a `malformed` fold over those facts has no route in."""
    registry = _section(doc, "#### 5.3.1 Determined defects",
                        "Four entries rest on one field each")
    components = {row[0].strip("`") for row in _rows(registry)}

    assert components == {"dos_header", "coff_header", "optional_header",
                          "directory_array"}
    assert "relocation_context" not in components
    assert "exactly six" in _flat(registry)


def test_a_derived_state_could_never_have_changed_the_rollup(doc):
    """§3.5.2's second argument, evaluated over every state assignment: a
    fact is never established on bytes its source component did not
    deliver, so the strongest fold available over these facts is never
    more dominant than §5.4.2's fold over those components -- which
    already takes the weakest in-scope state."""
    argument = _flat(_section(doc, "**And a fold would add nothing.**",
                              "So the rollup folds the components"))

    assert "belongs to a component already in the rollup's scope" in argument
    assert "cannot change a single profile state, for any image" in argument

    states = _ROLLUP_ORDER + ("declared_absent",)
    for coff, optional, array in product(states, repeat=3):
        in_scope = (coff, optional, array)
        # `dynamic_base` and the delta both read `optional_header`, so the
        # inputs are pinned to the components they come from.
        folded = _most_dominant_fold((coff, optional, optional, array))

        assert _profile_state(in_scope) == _profile_state(in_scope + (folded,))


def test_the_two_standalone_consequences_are_kept(doc):
    section = _flat(_section(doc, "Two consequences are worth stating",
                             "#### 3.5.3"))

    assert "An answered presence is an answer, not a gap" in section
    assert "`basereloc_present` carries it" in section
    assert "nothing downgrades the other facts for it" in section
    assert "A missing `relocation_delta` does not diminish the rest" in section
    assert "has established three facts and says so" in section
    assert "What the delta gates is §8.3's `relocation_expected`" in section


# ── §3.5.3: a disk_reference profile's null is §1.3's null ──────────────


def test_a_disk_profile_establishes_every_fact_but_the_base_pair(doc):
    section = _section(doc, "| Field | `disk_reference` |",
                       "That `null` is §1.3's `null`")
    rows = {row[0].strip("`"): row[1] for row in _rows(section)}

    assert set(rows) == set(_RELOCATION_FACTS) | {"actual_base"}
    for field in ("preferred_image_base", "relocs_stripped", "dynamic_base"):
        assert rows[field].startswith("Established from")
    assert "§4.3 state" in rows["basereloc_descriptor_state"]
    assert rows["actual_base"].startswith("`null`")
    assert rows["relocation_delta"].startswith("`null`")


def test_the_disk_null_is_the_one_null_the_vocabulary_defines(doc):
    """§1.3 is unconditional. A `null` that meant "not applicable" would
    give one token a second normative meaning, which no `source_kind`
    lookup on the consumer's side can undo."""
    vocabulary = _flat(_section(doc, "### 1.3 `null` versus empty versus zero",
                                "### 1.4 Ordering"))
    assert "`null` means the fact could not be established" in vocabulary

    section = _flat(_section(doc, "That `null` is §1.3's `null`",
                             "## §4 Data directories"))
    assert "with no second meaning and no exception to it" in section
    assert "a file on disk is not loaded, and so the fact was not established" \
        in section
    assert 'no state meaning "not applicable"' in section


def test_nothing_about_the_shape_is_source_discriminated(doc):
    section = _flat(_section(doc, "Nothing here is source-discriminated",
                             "## §4 Data directories"))

    assert "no field a `disk_reference` profile omits" in section
    assert "every field this contract defines is emitted for every profile" \
        in section
    assert "never as a decoder ring" in section

    # §9's rule is the one this defers to, and it says the same thing.
    structured, = [row for row in _rows(
        _section(doc, "| Surface | Shows |", "Four rules bind all three"))
        if row[0] == "Structured output"]
    assert "Every field this contract defines" in structured[1]
    assert "`null` for every fact not established" in structured[1]


# ── §4.3.1: the reserved indices' own constraints ───────────────────────

# Indices 7 and 15 are reserved descriptors -- the whole eight-byte entry
# must be zero, not just its first half.
_RESERVED_CONSTRAINTS = {
    7: ("value", "size"),
    8: ("size",),
    15: ("value", "size"),
}


def _descriptor_is_declared(*, declared, index) -> bool:
    """§4.3.1's guard: a constraint is checked only for a descriptor the
    image declared. Outside the count, the bytes at that offset are not a
    descriptor at all, so no constraint may be read over them."""
    return declared is not None and index < declared


def _descriptor_state_checked(*, declared, index, bytes_read, value=0, size=0):
    """§4.3 with §4.3.1's per-index constraints folded in, behind the
    guard: the owner decides whether there is a descriptor (§5.3's step
    1), and only then does §4.3.1 decide whether it is legal."""
    state = _descriptor_state(declared=declared, index=index,
                              bytes_read=bytes_read)
    if (_descriptor_is_declared(declared=declared, index=index)
            and bytes_read == 8 and index in _RESERVED_CONSTRAINTS):
        fields = {"value": value, "size": size}
        if any(fields[name] != 0 for name in _RESERVED_CONSTRAINTS[index]):
            return "malformed"
    if state == "complete" and value == 0:
        return "declared_absent"
    return state


@pytest.mark.parametrize("declared, index, bytes_read, value, expected", [
    # The review's three cases.
    (7, 7, 8, 1, "declared_absent"),   # outside the count: not a descriptor
    (8, 7, 8, 1, "malformed"),         # inside it: the constraint applies
    (None, 7, 8, 1, "unavailable"),    # no owner captured at all
    # And the same guard for the other two constrained indices.
    (8, 8, 8, 0, "declared_absent"),
    (15, 15, 8, 1, "declared_absent"),
    (16, 15, 8, 1, "malformed"),
])
def test_a_constraint_is_only_read_over_a_declared_descriptor(
        declared, index, bytes_read, value, expected):
    """§5.3's step 1 comes first: a count that denies the index answers
    the question, and bytes past the declared array belong to whatever
    follows it -- reading a reserved-directory constraint over those
    would report a defect from bytes the image never called a
    descriptor."""
    assert _descriptor_state_checked(declared=declared, index=index,
                                     bytes_read=bytes_read, value=value,
                                     size=value) == expected


def test_the_declared_first_guard_is_stated_with_its_reason(doc):
    intro = _flat(_section(doc, "#### 4.3.1 Per-index constraints",
                           "| Index | Constraint |"))
    assert "checked only for a descriptor the image **declared**" in intro
    assert "`declared` is not `null` and `index < declared`" in intro

    reason = _flat(_section(doc, "**The declared-first guard is not a formality.**",
                            "**No other index carries a format constraint.**"))
    assert "would outrank §5.3's step 1" in reason
    assert "the image says its array ends at index 6" in reason
    assert "from bytes the image never claimed were a directory entry" in reason
    assert "makes `declared is null` decide alone" in reason
    assert "the owner decides whether there is a descriptor, and only then" \
        in reason


def test_per_index_constraints_match_the_indices_that_declare_them(doc):
    section = _section(doc, "#### 4.3.1 Per-index constraints",
                       "This is §1.2's rule 3")
    documented = {int(row[0]): row[2] for row in _rows(section)}

    assert set(documented) == set(_RESERVED_CONSTRAINTS)
    for index, fields in _RESERVED_CONSTRAINTS.items():
        expected = " or ".join(f"{name} != 0" for name in fields)
        assert documented[index] == f"`{expected}`", index

    notes = _section(doc, "### 4.2 The sixteen indices", "Index 1 and index 12")
    constrained = {int(row[0]) for row in _rows(notes)
                   if "value to be zero" in row[3] or "must be `0` per" in row[3]}
    assert constrained == set(_RESERVED_CONSTRAINTS)


def test_the_index_notes_point_at_the_constraint_rule(doc):
    """§4.2 is the table an implementer copies from. A note saying only
    "reported, not interpreted" reads as "no state consequence", which is
    the opposite of §4.3.1."""
    notes = _section(doc, "### 4.2 The sixteen indices", "Index 1 and index 12")
    referring = {int(row[0]) for row in _rows(notes) if "§4.3.1" in row[3]}

    assert referring == set(_RESERVED_CONSTRAINTS)
    for row in _rows(notes):
        if int(row[0]) in _RESERVED_CONSTRAINTS:
            assert "`malformed`" in row[3], row[0]
            assert "never resolved as an address" in row[3], row[0]
    assert "reported, not interpreted" not in doc


def test_a_fully_reserved_descriptor_is_checked_in_both_halves(doc):
    """Indices 7 and 15 reserve the whole entry. Checking only `value`
    lets `value=0, size=1` pass as `declared_absent` -- a positive claim
    of absence drawn from an entry the format says is all zeroes."""
    for index in (7, 15):
        assert _descriptor_state_checked(declared=16, index=index, bytes_read=8,
                                         value=0, size=1) == "malformed"
        assert _descriptor_state_checked(declared=16, index=index, bytes_read=8,
                                         value=1, size=0) == "malformed"
        assert _descriptor_state_checked(declared=16, index=index, bytes_read=8,
                                         value=0, size=0) == "declared_absent"

    # Index 8's `value` is a genuine RVA, so only its `size` is checked.
    assert _descriptor_state_checked(declared=16, index=8, bytes_read=8,
                                     value=0x3000, size=0) == "complete"

    section = _flat(_section(doc, "Indices 7 and 15 are reserved descriptors",
                             "Index 8 is different"))
    assert "the whole eight-byte entry is required to be zero" in section
    assert "would let that entry pass as `declared_absent`" in section


@pytest.mark.parametrize("index, value, size, expected", [
    (7, 0x1000, 0, "malformed"),        # ARCHITECTURE: both halves reserved
    (7, 0, 0x1, "malformed"),
    (7, 0, 0, "declared_absent"),
    (8, 0, 0x100, "malformed"),         # GLOBALPTR.size must be zero
    (8, 0, 0, "declared_absent"),
    (15, 0x2000, 0, "malformed"),       # RESERVED: both halves reserved
    (15, 0, 0x1, "malformed"),
    (15, 0, 0, "declared_absent"),
    (1, 0x2000, 0x40, "complete"),      # an ordinary index is unconstrained
])
def test_a_violated_reserved_constraint_is_malformed(index, value, size, expected):
    assert _descriptor_state_checked(declared=16, index=index, bytes_read=8,
                                     value=value, size=size) == expected


# ── §4.5: declared, projected, and readable are three counts ────────────

def _directory_counts(*, raw, size_of_optional_header, pe32_plus=True,
                      cap=16) -> dict:
    """§4.5's three counts, kept separate."""
    array_offset = _DIRECTORY_ARRAY_OFFSET[pe32_plus]
    capacity = max((size_of_optional_header - array_offset) // 8, 0)
    declared = min(raw, cap)
    return {
        "declared_directory_count_raw": raw,
        "declared_directory_count": declared,
        "readable_directory_count": min(declared, capacity),
    }


@pytest.mark.parametrize("raw, capacity_size, declared, readable", [
    # (raw, SizeOfOptionalHeader, expected declared, expected readable)
    (16, 112, 16, 0),                     # capacity 0: declared stays 16
    (16, 112 + 3 * 8, 16, 3),
    (5, 112 + 3 * 8, 5, 3),
    (0, 112, 0, 0),
    (200, 112 + 200 * 8, 16, 16),
])
def test_capacity_never_reduces_the_declared_count(raw, capacity_size,
                                                   declared, readable):
    counts = _directory_counts(raw=raw, size_of_optional_header=capacity_size)

    assert counts["declared_directory_count_raw"] == raw
    assert counts["declared_directory_count"] == declared
    assert counts["readable_directory_count"] == readable


def test_an_unreadable_declared_directory_is_unavailable_not_absent():
    """Folding capacity into the declared count would make
    `index >= declared` fire for every index, turning one structural
    contradiction into sixteen positive claims of absence."""
    counts = _directory_counts(raw=16, size_of_optional_header=112)

    for index in range(16):
        assert index < counts["declared_directory_count"]
        assert _descriptor_state(
            declared=counts["declared_directory_count"], index=index,
            bytes_read=0) == "unavailable"

    collapsed = min(counts["declared_directory_count"],
                    counts["readable_directory_count"])
    assert _descriptor_state(declared=collapsed, index=0,
                             bytes_read=0) == "declared_absent"


def test_the_three_counts_are_documented_separately(doc):
    section = _section(doc, "### 4.5 How many descriptors are declared",
                       "**Only `declared_directory_count` decides")
    counts = {row[0]: row[1] for row in _rows(section)}

    assert counts["`declared_directory_count_raw`"] == "The field exactly as read"
    assert counts["`declared_directory_count`"] == "`min(raw, MAX_DIRECTORY_COUNT)`"
    assert counts["`readable_directory_count`"] == (
        "`min(declared_directory_count, optional_header_capacity)`")

    rule = _flat(_section(doc, "**Only `declared_directory_count` decides",
                          "The three bounds themselves"))
    assert "`readable_directory_count` decides nothing about presence" in rule
    # The worked example is a code block; its alignment is content, so it
    # is matched raw rather than through `_flat`.
    worked = _section(doc, "declared_directory_count_raw = 16", "```")
    assert "readable_directory_count     = 0" in worked
    assert "declared_directory_count     = 16" in worked
    assert "descriptor[0..15].state      = unavailable" in worked


def test_the_shipped_declared_count_is_the_projected_one():
    """The shipped parser already computes `min(raw, 16)`, which is §4.5's
    middle count -- not the capacity-reduced one."""
    result = parse_pe_header(_with_directory_count(200))

    assert result["declared_directory_count"] == _directory_counts(
        raw=200, size_of_optional_header=240)["declared_directory_count"]


def test_a_reserved_constraint_needs_a_fully_read_descriptor():
    """§1.2's rule 3 holds here too: four bytes of an illegal-looking
    value is still a short read, not a defect."""
    assert _descriptor_state_checked(declared=16, index=15, bytes_read=4,
                                     value=0x2000) == "partial"


# ── §4.4: the impossible declared count the shipped cap absorbs ─────────

def _with_optional_header_size(declared: int, *, opt_bytes: int = None) -> bytes:
    """A PE32+ image whose COFF header declares `SizeOfOptionalHeader =
    declared`, with `opt_bytes` of optional header actually present.

    The declaration and the bytes present are separate parameters because
    §3.3.1's bound is about the declaration: a helper that always shrank
    the buffer to match would only ever exercise `len(data)`.
    """
    opt = bytearray(declared if opt_bytes is None else opt_bytes)
    struct.pack_into("<H", opt, 0, 0x20b)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<Q", opt, 24, 0x140000000)
    struct.pack_into("<I", opt, 56, 0x5000)
    struct.pack_into("<I", opt, 108, 16)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    section = bytearray(40)
    section[0:8] = b".text".ljust(8, b"\x00")
    struct.pack_into("<IIII", section, 8, 0x2000, 0x1000, 0x2000, 0x400)
    struct.pack_into("<I", section, 36, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)

    return (bytes(dos) + b"PE\x00\x00"
            + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, declared, 0x0102)
            + bytes(opt) + bytes(section) + b"\x00" * 128)


def test_the_directory_walk_is_not_bounded_by_the_optional_header_today():
    """§11.2.1: with no `SizeOfOptionalHeader` bound the walk reads the
    section table as descriptors. Descriptor 0 comes back as the section
    name's own bytes."""
    result = parse_pe_header(_with_optional_header_size(112))

    assert result["valid"] is True
    assert result["directories_complete"] is True
    assert result["sections"][0]["name"] == ".text"

    name = b".text".ljust(8, b"\x00")
    assert result["data_directories"][0] == struct.unpack("<II", name)


_MIN_OPTIONAL_HEADER = {          # §3.3.1, per format
    "`Magic` alone": (2, 2),
    "Every §3.3 fixed field": (72, 72),
    "`NumberOfRvaAndSizes`": (96, 112),
    "The full directory array": (224, 240),
}


def test_minimum_optional_header_sizes_match_the_offset_table(doc, width_table):
    """§3.3.1's minimums are §2.4's offsets plus each field's width, so
    the two tables cannot drift apart."""
    section = _section(doc, "| Needed for | PE32 | PE32+ |",
                       "A `SizeOfOptionalHeader` of `0` or `1`")
    documented = {row[0]: (int(row[1].strip("`")), int(row[2].strip("`")))
                  for row in _rows(section)}

    assert documented == _MIN_OPTIONAL_HEADER

    for pe32_plus in (False, True):
        index = 1 if pe32_plus else 0
        count_off = _offset(width_table, "`NumberOfRvaAndSizes` offset", pe32_plus)
        array_off = _offset(width_table, "Directory array offset", pe32_plus)

        assert documented["`NumberOfRvaAndSizes`"][index] == count_off + 4
        assert documented["The full directory array"][index] == array_off + 16 * 8


def test_a_field_past_the_declared_header_size_is_unavailable(doc):
    section = _section(doc, "#### 3.3.1 Every field is bounded",
                       "The minimum size a stage")
    flat = _flat(section)

    assert "`o + w <= SizeOfOptionalHeader`" in flat
    assert "whatever the acquisition buffer happens to hold" in flat
    assert "every byte past the declared size **is** section-table content" in flat

    tail = _flat(_section(doc, "The minimum size a stage",
                          "### 3.4 Section table"))
    assert "An `unavailable` field is never by itself `malformed`" in tail
    assert "the two self-contradictions this contract names" in tail


_FIXED_PORTION_SIZE = {False: 96, True: 112}      # §3.3.1.1, per format


def _optional_header_state(*, size_of_optional_header, pe32_plus=None):
    """§3.3.1 plus §3.3.1.1, as one function. `pe32_plus` is `None` when
    `Magic` itself could not be read."""
    if size_of_optional_header < 2 or pe32_plus is None:
        return "unavailable"
    if size_of_optional_header < _FIXED_PORTION_SIZE[pe32_plus]:
        return "malformed"
    return "complete"


def test_the_fixed_portion_threshold_is_the_offset_tables_own(doc, width_table):
    section = _section(doc, "##### 3.3.1.1 A header too small",
                       "This is one of §5.3.1's")
    flat = _flat(section)

    assert "`96` for PE32 and `112` for PE32+" in flat
    for pe32_plus in (False, True):
        count_off = _offset(width_table, "`NumberOfRvaAndSizes` offset", pe32_plus)
        assert _FIXED_PORTION_SIZE[pe32_plus] == count_off + 4


@pytest.mark.parametrize("size, pe32_plus, expected", [
    (0, None, "unavailable"),       # `Magic` itself unreadable
    (1, None, "unavailable"),
    (20, True, "malformed"),        # decoded some fields, cannot be PE32+
    (100, True, "malformed"),       # PE32+ needs 112
    (100, False, "complete"),       # the same size is fine for PE32's 96
    (95, False, "malformed"),
    (96, False, "complete"),
    (112, True, "complete"),
    (240, True, "complete"),
])
def test_a_short_optional_header_has_exactly_one_state(size, pe32_plus, expected):
    """PE32+ at size 20 decodes `Magic` and `AddressOfEntryPoint` while
    `ImageBase` and `SizeOfImage` fall outside the declaration. That is
    not `unavailable`, not `complete`, and not `partial` -- the bytes past
    the boundary are the section table, not an unexamined range."""
    assert _optional_header_state(size_of_optional_header=size,
                                  pe32_plus=pe32_plus) == expected


def test_the_short_header_state_is_argued_from_the_alternatives(doc):
    section = _flat(_section(doc, "It is what keeps a partly-decoded",
                             "The fields that did decode"))

    assert "not `unavailable` — two fields were decoded" in section
    assert "not `complete` — several P0 fields have no value" in section
    assert "not `partial`, because `partial` requires an unexamined range" in section
    assert "they are not this component's bytes at all" in section


@pytest.mark.parametrize("size_of_optional_header", [0, 1, 100, 112])
def test_the_optional_header_size_is_not_consulted_today(size_of_optional_header):
    """§11.2.1's gap, at the field level: the shipped parser bounds its
    reads by `len(data)` alone, so an optional header declaring no room at
    all still yields sixteen directories read out of the section table."""
    result = parse_pe_header(_with_optional_header_size(
        size_of_optional_header, opt_bytes=_OPT_SIZE_PE32_PLUS))

    assert result["valid"] is True
    assert result["is_pe32_plus"] is True
    assert result["declared_directory_count"] == 16
    assert len(result["data_directories"]) == 16


def _with_short_optional_header() -> bytes:
    """A PE32+ image declaring `SizeOfOptionalHeader = 20` with exactly
    that many optional-header bytes present, so every field past `+20` is
    read out of the section table that follows."""
    opt = bytearray(20)
    struct.pack_into("<H", opt, 0, 0x20b)
    struct.pack_into("<I", opt, 16, 0x1000)          # AddressOfEntryPoint

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    section = bytearray(40)
    section[0:8] = b".text".ljust(8, b"\x00")
    struct.pack_into("<IIII", section, 8, 0x2000, 0x1000, 0x2000, 0x400)
    struct.pack_into("<I", section, 36, _TEXT_CHARACTERISTICS)
    filler = bytearray(40)
    filler[0:8] = b"AAAAAAAA"

    return (bytes(dos) + b"PE\x00\x00"
            + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 20, 0x0102)
            + bytes(opt) + bytes(section) + bytes(filler) + b"\x00" * 256)


_IMAGE_SCN_CNT_CODE = 0x00000020
_TEXT_CHARACTERISTICS = (_IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
                         | IMAGE_SCN_MEM_READ)


def test_optional_header_fields_are_read_past_the_declared_size_today():
    """§11.2.1.1: with no field-level bound, `image_base` and
    `size_of_image` come back as section-header bytes -- and the image
    still parses as `valid`."""
    result = parse_pe_header(_with_short_optional_header())

    assert result["valid"] is True
    assert result["address_of_entry_point"] == 0x1000     # inside the header
    assert result["image_base"] == 0x200000000074         # section-header bytes
    assert result["size_of_image"] == _TEXT_CHARACTERISTICS


def test_the_field_level_gap_is_documented_with_its_consumers(doc):
    section = _flat(_section(doc, "#### 11.2.1.1 Field level",
                             "#### 11.2.1.2 Array level"))

    assert "`SizeOfOptionalHeader = 20`" in section
    assert "the section's `Characteristics` field read as a length" in section
    assert "hunt.stomping" in section and "hunt.injection" in section
    assert "MainImagePeClaim" in section
    assert "it is a wrong address another component reads from" in section


def test_the_documented_corrupted_values_are_the_ones_the_parser_returns(doc):
    """The worked block's numbers must come from the parser, not from a
    measurement taken once and left to drift."""
    field_level = _section(doc, "#### 11.2.1.1 Field level",
                           "#### 11.2.1.2 Array level")
    block = _section(field_level, "```text", "```")
    documented = {name.strip(): int(value.split()[0], 16)
                  for name, value in (line.split("=", 1)
                                      for line in block.splitlines() if "=" in line)}
    result = parse_pe_header(_with_short_optional_header())

    assert documented == {
        "address_of_entry_point": result["address_of_entry_point"],
        "image_base": result["image_base"],
        "size_of_image": result["size_of_image"],
    }


def test_the_overlap_is_documented_as_unapplied_new_work(doc):
    section = _flat(_section(doc, "### 11.2.1 `SizeOfOptionalHeader` is not applied",
                             "### 11.3 New correlation"))

    assert "bounds every optional-header read by `len(data)` alone" in section
    assert "not merely unretained; they are not applied" in section
    assert "The field-level half is the more damaging of the two" in section

def test_an_impossible_declared_count_is_invisible_to_the_shipped_parser(
        documented_constants):
    """§4.4's `malformed` row needs the raw value §11.2 lists as new work:
    today the cap makes an impossible count indistinguishable from a
    well-formed sixteen."""
    cap = documented_constants["MAX_DIRECTORY_COUNT"]
    impossible = parse_pe_header(_with_directory_count(200))
    well_formed = parse_pe_header(_with_directory_count(cap))

    assert impossible["declared_directory_count"] == cap
    assert impossible["directories_complete"] is True
    assert (impossible["declared_directory_count"]
            == well_formed["declared_directory_count"])


_DIRECTORY_ARRAY_OFFSET = {False: 96, True: 112}   # §2.4, per format


def _fits_in_optional_header(raw, size_of_optional_header, pe32_plus) -> bool:
    """§4.5's second bound: the declared array must fit the header that
    declares it."""
    array_offset = _DIRECTORY_ARRAY_OFFSET[pe32_plus]
    room = (size_of_optional_header - array_offset) // 8
    return raw <= max(room, 0)


def _directory_array_state(*, count_read, raw, decoded, declared,
                           size_of_optional_header=None, pe32_plus=True):
    """§4.4's first-match rows, as one function."""
    if not count_read:
        return "unavailable"
    if size_of_optional_header is not None and not _fits_in_optional_header(
            raw, size_of_optional_header, pe32_plus):
        return "malformed"
    if raw == 0:
        return "declared_absent"
    if decoded < declared:
        return "partial"
    return "complete"


def test_directory_array_rows_are_in_the_documented_order(doc):
    section = _section(doc, "### 4.4 Directory array state",
                       "The `malformed` row is")
    assert [row[1] for row in _rows(section)] == [
        "`unavailable`", "`malformed`", "`declared_absent`",
        "`partial`, with the shortfall named as an unexamined range",
        "`complete`",
    ]


def test_a_large_declared_count_is_out_of_scope_not_malformed(
        documented_constants):
    """The PE format does not fix the directory count, so a count above
    what this contract projects is a budget being reached -- never a claim
    that the image is defective."""
    cap = documented_constants["MAX_DIRECTORY_COUNT"]
    roomy = 112 + 200 * 8      # an optional header that really holds 200

    assert _directory_array_state(
        count_read=True, raw=200, decoded=cap, declared=cap,
        size_of_optional_header=roomy) == "complete"
    assert _directory_array_state(
        count_read=True, raw=200, decoded=3, declared=cap,
        size_of_optional_header=roomy) == "partial"


def test_the_safety_bounds_section_keeps_the_two_kinds_apart(doc):
    """§10 is where an implementer looks up resource constraints; its
    bounded-stop sentence must not re-absorb `MAX_DIRECTORY_COUNT`."""
    section = _flat(_section(doc, "### 10.1 Bounds", "### 10.2 Determinism"))

    assert "which is **projection scope**" in section
    assert "an **acquisition budget** that binds is reported as a bounded stop" \
        in section
    assert "the one cap here that binds without producing a bounded stop" \
        in section
    assert "never a silent shortfall" in section


def test_projection_scope_is_never_called_a_bounded_stop_anywhere(doc):
    """A whole-document check: pinning only the paragraph that states the
    rule lets a worked example elsewhere keep the old wording, and an
    implementer following the example produces `partial`."""
    negated = re.compile(r"(\*\*)?not(\*\*)? (a|as a) bounded stop|no bounded stop"
                         r"|without producing a bounded stop")

    # Every mention inside the projection-scope section, whether or not it
    # names the constant -- the stale wording lived in a worked example
    # that never spelled `MAX_DIRECTORY_COUNT` out.
    scope = _section(doc, "### 4.5 How many descriptors are declared",
                     "## §5 Coverage")
    for sentence in re.split(r"(?<=[.:])\s", _flat(scope)):
        if "bounded stop" in sentence:
            assert negated.search(sentence), sentence

    # And anywhere else that names the constant. §2.6 legitimately
    # mentions both in one paragraph, in separate sentences, because
    # `MAX_E_LFANEW` really is a budget.
    for sentence in re.split(r"(?<=[.:])\s", _flat(doc)):
        if "MAX_DIRECTORY_COUNT" in sentence and "bounded stop" in sentence:
            assert negated.search(sentence), sentence


def test_the_over_scope_example_names_the_unprojected_count(doc):
    section = _flat(_section(doc, "The two are independent, and the second decides",
                             "### 4.6" if "### 4.6" in doc else "---"))

    assert "`unprojected_directory_count = 184`" in section
    assert "**no bounded stop**" in section


_LIMIT_KINDS = {
    "**Acquisition budget** — work dumpex declined to do": {
        "MAIN_IMAGE_PE_READ_MAX", "PE_VALIDATE_READ_MAX", "MAX_E_LFANEW",
        "MAX_IAT_*"},
    "**Projection scope** — meaning this contract does not define": {
        "MAX_DIRECTORY_COUNT"},
    "**Structural constraint** — a value the format does not permit": {
        "_MAX_SECTIONS"},
    "**Retention bound** — how much of one value the profile keeps": {
        "MAX_STRING_BYTES"},
}


def test_a_retention_bound_is_not_a_bounded_stop(limit_kinds, doc):
    """A truncated string ends no acquisition, leaves no PE structure
    unexamined, and carries no consumed/limit record -- none of what §6.2
    requires of a bounded stop."""
    budgets, = [names for kind, names in limit_kinds.items()
                if kind.startswith("**Acquisition budget**")]
    retention, = [names for kind, names in limit_kinds.items()
                  if kind.startswith("**Retention bound**")]

    assert "MAX_STRING_BYTES" not in budgets
    assert retention == {"MAX_STRING_BYTES"}

    section = _flat(_section(doc, "`MAX_STRING_BYTES` needs the fourth row",
                             "It bounds what the profile keeps"))
    for denial in ("does **not** end acquisition",
                   "produces **no** unexamined range",
                   "changes **no** component state",
                   "carries **no** consumed/limit record",
                   "never affects coverage"):
        assert denial in section, denial


@pytest.fixture(scope="module")
def limit_kinds(doc) -> dict:
    section = _section(doc, "| Kind | Constants | Reaching it produces |",
                       "`_MAX_SECTIONS` belongs in the third row")
    return {row[0]: set(re.findall(r"`([A-Z_][A-Za-z0-9_*]*)`", row[1]))
            for row in _rows(section)}


def test_every_constant_is_classified_exactly_once(limit_kinds,
                                                    documented_constants):
    assert limit_kinds == _LIMIT_KINDS

    classified = set().union(*limit_kinds.values())
    assert len(classified) == sum(len(names) for names in limit_kinds.values())

    # Every constant §1.5 lists is classified; `MAX_IAT_*` covers its six.
    unclassified = set(documented_constants) - classified
    assert all(name.startswith("MAX_IAT_") for name in unclassified), unclassified


def test_max_sections_is_a_structural_constraint_not_a_budget(limit_kinds, doc):
    """`NumberOfSections > 96` is a count no loadable image can declare;
    the shipped parser rejects it deterministically, not as a gap."""
    structural, = [names for kind, names in limit_kinds.items()
                   if kind.startswith("**Structural constraint**")]
    assert structural == {"_MAX_SECTIONS"}

    budgets, = [names for kind, names in limit_kinds.items()
                if kind.startswith("**Acquisition budget**")]
    assert "_MAX_SECTIONS" not in budgets

    header = bytearray(build_pe_header([TEXT_SECTION_RX]))
    offset = header.index(b"PE\x00\x00") + 4
    struct.pack_into("<H", header, offset + 2, _MAX_SECTIONS + 1)
    over = parse_pe_header(bytes(header))

    assert over["valid"] is False
    assert over["insufficient_data"] is False      # structural, not a gap


def test_the_safety_bounds_section_uses_all_three_kinds(doc):
    section = _flat(_section(doc, "### 10.1 Bounds", "### 10.2 Determinism"))

    assert "`MAX_E_LFANEW`, an **acquisition budget**" in section
    assert "`_MAX_SECTIONS`, which is a **structural constraint**" in section
    assert "exceeding it is `malformed`, not a stop" in section


def test_projection_scope_is_not_an_acquisition_budget(doc):
    """A bounded stop leaves a question unanswered, so it yields
    `partial`. Declining to project index 16 leaves nothing unanswered --
    §4.2 gives it no meaning -- so it must not be called a bounded stop,
    or `complete` and `partial` would both follow from one input."""
    kinds = _section(doc, "These constants are **four different kinds**",
                     "A budget stop leaves a question unanswered")
    flat = _flat(kinds)

    assert "**Acquisition budget**" in flat
    assert "**Projection scope**" in flat
    assert "Not a bounded stop; nothing was declined" in flat

    scope = _section(doc, "- **`raw > MAX_DIRECTORY_COUNT` is not",
                     "- **`raw` beyond the optional header")
    scope_flat = _flat(scope)
    assert "**not** as a bounded stop" in scope_flat
    assert "does not make the array `partial`" in scope_flat


def test_a_bounded_stop_yields_partial_or_unavailable_by_bytes(doc):
    """A stop landing on a component boundary leaves that component with
    no bytes at all, which §5.3 step 1 calls `unavailable`."""
    section = _section(doc, "What it *does* yield follows",
                       "The second row is why")
    outcomes = {row[0]: row[1] for row in _rows(section)}

    assert outcomes["Part-way through a component"].startswith("`partial`")
    assert outcomes["Before a component's first byte"].startswith("`unavailable`")

    rule = _flat(_section(doc, "not because the image said so",
                           "What it *does* yield"))
    assert "never yields `malformed`, and never *makes* a component "            "`declared_absent`" in rule
    assert "`partial`" not in rule.split("A budget is a fact")[0]

    # The claim has to be about what a stop produces, not about which
    # states may appear beside one: §5.3's step 1 can reach
    # `declared_absent` from an owner captured before the stop.
    assert "may still be `declared_absent` in a profile that stopped on a "            "budget" in rule
    assert "when a captured owner denied it before the stop" in rule
    assert "the stop contributed nothing to it" in rule
    assert "turn its own shortfall into a denial" in rule


def test_the_capacity_formula_is_clamped_at_zero(doc):
    """An optional header smaller than the array's own offset gives a
    negative quotient; feeding that to `min` yields a negative count."""
    section = _section(doc, "| Bound | Value | Kind |",
                       "The second bound is clamped")
    formula = [row[1] for row in _rows(section)][1]

    assert formula.startswith("`max(0, floor(")
    assert _fits_in_optional_header(0, 100, True)      # capacity 0, not -2
    assert not _fits_in_optional_header(1, 100, True)


def test_the_two_directory_bounds_are_decided_independently(
        documented_constants):
    """The same over-sixteen count is `malformed` or merely out of scope
    depending on the optional header that declares it -- so the scope
    bound can never stand in for the structural one."""
    cap = documented_constants["MAX_DIRECTORY_COUNT"]

    assert _directory_array_state(
        count_read=True, raw=200, decoded=cap, declared=cap,
        size_of_optional_header=240) == "malformed"
    assert _directory_array_state(
        count_read=True, raw=200, decoded=cap, declared=cap,
        size_of_optional_header=112 + 200 * 8) == "complete"


def test_a_count_that_overruns_the_optional_header_is_malformed():
    """The one genuinely structural constraint: the array and the section
    table cannot both start where the header says they do."""
    assert _directory_array_state(
        count_read=True, raw=16, decoded=16, declared=16,
        size_of_optional_header=112) == "malformed"
    assert _directory_array_state(
        count_read=True, raw=16, decoded=16, declared=16,
        size_of_optional_header=240) == "complete"


def test_the_scope_bound_and_the_structural_bound_stay_separate(doc):
    section = _section(doc, "The three bounds themselves:",
                       "A reader that omits the second bound")

    flat = _flat(section)
    assert "is not, on its own, malformed" in flat
    assert "does not fix the number of data directories" in flat
    assert "*is* malformed" in flat
    assert "The two are independent, and the second decides" in flat
    kinds = [row[2] for row in _rows(section)]
    assert kinds == ["A fact about the image", "A fact about the image",
                     "Projection scope of this contract"]


# Every place this contract decides `malformed` on a partly read
# component. The registry is what makes step 3 total: a defect that fires
# despite a gap and is not listed here leaves the same input
# implementable two ways.
_DETERMINED_DEFECTS = {
    ("`dos_header`", "`e_magic`"),
    ("`coff_header`", "The four signature bytes at `e_lfanew`"),
    ("`coff_header`", "`NumberOfSections`"),
    ("`optional_header`", "`Magic`"),
    ("`optional_header`", "`Magic`, `SizeOfOptionalHeader`"),
    ("`directory_array`", "`NumberOfRvaAndSizes`, `SizeOfOptionalHeader`"),
}

# The format fixes these values outright, so a full read that finds
# anything else is the plainest determined defect there is.
_FORMAT_CONSTANTS = {
    ("`dos_header`", "`e_magic`"),
    ("`coff_header`", "The four signature bytes at `e_lfanew`"),
    ("`optional_header`", "`Magic`"),
}


def test_the_determined_defect_registry_is_closed_and_complete(doc):
    section = _section(doc, "#### 5.3.1 Determined defects",
                       "Four entries rest on one field each")
    registered = {(row[0], row[1]) for row in _rows(section)}

    assert registered == _DETERMINED_DEFECTS
    assert "exactly six" in _flat(section)

    # Every rule that makes a component `malformed` on part of its bytes
    # belongs here; a format constant checked in prose but left out of
    # the registry is the gap this table exists to close.
    assert _FORMAT_CONSTANTS < registered
    shapes = _flat(_section(doc, "Four entries rest on one field each",
                            "Every entry satisfies the same three"))
    assert "Three of the four single-field entries are **format constants**" \
        in shapes
    assert "the bytes holding it were read, and they hold something else" \
        in shapes
    assert "They never disagree" in shapes

    # Every component named in the registry is one §1.2 declares, and
    # each entry's rule points at the section that states it.
    declared = {row[0] for row in _rows(_section(
        doc, "### 1.2 Component states", "A component holds bytes."))}
    assert {component for component, _bytes in registered} <= declared

    rules = [row[2] for row in _rows(section)]
    assert all(rule.startswith("§") for rule in rules), rules


def test_no_section_still_claims_a_single_exception(doc):
    for phrase in ("the only such case", "**The one exception.**",
                   "is the only exception"):
        assert phrase not in doc, phrase


_NUMBER_WORDS = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
                 7: "seven", 8: "eight"}


def _registry_size(doc: str) -> int:
    return len(_rows(_section(doc, "#### 5.3.1 Determined defects",
                              "Four entries rest on one field each")))


def test_both_registered_rules_point_back_at_the_registry(doc):
    """§3.3.1.1 and §4.4 each state the rule locally, and each must name
    the registry by the size the registry actually has. Spelling that
    size into the assertion is how a stale cross-reference survived a
    green run: the count comes from the table now."""
    optional_header = _flat(_section(doc, "##### 3.3.1.1 A header too small",
                                     "It is what keeps a partly-decoded"))
    directory_array = _flat(_section(doc, "The `malformed` row is",
                                     "### 4.5 How many descriptors"))

    assert "one of §5.3.1's registered determined defects" in optional_header
    assert "one of §5.3.1's registered determined defects" in directory_array
    assert "decided at §5.3's step 3" in directory_array

    # §1.2's rule 3 is the third reference, and it names no count either.
    rule = _flat(_section(doc, "3. **`malformed` requires",
                          "This is close to the distinction"))
    assert "§5.3.1 registers the determined defects this contract decides " \
           "that way" in rule


_NUMBER_WORD = "|".join(_NUMBER_WORDS.values())

# A count word qualifying "determined defect(s)" -- adjacency, not a
# window, because byte counts share these sentences ("a determined defect
# on `Magic`'s own two bytes").
_QUALIFIED_COUNT_RE = re.compile(
    rf"\b({_NUMBER_WORD})\b(?: registered)? determined defects?\b")


def test_the_registry_states_its_size_in_exactly_one_place(doc):
    """Chasing each phrasing with its own pattern is what let `registers
    the four determined defects` pass: a new way of writing the count
    needed a new pattern. So the count is written once, beside the table,
    and every cross-reference names the registry without a number --
    leaving nothing that can drift out of step with the rows."""
    size = _registry_size(doc)

    stated = re.findall(rf"registers exactly ({_NUMBER_WORD})\b", doc)
    assert stated == [_NUMBER_WORDS[size]], stated

    # And nowhere else does a number qualify the registry's contents.
    assert _QUALIFIED_COUNT_RE.findall(doc) == [], \
        _QUALIFIED_COUNT_RE.findall(doc)

    # Both halves have to be able to fail, or neither pins anything.
    assert re.findall(rf"registers exactly ({_NUMBER_WORD})\b",
                      doc.replace("registers exactly six",
                                  "registers exactly four", 1)) == ["four"]
    assert _QUALIFIED_COUNT_RE.findall(
        doc.replace("registers the determined defects",
                    "registers the four determined defects", 1)) == ["four"]

    # The cross-references still point at the registry, just without a
    # count of their own to keep in step.
    for section in ("##### 3.3.1.1 A header too small", "The `malformed` row is"):
        end = ("It is what keeps a partly-decoded"
               if section.startswith("#####") else "### 4.5 How many")
        assert "§5.3.1's registered determined defects" in \
            _flat(_section(doc, section, end)), section


def test_the_registrys_own_breakdown_adds_up(doc):
    """§5.3.1 splits its entries into single-field and paired defects.
    Those two counts are the same table read a second way, so they drift
    from it exactly as the cross-references did."""
    rows = _rows(_section(doc, "#### 5.3.1 Determined defects",
                          "Four entries rest on one field each"))
    single = [row for row in rows if "," not in row[1]]
    paired = [row for row in rows if "," in row[1]]

    breakdown = _flat(_section(doc, "Four entries rest on one field each",
                               "Every entry satisfies the same three"))
    assert f"{_NUMBER_WORDS[len(single)].capitalize()} entries rest on one " \
           f"field each" in f"Four entries rest on one field each {breakdown}"
    assert len(single) == 4 and len(paired) == 2
    assert len(single) + len(paired) == _registry_size(doc)

    assert f"and {_NUMBER_WORDS[len(paired)]} on a pair" in breakdown
    assert f"{_NUMBER_WORDS[len(_FORMAT_CONSTANTS)].capitalize()} of the " \
           f"{_NUMBER_WORDS[len(single)]} single-field entries" in breakdown


def test_the_registry_conditions_are_stated(doc):
    section = _flat(_section(doc, "Every entry satisfies the same three",
                             "Two things a registered defect does not do"))

    assert "read **in full**" in section
    assert "the rule names those bytes" in section
    assert "cannot be true of any PE image" in section
    assert "never a limit of this contract" in section
    assert "without any byte the component may still be missing" in section

    keeps = _flat(_section(doc, "Two things a registered defect does not do",
                           "A component with no registered defect"))
    assert "does not erase what decoded" in keeps
    assert "does not absorb the component's gaps" in keeps
    assert "still records them as unexamined ranges" in keeps


def test_rule_three_binds_the_contradiction_not_the_whole_component(doc):
    """Rule 3 must bind the CONTRADICTION's bytes; binding the whole
    component would make §3.3.1.1 and §4.4 both violate it."""
    section = _flat(_section(doc, "3. **`malformed` requires",
                             "This is close to the distinction"))

    assert "the contradiction itself to be fully read" in section
    assert "Unread bytes *elsewhere* in the component" in section
    assert "nor soften one that was fully read" in section


# ── §5.4: the rollup is one function, and the examples agree with it ────

_COMPONENT_RE = re.compile(r"`([a-z_]+)`")


def _cumulative_components(section: str, column: int) -> dict:
    """Stage -> the components named at that stage and every earlier one."""
    cumulative, seen = {}, []
    for row in _rows(section):
        seen = seen + _COMPONENT_RE.findall(row[column])
        cumulative[int(row[0])] = tuple(seen)
    return cumulative


@pytest.fixture(scope="module")
def stage_components(doc) -> dict:
    """§6.1's own `Yields` column -- the authority §5.4.1 defers to."""
    section = _section(doc, "| Stage | Reads | Yields | Enough for |",
                       "The `Reads` column")
    return _cumulative_components(section, 2)


def test_declared_components_are_the_frozen_component_names(doc, stage_components):
    section = _section(doc, "### 1.2 Component states",
                       "Every component carries exactly one state")
    declared = {row[0].strip("`") for row in _rows(section)}

    assert declared == set(stage_components[3])


def test_the_in_scope_set_is_exactly_the_cumulative_stage_yields(
        doc, stage_components):
    """§5.4.1 claims to be §6.1's cumulative yields; a component that
    appears in only one of the two tables is how a permanently
    `unavailable` component gets into the fold."""
    section = _section(doc, "#### 5.4.1 The in-scope component set",
                       "A component outside the requested stage")
    in_scope = _cumulative_components(section, 1)

    assert sorted(in_scope) == [0, 1, 2, 3]
    for stage, components in in_scope.items():
        assert set(components) == set(stage_components[stage]), stage


def _profile_state(in_scope_states) -> str:
    """§5.4.2's fold, as the single function §5.4's rules must reduce to.
    `declared_absent` never participates."""
    for state in ("malformed", "unavailable", "partial"):
        if state in in_scope_states:
            return state
    return "complete"


def _in_scope_size(stage_components, stage: int, source: str) -> int:
    """§5.4.1's set is source-independent: only components are folded, and
    every source acquires the same ones."""
    return len(set(stage_components[stage]))


def test_the_in_scope_set_does_not_vary_by_source(stage_components):
    for stage in stage_components:
        assert _in_scope_size(stage_components, stage, "disk") \
            == _in_scope_size(stage_components, stage, "memory")


def test_stage_one_does_not_claim_the_optional_header_magic(doc, stage_components):
    """`Magic` starts at `e_lfanew + 24`, so a stage that stops there
    cannot yield PE32 versus PE32+."""
    section = _section(doc, "| Stage | Reads | Yields | Enough for |",
                       "The `Reads` column")
    stage_one = [row for row in _rows(section) if row[0] == "1"][0]

    assert stage_one[1] == "through `e_lfanew + 24`"
    assert "format" not in stage_one[3]
    assert "optional_header" not in stage_components[1]

    full = build_pe_header([TEXT_SECTION_RX])
    at_stage_one = parse_pe_header(full[:0x80 + 24])
    assert at_stage_one["machine_name"] == "AMD64"
    assert at_stage_one["is_pe32_plus"] is None

    assert parse_pe_header(full[:0x80 + 26])["is_pe32_plus"] is True


def test_pointer_width_is_documented_as_a_stage_two_fact(doc):
    section = _section(doc, "Stage 1 stops one byte short",
                       "Stage 2 is also where §3.5's relocation facts")

    assert "Pointer width is a stage-2 fact" in _flat(section)
    assert "not as a guess from `Machine`" in _flat(section)

def test_only_components_are_folded_and_for_every_source(doc):
    section = _flat(_section(doc, "One rule narrows the set further",
                             "#### 5.4.2 The fold"))

    assert "folds as one unit" in section
    assert "otherwise the same for every source" in section
    assert "never which components are asked for" in section
    assert "Only components hold bytes, so only components are folded" in section
    assert "neither in this set nor missing from it" in section


def test_the_documented_fold_never_yields_declared_absent(doc):
    section = _section(doc, "#### 5.4.2 The fold", "> `declared_absent` never")
    outcomes = [row[1] for row in _rows(section)]

    assert outcomes == ["`malformed`", "`unavailable`", "`partial`", "`complete`"]
    assert "`declared_absent`" not in outcomes


_MULTISET_RE = re.compile(r"`([a-z_]+)` ×(\d+)")


@pytest.fixture(scope="module")
def worked_examples(doc) -> list:
    section = _section(doc, "#### 5.4.3 Worked examples",
                       "rows carry the rules")
    rows = _rows(section)
    assert len(rows) == 7
    return [(int(row[0]), row[1], _MULTISET_RE.findall(row[2]),
             row[3].strip("`")) for row in rows]


def test_worked_examples_cover_their_whole_in_scope_set(
        worked_examples, stage_components):
    """The multiset in each row must account for every in-scope component,
    not just the interesting ones -- otherwise a row says nothing about
    what the unlisted components were."""
    for stage, source, multiset, _expected in worked_examples:
        counted = sum(int(count) for _state, count in multiset)
        assert counted == _in_scope_size(stage_components, stage, source), \
            (stage, source, multiset)


def test_worked_examples_agree_with_the_single_fold(worked_examples):
    for stage, source, multiset, expected in worked_examples:
        states = [state for state, count in multiset for _ in range(int(count))]
        assert _profile_state(states) == expected, (stage, source, multiset)


def test_worked_examples_reach_every_profile_state(worked_examples):
    assert {expected for *_rest, expected in worked_examples} == {
        "complete", "partial", "unavailable", "malformed"}


def test_a_fully_parsed_disk_image_is_complete(worked_examples):
    disk = [row for row in worked_examples if row[1] == "disk"]

    assert disk, "no `disk_reference` example -- the §5.4.1 rule is unpinned"
    assert all(expected == "complete" for *_rest, expected in disk)


def _descriptors_unit(member_states) -> str:
    """§5.4.1's unit rule: §5.4.2 applied to the sixteen members, whose
    single result is the one thing that enters the outer fold."""
    assert len(member_states) == 16
    return _profile_state(member_states)


def _profile_state_two_level(components: dict) -> str:
    """The rollup as §5.4.3.1 defines it: the inner fold first, then the
    outer fold over §5.4.1's set with one `directory_descriptors` member.

    Descriptor states are passed as the sixteen members they are, so a
    test cannot accidentally hand a member state to the outer fold.
    """
    members = components["directory_descriptors"]
    outer = [state for name, state in components.items()
             if name != "directory_descriptors"]
    outer.append(_descriptors_unit(members))
    return _profile_state(outer)


def _perfect_stage_three(doc) -> dict:
    """Row 1's image: every component decoded, and the two descriptors
    §4.2 requires to be zero reading `declared_absent`."""
    section = _section(doc, "### 4.2 The sixteen indices", "Index 1 and index 12")
    required_zero = [int(row[0]) for row in _rows(section)
                     if "requires this descriptor's value to be zero" in row[3]]
    assert required_zero == [7, 15]

    return {
        "dos_header": "complete",
        "coff_header": "complete",
        "optional_header": "complete",
        "directory_array": "complete",
        "section_table": "complete",
        "directory_descriptors": [
            "declared_absent" if index in required_zero else "complete"
            for index in range(16)],
    }


def test_a_perfect_images_reserved_descriptors_stay_inside_the_unit(
        doc, worked_examples, stage_components):
    """The member state must not reach the outer fold. A row carrying
    `declared_absent` at the top level would be the visible symptom of an
    implementation that fed sixteen votes into the profile fold."""
    perfect = _perfect_stage_three(doc)

    assert set(perfect) == set(stage_components[3])
    assert _descriptors_unit(perfect["directory_descriptors"]) == "complete"
    assert _profile_state_two_level(perfect) == "complete"

    stage, source, multiset, expected = worked_examples[0]
    assert (stage, source, expected) == (3, "memory", "complete")
    assert multiset == [("complete", "6")]


def test_the_two_folds_are_over_two_different_sets(doc):
    section = _section(doc, "##### 5.4.3.1 The two folds",
                       "Row 1 above is the case")
    folds = {row[0]: (row[1], row[2]) for row in _rows(section)}

    assert set(folds) == {"Inner", "Outer"}
    assert "sixteen descriptors" in folds["Inner"][0]
    assert folds["Inner"][1] == "One `directory_descriptors` state"
    assert "as a single member" in folds["Outer"][0]

    # One `partial` member leaves the unit `partial`, and the unit is the
    # single thing the descriptors contribute to the outer fold.
    members = ["partial"] + ["complete"] * 15
    assert _descriptors_unit(members) == "partial"
    assert _profile_state_two_level({
        "dos_header": "complete", "coff_header": "complete",
        "optional_header": "complete", "directory_array": "complete",
        "section_table": "complete",
        "directory_descriptors": members}) == "partial"


def test_the_nesting_never_changes_the_profile_state(doc):
    """§5.4.2 returns the weakest state present and weighs nothing, so
    folding a subset first is state-neutral. The contract has to say so:
    an argument that the nesting changed an answer would invent weighting
    semantics §5.4.2 does not have."""
    claim = _flat(_section(doc, "**The nesting does not change the profile",
                           "What the unit rule fixes"))

    assert "gives the same answer as folding everything at once" in claim
    assert "yields the identical profile state for every assignment" in claim
    assert "There is no weighting in §5.4.2" in claim
    assert "because neither is weighed" in claim

    states = ("malformed", "unavailable", "partial", "complete",
              "declared_absent")
    for members in product(states, repeat=3):
        for others in product(states, repeat=5):
            nested = _profile_state(tuple(others) + (_profile_state(members),))
            flattened = _profile_state(tuple(others) + members)
            assert nested == flattened, (members, others)


def test_the_unit_rule_is_justified_as_representation(doc):
    """Since the two arrangements agree on the token, the reasons have to
    be about what the profile carries -- or the rule reads as arbitrary."""
    reasons = _flat(_section(doc, "What the unit rule fixes",
                             "Because the two arrangements agree"))

    assert "`directory_descriptors` has a state to report" in reasons
    assert "the component named in §1.2's table would not exist" in reasons
    assert "in-scope set stays the size §5.4.1 gives it" in reasons
    assert "20 members at stage 2 and 21 at stage 3" in reasons
    assert "A member state never stands where a component state belongs" \
        in reasons

    closing = _flat(_section(doc, "Because the two arrangements agree",
                             "Nothing else in this contract nests"))
    assert "no consumer can tell them apart from the rollup token alone" \
        in closing
    assert "the right summary and the wrong profile" in closing

    # Reason 1's promise, at its source: §5.4.4 and §9 both commit to
    # per-component states, which is what the unit exists to provide.
    assert "every consumer that needs the detail reads the component states" \
        in _flat(_section(doc, "#### 5.4.4 The rollup never replaces",
                          "## §6 Staged acquisition"))


def test_the_flattened_member_count_is_fixed_by_section_four_one(
        doc, directory_rows, stage_components):
    """§4.1 keeps all sixteen descriptors in every profile, `unavailable`
    rather than omitted, so flattening gives a fixed count, not one that
    tracks `NumberOfRvaAndSizes`. Reason 2 must be that the fixed count
    is the wrong one -- an argument from a variable count would need an
    implementation that violated §4.1 as well."""
    shape = _flat(_section(doc, "### 4.1 Descriptor shape", "| Field | Meaning |"))
    assert "All sixteen indices are always represented" in shape
    assert "present with state `unavailable`, not omitted" in shape
    assert len(directory_rows) == 16

    for stage, flattened in ((2, 20), (3, 21)):
        components = set(stage_components[stage])
        assert "directory_descriptors" in components
        assert len(components) - 1 + len(directory_rows) == flattened
        assert len(components) != flattened

    assert len(set(stage_components[2])) == 5
    assert len(set(stage_components[3])) == 6


def test_a_zero_directory_count_is_the_top_level_declared_absent(doc,
                                                                 worked_examples):
    """§4.4's `declared_absent` row is a component state and belongs in
    the outer multiset; the sixteen `declared_absent` members it implies
    do not."""
    lesson = _flat(_section(doc, "- Row 6 — the one place a `declared_absent`",
                            "- Row 7 —"))

    assert "makes `directory_array` itself `declared_absent`" in lesson
    assert "fold to a `complete` unit" in lesson
    assert "none of the sixteen says anything at this level" in lesson

    assert _directory_array_state(
        count_read=True, raw=0, decoded=0, declared=0) == "declared_absent"
    assert _descriptors_unit(["declared_absent"] * 16) == "complete"

    stage, _source, multiset, expected = worked_examples[5]
    assert (stage, expected) == (2, "complete")
    assert dict(multiset) == {"complete": "4", "declared_absent": "1"}


# ── §8: every observation has an evaluable predicate ────────────────────

_UNDETERMINED = object()


def _kleene_and(left, right):
    if left is False or right is False:
        return False
    if left is _UNDETERMINED or right is _UNDETERMINED:
        return _UNDETERMINED
    return True


def _kleene_or(left, right):
    if left is True or right is True:
        return True
    if left is _UNDETERMINED or right is _UNDETERMINED:
        return _UNDETERMINED
    return False


def _observation(predicate) -> str:
    """§8.3's three-valued rule over a predicate's own truth value."""
    if predicate is _UNDETERMINED:
        return "unavailable"
    return "conflict" if predicate else "consistent"


def _basereloc_present(*, declared, bytes_read, value):
    """§4.3's presence column for index 5, in §4.3's own row order: the
    owning count first, then the descriptor's `value`, of which four
    bytes are enough."""
    if declared is None:
        return None                       # no owner, so nothing is declared
    if 5 >= declared:
        return False                      # the count denies the index
    if bytes_read < 4:
        return None
    return value != 0


def _relocation_expected(*, delta, relocs_stripped, basereloc_present):
    """§8.3's `relocation_expected` predicate, evaluated three-valued."""
    non_zero = _UNDETERMINED if delta is None else delta != 0
    stripped = _UNDETERMINED if relocs_stripped is None else relocs_stripped
    absent = (_UNDETERMINED if basereloc_present is None
              else not basereloc_present)
    return _observation(_kleene_and(non_zero, _kleene_or(stripped, absent)))


def _entry_point_in_section(*, entry_point, inside_a_decoded_section,
                            table_state):
    """§8.5's rows, as §8.3's rule over the same predicate."""
    if entry_point is None:
        return "unavailable"
    non_zero = entry_point != 0
    outside = (False if inside_a_decoded_section
               else (True if table_state in ("complete", "declared_absent")
                     else _UNDETERMINED))
    return _observation(_kleene_and(non_zero, outside))


def test_the_three_valued_rule_is_stated_before_the_predicates(doc):
    """Without it, "otherwise `consistent`" and "`unavailable` when an
    operand is uncaptured" are two rules for one input."""
    section = _section(doc, "Every one is evaluated over **established facts",
                       "| Observation | Compares | Predicate |")
    outcomes = {row[0]: row[1] for row in _rows(section)}

    assert outcomes == {
        "determine the predicate true": "`conflict`",
        "determine it false": "`consistent`",
        "do not determine it": "`unavailable`"}

    flat = _flat(section)
    assert "a disjunction with one true operand is true whatever the other is" \
        in flat
    assert "a conjunction with one false operand is false" in flat
    assert "is not on its own an answer in either direction" in flat


def test_every_observation_states_its_operands_and_short_circuits(doc):
    section = _section(doc, "| Observation | Answers from | Short-circuit |",
                       "Exactly two rows short-circuit")
    rows = {row[0]: (row[1], row[2], row[3]) for row in _rows(section)}

    named = [row[0] for row in _rows(_section(
        doc, "| Observation | Compares | Predicate |", "#### 8.3.1 Operands"))]
    assert set(rows) == set(named)

    for observation, (operands, _short, absences) in rows.items():
        assert operands, observation
        assert "`unavailable`" in absences, observation


@pytest.mark.parametrize("delta, stripped, present, expected", [
    # The review case: a zero delta with the other two unestablished.
    (0, None, None, "consistent"),
    (0, True, False, "consistent"),          # no conflict without a delta
    (None, True, False, "unavailable"),
    (0x1000, True, None, "conflict"),        # one disjunct settles it
    (0x1000, None, False, "conflict"),
    (0x1000, None, None, "unavailable"),     # neither disjunct is known
    (0x1000, False, None, "unavailable"),
    (0x1000, False, True, "consistent"),
])
def test_relocation_expected_is_determined_or_unavailable(delta, stripped,
                                                          present, expected):
    assert _relocation_expected(delta=delta, relocs_stripped=stripped,
                                basereloc_present=present) == expected


@pytest.mark.parametrize("declared, bytes_read, value, state, present", [
    # §3.5.1's rule-4 table, row for row.
    (None, 0, 0, "unavailable", None),
    (None, 4, 0x3000, "unavailable", None),   # bytes read under no owner
    (5, 0, 0, "declared_absent", False),      # denied by the count
    (16, 2, 0, "partial", None),
    (16, 4, 0, "partial", False),             # an RVA read in full, and zero
    (16, 4, 0x3000, "partial", True),
    (16, 8, 0, "declared_absent", False),
    (16, 8, 0x3000, "complete", True),
])
def test_basereloc_presence_is_carried_separately_from_the_state(
        declared, bytes_read, value, state, present):
    """The two `partial` rows are the point: presence is already settled
    there, and an observation reading the descriptor's state instead
    would see only `partial` and withhold an answer the bytes gave."""
    assert _descriptor_state_checked(declared=declared, index=5,
                                     bytes_read=bytes_read, value=value) \
        == state
    assert _basereloc_present(declared=declared, bytes_read=bytes_read,
                              value=value) is present

    # And the observation must consume presence, not the state: with a
    # non-zero delta, a `partial` descriptor whose zero RVA is fully read
    # is a conflict, which a state-only predicate could never report.
    if present is False:
        assert _relocation_expected(delta=0x1000, relocs_stripped=False,
                                    basereloc_present=present) == "conflict"


def test_the_predicate_reads_presence_not_the_descriptor_state(doc):
    rows = {row[0]: (row[1], row[2]) for row in _rows(_section(
        doc, "| Index 5 | `basereloc_descriptor_state` | `basereloc_present` |",
        "Rows 4 and 5 are why the state is not enough"))}

    assert len(rows) == 7
    assert rows["`bytes_read` 4 to 7, `value == 0`"] == ("`partial`", "`false`")
    assert rows["`bytes_read` 4 to 7, `value != 0`"] == ("`partial`", "`true`")
    assert rows["`bytes_read < 4`"][1] == "`null`"

    # §4.3's own first row, which the presence column must obey too: with
    # no captured count, four bytes at the offset establish nothing.
    assert rows["`declared_directory_count` is `null`"] == \
        ("`unavailable`", "`null`")
    assert rows["Denied by the count — `5 >= declared` (§4.3)"] == \
        ("`declared_absent`", "`false`")

    reasoning = _flat(_section(doc, "Rows 4 and 5 are why the state is not",
                               "A `null` presence therefore has two"))
    assert "would answer *no* for both" in reasoning
    assert "an RVA read in full is an RVA, whatever the unread `size` after " \
           "it says" in reasoning
    assert "Row 1 is not the mirror of that" in reasoning
    assert "rather than whatever follows a shorter array" in reasoning


def test_a_null_presence_names_whichever_component_explains_it(doc):
    """A `complete` `directory_array` beside a `null` presence is the
    case that a single-component provenance cannot explain."""
    rows = {row[0]: row[1] for row in _rows(_section(
        doc, "| Why `basereloc_present` is `null` | The component that explains it |",
        "Naming only the array would be wrong"))}

    assert len(rows) == 2
    count_gap, = [v for k, v in rows.items() if "own four bytes" in k]
    descriptor_gap, = [v for k, v in rows.items()
                       if "fewer than four of its bytes" in k]

    assert count_gap == "`directory_array`"
    assert "`directory_descriptors`" in descriptor_gap
    assert "Index 5's descriptor" in descriptor_gap

    closing = _flat(_section(doc, "Naming only the array would be wrong",
                             "#### 3.5.2 Why there is no aggregate state"))
    assert "a `complete` `directory_array` sits beside a `null` presence" \
        in closing
    assert "would find nothing that explains the `null`" in closing

    # §8.3's own predicate must name presence, not the state.
    predicate, = [row[2] for row in _rows(_section(
        doc, "| Observation | Compares | Predicate |", "#### 8.3.1 Operands"))
        if row[0] == "`relocation_expected`"]
    assert "`basereloc_present` is false" in predicate
    assert "declared_absent" not in predicate


@pytest.mark.parametrize("entry, inside, table, expected", [
    # The review case: a zero entry point with no section table at all.
    (0, False, "unavailable", "consistent"),
    (None, False, "complete", "unavailable"),
    (0x1000, True, "partial", "consistent"),      # a hit needs no more rows
    (0x1000, False, "complete", "conflict"),
    (0x1000, False, "partial", "unavailable"),    # an undecoded entry may hold it
    (0x1000, False, "unavailable", "unavailable"),
])
def test_entry_point_in_section_is_determined_or_unavailable(entry, inside,
                                                             table, expected):
    assert _entry_point_in_section(entry_point=entry,
                                   inside_a_decoded_section=inside,
                                   table_state=table) == expected


def test_the_two_short_circuits_are_justified_as_false_conjuncts(doc):
    section = _flat(_section(doc, "Exactly two rows short-circuit",
                             "### 8.4 `machine_vs_format`"))

    assert "names a value of their own first operand" in section
    assert "make their conflict impossible" in section
    assert "would withhold an answer the established facts already give" \
        in section

    # The count and the table must agree: a relaxed expectation is not a
    # short-circuit, so `EBC` may not be counted as one.
    assert "`EBC` is not among them" in section
    assert "A short-circuit needs an established fact that settles the " \
           "predicate" in section

    short_circuits = [row[2] for row in _rows(_section(
        doc, "| Observation | Answers from | Short-circuit |",
        "Exactly two rows short-circuit"))]
    assert sum(1 for cell in short_circuits
               if not cell.startswith("None")) == 2, short_circuits
    assert "would withhold an answer the established facts already give" \
        in section


def test_the_observation_set_is_five_rows_without_the_deferred_one(doc):
    section = _section(doc, "| Observation | Compares | Predicate |",
                       "#### 8.3.1 Operands")
    names = [row[0] for row in _rows(section)]

    assert names == ["`base_vs_preferred`", "`relocation_expected`",
                     "`machine_vs_format`", "`entry_point_in_section`",
                     "`size_vs_image_extent`"]
    assert "module_identity" not in _flat(section)

def test_the_deferred_observation_is_named_out_of_scope(doc):
    section = _section(doc, "### 8.7 Deferred", "## §9 Projection rules")

    flat = _flat(section)
    assert "Export Directory" in flat and "Debug Directory" in flat
    assert "§0.2" in flat


_EXPECTED_FORMATS = {"PE32", "PE32+", "unconstrained"}


def test_machine_format_table_covers_every_named_machine(doc):
    section = _section(doc, "### 8.4 `machine_vs_format`",
                       "`EBC` is `unconstrained`")
    documented = {int(row[1].strip("`"), 16): (row[0].strip("`"), row[2])
                  for row in _rows(section)}

    assert set(documented) == set(_KNOWN_MACHINES)
    for value, (name, expected) in documented.items():
        assert name == _KNOWN_MACHINES[value]
        assert expected in _EXPECTED_FORMATS


def test_an_unnamed_machine_makes_the_observation_unavailable(doc):
    """The expectation is this contract's own, so a machine it does not
    name has no second operand -- not an agreement, and not a conflict."""
    predicate, = [row[2] for row in _rows(
        _section(doc, "| Observation | Compares | Predicate |",
                 "#### 8.3.1 Operands"))
        if row[0] == "`machine_vs_format`"]

    assert predicate.startswith("`conflict` when §8.4 defines a width")
    assert "§8.4 defining none leaves it undetermined" in predicate

    absence, = [row[3] for row in _rows(
        _section(doc, "| Observation | Answers from | Short-circuit |",
                 "Exactly two rows short-circuit"))
        if row[0] == "`machine_vs_format`"]
    assert "§8.4 names no width for the value → `unavailable`" in absence

    cases = {row[0]: (row[1], row[2]) for row in _rows(
        _section(doc, "| The `Machine` value | The expectation |",
                 "The second operand of this comparison"))}
    assert len(cases) == 4
    unnamed, = [v for k, v in cases.items() if k == "Not named here"]
    assert unnamed == ("None is defined", "`unavailable`")

    # `EBC` relaxes the expectation; it does not remove the operand. The
    # two `EBC` rows must therefore differ only in whether the width was
    # established, and disagree on the result.
    ebc = {condition: value for condition, value in cases.items()
           if condition.startswith("`EBC`")}
    assert len(ebc) == 2
    assert ebc["`EBC`, `is_pe32_plus` established"][1] == \
        "`consistent`, never `conflict`"
    assert ebc["`EBC`, `is_pe32_plus` `null`"][1] == "`unavailable`"
    assert len({expectation for expectation, _result in ebc.values()}) == 1

    reasoning = _flat(_section(doc, "The second operand of this comparison",
                               "### 8.5 `entry_point_in_section`"))
    assert "an expectation **this contract supplies**" in reasoning
    assert "`EBC` has one — \"either\"" in reasoning
    assert "would claim an agreement nobody checked" in reasoning


def test_the_unnamed_machine_case_is_not_merged_with_ebc(doc):
    """Both lack a width, and they are different facts: `EBC` has an
    expectation any width satisfies, an unnamed machine has none."""
    section = _flat(_section(doc, "A `Machine` value this contract does not name",
                             "| The `Machine` value | The expectation |"))

    assert "is a different case" in section
    assert "the two are never merged" in section

    # And §8.4 no longer defers to a `malformed` COFF header for the case.
    whole = _flat(_section(doc, "### 8.4 `machine_vs_format`",
                           "### 8.5 `entry_point_in_section`"))
    assert "makes the COFF header `malformed`" not in whole


def test_the_entry_point_rows_cover_both_operands(doc):
    """The predicate has two operands, so the table needs both: a row
    keyed on the entry point alone cannot say whether an entry point
    outside every decoded section is a conflict or a gap."""
    section = _section(doc, "The **first matching row**, over both operands",
                       "Rows 4 and 5 are §8.3's three-valued rule")
    rows = [(row[0], row[1], row[2]) for row in _rows(section)]

    assert [row[2] for row in rows] == [
        "`unavailable`", "`consistent`", "`consistent`", "`conflict`",
        "`unavailable`"]
    assert rows[0][0] == "`null`"
    assert rows[1] == ("`0`", "any, including `unavailable`", "`consistent`")
    assert "inside some **decoded** section" in rows[2][0]
    assert rows[3][1] == "`complete` or `declared_absent`"
    assert rows[4][1] == "`partial` or `unavailable`"

    assert "VirtualSize" in _flat(_section(
        doc, "### 8.5 `entry_point_in_section`", "The **first matching row**"))


def test_an_entry_point_outside_a_partial_table_is_not_a_conflict(doc):
    """§8.3's three-valued rule, at the one place a `partial` operand can
    hide the fact that would settle the predicate."""
    reasoning = _flat(_section(doc, "Rows 4 and 5 are §8.3's three-valued rule",
                               "An entry point of `0` is `consistent`"))

    assert "only when there are no sections left unexamined" in reasoning
    assert "an undecoded entry could be the one containing it" in reasoning
    assert "Row 3 needs no such qualification" in reasoning

    zero = _flat(_section(doc, "An entry point of `0` is `consistent`",
                          "### 8.6 `size_vs_image_extent`"))
    assert "without consulting the section table at all" in zero
    assert "a zero one settles the predicate alone" in zero

# ── §7: the cache key identifies which source, not just which kind ──────

def test_the_cache_key_carries_a_per_source_identity(doc):
    section = _section(doc, "### 7.1 The key", "#### 7.1.1")
    components = [row[0] for row in _rows(section)]

    assert "`source_kind`" in components
    assert "`source_identity`" in components


def test_the_cache_key_is_the_request_and_nothing_it_produced(doc):
    """A key is computed before the acquisition it guards, so no result
    of that acquisition can be in it."""
    section = _section(doc, "### 7.1 The key", "**Every component of the key")
    components = [row[0] for row in _rows(section)]

    assert "`requested_stage`" in components
    for produced in ("Highest completed stage", "Bounded stop",
                     "Profile state"):
        assert produced not in components

    rationale = _flat(_section(doc, "**Every component of the key is known",
                               "#### 7.1.1"))
    assert "nothing an acquisition *produces* can be part of it" in rationale
    assert "A key built from a result cannot be used to look up that result" \
        in rationale
    assert "The match rule reads none of them" in rationale


def test_the_requested_stage_keeps_the_two_profiles_apart(doc,
                                                          stage_components):
    """The collision the key must prevent: same span, same highest
    completed stage, different requests, different states."""
    rationale = _flat(_section(doc, "`requested_stage` is what keeps two",
                               "The completed stage is **result metadata**"))

    assert "share a highest completed stage of `1`" in rationale
    assert "they asked different questions" in rationale
    assert "neither answers for the other" in rationale

    succeeded_at_one = _profile_state(["complete"] * len(stage_components[1]))
    failed_at_three = _profile_state(
        ["complete"] * len(stage_components[1])
        + ["unavailable"] * (len(stage_components[3]) - len(stage_components[1])))

    assert succeeded_at_one == "complete"
    assert failed_at_three == "unavailable"


def test_the_completed_stage_is_result_metadata(doc):
    section = _flat(_section(doc, "The completed stage is **result metadata**",
                             "#### 7.1.1"))

    assert "`highest_completed_stage` says how far the acquisition got" in section
    assert "§5.4's" in section and "§6.2's bounded stop" in section
    assert "The match rule reads none of them" in section


def test_a_bounded_stop_is_excluded_for_the_same_reason(doc):
    section = _flat(_section(doc, "A bounded stop (§6.2) is deliberately",
                             "### 7.2 The reuse rule"))

    assert "for the same reason the completed stage is not" in section
    assert "the key exists to be computed before the acquisition runs" in section
    assert "caches that miss differently for the same request" in section


def test_an_identical_request_reuses_even_a_failed_result(doc):
    """The reuse rule and §7.3 have to agree: a stage-3 request that
    stopped at stage 1 is shared by the next identical stage-3 request,
    or four consumers repeat one failing read."""
    rule = _flat(_section(doc, "> A cached profile satisfies a request when",
                          "Every component of §7.1's key appears"))

    assert "and the same `requested_stage`. Otherwise the cache misses" in rule
    assert "completed stage" not in rule

    section = _flat(_section(doc, "**An identical request reuses the cached",
                             "**Only a different question acquires again.**"))
    assert "is `partial` or `unavailable`, and the next identical stage-3 " \
           "request is answered from it" in section
    assert "would contradict §7.3" in section
    assert "multiply the cost of exactly the images that already cost the most" \
        in section
    assert "§10.2 makes acquisition deterministic" in section
    assert "A cached failure is evidence, not a hole to be retried" in section

    shared = _flat(_section(doc, "### 7.3 One acquisition per invocation",
                            "A cache hit does not upgrade"))
    assert "nothing about how it turned out" in shared
    assert "an acquisition that fell short is shared on exactly the terms " \
           "one that succeeded is" in shared


def test_only_a_key_miss_acquires_again(doc):
    section = _section(doc, "| The new request | Result |",
                       "The last row is a deliberate cost")
    rows = [(row[0], row[1]) for row in _rows(section)]

    reuse = [request for request, result in rows if result.startswith("Reuse")]
    miss = [request for request, result in rows if result.startswith("Miss")]

    assert reuse == ["The same key",
                     "A span the cached `requested` contains, same "
                     "`requested_stage`"]
    assert len(miss) == 3
    assert any("higher `requested_stage`" in request for request in miss)
    assert any("lower `requested_stage`" in request for request in miss)
    assert any("does not contain" in request for request in miss)

    assert "whatever state the cached profile carries" in rows[0][1]


def _covering_entry(candidates, request):
    """§7.2.1's selection: shortest covering span, lowest base on a tie.

    `candidates` and `request` are `(base, length)`; a candidate covers
    the request when it contains it.
    """
    covering = [(base, length) for base, length in candidates
                if base <= request[0]
                and base + length >= request[0] + request[1]]
    if not covering:
        return None
    return min(covering, key=lambda span: (span[1], span[0]))


def test_two_covering_entries_have_one_documented_winner(doc):
    """Both entries satisfy §7.2's containment test, and they can carry
    different states, ranges and attributions -- so without a rule the
    same request gets different answers on different runs (§10.2)."""
    section = _flat(_section(doc, "#### 7.2.1 Choosing among covering entries",
                             "Those two keys are a total order"))

    assert "a 4 KiB acquisition and a 2 KiB acquisition" in section
    assert "cannot be left to whichever the cache happens to iterate first" \
        in section
    assert "the **shortest `requested` span**" in section
    assert "the one with the **lowest `base_address`**" in section

    reasoning = _flat(_section(doc, "Those two keys are a total order",
                               "The chosen profile is returned"))
    assert "the choice is unique and the same on every run" in reasoning
    assert '"contains" is a partial order' in reasoning
    assert "least evidence beyond the request" in reasoning

    # The review's own case, and the tie the length alone cannot settle.
    base = 0x140000000
    assert _covering_entry([(base, 4096), (base, 2048)], (base, 1024)) \
        == (base, 2048)
    assert _covering_entry([(base, 4096), (base - 64, 4096)], (base, 1024)) \
        == (base - 64, 4096)
    assert _covering_entry([(base, 512)], (base, 1024)) is None


def test_the_chosen_profile_keeps_its_own_provenance(doc):
    section = _flat(_section(doc, "The chosen profile is returned",
                             "### 7.3 One acquisition per invocation"))

    assert "never the narrower span that was asked for" in section
    assert "a record of the acquisition that produced it" in section
    assert "the same bytes describe two different requests" in section


def test_a_narrow_profile_is_never_full_scope_evidence(doc):
    """The rule survives the change, but its reason moves: a narrow read
    misses on its key, not on how far its acquisition got."""
    section = _flat(_section(doc, "A partial or targeted profile is therefore",
                             "### 7.3 One acquisition per invocation"))

    assert "not because its acquisition fell short" in section
    assert "are a different key" in section
    assert "another consumer's completeness claim" in section


def test_every_source_kind_has_a_documented_identity(doc):
    declared = _source_kinds(doc)

    section = _section(doc, "#### 7.1.1 `source_identity`",
                       "Every one is an integer or a fixed token")
    keyed = {row[0].strip("`") for row in _rows(section)}

    assert keyed == declared


def test_no_cache_key_component_is_an_attacker_controlled_string(doc):
    """§10.3 forbids using such a string as a lookup key; §7.1.1 must not
    quietly put a module path or a reference path into one."""
    section = _section(doc, "#### 7.1.1 `source_identity`",
                       "#### 7.1.2")
    identities = " ".join(row[1] for row in _rows(section))

    for forbidden in ("path", "name", "hash"):
        assert forbidden not in identities.lower(), forbidden

    flat = _flat(section)
    assert "Every one is an integer or a fixed token" in flat
    assert "They identify the source to a human. They do not identify it " \
           "to the cache." in flat


def test_every_projection_surface_carries_the_truncation_flag(doc):
    """§10.3.1 keeps the marker out of the value because an in-band one is
    forgeable. That only works if every surface shows the out-of-band
    flag; otherwise the design degrades to invisible truncation."""
    section = _section(doc, "| Surface | Shows |", "Four rules bind all three")
    shows = {row[0]: row[1] for row in _rows(section)}

    assert len(shows) == 3
    for surface, listed in shows.items():
        assert "truncated" in listed, surface

    assert "out-of-band `truncated` indication" in shows["Default console"]


def test_hiding_the_truncation_flag_is_named_as_a_false_claim(doc):
    section = _flat(_section(doc, "3. **A shortened string is never shown",
                             "4. **Addresses are formatted"))

    assert "a marker inside the value is forgeable" in section
    assert "Hiding `truncated` is rule 2's case exactly" in section
    assert "it asserts a string is complete" in section
    assert "never by editing the string" in section

    tail = _flat(_section(doc, "Rule 3 has a second consumer-visible",
                          "This contract does not select a schema version"))
    assert "an identity that appears complete beside an observation that " \
           "declined to evaluate" in tail


def test_the_string_length_bound_is_frozen_not_described(doc):
    """"Bounded in length" is not a rule an implementation can follow:
    the limit, its unit, the truncation rule, and how truncation is
    recorded all have to be stated."""
    section = _section(doc, "#### 10.3.1 The length bound, frozen", "### 10.4")
    rules = {row[0]: row[1] for row in _rows(section)}

    assert rules["Limit"] == "`MAX_STRING_BYTES` = `4096`"
    assert "UTF-8 **bytes**" in rules["Counted in"]
    assert "not code points" in rules["Counted in"]
    assert "never split a code point" in rules["On exceeding"]
    assert rules["Recorded as"] == "A `truncated` flag on the field itself"


def test_the_string_bound_matches_the_codebases_existing_ceiling(doc, documented_constants):
    from dumpex.core.memory import MAX_HANDLE_STRING_BYTES

    section = _flat(_section(doc, "#### 10.3.1 The length bound, frozen",
                             "Two consequences are normative"))
    documented = int(re.search(r"`MAX_STRING_BYTES` = `(\d+)`", section).group(1))

    assert documented == MAX_HANDLE_STRING_BYTES
    assert "does not introduce a second length regime" in section


def test_a_truncated_string_is_neither_compared_nor_matched(doc):
    section = _flat(_section(doc, "Two consequences are normative",
                             "`normalize_windows_path()` deliberately"))

    assert "A truncated string is never compared" in section
    assert "A comparison with a truncated operand is `unavailable`" in section
    assert "never becomes an identity" in section

    tail = _flat(_section(doc, "`normalize_windows_path()` deliberately",
                          "## §11"))
    assert "does not truncate" in tail


def test_the_hostile_string_rule_and_the_cache_key_agree(doc):
    section = _flat(_section(doc, "### 10.3 Hostile input", "### 10.4"))

    assert "never used as a filesystem path, a lookup key" in section
    assert "every component of the cache key is an integer or a fixed token" \
        in section


def test_the_disk_ordinal_trade_off_is_stated(doc):
    """An invocation-local ordinal cannot dedupe two paths naming one
    file; the contract must say so rather than leave it to be discovered."""
    section = _flat(_section(doc, "#### 7.1.2 What a `disk_reference` ordinal",
                             "### 7.2 The reuse rule"))

    assert "cannot recognize that two references name the same file" in section
    assert "costs one extra read" in section
    assert "unrecoverable evidence corruption" in section


def test_content_hashing_is_ruled_out_with_its_reason(doc):
    """A hash built to make a cache key runs before the lookup it guards:
    unbounded I/O outside every §1.5 budget, and racy besides."""
    section = _flat(_section(doc, "It also removes an obligation",
                             "### 7.2 The reuse rule"))

    assert "runs before the lookup it guards" in section
    assert "outside every acquisition budget in §1.5" in section
    assert "one file handle opened once for the invocation" in section
    assert "does not hash reference files for identity" in section


def test_the_two_collisions_are_named(doc):
    section = _section(doc, "Without it the key collides",
                       "A bounded stop (§6.2)")

    assert "no** `actual_base` at all" in _flat(section)
    assert "separately attributable" in _flat(section)

def test_the_size_predicate_names_both_va_range_tables(doc):
    """Telling "the image is smaller than it claims" from "the dump
    stopped writing" needs both tables; naming only one leaves the
    predicate for each consumer to invent."""
    section = _section(doc, "### 8.6 `size_vs_image_extent`",
                       "### 8.7 Deferred")

    assert "enumerate_captured_segments()" in _flat(section)
    assert "enumerate_captured_regions()" in _flat(section)
    assert hasattr(va_range, "enumerate_captured_segments")
    assert hasattr(va_range, "enumerate_captured_regions")


def test_unexamined_ranges_are_typed_by_the_profiles_address_space(doc):
    """§5.1.1 forbids `VirtualRange` for a disk profile, so §5.2 must not
    require every unexamined range to be one."""
    section = _section(doc, "### 5.2 Unexamined ranges",
                       "The two are never mixed")
    rows = {row[0]: row[2] for row in _rows(section)}

    memory = "`peb_image_base`, `module_list_entry`, `memory_candidate`"
    assert rows[memory] == "`VirtualRange`"
    assert rows["`disk_reference`"] == "The file-offset range type of §5.1.1"

    rationale = _flat(_section(doc, "The two are never mixed",
                               "An unexamined range is a statement"))
    assert "would construct without error and then lie" in rationale
    assert "tell the two apart from the value it is handed" in rationale


def test_the_section_five_preamble_does_not_overreach(doc):
    """The preamble must not claim unexamined ranges apply to both
    sources unchanged, which is what contradicted §5.1.1."""
    section = _flat(_section(doc, "**This subsection applies to memory-sourced",
                             "Each acquisition records all three"))

    assert "take their **type** from the profile's own address space" in section
    assert "not all of it identically" in section


def test_the_extent_algorithm_groups_by_allocation_base(doc):
    """Address adjacency does not delimit an image: a heap or the next
    image can abut it. `AllocationBase` is what groups one reservation,
    and `va_range` carries it."""
    section = _section(doc, "#### 8.6.1 Computing the mapped extent",
                       "#### 8.6.2")

    assert "`AllocationBase` is what actually groups one reservation" in _flat(section)
    assert "`allocation_base` to equal `actual_base`" in _flat(section)
    assert "different `allocation_base` are excluded however adjacent" in _flat(section)
    assert "allocation_base" in va_range.CapturedRegion.__dataclass_fields__


def test_memory_outside_the_image_does_not_disable_the_observation(doc):
    """A real dump captures a heap, a stack, and other images. Treating
    captured bytes outside this image as a disagreement would make the
    observation `unavailable` for every dump ever taken."""
    section = _section(doc, "#### 8.6.2 Computing the captured extent",
                       "The image is **fully captured**")
    flat = _flat(section)

    assert "Discard every segment disjoint from the mapped extent" in flat
    assert "say nothing about it" in flat
    assert "Clip every remaining segment" in flat
    assert "crossing one is ordinary and is never a conflict" in flat
    assert "Only within the mapped extent does disagreement matter" in flat


def test_a_hole_inside_the_image_is_a_short_capture_not_a_conflict(doc):
    section = _flat(_section(doc, "The image is **fully captured**",
                             "> Every `unavailable` above"))

    assert "union of the clipped spans equals the mapped extent" in section
    assert "is a short capture, not a conflict" in section


def test_the_extent_algorithm_refuses_to_answer_over_lossy_tables(doc):
    """`enumerate_*` skip descriptors the value model cannot represent;
    the skipped one might have been the one that mattered."""
    mapped = _section(doc, "#### 8.6.1 Computing the mapped extent",
                      "#### 8.6.2")
    captured = _section(doc, "#### 8.6.2 Computing the captured extent",
                        "> Every `unavailable` above")

    assert "`skipped`" in mapped and "`skipped`" in captured
    assert "not contiguous" in _flat(mapped)
    assert "clipped spans that overlap each other" in _flat(captured)
    assert "Discard every segment disjoint from the mapped extent" in _flat(captured)
    assert "skipped" in va_range.CapturedEnumeration.__dataclass_fields__


def test_the_extent_algorithm_prefers_silence_to_accusation(doc):
    section = _section(doc, "> Every `unavailable` above", "#### 8.6.3")

    assert "never a reason to accuse" in _flat(section)


# §8.6.3's rows, as predicates over the three independent facts the table
# actually reads. `fits_single_region` is the variable the table needs to
# keep rows 3 and 4 apart -- without it, "fits the extent" swallows
# "exceeds one region but fits the extent".
_SIZE_ROWS = (
    (lambda resolved, captured, region, extent: not resolved, "unavailable"),
    (lambda resolved, captured, region, extent: resolved and not captured,
     "unavailable"),
    (lambda resolved, captured, region, extent:
     resolved and captured and region, "consistent"),
    (lambda resolved, captured, region, extent:
     resolved and captured and not region and extent, "consistent"),
    (lambda resolved, captured, region, extent:
     resolved and captured and not extent, "conflict"),
)


def _size_matching_rows(*, extents_resolved, fully_captured,
                        fits_single_region, fits_mapped_extent):
    """Every row whose condition holds, not just the first."""
    return [index for index, (condition, _result) in enumerate(_SIZE_ROWS)
            if condition(extents_resolved, fully_captured,
                         fits_single_region, fits_mapped_extent)]


def _size_vs_image_extent(**facts) -> str:
    matched = _size_matching_rows(**facts)
    return _SIZE_ROWS[matched[0]][1] if matched else "consistent"


def test_the_size_predicate_rows_do_not_overlap(doc):
    """Mutual exclusivity has to hold over `fits_single_region` too. A
    row reading "fits the extent" is implied by "exceeds one region but
    fits the extent", so the two would overlap and first-match would be
    load-bearing where the contract says it is not."""
    section = _section(doc, "#### 8.6.3 The predicate",
                       "Rows 3 to 5 each say")
    conditions = [row[0] for row in _rows(section)]

    assert "**first matching row**" in _flat(
        _section(doc, "#### 8.6.3 The predicate", "| Condition | Result |"))
    assert "fits within the single region containing `actual_base`"         in conditions[2]
    assert "exceeds that region but fits the extent" in conditions[3]
    for condition in conditions[2:]:
        assert "fully captured" in condition, condition

    # Two dependencies among the facts, both from §8.6.1: a region lies
    # inside the extent, so fitting the region implies fitting the extent;
    # and an extent that was never produced cannot be fully captured.
    for resolved, captured, region, extent in product((True, False), repeat=4):
        if region and not extent:
            continue
        if captured and not resolved:
            continue
        matched = _size_matching_rows(
            extents_resolved=resolved, fully_captured=captured,
            fits_single_region=region, fits_mapped_extent=extent)
        assert len(matched) == 1, (resolved, captured, region, extent, matched)

    # The overlapping input: capture stopped, yet the declared size fits.
    assert _size_vs_image_extent(
        extents_resolved=True, fully_captured=False,
        fits_single_region=True, fits_mapped_extent=True) == "unavailable"
    assert _size_vs_image_extent(
        extents_resolved=True, fully_captured=True,
        fits_single_region=True, fits_mapped_extent=True) == "consistent"
    assert _size_vs_image_extent(
        extents_resolved=True, fully_captured=True,
        fits_single_region=False, fits_mapped_extent=True) == "consistent"
    assert _size_vs_image_extent(
        extents_resolved=True, fully_captured=True,
        fits_single_region=False, fits_mapped_extent=False) == "conflict"
    assert _size_vs_image_extent(
        extents_resolved=False, fully_captured=True,
        fits_single_region=True, fits_mapped_extent=True) == "unavailable"


def test_the_multi_region_row_states_why_it_exists(doc):
    """Row 4 is the reason the observation is not a region comparison;
    dropping it would make an ordinary multi-region image a conflict."""
    section = _flat(_section(doc, "Row 4 is the row that has to exist",
                             "Row 2 is deliberately the stronger claim"))

    assert "declares a `SizeOfImage` larger than any one of them" in section
    assert "would report `conflict` for an ordinary multi-region image" in section
    assert "every region sharing the reservation's `allocation_base`" in section


def test_the_stronger_row_two_claim_is_argued(doc):
    section = _flat(_section(doc, "Rows 3 to 5 each say",
                             "A missing region table"))

    assert "none of them overlaps row 1" in section
    assert "an extent that was never produced cannot be fully captured" \
        in section
    assert "or row 2" in section
    assert "they partition what is left" in section
    assert "No two of those can hold at once" in section
    assert "gives the same answer for every input" in section
    assert "a completeness claim §5.1 keeps separate everywhere else" in section


def test_a_short_capture_is_never_a_size_conflict(doc):
    section = _section(doc, "#### 8.6.3 The predicate", "A missing region")
    outcomes = [(row[0], row[1]) for row in _rows(section)]

    assert [outcome for _condition, outcome in outcomes] == [
        "`unavailable`", "`unavailable`", "`consistent`", "`consistent`",
        "`conflict`"]

    by_outcome = {}
    for condition, outcome in outcomes:
        by_outcome.setdefault(outcome, []).append(condition)

    assert any("did not produce an extent" in condition
               for condition in by_outcome["`unavailable`"])
    assert any("capture stopped" in condition
               for condition in by_outcome["`unavailable`"])
    assert by_outcome["`conflict`"] == [
        "The mapped extent is fully captured and `SizeOfImage` exceeds it"]


# ── §11.1: the "available now" list is the shipped parser's own result ──

_BACKTICKED_RE = re.compile(r"`([a-z0-9_]+)`")


def test_available_now_field_list_matches_the_shipped_parser(doc):
    section = _section(doc, "### 11.1 Available now, no new parsing",
                       "Consumers project **different subsets**")
    documented = set(_BACKTICKED_RE.findall(
        section.split("already retains:", 1)[1]))
    produced = set(parse_pe_header(build_pe_header([TEXT_SECTION_RX])))

    # `sections` and `data_directories` are named in prose rather than as
    # field literals; every other key the parser returns is listed.
    assert documented | {"sections", "data_directories"} == produced


_CONSUMER_PROJECTIONS = {
    "`process_info.MainImagePeFacts`": MainImagePeFacts,
    "`hunt.injection.models.PeHeaderInfo`": InjectionPeHeaderInfo,
    "`hunt.encoding.models.PeHeaderInfo`": EncodingPeHeaderInfo,
}


def test_consumer_projection_sizes_match_the_shipped_dataclasses(doc):
    """The document must not claim every consumer projects every field:
    each carries only what its own output needs, and a shared profile has
    to replace three differently-shaped projections."""
    section = _section(doc, "Consumers project **different subsets**",
                       "No consumer projects the whole dict")
    documented = {row[0]: row[1] for row in _rows(section)}

    for name, cls in _CONSUMER_PROJECTIONS.items():
        assert documented[name] == str(len(cls.__dataclass_fields__)), name


def test_no_consumer_projects_the_whole_parser_result():
    produced = set(parse_pe_header(build_pe_header([TEXT_SECTION_RX])))
    subsets = [set(cls.__dataclass_fields__)
               for cls in _CONSUMER_PROJECTIONS.values()]

    for fields in subsets:
        assert fields < produced          # a strict subset, never equal
    assert len({frozenset(fields) for fields in subsets}) == len(subsets)


def test_the_documented_omissions_are_really_omitted():
    injection = set(InjectionPeHeaderInfo.__dataclass_fields__)
    encoding = set(EncodingPeHeaderInfo.__dataclass_fields__)

    assert not injection & {"sections", "data_directories", "e_lfanew",
                            "machine", "time_date_stamp", "size_of_image"}
    assert not encoding & {"declared_directory_count", "directories_complete",
                           "insufficient_data"}
    assert set(MainImagePeFacts.__dataclass_fields__) == {
        "data_directories", "declared_directory_count", "is_pe32_plus",
        "insufficient_data"}


# ── §11.6: the bridge covers every shipped main-image state ─────────────

class _Facts:
    def __init__(self, insufficient_data):
        self.insufficient_data = insufficient_data


class _Claim:
    def __init__(self, checked, valid, insufficient_data=False):
        self.checked = checked
        self.valid = valid
        self.pe_facts = _Facts(insufficient_data) if checked else None


_SHIPPED_MAIN_IMAGE_STATES = (
    (None, _Claim(False, None)),
    (0x140000000, _Claim(False, None)),
    (0x140000000, _Claim(True, False, insufficient_data=True)),
    (0x140000000, _Claim(True, False, insufficient_data=False)),
    (0x140000000, _Claim(True, True)),
)


def test_state_bridge_enumerates_every_shipped_main_image_state(doc):
    section = _section(doc, "### 11.6 Vocabulary bridge",
                       "Two rules govern the coexistence")
    documented = [row[0].strip("`") for row in _rows(section)]
    # §1.3's spelling: the document writes the absent state as `null`.
    produced = [state if (state := _classify_main_image_state(base, claim))
                else "null"
                for base, claim in _SHIPPED_MAIN_IMAGE_STATES]

    assert documented == produced
    assert len(set(produced)) == len(produced)


def test_the_limitation_codes_stay_the_coverage_authority(doc):
    section = _section(doc, "Two rules govern the coexistence", "## §12")

    flat = _flat(section)
    assert "PROCESS_MAIN_IMAGE_*" in flat
    assert "never changes a coverage status or an exit code" in flat


# ── §1.2/§5.3: uncaptured and malformed stay distinguishable ────────────

def test_a_truncated_header_is_a_capture_gap_not_a_defect():
    truncated = build_pe_header([TEXT_SECTION_RX])[:0x90]
    result = parse_pe_header(truncated)

    assert result["valid"] is False
    assert result["insufficient_data"] is True


def test_a_complete_header_with_an_impossible_value_is_a_defect():
    unknown_machine = max(_KNOWN_MACHINES) + 1
    assert unknown_machine not in _KNOWN_MACHINES
    result = parse_pe_header(build_pe_header([TEXT_SECTION_RX],
                                              machine=unknown_machine))

    assert result["valid"] is False
    assert result["insufficient_data"] is False


def test_a_short_section_table_is_a_capture_gap_not_a_defect():
    full = build_pe_header([TEXT_SECTION_RX], trailing_padding=0)
    result = parse_pe_header(full[:-8])

    assert result["valid"] is False
    assert result["insufficient_data"] is True
    assert result["number_of_sections"] == 1
    assert result["sections"] == []


# ── §1.3: an uncaptured count and a declared zero stay distinguishable ──

def test_uncaptured_directory_count_is_null_never_zero():
    """A `0` here would be a positive "this image declares no directories"
    claim, which nothing was read to support."""
    header = build_pe_header([TEXT_SECTION_RX], trailing_padding=0)
    opt_off = header.index(b"PE\x00\x00") + 24
    result = parse_pe_header(header[:opt_off + 108])

    assert result["declared_directory_count"] is None
    assert result["directories_complete"] is False


def test_a_captured_zero_directory_count_is_zero_never_null():
    """The other half of §1.3: established-and-none is not could-not-tell.
    `build_pe_header()` leaves the optional-header tail zeroed."""
    result = parse_pe_header(build_pe_header([TEXT_SECTION_RX]))

    assert result["declared_directory_count"] == 0
    assert result["data_directories"] == []
    assert result["directories_complete"] is True

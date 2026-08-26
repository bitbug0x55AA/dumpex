"""Production semantic truth tables for the live Recon contract.

The cases in this module execute shipped functions directly. Developer
Markdown is explanatory input for humans and is never parsed or executed here.
"""
import inspect
import struct

import pytest

from dumpex.core.pe_utils import (
    parse_pe_header, _resolve_directory_present, _select_iat_outcome,
)
from dumpex.commands.process import _select_console_branch, _select_iat_source_state
from dumpex.core.process_info import (
    MAX_ENV_BYTES, MAX_ENV_ENTRIES, classify_process_create_time, normalize_command_line,
    normalize_image_base, normalize_pid, normalize_windows_path, resolve_module_by_base,
    walk_environment_block,
)
from dumpex.output.coverage import (
    CoverageLimitation, LimitationCode, render_limitation,
)

# ── production functions under test ───────────────────────────────────

@pytest.fixture(scope="module")
def resolve_present():
    return _resolve_directory_present


@pytest.fixture(scope="module")
def select_console_branch():
    return _select_console_branch


@pytest.fixture(scope="module")
def select_iat_source_state():
    return _select_iat_source_state


def _render_incomplete(affected_count):
    """Use the real construction and rendering path for this code."""
    return render_limitation(CoverageLimitation(
        code=LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE, source="iat",
        affected_count=affected_count))


# ── §3.5.2: presence resolver truth table ───────────────────────────────
#
# (test id, index, declared_directory_count, data_directories, expected)
# Covers the complete RVA/Size-independence truth table.
_PRESENCE_CASES = [
    ("count_none",                     1, None, [],                         None),
    ("declared_zero",                  1, 0,    [],                         False),
    ("index1_ge_declared_count_1",     1, 1,    [(0, 0)],                   False),
    ("index1_uncaptured_16_1",         1, 16,   [(0, 0)],                   None),
    ("index1_00_16_6",                 1, 16,   [(0, 0)] * 6,               False),
    ("index1_zero_rva_nonzero_size",   1, 16,   [(0, 0), (0, 0x40), (0, 0), (0, 0), (0, 0), (0, 0)], False),
    ("index1_nonzero_rva_zero_size",   1, 16,   [(0, 0), (0x2000, 0), (0, 0), (0, 0), (0, 0), (0, 0)], True),
    ("index1_nonzero_16_6",            1, 16,   [(0, 0), (0x2000, 0x40), (0, 0), (0, 0), (0, 0), (0, 0)], True),
    ("index12_uncaptured_16_6",        12, 16,  [(0, 0)] * 6,               None),
    ("index12_zero_rva_nonzero_size",  12, 16,  [(0, 0)] * 12 + [(0, 0x40)], False),
    ("index12_nonzero_rva_zero_size",  12, 16,  [(0, 0)] * 12 + [(0x3000, 0)], True),
    ("index12_00_16_13",               12, 16,  [(0, 0)] * 13,              False),
    ("index12_nonzero_16_13",          12, 16,  [(0, 0)] * 12 + [(0x3000, 0x20)], True),
    ("declared_2_index1_00",           1, 2,    [(0, 0), (0, 0)],           False),
    ("declared_2_index1_nonzero",      1, 2,    [(0, 0), (0x1000, 0x40)],   True),
    ("declared_2_index12_undeclared",  12, 2,   [(0, 0), (0x1000, 0x40)],   False),
]


@pytest.mark.parametrize("case_id,index,declared,dd,expected", _PRESENCE_CASES,
                          ids=[c[0] for c in _PRESENCE_CASES])
def test_presence_resolver_truth_table(resolve_present, case_id, index, declared, dd, expected):
    assert resolve_present(index, declared, dd) is expected


def test_presence_resolver_size_never_flips_a_nonzero_rva_to_absent(resolve_present):
    """RVA determines presence; Size plays no role in either direction."""
    for size in (0, 1, 0x40, 0xFFFFFFFF):
        assert resolve_present(1, 16, [(0, 0), (0, size)] + [(0, 0)] * 4) is False
    for size in (0, 1, 0x40, 0xFFFFFFFF):
        assert resolve_present(1, 16, [(0, 0), (0x2000, size)] + [(0, 0)] * 4) is True


# ── §3.5.2: outcome matrix truth table ─────────────────────────────────
#
# (import_directory_present, table_present) -> (walk_descriptors,
# limitation, diagnostic). The nullable row is expanded across all three
# values of the second field.
_IAT_OUTCOME_CASES = [
    # false | false or true -- determined absent, nothing missing.
    ("false_false", False, False, (False, None, None)),
    ("false_true",  False, True,  (False, None, None)),
    # false | null -- imports determined absent, index 12 still unknown.
    ("false_null",  False, None,  (False, "IAT_DIRECTORY_TABLE_INCOMPLETE", None)),
    # true | true -- the normal case.
    ("true_true",   True,  True,  (True, None, None)),
    # true | false -- walked; no range to check slots against.
    ("true_false",  True,  False, (True, None, "IAT_BOUNDS_CHECK_UNAVAILABLE")),
    # true | null -- walked; whether a range exists is unknown, so a
    # limitation and NOT the bounds diagnostic.
    ("true_null",   True,  None,  (True, "IAT_DIRECTORY_TABLE_INCOMPLETE", None)),
    # null | anything -- absorbs every value of the second field.
    ("null_false",  None,  False, (False, "IAT_DIRECTORY_TABLE_INCOMPLETE", None)),
    ("null_true",   None,  True,  (False, "IAT_DIRECTORY_TABLE_INCOMPLETE", None)),
    ("null_null",   None,  None,  (False, "IAT_DIRECTORY_TABLE_INCOMPLETE", None)),
]


def _outcome_tuple(outcome):
    """Production returns a frozen IatOutcome; the contract's reference
    function returns a plain tuple. Compared as tuples so the doc is not
    forced to name a production type it has no business knowing about."""
    return (outcome.walk_descriptors, outcome.limitation, outcome.diagnostic)


@pytest.mark.parametrize("case_id,import_present,table_present,expected",
                         _IAT_OUTCOME_CASES, ids=[c[0] for c in _IAT_OUTCOME_CASES])
def test_iat_outcome_matrix_truth_table(case_id, import_present, table_present, expected):
    assert _outcome_tuple(_select_iat_outcome(import_present, table_present)) == expected


def test_iat_bounds_check_unavailable_fires_only_for_a_determined_absent_table():
    """§6.2's firing rule for diagnostic 6, and §3.5.2's reason for it:
    the diagnostic ASSERTS the image declares no IAT directory. A `null`
    table_present does not establish that, so the pair (true, null) must
    produce the limitation instead -- reporting the diagnostic there
    would state as fact exactly what is unknown."""
    for import_present in (True, False, None):
        for table_present in (True, None):
            outcome = _select_iat_outcome(import_present, table_present)
            assert outcome.diagnostic is None
    assert _select_iat_outcome(True, False).diagnostic == "IAT_BOUNDS_CHECK_UNAVAILABLE"
    # ... and only when entries were actually walked (§6.2: "6 fires
    # exactly when table_present == false WHILE ENTRIES WERE WALKED").
    assert _select_iat_outcome(False, False).diagnostic is None
    assert _select_iat_outcome(None, False).diagnostic is None


def test_iat_outcome_limitation_fires_exactly_when_a_presence_is_undetermined(
        ):
    """§3.5.2: "A `null` is never a claim. When either index resolves to
    `null`, one IAT_DIRECTORY_TABLE_INCOMPLETE limitation fires." Stated
    as a biconditional and checked as one, over the whole input space."""
    for import_present in (True, False, None):
        for table_present in (True, False, None):
            undetermined = import_present is None or table_present is None
            outcome = _select_iat_outcome(import_present, table_present)
            assert (outcome.limitation is not None) is undetermined, (
                f"({import_present}, {table_present}) -> {outcome.limitation!r}")


def test_iat_outcome_never_emits_a_limitation_and_a_diagnostic_together(
        ):
    """§1.6's isolation rule at this section's own scale: a determined
    observation (diagnostic, coverage unaffected) and an undetermined one
    (limitation, partial) describe incompatible states of index 12, so no
    pair may produce both."""
    for import_present in (True, False, None):
        for table_present in (True, False, None):
            outcome = _select_iat_outcome(import_present, table_present)
            assert not (outcome.limitation and outcome.diagnostic)


def test_descriptors_are_walked_exactly_when_imports_are_determined_present():
    """The walk decision is a pure function of the FIRST field: §3.5.2's
    two `true | *` rows both walk, and every other row does not. Checked
    with 1/0 in the table_present slot as well, where an `is`-comparison
    and bare truthiness would part company."""
    for table_present in (True, False, None, 1, 0):
        assert _select_iat_outcome(True, table_present).walk_descriptors is True
        assert _select_iat_outcome(False, table_present).walk_descriptors is False
        assert _select_iat_outcome(None, table_present).walk_descriptors is False


# ── §3.8: console branch selector truth table ───────────────────────────
#
# (import_directory_present, has_entries, partial_iat_limitation, expected)
_CONSOLE_CASES = [
    (False, False, False, "no_imports"),
    (False, False, True,  "no_imports"),   # the false/null regression case
    (None,  False, True,  "unavailable"),
    (True,  True,  False, "count"),
    (True,  True,  True,  "count"),
    (True,  False, False, "present_empty"),
    (True,  False, True,  "unavailable"),
]


@pytest.mark.parametrize("import_present,has_entries,partial,expected", _CONSOLE_CASES)
def test_console_branch_selector_truth_table(
        select_console_branch, import_present, has_entries, partial, expected):
    assert select_console_branch(has_entries, import_present, partial) == expected


@pytest.mark.parametrize("has_entries", [False, True])
@pytest.mark.parametrize("partial_iat_limitation", [False, True])
def test_console_branch_4_is_never_selected_when_import_present_is_false(
        select_console_branch, has_entries, partial_iat_limitation):
    """This is the P1 defect made executable: `import_directory_present
    is False` must ALWAYS select "no_imports", regardless of
    has_entries/partial_iat_limitation -- branch 2 wins unconditionally,
    so branch 4 ("unavailable") is structurally unreachable for
    import_directory_present=False. A doc/impl change that lets branch 4
    win here reintroduces the exact regression this file exists to
    catch."""
    branch = select_console_branch(has_entries, False, partial_iat_limitation)
    if has_entries:
        # has_entries=True together with import_directory_present=False
        # is not a reachable real-world combination (§3.5.2: no entries
        # exist when imports are determined absent), but the selector is
        # a pure function checked in order -- branch 1 legitimately wins
        # here, and that's fine; the property under test is specifically
        # "never unavailable when import_directory_present is False".
        assert branch != "unavailable"
    else:
        assert branch == "no_imports"


def _assert_cannot_reach_table_present(fn, expected_params):
    """§3.8/§3.7.4: a selector must depend ONLY on its declared inputs --
    never directly on table_present.

    Check both halves of the dependency boundary:

      1. the parameter list is exactly the frozen one (nothing added,
         nothing renamed, nothing reordered), and
      2. the compiled body names `table_present` nowhere at all: not as a
         global/attribute load (co_names), not as a closed-over variable
         (co_freevars/co_cellvars), not as a local (co_varnames).

    Together those make "cannot reach table_present" an enforced fact
    about the shipped code rather than an accident of arity."""
    assert list(inspect.signature(fn).parameters) == list(expected_params)
    code = fn.__code__
    reachable = set(code.co_names) | set(code.co_freevars) | \
        set(code.co_cellvars) | set(code.co_varnames)
    assert "table_present" not in reachable, (
        f"{fn.__name__} can reach table_present via {sorted(reachable)}")


def test_console_branch_selector_never_inspects_table_present(select_console_branch):
    assert select_console_branch is _select_console_branch
    _assert_cannot_reach_table_present(
        select_console_branch,
        ("has_entries", "import_directory_present", "partial_iat_limitation"))


# ── §3.7.4: iat coverage-source state selector truth table ─────────────
#
# (image_available, import_present, entry_count, expected)
_IAT_SOURCE_CASES = [
    ("no_image_base_or_main_image", False, None,  0, "absent"),
    ("no_image_base_or_main_image_import_true", False, True, 3, "absent"),
    ("import_null",                 True,  None,  0, "absent"),
    ("import_false_table_null",     True,  False, 0, "present_empty"),
    ("import_true_zero_entries",    True,  True,  0, "present_empty"),
    ("import_true_has_entries",     True,  True,  3, "present"),
]


@pytest.mark.parametrize("case_id,image_available,import_present,entry_count,expected",
                          _IAT_SOURCE_CASES, ids=[c[0] for c in _IAT_SOURCE_CASES])
def test_iat_source_state_selector_truth_table(
        select_iat_source_state, case_id, image_available, import_present, entry_count, expected):
    assert select_iat_source_state(image_available, import_present, entry_count) == expected


def test_iat_source_state_stays_present_empty_for_the_false_null_regression(
        select_iat_source_state):
    """A determined absent import directory is `present_empty`, not absent."""
    assert select_iat_source_state(True, False, 0) == "present_empty"
    for entry_count in (0, 1, 999):   # entry_count is irrelevant once import_present is False
        assert select_iat_source_state(True, False, entry_count) == "present_empty"


def test_iat_source_state_selector_never_inspects_table_present(select_iat_source_state):
    """Mirrors the console-selector check above: `iat` source state must
    depend only on image_available/import_present/entry_count, never
    directly on table_present."""
    assert select_iat_source_state is _select_iat_source_state
    _assert_cannot_reach_table_present(
        select_iat_source_state, ("image_available", "import_present", "entry_count"))


# ── §6.1: IAT_DIRECTORY_TABLE_INCOMPLETE optional-count validator ──────

@pytest.mark.parametrize("count", [1, 2, 10, 15, 999])
def test_iat_directory_table_incomplete_renders_count_wording_for_positive_int(count):
    text = _render_incomplete(count)
    assert text.startswith(f"{count} declared data directory entr(y/ies) were not captured")
    assert "import/IAT directory presence is undetermined" in text


def test_iat_directory_table_incomplete_renders_count_free_wording_for_none():
    text = _render_incomplete(None)
    assert text == ("the data directory table was not captured; import/IAT directory "
                     "presence is undetermined")


@pytest.mark.parametrize("bad_count", [0, -1, -10])
def test_iat_directory_table_incomplete_rejects_zero_and_negative_counts(bad_count):
    with pytest.raises(ValueError):
        _render_incomplete(bad_count)


@pytest.mark.parametrize("bad_count", [True, False])
def test_iat_directory_table_incomplete_rejects_bool_despite_being_an_int_subclass(bad_count):
    """Python's bool is an int subclass, so a naive `isinstance(x, int)`
    validator would silently accept True/False as 1/0. The frozen
    validator must reject both explicitly."""
    with pytest.raises(ValueError):
        _render_incomplete(bad_count)


@pytest.mark.parametrize("bad_count", [1.5, "3", [1]])
def test_iat_directory_table_incomplete_rejects_non_integer_types(bad_count):
    with pytest.raises(ValueError):
        _render_incomplete(bad_count)


# ── Byte-level prototype: real PE bytes through the real parser ────────
#
# Field offsets for a PARSER-VALID, CRAFTED PE32+ header, matching
# EXACTLY what dumpex.core.pe_utils.parse_pe_header() computes for
# base_size==8 (PE32+). "Parser-valid crafted", not "well-formed": these
# buffers set SizeOfOptionalHeader=0, which is not how a real linker
# emits a PE, but is deliberate here -- it places parse_pe_header()'s
# section table at `sec_off = coff_off + 20 + 0`, i.e. immediately after
# the COFF header and BEFORE the data directory table this file is
# truncating. With exactly one section declared, that puts the full
# 40-byte section entry parse_pe_header() needs for `valid: True` well
# inside every truncation point used below (verified per-test), so these
# fixtures can exercise "PE structurally valid, but its data directory
# table was truncated" -- the exact crafted-header case §3.5.2 names as
# the reason IAT_DIRECTORY_TABLE_INCOMPLETE exists (PROCESS_MAIN_IMAGE_
# PE_INVALID, which suppresses that limitation, requires `valid: False`,
# so proving `valid: True` here is what makes these fixtures reach the
# code path under test at all, rather than a different, invalid-PE one).
# Building real bytes and running them through the real, already-shipped
# parser -- rather than hand-typing (rva, size) lists -- means these
# fixtures can't silently drift from what parse_pe_header() actually
# does with a truncated buffer.
_E_LFANEW = 0x80
_COFF_OFF = _E_LFANEW + 4
_OPT_OFF = _COFF_OFF + 20
_EP_OFF = _OPT_OFF + 16
_BASE_OFF = _OPT_OFF + 24
_SIZE_OFF = _OPT_OFF + 56
_NUM_RVA_SIZES_OFF = _OPT_OFF + 108
_DIR_OFF = _OPT_OFF + 112
_SIZE_OF_OPTIONAL_HEADER = 0   # deliberate -- see module comment above
_SECTION_TABLE_OFF = _COFF_OFF + 20 + _SIZE_OF_OPTIONAL_HEADER
_SECTION_TABLE_END = _SECTION_TABLE_OFF + 40   # one section, 40 bytes


def _build_pe_bytes(number_of_rva_and_sizes: int, directories: dict) -> bytes:
    """A full-length, parser-valid CRAFTED PE32+ header buffer (see the
    module comment above for why it is not a "well-formed" one), data
    directories populated per `directories` ({index: (rva, size)},
    default (0, 0)). Callers slice the result to simulate a partial
    capture -- parse_pe_header() already implements the prefix-
    truncation behavior §3.5.2 describes, so slicing this buffer
    exercises the REAL production code path."""
    buf = bytearray(_DIR_OFF + 16 * 8)
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, _E_LFANEW)
    buf[_E_LFANEW:_E_LFANEW + 4] = b'PE\x00\x00'
    struct.pack_into('<HHIIIHH', buf, _COFF_OFF,
                      0x8664, 1, 0, 0, 0, _SIZE_OF_OPTIONAL_HEADER, 0)
    struct.pack_into('<H', buf, _OPT_OFF, 0x20b)          # PE32+ magic
    struct.pack_into('<I', buf, _EP_OFF, 0x1000)
    struct.pack_into('<Q', buf, _BASE_OFF, 0x140000000)
    struct.pack_into('<I', buf, _SIZE_OFF, 0x2000)
    struct.pack_into('<I', buf, _NUM_RVA_SIZES_OFF, number_of_rva_and_sizes)
    for i, (rva, size) in directories.items():
        struct.pack_into('<II', buf, _DIR_OFF + i * 8, rva, size)
    return bytes(buf)


def _assert_parser_valid(parsed: dict, data: bytes) -> None:
    """Every byte-level fixture below must prove it reached a
    structurally VALID PE before trusting its data_directories -- a
    PROCESS_MAIN_IMAGE_PE_INVALID result (valid: False) would suppress
    IAT_DIRECTORY_TABLE_INCOMPLETE entirely (§3.5.2), making the
    three-state branch under test unreachable in the real command path.
    Also confirms the section table actually fits inside this
    particular truncation point, not just that it was declared to."""
    assert _SECTION_TABLE_END <= len(data), (
        f"this fixture's truncation point ({len(data)} bytes) cuts into "
        f"the crafted section table (needs {_SECTION_TABLE_END}) -- fix "
        f"the slice length, not this assertion")
    assert parsed["valid"] is True, (
        f"fixture must parse as a structurally valid PE, got reason "
        f"{parsed['reason']!r}")
    assert parsed["reason"] == ""


def _declared_directory_count_from_bytes(parsed: dict):
    """Read `declared_directory_count` from the production parser."""
    return parsed["declared_directory_count"]


def test_byte_level_captured_through_index5_nonzero_rva_is_true_null(resolve_present):
    """Declared 16, captured through index 5,
    index 1 has a non-zero RVA -> import True, table null, 10 missing."""
    data = _build_pe_bytes(16, {1: (0x2000, 0x40)})[:_DIR_OFF + 6 * 8]
    parsed = parse_pe_header(data)
    _assert_parser_valid(parsed, data)
    assert len(parsed["data_directories"]) == 6
    declared = _declared_directory_count_from_bytes(parsed)
    assert declared == 16
    assert resolve_present(1, declared, parsed["data_directories"]) is True
    assert resolve_present(12, declared, parsed["data_directories"]) is None
    assert declared - len(parsed["data_directories"]) == 10


def test_byte_level_captured_through_index5_zero_rva_is_false_null(resolve_present):
    """Declared 16, captured through index 5,
    index 1 has a ZERO RVA (and a non-zero Size, doubling as an RVA/Size
    independence check) -> import False, table null, 10 missing. This is
    the byte-level instance of the false/null console regression: the
    import claim is determined even though the table gap remains."""
    data = _build_pe_bytes(16, {1: (0, 0x40)})[:_DIR_OFF + 6 * 8]
    parsed = parse_pe_header(data)
    _assert_parser_valid(parsed, data)
    assert len(parsed["data_directories"]) == 6
    declared = _declared_directory_count_from_bytes(parsed)
    assert declared == 16
    assert resolve_present(1, declared, parsed["data_directories"]) is False
    assert resolve_present(12, declared, parsed["data_directories"]) is None
    assert declared - len(parsed["data_directories"]) == 10


def test_byte_level_captured_through_index0_only_is_null_null(resolve_present):
    """Declared 16, captured only through index
    0 -> both null, 15 missing."""
    data = _build_pe_bytes(16, {})[:_DIR_OFF + 1 * 8]
    parsed = parse_pe_header(data)
    _assert_parser_valid(parsed, data)
    assert len(parsed["data_directories"]) == 1
    declared = _declared_directory_count_from_bytes(parsed)
    assert declared == 16
    assert resolve_present(1, declared, parsed["data_directories"]) is None
    assert resolve_present(12, declared, parsed["data_directories"]) is None
    assert declared - len(parsed["data_directories"]) == 15


def test_byte_level_number_of_rva_and_sizes_uncaptured_is_null_null(resolve_present):
    """NumberOfRvaAndSizes itself uncaptured ->
    declared_directory_count is None, both presence flags null, count-
    free limitation rendering applies."""
    full = _build_pe_bytes(16, {1: (0x2000, 0x40)})
    data = full[:_SIZE_OFF + 4]
    assert _NUM_RVA_SIZES_OFF + 4 > len(data)
    parsed = parse_pe_header(data)
    _assert_parser_valid(parsed, data)
    assert parsed["data_directories"] == []
    declared = _declared_directory_count_from_bytes(parsed)
    assert declared is None
    assert resolve_present(1, declared, parsed["data_directories"]) is None
    assert resolve_present(12, declared, parsed["data_directories"]) is None


# (raw, expected). §3.2: a plain int in 1..UINT32_MAX, else None. `bool`
# is rejected by name -- it is an int subclass, so a stray True must
# never normalize to PID 1.
_PID_CASES = [
    (1, 1), (4242, 4242), (0xFFFFFFFF, 0xFFFFFFFF),
    (0, None),                                    # the library's unset value
    (-1, None), (0x100000000, None),
    (True, None), (False, None),
    ("4242", None), (4242.0, None), (None, None), ([], None),
]


@pytest.mark.parametrize("raw,expected", _PID_CASES)
def test_normalize_pid_truth_table(raw, expected):
    assert normalize_pid(raw) == expected


# (raw, expected). §3.2: range-checked BEFORE any datetime conversion,
# because datetime.fromtimestamp() is platform-dependent and happily
# converts values a UINT32 field cannot hold.
_CREATE_TIME_CASES = [
    (0, "unset"),
    (1, "ok"), (0xFFFFFFFF, "ok"),
    (-1, "invalid"), (0x100000000, "invalid"),
    (True, "invalid"), (False, "invalid"),
    ("0", "invalid"), (0.0, "invalid"), (None, "invalid"),
]


@pytest.mark.parametrize("raw,expected", _CREATE_TIME_CASES)
def test_classify_process_create_time_truth_table(raw, expected):
    assert classify_process_create_time(raw) == expected


# ── normalization truth tables ─────────────────────────────────────────
#
# Note what is deliberately NOT pinned: production applies
# `raw.rstrip("\x00").strip()`, so a NUL sitting INSIDE trailing
# whitespace ("x \x00 ") survives. §3.2's "strips trailing NULs and
# surrounding whitespace" fixes no order between the two operations, so
# asserting that case would pin an implementation detail the contract
# never froze -- it would fail on a reordering the contract permits.
# Every case below is one the prose decides on its own.

_PATH_CASES = [
    ("C:\\Windows\\System32\\notepad.exe", "C:\\Windows\\System32\\notepad.exe"),
    ("C:\\Windows\\System32\\notepad.exe\x00\x00", "C:\\Windows\\System32\\notepad.exe"),
    ("  C:\\Windows\\notepad.exe  ", "C:\\Windows\\notepad.exe"),
    ("\x00", None), ("", None), ("   ", None), ("\t\n", None),
    (None, None), (b"C:\\x", None), (42, None),
    # "never lowercases, never rewrites separators": the stored value is
    # evidence, so both of these must come back byte-identical.
    ("C:\\Windows\\NOTEPAD.EXE", "C:\\Windows\\NOTEPAD.EXE"),
    ("C:/Windows\\mixed/SEPARATORS.exe", "C:/Windows\\mixed/SEPARATORS.exe"),
]


@pytest.mark.parametrize("normalizer", [normalize_windows_path, normalize_command_line],
                         ids=["normalize_windows_path", "normalize_command_line"])
@pytest.mark.parametrize("raw,expected", _PATH_CASES)
def test_string_normalizers_truth_table(normalizer, raw, expected):
    """§3.2 states normalize_command_line as "same rules as
    normalize_windows_path, minus any path interpretation" -- neither
    interprets a path at all, so the same table must hold for both. A
    divergence means one grew behavior the other didn't."""
    assert normalizer(raw) == expected


def test_string_normalizers_never_truncate_a_long_value():
    """"Never truncates" is a rule about values no other fixture
    reaches."""
    long_path = "C:\\" + "a" * 8192 + "\\x.exe"
    assert normalize_windows_path(long_path) == long_path
    assert normalize_command_line(long_path) == long_path


# §3.2: plain int (not bool), 0 < raw <= UINT64_MAX, 0x1000-aligned.
_IMAGE_BASE_CASES = [
    (0x1000, 0x1000), (0x140000000, 0x140000000),
    (0xFFFFFFFFFFFFF000, 0xFFFFFFFFFFFFF000),
    (0, None),                                            # a read artifact
    (-0x1000, None), (0x10000000000000000, None),
    (0x1001, None), (0x140000001, None), (0xFFF, None),   # unaligned
    (True, None), (False, None), ("0x1000", None), (4096.0, None), (None, None),
]


@pytest.mark.parametrize("raw,expected", _IMAGE_BASE_CASES)
def test_normalize_image_base_truth_table(raw, expected):
    assert normalize_image_base(raw) == expected


class _FakeModule:
    def __init__(self, baseaddress, name="m"):
        self.baseaddress = baseaddress
        self.name = name


def test_resolve_module_by_base_matches_only_an_exact_base():
    """§3.3.3's whole point: EXACT equality, never addr_to_module()'s
    containment test, which would match the main image for any address
    inside it and so answer a weaker question than the one asked."""
    mods = [_FakeModule(0x1000, "a"), _FakeModule(0x140000000, "b")]
    assert resolve_module_by_base(0x140000000, mods) is mods[1]
    assert resolve_module_by_base(0x1000, mods) is mods[0]
    # Inside module a's range but not its base -- containment would match
    # here, exact equality must not.
    assert resolve_module_by_base(0x1004, mods) is None
    assert resolve_module_by_base(0x2000, mods) is None
    assert resolve_module_by_base(0x1000, []) is None


@pytest.mark.parametrize("base", [True, False, "0x1000", 4096.0, None, []])
def test_resolve_module_by_base_returns_none_for_a_non_int_base(base):
    """"Returns None immediately for a base_address that isn't a real int
    ... rather than raising" -- including bool, which would otherwise
    match a module registered at base 1 or 0."""
    assert resolve_module_by_base(base, [_FakeModule(0), _FakeModule(1)]) is None


def test_resolve_module_by_base_returns_the_module_object_itself():
    """§3.3.3 freezes the return as the module, not a copy or a wrapper
    -- process_info.py converts it into a scalar-only ModuleReference at
    its own boundary, and that conversion is only correct if this hands
    back the live object."""
    m = _FakeModule(0x1000)
    assert resolve_module_by_base(0x1000, [m]) is m


def test_environment_walk_uses_the_production_budget_defaults():
    defaults = inspect.signature(walk_environment_block).parameters
    assert defaults["max_bytes"].default == MAX_ENV_BYTES
    assert defaults["max_entries"].default == MAX_ENV_ENTRIES

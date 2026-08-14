"""
Executable semantic checks for docs/recon_process_sysinfo_handles_contract.md
(issue #37's second repair pass).

test_recon_contract_doc.py checks the document's WORDING (required
sections, registry-table consistency, forbidden phrases). It cannot
catch a SEMANTIC contradiction between two correctly-worded passages --
which is exactly how the previous revision shipped an unreachable
console branch (§3.8's branch 4 claimed to cover a case §3.5.2/branch 2
already made structurally unreachable) with every doc-lint test green.

This file closes that gap by being EXECUTABLE against the contract's
own frozen rules:

  1. §3.5.2 and §3.8 each embed a short ```python reference function
     (`resolve_present` / `select_console_branch`). This file extracts
     those functions directly out of the doc via regex and exec()s them,
     then runs each against a truth table built from the contract's
     prose. If a future edit changes the algorithm's behavior without
     updating the truth table (or vice versa), a row fails here --
     independent of how the surrounding prose is worded or wrapped.

  2. A byte-level prototype builds real PE32+ header bytes (reusing
     dumpex.core.pe_utils.parse_pe_header(), which already implements
     the truncation/prefix-capture behavior §3.5.2 describes) and feeds
     the result through the extracted `resolve_present`, covering the
     four highest-value fixtures from §8.3 item 6b/6b2 against actual
     bytes rather than hand-typed expectations.

  3. A reducer-retention prototype exercises §3.7.3's frozen
     `retain_completeness_checks_when_not_evaluated` design against the
     REAL dumpex.output.coverage.build_coverage_report() for the
     default-False (today's shipped behavior, unchanged) path, and a
     small test-only reference wrapper for the not-yet-implemented
     True path -- clearly marked as a #38 prototype, not production
     code. Scoped to the single-source-EvaluationRequirement shape
     --process/--handles actually use (§3.7.2/§5.5); a
     --handles-specific instantiation using HANDLES_PARSE_FAILED/
     HANDLES_ALL_DESCRIPTORS_INVALID is deferred, since those codes are
     not yet members of the live LimitationCode enum (#38/#40).
"""
import os
import re
import struct

import pytest

from dumpex.core.pe_utils import parse_pe_header
from dumpex.output.coverage import (
    SourceObservation, CoverageLimitation, CoverageReport, SourceRequirement,
    build_coverage_report, SourceState, CoverageStatus, LimitationCode,
    exit_code_for, EXIT_NOT_EVALUATED,
    _validate_limitation_against_sources,
)

_DOC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "docs", "recon_process_sysinfo_handles_contract.md")


@pytest.fixture(scope="module")
def doc() -> str:
    with open(_DOC_PATH, encoding="utf-8") as fh:
        return fh.read()


def _extract_python_function(doc: str, def_name: str):
    """Pull one fenced ```python block out of the contract by the name
    of the function it defines, and exec() it in an isolated namespace.
    This ties the tests below directly to the doc's OWN algorithm text:
    if the contract's pseudocode changes, these tests exercise the new
    version automatically rather than a stale copy pasted into the test
    suite, which is exactly the drift #37's reviews kept catching.

    Fences may be nested inside a markdown list item (indented) or sit
    at the top level (not indented) -- the opening/closing fence's own
    indentation is captured and stripped from every line so exec() sees
    valid, unindented Python either way."""
    pattern = re.compile(
        r"^([ \t]*)```python\n(.*?\n)\1```", re.DOTALL | re.MULTILINE)
    for indent, body in pattern.findall(doc):
        dedented = "\n".join(
            line[len(indent):] if line.startswith(indent) else line
            for line in body.splitlines())
        if dedented.startswith(f"def {def_name}("):
            ns = {}
            exec(compile(dedented, f"<contract:{def_name}>", "exec"), ns)
            return ns[def_name]
    raise AssertionError(f"contract has no ```python block defining {def_name}()")


@pytest.fixture(scope="module")
def resolve_present(doc):
    return _extract_python_function(doc, "resolve_present")


@pytest.fixture(scope="module")
def select_console_branch(doc):
    return _extract_python_function(doc, "select_console_branch")


@pytest.fixture(scope="module")
def select_iat_source_state(doc):
    return _extract_python_function(doc, "select_iat_source_state")


@pytest.fixture(scope="module")
def render_iat_directory_table_incomplete(doc):
    return _extract_python_function(doc, "render_iat_directory_table_incomplete")


# ── §3.5.2: presence resolver truth table ───────────────────────────────
#
# (test id, index, declared_directory_count, data_directories, expected)
# Covers both the P2 truth table and the RVA/Size-independence rows the
# presence-resolution table was previously missing.
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
    """The exact regression named in the review: a captured (0, nonzero)
    pair must resolve exactly like (0, 0), and a captured (nonzero, 0)
    pair must resolve exactly like a fully-populated pair -- Size plays
    no role in either direction."""
    for size in (0, 1, 0x40, 0xFFFFFFFF):
        assert resolve_present(1, 16, [(0, 0), (0, size)] + [(0, 0)] * 4) is False
    for size in (0, 1, 0x40, 0xFFFFFFFF):
        assert resolve_present(1, 16, [(0, 0), (0x2000, size)] + [(0, 0)] * 4) is True


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


def test_console_branch_selector_never_inspects_table_present(select_console_branch):
    """§3.8: branch selection must depend only on has_entries /
    import_directory_present / partial_iat_limitation -- never directly
    on table_present. Enforced by construction: the extracted function's
    signature has no such parameter, so passing one raises TypeError."""
    with pytest.raises(TypeError):
        select_console_branch(False, False, False, table_present=None)


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
    """The exact regression named in the review, made executable: when
    import_directory_present is False, `iat` must be `present_empty` --
    NEVER `absent` -- regardless of table_present (which this function
    doesn't even take as a parameter, by construction) or entry_count.
    A future doc/impl change that maps this combination to `absent`
    fails this assertion even if every other truth-table row still
    passes."""
    assert select_iat_source_state(True, False, 0) == "present_empty"
    for entry_count in (0, 1, 999):   # entry_count is irrelevant once import_present is False
        assert select_iat_source_state(True, False, entry_count) == "present_empty"


def test_iat_source_state_selector_never_inspects_table_present(select_iat_source_state):
    """Mirrors the console-selector check above: `iat` source state must
    depend only on image_available/import_present/entry_count, never
    directly on table_present."""
    with pytest.raises(TypeError):
        select_iat_source_state(True, False, 0, table_present=None)


# ── §6.1: IAT_DIRECTORY_TABLE_INCOMPLETE optional-count validator ──────

@pytest.mark.parametrize("count", [1, 2, 10, 15, 999])
def test_iat_directory_table_incomplete_renders_count_wording_for_positive_int(
        render_iat_directory_table_incomplete, count):
    text = render_iat_directory_table_incomplete(count)
    assert text.startswith(f"{count} declared data directory entr(y/ies) were not captured")
    assert "import/IAT directory presence is undetermined" in text


def test_iat_directory_table_incomplete_renders_count_free_wording_for_none(
        render_iat_directory_table_incomplete):
    text = render_iat_directory_table_incomplete(None)
    assert text == ("the data directory table was not captured; import/IAT directory "
                     "presence is undetermined")


@pytest.mark.parametrize("bad_count", [0, -1, -10])
def test_iat_directory_table_incomplete_rejects_zero_and_negative_counts(
        render_iat_directory_table_incomplete, bad_count):
    with pytest.raises(ValueError):
        render_iat_directory_table_incomplete(bad_count)


@pytest.mark.parametrize("bad_count", [True, False])
def test_iat_directory_table_incomplete_rejects_bool_despite_being_an_int_subclass(
        render_iat_directory_table_incomplete, bad_count):
    """Python's bool is an int subclass, so a naive `isinstance(x, int)`
    validator would silently accept True/False as 1/0. The frozen
    validator must reject both explicitly."""
    with pytest.raises(ValueError):
        render_iat_directory_table_incomplete(bad_count)


@pytest.mark.parametrize("bad_count", [1.5, "3", [1]])
def test_iat_directory_table_incomplete_rejects_non_integer_types(
        render_iat_directory_table_incomplete, bad_count):
    with pytest.raises(ValueError):
        render_iat_directory_table_incomplete(bad_count)


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


def _declared_directory_count_from_bytes(data: bytes):
    """Test-only mirror of §3.5.2's frozen `declared_directory_count`
    definition. NOT production code -- #39 will add this computation to
    parse_pe_header() itself. Kept here only so the byte-level fixtures
    below are executable ahead of that implementation."""
    if _NUM_RVA_SIZES_OFF + 4 > len(data):
        return None
    return min(struct.unpack_from('<I', data, _NUM_RVA_SIZES_OFF)[0], 16)


def test_byte_level_captured_through_index5_nonzero_rva_is_true_null(resolve_present):
    """§8.3 item 6b, fixture 1: declared 16, captured through index 5,
    index 1 has a non-zero RVA -> import True, table null, 10 missing."""
    data = _build_pe_bytes(16, {1: (0x2000, 0x40)})[:_DIR_OFF + 6 * 8]
    parsed = parse_pe_header(data)
    _assert_parser_valid(parsed, data)
    assert len(parsed["data_directories"]) == 6
    declared = _declared_directory_count_from_bytes(data)
    assert declared == 16
    assert resolve_present(1, declared, parsed["data_directories"]) is True
    assert resolve_present(12, declared, parsed["data_directories"]) is None
    assert declared - len(parsed["data_directories"]) == 10


def test_byte_level_captured_through_index5_zero_rva_is_false_null(resolve_present):
    """§8.3 item 6b, fixture 2: declared 16, captured through index 5,
    index 1 has a ZERO RVA (and a non-zero Size, doubling as an RVA/Size
    independence check) -> import False, table null, 10 missing. This is
    the byte-level instance of the false/null console regression: the
    import claim is determined even though the table gap remains."""
    data = _build_pe_bytes(16, {1: (0, 0x40)})[:_DIR_OFF + 6 * 8]
    parsed = parse_pe_header(data)
    _assert_parser_valid(parsed, data)
    assert len(parsed["data_directories"]) == 6
    declared = _declared_directory_count_from_bytes(data)
    assert declared == 16
    assert resolve_present(1, declared, parsed["data_directories"]) is False
    assert resolve_present(12, declared, parsed["data_directories"]) is None
    assert declared - len(parsed["data_directories"]) == 10


def test_byte_level_captured_through_index0_only_is_null_null(resolve_present):
    """§8.3 item 6b, fixture 3: declared 16, captured only through index
    0 -> both null, 15 missing."""
    data = _build_pe_bytes(16, {})[:_DIR_OFF + 1 * 8]
    parsed = parse_pe_header(data)
    _assert_parser_valid(parsed, data)
    assert len(parsed["data_directories"]) == 1
    declared = _declared_directory_count_from_bytes(data)
    assert declared == 16
    assert resolve_present(1, declared, parsed["data_directories"]) is None
    assert resolve_present(12, declared, parsed["data_directories"]) is None
    assert declared - len(parsed["data_directories"]) == 15


def test_byte_level_number_of_rva_and_sizes_uncaptured_is_null_null(resolve_present):
    """§8.3 item 6b, fixture 4: NumberOfRvaAndSizes itself uncaptured ->
    declared_directory_count is None, both presence flags null, count-
    free limitation rendering applies."""
    full = _build_pe_bytes(16, {1: (0x2000, 0x40)})
    data = full[:_SIZE_OFF + 4]
    assert _NUM_RVA_SIZES_OFF + 4 > len(data)
    parsed = parse_pe_header(data)
    _assert_parser_valid(parsed, data)
    assert parsed["data_directories"] == []
    declared = _declared_directory_count_from_bytes(data)
    assert declared is None
    assert resolve_present(1, declared, parsed["data_directories"]) is None
    assert resolve_present(12, declared, parsed["data_directories"]) is None


# ── §3.7.3: reducer-retention prototype ─────────────────────────────────

_PREBUILT_REGION = CoverageLimitation(
    code=LimitationCode.REGION_READ_TRUNCATED, source="requested_region")
_PREBUILT_PID = CoverageLimitation(
    code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info")


def _base_sources():
    return {
        "process_identity": SourceObservation(name="process_identity", state=SourceState.ABSENT),
        "peb": SourceObservation(name="peb", state=SourceState.FAILED, detail="boom"),
        "modules": SourceObservation(name="modules", state=SourceState.ABSENT),
        "requested_region": SourceObservation(name="requested_region", state=SourceState.PRESENT,
                                               record_count=1),
        "misc_info": SourceObservation(name="misc_info", state=SourceState.PRESENT, record_count=1),
    }


def _prototype_with_retention(sources, evaluation_sources, completeness_checks):
    """Test-only prototype of §3.7.3's frozen
    `retain_completeness_checks_when_not_evaluated=True` design. NOT
    implemented in dumpex.output.coverage yet (#38 territory) -- this
    reference model exists only to make the frozen ordering/retention
    rules executable now, so a rule regression is caught by pytest
    rather than by prose review.

    Scoped to the single-group shape --process/--handles actually use
    (a bare `evaluation_sources` tuple, which build_coverage_report()
    auto-wraps into exactly one EvaluationRequirement, contributing at
    most one group limitation) -- matching §3.7.2/§5.5 exactly. A
    caller passing `evaluation_groups` (multiple independent groups)
    is out of scope for this prototype.
    """
    # Production already does everything right EXCEPT retaining pre-built
    # CoverageLimitations under not_evaluated -- so call it once with the
    # FULL checks list. If the group didn't fire, production's ordinary
    # (non-not_evaluated) path already keeps pre-built entries in place;
    # that result is correct as-is. If it DID fire, production's
    # not_evaluated branch already dropped every pre-built entry, so
    # `baseline.limitations` is exactly [group..., failed...] with none
    # of them -- the correct base to splice retained entries into.
    baseline = build_coverage_report(sources, evaluation_sources=evaluation_sources,
                                      completeness_checks=completeness_checks)
    if baseline.status != CoverageStatus.NOT_EVALUATED:
        return baseline

    group_limitations = baseline.limitations[:1]
    failed_limitations = baseline.limitations[1:]
    retained = [c for c in completeness_checks if isinstance(c, CoverageLimitation)]
    for lim in retained:
        _validate_limitation_against_sources(lim, sources)   # "relaxes nothing about correctness"

    return CoverageReport(status=CoverageStatus.NOT_EVALUATED, sources=baseline.sources,
                           limitations=group_limitations + retained + failed_limitations)


def test_retention_default_false_matches_todays_shipped_behavior():
    """Default False: byte-for-byte today's build_coverage_report()
    behavior. This calls the REAL production function, not the
    prototype -- pre-built CoverageLimitations are dropped under
    not_evaluated, exactly as documented in §3.7.3's "Default False"
    bullet."""
    sources = _base_sources()
    checks = ["peb", SourceRequirement(source="modules"), _PREBUILT_REGION]
    report = build_coverage_report(sources, evaluation_sources=("process_identity",),
                                    completeness_checks=checks)
    assert report.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(report.status) == EXIT_NOT_EVALUATED
    codes = [l.code for l in report.limitations]
    assert codes == [LimitationCode.SOURCE_ABSENT, LimitationCode.SOURCE_FAILED]
    assert LimitationCode.REGION_READ_TRUNCATED not in codes


def test_retention_true_orders_group_then_retained_then_failed():
    """True: group limitation first, then retained pre-built
    CoverageLimitations in caller-declared order, then the re-surfaced
    FAILED-source limitation(s) -- exactly §3.7.3's frozen order. Two
    distinct pre-built codes (in reverse-of-declaration order relative
    to the bare checks) prove ordering is caller order, not code order
    or source-alphabetical order."""
    sources = _base_sources()
    checks = ["peb", _PREBUILT_PID, SourceRequirement(source="modules"), _PREBUILT_REGION]
    report = _prototype_with_retention(sources, ("process_identity",), checks)

    assert report.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(report.status) == EXIT_NOT_EVALUATED
    codes = [l.code for l in report.limitations]
    assert codes == [
        LimitationCode.SOURCE_ABSENT,          # 1. the group's own limitation
        LimitationCode.PID_NO_USABLE_FALLBACK,  # 2. retained pre-built, caller order
        LimitationCode.REGION_READ_TRUNCATED,   # 2. retained pre-built, caller order
        LimitationCode.SOURCE_FAILED,           # 3. re-surfaced FAILED source
    ]
    # Bare-name/SourceRequirement ABSENT checks keep today's behavior:
    # never resurfaced, retention flag or not.
    assert not any(l.source == "modules" for l in report.limitations)


def test_retention_true_result_still_not_evaluated_exit_4():
    """§3.7.3: "status is still not_evaluated and the exit code is still
    4 -- the flag changes which limitations are reported, never the
    status." """
    sources = _base_sources()
    checks = ["peb", _PREBUILT_REGION]
    report = _prototype_with_retention(sources, ("process_identity",), checks)
    assert report.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(report.status) == EXIT_NOT_EVALUATED


def test_retention_prototype_no_group_fired_returns_baseline_unchanged():
    """When the evaluation group does NOT fire (something was actually
    evaluated), retention is moot -- the prototype must fall through to
    ordinary partial/complete behavior, matching production exactly."""
    sources = _base_sources()
    sources["process_identity"] = SourceObservation(
        name="process_identity", state=SourceState.PRESENT, record_count=1)
    checks = ["peb", _PREBUILT_REGION]
    report = _prototype_with_retention(sources, ("process_identity",), checks)
    direct = build_coverage_report(sources, evaluation_sources=("process_identity",),
                                    completeness_checks=checks)
    assert report.status == direct.status == CoverageStatus.PARTIAL
    assert [l.code for l in report.limitations] == [l.code for l in direct.limitations]


def test_retention_prototype_still_validates_retained_limitations_against_sources():
    """"Every retained limitation still passes
    _validate_limitation_against_sources(). The flag relaxes nothing
    about correctness." -- a pre-built limitation that is internally
    well-formed but cross-source-invalid for THESE sources must still
    raise, retention or not."""
    sources = {
        "process_identity": SourceObservation(name="process_identity", state=SourceState.ABSENT),
        "exception": SourceObservation(name="exception", state=SourceState.ABSENT),
    }
    # PID_EXCEPTION_TID_FALLBACK's cross-source rule requires "exception"
    # to be PRESENT; it's ABSENT here, so this is well-formed at
    # construction time but must fail at retention/validation time.
    bad_prebuilt = CoverageLimitation(
        code=LimitationCode.PID_EXCEPTION_TID_FALLBACK, source="exception", thread_id=999)
    with pytest.raises(ValueError, match="requires exception to be present"):
        _prototype_with_retention(sources, ("process_identity",), [bad_prebuilt])

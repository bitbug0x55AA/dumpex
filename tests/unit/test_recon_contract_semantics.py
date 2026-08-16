"""
Executable semantic checks for docs/recon_process_sysinfo_handles_contract.md
(issue #37's second repair pass).

test_recon_contract_doc.py checks the document's WORDING (required
sections, registry-table consistency, forbidden phrases). It cannot
catch a SEMANTIC contradiction between two correctly-worded passages --
which is exactly how the previous revision shipped an unreachable
console branch (§3.8's branch 4 claimed to cover a case §3.5.2/branch 2
already made structurally unreachable) with every doc-lint test green.

This file closes that gap by being EXECUTABLE. There are three distinct
things that can be true or false about a frozen contract section, and
this file checks each one SEPARATELY so that a failure names its own
cause. Each layer compares two of the three artifacts involved: the
section's PROSE (hand-transcribed here into truth tables), the section's
own ```python REFERENCE FUNCTION (extracted from the doc by regex and
exec()'d), and the shipped PRODUCTION function.

  LAYER 1 -- prose <-> production. Is the shipped code correct?
     Every truth table runs against the REAL function:
     pe_utils._resolve_directory_present,
     process._select_console_branch, process._select_iat_source_state,
     coverage.render_limitation().

  LAYER 2 -- prose <-> the contract's pseudocode. Is the DOCUMENT
     internally consistent? This is #37's P1 defect in its original
     shape, and the only layer that needs no implementation to exist --
     a section frozen ahead of its code is still checkable here.

  LAYER 3 -- pseudocode <-> production. Has the doc drifted from the
     shipped algorithm (in either direction)?

An earlier revision had only what is now layer 2, while its docstrings
claimed layer 1 ("the exact regression named in the review", "today's
shipped behavior"): every truth table ran against the doc's copy of the
algorithm, so a production defect left all rows green. Layers 1 and 2
are redundant with each other by transitivity once layer 3 passes --
that redundancy is the point, because it is what makes each failure
diagnostic rather than merely loud.

Layer 1 also includes a byte-level section: it builds real PE32+ header
bytes (reusing dumpex.core.pe_utils.parse_pe_header(), which already
implements the truncation/prefix-capture behavior §3.5.2 describes) and
feeds the result through the real presence resolver, covering the four
highest-value fixtures from §8.3 item 6b/6b2 against actual bytes rather
than hand-typed expectations.

§3.7.3's not-yet-implemented `retain_completeness_checks_when_not_
evaluated` design (#38) is NOT modelled here: a reference model of an
unimplemented feature is not a semantic check of shipped behavior, and
mixing the two is what made this file's coverage claims hard to read.
It lives in tests/unit/test_recon_contract_retention_prototype.py.
"""
import inspect
import os
import re
import struct

import pytest

from dumpex.core.pe_utils import parse_pe_header, _resolve_directory_present
from dumpex.commands.process import _select_console_branch, _select_iat_source_state
from dumpex.output.coverage import (
    CoverageLimitation, LimitationCode, render_limitation,
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


# ── the functions under test: PRODUCTION, not the doc's copy ───────────
#
# These fixtures deliberately return the shipped implementations. The
# doc's own pseudocode is exercised separately, and only against these,
# in the equivalence section further down.

@pytest.fixture(scope="module")
def resolve_present():
    return _resolve_directory_present


@pytest.fixture(scope="module")
def select_console_branch():
    return _select_console_branch


@pytest.fixture(scope="module")
def select_iat_source_state():
    return _select_iat_source_state


@pytest.fixture(scope="module")
def doc_resolve_present(doc):
    return _extract_python_function(doc, "resolve_present")


@pytest.fixture(scope="module")
def doc_select_console_branch(doc):
    return _extract_python_function(doc, "select_console_branch")


@pytest.fixture(scope="module")
def doc_select_iat_source_state(doc):
    return _extract_python_function(doc, "select_iat_source_state")


@pytest.fixture(scope="module")
def doc_render_iat_directory_table_incomplete(doc):
    return _extract_python_function(doc, "render_iat_directory_table_incomplete")


def _render_incomplete(affected_count):
    """Production's §6.1 rendering path for IAT_DIRECTORY_TABLE_INCOMPLETE,
    reached exactly as a caller reaches it. Production splits what the
    contract states as one reference function into two halves -- the
    optional-positive-int validation runs at CoverageLimitation
    construction time (coverage._require_optional_positive_int), the
    wording in coverage._render_iat_directory_table_incomplete() behind
    the render_limitation() registry -- so this adapter puts them back
    together to compare against the doc's single function. Both halves
    are real production code; only the seam is test-side."""
    return render_limitation(CoverageLimitation(
        code=LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE, source="iat",
        affected_count=affected_count))


# ══ LAYER 1: prose <-> production ══════════════════════════════════════
#
# The truth tables below are the contract's PROSE, hand-transcribed. They
# run against the shipped functions. The same tables are re-run against
# the doc's own pseudocode in layer 2.


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


def _assert_cannot_reach_table_present(fn, expected_params):
    """§3.8/§3.7.4: a selector must depend ONLY on its declared inputs --
    never directly on table_present.

    An earlier revision asserted this by passing `table_present=None` and
    expecting TypeError. That only tested a property of Python function
    signatures: a body is perfectly free to read table_present out of a
    closure or a module global and still raise on the extra kwarg. So
    this checks both halves of the claim instead --

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


# ══ LAYER 2: prose <-> the contract's own pseudocode ═══════════════════
#
# The contract must be internally consistent BEFORE anything is built
# from it: §3.8's prose enumerating four branches must not contradict
# §3.8's own ```python block, which is exactly how #37's P1 defect
# shipped (prose claimed branch 4 covered a case the pseudocode made
# structurally unreachable) with every doc-lint test green.
#
# This layer reuses the SAME prose-derived case lists as layer 1 and runs
# them against the doc's extracted functions. For an already-implemented
# section it is redundant with layers 1+3 by transitivity. It earns its
# place for two reasons.
#
# First: three pairwise comparisons over three artifacts LOCALIZE the
# divergence. No single layer fires alone -- it is the pattern that
# names the culprit (each row below is a verified mutation, not a
# prediction):
#
#     L1   L2   L3   -> the odd one out is
#     ---  ---  ---
#     RED  ok   RED  -> production
#     ok   RED  RED  -> the contract's pseudocode
#     RED  RED  ok   -> the prose transcription (the truth table itself)
#
# Second: unlike the other two, this layer needs no implementation to
# exist, so a contract section frozen ahead of its code is still
# semantically checkable here.
#
# Note what these tables deliberately do NOT pin down: `has_entries` is a
# plain bool everywhere in the contract, so `if has_entries is True` and
# `if has_entries` are indistinguishable over in-contract inputs and no
# row here tries to tell them apart. The `is`-comparison rule §3.8 states
# is still enforced where it has real meaning -- `import_directory_
# present` is nullable, and the None/False rows below separate `is False`
# from bare truthiness. Layer 3 additionally feeds out-of-contract 1/0,
# where it only has to assert doc and production AGREE, not what either
# returns.

@pytest.mark.parametrize("case_id,index,declared,dd,expected", _PRESENCE_CASES,
                          ids=[c[0] for c in _PRESENCE_CASES])
def test_doc_presence_pseudocode_matches_prose_truth_table(
        doc_resolve_present, case_id, index, declared, dd, expected):
    assert doc_resolve_present(index, declared, dd) is expected


@pytest.mark.parametrize("import_present,has_entries,partial,expected", _CONSOLE_CASES)
def test_doc_console_pseudocode_matches_prose_truth_table(
        doc_select_console_branch, import_present, has_entries, partial, expected):
    assert doc_select_console_branch(has_entries, import_present, partial) == expected


@pytest.mark.parametrize("has_entries", [False, True])
@pytest.mark.parametrize("partial_iat_limitation", [False, True])
def test_doc_console_branch_4_is_unreachable_in_the_contracts_own_pseudocode(
        doc_select_console_branch, has_entries, partial_iat_limitation):
    """#37's P1 defect in its ORIGINAL form: a doc-internal contradiction,
    detectable with no reference to any implementation. §3.8's prose
    asserts "Branch 4 is never reached when `import_directory_present is
    false`"; this runs the section's own pseudocode to prove the prose
    is true of it."""
    branch = doc_select_console_branch(has_entries, False, partial_iat_limitation)
    if has_entries:
        assert branch != "unavailable"
    else:
        assert branch == "no_imports"


@pytest.mark.parametrize("case_id,image_available,import_present,entry_count,expected",
                          _IAT_SOURCE_CASES, ids=[c[0] for c in _IAT_SOURCE_CASES])
def test_doc_iat_source_pseudocode_matches_prose_truth_table(
        doc_select_iat_source_state, case_id, image_available, import_present,
        entry_count, expected):
    assert doc_select_iat_source_state(image_available, import_present, entry_count) == expected


def test_doc_iat_source_pseudocode_short_circuits_on_import_false(
        doc_select_iat_source_state):
    """§3.7.4's prose singles this out as "the critical, easy-to-get-wrong
    case": `import_present is False` must reach present_empty on its own,
    without help from entry_count."""
    for entry_count in (0, 1, 999):
        assert doc_select_iat_source_state(True, False, entry_count) == "present_empty"


@pytest.mark.parametrize("count,expected_prefix", [
    (1, "1 declared data directory entr(y/ies) were not captured"),
    (15, "15 declared data directory entr(y/ies) were not captured"),
])
def test_doc_renderer_pseudocode_matches_prose_wording(
        doc_render_iat_directory_table_incomplete, count, expected_prefix):
    """§6.1's table states both renderings in prose; the section's own
    reference validator/renderer must produce exactly those."""
    text = doc_render_iat_directory_table_incomplete(count)
    assert text.startswith(expected_prefix)
    assert "import/IAT directory presence is undetermined" in text


def test_doc_renderer_pseudocode_matches_prose_wording_for_none(
        doc_render_iat_directory_table_incomplete):
    assert doc_render_iat_directory_table_incomplete(None) == (
        "the data directory table was not captured; import/IAT directory "
        "presence is undetermined")


# ══ LAYER 3: the contract's pseudocode <-> production ══════════════════
#
# THE anti-drift check. Layer 1 runs production against prose; this layer
# runs the contract's own ```python reference functions side by side with
# production over the same inputs and asserts identical results, so the
# document cannot quietly diverge from the shipped algorithm in either
# direction. Inputs here are deliberately WIDER than the truth tables --
# including non-bool truthy/falsy values, which is where an `is True`
# comparison and a bare truthiness test stop agreeing (§3.8's stated
# reason for comparing with `is`).

_EQUIV_PRESENT = (True, False, None, 1, 0)
_EQUIV_ENTRIES = (True, False, 1, 0)
_EQUIV_DDS = (
    [], [(0, 0)], [(0x1000, 0x40)],
    [(0, 0)] * 6, [(0, 0), (0x2000, 0x40)] + [(0, 0)] * 4,
    [(0, 0), (0, 0x40)] + [(0, 0)] * 4,
    [(0, 0)] * 12 + [(0x3000, 0)], [(0, 0)] * 16,
)


def _assert_same_parameter_names(doc_fn, prod_fn):
    assert list(inspect.signature(doc_fn).parameters) == \
        list(inspect.signature(prod_fn).parameters), (
        f"contract's {doc_fn.__name__}() and production's {prod_fn.__name__}() "
        f"disagree on parameter names/order")


@pytest.mark.parametrize("index", [0, 1, 12, 15, 16])
@pytest.mark.parametrize("declared", [None, 0, 1, 2, 12, 13, 16])
def test_doc_resolve_present_matches_production(doc_resolve_present, index, declared):
    _assert_same_parameter_names(doc_resolve_present, _resolve_directory_present)
    for dd in _EQUIV_DDS:
        assert doc_resolve_present(index, declared, dd) is \
            _resolve_directory_present(index, declared, dd), (
            f"doc/production divergence at index={index} declared={declared} dd={dd}")


@pytest.mark.parametrize("has_entries", _EQUIV_ENTRIES)
@pytest.mark.parametrize("import_present", _EQUIV_PRESENT)
@pytest.mark.parametrize("partial", [True, False, 1, 0])
def test_doc_select_console_branch_matches_production(
        doc_select_console_branch, has_entries, import_present, partial):
    _assert_same_parameter_names(doc_select_console_branch, _select_console_branch)
    assert doc_select_console_branch(has_entries, import_present, partial) == \
        _select_console_branch(has_entries, import_present, partial)


@pytest.mark.parametrize("image_available", [True, False, 1, 0])
@pytest.mark.parametrize("import_present", _EQUIV_PRESENT)
@pytest.mark.parametrize("entry_count", [0, 1, 3, 999])
def test_doc_select_iat_source_state_matches_production(
        doc_select_iat_source_state, image_available, import_present, entry_count):
    _assert_same_parameter_names(doc_select_iat_source_state, _select_iat_source_state)
    assert doc_select_iat_source_state(image_available, import_present, entry_count) == \
        _select_iat_source_state(image_available, import_present, entry_count)


@pytest.mark.parametrize("count", [None, 1, 2, 10, 15, 999])
def test_doc_render_iat_directory_table_incomplete_matches_production(
        doc_render_iat_directory_table_incomplete, count):
    """Wording equivalence for the accepted inputs. Production reaches
    the same two strings through render_limitation()'s registry."""
    assert doc_render_iat_directory_table_incomplete(count) == _render_incomplete(count)


@pytest.mark.parametrize("bad_count", [0, -1, True, False, 1.5, "3", [1]])
def test_doc_render_iat_directory_table_incomplete_rejects_what_production_rejects(
        doc_render_iat_directory_table_incomplete, bad_count):
    """Rejection equivalence. The doc states validation and rendering as
    one function; production splits them across CoverageLimitation
    construction and render_limitation(). Both must refuse the same
    inputs with ValueError -- the split is an implementation detail, not
    a licence to accept a value the contract forbids."""
    with pytest.raises(ValueError):
        doc_render_iat_directory_table_incomplete(bad_count)
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
    """§3.5.2's `declared_directory_count`, read from the REAL parser.

    This used to be a test-only reimplementation, carrying the note "#39
    will add this computation to parse_pe_header() itself". #39 landed
    (dumpex/core/pe_utils.py computes and returns it), but the mirror
    stayed -- so the four byte-level fixtures below went on asserting
    against a private copy of a definition production had already taken
    over, and would have stayed green through any divergence. Exactly the
    drift this file exists to catch, so: ask the parser."""
    return parsed["declared_directory_count"]


def test_byte_level_captured_through_index5_nonzero_rva_is_true_null(resolve_present):
    """§8.3 item 6b, fixture 1: declared 16, captured through index 5,
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
    """§8.3 item 6b, fixture 2: declared 16, captured through index 5,
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
    """§8.3 item 6b, fixture 3: declared 16, captured only through index
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
    """§8.3 item 6b, fixture 4: NumberOfRvaAndSizes itself uncaptured ->
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

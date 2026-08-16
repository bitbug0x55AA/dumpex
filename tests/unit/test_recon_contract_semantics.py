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
     coverage.render_limitation(), and §3.2/§3.3.3's normalizers in
     process_info (normalize_pid, classify_process_create_time,
     normalize_windows_path, normalize_command_line,
     normalize_image_base, resolve_module_by_base).

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

Not every frozen section admits all three layers, and the final section
of this file ("the frozen normalizers") makes that explicit rather than
leaving it implicit: six of the contract's ten reference functions are
stated as a signature plus an English rule, with no algorithm text to
exec, so layers 2 and 3 do not exist for them and only layer 1 plus
signature equivalence runs. Which function is in which group is pinned
by test_reference_function_body_classification_is_pinned(), so a doc
change that adds or removes a body changes the available coverage
loudly.

§6.1's registry -- which code exists, its source, its fields, and the
exact sentence it renders -- is a fourth artifact pair (markdown table
<-> coverage._CODE_SPECS) and is checked in
tests/unit/test_recon_contract_registry.py.

§3.7.3's not-yet-implemented `retain_completeness_checks_when_not_
evaluated` design (#38) is NOT modelled here: a reference model of an
unimplemented feature is not a semantic check of shipped behavior, and
mixing the two is what made this file's coverage claims hard to read.
It lives in tests/unit/test_recon_contract_retention_prototype.py.
"""
import ast
import inspect
import os
import re
import struct

import pytest

from dumpex.core.pe_utils import (
    parse_pe_header, _resolve_directory_present, _select_iat_outcome,
)
from dumpex.commands.process import _select_console_branch, _select_iat_source_state
from dumpex.core.memory import observe_stream, stream_failure
from dumpex.core.process_info import (
    MAX_ENV_BYTES, MAX_ENV_ENTRIES, classify_process_create_time, normalize_command_line,
    normalize_image_base, normalize_pid, normalize_windows_path, resolve_module_by_base,
    walk_environment_block,
)
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


_PY_FENCE_RE = re.compile(r"^([ \t]*)```python\n(.*?\n)\1```", re.DOTALL | re.MULTILINE)


def _iter_python_blocks(doc: str):
    """Every fenced ```python block in the contract, dedented.

    Fences may be nested inside a markdown list item (indented) or sit
    at the top level (not indented) -- the opening/closing fence's own
    indentation is captured and stripped from every line so exec() sees
    valid, unindented Python either way."""
    for indent, body in _PY_FENCE_RE.findall(doc):
        yield "\n".join(
            line[len(indent):] if line.startswith(indent) else line
            for line in body.splitlines())


def _extract_python_function(doc: str, def_name: str, extra_globals: dict = None):
    """Pull the fenced ```python block that DEFINES `def_name` out of the
    contract, exec() it in an isolated namespace, and return the
    function. This ties the tests below directly to the doc's OWN
    algorithm text: if the contract's pseudocode changes, these tests
    exercise the new version automatically rather than a stale copy
    pasted into the test suite, which is exactly the drift #37's reviews
    kept catching.

    The block is located by searching for a top-level `def <name>(`
    ANYWHERE in it, not by requiring the block to start with one. The
    original version required `dedented.startswith("def <name>(")`, which
    silently made five of the contract's ten reference functions
    unreachable -- `classify_process_create_time`, `normalize_windows_
    path`, `normalize_command_line` and `normalize_image_base` all share
    §3.2's single fence with `normalize_pid` and are therefore not first,
    and §2.1's `open_dump` sits below that block's imports and
    `_STREAM_DISPATCH` table. Worse, the failure was indistinguishable
    from the real thing: this function raised "contract has no ```python
    block defining X()" for functions the contract plainly defines, so a
    caller could not tell "the doc never froze this" from "the extractor
    cannot see it".

    `extra_globals` supplies names a block legitimately reads from its
    surrounding module rather than defining itself (§4.3's
    `walk_environment_block` takes `MAX_ENV_BYTES`/`MAX_ENV_ENTRIES` as
    default arguments). Passing production's own constants there makes
    the defaults a checked fact rather than an untested assumption.
    """
    for dedented in _iter_python_blocks(doc):
        if not re.search(rf"^def {re.escape(def_name)}\(", dedented, re.MULTILINE):
            continue
        ns = dict(extra_globals or {})
        # Deliberately NOT wrapped in try//except: a block that fails to
        # exec is a defect in the contract (or a missing extra_globals
        # entry), and the real traceback names it far better than a
        # rewritten "not found" ever could.
        exec(compile(dedented, f"<contract:{def_name}>", "exec"), ns)
        assert def_name in ns, (
            f"the contract block containing `def {def_name}(` did not bind "
            f"that name after exec -- it is nested inside another "
            f"definition, not a top-level reference function")
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
def doc_select_iat_outcome(doc):
    return _extract_python_function(doc, "select_iat_outcome")


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


# ── §3.5.2: outcome matrix truth table ─────────────────────────────────
#
# (import_directory_present, table_present) -> (walk_descriptors,
# limitation, diagnostic), transcribed row by row from §3.5.2's "Frozen
# consequences of each determined combination" table. Every one of the
# six rows appears here, including the `null | anything` row expanded
# over all three values of the second field -- the contract asserts that
# row absorbs them all, and an expanded table is what checks it.
#
# This is the section that had NO executable coverage until #37's third
# repair pass: which code each pair emits was guarded only by a substring
# assertion over the markdown ("IAT_DIRECTORY_TABLE_INCOMPLETE" in row),
# which cannot fail when production changes. Production now decides all
# three consequences in one place (pe_utils._select_iat_outcome), reached
# by parse_iat() at each of the three sites that used to re-derive their
# own condition.
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


# §3.5.2's outcome table is markdown, but its outcome cells are not
# prose ABOUT the behavior -- they name the codes by symbol. That makes
# the table itself checkable against the selector, the same way §6.1's
# registry is checkable against _CODE_SPECS (see
# test_recon_contract_registry.py), and it closes the one loop the truth
# table above leaves open: _IAT_OUTCOME_CASES is a HAND transcription of
# these rows, so without this, editing a row without editing the
# transcription would go unnoticed.
#
# The only wording rule involved is negation: a code token preceded by
# "No" is one the row says must NOT fire. Everything else is symbol
# matching.
_OUTCOME_ROW_RE = re.compile(r"^\| (.*?) \| (.*?) \| (.*) \|$")
_OUTCOME_CODE_RE = re.compile(r"`(IAT_[A-Z_]+)`")
_TRISTATE = {"true": True, "false": False, "null": None}


def _parse_outcome_table(doc: str) -> list:
    """(import_values, table_values, asserted_codes, negated_codes) per
    row. A cell naming no tri-state value at all ("anything") stands for
    all three, which is exactly what the `null | anything` row claims."""
    section = doc.split("Frozen consequences of each determined combination", 1)[1]
    section = section.split("Restated as a reference selector", 1)[0]
    rows = []
    for line in section.splitlines():
        m = _OUTCOME_ROW_RE.match(line)
        if not m or m.group(1).startswith("---") or "`import_directory_present`" in m.group(1):
            continue
        import_cell, table_cell, outcome_cell = m.groups()
        asserted, negated = set(), set()
        for cm in _OUTCOME_CODE_RE.finditer(outcome_cell):
            preceding = outcome_cell[max(0, cm.start() - 4):cm.start()].rstrip()
            (negated if preceding.endswith("No") else asserted).add(cm.group(1))

        def values(cell):
            found = [_TRISTATE[t] for t in re.findall(r"`(true|false|null)`", cell)]
            return found or list(_TRISTATE.values())

        rows.append((values(import_cell), values(table_cell), asserted, negated))
    return rows


def test_outcome_table_parses(doc):
    """Guards the row regex: a layout change that stopped matching would
    turn the conformance check below into a vacuous pass."""
    rows = _parse_outcome_table(doc)
    assert len(rows) == 6, f"§3.5.2's outcome table parsed as {len(rows)} rows, expected 6"
    covered = {(i, t) for imports, tables, _a, _n in rows for i in imports for t in tables}
    assert len(covered) == 9, (
        f"§3.5.2 claims every (import_directory_present, table_present) pair "
        f"appears in exactly one row; the table covers {sorted(map(str, covered))}")


def test_outcome_table_rows_name_exactly_the_codes_production_emits(doc):
    """Each row's outcome cell, against pe_utils._select_iat_outcome:
    every code the row asserts must be one production emits for that
    pair, every code production emits must be named in the row, and no
    code the row explicitly negates ("No `X`") may be emitted."""
    for imports, tables, asserted, negated in _parse_outcome_table(doc):
        for import_present in imports:
            for table_present in tables:
                outcome = _select_iat_outcome(import_present, table_present)
                emitted = {c for c in (outcome.limitation, outcome.diagnostic) if c}
                assert asserted == emitted, (
                    f"({import_present}, {table_present}): §3.5.2's row names "
                    f"{sorted(asserted)}, production emits {sorted(emitted)}")
                assert not (negated & emitted), (
                    f"({import_present}, {table_present}): §3.5.2's row says "
                    f"{sorted(negated & emitted)} must NOT fire, production emits it")


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


@pytest.mark.parametrize("case_id,import_present,table_present,expected",
                         _IAT_OUTCOME_CASES, ids=[c[0] for c in _IAT_OUTCOME_CASES])
def test_doc_iat_outcome_pseudocode_matches_prose_truth_table(
        doc_select_iat_outcome, case_id, import_present, table_present, expected):
    """§3.5.2's six prose rows against §3.5.2's own selector. This is the
    layer that would have caught the table and the selector disagreeing
    before either was implemented."""
    assert tuple(doc_select_iat_outcome(import_present, table_present)) == expected


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


@pytest.mark.parametrize("import_present", _EQUIV_PRESENT)
@pytest.mark.parametrize("table_present", _EQUIV_PRESENT)
def test_doc_select_iat_outcome_matches_production(
        doc_select_iat_outcome, import_present, table_present):
    """Inputs deliberately include 1/0 in both slots -- the doc's selector
    returns a plain tuple and production returns a frozen IatOutcome, so
    the comparison is on the tuple, but the DECISION each makes must be
    identical even for values only an `is`-comparison separates."""
    _assert_same_parameter_names(doc_select_iat_outcome, _select_iat_outcome)
    assert tuple(doc_select_iat_outcome(import_present, table_present)) == \
        _outcome_tuple(_select_iat_outcome(import_present, table_present))


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


# ══ §3.2/§3.3.3/§4.3: the frozen normalizers ═══════════════════════════
#
# The layers above cover §3.5.2/§3.7.4/§3.8/§6.1 -- four of the
# contract's ten reference functions. The other six were frozen with no
# executable coverage at all, and five of them could not even be
# EXTRACTED: _extract_python_function() used to require its target to be
# the first `def` in its fence, so §3.2's block (five normalizers sharing
# one fence) yielded only normalize_pid, and §2.1's open_dump (below that
# block's imports) yielded nothing. See that function's own docstring.
#
# With extraction fixed, the six split by how the contract states them,
# and the split decides which layers are even POSSIBLE:
#
#   FULL BODY -- normalize_pid, classify_process_create_time. All three
#     layers apply, exactly as for the §3.5.2 selectors.
#
#   SIGNATURE + PROSE DOCSTRING only -- normalize_windows_path,
#     normalize_command_line, normalize_image_base,
#     resolve_module_by_base, walk_environment_block, observe_stream,
#     stream_failure. There is no algorithm text to exec, so layers 2 and
#     3 do not exist for these: running the doc's copy would only assert
#     that a function returning None returns None. What IS checkable is
#     layer 1 (the prose, hand-transcribed, against production) plus
#     signature equivalence -- and that is what runs below.
#
# test_reference_function_body_classification_is_pinned() freezes which
# function is in which group, so fleshing a docstring out into real
# pseudocode is noticed (it should gain layers 2+3) and hollowing one out
# is caught (it would silently lose them).

_FULL_BODY_REFERENCE_FUNCTIONS = frozenset({
    "normalize_pid", "classify_process_create_time", "resolve_present",
    "select_iat_outcome", "select_iat_source_state", "select_console_branch",
    "render_iat_directory_table_incomplete", "open_dump",
})
_PROSE_ONLY_REFERENCE_FUNCTIONS = frozenset({
    "normalize_windows_path", "normalize_command_line", "normalize_image_base",
    "resolve_module_by_base", "walk_environment_block", "observe_stream",
    "stream_failure",
})

# §4.3's walk_environment_block reads two budget constants as default
# arguments -- names it legitimately expects from its surrounding module
# rather than defining itself. Not a defect; see
# test_walk_environment_block_defaults_reference_the_budget_constants().
_ENV_WALK_SENTINELS = {"MAX_ENV_BYTES": object(), "MAX_ENV_ENTRIES": object()}

# §2.1's open_dump is located and classified by AST like every other
# reference function, but never exec()'d: its block imports a dozen
# minidump-library symbols and calls parse_handle_stream(), so running it
# would mean either importing that library here or stubbing out enough of
# it that the exec proves nothing. open_dump is I/O -- there is no truth
# table to run it against either way, so nothing is lost by leaving it at
# the AST level.
_NOT_EXECUTABLE_HERE = frozenset({"open_dump"})


def _reference_function_defs(doc: str) -> dict:
    """{name: ast.FunctionDef} for every top-level `def` the contract's
    ```python blocks declare.

    Not every ```python block is module text. Two are deliberately
    illustrative FRAGMENTS -- §6's `build_coverage_report(sources, *,
    ...)` call signature and §4.3's bare `while (env_len := ...)` loop
    header -- neither of which parses on its own and neither of which
    could contain a top-level `def`. They are skipped rather than
    treated as defects."""
    found = {}
    for block in _iter_python_blocks(doc):
        try:
            tree = ast.parse(block)
        except SyntaxError:
            continue
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                found[node.name] = node
    return found


def _is_docstring_only(node: ast.FunctionDef) -> bool:
    return (len(node.body) == 1 and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str))


def test_reference_function_body_classification_is_pinned(doc):
    """Which reference functions carry real algorithm text, and which are
    frozen as a signature plus prose. A change in either direction
    changes which layers of this file can cover them, so it must not
    happen silently."""
    defs = _reference_function_defs(doc)
    expected = _FULL_BODY_REFERENCE_FUNCTIONS | _PROSE_ONLY_REFERENCE_FUNCTIONS
    assert set(defs) == expected, (
        f"the contract's set of reference functions changed: "
        f"added={sorted(set(defs) - expected)} "
        f"removed={sorted(expected - set(defs))} -- classify each new one into "
        f"_FULL_BODY_/_PROSE_ONLY_REFERENCE_FUNCTIONS and give it the layers "
        f"that classification allows")
    prose_only = {n for n, node in defs.items() if _is_docstring_only(node)}
    assert prose_only == _PROSE_ONLY_REFERENCE_FUNCTIONS, (
        f"gained real pseudocode (move to _FULL_BODY_REFERENCE_FUNCTIONS and "
        f"wire into layers 2+3): {sorted(_PROSE_ONLY_REFERENCE_FUNCTIONS - prose_only)}; "
        f"lost its body (layers 2+3 would silently stop covering it): "
        f"{sorted(prose_only - _PROSE_ONLY_REFERENCE_FUNCTIONS)}")


@pytest.mark.parametrize("name", sorted((_FULL_BODY_REFERENCE_FUNCTIONS |
                                         _PROSE_ONLY_REFERENCE_FUNCTIONS) -
                                        _NOT_EXECUTABLE_HERE))
def test_every_reference_function_is_extractable(doc, name):
    """The regression that motivated rewriting _extract_python_function():
    four of these raised "contract has no ```python block defining X()"
    -- a message naming the contract as the culprit for what was purely
    an extractor limitation. (open_dump was a fifth; it is excluded here
    for the separate reason given at _NOT_EXECUTABLE_HERE, and is still
    covered structurally by the classification test above.)"""
    assert callable(_extract_python_function(doc, name, _ENV_WALK_SENTINELS))


# ── layers 1+2+3: normalize_pid, classify_process_create_time ──────────

@pytest.fixture(scope="module")
def doc_normalize_pid(doc):
    return _extract_python_function(doc, "normalize_pid")


@pytest.fixture(scope="module")
def doc_classify_process_create_time(doc):
    return _extract_python_function(doc, "classify_process_create_time")


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


@pytest.mark.parametrize("raw,expected", _PID_CASES)
def test_doc_normalize_pid_pseudocode_matches_prose_truth_table(
        doc_normalize_pid, raw, expected):
    assert doc_normalize_pid(raw) == expected


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


@pytest.mark.parametrize("raw,expected", _CREATE_TIME_CASES)
def test_doc_classify_process_create_time_matches_prose_truth_table(
        doc_classify_process_create_time, raw, expected):
    assert doc_classify_process_create_time(raw) == expected


_NORMALIZER_EQUIV_INPUTS = (
    0, 1, -1, 2, 0xFFFFFFFF, 0x100000000, 0xFFFFFFFFFFFFFFFF, 0x10000000000000000,
    True, False, None, "0", "1", 1.0, 0.0, [], (), object(),
)


@pytest.mark.parametrize("raw", _NORMALIZER_EQUIV_INPUTS)
def test_doc_normalize_pid_matches_production(doc_normalize_pid, raw):
    _assert_same_parameter_names(doc_normalize_pid, normalize_pid)
    assert doc_normalize_pid(raw) == normalize_pid(raw)


@pytest.mark.parametrize("raw", _NORMALIZER_EQUIV_INPUTS)
def test_doc_classify_process_create_time_matches_production(
        doc_classify_process_create_time, raw):
    _assert_same_parameter_names(doc_classify_process_create_time,
                                 classify_process_create_time)
    assert doc_classify_process_create_time(raw) == classify_process_create_time(raw)


# ── layer 1 only: the prose-frozen normalizers ─────────────────────────
#
# §3.2 states these as a signature and a rule in English. The rule is
# transcribed here and run against production; there is no pseudocode to
# run it against a second time.
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


# ── signature equivalence for the prose-frozen functions ───────────────

@pytest.mark.parametrize("name,production", [
    ("normalize_windows_path", normalize_windows_path),
    ("normalize_command_line", normalize_command_line),
    ("normalize_image_base", normalize_image_base),
    ("resolve_module_by_base", resolve_module_by_base),
    ("walk_environment_block", walk_environment_block),
    ("observe_stream", observe_stream),
    ("stream_failure", stream_failure),
])
def test_prose_frozen_functions_match_their_production_signature(doc, name, production):
    """With no body to compare, the signature IS the machine-checkable
    part of the freeze -- and it is not a formality: observe_stream's
    five parameters and resolve_module_by_base's two are the shape
    #38-#44 implement against."""
    doc_fn = _extract_python_function(doc, name, _ENV_WALK_SENTINELS)
    _assert_same_parameter_names(doc_fn, production)


def test_walk_environment_block_defaults_reference_the_budget_constants(doc):
    """§4.3's signature must take its budgets FROM the module constants,
    not hardcode two numbers that then drift from MAX_ENV_BYTES/
    MAX_ENV_ENTRIES.

    Checked with sentinel objects rather than by injecting the real
    constants and comparing: injecting them and asserting equality would
    be circular -- it passes both for a doc that spells the name and for
    one that hardcodes today's value. Identity against a sentinel proves
    the doc spells the NAME. Production's own defaults are then checked
    against the real constants separately."""
    doc_fn = _extract_python_function(doc, "walk_environment_block", _ENV_WALK_SENTINELS)
    doc_defaults = {p.name: p.default
                    for p in inspect.signature(doc_fn).parameters.values()}
    assert doc_defaults["max_bytes"] is _ENV_WALK_SENTINELS["MAX_ENV_BYTES"]
    assert doc_defaults["max_entries"] is _ENV_WALK_SENTINELS["MAX_ENV_ENTRIES"]

    prod_defaults = {p.name: p.default
                     for p in inspect.signature(walk_environment_block).parameters.values()}
    assert prod_defaults["max_bytes"] == MAX_ENV_BYTES
    assert prod_defaults["max_entries"] == MAX_ENV_ENTRIES

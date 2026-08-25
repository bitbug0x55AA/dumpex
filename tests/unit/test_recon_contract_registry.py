"""
Registry conformance for docs/developer/recon_process_sysinfo_handles_contract.md §6.1.

test_recon_contract_doc.py checks the document's STRUCTURE and
test_recon_contract_semantics.py checks its ALGORITHMS. Neither one
checks the third thing the contract freezes: the code registry -- which
`LimitationCode` exists, which source it is fixed to, which structured
fields it may carry, and the exact sentence it renders.

That registry is stated twice. §6.1 states it as a markdown table;
`dumpex/output/coverage.py` states it as `_CODE_SPECS`. §6.1's own
maintenance note says a row and its `_CodeSpec` "must update in the same
change -- a code whose trigger conditions or optional fields drift out of
sync with this table has shipped three times already in this contract's
own revision history." Nothing enforced that. This file does.

Every assertion here compares the two artifacts DIRECTLY, so it fails in
both directions and for the right reason:

  * reword a rendered template in the markdown -> RED, because that
    column is not prose about the behavior, it IS the sentence
    `render_limitation()` emits, verbatim, into real output;
  * change a `_render_*` function, a `fixed_source`, or an
    `allowed_fields` set without touching §6.1 -> RED.

What this file deliberately does NOT do is assert on the contract's
explanatory prose. A sentence that merely DESCRIBES a rule is checked by
running the rule, never by matching its wording -- see the module
docstring of test_recon_contract_semantics.py for why.

Note the asymmetry in scope: §6.1 is titled "New `LimitationCode`
members", so it declares a SUBSET of `_CODE_SPECS` (the codes issues
#38-#44 add), not all of it. Every check below therefore runs
doc -> production. The reverse direction -- every `LimitationCode` has a
`_CODE_SPECS` entry -- is already enforced by
test_output_coverage.py's `set(_CODE_SPECS) == set(LimitationCode)`.
"""
import os
import re

import pytest

from dumpex.output.coverage import (
    CoverageLimitation, LimitationCode, SourceObservation, SourceRequirement,
    SourceState, render_limitation,
    _CODE_SPECS, _ENV_TRUNCATION_SCOPES, _IAT_TRUNCATION_SCOPES,
    _STRUCTURED_FIELD_DEFAULTS, _derive_required_source_limitation,
)

_DOC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "docs", "developer", "recon_process_sysinfo_handles_contract.md")

# §6.1's row shape: | `CODE` | `source` | fields | rendered template |
_ROW_RE = re.compile(r"^\| `([A-Z][A-Z0-9_]+)` \| (.*?) \| (.*?) \| (.*) \|$")
_BACKTICKED_RE = re.compile(r"`([a-z_]+)`")
_QUOTED_RE = re.compile(r'"([^"]*)"')

# A `{name}` hole in a rendered template, and the CoverageLimitation
# field whose value fills it. Deliberately a closed set:
# test_every_template_placeholder_is_known() fails on any placeholder
# that isn't listed here, so a newly-added template with a `{foo}` hole
# cannot quietly render as an unchecked string.
#
# Templates also contain Python EXPRESSIONS in braces -- §6.1's
# ENVIRONMENT_ARCHITECTURE_UNSUPPORTED carries a
# `{'/'.join(unavailable_fields)}` clause. Those are not placeholders and
# are not expanded; _PLACEHOLDER_RE only matches a bare identifier, and
# the conditional clauses they belong to get their own dedicated tests at
# the bottom of this file.
_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")
_PLACEHOLDER_FIELDS = {
    "count": "affected_count",
    "scope": "scope",
    "limit": "budget_limit",
    "consumed": "budget_consumed",
    "detail": "detail",
}

# Representative values for building one real CoverageLimitation per
# code. Only fields the code actually declares in allowed_fields are
# passed, so each construction goes through that code's own real
# validator -- a code whose §6.1 `fields` column claims a field its
# _CodeSpec forbids raises here rather than failing an equality check.
#
# `scope` is per-code because two codes restrict it to a budget-scope
# vocabulary of their own; both vocabularies are imported from
# production rather than retyped, so adding a scope value there cannot
# leave this file asserting against a stale list.
_FIELD_VALUES = {
    "affected_count": 3,
    "detail": "SOME_DETAIL",
    "budget_limit": 10,
    "budget_consumed": 10,
}
_SCOPE_BY_CODE = {
    LimitationCode.IAT_ENTRIES_TRUNCATED: sorted(_IAT_TRUNCATION_SCOPES)[0],
    # a BUDGET scope, so the optional budget clause is present in the
    # default fixture; the clause-omitting scopes get their own test.
    LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED: "environment_bytes",
}
_DEFAULT_SCOPE = "dump"


def _read_doc() -> str:
    with open(_DOC_PATH, encoding="utf-8") as fh:
        return fh.read()


def _parse_registry_rows() -> list:
    """(code, source cell, fields cell, template cell) for every §6.1 row.

    Collected at import time, not in a fixture, because every check below
    is parametrized over it -- a parse failure must surface as a missing
    test id, which test_registry_table_parses() then names explicitly.
    """
    section = _read_doc().split("### 6.1 ", 1)[1].split("### 6.2 ", 1)[0]
    return [m.groups() for line in section.splitlines()
            if (m := _ROW_RE.match(line))]


_ROWS = _parse_registry_rows()
_IDS = [r[0] for r in _ROWS]


def _declared_fields(fields_cell: str) -> set:
    """The structured fields a §6.1 row's `fields` column declares.

    The column mixes field names with backticked prose -- "`affected_
    count` (**optional** -- `null` or a positive integer; `0`, negative
    values, and `bool` are never legal)". Filtering against production's
    own field universe (`_STRUCTURED_FIELD_DEFAULTS`) is what separates
    the two, and it is safe in both directions: a field the doc OMITS is
    still missing from the filtered set (mismatch, red), and a field the
    doc invents that production doesn't allow is still present in it
    (mismatch, red). Only genuine non-field words are dropped.
    """
    if fields_cell.strip() == "—":
        return set()
    return {t for t in _BACKTICKED_RE.findall(fields_cell)
            if t in _STRUCTURED_FIELD_DEFAULTS}


def _build_limitation(code: LimitationCode) -> CoverageLimitation:
    """One real CoverageLimitation for `code`, carrying every field its
    own _CodeSpec permits and nothing else."""
    spec = _CODE_SPECS[code]
    allowed = spec.allowed_fields or frozenset()
    fields = {f: v for f, v in _FIELD_VALUES.items() if f in allowed}
    if "scope" in allowed:
        fields["scope"] = _SCOPE_BY_CODE.get(code, _DEFAULT_SCOPE)
    return CoverageLimitation(code=code, source=spec.fixed_source, **fields)


def _expand(template: str, limitation: CoverageLimitation) -> str:
    """Fill a §6.1 template's `{name}` holes from the limitation that was
    actually built, so the comparison never depends on a hardcoded
    expected value drifting away from the fixture."""
    return _PLACEHOLDER_RE.sub(
        lambda m: str(getattr(limitation, _PLACEHOLDER_FIELDS[m.group(1)])), template)


# ── parser guards ───────────────────────────────────────────────────────

def test_registry_table_parses():
    """Everything below is parametrized over _ROWS, so a broken row regex
    would silently reduce this file to zero assertions instead of
    failing. §6.1 declares 37 codes today; the floor is deliberately
    below that so adding a code doesn't fail here, but a structural
    change to the table's column layout does."""
    assert len(_ROWS) >= 30, (
        f"§6.1's table parsed as {len(_ROWS)} rows -- the column layout "
        f"changed and _ROW_RE no longer matches it")
    assert len(set(_IDS)) == len(_IDS), "§6.1 declares a code more than once"


def test_every_template_placeholder_is_known():
    """Guards _PLACEHOLDER_FIELDS against silently going stale: a new
    template hole nobody taught this file about would otherwise survive
    expansion as a literal `{foo}` and fail with a confusing diff, or --
    worse -- match a production renderer that emits the same literal."""
    unknown = set()
    for _code, _src, _fields, template_cell in _ROWS:
        for quoted in _QUOTED_RE.findall(template_cell):
            unknown |= {n for n in _PLACEHOLDER_RE.findall(quoted)
                        if n not in _PLACEHOLDER_FIELDS}
    assert not unknown, (
        f"§6.1 templates use placeholders this file cannot expand: "
        f"{sorted(unknown)} -- add them to _PLACEHOLDER_FIELDS with the "
        f"CoverageLimitation field each one reads")


# ── §6.1 row <-> _CodeSpec ──────────────────────────────────────────────

@pytest.mark.parametrize("code,source_cell,fields_cell,template_cell", _ROWS, ids=_IDS)
def test_declared_code_is_a_live_limitation_code(code, source_cell, fields_cell, template_cell):
    assert code in LimitationCode.__members__, (
        f"§6.1 declares {code}, which is not a LimitationCode member")


@pytest.mark.parametrize("code,source_cell,fields_cell,template_cell", _ROWS, ids=_IDS)
def test_source_column_matches_fixed_source(code, source_cell, fields_cell, template_cell):
    """§6.1's `source` column is the code's `_CodeSpec.fixed_source` --
    construction rejects any other source, since the rendered sentence
    names that stream specifically."""
    spec = _CODE_SPECS[LimitationCode[code]]
    assert _BACKTICKED_RE.findall(source_cell) == [spec.fixed_source], (
        f"{code}: §6.1 says source={source_cell!r}, production says "
        f"fixed_source={spec.fixed_source!r}")


@pytest.mark.parametrize("code,source_cell,fields_cell,template_cell", _ROWS, ids=_IDS)
def test_fields_column_matches_allowed_fields(code, source_cell, fields_cell, template_cell):
    """§6.1's `fields` column is the code's `_CodeSpec.allowed_fields`.
    Drift here is the exact failure the table's maintenance note
    describes: a caller attaching data a fixed-sentence renderer ignores,
    or a validator rejecting a field the contract promises."""
    spec = _CODE_SPECS[LimitationCode[code]]
    assert _declared_fields(fields_cell) == set(spec.allowed_fields or ()), (
        f"{code}: §6.1 declares fields {sorted(_declared_fields(fields_cell))}, "
        f"production allows {sorted(spec.allowed_fields or ())}")


@pytest.mark.parametrize("code,source_cell,fields_cell,template_cell", _ROWS, ids=_IDS)
def test_rendered_template_column_is_what_production_actually_renders(
        code, source_cell, fields_cell, template_cell):
    """The one that makes the contract text and the code logic fail
    TOGETHER. §6.1's rendered-template column is quoted shipped output,
    not a description of it, so an exact comparison is correct here in a
    way it never is for explanatory prose: this string appears verbatim
    in `coverage.limitations[*].message`.

    A code whose column lists several templates (an optional field
    selecting between two whole sentences) satisfies this by matching any
    one of them; the OTHER renderings get their own explicit tests below,
    so listing two and implementing one still fails."""
    limitation = _build_limitation(LimitationCode[code])
    rendered = render_limitation(limitation)
    candidates = [_expand(q, limitation) for q in _QUOTED_RE.findall(template_cell)]
    assert candidates, f"{code}: §6.1's template column has no quoted template"
    assert rendered in candidates, (
        f"{code}: production renders {rendered!r}, but §6.1 freezes "
        f"{candidates!r}")


# ── §6.1's capability-flag list <-> _CodeSpec flags ─────────────────────

def _capability_list_section() -> str:
    doc = _read_doc()
    section = doc.split("Capability flags:", 1)[1]
    return section.split("### 6.2 ", 1)[0]


def _codes_named_in(text: str) -> set:
    return {t for t in re.findall(r"`([A-Z][A-Z0-9_]+)`", text)
            if t in LimitationCode.__members__}


def test_absent_capable_list_matches_production():
    """§6.1's `absent_capable` bullet names the codes usable as a
    `SourceRequirement.absent_code`. Previously this was a hardcoded
    tuple in test_recon_contract_doc.py that had to be kept in sync with
    the doc BY HAND (with its own test to check the hand-sync), while
    production's `_CodeSpec.absent_capable` -- the flag that actually
    decides whether `SourceRequirement.__post_init__` accepts the code --
    was never consulted at all. This compares the doc to the flag
    directly, so there is no third copy to drift."""
    bullet = _capability_list_section().split("- `caller_buildable`", 1)[0]
    declared = _codes_named_in(bullet)
    production = {c.name for c, s in _CODE_SPECS.items()
                  if s.absent_capable and c.name in _IDS}
    assert declared == production, (
        f"§6.1 declares absent_capable={sorted(declared)}, production has "
        f"{sorted(production)}")


def test_caller_buildable_is_every_other_code_in_the_table():
    """§6.1: "`caller_buildable` only: every other code in the table."
    Stated as a rule rather than a list, so it is checked as one."""
    absent_capable = {c.name for c, s in _CODE_SPECS.items() if s.absent_capable}
    for code in _IDS:
        spec = _CODE_SPECS[LimitationCode[code]]
        if code in absent_capable:
            continue
        assert spec.caller_buildable, (
            f"{code} is neither absent_capable nor caller_buildable, but §6.1 "
            f"says every code in the table is one or the other")


def test_no_code_in_the_table_is_group_capable():
    """§6.1: "`group_capable`: none. No code here describes a
    multi-source group."""
    leaked = sorted(c for c in _IDS if _CODE_SPECS[LimitationCode[c]].group_capable)
    assert not leaked, (
        f"§6.1 declares no group_capable code, but production flags {leaked} "
        f"-- a multi-source EvaluationRequirement.all_absent_code would now "
        f"accept a code whose sentence describes a single stream")


# ── the all-absent derivation path cannot render a placeholder ──────────

_ABSENT_CAPABLE_CODES = sorted(
    (c for c, s in _CODE_SPECS.items() if s.absent_capable), key=lambda c: c.name)


@pytest.mark.parametrize("code", _ABSENT_CAPABLE_CODES, ids=lambda c: c.name)
def test_absent_capable_codes_render_cleanly_through_the_derivation_path(code):
    """§6.1: "No `absent_capable` code may interpolate a field the
    derivation path cannot set." That branch builds its limitation with
    no `detail` and no `affected_count`, so a template with a hole
    renders it as the literal string "None".

    The doc-side version of this check asserted `"{" not in row` against
    the markdown, which tests the table's punctuation rather than the
    behavior: a renderer that interpolates a field the table doesn't
    mention passes it. This drives the REAL path --
    `_derive_required_source_limitation()` with a genuinely ABSENT
    observation and a bare requirement -- and inspects the sentence that
    comes out.

    It also covers every absent_capable code in the enum rather than the
    seven §6.1 happens to introduce, so a pre-existing code that grows a
    placeholder fails here too.
    """
    spec = _CODE_SPECS[code]
    name = spec.fixed_source or "some_source"
    obs = SourceObservation(name=name, state=SourceState.ABSENT)
    limitation = _derive_required_source_limitation(
        obs, SourceRequirement(source=name, absent_code=code), {name: obs})
    assert limitation is not None, (
        f"{code.name} is absent_capable but produced no limitation for an "
        f"ABSENT source")
    rendered = render_limitation(limitation)
    assert "None" not in rendered, (
        f"{code.name} interpolates a field the all-absent branch never sets: "
        f"{rendered!r}")
    assert "{" not in rendered and "}" not in rendered, (
        f"{code.name} rendered an unfilled template hole: {rendered!r}")


def test_every_absent_code_the_contract_configures_is_absent_capable():
    """A section specifying `absent_code=X` while X is not flagged
    absent_capable specifies a configuration that raises on the first
    call -- `SourceRequirement.__post_init__` rejects it. Checked against
    the live flag rather than against §6.1's bullet list, so the doc
    cannot authorize a code production refuses."""
    used = set(re.findall(r"absent_code=([A-Z][A-Z0-9_]+)", _read_doc()))
    unusable = sorted(
        c for c in used
        if c not in LimitationCode.__members__
        or not _CODE_SPECS[LimitationCode[c]].absent_capable)
    assert not unusable, (
        f"the contract configures absent_code={unusable}, which "
        f"SourceRequirement.__post_init__ rejects at construction time")


# ── the conditional-clause renderings §6.1 states in a second template ──
#
# Three codes render more than one sentence, selected by an optional
# field. The row-level test above accepts any one of a row's quoted
# templates; these pin the specific input that selects each, so a row
# that lists two renderings and a renderer that implements one still
# fails.

def test_iat_directory_table_incomplete_renders_the_count_free_sentence_for_none():
    """§6.1's second template for this code: `affected_count is None` ->
    the count-free sentence. This is the code whose optional
    affected_count the table singles out as its one exception."""
    text = render_limitation(CoverageLimitation(
        code=LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE, source="iat",
        affected_count=None))
    assert text == ("the data directory table was not captured; import/IAT "
                    "directory presence is undetermined")


@pytest.mark.parametrize("scope", sorted(_ENV_TRUNCATION_SCOPES - {"environment_bytes",
                                                                   "environment_entries"}))
def test_environment_block_truncated_omits_the_budget_clause_for_non_budget_scopes(scope):
    """§6.1: "the budget clause is omitted when `scope` is
    `captured_segment` or `undecodable_entry`". Those scopes also require
    budget_limit/budget_consumed to be unset, so this doubles as a check
    that the two halves of the rule agree."""
    text = render_limitation(CoverageLimitation(
        code=LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED, source="environment_block",
        affected_count=3, scope=scope))
    assert text == ("environment block capture ended before a terminator was "
                    "found; 3 entry(ies) kept")
    assert "budget" not in text


def test_environment_architecture_unsupported_appends_unavailable_fields():
    """§6.1's appended clause for this code: `"; {'/'.join(unavailable_
    fields)} unavailable"` when `unavailable_fields` is set. §4.2 makes
    `current_directory` the only value that reaches it."""
    text = render_limitation(CoverageLimitation(
        code=LimitationCode.ENVIRONMENT_ARCHITECTURE_UNSUPPORTED,
        source="environment_block", detail="ARM64",
        unavailable_fields=("current_directory",)))
    assert text == ("environment block not walked: unsupported processor "
                    "architecture (ARM64); current_directory unavailable")

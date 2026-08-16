"""
Contract-DOCUMENT tests for docs/recon_process_sysinfo_handles_contract.md
(issue #37's completion gate, items 1 and 2).

This file checks the things that are true of the contract AS A DOCUMENT
-- that it is independently readable, that its registry tables are
internally coherent, and that its live-enum invariants hold. It does not
check behavior. Anything a reader could describe as "the contract says
the console should do X" belongs somewhere executable:

  * §3.5.2/§3.7.4/§3.8's selectors, §3.2/§3.3.3's normalizers and every
    other reference function -> tests/unit/test_recon_contract_semantics.py,
    which exec()s the contract's own ```python blocks and runs them
    against production over shared truth tables.
  * §6.1's code registry (source, fields, rendered sentence) ->
    tests/unit/test_recon_contract_registry.py, which diffs the markdown
    table against dumpex.output.coverage._CODE_SPECS directly.

That split is the point, and it is a correction of how this file used to
work. It previously carried ~15 substring assertions over the contract's
EXPLANATORY PROSE -- `assert "RVA is zero (regardless of \\`Size\\`)" in
normalized`, `assert "index 1 **uncaptured**" in normalized`, and so on.
Those fail in both wrong directions at once: rewording a sentence turns
them red with no defect present, and changing the algorithm they
describe leaves them green with a real one. A `_normalize_ws()` helper
was added to survive markdown reflow, which fixed the line-wrapping
symptom without touching the underlying problem, namely that matching
prose is not checking behavior. Every one of those assertions now has an
executable counterpart in one of the two files above and has been
removed from here.

Two things are still checked mechanically, because both failed review at
least once while the contract was being written and neither is visible to
any other test:

1. The document is INDEPENDENTLY READABLE. Issues #38-#44 implement
   against it alone, so no normative rule may depend on an earlier,
   unpublished draft ("unchanged from rev2", "as in rev3", ...). Only
   Appendix A -- explicitly non-normative -- may mention older
   revisions.

2. Diagnostic codes CANNOT BECOME LIMITATIONS. The contract's whole
   optional-check isolation rule (§1.6/§3.5.4) rests on the diagnostic
   codes never being LimitationCode members: a CoverageLimitation always
   downgrades coverage.status, so a successfully-completed, informative
   check that got filed as a limitation would report a MORE complete
   result as a LESS complete one. This is asserted against the LIVE enum,
   not against the document, so a later child that adds one of them to
   dumpex.output.coverage.LimitationCode fails here immediately.

Exactly one prose check survives, at the bottom, and the comment above it
says why it is not a gap: it forbids a gating condition, and a
prohibition has no positive behavior to execute.
"""
import os
import re

import pytest

from dumpex.output.coverage import LimitationCode

_DOC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "docs", "recon_process_sysinfo_handles_contract.md")

# Codes the contract introduces all start with one of these prefixes
# (followed by an underscore). Deliberately anchored that way so the
# document's other SHOUTY_CASE tokens -- PROCESSOR_ARCHITECTURE,
# IMAGE_DIRECTORY_ENTRY_IMPORT, MINIDUMP_HANDLE_DESCRIPTOR, MAX_IAT_DLLS,
# the pre-existing PID_*/SYSINFO_*/SOURCE_* codes -- are not mistaken for
# newly-frozen codes.
_CODE_PREFIXES = ("PROCESS", "IAT", "ENVIRONMENT", "HANDLES", "HANDLE")
_CODE_TOKEN_RE = re.compile(
    r"`((?:%s)_[A-Z0-9_]+)`" % "|".join(_CODE_PREFIXES))
_NOT_A_CODE = ("MAX_",)

_LIMITATION_ROW_RE = re.compile(r"^\| `([A-Z][A-Z0-9_]+)` \|")
_DIAGNOSTIC_ROW_RE = re.compile(r"^\| \d+ \| `([A-Z][A-Z0-9_]+)` \|")

_REQUIRED_SECTIONS = (
    "## §0 Scope, non-goals, and how the pieces fit",
    "## §1 Shared vocabulary, formatting, and ordering rules",
    "## §2 Loader contract",
    "## §3 `--process`",
    "## §4 `--sysinfo`",
    "## §5 `--handles`",
    "## §6 Complete code registry",
    "## §7 CSV, compatibility, and schema v2.13",
    "## §8 Acceptance gate",
    "## Appendix A — revision history (non-normative)",
)

# The contract's §6.3: these keep their LimitationCode membership after
# --pid/--peb are removed, so historical documents stay renderable.
_RETIRED_BUT_RETAINED = (
    "PID_SOURCES_ABSENT", "PID_THREAD_LIST_FALLBACK",
    "PID_EXCEPTION_TID_FALLBACK", "PID_NO_USABLE_FALLBACK",
    "PEB_UNAVAILABLE",
)


@pytest.fixture(scope="module")
def doc() -> str:
    with open(_DOC_PATH, encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def normative_body(doc: str) -> str:
    """Everything before Appendix A. Appendix A/B are explicitly
    non-normative and are the ONLY place older drafts may be named."""
    head, sep, _tail = doc.partition("## Appendix A")
    assert sep, "the contract must keep a clearly delimited Appendix A"
    return head


def _rows(doc: str, start: str, end: str, pattern: re.Pattern) -> list:
    section = doc.split(start, 1)[1].split(end, 1)[0]
    return [m.group(1) for line in section.splitlines()
            if (m := pattern.match(line))]


@pytest.fixture(scope="module")
def limitation_codes(doc: str) -> list:
    return _rows(doc, "### 6.1 ", "### 6.2 ", _LIMITATION_ROW_RE)


@pytest.fixture(scope="module")
def diagnostic_codes(doc: str) -> list:
    return _rows(doc, "### 6.2 ", "### 6.3 ", _DIAGNOSTIC_ROW_RE)


# ── Gate item 1: independently readable ─────────────────────────────────

def test_document_states_a_revision_matching_its_own_history(doc):
    """The header's revision number must exist and must match the newest
    entry in Appendix A.

    Previously this asserted the literal string "revision 4", which made
    every revision bump a test failure with no defect behind it -- the
    same wording-coupling this file exists to get out of. Comparing the
    header to the history checks the property that actually matters: a
    reader cannot be told they are holding rev4 while the history stops
    at rev3."""
    header = doc[:600]
    stated = re.search(r"(?i)revision (\d+)", header)
    assert stated, f"the contract header states no revision: {header[:200]!r}"
    appendix = doc.split("## Appendix A", 1)[1]
    # `\b` rather than a closing `**`: Appendix A's entries carry
    # qualifiers inside the bold span ("**rev4 (this revision)**",
    # "**rev4, third review pass**").
    logged = [int(n) for n in re.findall(r"(?i)\*\*rev(\d+)\b", appendix)]
    assert logged, "Appendix A logs no revisions"
    assert int(stated.group(1)) == max(logged), (
        f"the header says revision {stated.group(1)}, but Appendix A's newest "
        f"entry is rev{max(logged)}")


@pytest.mark.parametrize("heading", _REQUIRED_SECTIONS)
def test_required_sections_present(doc, heading):
    assert heading in doc, f"missing required section heading: {heading}"


def test_no_normative_reference_to_an_unpublished_draft(normative_body):
    """rev1/rev2/rev3 were never published anywhere a reader of this
    repo can find them. A normative rule that says 'unchanged from rev2'
    is unimplementable, which is exactly what #37's review found."""
    offenders = re.findall(r"(?i)\b(rev\s?[123]\b|revision\s+[123]\b)", normative_body)
    assert not offenders, (
        f"normative sections reference an unpublished draft: {sorted(set(offenders))}")


def test_every_frozen_code_mentioned_anywhere_is_declared_in_a_registry_table(
        doc, limitation_codes, diagnostic_codes):
    """A code named in prose but missing from §6 has no frozen message
    template, source, or field set -- i.e. the implementing child would
    have to invent one."""
    declared = set(limitation_codes) | set(diagnostic_codes)
    mentioned = {t for t in _CODE_TOKEN_RE.findall(doc)
                 if not t.startswith(_NOT_A_CODE)}
    undeclared = sorted(mentioned - declared)
    assert not undeclared, (
        f"codes used in the contract but not declared in §6.1/§6.2: {undeclared}")


def test_registry_tables_have_no_duplicate_rows(limitation_codes, diagnostic_codes):
    for name, codes in (("§6.1", limitation_codes), ("§6.2", diagnostic_codes)):
        dupes = sorted({c for c in codes if codes.count(c) > 1})
        assert not dupes, f"{name} declares the same code more than once: {dupes}"


def test_registry_tables_are_non_trivial(limitation_codes, diagnostic_codes):
    # Guards against a refactor that silently breaks the row regexes and
    # turns every assertion above into a vacuous pass.
    assert len(limitation_codes) >= 25
    assert len(diagnostic_codes) >= 5


# ── Gate item 2: diagnostics can never downgrade coverage ───────────────

def test_diagnostic_and_limitation_registries_are_disjoint(
        limitation_codes, diagnostic_codes):
    overlap = sorted(set(limitation_codes) & set(diagnostic_codes))
    assert not overlap, (
        f"these codes are declared as BOTH a limitation and a diagnostic, so "
        f"whether they downgrade coverage is ambiguous: {overlap}")


def test_no_diagnostic_code_is_a_limitation_code(diagnostic_codes):
    """Asserted against the live enum: a CoverageLimitation always makes
    coverage.status partial/not_evaluated, so a diagnostic-only
    observation that got added to LimitationCode would silently report a
    successfully-checked result as an incomplete one."""
    leaked = sorted(c for c in diagnostic_codes
                    if c in LimitationCode.__members__)
    assert not leaked, (
        f"diagnostic-only codes leaked into LimitationCode: {leaked} -- see "
        f"the contract's §1.6 and §3.5.5")


def test_iat_slot_out_of_directory_bounds_is_diagnostic_only(
        limitation_codes, diagnostic_codes):
    """The single code #37's review called out by name: it was described
    as diagnostic-only while also being listed as a LimitationCode."""
    code = "IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS"
    assert code in diagnostic_codes
    assert code not in limitation_codes
    assert code not in LimitationCode.__members__


@pytest.mark.parametrize("code", _RETIRED_BUT_RETAINED)
def test_retired_pid_peb_codes_keep_their_enum_membership(code):
    """§6.3: --pid/--peb go away, their codes do not -- historical
    documents containing them must stay renderable."""
    assert code in LimitationCode.__members__


# ── JSON examples must match their own field tables ────────────────────

_JSON_KEY_RE = re.compile(r'^\s*"([a-z_]+)":')
_FIELD_ROW_RE = re.compile(r"^\| `([a-z_]+)` \|")


def test_handle_record_example_matches_its_field_table(doc):
    """§5.2's example and its field table drifted apart twice while this
    contract was being written (a field added to one, not the other).
    Every field the table declares must appear in the example, so a
    reader implementing from either one gets the same record.

    This stays a document check on purpose: both artifacts live in the
    markdown, so there is no third, executable copy to compare them
    against. It is a consistency check between two machine-readable
    structures, not a match against prose."""
    section = doc.split("### 5.2 Record shape", 1)[1].split("#### 5.2.1", 1)[0]
    example = section.split("```json", 1)[1].split("```", 1)[0]

    example_keys = {m.group(1) for line in example.splitlines()
                    if (m := _JSON_KEY_RE.match(line))}
    table_fields = {m.group(1) for line in section.splitlines()
                    if (m := _FIELD_ROW_RE.match(line))}

    assert table_fields, "§5.2's field table did not parse -- check the row format"
    missing = sorted(table_fields - example_keys)
    assert not missing, f"declared in §5.2's table but absent from its example: {missing}"
    undeclared = sorted(example_keys - table_fields)
    assert not undeclared, f"present in §5.2's example but not declared in its table: {undeclared}"


# ── One prose-only check remains ───────────────────────────────────────
#
# §3.5.2's outcome matrix -- the last section that had no executable
# form -- now has one (`select_iat_outcome()`), a production counterpart
# (pe_utils._select_iat_outcome, reached by parse_iat() at all three
# decision sites), and full three-layer coverage in
# test_recon_contract_semantics.py. The substring assertion that used to
# stand in for it is gone.
#
# What survives here is the ONE rule below, and it survives for a
# specific reason rather than by omission: it is a prohibition on a
# gating condition, and a prohibition has no positive behavior to run.
# The selectors are structurally unable to consult coverage.status
# (semantics.py asserts that against their compiled code objects), which
# covers the shipped code; this covers the DOCUMENT, so a future revision
# cannot quietly reintroduce the requirement in prose and have the next
# implementer build it.

_WS_RE = re.compile(r"\s+")


def _normalize_ws(text: str) -> str:
    return _WS_RE.sub(" ", text)


def test_import_claim_is_not_gated_on_global_process_coverage_status(doc):
    """A prior revision required `coverage.status == "complete"` for the
    "declares no imports" claim -- which an unrelated PID/start-time gap
    would falsely retract. The claim must be gated on
    `import_directory_present` alone."""
    section = doc.split("Presence of one directory index", 1)[1]
    section = section.split("Frozen consequences of each determined combination", 1)[0]
    normalized = _normalize_ws(section)
    assert 'coverage.status == "complete"' not in normalized, (
        "the import-absence claim must not require global coverage.status "
        "== complete -- an unrelated process limitation must not retract it")
    assert 'supported **exactly** when `import_directory_present is false`' in normalized, (
        "§3.5.2 must state the claim is gated on import_directory_present "
        "alone")

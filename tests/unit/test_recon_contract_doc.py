"""
Contract-document tests for docs/recon_process_sysinfo_handles_contract.md
(issue #37's completion gate, items 1 and 2).

Two things are checked mechanically, because both failed review at least
once while the contract was being written and neither is visible to any
other test:

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

def test_contract_document_exists(doc):
    assert "revision 4" in doc.split("\n\n", 2)[0].lower() or "revision 4" in doc[:600]


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


# ── JSON examples must match their own field tables ────────────────────

_JSON_KEY_RE = re.compile(r'^\s*"([a-z_]+)":')
_FIELD_ROW_RE = re.compile(r"^\| `([a-z_]+)` \|")


def test_handle_record_example_matches_its_field_table(doc):
    """§5.2's example and its field table drifted apart twice while this
    contract was being written (a field added to one, not the other).
    Every field the table declares must appear in the example, so a
    reader implementing from either one gets the same record."""
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


# ── The group-derivation path cannot fill a placeholder ────────────────

# §6.1: these are the codes reachable through build_coverage_report()'s
# all-absent branch (as a SourceRequirement.absent_code, or a
# single-source EvaluationRequirement.all_absent_code). That branch
# constructs CoverageLimitation(code, source, scope="dump",
# related_sources=...) and sets NOTHING else -- no detail, no
# affected_count -- so any {placeholder} in one of their templates would
# render as "None" in real output.
_ABSENT_CAPABLE = (
    "PROCESS_SOURCES_ABSENT", "PROCESS_MISC_INFO_UNAVAILABLE",
    "PROCESS_PEB_UNAVAILABLE", "PROCESS_MODULE_FALLBACK_UNAVAILABLE",
    "HANDLES_UNAVAILABLE", "HANDLES_PARSE_FAILED",
    "HANDLES_ALL_DESCRIPTORS_INVALID",
)
_TEMPLATE_RE = re.compile(r'"([^"]+)"')


@pytest.mark.parametrize("code", _ABSENT_CAPABLE)
def test_absent_capable_templates_have_no_placeholders(doc, code):
    row = next((l for l in doc.splitlines() if l.startswith(f"| `{code}` |")), None)
    assert row is not None, f"{code} has no §6.1 row"
    template = _TEMPLATE_RE.search(row)
    assert template is not None, f"{code}'s row has no quoted message template"
    assert "{" not in template.group(1), (
        f"{code} is absent_capable, so its limitation is built by "
        f"build_coverage_report()'s all-absent branch, which sets no detail/"
        f"affected_count -- its template must be fixed text, got "
        f"{template.group(1)!r}")


@pytest.mark.parametrize("code", _ABSENT_CAPABLE)
def test_absent_capable_codes_are_declared_as_limitations(code, limitation_codes):
    assert code in limitation_codes


def _declared_absent_capable(doc: str) -> set:
    """The codes §6.1's capability list actually declares absent_capable."""
    section = doc.split("- `absent_capable`", 1)[1].split("- `caller_buildable`", 1)[0]
    return {t for t in _CODE_TOKEN_RE.findall(section)
            if not t.startswith(_NOT_A_CODE)}


def test_absent_capable_list_matches_this_test(doc):
    """Keeps _ABSENT_CAPABLE above from silently drifting away from the
    contract's own capability list -- otherwise the placeholder check
    below would quietly stop covering a newly-added code."""
    assert _declared_absent_capable(doc) == set(_ABSENT_CAPABLE)


def test_every_absent_code_used_is_declared_absent_capable(doc):
    """SourceRequirement.__post_init__ and EvaluationRequirement reject
    any code outside _ABSENT_CAPABLE_CODES, so a section that specifies
    `absent_code=X` while §6.1 files X as caller-buildable-only
    specifies a configuration that raises on the first call. This caught
    exactly that for PROCESS_MODULE_FALLBACK_UNAVAILABLE."""
    used = set(re.findall(r"absent_code=([A-Z][A-Z0-9_]+)", doc))
    undeclared = sorted(used - _declared_absent_capable(doc))
    assert not undeclared, (
        f"used as an absent_code but not declared absent_capable in §6.1: "
        f"{undeclared}")


@pytest.mark.parametrize("code", _RETIRED_BUT_RETAINED)
def test_retired_pid_peb_codes_keep_their_enum_membership(code):
    """§6.3: --pid/--peb go away, their codes do not -- historical
    documents containing them must stay renderable."""
    assert code in LimitationCode.__members__


# ── Issue #37 follow-up: nullable-boolean/tri-state regressions ────────
#
# A second review pass found that the substring checks below can pass
# for the wrong reason: markdown line-wrapping breaks a literal phrase
# like "not iat.import_directory_present" across a newline, so a plain
# `"..." not in doc` check silently stops covering the exact regression
# it names the moment the paragraph reflows. Every check in this section
# either normalizes whitespace first, or -- for the semantics that
# actually matter -- is superseded by the EXECUTABLE truth tables in
# tests/unit/test_recon_contract_semantics.py, which exec() the
# contract's own embedded reference functions rather than pattern-match
# its prose.

_WS_RE = re.compile(r"\s+")


def _normalize_ws(text: str) -> str:
    return _WS_RE.sub(" ", text)


def test_console_branch_definitions_use_no_truthiness_on_a_nullable_bool(doc):
    """The four branch DEFINITIONS in §3.8 (not the surrounding prose,
    which is allowed to quote the anti-pattern by name when explaining
    why it's forbidden) must never spell a condition as `not iat.<x>`.
    `not iat.import_directory_present` is `True` for BOTH `false` and
    `null`, which would make the console's "no imports" line fire on an
    undetermined result. Checked whitespace-normalized so a future
    line-wrap can't silently defeat this."""
    branches = doc.split("The four branches, in evaluation order:", 1)[1]
    branches = branches.split("Restated as a reference selector", 1)[0]
    normalized = _normalize_ws(branches)
    assert not re.search(r"\bnot\s+iat\.\w", normalized), (
        f"a §3.8 branch definition uses truthiness on a nullable `iat.*` "
        f"field instead of an explicit is-comparison: {normalized!r}")


def test_forbidden_truthiness_phrase_only_appears_as_a_named_anti_pattern(doc):
    """`not iat.import_directory_present`/`not iat.has_entries` may only
    appear in the doc as the explicit anti-pattern §3.8 calls out by name
    ("... is never used: ...") -- never as an actual, live condition
    written elsewhere. Whitespace-normalized so line-wrap can't hide a
    real occurrence from a literal substring check."""
    normalized = _normalize_ws(doc)
    for phrase in ("not iat.import_directory_present", "not iat.has_entries"):
        for m in re.finditer(re.escape(phrase), normalized):
            window = normalized[m.start():m.start() + 200]
            assert "is never used" in window, (
                f"{phrase!r} appears outside the sentence that explicitly "
                f"forbids it as a live condition -- context: {window!r}")


def test_iat_outcome_matrix_covers_false_present_null_table(doc):
    """§3.5.2's outcome table must freeze a result for
    import_directory_present=false, table_present=null -- the reachable
    combination the third review pass left out."""
    row = next((l for l in doc.splitlines() if l.startswith("| `false` | `null` |")),
               None)
    assert row is not None, (
        "§3.5.2's outcome table has no row for "
        "import_directory_present=false, table_present=null")
    assert "IAT_DIRECTORY_TABLE_INCOMPLETE" in row
    assert "No `IAT_BOUNDS_CHECK_UNAVAILABLE`" in row


def test_iat_source_state_is_defined_for_import_present_null(doc):
    """§3.7.4 must give `coverage.sources["iat"]` a legal state in every
    branch of §3.5.2's `import_directory_present`, including `null` --
    previously only 'no image base'/'no main image' produced `absent`,
    leaving the uncaptured-directory-count case with no defined state."""
    section = doc.split("#### 3.7.4 Coverage sources", 1)[1]
    section = section.split("### 3.8", 1)[0]
    assert "import_directory_present is null` | `absent`" in section
    assert "import_directory_present is false` | `present_empty`" in section
    assert "import_directory_present is true` and `entry_count == 0` | `present_empty`" in section
    assert "import_directory_present is true` and `entry_count > 0` | `present`" in section


def test_iat_directory_table_incomplete_declares_optional_affected_count(doc):
    """§6.1's registry row is the frozen contract an implementer's
    `_CodeSpec` validator and renderer are built from. It must declare
    `affected_count` optional and carry both frozen renderings, not just
    the {count} template -- otherwise a validator that requires a
    positive count would reject the legitimate `None` case."""
    row = next((l for l in doc.splitlines()
                if l.startswith("| `IAT_DIRECTORY_TABLE_INCOMPLETE` |")), None)
    assert row is not None, "IAT_DIRECTORY_TABLE_INCOMPLETE has no §6.1 row"
    assert "optional" in row
    assert "declared data directory entr(y/ies) were not captured" in row
    assert "the data directory table was not captured" in row


def test_section_8_3_fixture_6b_pins_index1_rva_for_every_case(doc):
    """§8.3 item 6b's expected results (true+null vs. false+null) are
    only unique given index 1's exact (rva, size) pair -- the previous
    revision only described capture length, which is consistent with
    either outcome."""
    section = doc.split("6b. **An uncaptured directory table", 1)[1]
    section = section.split("6c. **A handle name", 1)[0]
    assert "nonzero_import_rva" in section, (
        "the true+null fixture must pin index 1 to a non-zero RVA")
    assert section.count("data_directories[1] = (0, 0)") >= 2, (
        "both false-outcome fixtures (false+null and false+false) must "
        "pin index 1 to an explicit (0, 0) pair")


# ── Issue #37 second follow-up: false/null console routing, RVA/Size ───

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
    assert "remains valid when `table_present` is `null`" in normalized, (
        "§3.5.2 must state the claim survives an undetermined table_present")


def test_console_branch_4_no_longer_claims_to_cover_the_false_null_case(doc):
    """Branch 2 (`import_directory_present is false`) is checked before
    branch 4 and matches unconditionally on `table_present`, so the
    false/null combination can never structurally reach branch 4. A
    prior revision's branch-4 prose claimed otherwise -- self-
    contradictory, since branch 2 already consumed that case."""
    section = doc.split("### 3.8 Console layout", 1)[1]
    section = section.split("## §4", 1)[0]
    normalized = _normalize_ws(section)
    assert "never reached when `import_directory_present is false`" in normalized, (
        "§3.8 must explicitly state branch 4 is unreachable for "
        "import_directory_present=false")
    # The old, contradictory claim must be gone: branch 4's own
    # description no longer names table_present is null as one of ITS
    # reachable cases.
    branch4_desc = section.split("4. Otherwise", 1)[1].split("Restated as", 1)[0]
    assert "table_present" not in _normalize_ws(branch4_desc), (
        "branch 4's own bullet must not mention table_present at all -- "
        "that combination is fully handled by branch 2")


def test_presence_resolver_defines_rva_zero_regardless_of_size(doc):
    """A captured `(RVA=0, Size>0)` pair was previously undefined: the
    old row matched only the literal pair `(0, 0)`. Presence must be a
    pure function of RVA; Size must never be a second discriminator in
    either direction."""
    section = doc.split("Presence of one directory index", 1)[1]
    section = section.split("A `null` is never a claim", 1)[0]
    normalized = _normalize_ws(section)
    assert "the pair is `(0, 0)`" not in normalized, (
        "the presence table must no longer gate falseness on the exact "
        "pair (0, 0) -- RVA alone must decide it")
    assert "RVA is zero (regardless of `Size`)" in normalized, (
        "the presence table must explicitly state RVA-zero is false "
        "regardless of Size")
    assert "RVA is non-zero (regardless of `Size`)" in normalized, (
        "the presence table must explicitly state RVA-non-zero is true "
        "regardless of Size")
    assert "second presence discriminator" in normalized


def test_section_8_3_has_rva_size_independence_fixtures(doc):
    """At least one §8.3 fixture must exercise a captured `(0,
    nonzero_size)` pair and a captured `(nonzero_rva, 0)` pair for BOTH
    index 1 and index 12, so the RVA/Size independence rule cannot
    silently regress back to undefined behavior."""
    section = doc.split("6b2. **`Size` is never a second presence", 1)[1]
    section = section.split("6c. **A handle name", 1)[0]
    assert "(0, 0x100)" in section, (
        "missing an index-1 (zero RVA, non-zero Size) fixture")
    assert "(0, 0x40)" in section, (
        "missing an index-12 (zero RVA, non-zero Size) fixture")
    assert "(0x2000, 0)" in section, (
        "missing an index-1 (non-zero RVA, zero Size) fixture")
    assert "(0x3000, 0)" in section, (
        "missing an index-12 (non-zero RVA, zero Size) fixture")

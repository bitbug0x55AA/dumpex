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
        f"the contract's §1.6 and §3.5.4")


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

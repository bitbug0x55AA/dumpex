"""Lightweight structure and consistency checks for the live Recon contract.

Behavior is tested against production code in focused command, record,
coverage, and semantic suites. These checks keep only parseable vocabulary
and agreement between a field table and its adjacent JSON example.
"""
import json
from pathlib import Path
import re

import pytest

from dumpex.output.coverage import LimitationCode
from dumpex.output.records import HANDLE_NAME_STATUSES


_DOC_PATH = Path(__file__).parents[2] / "docs" / "developer" / \
    "recon_process_sysinfo_handles_contract.md"

@pytest.fixture(scope="module")
def doc() -> str:
    return _DOC_PATH.read_text(encoding="utf-8")


_LIMITATION_ROW_RE = re.compile(r"^\| `([A-Z][A-Z0-9_]+)` \|", re.MULTILINE)
_DIAGNOSTIC_ROW_RE = re.compile(r"^\| \d+ \| `([A-Z][A-Z0-9_]+)` \|", re.MULTILINE)


def _section(doc: str, start: str, end: str) -> str:
    return doc.split(start, 1)[1].split(end, 1)[0]


def test_documented_limitation_codes_are_live_and_unique(doc):
    section = _section(doc, "### 6.1 ", "### 6.2 ")
    codes = _LIMITATION_ROW_RE.findall(section)
    assert len(codes) >= 30
    assert len(codes) == len(set(codes))
    assert set(codes) <= set(LimitationCode.__members__)


def test_documented_diagnostic_codes_are_closed_and_not_limitations(doc):
    section = _section(doc, "### 6.2 ", "### 6.3 ")
    codes = _DIAGNOSTIC_ROW_RE.findall(section)
    assert codes == [
        "PROCESS_MODULE_BASE_UNMATCHED",
        "PROCESS_MODULE_BASE_CONFLICT",
        "PROCESS_MODULE_NAME_AMBIGUOUS",
        "PROCESS_MODULE_IDENTITY_MISMATCH",
        "PROCESS_PATH_SOURCE_FALLBACK",
        "IAT_BOUNDS_CHECK_UNAVAILABLE",
        "IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS",
    ]
    assert not (set(codes) & set(LimitationCode.__members__))


_JSON_KEY_RE = re.compile(r'^\s*"([a-z_]+)":')
_FIELD_ROW_RE = re.compile(r"^\| `([a-z_]+)` \|")


def test_handle_record_example_matches_its_field_table(doc):
    section = _section(doc, "### 5.2 Record shape", "#### 5.2.1")
    example = section.split("```json", 1)[1].split("```", 1)[0]
    example_keys = {m.group(1) for line in example.splitlines()
                    if (m := _JSON_KEY_RE.match(line))}
    table_fields = {m.group(1) for line in section.splitlines()
                    if (m := _FIELD_ROW_RE.match(line))}
    assert table_fields
    assert example_keys == table_fields


_STATUS_ROW_RE = re.compile(r'^\| `"([a-z]+)"` \|')
_STATUS_UNION_RE = re.compile(
    r'^\| `(?:type|object)_name_status` \| `("[a-z]+"(?: \\\| "[a-z]+")*)`')


def test_handle_name_status_vocabulary_matches_the_shipped_enum(doc):
    status_section = _section(doc, "#### 5.2.1", "#### 5.2.2")
    rows = [m.group(1) for line in status_section.splitlines()
            if (m := _STATUS_ROW_RE.match(line))]
    assert tuple(rows) == HANDLE_NAME_STATUSES

    shape = _section(doc, "### 5.2 Record shape", "#### 5.2.1")
    unions = [m.group(1) for line in shape.splitlines()
              if (m := _STATUS_UNION_RE.match(line))]
    assert len(unions) == 2
    for union in unions:
        assert tuple(value.strip(' "') for value in union.split(r"\|")) == \
            HANDLE_NAME_STATUSES


def test_import_absence_rule_is_local_not_global(doc):
    section = _section(
        doc,
        "Presence of one directory index",
        "Frozen consequences of each determined combination",
    )
    normalized = re.sub(r"\s+", " ", section)
    assert 'coverage.status == "complete"' not in normalized
    assert "import_directory_present is false" in normalized

_PE_CONSOLE_LABEL_RE = re.compile(r"^    ([A-Z][A-Za-z ]+?)\s{2,}\S", re.MULTILINE)


def _flat(text: str) -> str:
    return " ".join(text.split())


def _pe_console_section(doc: str) -> str:
    return _section(doc, "#### 3.10.10 Console", "#### 3.10.11")


def test_the_documented_pe_console_labels_are_the_renderers_own(doc):
    """The example block in the contract is what a reader is told to
    expect, so a label that moved in the renderer must move here too."""
    from dumpex.commands import process

    example = _pe_console_section(doc).split("```")[1]
    labels = _PE_CONSOLE_LABEL_RE.findall(example)
    source = Path(process.__file__).read_text(encoding="utf-8")

    assert {"Actual Base", "Preferred Base", "Relocation", "Consistency",
            "Scope"} <= set(labels)
    for label in labels:
        assert f"'{label}'" in source, label


def test_the_pe_console_contract_keeps_the_two_withheld_answers_apart(doc):
    """One marker per meaning: evidence the dump does not carry, and a
    check the image's own declarations leave no subject for."""
    section = _flat(_pe_console_section(doc))

    assert "unavailable, 14 not applicable" in section
    assert ("`[??]` is evidence the dump does not carry, `[--]` is a check that "
            "does not apply") in section
    assert "never one number for both withheld answers" in section


def test_the_pe_console_contract_states_its_own_scope(doc):
    """A block of agreeing structural checks must not be publishable as
    evidence that the process is benign."""
    section = _flat(_pe_console_section(doc))

    assert "printed on every render of the block" in section
    assert "is not evidence that the process is benign" in section
    assert "never a verdict, a confidence, or an investigation policy" in section


def test_the_identity_heading_is_documented_as_conditional(doc):
    section = _flat(_section(doc, "### 3.8 Console layout", "The four branches"))
    assert "the heading and the block are omitted entirely when diagnostics is empty" in section


def test_the_identity_blocks_marker_is_the_renderers_own(doc):
    """One marker, one meaning, across this command's console: the
    identity checks withhold answers for the same reason §3.10.10's rows
    do, so the contract and the renderer must not name it differently."""
    from dumpex.commands import process

    section = _section(doc, "- Exactly four checks, in this frozen order",
                       "- The raw per-source claims stay available underneath")
    rules = re.split(r"\n  \d\. ", section)[1:]
    assert len(rules) == 4
    for rule in rules:
        assert process._CHECK_UNAVAILABLE in rule, rule

    # The other marker appears once, in the sentence that reserves it for
    # the block where it means something else.
    assert section.count(process._CHECK_NOT_APPLICABLE) == 1
    assert "reserved there for a check that does not apply" in _flat(section)


def test_the_acquisition_contract_names_three_shortfall_causes(doc):
    """A budget of dumpex's own is a third cause with its own remedy, and
    the two dump-attributed ones must not be made to stand for it."""
    section = _flat(_pe_console_section(doc))

    assert "which of **three** causes applies" in section
    assert "one of dumpex's own budgets declined to read further" in section
    assert "A budget is checked first and answers on its own" in section
    assert "would report a limit of this tool as a truncated dump" in section


def test_only_the_byte_budget_may_exonerate_the_dump(doc):
    """A read-count budget can be reached by this dump's own segment
    layout, so the contract must not let one sentence speak for every
    budget."""
    section = _flat(_pe_console_section(doc))

    assert "A byte budget exonerates the dump outright, and only that one does" in section
    assert "costs one read per segment" in section
    assert "Only the byte budget's sentence denies the dump a part in the shortfall" in section


def test_the_acquisition_contract_states_the_implication_it_can_keep(doc):
    """`no` implies the structure is not complete; `yes` implies nothing
    about soundness, because every required byte can arrive and a
    structure still be malformed."""
    section = _flat(_pe_console_section(doc))

    assert "`Required bytes present: no` implies `Structure` is not `complete`" in section
    assert "The converse does not hold" in section


def test_the_capture_line_is_documented_as_window_scoped(doc):
    section = _flat(_pe_console_section(doc))

    assert "`Captured in that window`" in section
    assert "never states how much of the *image* the dump holds" in section


def test_the_token_rule_covers_the_budget_scope(doc):
    section = _flat(_pe_console_section(doc))

    assert "a bounded stop's `scope`" in section
    assert "falls back to a sentence that names no token at all" in section


def test_the_token_rule_names_its_one_exception(doc):
    """The rule has to be true to be worth certifying: capture states do
    reach the console as they are, so the contract says so rather than
    claiming a totality the renderer does not keep."""
    section = _flat(_pe_console_section(doc))

    assert "The one vocabulary carried across as-is is the capture state" in section
    assert "ordinary English words under a `Capture` heading" in section


def test_the_overflow_row_uses_the_unconflated_word(doc):
    section = _flat(_pe_console_section(doc))

    assert "further conflicting or unanswered check(s)" in section
    assert "further conflicting or unevaluated check(s)" not in section


# ── §3.10's wire vocabulary is the four-state one the schema ships ──────
# These sections are a public output contract, not prose: a consumer that
# implements the three-state model from them counts an ordinary PE layout
# as missing evidence, which is the one reading §3.10.9 forbids.


def _pe_record_section(doc: str) -> str:
    return _section(doc, "#### 3.10.2 Shape", "#### 3.10.3")


def _observations_section(doc: str) -> str:
    return _section(doc, "#### 3.10.8 `observations`", "#### 3.10.8.1")


def test_the_record_table_and_its_example_carry_every_state(doc):
    """The field table and the adjacent JSON example are what a consumer
    reads the tally's shape from, so both name all four counts and the
    example's own numbers add up."""
    from dumpex.output.records import PE_OBSERVATION_STATES

    section = _pe_record_section(doc)
    row, = [line for line in section.splitlines()
            if line.startswith("| `observation_coverage`")]
    for state in PE_OBSERVATION_STATES:
        assert f"`{state}`" in row, state
    assert "the four states sum to the total" in row
    assert "the three states" not in row

    example, = re.findall(r'"observation_coverage": \{[^}]*\}', section)
    tally = json.loads("{" + example.split("{", 1)[1])
    assert set(tally) == {"total", *PE_OBSERVATION_STATES}
    assert sum(tally[state] for state in PE_OBSERVATION_STATES) == tally["total"]


def test_the_observations_section_carries_every_state(doc):
    section = _flat(_observations_section(doc))

    assert "All four states are carried" in section
    assert "`not_applicable` is a question this image gives no subject" in section
    assert "counts `unavailable` alone" in section
    assert "All three states are carried" not in section


def test_the_security_descriptor_rule_is_not_an_evidence_gap(doc):
    """Index 4's bound check has no subject, and a contract that calls
    that `unavailable` tells a consumer the dump is missing certificate
    evidence it was never going to carry."""
    section = _flat(_section(doc, "#### 3.10.7 `directories`", "#### 3.10.8 `observations`"))

    assert "bound observation is `not_applicable`" in section
    assert "bound observation is `unavailable`" not in section
    assert "a directory the header declares absent is" in section.lower()


def test_an_empty_tally_is_shown_in_the_words_the_console_uses(doc):
    section = _flat(_section(doc, "#### 3.10.8.1 `correlated`", "#### 3.10.9"))

    assert "0 unavailable, 0 not applicable" in section
    assert "not evaluated" not in section

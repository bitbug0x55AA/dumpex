"""Lightweight structure and consistency checks for the live Recon contract.

Behavior is tested against production code in focused command, record,
coverage, and semantic suites. These checks keep only parseable vocabulary
and agreement between a field table and its adjacent JSON example.
"""
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

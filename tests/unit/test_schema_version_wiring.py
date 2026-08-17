"""
Cross-artifact alignment for the output-contract version.

`dumpex.output.envelope.SCHEMA_VERSION` is the string every producer
stamps into `meta.schema_version`. Bumping it is never a one-line change:
a new `dumpex/schemas/dumpex-output-v<X>.schema.json` has to ship with it,
`dumpex.schemas.CURRENT_SCHEMA` has to name that file, the file's own
`$id`/`title`/`meta.schema_version.const` have to claim the same version,
docs/OUTPUT_SCHEMA.md's contract table has to move `(current)` onto it,
and every previous schema has to stay installed and untouched so
already-collected output remains validatable.

Asserting `SCHEMA_VERSION == "<current literal>"` proves none of that --
it only proves this file was edited in the same commit as envelope.py.
These tests assert the constant against the artifacts it has to agree
with, so a half-finished bump fails CI on the half that was skipped.

Whether documents actually validate against the schema is a separate
concern, covered by tests/integration/test_json_schema_v2.py (all
producers) and tests/integration/test_json_schema_v2_5_hunt.py.
"""
import json
import re
from pathlib import Path

import pytest

from dumpex.output.envelope import SCHEMA_VERSION
from dumpex.schemas import CURRENT_SCHEMA, schema_path

_REPO_ROOT = Path(__file__).parents[2]
_SCHEMA_DIR = _REPO_ROOT / "dumpex" / "schemas"
_FILENAME_RE = re.compile(r"^dumpex-output-v(\d+)\.(\d+)\.schema\.json$")


def _packaged_schemas():
    """(major, minor) -> filename for every schema file shipped in the
    package, discovered from disk rather than listed here, so a file that
    is added or deleted changes what these tests see."""
    found = {}
    for path in sorted(_SCHEMA_DIR.glob("dumpex-output-v*.schema.json")):
        match = _FILENAME_RE.match(path.name)
        assert match, f"schema filename does not encode a version: {path.name}"
        found[(int(match.group(1)), int(match.group(2)))] = path.name
    return found


def _version_tuple(version: str):
    major, minor = version.split(".")
    return int(major), int(minor)


def _load(filename: str):
    with schema_path(filename) as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ── every packaged schema is self-consistent ─────────────────────────────

@pytest.mark.parametrize("filename", sorted(_packaged_schemas().values()))
def test_each_schema_file_agrees_with_its_own_filename(filename):
    """A schema whose `const` and filename disagree is worse than a
    missing one: producers select it by name and then stamp a version it
    rejects. Catches both a mis-named new file and an in-place edit of a
    frozen historical schema's version const."""
    major, minor = _FILENAME_RE.match(filename).groups()
    declared = f"{major}.{minor}"
    schema = _load(filename)
    assert schema["$defs"]["meta"]["properties"]["schema_version"]["const"] == declared
    assert schema["$id"].endswith(filename)
    assert f"schema_version {declared}" in schema["title"]


# ── the constant, the package pointer and the shipped file ───────────────

def test_current_schema_names_the_file_for_schema_version():
    assert CURRENT_SCHEMA == f"dumpex-output-v{SCHEMA_VERSION}.schema.json"
    assert (_SCHEMA_DIR / CURRENT_SCHEMA).is_file()


def test_schema_version_is_the_newest_packaged_v2_schema():
    """Both failure directions of a half-finished bump: the constant
    moved but the new schema file was never added (nothing to validate
    against), or a new schema file was added but the constant still
    points at the previous one (a shipped contract no producer emits)."""
    v2 = {version for version in _packaged_schemas() if version[0] == 2}
    assert max(v2) == _version_tuple(SCHEMA_VERSION)


def test_the_previous_contract_is_still_installed():
    """Historical schemas are the only way already-collected evidence
    stays validatable, so the predecessor of the current version must
    never be deleted along with a bump."""
    current = _version_tuple(SCHEMA_VERSION)
    v2 = sorted(version for version in _packaged_schemas() if version[0] == 2)
    assert len(v2) > 1, "a v2 bump deleted the entire contract history"
    assert v2[v2.index(current) - 1] in _packaged_schemas()


def test_no_gaps_in_the_packaged_v2_version_history():
    # 2.0 .. SCHEMA_VERSION with nothing missing -- a gap means a version
    # was emitted at some point and its schema is no longer installed.
    minors = sorted(minor for major, minor in _packaged_schemas() if major == 2)
    assert minors == list(range(0, _version_tuple(SCHEMA_VERSION)[1] + 1))


# ── docs/OUTPUT_SCHEMA.md's contract table ───────────────────────────────

def _contract_table_rows():
    doc = (_REPO_ROOT / "docs" / "OUTPUT_SCHEMA.md").read_text(encoding="utf-8")
    table = doc.split("| Commands | Contract | Schema file |", 1)[1].split("\n\n", 1)[0]
    return [line for line in table.splitlines() if line.startswith("| ") and "schema.json" in line]


def test_contract_table_marks_exactly_schema_version_as_current():
    current_rows = [row for row in _contract_table_rows() if "(current)" in row]
    assert len(current_rows) == 1
    assert f"| v{SCHEMA_VERSION} (current) |" in current_rows[0]
    assert CURRENT_SCHEMA in current_rows[0]


def test_contract_table_documents_every_packaged_v2_schema():
    """The doc is the only place a consumer learns which file to fetch
    for an old `schema_version` they were handed, so a shipped schema
    missing from the table is a real gap, and a table row for a file that
    is not shipped is a broken link."""
    documented = set(re.findall(r"dumpex-output-v(\d+\.\d+)\.schema\.json", "\n".join(_contract_table_rows())))
    packaged = {f"{major}.{minor}" for major, minor in _packaged_schemas() if major == 2}
    assert {_version_tuple(v) for v in documented} == {_version_tuple(v) for v in packaged}


def test_every_historical_row_is_marked_frozen_and_not_produced():
    for row in _contract_table_rows():
        if "(current)" in row:
            continue
        assert "frozen" in row and "no command emits this anymore" in row, row

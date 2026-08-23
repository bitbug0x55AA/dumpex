"""
docs/CLI_REFERENCE.md carries a worked `--profile --verbose` JSON example
(a full v2.13 document, not a bare record fragment) meant to be genuinely
valid, not just illustrative -- a reader who copies it into a validator
should get a clean pass. Nothing enforces that at doc-edit time, so this
test extracts every fenced ```json block from the file and validates it
against the current schema, the same way
tests/integration/test_soc_quickstart_json_examples.py does for
docs/SOC_QUICKSTART.md. A prior version of this example was a bare,
incomplete `profileRecord` fragment (one capability instead of the
registry's fixed six, and a Memory64 evidence claim with no matching
stream row) that failed schema validation outright.
"""
import json
import pathlib
import re

import pytest

jsonschema = pytest.importorskip("jsonschema")

from dumpex.schemas import current_schema_path

_CLI_REFERENCE = pathlib.Path(__file__).parent.parent.parent / "docs" / "CLI_REFERENCE.md"


def _extract_json_blocks(text: str) -> list:
    return re.findall(r"```json\n(.*?)\n```", text, re.S)


@pytest.fixture(scope="module")
def validator():
    with current_schema_path() as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_cli_reference_has_a_json_example():
    blocks = _extract_json_blocks(_CLI_REFERENCE.read_text(encoding="utf-8"))
    # Guards against the extraction regex itself silently matching nothing
    # (e.g. the doc switches to a different fence style) and this test
    # quietly validating zero documents forever.
    assert len(blocks) >= 1, (
        "Expected at least the --profile worked JSON example in "
        "docs/CLI_REFERENCE.md")


def test_cli_reference_json_examples_validate(validator):
    blocks = _extract_json_blocks(_CLI_REFERENCE.read_text(encoding="utf-8"))
    for i, block in enumerate(blocks):
        try:
            doc = json.loads(block)
        except json.JSONDecodeError as e:
            pytest.fail(f"docs/CLI_REFERENCE.md json block #{i} is not valid JSON: {e}")
        errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
        assert not errors, (
            f"docs/CLI_REFERENCE.md json block #{i} fails schema validation:\n" +
            "\n".join(f"{list(e.path)}: {e.message}" for e in errors))


def test_cli_reference_profile_example_covers_all_six_capabilities_in_order():
    """Pins the specific teaching point this example exists for -- not
    just "some valid JSON" -- so a future edit can't quietly shrink it
    back to a one-capability fragment and still pass schema validation."""
    blocks = _extract_json_blocks(_CLI_REFERENCE.read_text(encoding="utf-8"))
    docs = [json.loads(b) for b in blocks]
    profile_docs = [d for d in docs if d.get("result", {}).get("kind") == "profile"]
    assert len(profile_docs) == 1
    record = profile_docs[0]["result"]["data"]["records"][0]

    from dumpex.output.records import CAPABILITY_IDS
    assert tuple(c["capability_id"] for c in record["capabilities"]) == CAPABILITY_IDS

    statuses = {c["status"] for c in record["capabilities"]}
    assert "available" in statuses and "unavailable" in statuses

    # The Memory64 evidence the surrounding prose describes must be backed
    # by a real stream row, not just claimed in memory_capture.
    assert record["memory_capture"]["memory64_list_present"] is True
    stream_names = {s["stream_type_name"] for s in record["streams"]}
    assert "Memory64ListStream" in stream_names

"""
docs/SOC_QUICKSTART.md's "Sanitized `--json` examples" section carries two
complete, hand-written v2.9 documents (`--hunt pipe` DETECTED, `--hunt
stomping` INCONCLUSIVE) meant to be genuinely valid, not just
representative -- a reader who copies one into a validator should get a
clean pass. Nothing enforces that at doc-edit time, so this test extracts
every fenced ```json block from the file and validates it against the
current schema, the same way tests/integration/test_json_schema_v2.py
validates real V2Output. If a future schema change (a new required field,
a tightened enum, a new allOf constraint) makes either example invalid,
this fails here instead of a reader discovering it by hand.
"""
import json
import pathlib
import re

import pytest

jsonschema = pytest.importorskip("jsonschema")

from dumpex.schemas import current_schema_path

_QUICKSTART = pathlib.Path(__file__).parent.parent.parent / "docs" / "SOC_QUICKSTART.md"


def _extract_json_blocks(text: str) -> list:
    return re.findall(r"```json\n(.*?)\n```", text, re.S)


@pytest.fixture(scope="module")
def validator():
    with current_schema_path() as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_quickstart_has_json_examples():
    blocks = _extract_json_blocks(_QUICKSTART.read_text(encoding="utf-8"))
    # Guards against the extraction regex itself silently matching nothing
    # (e.g. the doc switches to a different fence style) and this test
    # quietly validating zero documents forever.
    assert len(blocks) >= 2, (
        "Expected at least the --hunt pipe and --hunt stomping examples "
        "in docs/SOC_QUICKSTART.md's 'Sanitized --json examples' section")


def test_quickstart_json_examples_validate(validator):
    blocks = _extract_json_blocks(_QUICKSTART.read_text(encoding="utf-8"))
    for i, block in enumerate(blocks):
        try:
            doc = json.loads(block)
        except json.JSONDecodeError as e:
            pytest.fail(f"docs/SOC_QUICKSTART.md json block #{i} is not valid JSON: {e}")
        errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
        assert not errors, (
            f"docs/SOC_QUICKSTART.md json block #{i} fails schema validation:\n" +
            "\n".join(f"{list(e.path)}: {e.message}" for e in errors))


def test_quickstart_examples_cover_selected_and_summary_pipe_and_stomping():
    """Pins the two specific scenarios this section documents (not just
    "some valid JSON") -- a future edit that swaps in two DETECTED
    examples, say, would still pass schema validation but would silently
    drop the doc's own "score 0 is not the same as clean" teaching point."""
    blocks = _extract_json_blocks(_QUICKSTART.read_text(encoding="utf-8"))
    docs = [json.loads(b) for b in blocks]
    selected = {d["result"]["summary"]["selected"] for d in docs}
    assert selected == {"pipe", "stomping"}

    by_selected = {d["result"]["summary"]["selected"]: d for d in docs}
    pipe_doc = by_selected["pipe"]
    assert pipe_doc["result"]["data"]["records"][0]["status"] == "DETECTED"
    assert pipe_doc["result"]["coverage"]["status"] == "complete"

    stomping_doc = by_selected["stomping"]
    assert stomping_doc["result"]["data"]["records"][0]["status"] == "INCONCLUSIVE"
    assert stomping_doc["result"]["coverage"]["status"] == "partial"
    # The exact contradiction a prior version of this doc shipped: options.
    # ref_dir must agree with the "not supplied" coverage reason, not claim
    # a --ref-dir was passed while coverage says it wasn't.
    assert stomping_doc["meta"]["execution"]["options"]["ref_dir"] is None
    assert "not supplied" in stomping_doc["result"]["coverage"]["reasons"][0]

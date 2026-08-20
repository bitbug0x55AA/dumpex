"""
Cross-artifact alignment for the closed, frozen `ProcessDiagnosticRecord`
registry (docs/recon_process_sysinfo_handles_contract.md §6.2).

`dumpex.output.records._PROCESS_DIAGNOSTIC_DETAILS_SCHEMA` is the single
runtime source of truth for which diagnostic codes exist and what
`details` keys each one carries -- `ProcessDiagnosticRecord.__post_init__`
enforces it on every construction (see test_output_records.py for that).
But that registry is NOT the only place the same seven-code contract is
written down: the JSON schema pins the identical `code` enum and, per
code, an identical closed `details` shape via its own `allOf` (see
dumpex-output-v2.13.schema.json's own `processDiagnosticRecord`), and the
two real emission sites -- dumpex/core/process_info.py's
`ProcessDiagnostic` and dumpex/core/pe_utils.py's `IatDiagnostic` (kept
deliberately uncoupled from each other and from the output-layer type to
avoid a circular import -- see IatDiagnostic's own docstring) -- each
hard-code their own `code="..."` literals independently. None of those
three can be derived from the registry at import time (a JSON file and
two source files elsewhere in the tree are static artifacts), so each is
a place an 8th diagnostic code -- or a `details` key added to an existing
one -- can be forgotten.

These tests exist to make forgetting one of them a CI failure, the same
role test_hunter_roster_alignment.py plays for the hunter roster. They
deliberately assert the registry against those OTHER artifacts, never
against a second literal copy of the seven codes: re-typing the registry
here would only prove this file agrees with itself.
"""
import json
import re
from pathlib import Path

import pytest

from dumpex.output.records import _PROCESS_DIAGNOSTIC_DETAILS_SCHEMA
from dumpex.schemas import CURRENT_SCHEMA, schema_path

_REPO_ROOT = Path(__file__).parents[2]
_PROCESS_INFO = _REPO_ROOT / "dumpex" / "core" / "process_info.py"
_PE_UTILS = _REPO_ROOT / "dumpex" / "core" / "pe_utils.py"

_CODE_LITERAL_RE = re.compile(r'code="([A-Z_]+)"')


def _emitted_codes(path: Path) -> set:
    return set(_CODE_LITERAL_RE.findall(path.read_text(encoding="utf-8")))


def _schema_process_diagnostic_def() -> dict:
    with schema_path(CURRENT_SCHEMA) as p, open(p, encoding="utf-8") as fh:
        return json.load(fh)["$defs"]["processDiagnosticRecord"]


def test_registry_is_reachable_and_nonempty():
    # Guards the guard: an import that silently returned {} would make
    # every set-equality test below vacuously pass.
    assert len(_PROCESS_DIAGNOSTIC_DETAILS_SCHEMA) == 7


def test_process_info_emission_sites_match_the_registry():
    emitted = _emitted_codes(_PROCESS_INFO)
    assert emitted, f"no code=\"...\" diagnostic literals found in {_PROCESS_INFO}"
    registry_process_codes = {c for c in _PROCESS_DIAGNOSTIC_DETAILS_SCHEMA if c.startswith("PROCESS_")}
    assert emitted == registry_process_codes


def test_pe_utils_emission_sites_match_the_registry():
    emitted = _emitted_codes(_PE_UTILS)
    assert emitted, f"no code=\"...\" diagnostic literals found in {_PE_UTILS}"
    registry_iat_codes = {c for c in _PROCESS_DIAGNOSTIC_DETAILS_SCHEMA if c.startswith("IAT_")}
    assert emitted == registry_iat_codes


def test_every_emitted_code_is_a_registry_member():
    # The two tests above already prove per-file equality; this is the
    # same claim stated as one whole-registry assertion, so a future third
    # emission site (a new source file) can't quietly land outside either
    # per-file check above.
    all_emitted = _emitted_codes(_PROCESS_INFO) | _emitted_codes(_PE_UTILS)
    assert all_emitted == set(_PROCESS_DIAGNOSTIC_DETAILS_SCHEMA)


def test_schema_code_enum_matches_the_registry():
    node = _schema_process_diagnostic_def()["properties"]["code"]
    assert set(node["enum"]) == set(_PROCESS_DIAGNOSTIC_DETAILS_SCHEMA)


@pytest.mark.parametrize("code", sorted(_PROCESS_DIAGNOSTIC_DETAILS_SCHEMA))
def test_schema_details_shape_matches_the_registry_for_each_code(code):
    """Per code, the schema's own `allOf` branch closes `details` to
    exactly the registry's own key set for that code -- pulled out of the
    schema's `if/then` structure (rather than re-typed) so this fails the
    moment the two disagree, in either direction."""
    process_diagnostic_def = _schema_process_diagnostic_def()
    branch = next(
        (b for b in process_diagnostic_def["allOf"]
         if b.get("if", {}).get("properties", {}).get("code", {}).get("const") == code),
        None)
    assert branch is not None, f"schema has no allOf branch for code {code!r}"
    details_schema = branch["then"]["properties"]["details"]
    assert details_schema["additionalProperties"] is False
    assert set(details_schema["required"]) == set(details_schema["properties"])
    assert set(details_schema["properties"]) == _PROCESS_DIAGNOSTIC_DETAILS_SCHEMA[code]

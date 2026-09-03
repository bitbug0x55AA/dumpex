"""Cross-artifact alignment for the output-contract version."""
import json
import re
from pathlib import Path

import pytest

from dumpex.output.envelope import SCHEMA_VERSION
from dumpex.schemas import CURRENT_SCHEMA, schema_path
from scripts import package_smoke

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


def _validator_for(schema: dict, ref: str):
    """A validator for one `$def` of a loaded schema, so a relationship
    the schema claims to enforce can be checked against real documents
    rather than by reading its `allOf` back out."""
    jsonschema = pytest.importorskip("jsonschema")
    wrapper = {"$schema": schema["$schema"], "$ref": ref, "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


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


# ── docs/user/OUTPUT_MIGRATION.md's contract table ──────────────────────

def _contract_table_rows():
    doc = (_REPO_ROOT / "docs" / "user" / "OUTPUT_MIGRATION.md").read_text(encoding="utf-8")
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


def test_package_smoke_schema_filenames_match_the_packaged_set():
    packaged = {filename for filename in _packaged_schemas().values()}
    listed = set(package_smoke.SCHEMA_FILENAMES)
    assert listed == packaged, (
        f"scripts/package_smoke.py's schema list has drifted from the "
        f"packaged dumpex/schemas/ files -- missing: {sorted(packaged - listed)}, "
        f"extra: {sorted(listed - packaged)}")


def test_package_smoke_rejects_an_unlisted_current_schema(capsys):
    with pytest.raises(SystemExit) as exc_info:
        package_smoke.validate_current_schema_is_listed("dumpex-output-v99.0.schema.json")
    assert exc_info.value.code == 1
    assert "would never actually be smoke-tested" in capsys.readouterr().out


# ── v2.14's own consumer-visible relaxations ────────────────────────────
# The migration doc's version-summary table is where a pinned consumer learns
# what changed. A relationship that held across v2.0-v2.13 and no longer does
# is exactly the kind of change that must appear there and in the schema, not
# only in a module docstring. These rows are pinned to the version that
# introduced them rather than to whichever version is current: a later bump
# does not move the release a consumer has to read to learn about the
# relaxation.

def _version_summary_row(version: str) -> str:
    doc = (_REPO_ROOT / "docs" / "user" / "OUTPUT_MIGRATION.md").read_text(encoding="utf-8")
    table = doc.split("| Version | Consumer-visible change |", 1)[1]
    for line in table.splitlines():
        if line.startswith(f"| {version} |"):
            return line
    raise AssertionError(f"no version-summary row for {version}")


def test_v2_14s_row_names_the_new_limitation_code():
    assert "TARGETED_SOURCE_NOT_EVALUATED" in _version_summary_row("2.14")


def test_v2_14s_row_names_the_complete_with_limitations_relaxation():
    """`complete` implied an empty `limitations` array in every earlier
    version; a targeted record breaks that, and a consumer reading
    `len(limitations) > 0` as "gapped" needs to be told."""
    row = _version_summary_row("2.14")
    assert "complete" in row and "limitations" in row


# ── v2.15's missed-byte quantification ──────────────────────────────────

def test_the_current_versions_row_names_the_missed_byte_states():
    """A consumer thresholding on `bytes` has to be told, in the doc it
    pins against, that the number is a total only in one of the three
    states -- otherwise a lower bound or a null reads as a total."""
    row = _version_summary_row(SCHEMA_VERSION)
    assert "missed_bytes" in row
    for state in ("exact", "lower_bound", "unknown"):
        assert state in row


def test_the_current_versions_row_states_that_no_verdict_moves():
    """The one thing a consumer most needs to know about a coverage
    change is whether it moved any result. This one does not."""
    row = _version_summary_row(SCHEMA_VERSION)
    assert "coverage.status" in row and "exit code" in row


def test_the_schema_itself_defines_the_missed_byte_states():
    """The migration doc is prose; the schema is what consumers pin."""
    schema = _load(CURRENT_SCHEMA)
    missed = schema["$defs"]["missedBytes"]
    assert missed["properties"]["state"]["enum"] == ["exact", "lower_bound", "unknown"]
    # `bytes` must be nullable: "unknown" reports no figure at all rather
    # than a 0 a consumer would read as "nothing was missed".
    assert missed["properties"]["bytes"]["type"] == ["integer", "null"]
    assert set(missed["required"]) == {
        "state", "bytes", "complete", "quantified_gaps", "unquantified_gaps",
        "distinct_ranges"}
    scan_target = schema["$defs"]["scanTarget"]
    for field in ("examined_size", "unexamined_size"):
        assert field in scan_target["required"]
        assert scan_target["properties"][field]["type"] == ["integer", "null"]


def test_both_coverage_objects_require_the_aggregate():
    """A hunter record's own coverage and the document-level rollup both
    grade a partial, so a consumer reading either finds it -- and finds it
    always, rather than having to handle a producer that stopped emitting
    it as if it meant zero."""
    schema = _load(CURRENT_SCHEMA)
    for owner in ("result", "hunterRecord"):
        coverage = schema["$defs"][owner]["properties"]["coverage"]
        assert coverage["properties"]["missed_bytes"] == {"$ref": "#/$defs/missedBytes"}
        assert "missed_bytes" in coverage["required"]


def test_the_schema_enforces_the_relationships_its_description_states():
    """`state`, `complete`, `bytes` and `unquantified_gaps` are one fact in
    four spellings. A consumer branching on any one of them relies on the
    others agreeing, so the schema checks it rather than asserting it in
    prose."""
    schema = _load(CURRENT_SCHEMA)
    validator = _validator_for(schema, "#/$defs/missedBytes")

    def _doc(**kw):
        base = {"state": "exact", "bytes": 0, "complete": True,
                "quantified_gaps": 0, "unquantified_gaps": 0, "distinct_ranges": 0}
        base.update(kw)
        return base

    assert validator.is_valid(_doc())
    assert validator.is_valid(_doc(state="unknown", bytes=None, complete=False,
                                    unquantified_gaps=2))
    assert validator.is_valid(_doc(state="lower_bound", bytes=4096, complete=False,
                                    quantified_gaps=1, unquantified_gaps=1,
                                    distinct_ranges=1))
    # "unknown" with a byte figure would be the exact confusion `state`
    # exists to prevent.
    assert not validator.is_valid(_doc(state="unknown", bytes=0, complete=False,
                                        unquantified_gaps=1))
    # "exact" is the only state that may claim completeness, and it must.
    assert not validator.is_valid(_doc(state="exact", complete=False))
    assert not validator.is_valid(_doc(state="lower_bound", bytes=4096, complete=True,
                                        quantified_gaps=1, unquantified_gaps=1,
                                        distinct_ranges=1))
    # An exact aggregate cannot be hiding unmeasured gaps.
    assert not validator.is_valid(_doc(unquantified_gaps=1))
    # A lower bound is a bound on something: with nothing measured the
    # producer reports "unknown", so this state is unreachable and a
    # consumer must never have to handle it.
    assert not validator.is_valid(_doc(state="lower_bound", bytes=0, complete=False,
                                        quantified_gaps=0, unquantified_gaps=1))
    # Bytes belong to gaps, and gaps cover ranges. A figure with neither
    # describes memory that came from nowhere.
    assert not validator.is_valid(_doc(bytes=4096))
    assert not validator.is_valid(_doc(bytes=4096, quantified_gaps=1))
    assert validator.is_valid(_doc(bytes=4096, quantified_gaps=1, distinct_ranges=1))


def test_the_schema_itself_states_the_relaxation():
    """The migration doc is prose; the schema is what consumers pin."""
    schema = _load(CURRENT_SCHEMA)
    hunter_record = schema["$defs"]["hunterRecord"]["description"]
    assert "targeted_scope" in hunter_record
    assert "limitations" in hunter_record and "complete" in hunter_record
    assert "TARGETED_SOURCE_NOT_EVALUATED" in schema["$defs"]["coverageLimitation"]["description"]


# ── scan_scope is cross-checked against the rest of the document ─────────
#
# The current schema carries a per-analyzer targeted capability table so a
# consumer can trust `scan_scope`. That table is a copy of the registry's own
# grants, and a copy can drift: these tests pin it to the registry and to each
# adapter's real closure scopes, so a future analyzer cannot leave the schema
# describing a capability nobody registered (or reject a document the producer
# legitimately emits).

def _hunt_branch(schema):
    branches = schema["$defs"]["result"]["allOf"]
    hunt = [b for b in branches
            if b.get("if", {}).get("properties", {}).get("kind", {}).get("const") == "hunt"]
    assert len(hunt) == 1, "exactly one kind==hunt branch"
    return hunt[0]


def _targeted_hunter_branches(schema):
    """{hunter: then-clause} for each per-analyzer targeted branch."""
    out = {}
    for sub in _hunt_branch(schema)["then"]["allOf"]:
        scope = (sub.get("if", {}).get("properties", {}).get("summary", {})
                 .get("properties", {}).get("scan_scope", {}).get("properties", {}))
        if scope.get("kind", {}).get("const") != "targeted" or "hunter" not in scope:
            continue
        out[scope["hunter"]["const"]] = sub["then"]
    return out


def test_the_schemas_targeted_hunter_set_is_the_registrys_own():
    from dumpex.hunt import _registry

    assert (tuple(sorted(_targeted_hunter_branches(_load(CURRENT_SCHEMA))))
            == tuple(sorted(_registry.REGISTRY.targeted_identities())))


def test_each_schemas_targeted_source_is_the_registrys_own():
    from dumpex.hunt import _registry

    for hunter, then in _targeted_hunter_branches(_load(CURRENT_SCHEMA)).items():
        scan_scope = then["properties"]["summary"]["properties"]["scan_scope"]
        assert (scan_scope["properties"]["source"]["const"]
                == _registry.REGISTRY.targeted_source(hunter)), hunter


def _adapter_closure_order():
    """Each analyzer's closures in the adapter's own fixed order. Scoped
    analyzers name their scopes; the rest project one unscoped closure.

    Read from the adapters, NOT from `TargetedGrant.scopes`: pipe's grant is
    unscoped while its invocation closes `pipe_name` and `c2_context`
    independently, so a table built from the grant would reject a real pipe
    document."""
    from dumpex.hunt.encoding.targeted import TARGETED_LAYERS
    from dumpex.hunt.pipe.targeted import TARGETED_SCOPES

    return {"stomping": (None,), "pipe": tuple(TARGETED_SCOPES), "cs-beacon": (None,),
            "yara": (None,), "obfuscation": tuple(TARGETED_LAYERS)}


def test_each_schemas_targeted_scope_set_is_the_adapters_own_exactly():
    """Pinned as an exact array rather than by membership: a subset claims
    fewer closures ran than did, and another order is a different document."""
    order = _adapter_closure_order()
    for hunter, then in _targeted_hunter_branches(_load(CURRENT_SCHEMA)).items():
        rule = then["properties"]["summary"]["properties"]["scan_scope"]["properties"]["scopes"]
        assert rule == {"const": sorted(s for s in order[hunter] if s is not None)}, hunter


def _targeted_scope_rule(then):
    return (then["properties"]["data"]["properties"]["records"]["items"]
            ["properties"]["details"]["properties"]["targeted_scope"])


def test_each_analyzers_closure_count_and_order_are_pinned():
    """`summary.scan_scope.scopes` is sorted; `details.targeted_scope` follows
    the adapter's fixed closure order. Both are pinned as produced."""
    from dumpex.hunt import _registry

    order = _adapter_closure_order()
    for hunter, then in _targeted_hunter_branches(_load(CURRENT_SCHEMA)).items():
        rule = _targeted_scope_rule(then)
        closures = order[hunter]
        assert rule["minItems"] == rule["maxItems"] == len(closures), hunter
        assert rule["items"] is False, hunter
        assert [(item["properties"]["source"]["const"], item["properties"]["scope"]["const"])
                for item in rule["prefixItems"]] == [
                    (_registry.REGISTRY.targeted_source(hunter), scope)
                    for scope in closures], hunter


def test_a_targeted_hunter_branch_pins_selected_to_the_same_analyzer():
    """`selected` already pins the single record and its `hunter`, so pinning
    `scan_scope.hunter` to `selected` is what closes the identity chain."""
    for hunter, then in _targeted_hunter_branches(_load(CURRENT_SCHEMA)).items():
        assert then["properties"]["summary"]["properties"]["selected"]["const"] == hunter

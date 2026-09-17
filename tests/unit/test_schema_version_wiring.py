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

# A `vMAJOR.MINOR` written in prose. Compiled once, here, rather than
# inline at the call site: a pattern spelled with `\b` is one stray
# non-raw string away from matching two backspace characters instead of
# two word boundaries, which matches nothing and turns the assertion that
# uses it into a pass that tests nothing.
_VERSION_IN_PROSE = re.compile(r"\bv(\d+)\.(\d+)\b")


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

def test_v2_15s_row_names_the_missed_byte_states():
    """A consumer thresholding on `bytes` has to be told, in the doc it
    pins against, that the number is a total only in one of the three
    states -- otherwise a lower bound or a null reads as a total. Pinned
    to the version that introduced the field, like every other row test
    above: a later bump does not move the release a consumer reads to
    learn about it."""
    row = _version_summary_row("2.15")
    assert "missed_bytes" in row
    for state in ("exact", "lower_bound", "unknown"):
        assert state in row


# ── v2.17's report enrichment ───────────────────────────────────────────

def test_the_current_versions_row_names_the_enrichment_evidence_states():
    """The three states are the only thing standing between an empty
    enrichment subset and a consumer reading it as a process-wide
    negative, so the doc a consumer pins against has to name all three."""
    row = _version_summary_row(SCHEMA_VERSION)
    assert "process_enrichment" in row
    for state in ("missing", "partial", "complete"):
        assert state in row


def test_the_current_versions_row_names_every_card_scoped_projection():
    row = _version_summary_row(SCHEMA_VERSION)
    for projection in ("exception_context", "allocation_neighborhood", "handle_correlation",
                       "string_context"):
        assert projection in row


def test_the_schema_itself_defines_the_enrichment_evidence_states():
    """The migration doc is prose; the schema is what consumers pin."""
    schema = _load(CURRENT_SCHEMA)
    section = schema["$defs"]["enrichmentSection"]
    assert section["properties"]["status"]["enum"] == ["missing", "partial", "complete"]
    assert section["properties"]["scope"]["enum"] == ["process", "card"]
    assert set(section["required"]) == {
        "name", "scope", "status", "total", "included", "cap", "truncated", "provenance",
        "limitations"}
    # `total` and `cap` are nullable: an undeterminable eligible
    # population and an uncapped section each report no number rather
    # than a 0 a consumer would read as "nothing was eligible".
    assert section["properties"]["total"]["type"] == ["integer", "null"]
    assert section["properties"]["cap"]["type"] == ["integer", "null"]


def test_every_card_scoped_projection_is_required_on_a_triage_card():
    """Required-and-nullable, not optional: a consumer must be able to
    tell "this producer built no projection" from "this key is missing
    because the producer is older"."""
    card = _load(CURRENT_SCHEMA)["$defs"]["triageCardRecord"]
    for projection in ("exception_context", "allocation_neighborhood", "handle_correlation",
                       "string_context"):
        assert projection in card["required"]
        assert {"type": "null"} in card["properties"][projection]["anyOf"]


def test_enrichment_is_absent_from_the_triage_cards_judgment_fields():
    """Enrichment is captured evidence: the closed finding vocabulary and
    the verdict tiers are exactly what they were before it existed."""
    card = _load(CURRENT_SCHEMA)["$defs"]["triageCardRecord"]
    assert card["properties"]["findings"]["items"]["enum"] == [
        "unbacked_thread", "rwx_private", "injected_pe", "ioc_strings"]
    assert card["properties"]["verdict"]["enum"] == [
        "CLEAN", "SUSPICIOUS", "LIKELY_MALICIOUS", "HIGH_CONFIDENCE_MALICIOUS"]


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
        "distinct_ranges", "eligible_bytes", "unscanned_pass_bytes", "unscanned_fraction"}
    # Both sides of the proportion are nullable: a producer that
    # established no denominator reports no scale and no fraction, which
    # is a different claim from a run that took nothing into scope.
    assert missed["properties"]["eligible_bytes"]["type"] == ["integer", "null"]
    # The numerator the fraction is built from shares the denominator's
    # per-pass basis and is always present, unlike `bytes`, which measures
    # memory and is null in the UNKNOWN state.
    assert missed["properties"]["unscanned_pass_bytes"]["type"] == "integer"
    assert missed["properties"]["unscanned_fraction"]["type"] == ["number", "null"]
    assert missed["properties"]["unscanned_fraction"]["maximum"] == 1
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
                "quantified_gaps": 0, "unquantified_gaps": 0, "distinct_ranges": 0,
                "eligible_bytes": None, "unscanned_pass_bytes": 0, "unscanned_fraction": None}
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


def test_the_schema_enforces_what_a_proportion_may_be_stated_against():
    """The fraction is the byte figure divided by a scale, so every shape
    where there is no supportable scale -- or no measured numerator -- has
    to report no fraction rather than a number a consumer would threshold
    on."""
    schema = _load(CURRENT_SCHEMA)
    validator = _validator_for(schema, "#/$defs/missedBytes")

    def _doc(**kw):
        base = {"state": "exact", "bytes": 0, "complete": True,
                "quantified_gaps": 0, "unquantified_gaps": 0, "distinct_ranges": 0,
                "eligible_bytes": None, "unscanned_pass_bytes": 0, "unscanned_fraction": None}
        base.update(kw)
        return base

    # A complete scan over real in-scope work: 0% unscanned is an answer,
    # and the scale it is 0% of is stated.
    assert validator.is_valid(_doc(eligible_bytes=4096, unscanned_fraction=0.0))
    assert validator.is_valid(_doc(state="lower_bound", bytes=4096, complete=False,
                                    quantified_gaps=1, unquantified_gaps=1,
                                    distinct_ranges=1, eligible_bytes=8192,
                                    unscanned_pass_bytes=4096, unscanned_fraction=0.5))
    # No denominator, and a zero one, leave nothing for a proportion to be
    # of -- neither may carry a number.
    assert not validator.is_valid(_doc(unscanned_fraction=0.0))
    assert not validator.is_valid(_doc(eligible_bytes=0, unscanned_fraction=0.0))
    # Nothing measured: a fraction here would report a run whose budget
    # stopped it somewhere unknown as having missed a definite share.
    assert not validator.is_valid(_doc(state="unknown", bytes=None, complete=False,
                                        unquantified_gaps=2, eligible_bytes=4096,
                                        unscanned_fraction=0.0))
    # A run cannot miss a larger share of its scope than all of it.
    assert not validator.is_valid(_doc(bytes=4096, quantified_gaps=1, distinct_ranges=1,
                                        eligible_bytes=4096, unscanned_pass_bytes=4096,
                                        unscanned_fraction=1.5))
    # ... nor more per-pass BYTES than its scope holds. The full
    # `unscanned_pass_bytes <= eligible_bytes` is not expressible as such;
    # what is, and what catches the degenerate end of it, is that a run
    # reporting missed pass-bytes cannot also report a scope of zero.
    assert validator.is_valid(_doc(bytes=4096, quantified_gaps=1, distinct_ranges=1,
                                    eligible_bytes=8192, unscanned_pass_bytes=4096,
                                    unscanned_fraction=0.5))
    assert not validator.is_valid(_doc(bytes=4096, quantified_gaps=1, distinct_ranges=1,
                                        eligible_bytes=0, unscanned_pass_bytes=4096,
                                        unscanned_fraction=None))


def test_a_not_evaluated_coverage_object_may_not_carry_a_scale():
    """A hunter that evaluated nothing has no in-scope memory for a gap to
    be a proportion of. The producer short-circuits it; this is the half a
    consumer can actually pin."""
    schema = _load(CURRENT_SCHEMA)
    for owner in ("result", "hunterRecord"):
        validator = _validator_for(schema, f"#/$defs/{owner}/properties/coverage")
        missed = {"state": "exact", "bytes": 0, "complete": True, "quantified_gaps": 0,
                   "unquantified_gaps": 0, "distinct_ranges": 0, "eligible_bytes": None,
                   "unscanned_pass_bytes": 0, "unscanned_fraction": None}

        def _coverage(status, **kw):
            return {"status": status, "reasons": [], "sources": {}, "limitations": [],
                     "missed_bytes": {**missed, **kw}}

        assert validator.is_valid(_coverage("not_evaluated"))
        assert validator.is_valid(_coverage("complete", eligible_bytes=4096,
                                             unscanned_fraction=0.0))
        assert not validator.is_valid(_coverage("not_evaluated", eligible_bytes=4096,
                                                 unscanned_fraction=0.0))
        assert not validator.is_valid(_coverage("not_evaluated", eligible_bytes=0))


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


# ── v2.18's PE, instruction, and IAT correlation ────────────────────────

def test_v2_18s_row_names_the_new_projections():
    row = _version_summary_row("2.18")
    for token in ("pe_context", "anchor_pe_context", "instruction_context",
                  "iat_correlation"):
        assert token in row


def test_v2_18s_row_names_the_decoder_states_and_why_one_is_unavailable():
    row = _version_summary_row("2.18")
    for state in ("decoded", "not_run", "unavailable", "unsupported_arch",
                  "decode_error"):
        assert state in row
    # The decoder ships with every supported installation, so the row
    # explains `unavailable` as a broken install rather than telling a
    # consumer to install an extra.
    assert "capstone" in row
    assert "dumpex[disasm]" not in row


def test_v2_18s_row_states_that_no_verdict_moves():
    row = _version_summary_row("2.18")
    assert "coverage.status" in row and "exit code" in row


def test_the_schema_defines_the_new_card_projections_required_and_nullable():
    card = _load(CURRENT_SCHEMA)["$defs"]["triageCardRecord"]
    for projection in ("anchor_pe_context", "instruction_context", "iat_correlation"):
        assert projection in card["required"]
        assert {"type": "null"} in card["properties"][projection]["anyOf"]
    summary = _load(CURRENT_SCHEMA)["$defs"]["reportSummary"]
    assert "pe_context" in summary["required"]
    assert {"type": "null"} in summary["properties"]["pe_context"]["anyOf"]


def test_the_schema_defines_the_instruction_decoder_states():
    schema = _load(CURRENT_SCHEMA)
    assert schema["$defs"]["reportInstructionContext"]["properties"]["decoder_state"]["enum"] == [
        "decoded", "not_run", "unavailable", "unsupported_arch", "arch_undetermined",
        "decode_error", "undecoded_tail"]
    assert schema["$defs"]["reportBranchTarget"]["properties"]["kind"]["enum"] == [
        "direct", "iat_slot", "indirect_memory", "indirect_register"]


def test_enrichment_stays_absent_from_the_triage_cards_judgment_fields_in_v2_18():
    card = _load(CURRENT_SCHEMA)["$defs"]["triageCardRecord"]
    assert card["properties"]["findings"]["items"]["enum"] == [
        "unbacked_thread", "rwx_private", "injected_pe", "ioc_strings"]
    assert card["properties"]["verdict"]["enum"] == [
        "CLEAN", "SUSPICIOUS", "LIKELY_MALICIOUS", "HIGH_CONFIDENCE_MALICIOUS"]

# ── v2.19's `--process` PE profile ──────────────────────────────────────


def _uncollected_pe_image() -> dict:
    """`pe_image` for a run that built no profile."""
    return {
        "collected": False, "correlated": False, "unavailable_reason": "no_image_base",
        "source_kind": None,
        "module_identity": {"value": None, "form": None, "truncated": False},
        "actual_base": None, "preferred_image_base": None, "format": None,
        "machine": None, "machine_name": None, "time_date_stamp": None, "checksum": None,
        "subsystem": None, "dll_characteristics": None, "coff_characteristics": None,
        "size_of_image": None, "size_of_headers": None, "section_alignment": None,
        "file_alignment": None, "declared_section_count": None,
        "decoded_section_count": 0, "structural_state": None,
        "relocation": {"delta": None, "relocs_stripped": None, "dynamic_base": None,
                        "basereloc_present": None, "basereloc_descriptor_state": None},
        "entry_point": {"rva": None, "va": None, "va_overflow": False,
                         "section_index": None, "section_name": None, "capture_state": None,
                         "region_state": None, "region_type": None,
                         "region_protection": None},
        "acquisition": None,
        "directory_summary": {"declared_count": None, "declared_count_raw": None,
                               "readable_count": None, "unprojected_count": None},
        "module_match": None,
        "observation_coverage": {"total": 0, "consistent": 0, "conflict": 0, "unavailable": 0,
                                  "not_applicable": 0},
        "sections": [], "directories": [], "observations": [],
    }


def _collected_pe_image() -> dict:
    """The same object for a run that built one, in the smallest shape a
    collected profile can legitimately have: no decoded section, every
    descriptor present, and -- with `correlated` false -- no observation,
    no tally, and no resolution the correlation would have performed."""
    document = _uncollected_pe_image()
    document.update({
        "collected": True, "unavailable_reason": None, "source_kind": "peb_image_base",
        "actual_base": "0x0000000000400000", "structural_state": "partial",
        "module_match": "unregistered",
        # BASERELOC is one of the sixteen a collected profile always
        # carries, so its state is an answer even when nothing of the
        # descriptor arrived.
        "relocation": dict(document["relocation"],
                            basereloc_descriptor_state="unavailable"),
        "acquisition": {
            "requested_stage": "sections", "highest_completed_stage": "coff",
            "requested_bytes": 4096, "captured_bytes": 4096, "read_bytes": 64,
            "read_target_bytes": 64, "target_io_short": False, "bounded_stop": None,
            "components": {"dos_header": "complete", "coff_header": "complete",
                            "optional_header": "unavailable",
                            "directory_array": "unavailable",
                            "directory_descriptors": "unavailable",
                            "section_table": "unavailable"},
            "segment_table": "enumerated", "region_table": "enumerated",
            "capture_overlapping": False, "unexamined": []},
        "directories": [
            {"index": index, "name": "DIRECTORY_%d" % index, "value": None,
             "value_kind": "rva", "size": None, "bytes_read": 0, "present": None,
             "descriptor_state": "unavailable", "containing_section_index": None,
             "capture_state": None}
            for index in range(16)],
    })
    return document


def test_v2_19s_row_names_the_new_process_record():
    row = _version_summary_row("2.19")
    for token in ("pe_image", "collected", "unavailable_reason", "observations",
                  "structural_state"):
        assert token in row


def test_v2_19s_row_says_the_evidence_is_optional_and_moves_nothing():
    """The two things a consumer most needs to know: an unreadable image
    cannot downgrade the identity facts beside it, and nothing about
    coverage or exit behavior moved."""
    row = _version_summary_row("2.19")
    assert "coverage.status" in row and "exit code" in row
    assert "verdict" in row and "score" in row


def test_v2_19s_row_states_the_mapping_to_the_legacy_triple():
    """`identity_evidence.main_image_pe` keeps its meaning, so the doc a
    consumer pins has to say how the two relate rather than leaving them
    to guess that one replaced the other."""
    row = _version_summary_row("2.19")
    assert "identity_evidence.main_image_pe" in row
    assert "checked" in row


def test_the_schema_requires_the_pe_profile_on_every_process_record():
    """Required and never null: a consumer must be able to tell "this
    producer collected no profile" from "this key is missing because the
    producer is older"."""
    record = _load(CURRENT_SCHEMA)["$defs"]["processRecord"]
    assert "pe_image" in record["required"]
    assert record["properties"]["pe_image"] == {"$ref": "#/$defs/processPeRecord"}


def test_the_schema_defines_the_pe_profiles_own_vocabularies():
    schema = _load(CURRENT_SCHEMA)
    pe_record = schema["$defs"]["processPeRecord"]["properties"]
    assert pe_record["unavailable_reason"]["enum"] == [
        "no_image_base", "header_unreadable", "collection_failed", None]
    assert pe_record["structural_state"]["enum"] == [
        "complete", "partial", "unavailable", "malformed", "declared_absent", None]
    assert pe_record["format"]["enum"] == ["PE32", "PE32+", None]
    acquisition = schema["$defs"]["processPeAcquisition"]["properties"]
    assert acquisition["requested_stage"]["enum"] == ["dos", "coff", "optional", "sections"]
    # A table that could not be walked in full is why a byte fact or a
    # check is missing, so the record has somewhere to say so. There is no
    # "absent" value: an absent stream enumerates as a table with no
    # entries, which is a different claim.
    # Five states, because a table the dump never carried, one it carried
    # that yielded nothing, and one that parsed and is legitimately empty
    # are three different claims about evidence.
    for field_name in ("segment_table", "region_table"):
        assert acquisition[field_name]["enum"] == [
            "absent", "failed", "enumerated", "lossy", "unreadable"]


def test_the_schema_keeps_the_two_withheld_answers_apart():
    """An observation that withholds an answer says which of the two it
    is on the wire, not only on the console: a consumer counting the
    evidence gap counts `unavailable` alone."""
    schema = _load(CURRENT_SCHEMA)
    assert schema["$defs"]["peObservation"]["properties"]["state"]["enum"] == [
        "consistent", "conflict", "unavailable", "not_applicable"]

    coverage = schema["$defs"]["processPeRecord"]["properties"]["observation_coverage"]
    assert coverage["required"] == [
        "total", "consistent", "conflict", "unavailable", "not_applicable"]
    assert coverage["additionalProperties"] is False

    context = schema["$defs"]["reportPeContext"]
    for field_name in ("consistent_count", "conflict_count", "unavailable_count",
                       "not_applicable_count"):
        assert field_name in context["required"]
        assert context["properties"][field_name] == {"type": "integer", "minimum": 0}


def test_the_new_state_belongs_to_the_current_contract_alone():
    """A document is validated against the version that produced it, so a
    vocabulary added now must not appear in a frozen predecessor. v2.18's
    observation shape is the one `--report` already shipped."""
    previous = _load("dumpex-output-v2.18.schema.json")
    states = previous["$defs"]["reportPeObservation"]["properties"]["state"]["enum"]
    assert states == ["consistent", "conflict", "unavailable"]
    assert "not_applicable_count" not in \
        previous["$defs"]["reportPeContext"]["properties"]
    assert "processPeRecord" not in previous["$defs"]


def test_an_uncorrelated_profile_counts_nothing_in_any_state():
    """Every count is pinned to zero, so a state added to the tally
    cannot leave a correlation that did not run carrying a number."""
    schema = _load(CURRENT_SCHEMA)["$defs"]["processPeRecord"]
    for branch in schema["allOf"]:
        else_branch = branch.get("else", {}).get("properties", {})
        tally = else_branch.get("observation_coverage")
        if tally is None:
            continue
        assert set(tally["properties"]) == {
            "total", "consistent", "conflict", "unavailable", "not_applicable"}
        assert all(entry == {"const": 0} for entry in tally["properties"].values())


def test_the_observation_shape_is_shared_by_both_surfaces():
    """One observation shape, two consumers: a rename that left `--report`
    on a second copy would let the two drift."""
    schema = _load(CURRENT_SCHEMA)
    assert "peObservation" in schema["$defs"]
    assert "reportPeObservation" not in schema["$defs"]
    report = schema["$defs"]["reportPeContext"]["properties"]["observations"]["items"]
    process = schema["$defs"]["processPeRecord"]["properties"]["observations"]["items"]
    assert report == process == {"$ref": "#/$defs/peObservation"}


def test_the_schema_enforces_what_an_uncollected_profile_may_carry():
    """`collected` is one fact in several fields: a record claiming no
    profile while carrying sections, descriptors or observations would
    describe evidence that came from nowhere."""
    schema = _load(CURRENT_SCHEMA)
    validator = _validator_for(schema, "#/$defs/processPeRecord")

    def _doc(**kw):
        return {**_uncollected_pe_image(), **kw}

    assert validator.is_valid(_doc())
    # A reason is exactly what "no profile" means; a collected one has none.
    assert not validator.is_valid(_doc(unavailable_reason=None))
    assert not validator.is_valid(_doc(collected=True))
    # Evidence without a profile to have produced it.
    assert not validator.is_valid(_doc(observations=[
        {"name": "machine_vs_format", "state": "unavailable", "reason": "machine_null",
         "sources": [], "operands": {}}]))
    assert not validator.is_valid(_doc(directories=[{
        "index": 0, "name": "EXPORT", "value": 0, "value_kind": "rva", "size": 0,
        "bytes_read": 8, "present": False, "descriptor_state": "declared_absent",
        "containing_section_index": None, "capture_state": None}]))


@pytest.mark.parametrize("field,value", [
    ("source_kind", "peb_image_base"),
    ("actual_base", "0x0000000000400000"),
    ("preferred_image_base", "0x0000000000400000"),
    ("format", "PE32+"),
    ("machine", 0x8664),
    ("machine_name", "AMD64"),
    ("time_date_stamp", 1),
    ("size_of_image", 0x5000),
    ("declared_section_count", 1),
    ("decoded_section_count", 1),
    ("structural_state", "complete"),
    ("module_match", "resolved"),
])
def test_an_uncollected_profile_may_not_carry_a_pe_fact(field, value):
    """`collected` is the discriminator a consumer branches on. A record
    reporting no profile while carrying a base, a machine, or a module
    match describes evidence that came from nowhere."""
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _uncollected_pe_image()
    document[field] = value
    assert not validator.is_valid(document)


@pytest.mark.parametrize("owner,key,value", [
    ("module_identity", "value", "C:\\a.exe"),
    ("module_identity", "truncated", True),
    ("relocation", "delta", 0),
    ("relocation", "basereloc_descriptor_state", "complete"),
    ("entry_point", "rva", 4096),
    ("entry_point", "va_overflow", True),
    ("directory_summary", "declared_count", 16),
    ("observation_coverage", "total", 1),
    ("observation_coverage", "unavailable", 1),
])
def test_an_uncollected_profiles_nested_objects_establish_nothing(owner, key, value):
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _uncollected_pe_image()
    document[owner][key] = value
    assert not validator.is_valid(document)


@pytest.mark.parametrize("field", [
    "source_kind", "actual_base", "structural_state", "acquisition", "module_match",
])
def test_a_collected_profile_must_name_what_produced_it(field):
    """The converse: a profile with no source, no base it was read at, no
    state, no acquisition, or no answer about the loader's own record is a
    profile that does not exist, reported as one that does."""
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _collected_pe_image()
    assert validator.is_valid(document)
    document[field] = None
    assert not validator.is_valid(document)


def test_a_collected_profile_must_state_its_relocation_descriptor_state():
    """BASERELOC is one of the sixteen descriptors a collected profile
    always carries, so how much of it was read is always an answer. The
    record layer refuses a null here, and the schema says the same thing:
    a consumer must not be left a branch dumpex never produces."""
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _collected_pe_image()
    assert validator.is_valid(document)
    document["relocation"]["basereloc_descriptor_state"] = None
    assert not validator.is_valid(document)


@pytest.mark.parametrize("field", [
    "delta", "relocs_stripped", "dynamic_base", "basereloc_present",
])
def test_the_other_relocation_facts_stay_independently_nullable(field):
    """Each of the four is a decoded field that may not have been read,
    and an unread Characteristics bit is not a false one."""
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _collected_pe_image()
    document["relocation"][field] = None
    assert validator.is_valid(document)


def test_a_collected_profile_carries_every_descriptor():
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _collected_pe_image()
    document["directories"] = document["directories"][:8]
    assert not validator.is_valid(document)


def test_the_schema_keeps_a_mapped_range_one_fact():
    """A start with no extent, or an extent with no place, is not a range."""
    schema = _load(CURRENT_SCHEMA)
    validator = _validator_for(schema, "#/$defs/processPeSection")

    def _section(**kw):
        base = {"section_index": 0, "name": ".text", "virtual_address": 4096,
                 "virtual_size": 8192, "size_of_raw_data": 8192,
                 "characteristics": 0, "declared_readable": True,
                 "declared_writable": False, "declared_executable": True,
                 "mapped_base_address": "0x0000000000401000", "mapped_size": 8192,
                 "capture_state": "complete", "live_protections": []}
        base.update(kw)
        return base

    assert validator.is_valid(_section())
    assert validator.is_valid(_section(mapped_base_address=None, mapped_size=None))
    assert not validator.is_valid(_section(mapped_base_address=None))
    assert not validator.is_valid(_section(mapped_size=None))


def test_a_correlation_that_ran_carries_its_observations():
    """`total: 0` beside `correlated: true` would report a correlation that
    established nothing -- and read exactly like a clean image."""
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _collected_pe_image()
    document["correlated"] = True
    assert not validator.is_valid(document)

    document["observations"] = [{
        "name": "machine_vs_format", "state": "unavailable", "reason": "machine_null",
        "sources": ["profile.coff_header"], "operands": {}}]
    document["observation_coverage"] = {"total": 1, "consistent": 0, "conflict": 0,
                                         "unavailable": 1, "not_applicable": 0}
    assert validator.is_valid(document)


@pytest.mark.parametrize("owner,key,value", [
    ("entry_point", "va", "0x0000000000401000"),
    ("entry_point", "section_index", 0),
    ("entry_point", "region_protection", "PAGE_EXECUTE_READ"),
])
def test_an_uncorrelated_profile_resolves_nothing_into_the_process(owner, key, value):
    """Everything the correlation resolves -- the entry point's VA, its
    section, the memory around it -- is withheld when it did not run."""
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _collected_pe_image()
    document[owner][key] = value
    assert not validator.is_valid(document)


def test_an_uncorrelated_profiles_sections_carry_no_resolution():
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _collected_pe_image()
    document["decoded_section_count"] = 1
    document["sections"] = [{
        "section_index": 0, "name": ".text", "virtual_address": 0x1000,
        "virtual_size": 0x2000, "size_of_raw_data": 0x2000, "characteristics": 0,
        "declared_readable": True, "declared_writable": False, "declared_executable": True,
        "mapped_base_address": None, "mapped_size": None, "capture_state": None,
        "live_protections": []}]
    assert validator.is_valid(document)

    document["sections"][0]["live_protections"] = ["PAGE_EXECUTE_READ"]
    assert not validator.is_valid(document)


def test_every_table_state_is_reportable_on_the_wire():
    """The fix for a table that bounds nothing has to be expressible
    without another public bump, so the field exists in this cutover --
    with the byte provenance each state allows."""
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeAcquisition")
    acquisition = _collected_pe_image()["acquisition"]
    assert acquisition["captured_bytes"] is not None

    # The region table bounds no read, so it constrains nothing here.
    for state in ("absent", "failed", "enumerated", "lossy", "unreadable"):
        assert validator.is_valid({**acquisition, "region_table": state})
    assert not validator.is_valid({**acquisition, "region_table": "missing"})
    assert not validator.is_valid({**acquisition, "segment_table": "missing"})


@pytest.mark.parametrize("state", ["absent", "failed", "lossy", "unreadable"])
def test_a_segment_table_that_established_nothing_resolved_no_capture(state):
    """Only a table that enumerated whole can resolve the header's byte
    provenance. A record reporting a byte count under any other state
    claims a slice resolved against a table that established nothing."""
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeAcquisition")
    acquisition = _collected_pe_image()["acquisition"]

    assert not validator.is_valid({**acquisition, "segment_table": state})
    assert validator.is_valid({**acquisition, "segment_table": state,
                                "captured_bytes": None, "capture_overlapping": None})


def test_an_enumerated_table_may_still_resolve_no_capture():
    """The implication runs one way: `_capture_for` also refuses a slice
    accounting for fewer bytes than the read returned, and that leaves an
    `enumerated` table with no byte provenance."""
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeAcquisition")
    acquisition = _collected_pe_image()["acquisition"]

    assert validator.is_valid({**acquisition, "captured_bytes": None,
                                "capture_overlapping": None})


def test_a_capture_slice_and_its_overlap_answer_are_one_fact():
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeAcquisition")
    acquisition = _collected_pe_image()["acquisition"]

    assert not validator.is_valid({**acquisition, "captured_bytes": None})
    assert not validator.is_valid({**acquisition, "capture_overlapping": None})


def test_no_schema_files_opening_sentence_names_another_version():
    """The top-level description is the authoritative prose for a shipped
    contract, and a new schema is always a copy of the previous one --
    which is exactly how one comes to open by naming the version it was
    copied from. Asserted as "names no OTHER version" rather than "starts
    with its own", because the early v2 files legitimately say "the v2
    envelope" with no minor at all, and they are frozen."""
    for (major, minor), filename in _packaged_schemas().items():
        opening = _load(filename)["description"].split(". ", 1)[0]
        named = set(re.findall(_VERSION_IN_PROSE, opening))
        assert named <= {(str(major), str(minor))}, (filename, sorted(named))


def test_the_current_schemas_description_opens_with_its_own_version():
    major, minor = _version_tuple(SCHEMA_VERSION)
    description = _load(CURRENT_SCHEMA)["description"]
    assert description.startswith(f"Validates the v{major}.{minor} ")


@pytest.mark.parametrize("opening,named", [
    ("Validates the v2.18 `--json` envelope for --list", {("2", "18")}),
    ("Validates the v2 envelope written by the six recon commands", set()),
    ("Validates the v2.19 envelope, superseding v2.18", {("2", "19"), ("2", "18")}),
])
def test_the_version_pattern_actually_finds_a_version_in_prose(opening, named):
    """The check above is only worth its assertion if the pattern matches
    a real sentence. A pattern that matches nothing makes every document
    pass, which is indistinguishable from every document being correct --
    so the pattern is tested against prose that does and does not name a
    version, rather than only against the shipped files."""
    assert set(re.findall(_VERSION_IN_PROSE, opening)) == named


def test_a_description_naming_another_version_is_caught():
    """The failure this guards against, evaluated end to end: the same
    comparison the loop above performs, over a description copied forward
    without its version being updated."""
    opening = "Validates the v2.18 `--json` envelope for --list".split(". ", 1)[0]
    named = set(re.findall(_VERSION_IN_PROSE, opening))

    assert named, "the pattern found no version at all -- the check would be vacuous"
    assert not named <= {("2", "19")}

# ── the producer contract and the consumer contract admit the same data ─
# A field the record layer validates with `_require_optional_nonneg_int`
# and a schema field with no `minimum` are two different contracts: the
# schema would certify a document no producer can build, which is the one
# direction a consumer cannot defend against.

_NON_NEGATIVE_RECORD_FIELDS = (
    "machine", "time_date_stamp", "checksum", "subsystem", "dll_characteristics",
    "coff_characteristics", "size_of_image", "size_of_headers", "section_alignment",
    "file_alignment", "declared_section_count",
)


@pytest.mark.parametrize("field", _NON_NEGATIVE_RECORD_FIELDS)
def test_a_pe_count_may_not_be_negative(field):
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _collected_pe_image()
    document[field] = -1
    assert not validator.is_valid(document)


@pytest.mark.parametrize("owner,key", [
    ("directory_summary", "declared_count"),
    ("directory_summary", "declared_count_raw"),
    ("directory_summary", "readable_count"),
    ("directory_summary", "unprojected_count"),
    ("acquisition", "captured_bytes"),
])
def test_a_nested_pe_count_may_not_be_negative(owner, key):
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _collected_pe_image()
    document[owner][key] = -1
    assert not validator.is_valid(document)


def test_the_relocation_delta_stays_signed():
    """An image loaded below its preferred base has moved down, and a
    non-negative bound would forbid saying so."""
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _collected_pe_image()
    document["relocation"]["delta"] = -0x10000
    assert validator.is_valid(document)


@pytest.mark.parametrize("field", ["value", "size", "containing_section_index", "bytes_read"])
def test_a_descriptors_counts_may_not_be_negative(field):
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeDirectory")
    descriptor = {"index": 0, "name": "EXPORT", "value": 0, "value_kind": "rva", "size": 0,
                   "bytes_read": 8, "present": False, "descriptor_state": "declared_absent",
                   "containing_section_index": None, "capture_state": None}
    assert validator.is_valid(descriptor)
    assert not validator.is_valid({**descriptor, field: -1})


@pytest.mark.parametrize("field", ["mapped_size"])
def test_a_sections_counts_may_not_be_negative(field):
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeSection")
    section = {"section_index": 0, "name": ".text", "virtual_address": 0x1000,
                "virtual_size": 0x2000, "size_of_raw_data": 0x2000, "characteristics": 0,
                "declared_readable": True, "declared_writable": False,
                "declared_executable": True, "mapped_base_address": "0x0000000000401000",
                "mapped_size": 0x2000, "capture_state": "complete", "live_protections": []}
    assert validator.is_valid(section)
    assert not validator.is_valid({**section, field: -1})


# ── a zero entry point resolves nothing ─────────────────────────────────

def _entry_point(**kw):
    base = {"rva": 0, "va": None, "va_overflow": False, "section_index": None,
             "section_name": None, "capture_state": None, "region_state": None,
             "region_type": None, "region_protection": None}
    base.update(kw)
    return base


@pytest.mark.parametrize("field,value", [
    ("va", "0x0000000000401000"),
    ("section_index", 0),
    ("section_name", ".text"),
    ("capture_state", "complete"),
    ("region_state", "MEM_COMMIT"),
    ("region_type", "MEM_IMAGE"),
    ("region_protection", "PAGE_EXECUTE_READ"),
    ("va_overflow", True),
])
def test_a_zero_entry_point_resolves_nothing_into_the_process(field, value):
    """`rva: 0` is "this image declares no entry point". Resolving
    `actual_base + 0` would present the header page as where execution
    begins, so every field that would have said so is null."""
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeEntryPoint")
    assert validator.is_valid(_entry_point())
    assert not validator.is_valid(_entry_point(**{field: value}))


def test_a_real_entry_point_still_carries_its_context():
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeEntryPoint")
    assert validator.is_valid(_entry_point(
        rva=0x1000, va="0x0000000000401000", section_index=0, section_name=".text",
        capture_state="complete", region_state="MEM_COMMIT", region_type="MEM_IMAGE",
        region_protection="PAGE_EXECUTE_READ"))


# ── indices, arrays and counts ──────────────────────────────────────────

def test_every_descriptor_sits_at_its_own_index():
    """Sixteen descriptors that are all index 0 is a table with one
    descriptor repeated, not the sixteen the record promises."""
    validator = _validator_for(_load(CURRENT_SCHEMA), "#/$defs/processPeRecord")
    document = _collected_pe_image()
    assert validator.is_valid(document)

    duplicated = _collected_pe_image()
    duplicated["directories"][1] = dict(duplicated["directories"][0])
    assert not validator.is_valid(duplicated)

    reversed_order = _collected_pe_image()
    reversed_order["directories"].reverse()
    assert not validator.is_valid(reversed_order)

    seventeen = _collected_pe_image()
    seventeen["directories"].append(dict(seventeen["directories"][0]))
    assert not validator.is_valid(seventeen)


def test_the_schema_names_the_relationships_it_cannot_express():
    """`decoded_section_count`, the observation total and the tally's sum
    are cross-field equalities JSON Schema has no way to state. The record
    layer enforces all three; the schema says so, so a consumer reads the
    limit rather than assuming validation covered it."""
    description = _load(CURRENT_SCHEMA)["$defs"]["processPeRecord"]["description"]
    assert "NOT expressible in JSON Schema" in description
    for relationship in ("decoded_section_count", "observation_coverage.total",
                          "sum to its total"):
        assert relationship in description

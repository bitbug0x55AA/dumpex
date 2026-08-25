"""
Validates real dumpex.output.V2Output JSON against
dumpex/schemas/dumpex-output-v2.13.schema.json (the current v2 schema --
every producer now stamps schema_version "2.13") for each of the seven
recon-command kinds (memory_regions/modules/threads/process/sysinfo/
handles/profile), in normal, empty, and partial-coverage shapes -- built
through the actual collect_*() functions against synthetic fixtures, not
hand-written fixture JSON, so a shape change in any of them is caught
here. v2.13 (issue #43) is the single atomic cutover that removed
`--pid`/`--peb` (kinds "pid"/"peb") and replaced them with `--process`/
`--handles`/`--profile` -- dumpex-output-v2.12.schema.json (and every
schema before it) still describes the six-kind shape those two commands
used, and stays installed so a genuine v2.12-era pid/peb document remains
validatable against its own frozen schema (see the "v2.12-era pid/peb"
section below), separate from the historical-delta chain this docstring
otherwise describes below (v2.0 through v2.10, all of which predate #43
and never touched the pid/peb/sysinfo shapes at all).
dumpex-output-v2.0.schema.json, dumpex-output-v2.1.schema.json,
dumpex-output-v2.2.schema.json, dumpex-output-v2.3.schema.json,
dumpex-output-v2.4.schema.json, dumpex-output-v2.5.schema.json,
dumpex-output-v2.6.schema.json, dumpex-output-v2.7.schema.json,
dumpex-output-v2.8.schema.json, and dumpex-output-v2.9.schema.json (the
frozen historical shapes) are also exercised directly (see the "schema
version history" section below) to
prove each still validates a genuine document from its own era and
still rejects a `result.kind` it was never updated to know about --
v2.7 is a strict superset of v2.6 for these six recon-command kinds
(v2.7's only actual change is re-keying `--hunt cs-beacon`'s
csBeaconDetails.configs[*].fields by field NAME instead of numeric ID --
see tests/hunt/test_cs_beacon_collect.py for that; none of it is visible
to this file's own six recon-command kinds), so every real document that
validated against v2.6 continues to validate against v2.7 unchanged,
just carrying the new version label. v2.6 itself was a strict superset
of v2.5 for these six kinds too (v2.6's only actual change was removing
`raw` from csBeaconDetails.configs[*].fields[*]), and v2.5 was a strict
superset of v2.4 (v2.5's only actual change was extending the hunt
`finding` $def with id/severity/technique_ids/evidence_refs/iocs/rule_id/
rule_version -- see test_json_schema_v2_5_hunt.py for that).

v2.8 broke that "strict superset, old document still validates
unmodified" chain once, the only time since v2.0: it added a `targets`
array to the shared `coverageLimitation` $def (see "SCAN_REGION_
OVERSIZED_SKIPPED source contract" below) and, following this schema's
own established convention that every CoverageLimitation field is always
emitted and therefore `required` (matching unavailable_fields/
available_fields/etc., all required even when empty), `targets` is
`required` too -- not merely additive-and-optional. All six recon
commands can emit coverageLimitation entries (SOURCE_ABSENT/SOURCE_
FAILED/...), so a genuine v2.7-era document of any of these six kinds,
which never had a `targets` key at all, FAILS validation against v2.8
with `'targets' is a required property` -- this is exactly why that
version bump was necessary, not an oversight. `dumpex-output-v2.7.
schema.json` stays installed specifically so that already-collected
v2.7-era output remains validatable against ITS OWN frozen schema (see
test_a_genuine_v2_7_era_document_still_validates_against_the_v2_7_schema
below), not against v2.8/v2.9.

v2.9 (issue #19 Phase 1) is back to being a strict superset for these six
recon-command kinds: its only actual change is `huntSummary.
investigation_actions` (result.summary for `kind == "hunt"` only -- see
test_json_schema_v2_5_hunt.py), which none of memory_regions/modules/
threads/sysinfo/pid/peb ever populates, so a v2.8-era document of any of
these six kinds keeps validating against v2.9 unchanged, just carrying
the new version label (see
test_a_genuine_v2_8_era_document_still_validates_against_the_v2_8_schema
below, mirroring the v2.6-era precedent rather than the v2.7-era one).

v2.10 (issue #19 Phase 2) is a strict superset for these six kinds too:
its only actual change is `triageInfo.content_reason_codes` (also under
`huntSummary`, for `kind == "hunt"` only -- see
test_json_schema_v2_5_hunt.py), so a v2.9-era document of any of these
six kinds keeps validating against v2.10 unchanged (see
test_a_genuine_v2_9_era_document_still_validates_against_the_v2_9_schema
below).

Loaded through dumpex.schemas.schema_path() (importlib.resources) so
this also proves the v2 schema is reachable the way an installed
(wheel) consumer would reach it.
"""
import json
import os
import tempfile

import pytest
import dumpex

jsonschema = pytest.importorskip("jsonschema")

from tests.fixtures.fakes import (
    Region, Module, ThreadInfo, Thread, Ctx, Peb, SysInfo, MiscInfo,
    FakeStream, FakeMF, mem_reader, Handle, wire_environment_walk,
)
from tests.unit.test_process_cmd import _complete_mf as _process_complete_mf

from dumpex.output import V2Output
from dumpex.output.envelope import SCHEMA_VERSION
from dumpex.schemas import CURRENT_SCHEMA, schema_path
from dumpex.commands.list_cmd import collect_regions
from dumpex.commands.modules import collect_modules
from dumpex.commands.threads import collect_threads
from dumpex.commands.sysinfo import collect_sysinfo
from dumpex.commands.process import collect_process
from dumpex.commands.handles import collect_handles
from dumpex.commands.profile import collect_profile
from dumpex.output.coverage import (
    SourceObservation, CoverageLimitation, LimitationCode, CoverageReport, COVERAGE_COMPLETE,
)
from dumpex.output.command_result import CommandResult
from dumpex.output.records import Artifact, Diagnostic, SEVERITY_WARNING, SEVERITY_ERROR


@pytest.fixture(scope="module")
def schema():
    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def schema_v2_9():
    with schema_path("dumpex-output-v2.9.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_9(schema_v2_9):
    jsonschema.Draft202012Validator.check_schema(schema_v2_9)
    return jsonschema.Draft202012Validator(schema_v2_9)


@pytest.fixture(scope="module")
def schema_v2_12():
    with schema_path("dumpex-output-v2.12.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_12(schema_v2_12):
    jsonschema.Draft202012Validator.check_schema(schema_v2_12)
    return jsonschema.Draft202012Validator(schema_v2_12)


@pytest.fixture(scope="module")
def schema_v2_8():
    with schema_path("dumpex-output-v2.8.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_8(schema_v2_8):
    jsonschema.Draft202012Validator.check_schema(schema_v2_8)
    return jsonschema.Draft202012Validator(schema_v2_8)


@pytest.fixture(scope="module")
def schema_v2_6():
    with schema_path("dumpex-output-v2.6.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_6(schema_v2_6):
    jsonschema.Draft202012Validator.check_schema(schema_v2_6)
    return jsonschema.Draft202012Validator(schema_v2_6)


@pytest.fixture(scope="module")
def schema_v2_7():
    with schema_path("dumpex-output-v2.7.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_7(schema_v2_7):
    jsonschema.Draft202012Validator.check_schema(schema_v2_7)
    return jsonschema.Draft202012Validator(schema_v2_7)


@pytest.fixture(scope="module")
def schema_v2_5():
    with schema_path("dumpex-output-v2.5.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_5(schema_v2_5):
    jsonschema.Draft202012Validator.check_schema(schema_v2_5)
    return jsonschema.Draft202012Validator(schema_v2_5)


@pytest.fixture(scope="module")
def schema_v2_4():
    with schema_path("dumpex-output-v2.4.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_4(schema_v2_4):
    jsonschema.Draft202012Validator.check_schema(schema_v2_4)
    return jsonschema.Draft202012Validator(schema_v2_4)


@pytest.fixture(scope="module")
def schema_v2_3():
    with schema_path("dumpex-output-v2.3.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_3(schema_v2_3):
    jsonschema.Draft202012Validator.check_schema(schema_v2_3)
    return jsonschema.Draft202012Validator(schema_v2_3)


@pytest.fixture(scope="module")
def schema_v2_2():
    with schema_path("dumpex-output-v2.2.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_2(schema_v2_2):
    jsonschema.Draft202012Validator.check_schema(schema_v2_2)
    return jsonschema.Draft202012Validator(schema_v2_2)


@pytest.fixture(scope="module")
def schema_v2_0():
    with schema_path("dumpex-output-v2.0.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_0(schema_v2_0):
    jsonschema.Draft202012Validator.check_schema(schema_v2_0)
    return jsonschema.Draft202012Validator(schema_v2_0)


@pytest.fixture(scope="module")
def schema_v2_1():
    with schema_path("dumpex-output-v2.1.schema.json") as path, open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def validator_v2_1(schema_v2_1):
    jsonschema.Draft202012Validator.check_schema(schema_v2_1)
    return jsonschema.Draft202012Validator(schema_v2_1)


@pytest.fixture(scope="module")
def validator(schema):
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


@pytest.fixture(scope="module")
def source_observation_schema(schema):
    return schema["$defs"]["sourceObservation"]


@pytest.fixture(scope="module")
def coverage_limitation_schema(schema):
    return schema["$defs"]["coverageLimitation"]


@pytest.fixture(scope="module")
def coverage_limitation_validator(schema):
    # Unlike the bare `coverage_limitation_schema` fixture above (fine for
    # every existing test, none of which populates `targets` with a real
    # scanTarget item), a SCAN_REGION_OVERSIZED_SKIPPED document's own
    # `targets[*]` is `$ref: "#/$defs/scanTarget"` -- that $ref only
    # resolves when $defs is still reachable from the validated root, so
    # these tests need the wrapped form (see _fragment_validator above).
    return _fragment_validator(schema, "coverageLimitation")


def _fragment_validator(schema, def_name):
    # Wraps a single $defs entry as its own root document (a $ref sibling
    # to the same $defs map) rather than validating the extracted dict
    # directly -- moduleDiffRecord/threadDiffRecord/memoryDiffRecord all
    # contain "#/$defs/hexAddress" $refs, which only resolve when $defs is
    # still reachable from the document actually being validated. This is
    # unlike sourceObservation/coverageLimitation above, whose extracted
    # fragments happen to contain no $ref at all.
    wrapper = {"$schema": schema["$schema"], "$ref": f"#/$defs/{def_name}", "$defs": schema["$defs"]}
    jsonschema.Draft202012Validator.check_schema(wrapper)
    return jsonschema.Draft202012Validator(wrapper)


@pytest.fixture(scope="module")
def module_diff_record_schema(schema):
    return _fragment_validator(schema, "moduleDiffRecord")


@pytest.fixture(scope="module")
def thread_diff_record_schema(schema):
    return _fragment_validator(schema, "threadDiffRecord")


@pytest.fixture(scope="module")
def memory_diff_record_schema(schema):
    return _fragment_validator(schema, "memoryDiffRecord")


@pytest.fixture(scope="module")
def profile_capability_entry_schema(schema):
    return _fragment_validator(schema, "profileCapabilityEntry")


@pytest.fixture(scope="module")
def capability_thread_analysis_schema(schema):
    return _fragment_validator(schema, "profileCapabilityThreadAnalysis")


@pytest.fixture(scope="module")
def capability_handle_analysis_schema(schema):
    return _fragment_validator(schema, "profileCapabilityHandleAnalysis")


@pytest.fixture(scope="module")
def capability_module_analysis_schema(schema):
    return _fragment_validator(schema, "profileCapabilityModuleAnalysis")


@pytest.fixture(scope="module")
def capability_injector_handle_assessment_schema(schema):
    return _fragment_validator(schema, "profileCapabilityInjectorHandleAssessment")


@pytest.fixture(scope="module")
def profile_record_schema(schema):
    return _fragment_validator(schema, "profileRecord")


@pytest.fixture(scope="module")
def profile_stream_entry_schema(schema):
    return _fragment_validator(schema, "profileStreamEntry")


@pytest.fixture(scope="module")
def iat_record_schema(schema):
    return _fragment_validator(schema, "iatRecord")


@pytest.fixture(scope="module")
def process_diagnostic_record_schema(schema):
    return _fragment_validator(schema, "processDiagnosticRecord")


@pytest.fixture(scope="module")
def import_entry_record_schema(schema):
    return _fragment_validator(schema, "importEntryRecord")


@pytest.fixture(scope="module")
def handle_record_schema(schema):
    return _fragment_validator(schema, "handleRecord")


def _make_dump_file() -> str:
    fd, path = tempfile.mkstemp(suffix=".dmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(b"synthetic dump content")
    return path


def _validate(validator, result):
    dump_path = _make_dump_file()
    try:
        out = V2Output(dump_path, command=result.kind, options={"verbose": False})
        out.set_command_result(result)
        doc = json.loads(out.to_json())
        errors = sorted(validator.iter_errors(doc), key=str)
        assert not errors, "\n".join(str(e) for e in errors)
        return doc
    finally:
        os.remove(dump_path)


# ── memory_regions (--list) ───────────────────────────────────────────────

def test_memory_regions_normal_validates(validator):
    mf = FakeMF()
    mf.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")
    result = collect_regions(mf)
    doc = _validate(validator, result)
    assert doc["result"]["execution_status"] == "completed"
    assert doc["result"]["coverage"]["status"] == "complete"


def test_memory_regions_empty_validates(validator):
    result = collect_regions(FakeMF())
    assert result.records == []
    _validate(validator, result)


# ── modules ────────────────────────────────────────────────────────────

def test_modules_normal_validates(validator):
    mf = FakeMF()
    mf.modules = FakeStream([Module(0x140000000, 0x5000, r"C:\Windows\System32\ntdll.dll")],
                             "modules")
    result = collect_modules(mf)
    _validate(validator, result)


def test_modules_empty_validates(validator):
    result = collect_modules(FakeMF())
    _validate(validator, result)


# ── threads ────────────────────────────────────────────────────────────

def test_threads_normal_validates(validator):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
    mf.modules = FakeStream([Module(0x7ffe0000, 0x1000, "legit.dll")], "modules")
    result = collect_threads(mf)
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "complete"
    assert doc["result"]["data"]["records"][0]["module_context"] == "resolved"


def test_threads_degraded_is_partial_and_validates(validator):
    mf = FakeMF()
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")   # no thread_info stream
    result = collect_threads(mf)
    assert result.coverage.status == "partial"
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "partial"
    assert doc["result"]["coverage"]["reasons"]
    # Structured coverage reaches the wire alongside `reasons`, not instead
    # of it -- schema-valid AND matches the Python-side CoverageReport.
    sources = doc["result"]["coverage"]["sources"]
    assert sources["threads"] == {"state": "present", "record_count": 1, "detail": None}
    assert sources["thread_info"] == {"state": "absent", "record_count": None, "detail": None}
    limitations = doc["result"]["coverage"]["limitations"]
    assert [l["code"] for l in limitations] == ["SOURCE_ABSENT", "MODULE_CLASSIFICATION_UNAVAILABLE"]
    assert limitations[0]["source"] == "thread_info"


def test_threads_empty_validates(validator):
    result = collect_threads(FakeMF())
    _validate(validator, result)


# ── sysinfo ────────────────────────────────────────────────────────────
# issue #41 changed collect_sysinfo()'s live SysInfoRecord shape ahead of
# the v2.13 schema cutover #43 now performs -- these two tests were xfail
# (CURRENT_SCHEMA still froze the OLD sysInfoRecord shape) until this
# commit; see tests/unit/test_record_schema_alignment.py's own dropped
# xfail marker for the equivalent field-set-only pin.

def test_sysinfo_normal_validates(validator):
    mf = FakeMF()
    mf.sysinfo = SysInfo()
    mf.misc_info = MiscInfo(process_id=1234)
    mf.peb = Peb(0x140000000, r"C:\test.exe", current_directory=r"C:\work")
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    mf.modules = FakeStream([Module(0, 0, "a")], "modules")
    wire_environment_walk(mf, b"\x00\x00\x00\x00")   # verified-empty environment block
    result = collect_sysinfo(mf)
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "complete"


def test_sysinfo_partial_missing_streams_validates(validator):
    result = collect_sysinfo(FakeMF())
    assert result.coverage.status == "partial"
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["reasons"]


def test_sysinfo_environment_variable_entry_with_an_extra_key_is_rejected(validator):
    doc = _minimal_valid_doc(kind="sysinfo")
    doc["result"]["data"]["records"] = [{
        "dump_file": None, "dump_file_size_bytes": None, "dump_sha256": None,
        "dump_time_utc": None, "hostname": None, "username": None, "os": None,
        "os_version": None, "architecture": None, "product_type": None,
        "processors": None, "cpu_vendor": None, "cpu_current_mhz": None,
        "cpu_max_mhz": None, "thread_count": None, "module_count": None,
        "current_directory": None,
        "environment_variables": [{"name": "A", "value": "1", "extra_key": "x"}]}]
    assert not validator.is_valid(doc)


# ── process (--process, issues #40/#43 -- replaces v2.12's pid/peb) ─────

def test_process_complete_with_imports_and_verbose_peb_extended_validates(validator):
    # Reuses test_process_cmd.py's own fully-populated fixture (one named
    # IAT import, PEB/MiscInfo/ModuleList all present and agreeing) --
    # exercises importEntryRecord, iatRecord, and identity_evidence's own
    # nested misc_info_claim/peb_claim/module_claim/main_image_pe shapes
    # against the real ProcessRecord.to_dict() output, not a hand-shaped
    # stand-in. --verbose also populates the schema's one optional
    # property, peb_extended.
    mf = _process_complete_mf()
    result = collect_process(mf, verbose=True)
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "complete"
    record = doc["result"]["data"]["records"][0]
    assert record["iat"]["entries"][0]["dll"] == "KERNEL32.dll"
    assert record["identity_evidence"]["module_claim"]["match_state"] == "resolved"
    assert record["peb_extended"] is not None


def test_process_empty_dump_still_returns_one_all_null_record_and_validates(validator):
    # §3: --process always emits exactly one record, even when every
    # scalar field (and the optional peb_extended key) is absent/null.
    result = collect_process(FakeMF())
    assert result.coverage.status == "not_evaluated"
    doc = _validate(validator, result)
    record = doc["result"]["data"]["records"][0]
    assert record["process_name"] is None
    assert "peb_extended" not in record


def test_process_peb_module_base_conflict_diagnostic_validates(validator):
    # Exercises identity_evidence.diagnostics[] (processDiagnosticRecord)
    # with a real PROCESS_MODULE_BASE_CONFLICT entry -- the PEB and module
    # claims disagree on base address but neither overwrites the other
    # (§3.3.4), and the diagnostic's severity stays in the info/warning
    # vocabulary the schema enforces.
    from tests.unit.test_process_cmd import _mf as _process_mf, _build_valid_image_no_imports, IMAGE_BASE
    misc = MiscInfo(process_id=4242, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\Samples\malware.exe", command_line=r"C:\Samples\malware.exe")
    other_base = 0x00007ff700000000
    mod = Module(other_base, 0x6000, r"C:\Windows\Temp\malware.exe")
    mf = _process_mf(misc_info=misc, peb=peb, modules=[mod], memory=_build_valid_image_no_imports())
    result = collect_process(mf)
    doc = _validate(validator, result)
    diagnostics = doc["result"]["data"]["records"][0]["identity_evidence"]["diagnostics"]
    assert any(d["code"] == "PROCESS_MODULE_BASE_CONFLICT" for d in diagnostics)
    assert all(d["severity"] in ("info", "warning") for d in diagnostics)


# ── handles (--handles, issues #42/#43) ─────────────────────────────────

def test_handles_populated_validates(validator):
    mf = FakeMF()
    mf.handles = FakeStream(
        [Handle(0x10, "File", r"\Device\HarddiskVolume1\notes.txt")], "handles")
    result = collect_handles(mf)
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "complete"
    assert doc["result"]["data"]["records"][0]["handle"] == "0x0000000000000010"


def test_handles_present_empty_stream_validates(validator):
    # A present-but-empty HandleDataStream is complete with zero records
    # (§5.5 case 4), not a failure -- FakeStream([], "handles") gives a
    # parsed object whose own `.handles` list is empty.
    mf = FakeMF()
    mf.handles = FakeStream([], "handles")
    result = collect_handles(mf)
    assert result.coverage.status == "complete"
    doc = _validate(validator, result)
    assert doc["result"]["data"]["records"] == []


def test_handles_absent_stream_is_not_evaluated_and_validates(validator):
    result = collect_handles(FakeMF())
    assert result.coverage.status == "not_evaluated"
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["reasons"]


# ── profile (--profile, issue #95/#43 -- issue #95's own evidence-       │
#    capability map, never a verdict) ────────────────────────────────────

def test_profile_fully_populated_every_capability_available_validates(validator):
    # Reuses test_profile_cmd.py's own fully-populated fixture -- every
    # one of the six frozen capability ids reaches "available" with zero
    # limitations, exercising profileCapabilityEntry's "available implies
    # no limitations" schema rule against real collector output.
    from minidump.constants import MINIDUMP_STREAM_TYPE, MINIDUMP_TYPE
    from tests.unit.test_profile_cmd import _mf as _profile_mf, _Directory
    mf = _profile_mf(
        flags=MINIDUMP_TYPE.MiniDumpWithFullMemory.value,
        directories=[
            _Directory(MINIDUMP_STREAM_TYPE.SystemInfoStream),
            _Directory(MINIDUMP_STREAM_TYPE.ModuleListStream),
            _Directory(MINIDUMP_STREAM_TYPE.ThreadListStream),
            _Directory(MINIDUMP_STREAM_TYPE.ThreadInfoListStream),
            _Directory(MINIDUMP_STREAM_TYPE.MemoryInfoListStream),
            _Directory(MINIDUMP_STREAM_TYPE.Memory64ListStream),
            _Directory(MINIDUMP_STREAM_TYPE.HandleDataStream),
        ],
        sysinfo=SysInfo(),
        modules=FakeStream([Module(0x1000, 0x1000, "a.dll")], "modules"),
        threads=FakeStream([Thread(1, Ctx(0x1000))], "threads"),
        thread_info=FakeStream([object()], "infos"),
        memory_info=FakeStream([object()], "infos"),
        memory_segments_64=FakeStream([object()], "memory_segments"),
        handles=FakeStream([Handle(0x10, "File", r"\Device\x")], "handles"),
    )
    result = collect_profile(mf)
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "complete"
    for entry in doc["result"]["data"]["records"][0]["capabilities"]:
        assert entry["status"] == "available"
        assert entry["limitations"] == []


def test_profile_successfully_profiled_sparse_dump_stays_complete_with_unavailable_capabilities_validates(
        validator):
    # #95's own explicit acceptance case: a successfully profiled sparse
    # dump validates and exits 0 while one or more downstream capabilities
    # remain unavailable -- coverage.status must not be dragged down by a
    # capability gap.
    from tests.unit.test_profile_cmd import _mf as _profile_mf
    result = collect_profile(_profile_mf(flags=0, directories=[], sysinfo=SysInfo()))
    assert result.coverage.status == "complete"
    doc = _validate(validator, result)
    capabilities = doc["result"]["data"]["records"][0]["capabilities"]
    assert any(c["status"] == "unavailable" for c in capabilities)
    for entry in capabilities:
        if entry["status"] == "unavailable":
            assert any(l["code"].startswith("REQUIRED_SOURCE_") for l in entry["limitations"])


def test_profile_no_defensible_profile_is_not_evaluated_and_validates(validator):
    from tests.unit.test_profile_cmd import _mf as _profile_mf
    result = collect_profile(_profile_mf(header=False))
    assert result.records == []
    assert result.coverage.status == "not_evaluated"
    doc = _validate(validator, result)
    assert doc["result"]["data"]["records"] == []


# ── negative cases: documents that MUST fail schema validation ───────────
# The schema being internally well-formed and every REAL collect_*() output
# validating is necessary but not sufficient -- these prove the schema
# actually rejects the malformed shapes it claims to guard against, not
# just "happens to accept everything real code produces."

def _minimal_valid_doc(kind="modules"):
    return {
        "meta": {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "dumpex", "version": dumpex.__version__},
            "execution": {"started_at": "x", "finished_at": "x", "duration_seconds": 0.1,
                          "command": kind, "options": {}},
            "evidence": [{"id": "primary", "role": "primary"}],
        },
        "result": {
            "kind": kind,
            "execution_status": "completed",
            "coverage": {"status": "complete", "reasons": []},
            "summary": {"count": 1},
            "data": {"records": [_minimal_module_record()]},
        },
    }


def _minimal_module_record():
    return {"name": "a.dll", "full_path": None, "base_address": "0x0000000000001000",
            "end_address": "0x0000000000002000", "size": 4096, "compiled_utc": None,
            "file_version": None, "checksum": None, "anomaly_flags": []}


def _minimal_thread_record():
    return {"tid": 1, "start_address": None, "backing_module": None, "module_context": None,
            "flags": [], "create_time": None, "exit_time": None, "exit_status": None,
            "kernel_time_100ns": None, "user_time_100ns": None, "suspend_count": None,
            "priority": None, "teb": None}


def _minimal_process_record():
    return {"process_name": None, "pid": None, "process_path": None, "command_line": None,
            "process_start_utc": None, "image_base_address": None,
            "iat": {"table_present": None, "table_va": None, "table_size": None,
                     "import_directory_present": None, "import_directory_va": None,
                     "import_directory_size": None, "has_entries": False, "dll_count": 0,
                     "entry_count": 0, "entries": [], "diagnostics": []},
            "identity_evidence": {
                "misc_info_claim": {"pid": None, "process_create_time_utc": None,
                                     "raw_pid": None, "raw_process_create_time": None},
                "peb_claim": {"image_base_address": None, "image_path": None, "name": None,
                              "raw_image_base_address": None, "raw_image_path": None,
                              "raw_command_line": None},
                "module_claim": {"match_state": "unavailable", "base_address": None,
                                  "name": None, "path": None, "name_matched_candidate": None,
                                  "name_matched_candidate_ambiguous": False},
                "main_image_pe": {"checked": False, "valid": None, "reason": None},
                "selected_path_source": None, "diagnostics": []}}


def _minimal_handle_record():
    return {"handle": "0x0000000000000010", "type_name": None, "type_name_status": "unnamed",
            "object_name": None, "object_name_status": "unnamed", "attributes": None,
            "granted_access": None, "handle_count": None, "pointer_count": None}


def test_dropped_required_field_is_rejected(validator):
    doc = _minimal_valid_doc()
    del doc["result"]["data"]["records"][0]["checksum"]
    assert not validator.is_valid(doc)


def test_variable_width_hex_address_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["data"]["records"][0]["base_address"] = "0x1000"   # not zero-padded to 16 digits
    assert not validator.is_valid(doc)


# ── profile capability status/limitations cross-field rules ──────────────
# Mirrors dumpex.output.records.ProfileCapabilityEntry.__post_init__'s own
# status<->limitations cross-checks (§4.3 of docs/developer/recon_profile_contract.md)
# in the schema itself, not just in the Python model that happens to be the
# only current producer -- a hand-built or third-party document making the
# same claim must be rejected too.

def _capability(**overrides):
    base = {"capability_id": "handle_analysis", "status": "unavailable",
            "required_source_groups": [["handles"]], "required_sources": ["handles"],
            "optional_sources": [], "limitations": [
                {"code": "REQUIRED_SOURCE_ABSENT", "source": "handles",
                 "detail": "HandleDataStream is not present in this dump"}]}
    base.update(overrides)
    return base


def test_capability_available_with_nonempty_limitations_is_rejected(profile_capability_entry_schema):
    doc = _capability(status="available")   # limitations left non-empty -- contradiction
    assert not profile_capability_entry_schema.is_valid(doc)


def test_capability_unavailable_with_no_limitations_is_rejected(profile_capability_entry_schema):
    # The exact illegal shape a real ProfileCapabilityEntry() construction
    # already refuses: "unavailable" with nothing explaining why.
    doc = _capability(status="unavailable", limitations=[])
    assert not profile_capability_entry_schema.is_valid(doc)


def test_capability_unavailable_with_only_optional_gap_is_rejected(profile_capability_entry_schema):
    # A capability cannot be "unavailable" over a merely optional gap --
    # that's REQUIRED_SOURCE_* territory.
    doc = _capability(status="unavailable", limitations=[
        {"code": "OPTIONAL_SOURCE_ABSENT", "source": "threads", "detail": "threads is optional"}])
    assert not profile_capability_entry_schema.is_valid(doc)


def test_capability_limited_with_no_limitations_is_rejected(profile_capability_entry_schema):
    doc = _capability(status="limited", limitations=[])
    assert not profile_capability_entry_schema.is_valid(doc)


def test_capability_limited_with_a_blocking_required_source_gap_is_rejected(profile_capability_entry_schema):
    # A REQUIRED_SOURCE_* gap makes the capability unavailable, never
    # merely "limited" -- "limited" is reserved for a satisfied-but-
    # degraded evidence set (group-member/optional/truncated gaps).
    doc = _capability(status="limited", limitations=[
        {"code": "REQUIRED_SOURCE_ABSENT", "source": "handles",
         "detail": "HandleDataStream is not present in this dump"}])
    assert not profile_capability_entry_schema.is_valid(doc)


def test_capability_limited_with_a_genuine_degraded_gap_validates(profile_capability_entry_schema):
    doc = _capability(status="limited", limitations=[
        {"code": "OPTIONAL_SOURCE_ABSENT", "source": "threads", "detail": "threads is optional"}])
    assert profile_capability_entry_schema.is_valid(doc)


def test_capability_unavailable_with_a_real_required_source_gap_validates(profile_capability_entry_schema):
    assert profile_capability_entry_schema.is_valid(_capability())


# ── per-capability limitation cross-field rules ───────────────────────────
# The generic $defs/profileCapabilityEntry above cannot know which sources
# a given capability_id actually owns, so its own status<->limitations
# rules stop short of source-level enforcement -- that lives in each of
# the six per-capability $defs instead (profileCapabilityThreadAnalysis,
# ...), which additionally close `limitations[*].source` to that
# capability's own known sources, forbid a source from appearing twice,
# and pair each limitation code's family (REQUIRED_SOURCE_*/
# REQUIRED_GROUP_MEMBER_*/OPTIONAL_SOURCE_*) to whether its source is a
# required-group member or purely optional -- mirroring
# ProfileCapabilityEntry.__post_init__'s own per-instance checks.

def test_multi_member_group_partially_blocked_unavailable_is_rejected(capability_thread_analysis_schema):
    # thread_analysis's own required group is ("threads", "thread_info") --
    # only "threads" carries a REQUIRED_SOURCE_* limitation, "thread_info"
    # carries none at all, yet status claims "unavailable". A required
    # OR-group is either fully blocked or fully unblocked, never partially.
    doc = {"capability_id": "thread_analysis", "status": "unavailable",
           "required_source_groups": [["threads", "thread_info"]],
           "required_sources": ["threads", "thread_info"], "optional_sources": ["modules"],
           "limitations": [{"code": "REQUIRED_SOURCE_ABSENT", "source": "threads",
                             "detail": "not present"}]}
    assert not capability_thread_analysis_schema.is_valid(doc)


def test_multi_member_group_fully_blocked_unavailable_validates(capability_thread_analysis_schema):
    doc = {"capability_id": "thread_analysis", "status": "unavailable",
           "required_source_groups": [["threads", "thread_info"]],
           "required_sources": ["threads", "thread_info"], "optional_sources": ["modules"],
           "limitations": [{"code": "REQUIRED_SOURCE_ABSENT", "source": "threads",
                             "detail": "not present"},
                            {"code": "REQUIRED_SOURCE_FAILED", "source": "thread_info",
                             "detail": "could not be parsed"}]}
    assert capability_thread_analysis_schema.is_valid(doc)


def test_nonexistent_source_name_is_rejected(capability_handle_analysis_schema):
    doc = {"capability_id": "handle_analysis", "status": "unavailable",
           "required_source_groups": [["handles"]], "required_sources": ["handles"],
           "optional_sources": [],
           "limitations": [{"code": "REQUIRED_SOURCE_ABSENT", "source": "totally_wrong",
                             "detail": "not present"}]}
    assert not capability_handle_analysis_schema.is_valid(doc)


def test_same_source_with_two_contradictory_codes_is_rejected(capability_handle_analysis_schema):
    doc = {"capability_id": "handle_analysis", "status": "unavailable",
           "required_source_groups": [["handles"]], "required_sources": ["handles"],
           "optional_sources": [],
           "limitations": [{"code": "REQUIRED_SOURCE_ABSENT", "source": "handles", "detail": "x"},
                            {"code": "REQUIRED_SOURCE_FAILED", "source": "handles", "detail": "y"}]}
    assert not capability_handle_analysis_schema.is_valid(doc)


def test_optional_source_code_used_on_a_required_source_is_rejected(capability_thread_analysis_schema):
    # OPTIONAL_SOURCE_* asserts "optional corroborating evidence" -- using
    # it on "threads" (a required-group member) would fabricate that claim
    # for a source the registry genuinely requires.
    doc = {"capability_id": "thread_analysis", "status": "limited",
           "required_source_groups": [["threads", "thread_info"]],
           "required_sources": ["threads", "thread_info"], "optional_sources": ["modules"],
           "limitations": [{"code": "OPTIONAL_SOURCE_ABSENT", "source": "threads",
                             "detail": "wrong family"}]}
    assert not capability_thread_analysis_schema.is_valid(doc)


def test_required_source_code_used_on_an_optional_source_is_rejected(capability_thread_analysis_schema):
    doc = {"capability_id": "thread_analysis", "status": "limited",
           "required_source_groups": [["threads", "thread_info"]],
           "required_sources": ["threads", "thread_info"], "optional_sources": ["modules"],
           "limitations": [{"code": "REQUIRED_SOURCE_ABSENT", "source": "modules",
                             "detail": "wrong family"}]}
    assert not capability_thread_analysis_schema.is_valid(doc)


def test_optional_source_code_on_its_own_optional_source_validates(capability_thread_analysis_schema):
    doc = {"capability_id": "thread_analysis", "status": "limited",
           "required_source_groups": [["threads", "thread_info"]],
           "required_sources": ["threads", "thread_info"], "optional_sources": ["modules"],
           "limitations": [{"code": "OPTIONAL_SOURCE_ABSENT", "source": "modules",
                             "detail": "modules is optional"}]}
    assert capability_thread_analysis_schema.is_valid(doc)


def test_required_group_member_code_on_a_single_member_group_is_rejected(capability_handle_analysis_schema):
    # handle_analysis's own required group has exactly one member
    # ("handles") -- REQUIRED_GROUP_MEMBER_* asserts "a DIFFERENT member of
    # this SAME group already satisfies it", which is meaningless (and
    # therefore forbidden) when there is no sibling to make that claim
    # about.
    doc = {"capability_id": "handle_analysis", "status": "limited",
           "required_source_groups": [["handles"]], "required_sources": ["handles"],
           "optional_sources": [],
           "limitations": [{"code": "REQUIRED_GROUP_MEMBER_ABSENT", "source": "handles",
                             "detail": "no sibling exists"}]}
    assert not capability_handle_analysis_schema.is_valid(doc)


def test_required_group_member_code_on_a_multi_member_group_validates(capability_thread_analysis_schema):
    # A genuinely degraded (not blocking) gap: "thread_info" satisfies the
    # group, "threads" is absent but has a sibling that already covers it.
    doc = {"capability_id": "thread_analysis", "status": "limited",
           "required_source_groups": [["threads", "thread_info"]],
           "required_sources": ["threads", "thread_info"], "optional_sources": ["modules"],
           "limitations": [{"code": "REQUIRED_GROUP_MEMBER_ABSENT", "source": "threads",
                             "detail": "thread_info already satisfies this capability"}]}
    assert capability_thread_analysis_schema.is_valid(doc)


def test_no_optional_sources_at_all_rejects_any_optional_code(capability_module_analysis_schema):
    # module_analysis has zero optional_sources -- there is no source an
    # OPTIONAL_SOURCE_* code could legally describe.
    doc = {"capability_id": "module_analysis", "status": "limited",
           "required_source_groups": [["modules"]], "required_sources": ["modules"],
           "optional_sources": [],
           "limitations": [{"code": "OPTIONAL_SOURCE_ABSENT", "source": "modules",
                             "detail": "wrong family for a required source"}]}
    assert not capability_module_analysis_schema.is_valid(doc)


def test_injector_handle_assessment_optional_threads_source_validates(
        capability_injector_handle_assessment_schema):
    doc = {"capability_id": "injector_handle_assessment", "status": "limited",
           "required_source_groups": [["handles"]], "required_sources": ["handles"],
           "optional_sources": ["threads"],
           "limitations": [{"code": "OPTIONAL_SOURCE_ABSENT", "source": "threads",
                             "detail": "threads is optional"}]}
    assert capability_injector_handle_assessment_schema.is_valid(doc)


# ── profile capability registry: frozen six-slot order/identity ──────────
# #95's own six capability ids, each with its own frozen source rule, are
# a closed matrix -- a producer must not be able to repeat, reorder, drop,
# or misattribute a capability's own required/optional sources and still
# validate as a "profile" document.

def _minimal_profile_record(capabilities):
    return {
        "architecture": None, "raw_flags": None, "recognized_flags": [],
        "unrecognized_flag_bits": None,
        "memory_capture": {"full_memory_flag_set": None, "memory64_list_present": False,
                            "memory_list_present": False, "captured_segment_count": None,
                            "captured_bytes_total": None},
        "streams": [], "capabilities": capabilities,
    }


_FROZEN_CAPABILITY_ORDER = (
    ("memory_region_analysis", [["memory_info"]], ["memory_info"], []),
    ("module_analysis", [["modules"]], ["modules"], []),
    ("injection_artifact_analysis", [["memory_info", "thread_info"]],
     ["memory_info", "thread_info"], ["modules", "threads", "memory_content"]),
    ("thread_analysis", [["threads", "thread_info"]], ["threads", "thread_info"], ["modules"]),
    ("handle_analysis", [["handles"]], ["handles"], []),
    ("injector_handle_assessment", [["handles"]], ["handles"], ["threads"]),
)


def _unavailable_entry(capability_id, required_source_groups, required_sources, optional_sources):
    # A required OR-group is either fully blocked or fully unblocked, never
    # partially (ProfileCapabilityEntry.__post_init__'s own rule) -- every
    # member of the FIRST group, not just its first member, needs its own
    # REQUIRED_SOURCE_* limitation for a genuinely "unavailable" capability.
    first_group = required_source_groups[0]
    return {"capability_id": capability_id, "status": "unavailable",
            "required_source_groups": required_source_groups, "required_sources": required_sources,
            "optional_sources": optional_sources,
            "limitations": [{"code": "REQUIRED_SOURCE_ABSENT", "source": name,
                              "detail": "not present in this dump"} for name in first_group]}


def _frozen_capabilities():
    return [_unavailable_entry(*row) for row in _FROZEN_CAPABILITY_ORDER]


def test_correctly_ordered_frozen_capabilities_validates(profile_record_schema):
    doc = _minimal_profile_record(_frozen_capabilities())
    assert profile_record_schema.is_valid(doc)


# ── raw_flags <-> recognized_flags/unrecognized_flag_bits/                │
#    memory_capture.full_memory_flag_set nullability ─────────────────────
# dumpex.commands.profile._decode_flags()/_build_memory_capture() read all
# three of the other fields from the SAME raw_flags is-None branch (a
# truncated header union means nothing was read at all, so nothing can be
# recognized/unaccounted/flag-tested) -- the schema mirrors that.

def test_raw_flags_null_with_nonempty_recognized_flags_is_rejected(profile_record_schema):
    doc = _minimal_profile_record(_frozen_capabilities())
    doc["raw_flags"] = None
    doc["recognized_flags"] = ["MiniDumpWithDataSegs"]
    assert not profile_record_schema.is_valid(doc)


def test_raw_flags_null_with_nonnull_unrecognized_flag_bits_is_rejected(profile_record_schema):
    doc = _minimal_profile_record(_frozen_capabilities())
    doc["raw_flags"] = None
    doc["unrecognized_flag_bits"] = 0
    assert not profile_record_schema.is_valid(doc)


def test_raw_flags_null_with_nonnull_full_memory_flag_set_is_rejected(profile_record_schema):
    doc = _minimal_profile_record(_frozen_capabilities())
    doc["raw_flags"] = None
    doc["memory_capture"]["full_memory_flag_set"] = False
    assert not profile_record_schema.is_valid(doc)


def test_raw_flags_set_with_null_unrecognized_flag_bits_is_rejected(profile_record_schema):
    doc = _minimal_profile_record(_frozen_capabilities())
    doc["raw_flags"] = 2
    doc["unrecognized_flag_bits"] = None
    assert not profile_record_schema.is_valid(doc)


def test_raw_flags_set_with_null_full_memory_flag_set_is_rejected(profile_record_schema):
    doc = _minimal_profile_record(_frozen_capabilities())
    doc["raw_flags"] = 2
    doc["unrecognized_flag_bits"] = 0
    doc["memory_capture"]["full_memory_flag_set"] = None
    assert not profile_record_schema.is_valid(doc)


def test_raw_flags_set_with_all_fields_consistent_validates(profile_record_schema):
    doc = _minimal_profile_record(_frozen_capabilities())
    doc["raw_flags"] = 2
    doc["recognized_flags"] = ["MiniDumpWithDataSegs"]
    doc["unrecognized_flag_bits"] = 0
    doc["memory_capture"]["full_memory_flag_set"] = False
    assert profile_record_schema.is_valid(doc)


def test_unknown_stream_type_and_duplicate_stream_type_entries_validate_and_survive(
        profile_record_schema):
    # docs/developer/recon_profile_contract.md: an unrecognized numeric stream type
    # gets its own row (stream_type_name null) rather than being dropped,
    # and a stream type with 2+ directory entries stays INDETERMINATE
    # rather than being merged/deduplicated -- both must reach the schema
    # as real, separate entries, not be silently discarded on the way to
    # --json.
    doc = _minimal_profile_record(_frozen_capabilities())
    doc["streams"] = [
        {"directory_index": 0, "stream_type_id": 999999, "stream_type_name": None,
         "parser_state": "unparsed", "record_count": None, "detail": None},
        {"directory_index": 1, "stream_type_id": 7, "stream_type_name": "SystemInfoStream",
         "parser_state": "indeterminate", "record_count": None,
         "detail": "duplicate directory entries for this stream type"},
        {"directory_index": 2, "stream_type_id": 7, "stream_type_name": "SystemInfoStream",
         "parser_state": "indeterminate", "record_count": None,
         "detail": "duplicate directory entries for this stream type"},
    ]
    assert profile_record_schema.is_valid(doc)
    # Both duplicate-type rows and the unknown-type row are present, not
    # collapsed -- the schema's own acceptance is only meaningful if the
    # instance we validated actually kept all three.
    assert len(doc["streams"]) == 3
    assert [s["stream_type_id"] for s in doc["streams"]] == [999999, 7, 7]


def test_six_duplicate_capabilities_with_wrong_sources_is_rejected(profile_record_schema):
    bad = {"capability_id": "handle_analysis", "status": "available",
           "required_source_groups": [["totally_wrong"]],
           "required_sources": ["different_wrong_value"],
           "optional_sources": ["also_wrong"], "limitations": []}
    doc = _minimal_profile_record([dict(bad) for _ in range(6)])
    assert not profile_record_schema.is_valid(doc)


def test_capabilities_out_of_order_is_rejected(profile_record_schema):
    caps = _frozen_capabilities()
    caps[0], caps[1] = caps[1], caps[0]   # swap module_analysis/memory_region_analysis
    assert not profile_record_schema.is_valid(_minimal_profile_record(caps))


def test_capabilities_missing_one_slot_is_rejected(profile_record_schema):
    caps = _frozen_capabilities()[:5]   # only 5 of the frozen 6
    assert not profile_record_schema.is_valid(_minimal_profile_record(caps))


def test_capability_with_tampered_required_source_is_rejected(profile_record_schema):
    caps = _frozen_capabilities()
    caps[4] = _unavailable_entry("handle_analysis", [["not_handles"]], ["not_handles"], [])
    assert not profile_record_schema.is_valid(_minimal_profile_record(caps))


def test_capability_with_tampered_optional_source_is_rejected(profile_record_schema):
    caps = _frozen_capabilities()
    entry = dict(caps[2])   # injection_artifact_analysis
    entry["optional_sources"] = ["not_a_real_optional_source"]
    caps[2] = entry
    assert not profile_record_schema.is_valid(_minimal_profile_record(caps))


def test_capability_required_groups_flattening_mismatch_is_rejected(profile_record_schema):
    caps = _frozen_capabilities()
    entry = dict(caps[3])   # thread_analysis: required_sources must equal the flattened groups
    entry["required_sources"] = ["threads"]   # dropped "thread_info"
    caps[3] = entry
    assert not profile_record_schema.is_valid(_minimal_profile_record(caps))


# ── profile stream entry: parser_state <-> record_count/detail ───────────

def test_present_empty_stream_with_nonzero_count_and_detail_is_rejected(profile_stream_entry_schema):
    doc = {"directory_index": 0, "stream_type_id": 7, "stream_type_name": "SystemInfoStream",
           "parser_state": "present_empty", "record_count": 99, "detail": "impossible"}
    assert not profile_stream_entry_schema.is_valid(doc)


def test_unparsed_stream_with_a_count_is_rejected(profile_stream_entry_schema):
    doc = {"directory_index": 0, "stream_type_id": 999999, "stream_type_name": None,
           "parser_state": "unparsed", "record_count": 3, "detail": None}
    assert not profile_stream_entry_schema.is_valid(doc)


def test_failed_stream_without_a_detail_is_rejected(profile_stream_entry_schema):
    doc = {"directory_index": 0, "stream_type_id": 7, "stream_type_name": "SystemInfoStream",
           "parser_state": "failed", "record_count": None, "detail": None}
    assert not profile_stream_entry_schema.is_valid(doc)


def test_indeterminate_stream_with_a_count_is_rejected(profile_stream_entry_schema):
    doc = {"directory_index": 0, "stream_type_id": 7, "stream_type_name": "SystemInfoStream",
           "parser_state": "indeterminate", "record_count": 1, "detail": "duplicate directory entries"}
    assert not profile_stream_entry_schema.is_valid(doc)


def test_correctly_shaped_present_empty_stream_validates(profile_stream_entry_schema):
    doc = {"directory_index": 0, "stream_type_id": 7, "stream_type_name": "SystemInfoStream",
           "parser_state": "present_empty", "record_count": 0, "detail": None}
    assert profile_stream_entry_schema.is_valid(doc)


# ── IAT presence/address/count consistency ────────────────────────────────

def _iat(**overrides):
    base = {"table_present": None, "table_va": None, "table_size": None,
            "import_directory_present": None, "import_directory_va": None,
            "import_directory_size": None, "has_entries": False, "dll_count": 0,
            "entry_count": 0, "entries": [], "diagnostics": []}
    base.update(overrides)
    return base


def test_iat_table_not_present_with_address_and_size_is_rejected(iat_record_schema):
    doc = _iat(table_present=False, table_va="0x0000000000001000", table_size=8)
    assert not iat_record_schema.is_valid(doc)


def test_iat_table_va_without_table_size_is_rejected(iat_record_schema):
    doc = _iat(table_present=True, table_va="0x0000000000001000", table_size=None)
    assert not iat_record_schema.is_valid(doc)


def test_iat_import_directory_not_present_with_address_is_rejected(iat_record_schema):
    doc = _iat(import_directory_present=False, import_directory_va="0x0000000000002000")
    assert not iat_record_schema.is_valid(doc)


def test_iat_import_directory_size_without_va_validates_when_present(iat_record_schema):
    # Contract-approved asymmetry: import_directory_size can legitimately
    # be set while import_directory_va stays null when
    # import_directory_present is True (the RVA's own address arithmetic
    # overflowed, but the declared Size was still recorded).
    doc = _iat(import_directory_present=True, import_directory_va=None, import_directory_size=0x28)
    assert iat_record_schema.is_valid(doc)


def test_iat_has_entries_true_with_zero_entry_count_is_rejected(iat_record_schema):
    doc = _iat(has_entries=True, entry_count=0, entries=[])
    assert not iat_record_schema.is_valid(doc)


def test_iat_has_entries_false_with_nonzero_entry_count_is_rejected(iat_record_schema):
    entry = {"dll": "a.dll", "import_by": "name", "symbol": "X", "ordinal": None,
             "iat_slot_va": "0x0000000000001000", "resolved_target_va": "0x0000000000002000",
             "slot_in_bounds": True}
    doc = _iat(has_entries=False, entry_count=1, entries=[entry])
    assert not iat_record_schema.is_valid(doc)


def test_iat_zero_entries_with_nonempty_entries_array_is_rejected(iat_record_schema):
    entry = {"dll": "a.dll", "import_by": "name", "symbol": "X", "ordinal": None,
             "iat_slot_va": "0x0000000000001000", "resolved_target_va": "0x0000000000002000",
             "slot_in_bounds": True}
    doc = _iat(has_entries=False, entry_count=0, entries=[entry])
    assert not iat_record_schema.is_valid(doc)


# ── processDiagnosticRecord: verdict vocabulary cannot masquerade as a ────
#    Recon diagnostic (§37/§40/§43's frozen "no peb_trusted, no verdict"
#    boundary, enforced at the schema level, not just by Python discipline)

def test_fabricated_peb_trusted_verdict_diagnostic_is_rejected(process_diagnostic_record_schema):
    # The exact payload a producer could otherwise use to smuggle a
    # verdict/confidence/ATT&CK/reconstructed-address claim into a Recon
    # diagnostic under a plausible-looking but non-frozen code.
    doc = {"code": "PEB_TRUSTED", "severity": "info", "message": "peb verified authentic",
           "affected_count": None,
           "details": {"peb_trusted": True, "confidence": 0.98, "verdict": "malicious",
                       "reconstructed_image_base": "0x0000000140000000", "attck": "T1055"}}
    assert not process_diagnostic_record_schema.is_valid(doc)


def test_diagnostic_code_outside_the_frozen_seven_is_rejected(process_diagnostic_record_schema):
    doc = {"code": "PROCESS_SOMETHING_MADE_UP", "severity": "info", "message": "x",
           "affected_count": None, "details": {}}
    assert not process_diagnostic_record_schema.is_valid(doc)


def test_diagnostic_severity_outside_info_warning_is_rejected(process_diagnostic_record_schema):
    doc = {"code": "PROCESS_MODULE_BASE_UNMATCHED", "severity": "critical",
           "message": "x", "affected_count": None, "details": {"peb_base": None}}
    assert not process_diagnostic_record_schema.is_valid(doc)


def test_diagnostic_details_with_an_extra_key_is_rejected(process_diagnostic_record_schema):
    # additionalProperties: false per code -- a legitimate code cannot be
    # used to smuggle an extra, unrelated key into details either.
    doc = {"code": "PROCESS_MODULE_BASE_UNMATCHED", "severity": "info", "message": "x",
           "affected_count": None, "details": {"peb_base": None, "verdict": "malicious"}}
    assert not process_diagnostic_record_schema.is_valid(doc)


def test_diagnostic_details_missing_the_required_key_is_rejected(process_diagnostic_record_schema):
    doc = {"code": "PROCESS_MODULE_BASE_UNMATCHED", "severity": "info", "message": "x",
           "affected_count": None, "details": {}}
    assert not process_diagnostic_record_schema.is_valid(doc)


@pytest.mark.parametrize("code,details", [
    ("PROCESS_MODULE_BASE_UNMATCHED", {"peb_base": "0x0000000140000000"}),
    ("PROCESS_MODULE_BASE_CONFLICT", {"name": "a.exe", "module_base": "0x0000000140010000",
                                       "peb_base": "0x0000000140000000"}),
    ("PROCESS_MODULE_NAME_AMBIGUOUS", {"name": "a.exe", "count": 2}),
    ("PROCESS_MODULE_IDENTITY_MISMATCH", {"peb_name": "a.exe", "module_name": "b.exe"}),
    ("PROCESS_PATH_SOURCE_FALLBACK", {"module_path": r"C:\a.exe"}),
    ("IAT_BOUNDS_CHECK_UNAVAILABLE", {"import_directory_va": None}),
    ("IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS", {"table_va": "0x0000000140001000", "table_size": 40,
                                           "first_out_of_bounds_slot_va": "0x0000000140002000"}),
])
def test_each_frozen_diagnostic_code_validates_with_its_own_details_shape(
        process_diagnostic_record_schema, code, details):
    doc = {"code": code, "severity": "info", "message": "x", "affected_count": None,
           "details": details}
    assert process_diagnostic_record_schema.is_valid(doc)


# ── importEntryRecord: import_by <-> symbol/ordinal pairing ──────────────

def _import_entry(**overrides):
    base = {"dll": "a.dll", "import_by": "name", "symbol": "CreateFileW", "ordinal": None,
            "iat_slot_va": "0x0000000000001000", "resolved_target_va": "0x0000000000002000",
            "slot_in_bounds": True}
    base.update(overrides)
    return base


def test_import_by_name_with_a_nonnull_ordinal_is_rejected(import_entry_record_schema):
    doc = _import_entry(import_by="name", symbol="CreateFileW", ordinal=7)
    assert not import_entry_record_schema.is_valid(doc)


def test_import_by_ordinal_with_a_nonnull_symbol_is_rejected(import_entry_record_schema):
    doc = _import_entry(import_by="ordinal", symbol="CreateFileW", ordinal=7)
    assert not import_entry_record_schema.is_valid(doc)


def test_import_by_ordinal_with_a_null_ordinal_is_rejected(import_entry_record_schema):
    # §3.5.3: an ordinal is decoded directly from the already-captured
    # thunk value -- there is no "ordinal read failed" case, unlike symbol.
    doc = _import_entry(import_by="ordinal", symbol=None, ordinal=None)
    assert not import_entry_record_schema.is_valid(doc)


def test_import_by_unavailable_with_a_symbol_is_rejected(import_entry_record_schema):
    doc = _import_entry(import_by="unavailable", symbol="CreateFileW", ordinal=None)
    assert not import_entry_record_schema.is_valid(doc)


def test_import_by_name_entry_validates(import_entry_record_schema):
    assert import_entry_record_schema.is_valid(_import_entry())


def test_import_by_ordinal_entry_validates(import_entry_record_schema):
    doc = _import_entry(import_by="ordinal", symbol=None, ordinal=7)
    assert import_entry_record_schema.is_valid(doc)


# ── handleRecord: name value <-> name status pairing, malformed handles ──

def _handle(**overrides):
    base = {"handle": "0x0000000000000010", "type_name": "File", "type_name_status": "ok",
            "object_name": r"\Device\HarddiskVolume1\x", "object_name_status": "ok",
            "attributes": 0x40, "granted_access": 0x12019f, "handle_count": 1, "pointer_count": 1}
    base.update(overrides)
    return base


def test_handle_ok_status_with_a_null_name_is_rejected(handle_record_schema):
    doc = _handle(type_name=None, type_name_status="ok")
    assert not handle_record_schema.is_valid(doc)


def test_handle_unnamed_status_with_a_nonnull_name_is_rejected(handle_record_schema):
    doc = _handle(type_name="File", type_name_status="unnamed")
    assert not handle_record_schema.is_valid(doc)


def test_handle_unreadable_status_with_a_nonnull_object_name_is_rejected(handle_record_schema):
    doc = _handle(object_name=r"\Device\x", object_name_status="unreadable")
    assert not handle_record_schema.is_valid(doc)


def test_handle_value_null_is_rejected(handle_record_schema):
    doc = _handle(handle=None)
    assert not handle_record_schema.is_valid(doc)


def test_handle_value_variable_width_is_rejected(handle_record_schema):
    doc = _handle(handle="0x10")   # not zero-padded to 16 digits
    assert not handle_record_schema.is_valid(doc)


def test_handle_negative_attributes_is_rejected(handle_record_schema):
    doc = _handle(attributes=-1)
    assert not handle_record_schema.is_valid(doc)


def test_well_formed_handle_validates(handle_record_schema):
    assert handle_record_schema.is_valid(_handle())


def test_uppercase_hex_address_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["data"]["records"][0]["base_address"] = "0X0000000000001000"
    assert not validator.is_valid(doc)


def test_size_as_string_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["data"]["records"][0]["size"] = "4096"
    assert not validator.is_valid(doc)


def test_tid_as_string_is_rejected(validator):
    doc = _minimal_valid_doc(kind="threads")
    doc["result"]["data"]["records"] = [_minimal_thread_record()]
    doc["result"]["data"]["records"][0]["tid"] = "1"
    assert not validator.is_valid(doc)


def test_thread_fields_in_a_modules_record_is_rejected(validator):
    # Cross-kind contamination: a thread-shaped record where a
    # modules-shaped one is required by result.kind.
    doc = _minimal_valid_doc(kind="modules")
    doc["result"]["data"]["records"] = [_minimal_thread_record()]
    assert not validator.is_valid(doc)


def test_a_handle_record_in_a_process_result_is_rejected(validator):
    doc = _minimal_valid_doc(kind="process")
    doc["result"]["data"]["records"] = [_minimal_handle_record()]
    assert not validator.is_valid(doc)


def test_a_process_record_in_a_handles_result_is_rejected(validator):
    doc = _minimal_valid_doc(kind="handles")
    doc["result"]["data"]["records"] = [_minimal_process_record()]
    assert not validator.is_valid(doc)


def test_a_module_record_in_a_profile_result_is_rejected(validator):
    doc = _minimal_valid_doc(kind="profile")
    doc["result"]["data"]["records"] = [_minimal_module_record()]
    assert not validator.is_valid(doc)


def test_a_well_formed_process_record_validates(validator):
    doc = _minimal_valid_doc(kind="process")
    doc["result"]["data"]["records"] = [_minimal_process_record()]
    assert validator.is_valid(doc)


def test_a_well_formed_handle_record_in_a_handles_result_validates(validator):
    doc = _minimal_valid_doc(kind="handles")
    doc["result"]["data"]["records"] = [_minimal_handle_record()]
    assert validator.is_valid(doc)


def test_unknown_extra_field_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["data"]["records"][0]["totally_unexpected_field"] = "x"
    assert not validator.is_valid(doc)


def test_invalid_module_context_enum_value_is_rejected(validator):
    doc = _minimal_valid_doc(kind="threads")
    rec = _minimal_thread_record()
    rec["module_context"] = "definitely_not_a_valid_value"
    doc["result"]["data"]["records"] = [rec]
    assert not validator.is_valid(doc)


def test_limitation_missing_required_source_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["coverage"]["limitations"] = [{"code": "SOURCE_ABSENT"}]   # no `source`
    assert not validator.is_valid(doc)


def test_limitation_unknown_extra_field_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["coverage"]["limitations"] = [
        {"code": "SOURCE_ABSENT", "source": "modules", "totally_unexpected_field": "x"}]
    assert not validator.is_valid(doc)


def test_source_observation_invalid_state_is_rejected(validator):
    doc = _minimal_valid_doc()
    doc["result"]["coverage"]["sources"] = {"modules": {"state": "not_a_real_state"}}
    assert not validator.is_valid(doc)


# ── Python model <-> JSON Schema alignment ───────────────────────────────
# The Python dataclasses (SourceObservation/CoverageLimitation) and the
# JSON Schema fragments they're supposed to produce ($defs/sourceObservation,
# $defs/coverageLimitation) are two independent descriptions of the same
# shape -- nothing forces them to agree just because both exist. These
# tests close that gap from both directions where the schema CAN express
# the same rule: every real to_dict() output must validate, and the
# domain-invalid shapes the Python model itself refuses to construct
# must ALSO be rejected by the schema directly (in case some future
# producer builds the JSON without going through these classes at all).
#
# This is NOT full parity, and no test here claims otherwise: standard
# JSON Schema cannot express "these two field VALUES must differ"
# (CoverageLimitation's source != counterpart_source) or a check against
# a DIFFERENT object entirely outside this fragment (counterpart_source's
# own record_count in result.coverage.sources, a sibling key the
# coverageLimitation fragment never sees in isolation) -- those stay
# Python-only, enforced in CoverageLimitation.__post_init__ and
# _validate_source_absent_against_sources, with their own dedicated unit
# tests in test_output_coverage.py instead of here.

@pytest.mark.parametrize("state,record_count", [
    ("absent", None), ("failed", None), ("present_empty", 0), ("present", 1), ("present", 5),
])
def test_source_observation_to_dict_validates_for_every_state(
        state, record_count, source_observation_schema):
    obs = SourceObservation(name="x", state=state, record_count=record_count)
    jsonschema.validate(obs.to_dict(), source_observation_schema)


@pytest.mark.parametrize("doc", [
    {"state": "present", "record_count": 0, "detail": None},        # present must be >= 1
    {"state": "absent", "record_count": 3, "detail": None},         # absent must be null
    {"state": "present", "record_count": True, "detail": None},     # bool, not a real int
    {"state": "present_empty", "record_count": False, "detail": None},  # bool, not a real int
    {"state": "present_empty", "record_count": 1, "detail": None},  # present_empty must be exactly 0
    {"state": "modules"},                                            # missing record_count/detail
])
def test_source_observation_domain_invalid_shapes_rejected_by_schema(
        doc, source_observation_schema):
    assert not jsonschema.Draft202012Validator(source_observation_schema).is_valid(doc)


@pytest.mark.parametrize("code,kwargs", [
    (LimitationCode.SOURCE_ABSENT, dict(source="modules", scope="dump")),
    (LimitationCode.SOURCE_FAILED, dict(source="modules", scope="dump", detail="boom")),
    (LimitationCode.SOURCE_GROUP_ABSENT,
     dict(source="threads", scope="dump", related_sources=["threads", "thread_info"])),
    (LimitationCode.PID_THREAD_LIST_FALLBACK,
     dict(source="misc_info", counterpart_source="threads", related_tids=[1, 2])),
    (LimitationCode.PID_EXCEPTION_TID_FALLBACK, dict(source="exception", thread_id=9)),
])
def test_coverage_limitation_to_dict_validates_for_representative_codes(
        code, kwargs, coverage_limitation_schema):
    limitation = CoverageLimitation(code=code, **kwargs)
    jsonschema.validate(limitation.to_dict(), coverage_limitation_schema)


def test_coverage_limitation_minimal_shape_rejected_by_schema(coverage_limitation_schema):
    # Same fact as test_limitation_missing_required_source_is_rejected
    # above, checked directly against the fragment rather than a full
    # envelope -- code/source alone is not enough; every field
    # CoverageLimitation.to_dict() always emits is required.
    doc = {"code": "SOURCE_ABSENT", "source": "modules"}
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


@pytest.mark.parametrize("thread_id", [0, -1, True])
def test_coverage_limitation_non_positive_thread_id_rejected_by_schema(
        thread_id, coverage_limitation_schema):
    # The Python model already refuses to construct one of these (see
    # test_output_coverage.py) -- this proves the schema independently
    # rejects the same shape too, in case a future producer builds the
    # JSON without going through CoverageLimitation at all.
    doc = CoverageLimitation(code=LimitationCode.PID_EXCEPTION_TID_FALLBACK,
                              source="exception", thread_id=9).to_dict()
    doc["thread_id"] = thread_id
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


@pytest.mark.parametrize("related_tids", [[0], [-1], [9, True], [9, 0]])
def test_coverage_limitation_non_positive_related_tid_rejected_by_schema(
        related_tids, coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                              counterpart_source="threads", related_tids=[9]).to_dict()
    doc["related_tids"] = related_tids
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


# ── coverageLimitation's per-code allOf/if-then (review round 2/3, P1) ────
# The Python model (CoverageLimitation.__post_init__) already refuses to
# construct a shape where a code's disallowed fields are set, or where a
# code-specific field-shape/dependency rule is violated -- these tests
# prove the schema independently rejects the same shapes too, for a
# hand-built JSON document that never went through the Python model at
# all (the exact scenario the schema is the last line of defense for).
# Each test below isolates exactly ONE violated rule -- bundling several
# wrong fields into one document (as the very first version of these
# tests did) proves only that AT LEAST ONE of them was caught, not that
# each one individually is; a single test with several unrelated invalid
# fields set would still pass even if all but one of the corresponding
# `then` constraints were missing or wrong.

def test_coverage_limitation_pid_no_usable_fallback_wrong_source_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info").to_dict()
    doc["source"] = "modules"
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_no_usable_fallback_nonnull_scope_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info").to_dict()
    doc["scope"] = "module"
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_no_usable_fallback_nonnull_affected_count_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info").to_dict()
    doc["affected_count"] = 7
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_no_usable_fallback_correct_shape_accepted_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info").to_dict()
    jsonschema.validate(doc, coverage_limitation_schema)


def test_coverage_limitation_source_group_absent_single_related_source_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.SOURCE_GROUP_ABSENT, source="a",
                              related_sources=["a", "b"]).to_dict()
    doc["related_sources"] = ["a"]
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_sources_absent_wrong_related_sources_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_SOURCES_ABSENT, source="misc_info",
                              related_sources=["misc_info", "threads", "exception"]).to_dict()
    doc["related_sources"] = ["misc_info", "threads"]
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_thread_list_fallback_missing_counterpart_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                              counterpart_source="threads", related_tids=[1]).to_dict()
    doc["counterpart_source"] = None
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_thread_list_fallback_empty_related_tids_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
                              counterpart_source="threads", related_tids=[1]).to_dict()
    doc["related_tids"] = []
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_pid_exception_tid_fallback_null_thread_id_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.PID_EXCEPTION_TID_FALLBACK, source="exception",
                              thread_id=9).to_dict()
    doc["thread_id"] = None
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_source_absent_count_without_counterpart_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.SOURCE_ABSENT, source="modules").to_dict()
    doc["affected_count"] = 3
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_source_absent_available_without_unavailable_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.SOURCE_ABSENT, source="modules").to_dict()
    doc["available_fields"] = ["TID"]
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_source_absent_available_with_counterpart_rejected_by_schema(
        coverage_limitation_schema):
    # available_fields alongside unavailable_fields alone isn't enough --
    # _render_source_absent branches on counterpart_source FIRST, so
    # available_fields is unused whenever it's set too.
    doc = CoverageLimitation(code=LimitationCode.SOURCE_ABSENT, source="modules",
                              unavailable_fields=["StartAddress"]).to_dict()
    doc["available_fields"] = ["TID"]
    doc["counterpart_source"] = "other"
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_source_failed_with_unavailable_fields_validates(
        coverage_limitation_schema):
    # comparison.py's thread diff customizes a FAILED target.modules with
    # scope="thread" + unavailable_fields (see dumpex.commands.comparison
    # collect_thread_diff) -- the schema must accept this shape, not just
    # the plain no-context SOURCE_FAILED every other producer emits.
    doc = CoverageLimitation(
        code=LimitationCode.SOURCE_FAILED, source="modules", scope="thread", detail="boom",
        unavailable_fields=["backing_module_after", "backing_module_context"]).to_dict()
    jsonschema.validate(doc, coverage_limitation_schema)


def test_coverage_limitation_source_failed_available_without_unavailable_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.SOURCE_FAILED, source="modules").to_dict()
    doc["available_fields"] = ["tid"]
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_source_failed_nonnull_affected_count_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.SOURCE_FAILED, source="modules").to_dict()
    doc["affected_count"] = 3
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


# ── SCAN_REGION_OVERSIZED_SKIPPED source contract (schema_version 2.8) ────
# Mirrors dumpex.output.coverage._SCAN_REGION_OVERSIZED_SKIPPED_SOURCE_
# CONTRACTS at the schema level: for a KNOWN source, both `scope` and
# every targets[*].kind are pinned to what that source's own scan loop
# can actually produce. Without this, the schema would accept a document
# the Python model itself refuses to construct -- e.g. a hand-rolled or
# third-party-produced JSON claiming segment_scan skipped a memory_region,
# which nothing on the wire contract would catch.

def _scan_target(kind, base_address="0x0000000000001000", size=100, size_limit=50):
    return {"kind": kind, "base_address": base_address, "size": size,
            "size_limit": size_limit, "file_offset": None, "allocation_base": None,
            "state": None, "type": None, "protection": None,
            "captured_size": None, "capture_state": None}


def _oversized_skipped_doc(source, scope, kind):
    return {
        "code": "SCAN_REGION_OVERSIZED_SKIPPED", "source": source, "scope": scope,
        "affected_count": 1, "unavailable_fields": [], "available_fields": [],
        "counterpart_source": None, "related_sources": [], "related_tids": [],
        "thread_id": None, "detail": None, "targets": [_scan_target(kind)],
        "budget_limit": None, "budget_consumed": None,
    }


@pytest.mark.parametrize("source,scope,kind", [
    ("pipe_name_scan", None, "memory_region"),
    ("ioc_string_scan", None, "memory_region"),
    ("segment_scan", None, "memory_segment"),
    ("encoding_scan", "sleep_mask", "memory_region"),
    ("encoding_scan", "entropy", "memory_region"),
    ("encoding_scan", "decode", "memory_region"),
])
def test_oversized_skipped_correct_source_scope_kind_combos_validate(
        source, scope, kind, coverage_limitation_validator):
    doc = _oversized_skipped_doc(source, scope, kind)
    assert list(coverage_limitation_validator.iter_errors(doc)) == []


@pytest.mark.parametrize("source,scope,kind", [
    # The exact bug this contract exists to catch: a segment-table source
    # claiming a MemoryInfo region target, and vice versa.
    ("segment_scan", None, "memory_region"),
    ("pipe_name_scan", None, "memory_segment"),
    # encoding_scan requires a real layer scope -- neither unscoped nor a
    # misspelled/unknown layer name is legal.
    ("encoding_scan", None, "memory_region"),
    ("encoding_scan", "sleepmask", "memory_region"),
    # A known source's scope pinned to null must not accept an unrelated
    # non-null value either.
    ("pipe_name_scan", "unexpected", "memory_region"),
    ("segment_scan", "unexpected", "memory_segment"),
    ("ioc_string_scan", None, "memory_segment"),
    ("ioc_string_scan", "unexpected", "memory_region"),
])
def test_oversized_skipped_wrong_source_scope_kind_combos_rejected_by_schema(
        source, scope, kind, coverage_limitation_validator):
    doc = _oversized_skipped_doc(source, scope, kind)
    assert list(coverage_limitation_validator.iter_errors(doc)) != []


def test_oversized_skipped_unknown_source_stays_unconstrained_by_schema(
        coverage_limitation_validator):
    # `source` is an open vocabulary for this code (see LimitationCode's
    # own enum comment) -- a source this schema hasn't been taught about
    # yet must not be rejected just for an unfamiliar scope/kind pairing.
    doc = _oversized_skipped_doc("future_scan", "anything", "memory_segment")
    assert list(coverage_limitation_validator.iter_errors(doc)) == []


def test_coverage_limitation_unknown_future_code_stays_open_in_schema(coverage_limitation_schema):
    # `code` deliberately stays a plain string, not an enum, so a future
    # LimitationCode the schema hasn't been updated for isn't rejected
    # outright -- none of the per-code `if` branches match an unlisted
    # value, so it's validated only against the generic per-field types,
    # same as before this allOf block existed.
    doc = {
        "code": "SOME_FUTURE_CODE", "source": "anything", "scope": "whatever",
        "affected_count": 99, "unavailable_fields": [], "available_fields": [],
        "counterpart_source": None, "related_sources": [], "related_tids": [],
        "thread_id": None, "detail": "free text", "targets": [],
        "budget_limit": None, "budget_consumed": None,
    }
    jsonschema.validate(doc, coverage_limitation_schema)


def test_real_artifact_and_diagnostic_instances_validate_in_full_envelope(validator):
    # Routes real Artifact/Diagnostic instances through the actual
    # CommandResult -> V2Output.set_command_result() -> to_json() path
    # (not a hand-built dict) and validates the WHOLE envelope --
    # confirms the tightened artifact/diagnosticEntry $defs agree with
    # what these two classes' own to_dict() actually produces.
    result = CommandResult(
        kind="modules", records=[],
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        diagnostics=[
            Diagnostic(severity=SEVERITY_WARNING, message="w1", code="W001"),
            Diagnostic(severity=SEVERITY_ERROR, message="e1"),
        ],
        artifacts=[
            Artifact(id="a1", kind="extracted_region", path="region_0x1000.bin",
                     size_bytes=4096, sha256="deadbeef", description="RWX region"),
            Artifact(id="a2", kind="extracted_region", path="region_0x2000.bin"),
        ],
    )
    doc = _validate(validator, result)
    assert doc["artifacts"][0]["kind"] == "extracted_region"
    assert doc["artifacts"][1]["size_bytes"] is None
    assert doc["diagnostics"]["warnings"][0]["code"] == "W001"
    assert doc["diagnostics"]["errors"][0]["code"] is None


def test_sanity_the_minimal_valid_doc_itself_validates(validator):
    # Guards against the negative tests above passing for the wrong
    # reason (a typo elsewhere making _minimal_valid_doc() invalid too).
    assert validator.is_valid(_minimal_valid_doc())
    thread_doc = _minimal_valid_doc(kind="threads")
    thread_doc["result"]["data"]["records"] = [_minimal_thread_record()]
    assert validator.is_valid(thread_doc)


# ── multi-evidence V2Output.from_evidence() (Phase C, PR1) ────────────────
# kind="modules" here deliberately, even though "comparison" is now a
# schema-registered result.kind (PR2) -- the point of this specific test
# is proving the EVIDENCE ARRAY produced by from_evidence() satisfies the
# real schema end to end, independent of which kind is being reported.
# See the "kind == comparison" section below for comparisonRecord's own
# schema coverage.

def test_v2output_from_evidence_full_envelope_validates_against_schema(validator):
    from dumpex.output.envelope import EvidenceInput

    dump_a = _make_dump_file()
    dump_b = _make_dump_file()
    try:
        out = V2Output.from_evidence([
            EvidenceInput(id="baseline", role="baseline", path=dump_a),
            EvidenceInput(id="target", role="target", path=dump_b),
        ], command="modules", options={"verbose": False})
        out.set_command_result(CommandResult(
            kind="modules", records=[], coverage=CoverageReport(status=COVERAGE_COMPLETE)))
        doc = json.loads(out.to_json())
        errors = sorted(validator.iter_errors(doc), key=str)
        assert not errors, "\n".join(str(e) for e in errors)
        assert len(doc["meta"]["evidence"]) == 2
        assert doc["meta"]["evidence"][0]["id"] == "baseline"
        assert doc["meta"]["evidence"][1]["id"] == "target"
    finally:
        os.remove(dump_a)
        os.remove(dump_b)


# ── result.kind == "comparison" (Phase C, PR2) ────────────────────────────

def test_comparison_full_envelope_with_all_three_entity_types_validates(validator):
    from dumpex.output.envelope import EvidenceInput
    from dumpex.commands.comparison import collect_comparison

    mf_baseline = FakeMF()
    mf_baseline.modules = FakeStream([Module(0x1000, 0x1000, r"C:\a.dll")], "modules")
    mf_baseline.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    mf_baseline.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")], "infos")

    mf_target = FakeMF()
    mf_target.modules = FakeStream([Module(0x2000, 0x1000, r"C:\b.dll")], "modules")
    mf_target.thread_info = FakeStream([ThreadInfo(2, 0x2000)], "infos")
    mf_target.memory_info = FakeStream(
        [Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")], "infos")

    result = collect_comparison(mf_baseline, mf_target, mode="all")
    assert result.coverage.status == "complete"

    dump_a = _make_dump_file()
    dump_b = _make_dump_file()
    try:
        out = V2Output.from_evidence([
            EvidenceInput(id="baseline", role="baseline", path=dump_a),
            EvidenceInput(id="target", role="target", path=dump_b),
        ], command="comparison", options={"verbose": False})
        out.set_command_result(result)
        doc = json.loads(out.to_json())
        errors = sorted(validator.iter_errors(doc), key=str)
        assert not errors, "\n".join(str(e) for e in errors)
        entity_types = {r["entity_type"] for r in doc["result"]["data"]["records"]}
        assert entity_types == {"module", "thread", "memory_region"}
        assert doc["result"]["coverage"]["sources"]["baseline.modules"]["state"] == "present"
    finally:
        os.remove(dump_a)
        os.remove(dump_b)


# ── result.kind == "extract" (Phase E, PR1) ───────────────────────────────

def test_extract_full_envelope_with_mz_header_validates(validator, tmp_path):
    import dumpex.commands.extract as extract_mod
    from dumpex.commands.extract import collect_extract

    mf = FakeMF()
    mf.filename = "test.dmp"
    extract_mod.read_region = mem_reader({0x1000: b"MZ" + b"\x90" * 62})
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x1000, 64, out_path, auto_size=False, force=True)
    doc = _validate(validator, result)
    assert doc["result"]["kind"] == "extract"
    assert doc["result"]["coverage"]["status"] == "complete"
    assert doc["artifacts"][0]["kind"] == "extracted_region"
    assert doc["diagnostics"]["warnings"][0]["code"] == "EXTRACT_MZ_HEADER_DETECTED"


def test_extract_short_read_validates_with_region_read_truncated_limitation(validator, tmp_path):
    # P1-4 remediation: a short read must still produce a schema-valid
    # document -- coverage.status becomes "partial" and a
    # REGION_READ_TRUNCATED limitation appears, rather than silently
    # reporting a truncated read as "complete".
    import dumpex.commands.extract as extract_mod
    from dumpex.commands.extract import collect_extract

    mf = FakeMF()
    mf.filename = "test.dmp"
    extract_mod.read_region = mem_reader({0x1000: b"short"})
    out_path = str(tmp_path / "out.bin")
    result = collect_extract(mf, 0x1000, 64, out_path, auto_size=False, force=True)
    doc = _validate(validator, result)
    assert doc["result"]["coverage"]["status"] == "partial"
    assert doc["result"]["data"]["records"][0]["requested_size"] == 64
    assert doc["result"]["data"]["records"][0]["bytes_read"] == 5
    codes = {lim["code"] for lim in doc["result"]["coverage"]["limitations"]}
    assert codes == {"REGION_READ_TRUNCATED"}


# ── result.kind == "strings" (Phase E, PR2) ───────────────────────────────

def test_strings_full_envelope_with_grep_validates(validator):
    import dumpex.commands.extract as extract_mod
    from dumpex.commands.extract import collect_strings

    mf = FakeMF()
    mf.filename = "test.dmp"
    data = b"apple pie recipe" + b"\x00" * 5 + b"cherry tart notes"
    extract_mod.read_region = mem_reader({0x1000: data})
    result = collect_strings(mf, 0x1000, len(data), 6, "recipe", "ascii")
    doc = _validate(validator, result)
    assert doc["result"]["kind"] == "strings"
    assert doc["result"]["coverage"]["status"] == "complete"
    assert doc["result"]["data"]["records"][0]["matched_grep"] is True
    assert doc["result"]["data"]["records"][1]["matched_grep"] is False


def test_strings_empty_result_validates(validator):
    import dumpex.commands.extract as extract_mod
    from dumpex.commands.extract import collect_strings

    mf = FakeMF()
    mf.filename = "test.dmp"
    extract_mod.read_region = mem_reader({0x4000: b"\x01\x02\x03" * 5})
    result = collect_strings(mf, 0x4000, 15, 6, None, "both")
    doc = _validate(validator, result)
    assert doc["result"]["kind"] == "strings"
    assert doc["result"]["data"]["records"] == []
    assert doc["result"]["coverage"]["sources"]["requested_region"]["state"] == "present_empty"


def _minimal_valid_strings_summary():
    return {"count": 0, "shown": 0, "requested_address": "0x0000000000001000",
            "requested_size": 16, "bytes_read": 16, "auto_sized": False}


def _minimal_valid_strings_doc():
    """A genuinely valid kind == "strings" envelope -- unlike the generic
    _minimal_valid_doc(kind="strings"), which stamps `summary={"count":
    1}` (correct for every OTHER kind, but missing stringsSummary's other
    five required fields) and a moduleRecord-shaped `data.records` entry
    (wrong shape for "strings"). Using the generic helper as the base for
    a "records" negative test would mean the document was ALREADY invalid
    before the test even touched the field under test -- the test would
    keep "passing" (finding some schema violation) even if the specific
    constraint it claims to check were silently removed. Every strings-
    kind schema test below must start from THIS helper, then mutate
    exactly the one thing being tested."""
    doc = _minimal_valid_doc(kind="strings")
    doc["result"]["summary"] = _minimal_valid_strings_summary()
    doc["result"]["data"]["records"] = []
    return doc


def test_strings_minimal_valid_summary_passes_schema(validator):
    # Baseline for the negative tests below: proves the "valid" shape
    # really does validate, so a failure in one of them is attributable
    # to the specific mutation, not to some other unrelated defect.
    assert validator.is_valid(_minimal_valid_strings_doc())


def test_strings_summary_missing_requested_address_is_rejected_by_schema(validator):
    # P2 remediation: before stringsSummary existed, result.summary for
    # kind == "strings" was only `{"type": "object"}` -- deleting
    # requested_address entirely (or any of the other five required
    # fields) still validated. This is the exact regression the schema
    # itself must now catch, not just collect_strings()'s own
    # implementation and unit tests.
    doc = _minimal_valid_strings_doc()
    del doc["result"]["summary"]["requested_address"]
    assert not validator.is_valid(doc)


def test_strings_summary_null_requested_address_is_rejected_by_schema(validator):
    doc = _minimal_valid_strings_doc()
    doc["result"]["summary"]["requested_address"] = None
    assert not validator.is_valid(doc)


def test_strings_summary_wrong_type_requested_size_is_rejected_by_schema(validator):
    doc = _minimal_valid_strings_doc()
    doc["result"]["summary"]["requested_size"] = "16"
    assert not validator.is_valid(doc)


def test_strings_summary_missing_count_is_rejected_by_schema(validator):
    doc = _minimal_valid_strings_doc()
    del doc["result"]["summary"]["count"]
    assert not validator.is_valid(doc)


def test_strings_summary_missing_shown_is_rejected_by_schema(validator):
    doc = _minimal_valid_strings_doc()
    del doc["result"]["summary"]["shown"]
    assert not validator.is_valid(doc)


def test_strings_summary_missing_bytes_read_is_rejected_by_schema(validator):
    doc = _minimal_valid_strings_doc()
    del doc["result"]["summary"]["bytes_read"]
    assert not validator.is_valid(doc)


def test_strings_summary_missing_auto_sized_is_rejected_by_schema(validator):
    doc = _minimal_valid_strings_doc()
    del doc["result"]["summary"]["auto_sized"]
    assert not validator.is_valid(doc)


def test_strings_summary_unknown_extra_field_is_rejected_by_schema(validator):
    doc = _minimal_valid_strings_doc()
    doc["result"]["summary"]["totally_unexpected_field"] = "x"
    assert not validator.is_valid(doc)


def test_minimal_valid_string_record_passes_schema(validator):
    # Baseline for the three negative tests below (P2 remediation, round
    # 3): proves a fully valid strings envelope -- valid summary AND a
    # valid stringRecord -- really does validate, so each negative test's
    # failure is attributable to the ONE field it deliberately breaks, not
    # to some other already-invalid part of the base document (see
    # _minimal_valid_strings_doc's own docstring for why the OLD base --
    # _minimal_valid_doc(kind="strings") -- was already invalid on its
    # own, via a missing stringsSummary, before these tests even touched
    # `data.records`).
    doc = _minimal_valid_strings_doc()
    doc["result"]["data"]["records"] = [{
        "offset": 0, "address": "0x0000000000001000", "encoding": "ASCII",
        "text": "x", "matched_grep": None}]
    assert validator.is_valid(doc)


def test_string_record_null_address_is_rejected_by_schema(validator):
    # P2-1 remediation: unlike most hexAddress-typed fields, stringRecord's
    # `address` is never null on the wire (a string is always found at
    # some real address) -- the schema must reject a null there even
    # though hexAddress itself otherwise allows it. Starts from
    # _minimal_valid_strings_doc() (a genuinely valid envelope, including
    # a valid stringsSummary), not the old _minimal_valid_doc(kind=
    # "strings") -- that base was already schema-invalid via a missing
    # stringsSummary, so this test would have kept "passing" (finding
    # SOME violation) even if the address-nullability check were removed.
    doc = _minimal_valid_strings_doc()
    doc["result"]["data"]["records"] = [{
        "offset": 0, "address": None, "encoding": "ASCII", "text": "x", "matched_grep": None}]
    assert not validator.is_valid(doc)


def test_string_record_negative_offset_is_rejected_by_schema(validator):
    doc = _minimal_valid_strings_doc()
    doc["result"]["data"]["records"] = [{
        "offset": -1, "address": "0x0000000000001000", "encoding": "ASCII",
        "text": "x", "matched_grep": None}]
    assert not validator.is_valid(doc)


def test_string_record_unknown_encoding_is_rejected_by_schema(validator):
    doc = _minimal_valid_strings_doc()
    doc["result"]["data"]["records"] = [{
        "offset": 0, "address": "0x0000000000001000", "encoding": "BOGUS",
        "text": "x", "matched_grep": None}]
    assert not validator.is_valid(doc)


def test_extract_record_negative_bytes_read_is_rejected_by_schema(validator):
    doc = _minimal_valid_doc(kind="extract")
    doc["result"]["data"]["records"] = [{
        "requested_address": "0x0000000000001000", "requested_size": 16,
        "auto_sized": False, "bytes_read": -1, "mz_header_detected": False}]
    assert not validator.is_valid(doc)


def test_extract_record_null_requested_address_is_rejected_by_schema(validator):
    # P2 remediation: requested_address is non-nullable on extractRecord --
    # a successful --extract always knows the exact address it read.
    doc = _minimal_valid_doc(kind="extract")
    doc["result"]["data"]["records"] = [{
        "requested_address": None, "requested_size": 16,
        "auto_sized": False, "bytes_read": 16, "mz_header_detected": False}]
    assert not validator.is_valid(doc)


def test_extract_record_null_requested_size_is_rejected_by_schema(validator):
    doc = _minimal_valid_doc(kind="extract")
    doc["result"]["data"]["records"] = [{
        "requested_address": "0x0000000000001000", "requested_size": None,
        "auto_sized": False, "bytes_read": 16, "mz_header_detected": False}]
    assert not validator.is_valid(doc)


def test_strings_kind_is_rejected_by_the_frozen_v2_1_schema(validator_v2_1):
    # dumpex-output-v2.1.schema.json predates "strings" entirely -- proves
    # the frozen historical schema was never silently updated to accept
    # it (same precedent as "extract" and "comparison" above).
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.1"
    doc["result"]["kind"] = "strings"
    doc["result"]["data"]["records"] = []
    assert not validator_v2_1.is_valid(doc)


def test_extract_kind_is_rejected_by_the_frozen_v2_1_schema(validator_v2_1):
    # dumpex-output-v2.1.schema.json predates "extract" entirely -- proves
    # the frozen historical schema was never silently updated to accept
    # it (the whole point of keeping it as its own file, same precedent
    # as v2.0 not accepting "comparison").
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.1"
    doc["result"]["kind"] = "extract"
    doc["result"]["data"]["records"] = []
    assert not validator_v2_1.is_valid(doc)


def test_a_genuine_v2_1_era_document_still_validates_against_the_v2_1_schema(validator_v2_1):
    # The frozen historical schema must keep validating output produced
    # before schema_version 2.2 existed.
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.1"
    assert validator_v2_1.is_valid(doc)


def test_report_kind_is_rejected_by_the_frozen_v2_2_schema(validator_v2_2):
    # RevFix-P1a: dumpex-output-v2.2.schema.json predates "report" entirely
    # -- v2.2 was already shipped/used by extract/strings output before
    # this round's review, so it must stay byte-frozen and never start
    # silently accepting a result.kind it didn't originally define.
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.2"
    doc["result"]["kind"] = "report"
    doc["result"]["data"]["records"] = []
    assert not validator_v2_2.is_valid(doc)


def test_a_genuine_v2_2_era_extract_document_still_validates_against_the_v2_2_schema(
        validator_v2_2):
    # The frozen historical schema must keep validating real extract/
    # strings output produced before schema_version 2.3 existed.
    doc = _minimal_valid_doc(kind="extract")
    doc["meta"]["schema_version"] = "2.2"
    doc["result"]["data"]["records"] = [{
        "requested_address": "0x0000000000001000", "requested_size": 16,
        "auto_sized": False, "bytes_read": 16, "mz_header_detected": False}]
    assert validator_v2_2.is_valid(doc)


def test_hunt_kind_is_rejected_by_the_frozen_v2_3_schema(validator_v2_3):
    # dumpex-output-v2.3.schema.json predates "hunt" entirely -- v2.3 was
    # already shipped/used by report output before the hunt migration's
    # PR3, so it must stay byte-frozen and never start silently accepting
    # a result.kind it didn't originally define (same precedent as the
    # v2.2-rejects-"report" pair above).
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.3"
    doc["result"]["kind"] = "hunt"
    doc["result"]["data"]["records"] = []
    assert not validator_v2_3.is_valid(doc)


def test_a_genuine_v2_3_era_report_document_still_validates_against_the_v2_3_schema(
        validator_v2_3):
    # The frozen historical schema must keep validating real report
    # output produced before schema_version 2.4 existed.
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.3"
    assert validator_v2_3.is_valid(doc)


def test_a_genuine_v2_4_era_document_still_validates_against_the_v2_4_schema(validator_v2_4):
    # v2.5's only actual change is the hunt `finding` $def (see
    # test_json_schema_v2_5_hunt.py) -- no six-recon-command shape
    # changed between v2.4 and v2.5, so a v2.4-era document of any of
    # those kinds must keep validating against the frozen v2.4 schema
    # unchanged.
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.4"
    assert validator_v2_4.is_valid(doc)


def test_a_genuine_v2_5_era_document_still_validates_against_the_v2_5_schema(validator_v2_5):
    # v2.6's only actual change is removing `raw` from `--hunt cs-beacon`'s
    # csBeaconDetails.configs[*].fields[*] (see
    # tests/hunt/test_cs_beacon_collect.py) -- no six-recon-command shape
    # changed between v2.5 and v2.6, so a v2.5-era document of any of
    # those kinds must keep validating against the frozen v2.5 schema
    # unchanged.
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.5"
    assert validator_v2_5.is_valid(doc)


def test_a_genuine_v2_6_era_document_still_validates_against_the_v2_6_schema(validator_v2_6):
    # v2.7's only actual change is re-keying `--hunt cs-beacon`'s
    # csBeaconDetails.configs[*].fields by field NAME instead of numeric
    # ID (see tests/hunt/test_cs_beacon_collect.py) -- no six-recon-command
    # shape changed between v2.6 and v2.7, so a v2.6-era document of any
    # of those kinds must keep validating against the frozen v2.6 schema
    # unchanged.
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.6"
    assert validator_v2_6.is_valid(doc)


def test_a_genuine_v2_7_era_document_still_validates_against_the_v2_7_schema(validator_v2_7):
    # Unlike every earlier version in this chain, v2.8's change (a new
    # `required` `targets` array on the shared `coverageLimitation` $def
    # -- see this file's own module docstring) DOES touch these six
    # recon commands' own shape: a v2.7-era coverageLimitation entry
    # never had a `targets` key at all, so it fails against v2.8 with
    # `'targets' is a required property` (see
    # test_v2_7_era_coverage_limitation_is_rejected_by_v2_8_schema below).
    # `dumpex-output-v2.7.schema.json` stays installed so a genuine
    # v2.7-era document keeps validating against ITS OWN frozen schema.
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.7"
    assert validator_v2_7.is_valid(doc)


def test_v2_7_era_coverage_limitation_is_rejected_by_v2_8_schema(coverage_limitation_schema):
    # The concrete counterpart to the module docstring's claim: a
    # coverageLimitation dict shaped exactly like v2.7 produced it (no
    # `targets` key -- that field didn't exist yet) is NOT accepted by
    # the current (v2.9) schema either -- v2.9 never relaxed v2.8's own
    # `targets` requirement. This is what made THAT version bump
    # necessary rather than cosmetic.
    v27_doc = {
        "code": "SOURCE_ABSENT", "source": "modules", "scope": "dump",
        "affected_count": None, "unavailable_fields": [], "available_fields": [],
        "counterpart_source": None, "related_sources": [], "related_tids": [],
        "thread_id": None, "detail": None,
    }
    assert "targets" not in v27_doc
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(v27_doc)


def test_a_genuine_v2_8_era_document_still_validates_against_the_v2_8_schema(validator_v2_8):
    # v2.9's only actual change is huntSummary.investigation_actions
    # (result.summary for kind == "hunt" only -- see this file's own
    # module docstring and test_json_schema_v2_5_hunt.py) -- no six-recon
    # -command shape changed between v2.8 and v2.9, so a v2.8-era
    # document of any of those kinds must keep validating against the
    # frozen v2.8 schema unchanged.
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.8"
    assert validator_v2_8.is_valid(doc)


def test_a_genuine_v2_9_era_document_still_validates_against_the_v2_9_schema(validator_v2_9):
    # v2.10's only actual change is triageInfo.content_reason_codes (also
    # under huntSummary, for kind == "hunt" only -- see this file's own
    # module docstring and test_json_schema_v2_5_hunt.py) -- no six-recon
    # -command shape changed between v2.9 and v2.10, so a v2.9-era
    # document of any of those kinds must keep validating against the
    # frozen v2.9 schema unchanged.
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.9"
    assert validator_v2_9.is_valid(doc)


# ── v2.12-era pid/peb: frozen and still validatable, and rejected by ─────
#    v2.13 -- #43's own "immediate removal, no hidden deprecation alias"
#    decision (docs/developer/recon_process_sysinfo_handles_contract.md §7.2) means
#    a genuine pre-#43 document must still validate against ITS OWN frozen
#    v2.12 schema, and result.kind == "pid"/"peb" must be rejected by the
#    new v2.13 file that replaced them with "process"/"handles". These
#    records are genuine collector output captured before #43 removed the
#    commands that produced them (frozen here as static JSON rather than
#    re-generated, since collect_pid()/collect_peb() no longer exist to
#    regenerate them from).

_V2_12_ERA_PID_RECORD = {"pid": 4321, "source": "MINIDUMP_MISC_INFO (ProcessId field)",
                          "thread_count": None, "exc_tid": None}

_V2_12_ERA_PEB_RECORD = {"peb_address": "0x0000000000000000",
                          "image_base_address": "0x0000000140000000",
                          "being_debugged": False, "image_path": "C:\\test.exe",
                          "command_line": None, "window_title": None, "dll_path": None,
                          "current_directory": None, "standard_input": None,
                          "standard_output": None, "standard_error": None,
                          "environment_variables": None}


def test_a_genuine_v2_12_era_pid_document_still_validates_against_the_v2_12_schema(validator_v2_12):
    doc = _minimal_valid_doc(kind="pid")
    doc["meta"]["schema_version"] = "2.12"
    doc["result"]["data"]["records"] = [_V2_12_ERA_PID_RECORD]
    assert validator_v2_12.is_valid(doc)


def test_a_genuine_v2_12_era_peb_document_still_validates_against_the_v2_12_schema(validator_v2_12):
    doc = _minimal_valid_doc(kind="peb")
    doc["meta"]["schema_version"] = "2.12"
    doc["result"]["data"]["records"] = [_V2_12_ERA_PEB_RECORD]
    assert validator_v2_12.is_valid(doc)


def test_pid_kind_is_rejected_by_v2_13(validator):
    # v2.13 (issue #43) removed "pid" from result.kind's enum entirely --
    # the same genuine v2.12-era document that just validated above must
    # now be rejected once it claims to be a v2.13 document.
    doc = _minimal_valid_doc(kind="pid")
    doc["result"]["data"]["records"] = [_V2_12_ERA_PID_RECORD]
    assert not validator.is_valid(doc)


def test_peb_kind_is_rejected_by_v2_13(validator):
    doc = _minimal_valid_doc(kind="peb")
    doc["result"]["data"]["records"] = [_V2_12_ERA_PEB_RECORD]
    assert not validator.is_valid(doc)


def test_comparison_kind_is_rejected_by_the_frozen_v2_0_schema(validator_v2_0):
    # dumpex-output-v2.0.schema.json predates "comparison" entirely --
    # proves the frozen historical schema was never silently updated to
    # accept it (the whole point of keeping it as its own file).
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.0"
    doc["result"]["kind"] = "comparison"
    doc["result"]["data"]["records"] = []
    assert not validator_v2_0.is_valid(doc)


def test_a_genuine_v2_0_era_document_still_validates_against_the_v2_0_schema(validator_v2_0):
    # The frozen historical schema must keep validating output produced
    # before schema_version 2.1 existed -- freezing it is only useful if
    # it still actually works for that purpose.
    doc = _minimal_valid_doc(kind="modules")
    doc["meta"]["schema_version"] = "2.0"
    assert validator_v2_0.is_valid(doc)


def test_module_diff_record_added_with_a_before_value_rejected(module_diff_record_schema):
    from dumpex.output.records import ModuleDiffRecord, MODULE_DIFF_ADDED
    doc = ModuleDiffRecord(change_type=MODULE_DIFF_ADDED, name="a.dll",
                            full_path_before=None, full_path_after="C:\\a.dll",
                            base_address_before=None,
                            base_address_after="0x0000000000001000").to_dict()
    doc["full_path_before"] = "C:\\a.dll"   # added must never carry a baseline-side value
    assert not module_diff_record_schema.is_valid(doc)


def test_module_diff_record_rebased_valid_shape_accepted(module_diff_record_schema):
    from dumpex.output.records import ModuleDiffRecord, MODULE_DIFF_REBASED
    doc = ModuleDiffRecord(change_type=MODULE_DIFF_REBASED, name="a.dll",
                            full_path_before="C:\\a.dll", full_path_after="C:\\a.dll",
                            base_address_before="0x0000000000001000",
                            base_address_after="0x0000000000009000").to_dict()
    assert module_diff_record_schema.is_valid(doc)


def test_module_diff_record_anonymous_added_module_accepted(module_diff_record_schema):
    # Regression: an anonymous module (no name at all) has a real
    # base_address but no full_path -- the schema must not require
    # full_path_after to be non-null for "added" (only base_address is
    # the field a module diff actually always has).
    from dumpex.output.records import ModuleDiffRecord, MODULE_DIFF_ADDED
    doc = ModuleDiffRecord(change_type=MODULE_DIFF_ADDED, name="(unnamed)",
                            full_path_before=None, full_path_after=None,
                            base_address_before=None,
                            base_address_after="0x0000000000001000").to_dict()
    assert module_diff_record_schema.is_valid(doc)


def test_thread_diff_record_removed_with_a_backing_module_rejected(thread_diff_record_schema):
    from dumpex.output.records import ThreadDiffRecord, THREAD_DIFF_REMOVED
    doc = ThreadDiffRecord(change_type=THREAD_DIFF_REMOVED, tid=1,
                            start_address_before="0x0000000000001000",
                            start_address_after=None).to_dict()
    doc["backing_module_after"] = "ntdll.dll"   # diff_threads never resolves this for removed
    assert not thread_diff_record_schema.is_valid(doc)


def test_thread_diff_record_added_valid_shape_accepted(thread_diff_record_schema):
    from dumpex.output.records import ThreadDiffRecord, THREAD_DIFF_ADDED
    from dumpex.output.records import MODULE_CONTEXT_UNREGISTERED
    doc = ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                            start_address_before=None,
                            start_address_after="0x0000000000002000",
                            backing_module_after=None,
                            backing_module_context=MODULE_CONTEXT_UNREGISTERED).to_dict()
    assert thread_diff_record_schema.is_valid(doc)


def test_thread_diff_record_resolved_without_backing_module_rejected(thread_diff_record_schema):
    from dumpex.output.records import ThreadDiffRecord, THREAD_DIFF_ADDED, MODULE_CONTEXT_RESOLVED
    doc = ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                            start_address_before=None,
                            start_address_after="0x0000000000001000",
                            backing_module_after="ntdll.dll",
                            backing_module_context=MODULE_CONTEXT_RESOLVED).to_dict()
    doc["backing_module_after"] = None   # resolved must carry a backing module
    assert not thread_diff_record_schema.is_valid(doc)


def test_thread_diff_record_unregistered_with_backing_module_rejected(thread_diff_record_schema):
    from dumpex.output.records import ThreadDiffRecord, THREAD_DIFF_ADDED, MODULE_CONTEXT_UNREGISTERED
    doc = ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                            start_address_before=None,
                            start_address_after="0x0000000000001000",
                            backing_module_after=None,
                            backing_module_context=MODULE_CONTEXT_UNREGISTERED).to_dict()
    doc["backing_module_after"] = "ntdll.dll"   # unregistered must never carry one
    assert not thread_diff_record_schema.is_valid(doc)


def test_thread_diff_record_added_null_address_with_module_context_rejected(
        thread_diff_record_schema):
    from dumpex.output.records import ThreadDiffRecord, THREAD_DIFF_ADDED
    doc = ThreadDiffRecord(change_type=THREAD_DIFF_ADDED, tid=1,
                            start_address_before=None, start_address_after=None).to_dict()
    doc["backing_module_context"] = "unavailable"   # address unknown -- resolution never attempted
    assert not thread_diff_record_schema.is_valid(doc)


def test_thread_diff_record_added_known_address_without_module_context_rejected(
        thread_diff_record_schema):
    from dumpex.output.records import ThreadDiffRecord
    doc = {"entity_type": "thread", "change_type": "added", "tid": 1,
           "start_address_before": None, "start_address_after": "0x0000000000001000",
           "backing_module_after": None, "backing_module_context": None}
    assert not thread_diff_record_schema.is_valid(doc)


def test_memory_diff_record_protection_changed_missing_protect_after_rejected(
        memory_diff_record_schema):
    from dumpex.output.records import MemoryDiffRecord, MEMORY_DIFF_PROTECTION_CHANGED
    doc = MemoryDiffRecord(
        change_type=MEMORY_DIFF_PROTECTION_CHANGED, base_address="0x0000000000001000",
        size_before=4096, size_after=4096,
        protect_before="PAGE_READWRITE", protect_after="PAGE_EXECUTE_READWRITE",
        type_before="MEM_PRIVATE", type_after="MEM_PRIVATE",
        suspicious_before=False, suspicious_after=True).to_dict()
    doc["protect_after"] = None   # protection_changed requires both sides populated
    assert not memory_diff_record_schema.is_valid(doc)


def test_memory_diff_record_added_valid_shape_accepted(memory_diff_record_schema):
    from dumpex.output.records import MemoryDiffRecord, MEMORY_DIFF_ADDED
    doc = MemoryDiffRecord(
        change_type=MEMORY_DIFF_ADDED, base_address="0x0000000000001000",
        size_before=None, size_after=4096,
        protect_before=None, protect_after="PAGE_READWRITE",
        type_before=None, type_after="MEM_PRIVATE",
        suspicious_before=None, suspicious_after=False).to_dict()
    assert memory_diff_record_schema.is_valid(doc)


def test_memory_diff_record_protection_changed_null_suspicious_rejected(memory_diff_record_schema):
    from dumpex.output.records import MemoryDiffRecord, MEMORY_DIFF_PROTECTION_CHANGED
    doc = MemoryDiffRecord(
        change_type=MEMORY_DIFF_PROTECTION_CHANGED, base_address="0x0000000000001000",
        size_before=4096, size_after=4096,
        protect_before="PAGE_READWRITE", protect_after="PAGE_EXECUTE_READWRITE",
        type_before="MEM_PRIVATE", type_after="MEM_PRIVATE",
        suspicious_before=False, suspicious_after=True).to_dict()
    doc["suspicious_before"] = None
    doc["suspicious_after"] = None
    assert not memory_diff_record_schema.is_valid(doc)


# ── empty string "" is never a legitimate stand-in for "no value" ────────
# (Phase C review round 3) -- these optional string fields only gained
# minLength: 1 in this same round, matching the stricter check the Python
# model's own field-shape validators had already started enforcing.

def test_module_diff_record_empty_full_path_rejected_by_schema(module_diff_record_schema):
    doc = {"entity_type": "module", "change_type": "rebased", "name": "a.dll",
           "full_path_before": "", "full_path_after": "x",
           "base_address_before": "0x0000000000001000", "base_address_after": "0x0000000000002000"}
    assert not module_diff_record_schema.is_valid(doc)


def test_thread_diff_record_empty_backing_module_after_rejected_by_schema(thread_diff_record_schema):
    doc = {"entity_type": "thread", "change_type": "added", "tid": 1,
           "start_address_before": None, "start_address_after": "0x0000000000001000",
           "backing_module_after": "", "backing_module_context": "resolved"}
    assert not thread_diff_record_schema.is_valid(doc)


def test_memory_diff_record_empty_protect_rejected_by_schema(memory_diff_record_schema):
    doc = {"entity_type": "memory_region", "change_type": "added", "base_address": "0x0000000000001000",
           "size_before": None, "size_after": 4096,
           "protect_before": None, "protect_after": "",
           "type_before": None, "type_after": "MEM_PRIVATE",
           "suspicious_before": None, "suspicious_after": False}
    assert not memory_diff_record_schema.is_valid(doc)


def test_memory_diff_record_null_base_address_rejected_by_schema(memory_diff_record_schema):
    # Regression: base_address is memory_diff's match key -- it can never
    # legitimately be null (unlike moduleDiffRecord/threadDiffRecord's
    # OWN address fields, which reuse the same hexAddress $ref precisely
    # because they CAN be null on the missing side). Reusing hexAddress
    # bare here let a null base_address through the schema even though
    # MemoryDiffRecord.__post_init__ already rejects it outright.
    doc = {"entity_type": "memory_region", "change_type": "added", "base_address": None,
           "size_before": None, "size_after": 4096,
           "protect_before": None, "protect_after": "PAGE_READWRITE",
           "type_before": None, "type_after": "MEM_PRIVATE",
           "suspicious_before": None, "suspicious_after": False}
    assert not memory_diff_record_schema.is_valid(doc)


# ── report kind (Phase E, PR3) ─────────────────────────────────────────────

def _minimal_valid_report_summary():
    return {"mode": "addr", "card_count": 1, "query_string": None, "query_tid": None,
            "query_addr": "0x1000", "total_hits": None, "hits_private": None,
            "hits_image": None, "image_hit_modules": [], "skipped_unreadable_regions": 0,
            "truncated_regions": 0, "clamped_regions": 0}


def _minimal_valid_triage_card_record():
    return {
        "anchor_tid": None, "anchor_address": "0x0000000000001000", "anchor_source": "address",
        "thread": None, "region": None, "string_hit": None,
        "other_threads_in_region": [], "notable_strings": [], "ioc_strings": [],
        "string_scan": None, "string_scan_error": None,
        "thread_region_correlation_excluded": False,
        "findings": [], "finding_details": {}, "verdict": "CLEAN",
        "artifact_id": None, "extract_read_clamped": None, "extract_read_truncated": None,
    }


def _minimal_valid_report_doc():
    """A genuinely valid kind == "report" envelope -- see
    _minimal_valid_strings_doc's own docstring for why the generic
    _minimal_valid_doc(kind="report") (summary={"count": 1}, a
    moduleRecord-shaped records[0]) is the wrong base for a report-kind
    negative test: it is already schema-invalid before the test's own
    mutation even applies."""
    doc = _minimal_valid_doc(kind="report")
    doc["result"]["summary"] = _minimal_valid_report_summary()
    doc["result"]["data"]["records"] = [_minimal_valid_triage_card_record()]
    return doc


def test_minimal_valid_report_doc_passes_schema(validator):
    assert validator.is_valid(_minimal_valid_report_doc())


def test_report_summary_missing_query_tid_is_rejected_by_schema(validator):
    doc = _minimal_valid_report_doc()
    del doc["result"]["summary"]["query_tid"]
    assert not validator.is_valid(doc)


def test_report_summary_string_mode_requires_non_null_query_string(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["summary"]["mode"] = "string"
    doc["result"]["summary"]["total_hits"] = 1
    doc["result"]["summary"]["hits_private"] = 1
    doc["result"]["summary"]["hits_image"] = 0
    # query_string still None -- violates the mode == "string" allOf rule
    assert not validator.is_valid(doc)


def test_report_summary_string_mode_with_all_fields_set_passes(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["summary"] = {
        "mode": "string", "card_count": 1, "query_string": "needle", "query_tid": None,
        "query_addr": None, "total_hits": 1, "hits_private": 1, "hits_image": 0,
        "image_hit_modules": [], "skipped_unreadable_regions": 0,
        "truncated_regions": 0, "clamped_regions": 0,
    }
    doc["result"]["data"]["records"] = [{
        **_minimal_valid_triage_card_record(),
        "anchor_source": "string_hit",
        "string_hit": {"offset": 0, "address": "0x0000000000001000", "encoding": "ASCII"},
    }]
    assert validator.is_valid(doc)


def test_report_summary_tid_mode_with_non_null_query_string_is_rejected(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["summary"]["mode"] = "tid"
    doc["result"]["summary"]["query_string"] = "should not be set in tid mode"
    assert not validator.is_valid(doc)


def test_report_summary_non_string_mode_with_nonzero_search_counters_is_rejected(validator):
    # RevFix3-P2b: a non-string mode summary must not be able to carry
    # search-only facts (total_hits/skipped_unreadable_regions/etc) --
    # these are only ever meaningful for a --report-string run.
    doc = _minimal_valid_report_doc()
    doc["result"]["summary"]["total_hits"] = 99
    doc["result"]["summary"]["skipped_unreadable_regions"] = 9
    doc["result"]["summary"]["truncated_regions"] = 8
    doc["result"]["summary"]["clamped_regions"] = 7
    assert not validator.is_valid(doc)


def test_report_summary_non_string_mode_with_nonempty_image_hit_modules_is_rejected(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["summary"]["image_hit_modules"] = ["kernel32.dll"]
    assert not validator.is_valid(doc)


def test_report_summary_string_mode_with_null_total_hits_is_rejected(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["summary"] = {
        "mode": "string", "card_count": 0, "query_string": "needle", "query_tid": None,
        "query_addr": None, "total_hits": None, "hits_private": None, "hits_image": None,
        "image_hit_modules": [], "skipped_unreadable_regions": 0,
        "truncated_regions": 0, "clamped_regions": 0,
    }
    doc["result"]["data"]["records"] = []
    assert not validator.is_valid(doc)


def test_coverage_limitation_report_string_scan_incomplete_wrong_source_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.REPORT_STRING_SCAN_INCOMPLETE,
                              source="string_search", affected_count=1).to_dict()
    doc["source"] = "wrong_source"
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_coverage_limitation_report_string_scan_truncated_wrong_source_rejected_by_schema(
        coverage_limitation_schema):
    doc = CoverageLimitation(code=LimitationCode.REPORT_STRING_SCAN_TRUNCATED,
                              source="string_search", affected_count=1).to_dict()
    doc["source"] = "wrong_source"
    assert not jsonschema.Draft202012Validator(coverage_limitation_schema).is_valid(doc)


def test_triage_card_string_hit_anchor_requires_non_null_string_hit(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["anchor_source"] = "string_hit"
    # string_hit left None -- violates the anchor_source == "string_hit" allOf rule
    assert not validator.is_valid(doc)


def test_triage_card_non_string_hit_anchor_rejects_non_null_string_hit(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["string_hit"] = {
        "offset": 0, "address": "0x0000000000001000", "encoding": "ASCII"}
    assert not validator.is_valid(doc)


def test_triage_card_string_scan_and_error_mutually_exclusive(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["string_scan"] = {
        "requested_bytes": 100, "bytes_read": 100, "clamped": False, "truncated": False,
        "total": 0, "ascii_count": 0, "utf16_count": 0}
    doc["result"]["data"]["records"][0]["string_scan_error"] = "boom"
    assert not validator.is_valid(doc)


def test_triage_card_unknown_extra_field_is_rejected_by_schema(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["totally_unexpected_field"] = "x"
    assert not validator.is_valid(doc)


def _minimal_valid_report_region(**overrides):
    base = {
        "base_address": "0x0000000000001000", "size": 4096, "protect": "PAGE_READWRITE",
        "type": "MEM_PRIVATE", "module_owner": None, "file_offset": None,
        "is_rwx_private": False, "module_context": "unavailable",
        "mz_header_detected": None, "has_injected_pe": None, "protection_suspicious": False,
    }
    base.update(overrides)
    return base


def test_report_region_info_is_rwx_private_requires_protection_suspicious(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["region"] = _minimal_valid_report_region(
        protect="PAGE_READWRITE", is_rwx_private=True, protection_suspicious=False)
    assert not validator.is_valid(doc)


def test_report_region_info_valid_rwx_private_passes(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["region"] = _minimal_valid_report_region(
        protect="PAGE_EXECUTE_READWRITE", is_rwx_private=True, protection_suspicious=True)
    assert validator.is_valid(doc)


def test_report_region_info_mz_header_null_requires_null_has_injected_pe(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["region"] = _minimal_valid_report_region(
        mz_header_detected=None, has_injected_pe=False)
    assert not validator.is_valid(doc)


def test_report_region_info_mz_header_true_unregistered_requires_injected_pe_true(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["region"] = _minimal_valid_report_region(
        mz_header_detected=True, module_context="unregistered", has_injected_pe=False)
    assert not validator.is_valid(doc)


def test_report_region_info_mz_header_true_unavailable_context_valid(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["region"] = _minimal_valid_report_region(
        mz_header_detected=True, module_context="unavailable", has_injected_pe=None)
    assert validator.is_valid(doc)


def test_report_thread_info_resolved_without_range_is_still_valid(validator):
    # module_context == "resolved" does NOT force backing_module_base/end
    # to be set -- Section 3's "other threads sharing this region" entries
    # are resolved but never fetch a module range (only the anchor
    # thread's own Section 1 print does). Only the REVERSE direction is
    # constrained: a non-null backing_module_base requires
    # module_context == "resolved" (see the next test).
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["thread"] = {
        "tid": 1, "start_address": "0x0000000000001000", "backing_module": "ntdll.dll",
        "module_context": "resolved", "kernel_time_100ns": 0, "user_time_100ns": 0,
        "backing_module_base": None, "backing_module_end": None,
    }
    assert validator.is_valid(doc)


def test_report_thread_info_unregistered_with_module_range_is_rejected(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["thread"] = {
        "tid": 1, "start_address": "0x0000000000001000", "backing_module": None,
        "module_context": "unregistered", "kernel_time_100ns": 0, "user_time_100ns": 0,
        "backing_module_base": "0x0000000000001000", "backing_module_end": "0x0000000000002000",
    }
    assert not validator.is_valid(doc)


def test_report_thread_info_valid_resolved_passes(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["thread"] = {
        "tid": 1, "start_address": "0x0000000000001000", "backing_module": "ntdll.dll",
        "module_context": "resolved", "kernel_time_100ns": 0, "user_time_100ns": 0,
        "backing_module_base": "0x0000000000001000", "backing_module_end": "0x0000000000002000",
    }
    assert validator.is_valid(doc)


def test_triage_card_ioc_string_missing_is_network_pattern_is_rejected(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["ioc_strings"] = [{
        "offset": 0, "address": "0x0000000000001000", "encoding": "ASCII", "text": "x",
        "context_hex": None, "context_base_address": None, "context_hit_offset": None}]
    assert not validator.is_valid(doc)


def test_triage_card_ioc_string_valid_non_network_entry_passes(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["ioc_strings"] = [{
        "offset": 0, "address": "0x0000000000001000", "encoding": "ASCII", "text": "x",
        "is_network_pattern": False, "context_hex": None, "context_base_address": None,
        "context_hit_offset": None}]
    assert validator.is_valid(doc)


def test_triage_card_ioc_string_network_pattern_requires_context_hex(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["ioc_strings"] = [{
        "offset": 0, "address": "0x0000000000001000", "encoding": "ASCII", "text": "x",
        "is_network_pattern": True, "context_hex": None, "context_base_address": None,
        "context_hit_offset": None}]
    assert not validator.is_valid(doc)


def test_triage_card_ioc_string_valid_network_pattern_entry_passes(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["ioc_strings"] = [{
        "offset": 0, "address": "0x0000000000001000", "encoding": "ASCII", "text": "x",
        "is_network_pattern": True, "context_hex": "deadbeef",
        "context_base_address": "0x0000000000000f80", "context_hit_offset": 4}]
    assert validator.is_valid(doc)


def test_triage_card_ioc_string_non_network_with_context_hex_is_rejected(validator):
    doc = _minimal_valid_report_doc()
    doc["result"]["data"]["records"][0]["ioc_strings"] = [{
        "offset": 0, "address": "0x0000000000001000", "encoding": "ASCII", "text": "x",
        "is_network_pattern": False, "context_hex": "deadbeef",
        "context_base_address": "0x0000000000000f80", "context_hit_offset": 4}]
    assert not validator.is_valid(doc)

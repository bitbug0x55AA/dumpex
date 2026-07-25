"""
Integration tests for the --json meta block (dumpex.ui.structured.
StructuredOutput._build_meta() and friends) — evidence hashing,
redaction, and graceful degradation when a piece of metadata can't be
computed.
"""
import json
import os
import tempfile

from dumpex.ui.structured import StructuredOutput
from dumpex.rules_pkg.loader import configure_rules_source, get_rules


def _make_dump_file(content: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".dmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(content)
    return path


def test_meta_top_level_shape():
    path = _make_dump_file(b"synthetic dump content")
    try:
        out = StructuredOutput(path, mf=None, command="modules")
        doc = json.loads(out.to_json())
    finally:
        os.unlink(path)

    meta = doc["meta"]
    assert meta["schema_version"] == "1.0"
    assert meta["tool"]["name"] == "dumpex"
    assert meta["execution"]["command"] == "modules"
    assert meta["evidence"]["file_name"] == os.path.basename(path)
    assert "python_version" in meta["runtime"]


def test_evidence_sha256_consistent_across_instances():
    path = _make_dump_file(os.urandom(4096))
    try:
        h1 = json.loads(StructuredOutput(path, mf=None, command="a").to_json())["meta"]["evidence"]["sha256"]
        h2 = json.loads(StructuredOutput(path, mf=None, command="b").to_json())["meta"]["evidence"]["sha256"]
    finally:
        os.unlink(path)
    assert h1 == h2
    assert len(h1) == 64   # hex sha256


def test_evidence_sha256_matches_known_content():
    import hashlib
    content = b"A" * 10_000
    path = _make_dump_file(content)
    try:
        doc = json.loads(StructuredOutput(path, mf=None, command="modules").to_json())
    finally:
        os.unlink(path)
    assert doc["meta"]["evidence"]["sha256"] == hashlib.sha256(content).hexdigest()


def test_execution_timestamps_are_utc_and_ordered():
    path = _make_dump_file(b"x")
    try:
        doc = json.loads(StructuredOutput(path, mf=None, command="modules").to_json())
    finally:
        os.unlink(path)
    execution = doc["meta"]["execution"]
    assert execution["started_at"].endswith("Z")
    assert execution["finished_at"].endswith("Z")
    assert execution["duration_seconds"] >= 0


def test_case_id_and_analyst_pass_through():
    path = _make_dump_file(b"x")
    try:
        out = StructuredOutput(path, mf=None, command="modules",
                                case_id="CASE-42", analyst="grace")
        doc = json.loads(out.to_json())
    finally:
        os.unlink(path)
    assert doc["meta"]["execution"]["case_id"] == "CASE-42"
    assert doc["meta"]["execution"]["analyst"] == "grace"


# ── --redact-paths hides absolute paths in evidence.path and any path- ────
# shaped CLI option, without touching non-path options ─────────────────────

def test_redact_paths_hides_absolute_paths():
    path = _make_dump_file(b"x")
    try:
        out = StructuredOutput(path, mf=None, command="hunt_stomping",
                                options={"ref_dir": "/home/analyst/refs", "verbose": True},
                                redact_paths=True)
        doc = json.loads(out.to_json())
    finally:
        os.unlink(path)
    assert "path" not in doc["meta"]["evidence"]
    assert doc["meta"]["evidence"]["file_name"] == os.path.basename(path)
    assert doc["meta"]["execution"]["options"]["ref_dir"] == "refs"
    assert doc["meta"]["execution"]["options"]["verbose"] is True


def test_without_redact_paths_absolute_path_is_present():
    path = _make_dump_file(b"x")
    try:
        out = StructuredOutput(path, mf=None, command="modules", redact_paths=False)
        doc = json.loads(out.to_json())
    finally:
        os.unlink(path)
    assert doc["meta"]["evidence"]["path"] == os.path.abspath(path)


# ── a hash/stat failure must degrade gracefully — the rest of the analysis ─
# still gets written, never an exception that loses completed work ─────────

def test_missing_evidence_file_does_not_crash_to_json():
    out = StructuredOutput("/tmp/definitely_does_not_exist_dumpex_test.dmp",
                            mf=None, command="modules")
    out.add("modules", [{"name": "ntdll.dll"}])
    doc = json.loads(out.to_json())   # must not raise
    assert "error" in doc["meta"]["evidence"]
    assert doc["meta"]["evidence"]["size_bytes"] is None
    # the actual analysis data must still be intact despite the metadata gap
    assert doc["modules"] == [{"name": "ntdll.dll"}]


# ── rules provenance is surfaced once, in meta.rules, and omitted (not a ──
# misleading empty object) when get_rules() was never called this run ─────

def test_rules_meta_omitted_when_never_loaded():
    configure_rules_source(None)   # force a clean slate regardless of test order
    path = _make_dump_file(b"x")
    try:
        doc = json.loads(StructuredOutput(path, mf=None, command="modules").to_json())
    finally:
        os.unlink(path)
    assert "rules" not in doc["meta"]


def test_rules_meta_present_after_get_rules_called():
    configure_rules_source(None)
    get_rules()   # simulate a hunter (stomping/pipe/obfuscation) having run
    path = _make_dump_file(b"x")
    try:
        doc = json.loads(StructuredOutput(path, mf=None, command="hunt_stomping").to_json())
    finally:
        os.unlink(path)
    assert "rules" in doc["meta"]
    assert "explicit" in doc["meta"]["rules"]


# ── hunt data itself is untouched by the meta changes — no "_rules_source" ─
# leftover inside the hunt section anymore, and ordinary finding data is ──
# unaffected either way ─────────────────────────────────────────────────────

def test_hunt_section_has_no_rules_source_leftover():
    path = _make_dump_file(b"x")
    try:
        out = StructuredOutput(path, mf=None, command="hunt_stomping")
        out.add("hunt", {"stomping": {"score": 0, "status": "NOT_DETECTED_IN_SCANNED_SCOPE"}})
        doc = json.loads(out.to_json())
    finally:
        os.unlink(path)
    assert "_rules_source" not in doc["hunt"]
    assert doc["hunt"]["stomping"]["score"] == 0

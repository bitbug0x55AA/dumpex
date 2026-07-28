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
import dumpex.hunt.yara_hunt as yara_hunt


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
    assert meta["schema_version"] == "1.1"
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


# ── started_at can be injected (cli.py passes the timestamp captured at ───
# the CLI entry point, before open_dump()/MinidumpFile.parse() runs) so
# duration_seconds covers the whole invocation, not just the time since
# StructuredOutput itself was constructed.

def test_started_at_parameter_is_used_when_provided():
    import datetime
    custom_start = datetime.datetime(2020, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    path = _make_dump_file(b"x")
    try:
        doc = json.loads(StructuredOutput(path, mf=None, command="modules",
                                           started_at=custom_start).to_json())
    finally:
        os.unlink(path)
    assert doc["meta"]["execution"]["started_at"] == "2020-01-01T00:00:00Z"
    # duration_seconds must reflect the full span from the injected
    # started_at (years), not from construction time (milliseconds)
    assert doc["meta"]["execution"]["duration_seconds"] > 1_000_000


def test_started_at_defaults_to_construction_time_when_omitted():
    path = _make_dump_file(b"x")
    try:
        doc = json.loads(StructuredOutput(path, mf=None, command="modules").to_json())
    finally:
        os.unlink(path)
    # No started_at given -> behaves as before: duration is small (this
    # test itself takes well under a minute).
    assert 0 <= doc["meta"]["execution"]["duration_seconds"] < 60


# ── tool.version falls back to dumpex.__version__ when the package isn't ──
# registered with importlib.metadata (e.g. a source checkout run without
# `pip install -e .`) instead of going null ──────────────────────────────

def test_tool_version_falls_back_to_dunder_version_when_not_installed(monkeypatch):
    import importlib.metadata as importlib_metadata
    import dumpex.ui.structured as structured_mod
    import dumpex

    def _raise(name):
        raise importlib_metadata.PackageNotFoundError(name)

    monkeypatch.setattr(structured_mod.importlib.metadata, "version", _raise)

    path = _make_dump_file(b"x")
    try:
        doc = json.loads(StructuredOutput(path, mf=None, command="modules").to_json())
    finally:
        os.unlink(path)

    assert doc["meta"]["tool"]["version"] == dumpex.__version__
    assert doc["meta"]["tool"]["version"] is not None


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


# ── --redact-paths must also redact meta.rules.path -- an explicit ────────
# --rules-file is a real absolute filesystem path (unlike the packaged
# "<dumpex.rules_pkg>/data/rules.yaml" display string), so it leaks the
# same local-directory-layout information evidence.path and CLI path
# options do, and must go through the identical basename-only redaction.

def test_redact_paths_hides_rules_meta_path():
    tmp_dir = tempfile.mkdtemp()
    rules_path = os.path.join(tmp_dir, "custom_rules.yaml")
    with open(rules_path, "w") as fh:
        fh.write("version: 1\n")
    dump_path = _make_dump_file(b"x")
    try:
        configure_rules_source(rules_path)
        get_rules()
        doc = json.loads(StructuredOutput(dump_path, mf=None, command="hunt_stomping",
                                           redact_paths=True).to_json())
    finally:
        os.unlink(dump_path)
        os.unlink(rules_path)
        os.rmdir(tmp_dir)
        configure_rules_source(None)

    assert doc["meta"]["rules"]["path"] == "custom_rules.yaml"
    assert tmp_dir not in json.dumps(doc), "no absolute temp-dir path may survive serialization"


def test_without_redact_paths_rules_meta_path_is_absolute():
    tmp_dir = tempfile.mkdtemp()
    rules_path = os.path.join(tmp_dir, "custom_rules.yaml")
    with open(rules_path, "w") as fh:
        fh.write("version: 1\n")
    dump_path = _make_dump_file(b"x")
    try:
        configure_rules_source(rules_path)
        get_rules()
        doc = json.loads(StructuredOutput(dump_path, mf=None, command="hunt_stomping",
                                           redact_paths=False).to_json())
    finally:
        os.unlink(dump_path)
        os.unlink(rules_path)
        os.rmdir(tmp_dir)
        configure_rules_source(None)

    assert doc["meta"]["rules"]["path"] == rules_path


# ── meta.yara_rules: reproducible YARA content provenance, omitted when ───
# never loaded, and redacted the same way meta.rules.path is. Exercised
# against yara_hunt._LAST_YARA_PROVENANCE directly (rather than an actual
# _load_yara_rules() call) so this doesn't depend on the optional
# yara-python package being installed — see tests/unit/test_yara_hunt.py
# for the real _load_yara_rules() provenance-recording behavior itself.

def test_yara_meta_omitted_when_never_loaded():
    yara_hunt._LAST_YARA_PROVENANCE = None
    path = _make_dump_file(b"x")
    try:
        doc = json.loads(StructuredOutput(path, mf=None, command="modules").to_json())
    finally:
        os.unlink(path)
    assert "yara_rules" not in doc["meta"]


def test_yara_meta_present_and_redacts_rules_dir_path():
    yara_hunt._LAST_YARA_PROVENANCE = {
        "rules_dir":        "/home/analyst/case123/yara_rules",
        "files":            [{"name": "a.yar", "sha256": "aa" * 32,
                               "compiled": True, "error": None}],
        "aggregate_sha256": "bb" * 32,
        "compiled_ok":      1,
        "compile_failed":   0,
    }
    path = _make_dump_file(b"x")
    try:
        doc_redacted = json.loads(StructuredOutput(path, mf=None, command="hunt_yara",
                                                     redact_paths=True).to_json())
        doc_plain = json.loads(StructuredOutput(path, mf=None, command="hunt_yara",
                                                  redact_paths=False).to_json())
    finally:
        os.unlink(path)
        yara_hunt._LAST_YARA_PROVENANCE = None

    assert doc_redacted["meta"]["yara_rules"]["rules_dir"] == "yara_rules"
    assert doc_plain["meta"]["yara_rules"]["rules_dir"] == "/home/analyst/case123/yara_rules"
    assert doc_redacted["meta"]["yara_rules"]["compiled_ok"] == 1
    assert doc_redacted["meta"]["yara_rules"]["files"][0]["name"] == "a.yar"
    assert "/home/analyst/case123" not in json.dumps(doc_redacted), \
        "no absolute path may survive serialization under --redact-paths"

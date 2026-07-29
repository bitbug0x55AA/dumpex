"""
Unit tests for dumpex.output.envelope -- meta/result/envelope
construction. Covers meta.evidence being an array (not a single object,
unlike v1.1), execution_status/coverage staying independent axes, and
the meta-construction failure net.
"""
import datetime

import dumpex.output.envelope as envelope_mod
from dumpex.output.envelope import (
    build_meta_v2, Result, Envelope, SCHEMA_VERSION,
    EXECUTION_COMPLETED, EXECUTION_PARTIAL, EXECUTION_FAILED,
)


def _meta(tmp_path, **overrides):
    dump = tmp_path / "sample.dmp"
    dump.write_bytes(b"fake dump content")
    kwargs = dict(
        dump_path_abs=str(dump), dump_file_name="sample.dmp", command="modules",
        options={"verbose": False}, case_id=None, analyst=None, redact_paths=False,
        started_at=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
        finished_at=datetime.datetime(2026, 1, 1, 0, 0, 1, tzinfo=datetime.timezone.utc),
    )
    kwargs.update(overrides)
    return build_meta_v2(**kwargs)


# ── meta.evidence is an array ─────────────────────────────────────────────

def test_meta_evidence_is_a_single_element_array(tmp_path):
    meta = _meta(tmp_path)
    assert meta["schema_version"] == SCHEMA_VERSION == "2.0"
    assert isinstance(meta["evidence"], list)
    assert len(meta["evidence"]) == 1
    entry = meta["evidence"][0]
    assert entry["id"] == "primary"
    assert entry["role"] == "primary"
    assert entry["file_name"] == "sample.dmp"
    assert len(entry["sha256"]) == 64
    assert entry["size_bytes"] == len(b"fake dump content")


def test_meta_evidence_path_present_by_default(tmp_path):
    meta = _meta(tmp_path)
    assert "path" in meta["evidence"][0]


def test_meta_redact_paths_omits_evidence_path(tmp_path):
    meta = _meta(tmp_path, redact_paths=True)
    assert "path" not in meta["evidence"][0]
    # sha256/file_name/size_bytes remain for correlation even redacted
    assert meta["evidence"][0]["file_name"] == "sample.dmp"
    assert len(meta["evidence"][0]["sha256"]) == 64


def test_meta_redact_paths_reduces_path_options_to_basename(tmp_path):
    meta = _meta(tmp_path, options={"verbose": False, "rules_file": "/case/rules.yaml"},
                 redact_paths=True)
    assert meta["execution"]["options"]["rules_file"] == "rules.yaml"


def test_meta_evidence_missing_file_reports_error_not_crash(tmp_path):
    meta = _meta(tmp_path, dump_path_abs=str(tmp_path / "does_not_exist.dmp"))
    entry = meta["evidence"][0]
    assert entry["size_bytes"] is None
    assert "error" in entry


def test_meta_execution_fields(tmp_path):
    meta = _meta(tmp_path)
    assert meta["execution"]["command"] == "modules"
    assert meta["execution"]["duration_seconds"] == 1.0
    assert meta["execution"]["options"] == {"verbose": False}


def test_meta_construction_failure_is_isolated_to_its_own_block(monkeypatch, tmp_path):
    # A failure in ONE block (tool) must not blow away the rest of meta
    # into a shape that fails the v2 schema's own required fields --
    # execution/evidence/runtime must still build normally.
    def _boom():
        raise RuntimeError("simulated failure")
    monkeypatch.setattr(envelope_mod, "_tool_meta", _boom)
    meta = _meta(tmp_path)
    assert meta["schema_version"] == SCHEMA_VERSION
    assert meta["tool"] == {"name": "dumpex", "version": None,
                             "error": "tool metadata failed: simulated failure"}
    # required top-level meta fields still present and well-formed
    assert meta["execution"]["command"] == "modules"
    assert len(meta["evidence"]) == 1
    assert "error" not in meta["execution"]
    assert "error" not in meta["evidence"][0]


def test_meta_evidence_construction_failure_stays_schema_shaped(monkeypatch, tmp_path):
    def _boom(*a, **kw):
        raise RuntimeError("simulated evidence failure")
    monkeypatch.setattr(envelope_mod, "_evidence_entry", _boom)
    meta = _meta(tmp_path)
    assert meta["evidence"] == [{"id": "primary", "role": "primary",
                                  "error": "evidence metadata failed: simulated evidence failure"}]
    # every other block still built normally
    assert meta["tool"]["name"] == "dumpex"
    assert meta["execution"]["command"] == "modules"


# ── execution_status / coverage stay independent axes ────────────────────

def test_result_keeps_execution_status_and_coverage_status_independent():
    result = Result(kind="threads", execution_status=EXECUTION_COMPLETED,
                     coverage_status="partial", coverage_reasons=["stream missing"],
                     summary={"count": 2}, records=[{"tid": 1}])
    d = result.to_dict()
    assert d["execution_status"] == "completed"
    assert d["coverage"]["status"] == "partial"
    assert d["coverage"]["reasons"] == ["stream missing"]
    assert d["kind"] == "threads"
    assert d["data"]["records"] == [{"tid": 1}]


def test_execution_status_constants_are_distinct_strings():
    assert {EXECUTION_COMPLETED, EXECUTION_PARTIAL, EXECUTION_FAILED} == {
        "completed", "partial", "failed"}


def test_result_defaults_are_empty_not_none():
    result = Result(kind="modules", execution_status=EXECUTION_COMPLETED,
                     coverage_status="complete")
    d = result.to_dict()
    assert d["coverage"]["reasons"] == []
    assert d["summary"] == {}
    assert d["data"]["records"] == []


# ── Envelope.to_dict ───────────────────────────────────────────────────────

def test_envelope_to_dict_full_shape():
    result = Result(kind="modules", execution_status=EXECUTION_COMPLETED,
                     coverage_status="complete", records=[{"name": "a.dll"}])
    env = Envelope(meta={"schema_version": "2.0"}, result=result,
                    diagnostics_warnings=[{"severity": "warning", "message": "m", "code": None}])
    d = env.to_dict()
    assert set(d.keys()) == {"meta", "result", "artifacts", "diagnostics"}
    assert d["artifacts"] == []
    assert d["diagnostics"]["warnings"] == [{"severity": "warning", "message": "m", "code": None}]
    assert d["diagnostics"]["errors"] == []

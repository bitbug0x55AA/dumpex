"""
Unit tests for dumpex.output.envelope -- meta/result/envelope
construction. Covers meta.evidence being an array (not a single object,
unlike v1.1), execution_status/coverage staying independent axes, and
the meta-construction failure net.
"""
import datetime

import pytest

import dumpex.output.envelope as envelope_mod
from dumpex.output.envelope import (
    build_meta_v2, Result, Envelope, SCHEMA_VERSION, EvidenceInput,
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
    assert meta["schema_version"] == SCHEMA_VERSION == "2.3"
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


def test_meta_redact_paths_reduces_output_option_to_basename(tmp_path):
    # P1-3 remediation: --extract's own --output path was missing from
    # _PATH_OPTION_KEYS entirely, so meta.execution.options.output kept
    # leaking the full absolute path even with --redact-paths set.
    meta = _meta(tmp_path, options={"verbose": False, "output": "/case/evidence/extracted.bin"},
                 redact_paths=True)
    assert meta["execution"]["options"]["output"] == "extracted.bin"


def test_meta_without_redact_paths_output_option_stays_absolute(tmp_path):
    meta = _meta(tmp_path, options={"verbose": False, "output": "/case/evidence/extracted.bin"},
                 redact_paths=False)
    assert meta["execution"]["options"]["output"] == "/case/evidence/extracted.bin"


# ── _redact_artifacts ────────────────────────────────────────────────────

def test_redact_artifacts_reduces_path_to_basename_leaves_other_fields():
    artifacts = [{"id": "extract_output", "kind": "extracted_region",
                  "path": "/case/evidence/extracted.bin", "size_bytes": 64,
                  "sha256": "abc123", "description": "Bytes extracted from 0x1000"}]
    redacted = envelope_mod._redact_artifacts(artifacts)
    assert redacted[0]["path"] == "extracted.bin"
    assert redacted[0]["size_bytes"] == 64
    assert redacted[0]["sha256"] == "abc123"
    assert redacted[0]["description"] == "Bytes extracted from 0x1000"


def test_redact_artifacts_does_not_mutate_the_original_dicts():
    original = {"id": "a1", "kind": "extracted_region", "path": "/case/out.bin"}
    artifacts = [original]
    envelope_mod._redact_artifacts(artifacts)
    assert original["path"] == "/case/out.bin"   # untouched -- a NEW dict was returned


def test_redact_artifacts_tolerates_null_path():
    redacted = envelope_mod._redact_artifacts([{"id": "a1", "kind": "k", "path": None}])
    assert redacted[0]["path"] is None


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


# ── EvidenceInput / multi-evidence build_meta_v2(evidence=...) ────────────
# Phase C groundwork: a future comparison command builds two EvidenceInputs
# (baseline/target) instead of relying on the single dump_path_abs/
# dump_file_name form every existing single-dump command still uses
# unchanged (see the tests above, none of which pass evidence=).

def _meta_kwargs(**overrides):
    kwargs = dict(
        command="comparison", options={}, case_id=None, analyst=None, redact_paths=False,
        started_at=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
        finished_at=datetime.datetime(2026, 1, 1, 0, 0, 1, tzinfo=datetime.timezone.utc),
    )
    kwargs.update(overrides)
    return kwargs


def test_evidence_input_rejects_empty_fields():
    with pytest.raises(ValueError, match="path"):
        EvidenceInput(id="baseline", role="baseline", path="")


def test_build_meta_v2_requires_dump_path_abs_or_evidence(tmp_path):
    with pytest.raises(TypeError, match="evidence"):
        build_meta_v2(**_meta_kwargs())


def test_build_meta_v2_rejects_empty_evidence_list(tmp_path):
    # meta.evidence's own schema requires minItems: 1 -- {"evidence": []}
    # would build a document that names schema_version but can't
    # actually pass the schema it claims to follow. V2Output's own
    # constructor already rejects this before ever reaching build_meta_v2
    # (see test_v2output_from_evidence_requires_nonempty_list); this is
    # the same check for any other caller of build_meta_v2() directly.
    with pytest.raises(ValueError, match="at least one"):
        build_meta_v2(evidence=[], **_meta_kwargs())


# ── build_meta_v2() is a public export (__all__) -- it must enforce the
# same construction contract as V2Output, not a looser one a caller could
# reach by bypassing V2Output entirely. All four cases below used to be
# silently accepted (or crash with an unrelated AttributeError).

def test_build_meta_v2_rejects_dump_path_abs_and_evidence_together(tmp_path):
    dump = tmp_path / "sample.dmp"
    dump.write_bytes(b"x")
    with pytest.raises(TypeError, match="both"):
        build_meta_v2(dump_path_abs=str(dump), dump_file_name="sample.dmp",
                       evidence=[EvidenceInput(id="a", role="a", path=str(dump))],
                       **_meta_kwargs())


def test_build_meta_v2_requires_dump_file_name_alongside_dump_path_abs(tmp_path):
    dump = tmp_path / "sample.dmp"
    dump.write_bytes(b"x")
    with pytest.raises(TypeError, match="dump_file_name"):
        build_meta_v2(dump_path_abs=str(dump), **_meta_kwargs())


def test_build_meta_v2_rejects_duplicate_evidence_ids(tmp_path):
    dump_a = tmp_path / "a.dmp"
    dump_a.write_bytes(b"a")
    dump_b = tmp_path / "b.dmp"
    dump_b.write_bytes(b"b")
    with pytest.raises(ValueError, match="unique"):
        build_meta_v2(evidence=[
            EvidenceInput(id="same", role="baseline", path=str(dump_a)),
            EvidenceInput(id="same", role="target", path=str(dump_b)),
        ], **_meta_kwargs())


def test_build_meta_v2_rejects_bare_dict_evidence_entries(tmp_path):
    with pytest.raises(TypeError, match="EvidenceInput"):
        build_meta_v2(evidence=[{"id": "a", "role": "a", "path": "x"}], **_meta_kwargs())


def test_build_meta_v2_rejects_generator_evidence_argument(tmp_path):
    # A generator is exhausted by the first of _normalize_evidence_inputs'
    # several validation passes over it -- silently accepting one would
    # leave every LATER pass (id-uniqueness, path normalization) and the
    # final meta["evidence"] list operating on an already-empty sequence,
    # producing meta.evidence=[] (schema-invalid) from a non-empty input.
    dump = tmp_path / "sample.dmp"
    dump.write_bytes(b"x")

    def gen():
        yield EvidenceInput(id="a", role="a", path=str(dump))

    with pytest.raises(TypeError, match="list or tuple"):
        build_meta_v2(evidence=gen(), **_meta_kwargs())


def test_build_meta_v2_evidence_list_produces_one_entry_per_input(tmp_path):
    dump_a = tmp_path / "baseline.dmp"
    dump_a.write_bytes(b"aaa")
    dump_b = tmp_path / "target.dmp"
    dump_b.write_bytes(b"bbbbb")
    meta = build_meta_v2(evidence=[
        EvidenceInput(id="baseline", role="baseline", path=str(dump_a)),
        EvidenceInput(id="target", role="target", path=str(dump_b)),
    ], **_meta_kwargs())
    assert len(meta["evidence"]) == 2
    baseline, target = meta["evidence"]
    assert baseline["id"] == baseline["role"] == "baseline"
    assert baseline["file_name"] == "baseline.dmp"
    assert baseline["size_bytes"] == 3
    assert len(baseline["sha256"]) == 64
    assert target["id"] == target["role"] == "target"
    assert target["file_name"] == "target.dmp"
    assert target["size_bytes"] == 5


def test_build_meta_v2_evidence_list_respects_redact_paths_per_entry(tmp_path):
    dump_a = tmp_path / "baseline.dmp"
    dump_a.write_bytes(b"a")
    dump_b = tmp_path / "target.dmp"
    dump_b.write_bytes(b"b")
    meta = build_meta_v2(evidence=[
        EvidenceInput(id="baseline", role="baseline", path=str(dump_a)),
        EvidenceInput(id="target", role="target", path=str(dump_b)),
    ], **_meta_kwargs(redact_paths=True))
    assert "path" not in meta["evidence"][0]
    assert "path" not in meta["evidence"][1]
    assert meta["evidence"][0]["file_name"] == "baseline.dmp"


def test_build_meta_v2_evidence_entry_failure_does_not_blank_the_other_entry(tmp_path, monkeypatch):
    # The critical isolation case: baseline's stat fails, target must
    # still be fully populated -- NOT the single-entry behavior where
    # one try/except around the whole call would have blanked everything.
    dump_a = tmp_path / "baseline.dmp"   # never created -- os.path.getsize fails
    dump_b = tmp_path / "target.dmp"
    dump_b.write_bytes(b"target content")
    meta = build_meta_v2(evidence=[
        EvidenceInput(id="baseline", role="baseline", path=str(dump_a)),
        EvidenceInput(id="target", role="target", path=str(dump_b)),
    ], **_meta_kwargs())
    baseline, target = meta["evidence"]
    assert baseline["size_bytes"] is None
    assert "error" in baseline
    assert target["size_bytes"] == len(b"target content")
    assert "error" not in target
    assert len(target["sha256"]) == 64


def test_build_meta_v2_evidence_entry_unexpected_exception_isolated_with_id_role_preserved(
        tmp_path, monkeypatch):
    # Beyond _evidence_entry's own internal OSError/hash-failure handling:
    # something else raising entirely (e.g. os.path.basename choking)
    # must still produce a schema-shaped fallback entry carrying the
    # original id/role, not crash the whole evidence array.
    dump_b = tmp_path / "target.dmp"
    dump_b.write_bytes(b"target content")

    def _boom(path):
        if "baseline" in str(path):
            raise RuntimeError("simulated failure")
        return "target.dmp"
    monkeypatch.setattr(envelope_mod.os.path, "basename", _boom)
    meta = build_meta_v2(evidence=[
        EvidenceInput(id="baseline", role="baseline", path="baseline.dmp"),
        EvidenceInput(id="target", role="target", path=str(dump_b)),
    ], **_meta_kwargs())
    baseline, target = meta["evidence"]
    assert baseline == {"id": "baseline", "role": "baseline",
                         "error": "evidence metadata failed: simulated failure"}
    assert target["file_name"] == "target.dmp"
    assert "error" not in target


def test_build_meta_v2_without_evidence_is_byte_identical_to_before_phase_c(tmp_path):
    # Omitting evidence= must reproduce today's single-primary-entry
    # shape exactly -- this is what keeps all six existing commands
    # (which never pass evidence=) fully unaffected by this change.
    dump = tmp_path / "sample.dmp"
    dump.write_bytes(b"fake dump content")
    meta = build_meta_v2(dump_path_abs=str(dump), dump_file_name="sample.dmp",
                          **_meta_kwargs(command="modules"))
    assert len(meta["evidence"]) == 1
    entry = meta["evidence"][0]
    assert entry["id"] == "primary"
    assert entry["role"] == "primary"
    assert entry["file_name"] == "sample.dmp"
    assert entry["size_bytes"] == len(b"fake dump content")
    assert len(entry["sha256"]) == 64


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

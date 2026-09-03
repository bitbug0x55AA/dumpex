"""Unit tests for dumpex.output.collector.V2Output."""
import json

import pytest

from dumpex.output.collector import V2Output
from dumpex.output.command_result import CommandResult
from dumpex.output.coverage import CoverageReport, COVERAGE_COMPLETE
from dumpex.output.records import Diagnostic, Artifact, SEVERITY_WARNING, SEVERITY_ERROR
from tests.fixtures.fakes import FakeMF


def test_set_command_result_forwards_execution_status(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="modules", options={})
    result = CommandResult(kind="modules", records=_fake_records(),
                            coverage=CoverageReport(status=COVERAGE_COMPLETE),
                            execution_status="partial")

    out.set_command_result(result)
    doc = json.loads(out.to_json())

    assert doc["result"]["execution_status"] == "partial"


def test_set_command_result_forwards_diagnostics_by_severity(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="modules", options={})
    result = CommandResult(
        kind="modules", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        diagnostics=[
            Diagnostic(severity=SEVERITY_WARNING, message="w1"),
            Diagnostic(severity=SEVERITY_ERROR, message="e1"),
        ],
    )

    out.set_command_result(result)
    doc = json.loads(out.to_json())

    assert [d["message"] for d in doc["diagnostics"]["warnings"]] == ["w1"]
    assert [d["message"] for d in doc["diagnostics"]["errors"]] == ["e1"]


def test_set_command_result_forwards_artifacts(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="modules", options={})
    result = CommandResult(
        kind="modules", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        artifacts=[Artifact(id="a1", kind="extracted_region", path="x.bin")])

    out.set_command_result(result)
    doc = json.loads(out.to_json())

    assert doc["artifacts"] == [{"id": "a1", "kind": "extracted_region", "path": "x.bin",
                                  "size_bytes": None, "sha256": None, "description": None}]


def test_set_yara_provenance_reaches_meta_yara_rules(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="hunt_yara", options={})
    provenance = {"rules_dir": "/case/rules/yara", "files": [], "aggregate_sha256": "a" * 64,
                  "compiled_ok": 0, "compile_failed": 0}

    out.set_yara_provenance(provenance)
    out.set_command_result(CommandResult(
        kind="hunt", records=_fake_records(), coverage=CoverageReport(status=COVERAGE_COMPLETE)))
    doc = json.loads(out.to_json())

    assert doc["meta"]["yara_rules"] == provenance


def test_yara_provenance_defaults_to_omitted_when_never_set(tmp_path):
    """A command that never calls `set_yara_provenance()` (every command
    except `--hunt yara`/`--hunt all`) must not have `meta.yara_rules`
    fabricated from some other, unrelated run's global state -- see
    `V2Output.set_yara_provenance()`'s own docstring."""
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="modules", options={})
    out.set_command_result(CommandResult(
        kind="modules", records=_fake_records(), coverage=CoverageReport(status=COVERAGE_COMPLETE)))
    doc = json.loads(out.to_json())

    assert "yara_rules" not in doc["meta"]


def test_two_v2outputs_with_different_yara_provenance_never_cross_contaminate():
    """The core P1 review regression: two INDEPENDENT V2Output instances
    (standing in for two separate `--hunt yara` invocations, or a batch
    caller building more than one in the same process) must each keep
    their OWN `set_yara_provenance()` value -- one instance's metadata
    must never reflect the other's, the way a shared global could."""
    out_a = V2Output("/tmp/a.dmp", command="hunt_yara", options={})
    out_b = V2Output("/tmp/b.dmp", command="hunt_yara", options={})
    provenance_a = {"rules_dir": "/case/a/rules", "files": [], "aggregate_sha256": "a" * 64,
                     "compiled_ok": 1, "compile_failed": 0}
    provenance_b = {"rules_dir": "/case/b/rules", "files": [], "aggregate_sha256": "b" * 64,
                     "compiled_ok": 2, "compile_failed": 1}

    # B's provenance is set FIRST, and A's build only completes afterward
    # -- interleaved order, the exact shape a shared "last write wins"
    # global would get wrong.
    out_b.set_yara_provenance(provenance_b)
    out_a.set_yara_provenance(provenance_a)
    for out in (out_a, out_b):
        out.set_command_result(CommandResult(
            kind="hunt", records=_fake_records(), coverage=CoverageReport(status=COVERAGE_COMPLETE)))

    doc_a = json.loads(out_a.to_json())
    doc_b = json.loads(out_b.to_json())
    assert doc_a["meta"]["yara_rules"] == provenance_a
    assert doc_b["meta"]["yara_rules"] == provenance_b


def test_set_command_result_protects_artifact_path_from_later_writes(tmp_path, capsys):
    # P1-1 remediation, second line of defense: an artifact this run
    # already wrote (e.g. --extract's own --output file) must become a
    # protected path for a later write_json call, so a
    # collision (--json pointed at the same path) is refused instead of
    # silently overwriting the artifact -- see safe_io.check_not_dump_path's
    # (path, description) tuple support.
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    artifact_path = tmp_path / "extracted.bin"
    artifact_path.write_bytes(b"original artifact bytes")

    out = V2Output(str(dump_path), command="extract", options={})
    result = CommandResult(
        kind="extract", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        artifacts=[Artifact(id="extract_output", kind="extracted_region",
                             path=str(artifact_path))])
    out.set_command_result(result)

    with pytest.raises(SystemExit) as exc:
        out.write_json(str(artifact_path), cmd_label="extract")
    assert exc.value.code == 1
    err = capsys.readouterr().out
    assert "extracted_region" in err
    assert artifact_path.read_bytes() == b"original artifact bytes"   # untouched


def test_set_command_result_then_to_json_redacts_artifact_path_when_requested(tmp_path):
    # P1-3 remediation: artifacts[].path leaked the full absolute path
    # even under --redact-paths -- only meta.evidence.path and
    # meta.execution.options were ever redacted.
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="extract",
                    options={"output": str(tmp_path / "extracted.bin")}, redact_paths=True)
    result = CommandResult(
        kind="extract", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        artifacts=[Artifact(id="extract_output", kind="extracted_region",
                             path=str(tmp_path / "extracted.bin"), size_bytes=64,
                             sha256="abc123")])
    out.set_command_result(result)
    doc = json.loads(out.to_json())

    assert doc["artifacts"][0]["path"] == "extracted.bin"
    assert doc["artifacts"][0]["size_bytes"] == 64
    assert doc["artifacts"][0]["sha256"] == "abc123"
    assert doc["meta"]["execution"]["options"]["output"] == "extracted.bin"
    assert str(tmp_path) not in json.dumps(doc)


def test_real_collect_extract_redact_paths_leaves_no_absolute_path_in_json(tmp_path):
    # P1 remediation (round 2): collect_extract()'s own summary used to
    # carry a second, UNREDACTED copy of the output path
    # (summary["output_path"]) -- --redact-paths only ever touched
    # meta.execution.options.output and artifacts[].path, so the full
    # absolute path (and its parent directory) still leaked through
    # result.summary in the JSON text. Uses the REAL collect_extract(),
    # not a hand-built CommandResult, so this exercises the exact
    # producer the bug was in.
    import dumpex.commands.extract as extract_mod
    from tests.fixtures.fakes import mem_reader

    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out_dir = tmp_path / "case_evidence_dir"
    out_dir.mkdir()
    output_path = str(out_dir / "extracted.bin")

    mf = FakeMF()
    mf.filename = str(dump_path)
    extract_mod.read_region = mem_reader({0x1000: b"hello world"})
    result = extract_mod.collect_extract(mf, 0x1000, 11, output_path, force=True)

    out = V2Output(str(dump_path), command="extract",
                    options={"output": output_path}, redact_paths=True)
    out.set_command_result(result)
    doc = json.loads(out.to_json())
    full_text = json.dumps(doc)

    assert str(out_dir) not in full_text, "parent directory leaked despite --redact-paths"
    assert output_path not in full_text, "full absolute output path leaked despite --redact-paths"
    assert doc["artifacts"][0]["path"] == "extracted.bin"
    assert "output_path" not in doc["result"]["summary"]
    assert doc["meta"]["execution"]["options"]["output"] == "extracted.bin"


def test_set_command_result_then_to_json_keeps_full_artifact_path_by_default(tmp_path):
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")
    out = V2Output(str(dump_path), command="extract",
                    options={"output": str(tmp_path / "extracted.bin")}, redact_paths=False)
    result = CommandResult(
        kind="extract", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE),
        artifacts=[Artifact(id="extract_output", kind="extracted_region",
                             path=str(tmp_path / "extracted.bin"))])
    out.set_command_result(result)
    doc = json.loads(out.to_json())

    assert doc["artifacts"][0]["path"] == str(tmp_path / "extracted.bin")
    assert doc["meta"]["execution"]["options"]["output"] == str(tmp_path / "extracted.bin")


def test_command_result_rejects_bare_dict_artifact():
    # A bare dict would bypass Artifact's own validation (required
    # `kind`, type checks) and could reach the wire in a shape the JSON
    # Schema rejects -- must fail loudly at construction time instead.
    with pytest.raises(TypeError, match="Artifact"):
        CommandResult(kind="modules", records=_fake_records(),
                      coverage=CoverageReport(status=COVERAGE_COMPLETE),
                      artifacts=[{"id": "a1", "path": "x.bin"}])


def test_command_result_rejects_bare_dict_diagnostic():
    with pytest.raises(TypeError, match="Diagnostic"):
        CommandResult(kind="modules", records=_fake_records(),
                      coverage=CoverageReport(status=COVERAGE_COMPLETE),
                      diagnostics=[{"severity": "warning", "message": "x"}])


def test_set_command_result_minimal_produces_expected_shape(tmp_path):
    # list_cmd.py/modules.py never populate execution_status/diagnostics/
    # artifacts, nor coverage.sources/limitations -- a CommandResult built
    # with only kind/records/coverage (every other field left at its own
    # default) must still produce the full, correctly-shaped document,
    # including empty (not missing) sources/limitations/artifacts/
    # diagnostics.
    dump_path = tmp_path / "sample.dmp"
    dump_path.write_bytes(b"fake")

    out = V2Output(str(dump_path), command="modules", options={})
    out.set_command_result(CommandResult(
        kind="modules", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE)))
    doc = json.loads(out.to_json())

    assert doc["result"]["kind"] == "modules"
    assert doc["result"]["execution_status"] == "completed"
    assert doc["result"]["coverage"] == {
        "status": "complete", "reasons": [], "sources": {}, "limitations": [],
        # A complete result reports an exact zero rather than omitting the
        # aggregate: "nothing was missed" is a measurement, and a missing
        # field is indistinguishable from an unmeasured one to a consumer
        # thresholding on it. The scale stays null: this command runs no
        # eligibility ledger, so there is no proportion to state.
        "missed_bytes": {"state": "exact", "bytes": 0, "complete": True,
                          "quantified_gaps": 0, "unquantified_gaps": 0,
                          "distinct_ranges": 0, "eligible_bytes": None,
                          "unscanned_pass_bytes": 0, "unscanned_fraction": None}}
    assert doc["result"]["summary"] == {"count": 2}
    assert doc["result"]["data"]["records"] == [{"name": "a.dll"}, {"name": "b.dll"}]
    assert doc["artifacts"] == []
    assert doc["diagnostics"] == {"warnings": [], "errors": []}


# ── V2Output multi-evidence construction (Phase C groundwork) ────────────
# No current command calls from_evidence() -- these tests pin the
# capability itself (a future comparison command's one-line integration
# point), independent of whether any command uses it yet.

def test_v2output_requires_dump_path_or_evidence():
    with pytest.raises(TypeError, match="evidence"):
        V2Output()


def test_v2output_from_evidence_produces_two_element_evidence_array(tmp_path):
    # kind="modules" deliberately -- "comparison" isn't a schema-registered
    # result.kind yet (that's Phase C's PR2); a real schema-validating
    # round trip for this same construction lives in
    # tests/integration/test_json_schema_v2.py, where kind="comparison"
    # would validate for the wrong reason (or not at all).
    from dumpex.output.envelope import EvidenceInput

    dump_a = tmp_path / "baseline.dmp"
    dump_a.write_bytes(b"aaa")
    dump_b = tmp_path / "target.dmp"
    dump_b.write_bytes(b"bbbbb")

    out = V2Output.from_evidence([
        EvidenceInput(id="baseline", role="baseline", path=str(dump_a)),
        EvidenceInput(id="target", role="target", path=str(dump_b)),
    ], command="modules", options={})
    out.set_command_result(CommandResult(
        kind="modules", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE)))
    doc = json.loads(out.to_json())

    assert len(doc["meta"]["evidence"]) == 2
    baseline, target = doc["meta"]["evidence"]
    assert baseline["id"] == baseline["role"] == "baseline"
    assert target["id"] == target["role"] == "target"
    assert doc["result"]["kind"] == "modules"


def test_v2output_from_evidence_requires_nonempty_list():
    from dumpex.output.envelope import EvidenceInput
    with pytest.raises(ValueError, match="at least one"):
        V2Output.from_evidence([])


def test_v2output_rejects_both_dump_path_and_evidence(tmp_path):
    from dumpex.output.envelope import EvidenceInput
    dump = tmp_path / "sample.dmp"
    dump.write_bytes(b"x")
    with pytest.raises(TypeError, match="both"):
        V2Output(str(dump), evidence=[EvidenceInput(id="a", role="a", path=str(dump))])


def test_v2output_from_evidence_rejects_duplicate_ids(tmp_path):
    from dumpex.output.envelope import EvidenceInput
    dump_a = tmp_path / "a.dmp"
    dump_a.write_bytes(b"a")
    dump_b = tmp_path / "b.dmp"
    dump_b.write_bytes(b"b")
    with pytest.raises(ValueError, match="unique"):
        V2Output.from_evidence([
            EvidenceInput(id="same", role="baseline", path=str(dump_a)),
            EvidenceInput(id="same", role="target", path=str(dump_b)),
        ])


def test_v2output_from_evidence_rejects_bare_dict_entries():
    with pytest.raises(TypeError, match="EvidenceInput"):
        V2Output.from_evidence([{"id": "a", "role": "a", "path": "x"}])


def test_v2output_from_evidence_rejects_generator(tmp_path):
    # A generator would otherwise be silently exhausted by the first of
    # several validation passes over it (see envelope._normalize_evidence_
    # inputs), leaving self._evidence and self._protected_paths BOTH
    # empty from a genuinely non-empty input -- schema-invalid output and
    # a fully disabled overwrite guard from one construction call.
    from dumpex.output.envelope import EvidenceInput

    dump = tmp_path / "sample.dmp"
    dump.write_bytes(b"x")

    def gen():
        yield EvidenceInput(id="a", role="a", path=str(dump))
        yield EvidenceInput(id="b", role="b", path=str(dump))

    with pytest.raises(TypeError, match="list or tuple"):
        V2Output.from_evidence(gen())


def test_v2output_evidence_path_stays_stable_across_a_cwd_change(tmp_path, monkeypatch):
    # EvidenceInput.path is resolved to absolute ONCE, at construction --
    # a caller passing a relative path, followed by a cwd change before
    # to_json()/write_json() runs, must not cause metadata and the
    # overwrite guard to silently disagree about which on-disk file a
    # given entry refers to.
    from dumpex.output.envelope import EvidenceInput

    dir_a = tmp_path / "a"
    dir_a.mkdir()
    dir_b = tmp_path / "b"
    dir_b.mkdir()
    (dir_a / "same.dmp").write_bytes(b"AAAA")
    (dir_b / "same.dmp").write_bytes(b"BBBB")

    monkeypatch.chdir(dir_a)
    out = V2Output.from_evidence([EvidenceInput(id="x", role="x", path="same.dmp")],
                                  command="modules", options={})
    protected_at_construction = out._protected_paths[0]

    monkeypatch.chdir(dir_b)
    out.set_command_result(CommandResult(
        kind="modules", records=[], coverage=CoverageReport(status=COVERAGE_COMPLETE)))
    doc = json.loads(out.to_json())

    assert out._evidence[0].path == protected_at_construction
    assert doc["meta"]["evidence"][0]["path"] == str(dir_a / "same.dmp")
    assert doc["meta"]["evidence"][0]["size_bytes"] == 4   # b"AAAA", not dir_b's b"BBBB"


# ── V2Output.write_json refuses to overwrite ANY evidence path ──
# (Phase C review finding: an evidence=-constructed instance previously
# passed dump_path_abs=None into the safe-write layer, silently disabling
# the guard entirely for both baseline and target.)

def _comparison_output(dump_a, dump_b):
    from dumpex.output.envelope import EvidenceInput
    out = V2Output.from_evidence([
        EvidenceInput(id="baseline", role="baseline", path=str(dump_a)),
        EvidenceInput(id="target", role="target", path=str(dump_b)),
    ], command="modules", options={})
    out.set_command_result(CommandResult(
        kind="modules", records=_fake_records(),
        coverage=CoverageReport(status=COVERAGE_COMPLETE)))
    return out


@pytest.mark.parametrize("which", ["baseline", "target"])
def test_write_json_refuses_to_overwrite_either_evidence_path(tmp_path, which):
    dump_a = tmp_path / "baseline.dmp"
    dump_a.write_bytes(b"BASELINE CONTENT")
    dump_b = tmp_path / "target.dmp"
    dump_b.write_bytes(b"TARGET CONTENT")
    out = _comparison_output(dump_a, dump_b)
    target_path = dump_a if which == "baseline" else dump_b
    original = target_path.read_bytes()

    with pytest.raises(SystemExit):
        out.write_json(str(target_path), force=True)
    assert target_path.read_bytes() == original


class _FakeRecord:
    def __init__(self, name):
        self._name = name

    def to_dict(self):
        return {"name": self._name}


def _fake_records():
    return [_FakeRecord("a.dll"), _FakeRecord("b.dll")]

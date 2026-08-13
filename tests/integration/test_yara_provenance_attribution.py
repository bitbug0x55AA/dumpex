"""P1 review regression (issue #11): `--hunt yara`'s rule provenance in
`--json` `meta.yara_rules` must be tied to the SPECIFIC command run that
produced it, never a process-wide "last completed YaraReport build" cache
(`dumpex.hunt.yara_hunt.get_yara_provenance()`'s own global -- kept only
as a compatibility adapter for the legacy `dumpex.ui.structured.
StructuredOutput` path).

This exercises the REAL production wiring end to end: `dumpex.hunt.
cmd_hunt(..., collect_records=True)` (the actual `--hunt` CLI entry point,
see `dumpex/cli.py`'s own `--hunt` branch) returns `yara_provenance`
alongside its records; that value is threaded into `V2Output.
set_yara_provenance()` -- exactly what cli.py itself does -- before
`to_json()` serializes `meta.yara_rules`. Two builds, A then B, using
DIFFERENT rules directories, prove neither's own serialized metadata
depends on which one happened to be built (or serialized) more recently.
"""
import os
import tempfile

import pytest

pytest.importorskip("yara")

from tests.fixtures.fakes import Segment, FakeReader, FakeStream, FakeMF

import dumpex.hunt as hunt_pkg
from dumpex.output.collector import V2Output
from dumpex.output.command_result import CommandResult
from dumpex.output.coverage import CoverageReport, COVERAGE_COMPLETE


def _write_rule(d, name, rule_name):
    with open(os.path.join(d, name), "w") as fh:
        fh.write(f'rule {rule_name} {{ condition: true }}')


def _mf_with_segment(seg_va, seg_fo, data):
    seg = Segment(seg_va, seg_fo, len(data))

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        _reader                = FakeReader({seg_va: data})
    return MF()


def _run_hunt_yara_to_v2output(mf, rules_dir: str) -> V2Output:
    """Reproduces dumpex/cli.py's own `--hunt` branch: call `cmd_hunt(...,
    collect_records=True)`, thread its `yara_provenance` return value into
    a fresh `V2Output` via `set_yara_provenance()`, exactly as cli.py
    does before writing `--json`."""
    _results, records, _actions, _diagnostics, yara_provenance = hunt_pkg.cmd_hunt(
        mf, "yara", verbose=False, yara_dir=rules_dir, collect_records=True)
    out = V2Output("/tmp/fake.dmp", command="hunt_yara", options={})
    out.set_yara_provenance(yara_provenance)
    out.set_command_result(CommandResult(
        kind="hunt", records=records, coverage=CoverageReport(status=COVERAGE_COMPLETE)))
    return out


def test_interleaved_yara_hunt_runs_each_serialize_their_own_provenance(capsys):
    """Build A (rules dir 1), build B (rules dir 2), THEN serialize A --
    A's own meta.yara_rules must still name rules dir 1, not B's (the
    scenario a shared "last build" global would get wrong: by the time A
    is serialized, the global would already have been overwritten by B).
    """
    seg_va, seg_fo = 0x81000, 0x8100
    data = b'\x00' * 0x100

    with tempfile.TemporaryDirectory() as d_a, tempfile.TemporaryDirectory() as d_b:
        _write_rule(d_a, "a.yar", "RuleA")
        _write_rule(d_b, "b.yar", "RuleB")

        out_a = _run_hunt_yara_to_v2output(_mf_with_segment(seg_va, seg_fo, data), d_a)
        out_b = _run_hunt_yara_to_v2output(_mf_with_segment(seg_va, seg_fo, data), d_b)

        # Serialize A LAST (after B was already built) -- if anything were
        # still reading a shared global at serialization time, this is
        # exactly the ordering that would expose it.
        doc_b = out_b.to_json()
        doc_a = out_a.to_json()

    import json
    meta_a = json.loads(doc_a)["meta"]["yara_rules"]
    meta_b = json.loads(doc_b)["meta"]["yara_rules"]
    assert meta_a["rules_dir"] == d_a
    assert [f["name"] for f in meta_a["files"]] == ["a.yar"]
    assert meta_b["rules_dir"] == d_b
    assert [f["name"] for f in meta_b["files"]] == ["b.yar"]
    capsys.readouterr()   # drain the console output cmd_hunt() also printed

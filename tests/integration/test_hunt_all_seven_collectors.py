"""
End-to-end integration test for PR2b: run all 7 hunters' real
collect_*_record() functions against ONE shared synthetic MinidumpFile,
feed the resulting 7 HunterRecords through the real
dumpex.hunt.summary.build_hunt_summary() reducer (and, since issue #19,
the real dumpex.hunt._investigation_actions_json() too), and confirm the
whole envelope validates against dumpex-output-v2.12.schema.json -- the
exact shape `--hunt all`'s real CLI wiring (`cli.py` -> `dumpex.hunt.
collect_hunt()`, shipped in PR4) produces, built here independently of
that CLI/dispatcher code (see tests/integration/
test_hunt_cli_compat_freeze.py for the CLI-layer equivalent).
"""
import json

import pytest

from tests.fixtures.fakes import FakeStream, empty_mf as _empty_mf

from dumpex.hunt.injection.collect import collect_injection_record
from dumpex.hunt.hollowing.collect import collect_hollowing_record
from dumpex.hunt.stomping.collect import collect_stomping_record
from dumpex.hunt.pipe.collect import collect_pipe_record
from dumpex.hunt.cs_beacon.collect import collect_cs_beacon_record
from dumpex.hunt.yara_hunt.collect import collect_yara_record
from dumpex.hunt.encoding.collect import collect_obfuscation_record
from dumpex.output.envelope import SCHEMA_VERSION
from dumpex.hunt.summary import build_hunt_summary
from dumpex.hunt import _investigation_actions_json
from dumpex.output.records import HUNTERS, HunterRecord

jsonschema = pytest.importorskip("jsonschema")
from dumpex.schemas import CURRENT_SCHEMA, schema_path


@pytest.fixture(scope="module")
def validator():
    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_all_seven_collectors_agree_with_hunters_own_fixed_order():
    mf = _empty_mf()
    records = [
        collect_injection_record(mf),
        collect_hollowing_record(mf),
        collect_stomping_record(mf),
        collect_pipe_record(mf),
        collect_cs_beacon_record(mf),
        collect_yara_record(mf),
        collect_obfuscation_record(mf),
    ]
    assert tuple(r.hunter for r in records) == HUNTERS
    assert all(isinstance(r, HunterRecord) for r in records)


def test_all_seven_collectors_feed_the_real_summary_reducer_and_validate(validator):
    mf = _empty_mf()
    records = [
        collect_injection_record(mf),
        collect_hollowing_record(mf),
        collect_stomping_record(mf),
        collect_pipe_record(mf),
        collect_cs_beacon_record(mf),
        collect_yara_record(mf),
        collect_obfuscation_record(mf),
    ]

    summary = build_hunt_summary(records, selected="all")
    summary["investigation_actions"] = _investigation_actions_json(records, "all", mf)

    doc = {
        "meta": {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "dumpex", "version": None},
            "execution": {"started_at": "x", "finished_at": "y", "duration_seconds": 1,
                          "command": "hunt_all", "options": {"hunt": "all"}},
            "evidence": [{"id": "primary", "role": "primary"}],
        },
        "result": {
            "kind": "hunt",
            "execution_status": "completed",
            "coverage": {"status": "not_evaluated" if summary["overall_status"] == "NOT_EVALUATED"
                         else "partial", "reasons": [], "sources": {}, "limitations": []},
            "summary": summary,
            "data": {"records": [r.to_dict() for r in records]},
        },
        "artifacts": [],
        "diagnostics": {"warnings": [], "errors": []},
    }

    errors = list(validator.iter_errors(doc))
    assert errors == [], "\n".join(f"{list(e.path)}: {e.message}" for e in errors)
    # On a dump with essentially nothing captured, every hunter should be
    # some non-DETECTED terminal state -- confirming no collector crashed
    # or silently fabricated a detection on empty input.
    assert summary["detected_count"] == 0

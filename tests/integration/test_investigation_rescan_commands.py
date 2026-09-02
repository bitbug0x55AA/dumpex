"""The investigation queue's `--hunt-addr` follow-up, end to end.

A `--hunt all` run that leaves a skipped target has to tell the analyst exactly
which command closes it, and that command has to be one this same CLI accepts:
these tests run the real `cli.main()` twice -- once for the full-scope hunt that
produces the queue entry, once for the command that entry renders -- and check
that the second run lands on the range the first one named.

The structured document stays free of any command string: `--json` carries the
target's own address and size plus the hunters a rescan can name, and a consumer
builds an invocation from those under its own shell's quoting rules.
"""
import json

import pytest

jsonschema = pytest.importorskip("jsonschema")

import dumpex.cli as cli
import dumpex.hunt.pipe.memory_scan as pipe_memory_scan
import dumpex.hunt.pipe.targeted as pipe_targeted
from dumpex.hunt import _registry
from dumpex.hunt._rescan_command import PROGRAM_NAME, RescanCommand
from dumpex.schemas import CURRENT_SCHEMA, schema_path

from tests.fixtures.fakes import FakeMF, FakeStream, Region, Segment
from tests.fixtures.hunt_cli_harness import run_cli, split_console_body

_BASE = 0x20000000
_SIZE = 0x4000
_FILE_OFFSET = 0x3000
# Small enough that the region above is oversized for the full-scope pipe walk,
# which is what puts it in the investigation queue in the first place.
_PIPE_SCAN_MAX = 0x400


@pytest.fixture(scope="module")
def validator():
    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        return jsonschema.Draft202012Validator(json.load(fh))


def _mf():
    class MF(FakeMF):
        memory_info = FakeStream(
            [Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
            "infos")
        memory_segments_64 = FakeStream([Segment(_BASE, _FILE_OFFSET, _SIZE)], "memory_segments")
        modules = FakeStream([], "modules")
    return MF()


def _run_hunt_all(monkeypatch, tmp_path):
    """A full-scope `--hunt all` whose pipe walk skips one oversized region."""
    monkeypatch.setattr(pipe_memory_scan, "PIPE_SCAN_MAX", _PIPE_SCAN_MAX)
    return run_cli(monkeypatch, tmp_path, ["--hunt", "all"], _mf())


def _actions(doc):
    return doc["result"]["summary"]["investigation_actions"]


def _pipe_action(doc):
    for action in _actions(doc):
        if any(rel["hunter"] == "pipe" for rel in action["skipped_by"]):
            return action
    raise AssertionError("no investigation action names pipe")


def _rescan_hunters(action):
    for entry in action["recommended_actions"]:
        if entry["type"] == "targeted_hunter_rescan":
            return entry["hunters"]
    return []


def test_a_skipped_target_reaches_the_queue_with_a_pipe_rescan_recommendation(
        monkeypatch, tmp_path):
    _, doc, _console = _run_hunt_all(monkeypatch, tmp_path)
    action = _pipe_action(doc)
    assert action["target"]["size"] == _SIZE
    assert "pipe" in _rescan_hunters(action)


def test_the_console_renders_the_command_for_the_dump_path_it_was_given(
        monkeypatch, tmp_path):
    _, doc, console = _run_hunt_all(monkeypatch, tmp_path)
    action = _pipe_action(doc)
    command = RescanCommand(
        hunter="pipe", dump_path=str(tmp_path / "test.dmp"),
        base_address=int(action["target"]["base_address"], 16),
        size=action["target"]["size"], target_size=action["target"]["size"])
    assert command.render() in console
    assert "SKIPPED TARGET ACTIONS" in console


def test_the_rendered_command_runs_and_lands_on_the_range_the_queue_named(
        monkeypatch, tmp_path, validator):
    """The reconciliation loop closed: the second invocation's own
    `scan_scope` carries the hunter, source, base address, and size the first
    invocation's queue entry named."""
    _, doc, _console = _run_hunt_all(monkeypatch, tmp_path)
    action = _pipe_action(doc)
    base = int(action["target"]["base_address"], 16)
    size = action["target"]["size"]
    command = RescanCommand(hunter="pipe", dump_path=str(tmp_path / "test.dmp"),
                            base_address=base, size=size, target_size=size)

    monkeypatch.setattr(pipe_targeted, "read_region_spanning",
                        lambda mf, addr, length: b"\x00" * length)
    argv_extra = list(command.option_argv)
    exit_code, rescan_doc, _rescan_console = run_cli(monkeypatch, tmp_path, argv_extra, _mf())

    assert not list(validator.iter_errors(rescan_doc))
    assert exit_code in (0, 3)
    scan_scope = rescan_doc["result"]["summary"]["scan_scope"]
    assert scan_scope["kind"] == "targeted"
    assert scan_scope["hunter"] == "pipe"
    assert scan_scope["source"] == _registry.REGISTRY.targeted_source("pipe")
    assert scan_scope["base_address"] == action["target"]["base_address"]
    assert scan_scope["size"] == size


def test_a_rendered_command_for_a_dash_leading_dump_name_actually_runs(
        monkeypatch, tmp_path, capsys):
    """A dump named `-case.dmp` is an ordinary file: `--hunt all -- -case.dmp`
    opens it, so the command that run recommends has to open it too. Driven
    through the real `cli.main()` argument parser, which is what rejects a
    leading `-` in a positional however the shell quoted it."""
    dump = tmp_path / "-case.dmp"
    dump.write_bytes(b"synthetic dump content")
    command = RescanCommand(hunter="pipe", dump_path=str(dump), base_address=_BASE,
                            size=_SIZE, target_size=_SIZE)
    assert command.renderable

    monkeypatch.setattr(pipe_targeted, "read_region_spanning",
                        lambda mf, addr, length: b"\x00" * length)
    monkeypatch.setattr(cli, "open_dump", lambda path: _mf() if path == str(dump)
                        else pytest.fail(f"opened {path!r}, not the dash-leading dump"))
    # Exactly the tokens the console prints, minus the program name: argparse
    # sees the same argv a shell would build from that line.
    monkeypatch.setattr("sys.argv", ["dumpex", *command.argv[1:]])
    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code

    # Exit 2 is argparse's own usage failure -- what a path-first command line
    # for this dump produces ("the following arguments are required: dumpfile").
    assert exit_code != 2, (
        f"the rendered command was rejected as a usage error: {command.render()}")
    assert "HUNT: TARGETED RESCAN" in capsys.readouterr().out


def test_the_document_carries_no_shell_command_anywhere_in_the_queue(monkeypatch, tmp_path):
    """Quoting is the reading shell's property, not the document's: no
    investigation action may carry a rendered command line, under any key."""
    _, doc, _console = _run_hunt_all(monkeypatch, tmp_path)
    actions = _actions(doc)
    assert actions
    blob = json.dumps(actions)
    assert PROGRAM_NAME not in blob
    assert "--hunt-addr" not in blob
    assert "--size" not in blob


def test_the_queue_entry_still_reports_its_gap_as_unresolved(monkeypatch, tmp_path):
    """Recommending a rescan is advisory. The entry closes nothing by itself,
    and generating it never rewrites the hunter's own verdict or coverage."""
    _, doc, _console = _run_hunt_all(monkeypatch, tmp_path)
    action = _pipe_action(doc)
    assert action["coverage_effect"] == "original_hunter_gap_not_resolved"
    pipe_record = next(r for r in doc["result"]["data"]["records"] if r["hunter"] == "pipe")
    assert pipe_record["coverage"]["status"] != "complete"


def test_redact_paths_reduces_the_rendered_command_to_the_dump_basename(monkeypatch, tmp_path):
    """`--redact-paths` makes the console and `--txt` transcript as shareable as
    the structured document: the command still names the dump, by basename, and
    still runs from the directory holding it."""
    monkeypatch.setattr(pipe_memory_scan, "PIPE_SCAN_MAX", _PIPE_SCAN_MAX)
    _code, doc, console = run_cli(
        monkeypatch, tmp_path, ["--hunt", "all", "--redact-paths"], _mf())
    action = _pipe_action(doc)
    base = int(action["target"]["base_address"], 16)
    size = action["target"]["size"]

    # The trailing JSON-write confirmation names the --json output path, which
    # this flag has never covered; the summary card itself must carry no path.
    body = split_console_body(console)
    assert str(tmp_path) not in body
    assert RescanCommand(hunter="pipe", dump_path="test.dmp", base_address=base,
                         size=size, target_size=size).render() in body

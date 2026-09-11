"""End-to-end console and JSON projection of `--report` enrichment.

Runs the real `cli.main()` against a FakeMF and asserts what an analyst
and a consumer each see: one process-wide block per invocation, four
card-scoped blocks per card, every section stating its own evidence state
and truncation, dump-derived text escaped at the console boundary, and a
document that validates against the current schema with the exit code and
verdict semantics unchanged.

How much of each section the two console detail levels project is
tests/integration/test_report_verbose_detail.py; collector-level
semantics are tests/unit/test_report_enrichment.py.
"""
import datetime
import json
import sys

import jsonschema
import pytest

from minidump.constants import MINIDUMP_STREAM_TYPE

import dumpex.cli as cli
import dumpex.commands.report as report_mod
import dumpex.core.memory as core_memory_mod
import dumpex.output.collector as collector_mod
from dumpex.commands.report_enrichment import CONSOLE_STRING_CONTEXT, MAX_CORRELATED_HANDLES
from dumpex.rules_pkg.loader import configure_rules_source
from dumpex.schemas import CURRENT_SCHEMA, schema_path
from tests.fixtures.fakes import (
    DirectoryEntry, ExceptionListStream, ExceptionRecordDetail, ExceptionStreamEntry,
    FakeMF, FakeStream, HandleStreamDirectory, Region, ThreadInfo, mem_reader,
    parsed_handle_stream,
)

REGION_BASE = 0x1000
REGION_SIZE = 0x1000
ANCHOR_TID = 0x11
PIPE_NAME = "\\Device\\NamedPipe\\evilpipe"
REGION_BYTES = (PIPE_NAME.encode() + b"\x00"
                + b"http://c2.example.com/beacon\x00"
                + b"a perfectly ordinary long string\x00")


class _FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2024, 1, 1, tzinfo=tz)


_REAL_TIMEZONE = datetime.timezone
_REAL_TIMEDELTA = datetime.timedelta


class _FrozenDateTimeModule:
    datetime = _FixedDateTime
    timezone = _REAL_TIMEZONE
    timedelta = _REAL_TIMEDELTA


@pytest.fixture(scope="module")
def validator():
    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _build_mf(tmp_path, *, regions=None, handles=None, exception=None, directories=None,
              object_name=PIPE_NAME):
    dump_path = str(tmp_path / "test.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(b"synthetic dump content")
    mf = FakeMF()
    mf.filename = dump_path
    mf.modules = FakeStream([], "modules")
    mf.thread_info = FakeStream([ThreadInfo(ANCHOR_TID, REGION_BASE)], "infos")
    mf.memory_info = FakeStream(regions if regions is not None else [
        Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT", "PAGE_READWRITE",
               "MEM_PRIVATE"),
        Region(0x2000, REGION_BASE, REGION_SIZE, "MEM_COMMIT", "PAGE_READWRITE",
               "MEM_PRIVATE"),
    ], "infos")
    mf.handles = handles
    mf.exception = exception
    mf.directories = list(directories) if directories is not None else []
    mf._dumpex_stream_failures = {}
    return mf, dump_path


def _run(monkeypatch, tmp_path, mf, dump_path, argv_extra, *, read_map=None):
    monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(collector_mod, "datetime", _FrozenDateTimeModule)
    configure_rules_source(None)
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)
    reader = mem_reader(read_map if read_map is not None else {REGION_BASE: REGION_BYTES})
    monkeypatch.setattr(report_mod, "read_region", reader)
    monkeypatch.setattr(core_memory_mod, "read_region", reader)

    out_json = str(tmp_path / "out.json")
    monkeypatch.setattr(sys, "argv",
                        ["dumpex", dump_path, "--report", *argv_extra, "--json", out_json,
                         "--force"])
    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    with open(out_json, encoding="utf-8") as fh:
        return exit_code, json.load(fh)


def _enriched(tmp_path, **kwargs):
    handles = parsed_handle_stream([
        {"handle": 0x40, "type_name": "File", "object_name": kwargs.pop("object_name",
                                                                        PIPE_NAME)},
        {"handle": 0x44, "type_name": "Key", "object_name": "\\REGISTRY\\MACHINE\\SOFTWARE"},
    ])
    exception = ExceptionListStream([ExceptionStreamEntry(
        ANCHOR_TID, ExceptionRecordDetail(0xC0000005, code_name="EXCEPTION_ACCESS_VIOLATION",
                                          address=REGION_BASE + 0x10, information=(0, 0x41)))])
    return _build_mf(tmp_path, handles=handles, exception=exception,
                     directories=[HandleStreamDirectory(0, 16),
                                  DirectoryEntry(MINIDUMP_STREAM_TYPE.TokenStream)],
                     **kwargs)


# ── console projection ──────────────────────────────────────────────────

def test_every_enrichment_block_is_printed_for_an_address_card(monkeypatch, tmp_path, capsys):
    mf, dump_path = _enriched(tmp_path)
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-addr", hex(REGION_BASE)])
    out = capsys.readouterr().out

    for header in ("PROCESS CONTEXT", "EXCEPTION CONTEXT",
                   "ALLOCATION NEIGHBORHOOD", "CORRELATED HANDLES",
                   "STRING CONTEXT AROUND THE ANCHOR"):
        assert header in out


def test_every_console_block_states_its_scope_state_and_counts(monkeypatch, tmp_path, capsys):
    """The full scope/state/count/cap envelope is verbose detail: scope and
    cap describe the section's own definition, not this dump."""
    mf, dump_path = _enriched(tmp_path)
    _run(monkeypatch, tmp_path, mf, dump_path,
         ["--report-addr", hex(REGION_BASE), "--verbose"])
    out = capsys.readouterr().out

    assert "scope: process   evidence:" in out
    assert "scope: card   evidence:" in out
    assert "kept:" in out and "cap:" in out


def test_the_process_block_is_printed_once_for_a_multi_card_string_run(
        monkeypatch, tmp_path, capsys):
    """One process, one block: repeating it above every card would invite
    an analyst to read process-wide facts as card-specific ones."""
    mf, dump_path = _enriched(tmp_path)
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-string", "beacon"],
         read_map={REGION_BASE: REGION_BYTES, 0x2000: REGION_BYTES})
    out = capsys.readouterr().out

    assert out.count("PROCESS CONTEXT") == 1
    assert out.count("EXCEPTION CONTEXT") == 2


def test_a_missing_section_says_so_rather_than_printing_nothing(monkeypatch, tmp_path, capsys):
    """A silently absent block reads as "there was nothing to find". The
    console has to distinguish that from "this was not evaluated"."""
    mf, dump_path = _build_mf(tmp_path)
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-addr", hex(REGION_BASE)])
    out = capsys.readouterr().out

    assert "No exception evidence was evaluated." in out
    assert "No handle evidence was evaluated for this card." in out
    assert "evidence: not evaluated" in out


def test_a_completed_empty_subset_reads_differently_from_a_missing_one(
        monkeypatch, tmp_path, capsys):
    handles = parsed_handle_stream([
        {"handle": 0x44, "type_name": "Key", "object_name": "\\REGISTRY\\MACHINE\\SOFTWARE"}])
    mf, dump_path = _build_mf(tmp_path, handles=handles,
                              directories=[HandleStreamDirectory(0, 16)])
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-addr", hex(REGION_BASE)])
    out = capsys.readouterr().out

    assert "No handle object name appears in this card's captured text." in out
    assert "No handle evidence was evaluated for this card." not in out


def test_the_console_says_when_it_shows_less_than_was_retained(monkeypatch, tmp_path, capsys):
    data = b"".join(f"ordinary string number {i:03d}\x00".encode() for i in range(20))
    mf, dump_path = _enriched(tmp_path)
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-addr", hex(REGION_BASE)],
         read_map={REGION_BASE: data})
    out = capsys.readouterr().out

    assert f"this section shows {CONSOLE_STRING_CONTEXT} of" in out
    assert "use --verbose for all of them" in out
    assert "--json carries the same retained set" in out


def test_console_omission_and_data_truncation_are_worded_differently(
        monkeypatch, tmp_path, capsys):
    handles = parsed_handle_stream([
        {"handle": 0x40 + i, "type_name": "File", "object_name": PIPE_NAME}
        for i in range(MAX_CORRELATED_HANDLES + 3)])
    mf, dump_path = _build_mf(tmp_path, handles=handles,
                              directories=[HandleStreamDirectory(0, 16)])
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-addr", hex(REGION_BASE)])
    out = capsys.readouterr().out

    assert "this section shows" in out
    assert f"retained set cut at the cap of {MAX_CORRELATED_HANDLES}" in out
    # A cap drops eligible records before anything is retained, so no
    # detail level and no document can produce them.
    assert "are in neither the console nor --json" in out


def test_dump_derived_names_are_escaped_at_the_console_boundary(
        monkeypatch, tmp_path, capsys):
    """A handle object name is attacker-influenced text. It reaches the
    console escaped and reaches --json exactly as captured."""
    hostile = "\\Device\\Named\x1b[31mPipe\\evilpipe"
    handles = parsed_handle_stream([
        {"handle": 0x40, "type_name": "File", "object_name": hostile}])
    mf, dump_path = _build_mf(tmp_path, handles=handles,
                              directories=[HandleStreamDirectory(0, 16)])
    _exit, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                      ["--report-addr", hex(REGION_BASE)],
                      read_map={REGION_BASE: hostile.encode() + b"\x00"})
    out = capsys.readouterr().out

    assert "\x1b[31m" not in out
    entries = doc["result"]["data"]["records"][0]["handle_correlation"]["entries"]
    assert [entry["object_name"] for entry in entries] == [hostile]


# ── structured projection ───────────────────────────────────────────────

def test_the_enriched_document_validates_against_the_current_schema(
        monkeypatch, tmp_path, validator):
    mf, dump_path = _enriched(tmp_path)
    _exit, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                      ["--report-addr", hex(REGION_BASE)])

    assert list(validator.iter_errors(doc)) == []


def test_a_bare_dumps_report_also_validates_with_every_section_missing(
        monkeypatch, tmp_path, validator):
    mf, dump_path = _build_mf(tmp_path)
    _exit, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                      ["--report-addr", hex(REGION_BASE)])
    card = doc["result"]["data"]["records"][0]

    assert list(validator.iter_errors(doc)) == []
    assert card["exception_context"]["section"]["status"] == "missing"
    assert card["handle_correlation"]["section"]["status"] == "missing"
    assert doc["result"]["summary"]["process_enrichment"]["handles"]["section"]["status"] == (
        "missing")


def test_a_string_mode_document_validates_with_a_query_match_entry(
        monkeypatch, tmp_path, validator):
    mf, dump_path = _enriched(tmp_path)
    _exit, doc = _run(monkeypatch, tmp_path, mf, dump_path, ["--report-string", "beacon"],
                      read_map={REGION_BASE: REGION_BYTES})
    card = doc["result"]["data"]["records"][0]
    reasons = [entry["selection_reason"] for entry in card["string_context"]["entries"]]

    assert list(validator.iter_errors(doc)) == []
    assert reasons[0] == "query_match"
    assert card["string_context"]["entries"][0]["distance"] is None


def test_console_and_json_project_the_same_retained_records(monkeypatch, tmp_path, capsys):
    """The console renders from the records the document carries, so a
    fact an analyst reads on screen is a fact a consumer can query."""
    mf, dump_path = _enriched(tmp_path)
    _exit, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                      ["--report-addr", hex(REGION_BASE)])
    out = capsys.readouterr().out
    card = doc["result"]["data"]["records"][0]

    for entry in card["handle_correlation"]["entries"]:
        assert entry["object_name"] in out
    for entry in card["allocation_neighborhood"]["entries"]:
        assert f"0x{int(entry['base_address'], 16):016x}" in out
    assert card["exception_context"]["entries"][0]["exception_code"] in out


def test_enrichment_leaves_findings_verdict_coverage_and_exit_code_alone(
        monkeypatch, tmp_path):
    bare_mf, bare_path = _build_mf(tmp_path)
    bare_exit, bare_doc = _run(monkeypatch, tmp_path, bare_mf, bare_path,
                               ["--report-addr", hex(REGION_BASE)])
    rich_mf, rich_path = _enriched(tmp_path)
    rich_exit, rich_doc = _run(monkeypatch, tmp_path, rich_mf, rich_path,
                               ["--report-addr", hex(REGION_BASE)])

    bare_card = bare_doc["result"]["data"]["records"][0]
    rich_card = rich_doc["result"]["data"]["records"][0]
    assert bare_exit == rich_exit
    assert bare_card["findings"] == rich_card["findings"]
    assert bare_card["verdict"] == rich_card["verdict"]
    assert bare_doc["result"]["coverage"]["status"] == rich_doc["result"]["coverage"]["status"]
    assert (bare_doc["result"]["execution_status"]
            == rich_doc["result"]["execution_status"])
    assert (bare_doc["result"]["coverage"]["limitations"]
            == rich_doc["result"]["coverage"]["limitations"])

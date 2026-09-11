"""`--report`'s two console detail levels.

The default is a concise, self-contained card: every anchor fact, every
incomplete evidence state, every actionable conflict, and a bounded
preview of each populated enrichment section. `--verbose` expands that
same retained evidence -- every retained row plus the per-section
envelope and the selection reasons behind it.

Both levels project one collection. These tests pin that: the same
collectors run the same number of times, the region is read the same
number of times, and the structured document, findings, verdict,
coverage, execution status, diagnostics, artifacts, and exit code are
identical. Verbosity moves nothing across the collection boundary.

Section-level projection rules are tests/integration/
test_report_enrichment_output.py; collector semantics are
tests/unit/test_report_enrichment.py.
"""
import datetime
import json
import os
import re
import struct
import subprocess
import sys

import pytest

from minidump.constants import MINIDUMP_STREAM_TYPE

import dumpex.cli as cli
import dumpex.commands.report as report_mod
import dumpex.core.memory as core_memory_mod
import dumpex.output.collector as collector_mod
from dumpex.commands.report_enrichment import (
    CONSOLE_CORRELATED_HANDLES, CONSOLE_HANDLE_TYPE_ROWS, CONSOLE_NEIGHBOR_REGIONS,
    CONSOLE_STRING_CONTEXT, MAX_CORRELATED_HANDLES, MAX_HANDLE_TYPE_ROWS,
    MAX_NEIGHBOR_REGIONS, MAX_STRING_CONTEXT_ENTRIES,
)
from dumpex.output.coverage import EXIT_NOT_EVALUATED
from dumpex.output.records import ENRICHMENT_TEXT_CAP
from dumpex.rules_pkg.loader import configure_rules_source
from tests.fixtures.fakes import (
    Ctx, DirectoryEntry, ExceptionListStream, ExceptionRecordDetail, ExceptionStreamEntry,
    FakeMF, FakeStream, HandleStreamDirectory, MiscInfo, Module, Peb, Region, SysInfo,
    Thread, ThreadInfo, mem_reader, parsed_handle_stream, wire_environment_walk,
)
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

REGION_BASE = 0x1000
REGION_SIZE = 0x1000
ALLOCATION_REGIONS = 7          # > CONSOLE_NEIGHBOR_REGIONS, <= MAX_NEIGHBOR_REGIONS
CORRELATED_HANDLES = 6          # > CONSOLE_CORRELATED_HANDLES, <= MAX_CORRELATED_HANDLES
ANCHOR_TID = 0x11

# Six correlated handles, each with its own type name, plus three types
# whose object names never appear in the card's text: nine census rows,
# more than the default shows and fewer than the collector keeps.
PIPE_NAMES = [f"\\Device\\NamedPipe\\dumpex-synthetic-pipe-{i:02d}"
              for i in range(CORRELATED_HANDLES)]
UNCORRELATED = [("Key", "\\REGISTRY\\MACHINE\\SOFTWARE\\Synthetic"),
                ("Event", "\\BaseNamedObjects\\SyntheticEvent"),
                ("Mutant", "\\BaseNamedObjects\\SyntheticMutant")]
EXTRA_STRINGS = ["a perfectly ordinary long string",
                 "http://c2.example.invalid/beacon",
                 "another entirely ordinary string"]

# Nine strings, more than the default shows and fewer than the collector
# keeps. Padded to the full region size so the read is complete: a short
# read is its own evidence state and would print at both levels.
_TEXT = b"\x00".join(s.encode() for s in PIPE_NAMES + EXTRA_STRINGS) + b"\x00"
REGION_BYTES = _TEXT + b"\x00" * (REGION_SIZE - len(_TEXT))

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


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


def _build_mf(tmp_path, *, handles=None, regions=None, exception=None,
              directories=None):
    dump_path = str(tmp_path / "test.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(b"synthetic dump content")
    mf = FakeMF()
    mf.filename = dump_path
    mf.modules = FakeStream([], "modules")
    mf.thread_info = FakeStream([ThreadInfo(ANCHOR_TID, REGION_BASE)], "infos")
    mf.memory_info = FakeStream(regions, "infos")
    mf.handles = handles
    mf.exception = exception
    mf.directories = list(directories) if directories is not None else []
    mf._dumpex_stream_failures = {}
    return mf, dump_path


def _populated(tmp_path, *, handle_names=None):
    """One card whose four card-scoped sections all retain more rows than
    the default shows, and none of which reaches its cap."""
    names = PIPE_NAMES if handle_names is None else handle_names
    descriptors = [{"handle": 0x40 + i, "type_name": f"File{i:02d}", "object_name": obj}
                   for i, obj in enumerate(names)]
    descriptors += [{"handle": 0x80 + i, "type_name": type_name, "object_name": obj}
                    for i, (type_name, obj) in enumerate(UNCORRELATED)]
    regions = [Region(REGION_BASE + i * REGION_SIZE, REGION_BASE, REGION_SIZE,
                      "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")
               for i in range(ALLOCATION_REGIONS)]
    exception = ExceptionListStream([ExceptionStreamEntry(
        ANCHOR_TID, ExceptionRecordDetail(0xC0000005, code_name="EXCEPTION_ACCESS_VIOLATION",
                                          address=REGION_BASE + 0x10, information=(0, 0x41)))])
    return _build_mf(tmp_path,
                     handles=parsed_handle_stream(descriptors), regions=regions,
                     exception=exception,
                     directories=[HandleStreamDirectory(0, 16),
                                  DirectoryEntry(MINIDUMP_STREAM_TYPE.TokenStream)])


def _with_session(mf, *entries):
    """A real TEB->PEB->ProcessParameters->Environment chain over an
    environment block, so the session block has values to project."""
    sysinfo = SysInfo()
    sysinfo.ProcessorArchitecture = PROCESSOR_ARCHITECTURE.AMD64
    mf.sysinfo = sysinfo
    mf.threads = FakeStream([Thread(ANCHOR_TID, Ctx(0))], "threads")
    block = b"".join(entry.encode("utf-16-le") + b"\x00\x00" for entry in entries)
    wire_environment_walk(mf, block + b"\x00\x00")
    return mf


def _run(monkeypatch, tmp_path, mf, dump_path, argv_extra, *, read_map=None,
         out_name="out"):
    monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(collector_mod, "datetime", _FrozenDateTimeModule)
    configure_rules_source(None)
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)
    reader = mem_reader(read_map if read_map is not None else {REGION_BASE: REGION_BYTES})
    monkeypatch.setattr(report_mod, "read_region", reader)
    monkeypatch.setattr(core_memory_mod, "read_region", reader)

    out_json = str(tmp_path / f"{out_name}.json")
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


def _both_levels(monkeypatch, tmp_path, capsys, argv_extra, *, mf_factory=_populated,
                 read_map=None):
    """The same anchor at both detail levels, as two complete runs."""
    results = {}
    for label, extra in (("normal", []), ("verbose", ["--verbose"])):
        mf, dump_path = mf_factory(tmp_path)
        exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                              [*argv_extra, *extra], read_map=read_map,
                              out_name=label)
        results[label] = (exit_code, doc, capsys.readouterr().out)
    return results


def _with_identity(mf, *, image_base=0x7FF600000000, modules=()):
    """A dump that resolves a PID, a PEB path, and a start time, so the
    process section evaluates completely. `modules` is the captured module
    list the image base is matched against; None means the dump carries no
    ModuleListStream at all."""
    mf.peb = Peb(image_base, "C:\\Windows\\System32\\synthetic.exe",
                 command_line="synthetic.exe --run")
    mf.misc_info = MiscInfo(process_id=4321, process_create_time=1700000000)
    mf.modules = None if modules is None else FakeStream(list(modules), "modules")
    return mf


def _strings_in(value) -> list:
    """Every string the document holds, as values rather than as JSON
    text: a path compared against `json.dumps` output would never match,
    because JSON escapes the separators a Windows path is made of."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings_in(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings_in(v)]
    return []


_HEADER_RULE = re.compile(r"\n([─=]{50})\n")


def _enrichment_region(console_text: str) -> str:
    """Everything the report prints for its one anchor, from the current
    assessment down to (but not including) the extract result -- the part
    of the console whose content this change decides. The extract result
    is excluded because an unredacted artifact path legitimately contains
    the directory this function is used to check for."""
    start = console_text.index("ASSESSMENT")
    end = console_text.find("Region extracted", start)
    return console_text[start:end] if end != -1 else console_text[start:]


def _section(console_text: str, header: str) -> str:
    """One named block, from its header to the next one. Every header --
    section or group -- is immediately followed by its own full-width
    rule line ('─' * 50 for a section, '═' * 50 for a group), so the next
    one is the next line immediately preceding such a rule. A retained
    string is printed by the STRINGS IN REGION section as well, so a
    claim about the string-context section's own preview has to be made
    against that section's own text."""
    start = console_text.index(header)
    body_start = _HEADER_RULE.search(console_text, start).end()
    next_rule = _HEADER_RULE.search(console_text, body_start)
    if next_rule is None:
        return console_text[body_start:]
    next_header_start = console_text.rfind("\n", body_start, next_rule.start()) + 1
    return console_text[body_start:next_header_start]


def _canonical(doc: dict) -> dict:
    """The document minus the fields a second run legitimately varies:
    when it ran, and which file it read."""
    trimmed = json.loads(json.dumps(doc))
    meta = trimmed["meta"]
    for key in ("generated_at", "started_at", "completed_at", "duration_ms"):
        meta.pop(key, None)
    meta.pop("input", None)
    execution = meta.get("execution", {})
    for key in ("started_at", "completed_at", "duration_ms", "command_line", "options"):
        execution.pop(key, None)
    return trimmed


# ── the fixture itself ──────────────────────────────────────────────────

def test_the_fixture_exceeds_every_console_preview_without_reaching_a_cap(
        monkeypatch, tmp_path, capsys):
    """The premise the rest of this module rests on: each of the four
    previewed sections retains strictly more rows than the default shows,
    and strictly fewer than its collector would cut."""
    mf, dump_path = _populated(tmp_path)
    _exit, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                      ["--report-addr", hex(REGION_BASE)])
    capsys.readouterr()
    card = doc["result"]["data"]["records"][0]
    handles = doc["result"]["summary"]["process_enrichment"]["handles"]

    for retained, console_limit, cap in (
            (len(handles["by_type"]), CONSOLE_HANDLE_TYPE_ROWS, MAX_HANDLE_TYPE_ROWS),
            (len(card["allocation_neighborhood"]["entries"]), CONSOLE_NEIGHBOR_REGIONS,
             MAX_NEIGHBOR_REGIONS),
            (len(card["handle_correlation"]["entries"]), CONSOLE_CORRELATED_HANDLES,
             MAX_CORRELATED_HANDLES),
            (len(card["string_context"]["entries"]), CONSOLE_STRING_CONTEXT,
             MAX_STRING_CONTEXT_ENTRIES)):
        assert console_limit < retained <= cap


# ── the flag reaches the renderer ───────────────────────────────────────

def test_the_cli_forwards_verbose_into_report_rendering(monkeypatch, tmp_path):
    """A flag argparse accepts has to reach the code that answers to it:
    the renderer sees exactly the level the command line asked for."""
    seen = {}
    real_render = report_mod.render_report_console

    def spy(*args, **kwargs):
        seen["render_verbose"] = args[-1] if len(args) > 7 else kwargs.get("verbose")
        return real_render(*args, **kwargs)

    monkeypatch.setattr(report_mod, "render_report_console", spy)
    mf, dump_path = _populated(tmp_path)
    _run(monkeypatch, tmp_path, mf, dump_path,
         ["--report-addr", hex(REGION_BASE), "--verbose"])
    assert seen["render_verbose"] is True

    seen.clear()
    mf, dump_path = _populated(tmp_path)
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-addr", hex(REGION_BASE)],
         out_name="plain")
    assert seen["render_verbose"] is False


@pytest.mark.parametrize("mode_argv, out_name", [
    (["--report-addr", hex(REGION_BASE)], "addr"),
    (["--report-tid", hex(ANCHOR_TID)], "tid"),
    (["--report-string", "dumpex-synthetic-pipe-00"], "string"),
])
def test_verbose_expands_the_console_in_every_report_mode(
        monkeypatch, tmp_path, capsys, mode_argv, out_name):
    """Address, TID, and string anchors all reach the same enrichment
    projection, so all three have to answer to the flag."""
    results = _both_levels(monkeypatch, tmp_path, capsys, mode_argv)
    normal = results["normal"][2]
    verbose = results["verbose"][2]

    assert len(verbose.splitlines()) > len(normal.splitlines())
    assert "this section shows" in normal
    assert "this section shows" not in verbose


# ── what each level shows ───────────────────────────────────────────────

def test_verbose_prints_every_retained_row_of_all_four_sections(
        monkeypatch, tmp_path, capsys):
    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)])
    normal = results["normal"][2]
    verbose = results["verbose"][2]
    card = results["verbose"][1]["result"]["data"]["records"][0]
    handles = results["verbose"][1]["result"]["summary"]["process_enrichment"]["handles"]
    # Every string in this fixture is either the one IOC hit (the beacon
    # URL) or a notable string (the pipe names, the two ordinary ones) --
    # all of them are also selected into string_context by anchor
    # proximity, so a retained string carrying both roles is the norm
    # here, not the exception. STRING CONTEXT presents each as a
    # cross-reference rather than a second copy of its text.
    dedup_identities = {(s["address"], s["encoding"]) for s in card["ioc_strings"]}
    dedup_identities |= {(s["address"], s["encoding"]) for s in card["notable_strings"]}

    for row in handles["by_type"]:
        assert f"{row['type_name']}={row['count']}" in verbose
    for entry in card["allocation_neighborhood"]["entries"]:
        assert f"0x{int(entry['base_address'], 16):016x}" in verbose
    for entry in card["handle_correlation"]["entries"]:
        assert entry["object_name"] in verbose
    for entry in card["string_context"]["entries"]:
        # Still present in the full verbose output either way: an
        # overlapping entry's text was already printed as IOC evidence.
        assert entry["text"] in verbose

    # ... and the default shows a strict prefix of each of them.
    neighborhood = _section(normal, "ALLOCATION NEIGHBORHOOD")
    correlated = _section(normal, "CORRELATED HANDLES")
    strings = _section(normal, "STRING CONTEXT AROUND THE ANCHOR")
    assert sum(f"0x{int(e['base_address'], 16):016x}" in neighborhood
               for e in card["allocation_neighborhood"]["entries"]) == (
        CONSOLE_NEIGHBOR_REGIONS)
    assert sum(e["object_name"] in correlated
               for e in card["handle_correlation"]["entries"]) == (
        CONSOLE_CORRELATED_HANDLES)
    shown_context = card["string_context"]["entries"][:CONSOLE_STRING_CONTEXT]
    hidden_context = card["string_context"]["entries"][CONSOLE_STRING_CONTEXT:]
    overlapping_shown = [e for e in shown_context
                         if (e["address"], e["encoding"]) in dedup_identities]
    non_overlapping_shown = [e for e in shown_context
                             if (e["address"], e["encoding"]) not in dedup_identities]
    assert overlapping_shown, "fixture no longer exercises the dedup-overlap case"
    assert all(e["text"] in strings for e in non_overlapping_shown)
    assert all(e["text"] not in strings for e in overlapping_shown)
    # Beyond the cap, an entry is not rendered at all -- neither its text
    # nor a cross-reference stands in for it.
    assert all(e["text"] not in strings for e in hidden_context)
    assert "also retained as evidence under" in strings


def test_the_default_discloses_each_omission_and_verbose_removes_it(
        monkeypatch, tmp_path, capsys):
    """An omission notice is a promise that the rows still exist. Once
    every one of them is on screen the promise has nothing left to make,
    and repeating it would misdescribe the output."""
    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)])
    normal = results["normal"][2]
    verbose = results["verbose"][2]

    assert f"this section shows {CONSOLE_HANDLE_TYPE_ROWS} of" in normal
    assert f"this section shows {CONSOLE_NEIGHBOR_REGIONS} of" in normal
    assert f"this section shows {CONSOLE_CORRELATED_HANDLES} of" in normal
    assert f"this section shows {CONSOLE_STRING_CONTEXT} of" in normal
    assert "use --verbose for all of them" in normal
    assert "--json carries the same retained set" in normal
    assert "this section shows" not in verbose
    assert "use --verbose" not in verbose


def test_the_per_section_envelope_and_selection_reasons_are_verbose_only(
        monkeypatch, tmp_path, capsys):
    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)])
    normal = results["normal"][2]
    verbose = results["verbose"][2]

    assert "scope: card   evidence:" in verbose
    assert "cap: " in verbose
    assert "built from: " in verbose
    assert "selected: " in verbose
    assert "scope: " not in normal
    assert "cap: " not in normal
    assert "built from: " not in normal
    assert "selected: " not in normal


def test_a_retention_cut_is_stated_at_both_levels_and_never_points_at_json(
        monkeypatch, tmp_path, capsys):
    """A cap drops eligible records before anything is retained. No detail
    level and no document can produce them, and the console must not say
    otherwise."""
    names = [f"\\Device\\NamedPipe\\dumpex-synthetic-pipe-{i:02d}"
             for i in range(MAX_CORRELATED_HANDLES + 3)]
    text = b"\x00".join(n.encode() for n in names) + b"\x00"
    read_map = {REGION_BASE: text + b"\x00" * (REGION_SIZE - len(text))}

    def factory(tmp_path):
        return _populated(tmp_path, handle_names=names)

    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)],
                           mf_factory=factory, read_map=read_map)

    for _exit, doc, out in results.values():
        section = doc["result"]["data"]["records"][0]["handle_correlation"]["section"]
        assert section["truncated"] is True
        assert f"retained set cut at the cap of {MAX_CORRELATED_HANDLES}" in out
        assert "were not retained and are in neither the console nor --json" in out
        assert "the full retained subset is in --json" not in out


def test_missing_partial_and_completed_negative_stay_apart_at_both_levels(
        monkeypatch, tmp_path, capsys):
    """The three states an empty section can be in are different answers.
    Neither level may collapse them into "nothing to see"."""
    def bare(tmp_path):
        regions = [Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                          "PAGE_READWRITE", "MEM_PRIVATE")]
        handles = parsed_handle_stream([
            {"handle": 0x44, "type_name": "Key", "object_name": "\\REGISTRY\\MACHINE"}])
        return _build_mf(tmp_path, handles=handles, regions=regions,
                         directories=[HandleStreamDirectory(0, 16)])

    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)], mf_factory=bare)

    for _exit, _doc, out in results.values():
        # Not evaluated: the stream this section needs is not in the dump.
        assert "No exception evidence was evaluated." in out
        assert "evidence: not evaluated" in out
        # Completed and negative: the evaluation ran and found nothing.
        assert "No handle object name appears in this card's captured text." in out
        assert "No handle evidence was evaluated for this card." not in out


def test_a_partial_read_is_reported_at_both_levels(monkeypatch, tmp_path, capsys):
    """A short read is an evidence state, not a level of detail."""
    short = b"a perfectly ordinary long string\x00"
    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)],
                           read_map={REGION_BASE: short})

    for _exit, _doc, out in results.values():
        assert f"{len(short)} of {REGION_SIZE} requested byte(s)" in out
        assert "came up short" in out
    assert "evidence: partial" in results["normal"][2]
    assert "evidence: partial   kept:" in results["normal"][2]
    assert "scope: card   evidence: partial" in results["verbose"][2]


def test_hostile_dump_text_is_escaped_at_both_levels(monkeypatch, tmp_path, capsys):
    """A handle object name is attacker-influenced text and reaches the
    console escaped however much of it this section shows."""
    hostile = ["\\Device\\Named\x1b[31mPipe\\evil-{}".format(i)
               for i in range(CORRELATED_HANDLES)]
    text = b"\x00".join(n.encode() for n in hostile) + b"\x00"
    read_map = {REGION_BASE: text + b"\x00" * (REGION_SIZE - len(text))}

    def factory(tmp_path):
        return _populated(tmp_path, handle_names=hostile)

    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)],
                           mf_factory=factory, read_map=read_map)

    for _exit, doc, out in results.values():
        assert "\x1b[31m" not in out
        entries = doc["result"]["data"]["records"][0]["handle_correlation"]["entries"]
        assert entries and all("\x1b" in entry["object_name"] for entry in entries)


# ── what neither level touches ──────────────────────────────────────────

def test_both_levels_publish_the_same_document_and_exit_code(
        monkeypatch, tmp_path, capsys):
    # `--output` so the artifact record is a real one on both sides: both
    # runs extract the same region to the same file.
    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE),
                            "--output", str(tmp_path / "region.bin")])
    normal_exit, normal_doc, _ = results["normal"]
    verbose_exit, verbose_doc, _ = results["verbose"]

    assert normal_exit == verbose_exit
    assert _canonical(normal_doc) == _canonical(verbose_doc)
    # Spelled out as well as compared whole: these are the fields a
    # presentation change is least allowed to move.
    normal_card = normal_doc["result"]["data"]["records"][0]
    verbose_card = verbose_doc["result"]["data"]["records"][0]
    assert normal_card["findings"] == verbose_card["findings"]
    assert normal_card["verdict"] == verbose_card["verdict"]
    assert normal_doc["result"]["coverage"] == verbose_doc["result"]["coverage"]
    assert normal_doc["result"]["execution_status"] == verbose_doc["result"]["execution_status"]
    assert normal_doc["diagnostics"] == verbose_doc["diagnostics"]
    assert normal_doc["artifacts"] == verbose_doc["artifacts"]
    assert len(normal_doc["artifacts"]) == 1
    assert normal_doc["meta"]["execution"]["options"]["verbose"] is False
    assert verbose_doc["meta"]["execution"]["options"]["verbose"] is True


def test_redaction_still_removes_paths_and_does_so_at_both_levels(
        monkeypatch, tmp_path, capsys):
    """Redaction is a document contract, and neither detail level may
    weaken it or leave a filesystem path in the enrichment it prints."""
    argv = ["--report-addr", hex(REGION_BASE), "--output", str(tmp_path / "region.bin")]
    redacted = _both_levels(monkeypatch, tmp_path, capsys, [*argv, "--redact-paths"])
    plain = _both_levels(monkeypatch, tmp_path, capsys, argv)

    directory = str(tmp_path)
    for _exit, doc, out in redacted.values():
        assert not [s for s in _strings_in(doc) if directory in s]
        assert all("path" not in entry for entry in doc["meta"]["evidence"])
        assert doc["artifacts"][0]["path"] == "region.bin"
        assert directory not in _enrichment_region(out)
    # Not vacuous: the same runs without the flag do publish those paths.
    for _exit, doc, _out in plain.values():
        assert [s for s in _strings_in(doc) if directory in s]
        assert doc["artifacts"][0]["path"] != "region.bin"

    assert _canonical(redacted["normal"][1]) == _canonical(redacted["verbose"][1])


def test_neither_level_reads_the_dump_again_or_calls_a_collector_again(
        monkeypatch, tmp_path, capsys):
    """Verbose projects what collection already retained. If it cost one
    extra read, one extra collector call, or one wider cap, it would be
    changing evidence rather than presenting it."""
    collectors = ("collect_process_enrichment", "collect_exception_context",
                  "collect_allocation_neighborhood", "collect_handle_correlation",
                  "collect_string_context")
    originals = {name: getattr(report_mod, name) for name in collectors}
    counts = {}

    def instrument(label):
        calls = {"reads": 0, **{name: 0 for name in collectors}}
        counts[label] = calls
        reader = mem_reader({REGION_BASE: REGION_BYTES})

        def counting_read(mf, addr, size):
            calls["reads"] += 1
            return reader(mf, addr, size)

        monkeypatch.setattr(report_mod, "read_region", counting_read)
        monkeypatch.setattr(core_memory_mod, "read_region", counting_read)
        for name in collectors:
            def wrap(*args, _real=originals[name], _name=name, **kwargs):
                calls[_name] += 1
                return _real(*args, **kwargs)

            monkeypatch.setattr(report_mod, name, wrap)

    for label, extra in (("normal", []), ("verbose", ["--verbose"])):
        mf, dump_path = _populated(tmp_path)
        monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
        monkeypatch.setattr(collector_mod, "datetime", _FrozenDateTimeModule)
        configure_rules_source(None)
        monkeypatch.setattr(cli, "open_dump", lambda path, _mf=mf: _mf)
        instrument(label)
        out_json = str(tmp_path / f"{label}.json")
        monkeypatch.setattr(sys, "argv",
                            ["dumpex", dump_path, "--report", "--report-addr",
                             hex(REGION_BASE), *extra, "--json", out_json, "--force"])
        try:
            cli.main()
        except SystemExit:
            pass
        capsys.readouterr()

    assert counts["normal"] == counts["verbose"]
    assert counts["normal"]["reads"] > 0


def test_the_txt_tee_mirrors_the_selected_level_without_ansi(
        monkeypatch, tmp_path, capsys):
    """`--txt` is the console, written down: it carries the level that was
    asked for and never carries escape sequences."""
    written = {}
    for label, extra in (("normal", []), ("verbose", ["--verbose"])):
        mf, dump_path = _populated(tmp_path)
        txt_path = str(tmp_path / f"{label}.txt")
        _run(monkeypatch, tmp_path, mf, dump_path,
             ["--report-addr", hex(REGION_BASE), "--txt", txt_path, *extra],
             out_name=label)
        capsys.readouterr()
        with open(txt_path, encoding="utf-8") as fh:
            written[label] = fh.read()

    for text in written.values():
        assert _ANSI.search(text) is None
    assert "this section shows" in written["normal"]
    assert "this section shows" not in written["verbose"]
    assert "scope: card   evidence:" in written["verbose"]
    assert "scope: card   evidence:" not in written["normal"]


def test_the_session_block_names_its_variables_and_verbose_adds_the_values(
        monkeypatch, tmp_path, capsys):
    """Which variables were captured places the session; the values are
    routine strings. The default names them and says the values are one
    flag away, so nothing reads as uncaptured."""
    def factory(tmp_path):
        mf, dump_path = _populated(tmp_path)
        return _with_session(mf, "COMPUTERNAME=SYNTHETIC-HOST",
                             "SESSIONNAME=Console",
                             "PATH=C:\\Windows"), dump_path

    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)], mf_factory=factory)
    normal = results["normal"][2]
    verbose = results["verbose"][2]
    published = results["normal"][1]["result"]["summary"]["process_enrichment"]
    entries = published["environment"]["entries"]

    assert [entry["name"] for entry in entries] == ["COMPUTERNAME", "SESSIONNAME"]
    for entry in entries:
        assert entry["name"] in normal
        assert entry["value"] not in normal
        assert entry["value"] in verbose
    assert "values not shown — use --verbose for them" in normal
    assert "--json carries the same retained set" in normal
    # A name outside the allowlist is not retained at all, so no level
    # can show it.
    assert "PATH" not in normal


# ── values that reached the retained-text cap ───────────────────────────

def test_a_capped_handle_type_or_object_name_is_marked_where_it_is_shown(
        monkeypatch, tmp_path, capsys):
    """A capped value is a prefix of what the dump held. Rendered without
    a mark it reads as the whole name, which is the one thing a console
    preview must never let an analyst conclude."""
    long_object = "\\Device\\NamedPipe\\" + "p" * (ENRICHMENT_TEXT_CAP + 50)
    long_type = "T" * (ENRICHMENT_TEXT_CAP + 50)

    def factory(tmp_path):
        descriptors = [{"handle": 0x40, "type_name": long_type,
                        "object_name": long_object}]
        regions = [Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                          "PAGE_READWRITE", "MEM_PRIVATE")]
        return _build_mf(tmp_path, handles=parsed_handle_stream(descriptors),
                         regions=regions, directories=[HandleStreamDirectory(0, 16)])

    text = long_object.encode() + b"\x00"
    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)], mf_factory=factory,
                           read_map={REGION_BASE: text + b"\x00" * (REGION_SIZE - len(text))})

    for _exit, doc, out in results.values():
        card = doc["result"]["data"]["records"][0]
        entry = card["handle_correlation"]["entries"][0]
        assert entry["type_name_truncated"] and entry["object_name_truncated"]
        # One mark for the row, naming both fields it applies to.
        assert "[truncated: type name, object name]" in out


def _census_handles(names):
    """One handle per type name, so every name is its own census row."""
    return parsed_handle_stream(
        [{"handle": 0x40 + i, "type_name": name, "object_name": None}
         for i, name in enumerate(names)])


def _census_mf(tmp_path, names):
    regions = [Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                      "PAGE_READWRITE", "MEM_PRIVATE")]
    return _build_mf(tmp_path, handles=_census_handles(names), regions=regions,
                     directories=[HandleStreamDirectory(0, 16)])


def _census_line(console_text: str) -> str:
    for line in _section(console_text, "PROCESS CONTEXT").splitlines():
        if line.strip().startswith("By type"):
            return line
    raise AssertionError("the process block printed no census line")


def test_only_the_census_names_actually_on_screen_are_marked_as_prefixes(
        monkeypatch, tmp_path, capsys):
    """The census is ordered count-descending then name-ascending, so a
    capped name can land in the tail the default never prints. Counting it
    into a "shown as prefixes" total would describe output that is not on
    screen."""
    # Six short names sort ahead of the capped one, which lands seventh --
    # one past the default preview.
    names = [f"Aa{i:02d}" for i in range(CONSOLE_HANDLE_TYPE_ROWS)]
    hidden = "z" * (ENRICHMENT_TEXT_CAP + 50)
    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)],
                           mf_factory=lambda p: _census_mf(p, [*names, hidden]))
    rows = results["normal"][1]["result"]["summary"]["process_enrichment"][
        "handles"]["by_type"]

    assert [row["type_name_truncated"] for row in rows] == (
        [False] * CONSOLE_HANDLE_TYPE_ROWS + [True])

    normal = results["normal"][2]
    assert "…" not in _census_line(normal)
    assert "reached the retained-text cap — a trailing" not in normal
    assert "1 retained type name(s) not shown here also reached the retained-text cap" in normal

    # Verbose prints that row, so there the name carries its own cut point
    # and nothing is left unshown to report separately.
    verbose = results["verbose"][2]
    assert "z" * ENRICHMENT_TEXT_CAP + "…=1" in _census_line(verbose)
    assert "1 type name(s) above reached the retained-text cap — a trailing …" in verbose
    assert "not shown here also reached" not in verbose


def test_a_mixed_census_marks_the_capped_names_and_leaves_the_rest_alone(
        monkeypatch, tmp_path, capsys):
    """A summary count cannot say which of several names on one line was
    cut. The cut point travels with the name that was cut."""
    capped = ["A" + letter * (ENRICHMENT_TEXT_CAP + 50) for letter in ("a", "b")]
    intact = ["Bshort01", "Bshort02"]
    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)],
                           mf_factory=lambda p: _census_mf(p, [*capped, *intact]))

    for _exit, doc, out in results.values():
        rows = doc["result"]["summary"]["process_enrichment"]["handles"]["by_type"]
        assert sum(row["type_name_truncated"] for row in rows) == len(capped)
        line = _census_line(out)
        assert line.count("…=1") == len(capped)
        for name in intact:
            assert f"{name}=1" in line and f"{name}…" not in line
        assert "2 type name(s) above reached the retained-text cap — a trailing …" in out
        assert "not shown here also reached" not in out


def test_a_capped_module_owner_is_marked_where_it_is_shown(
        monkeypatch, tmp_path, capsys):
    long_name = "m" * (ENRICHMENT_TEXT_CAP + 50) + ".dll"

    def factory(tmp_path):
        mf, dump_path = _populated(tmp_path)
        mf.modules = FakeStream(
            [Module(REGION_BASE, REGION_SIZE * ALLOCATION_REGIONS, long_name)], "modules")
        return mf, dump_path

    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)], mf_factory=factory)
    verbose_doc = results["verbose"][1]
    entries = verbose_doc["result"]["data"]["records"][0]["allocation_neighborhood"]["entries"]

    assert all(entry["module_owner_truncated"] for entry in entries)
    # The owner is verbose detail, so the default shows no prefix to
    # mistake for a whole name and verbose shows the mark.
    assert "owner: " not in results["normal"][2]
    assert "[truncated: module owner]" in results["verbose"][2]


# ── module matching ─────────────────────────────────────────────────────

def test_an_unavailable_module_match_is_stated_even_when_the_section_completed(
        monkeypatch, tmp_path, capsys):
    """A dump can resolve a PID, a path, and a start time — a complete
    process evaluation — while carrying no module list to place the image
    base in. The evidence state does not carry that, so the block says it
    at both levels."""
    def factory(tmp_path):
        mf, dump_path = _populated(tmp_path)
        return _with_identity(mf, modules=None), dump_path

    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)], mf_factory=factory)

    for _exit, doc, out in results.values():
        enrichment = doc["result"]["summary"]["process_enrichment"]
        assert enrichment["module_match_state"] == "unavailable"
        assert enrichment["section"]["status"] == "complete"
        assert "Module match" in out
        assert "unavailable — no usable module list to match against" in out


def test_a_resolved_module_match_is_verbose_only(monkeypatch, tmp_path, capsys):
    """`resolved` is the routine positive: it adds a line to every default
    card and tells an analyst nothing to act on."""
    image_base = 0x7FF600000000

    def factory(tmp_path):
        mf, dump_path = _populated(tmp_path)
        return _with_identity(mf, image_base=image_base,
                              modules=[Module(image_base, 0x1000, "synthetic.exe")]), dump_path

    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)], mf_factory=factory)

    assert results["verbose"][1]["result"]["summary"]["process_enrichment"][
        "module_match_state"] == "resolved"
    assert "Module match" not in results["normal"][2]
    assert "resolved" in _section(results["verbose"][2], "PROCESS CONTEXT")


def test_an_unregistered_module_match_is_stated_at_both_levels(
        monkeypatch, tmp_path, capsys):
    def factory(tmp_path):
        mf, dump_path = _populated(tmp_path)
        return _with_identity(mf, modules=[Module(0x10000000, 0x1000, "other.dll")]), dump_path

    results = _both_levels(monkeypatch, tmp_path, capsys,
                           ["--report-addr", hex(REGION_BASE)], mf_factory=factory)

    for _exit, doc, out in results.values():
        assert doc["result"]["summary"]["process_enrichment"]["module_match_state"] == (
            "unregistered")
        assert "unregistered — the image base is in no captured module" in out


# ── the packaged entry point ────────────────────────────────────────────

def _minimal_dump(path) -> str:
    """A real, parseable minidump with an empty stream directory: enough
    for the packaged CLI to open it and run a report whose every section
    is honestly `not evaluated`."""
    header = (b"MDMP" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0)
              + struct.pack("<I", 32) + struct.pack("<I", 0) + struct.pack("<I", 0)
              + struct.pack("<Q", 0))
    path.write_bytes(header)
    return str(path)


def test_the_packaged_cli_answers_to_report_verbose(tmp_path):
    """Through the installed entry point, in its own process: no
    monkeypatch can make `--report --verbose` look wired if the shipped
    argument path drops it."""
    dump_path = _minimal_dump(tmp_path / "smoke.dmp")
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    runs = {}
    for label, extra in (("normal", []), ("verbose", ["--verbose"])):
        runs[label] = subprocess.run(
            [sys.executable, "-m", "dumpex", dump_path, "--report",
             "--report-addr", hex(REGION_BASE), *extra],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=env, timeout=120)

    for label, completed in runs.items():
        assert completed.returncode == EXIT_NOT_EVALUATED, (
            f"{label}: {completed.stdout[-800:]}{completed.stderr[-800:]}")
        assert "PROCESS CONTEXT" in completed.stdout

    assert "scope: process   evidence:" in runs["verbose"].stdout
    assert "built from: " in runs["verbose"].stdout
    assert "scope: process   evidence:" not in runs["normal"].stdout
    assert len(runs["verbose"].stdout.splitlines()) > len(runs["normal"].stdout.splitlines())

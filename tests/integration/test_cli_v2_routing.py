"""
Integration tests for cli.py's v2 routing: the pre-flight rejection of
--json on not-yet-migrated commands (before the dump is even
opened), the seven recon commands (--list/--modules/--threads/--sysinfo/
--process/--handles/--profile) actually writing a v2-shaped document,
--hunt now also writing a v2.4-shaped document (PR4 -- see
dumpex.hunt.cmd_hunt()'s own collect_records= docstring), and the
exit-code contract (0 complete / 3 partial / 4 not_evaluated) for the
v2-routed commands.
"""
import json
import os
import re
import sys
import tempfile

import pytest

import dumpex.cli as cli
from dumpex.output.envelope import SCHEMA_VERSION
from tests.fixtures.fakes import (
    FakeMF, Module, Region, Thread, ThreadInfo, Ctx, FakeStream, Peb, MiscInfo,
    SysInfo, wire_environment_walk,
)

_wire_environment_walk = wire_environment_walk   # local alias, pre-existing call sites unchanged


def _run(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["dumpex"] + argv)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_help_groups_commands_and_modifiers_and_hides_legacy_names(
        monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["dumpex", "--help"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    for heading in ("commands:", "memory and extraction options:",
                    "string scan options:", "diff options:", "hunt options:",
                    "report options:", "output and case metadata:"):
        assert heading in help_text
    assert "--diff-scope {modules,threads,memory,all}" in help_text
    assert "--strings-encoding {ascii,unicode,both}" in help_text
    # P3 regression: --verbose's help text must name --sysinfo now that it
    # gates whether environment variable values print to the console --
    # and, since #43's v2.13 cutover, --process too (peb_extended).
    assert "Show additional detail for --process, --sysinfo," in help_text
    # argparse's own line-wrapping is width-dependent and can break
    # mid-word at a hyphen -- "peb_extended" (an underscore, never
    # hyphen-broken by textwrap) is the resistant marker to check for.
    collapsed_help = " ".join(help_text.split())

    def collapsed_verbose_help() -> str:
        """The display-options group alone, reflowed onto one line:
        argparse wraps at a width this test cannot control, so a
        substring check against the raw text is width-dependent. Sliced
        from the group heading, not from the first "--verbose" in the
        text -- that one is in the usage line."""
        start = collapsed_help.index("display options:")
        return collapsed_help[start:collapsed_help.index("hunt options:", start)]

    assert "adds the retired" in collapsed_help
    assert "peb_extended" in collapsed_help
    # #98: --verbose now also gates the --handles projection, and the
    # help text has to say so -- passing it used to be silently ignored.
    assert "--handles" in collapsed_verbose_help()
    assert "Temporarily unavailable; reserved for future" in collapsed_help
    assert "recovery orchestration" in collapsed_help
    # --sysinfo's own help text must reflect the removed Process section /
    # added Environment section, not the pre-#41 "process" summary.
    assert "Show OS, host, environment and CPU summary" in help_text
    assert "--diff-mode" not in help_text
    assert "--encoding " not in help_text
    # #43: --pid/--peb are gone from public routing (no longer offered as
    # argparse flags in the usage/commands section), and the epilogue
    # redirects a user of the old flags to their replacement.
    assert "  --pid " not in help_text
    assert "  --peb " not in help_text
    assert "--pid and --peb were replaced by --process in v2.13" in help_text
    assert "--process " in help_text
    assert "--handles " in help_text
    assert "--profile " in help_text


def test_legacy_encoding_alias_still_reaches_strings_command(monkeypatch, capsys):
    code = _run(monkeypatch, ["/nonexistent.dmp", "--strings", "0x1000",
                              "--encoding", "unicode"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


# ── pre-flight: every mode reaches open_dump(), none are rejected ────────
# _UNSUPPORTED_STRUCTURED_MODES is permanently empty as of Phase E, PR3
# (--report was the last command still on it) -- there is no longer any
# mode a --json pre-flight check can reject before open_dump().

def test_json_on_v2_mode_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    # A v2-supported mode must proceed past the pre-flight check and reach
    # open_dump()'s own (different) failure mode for a nonexistent file.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules", "--json", "out.json"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


def test_json_on_extract_mode_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    # --extract is v2-supported too (Phase E, PR1) -- must proceed past
    # the pre-flight check and reach open_dump()'s own failure mode.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--extract", "0x1000", "--json", "out.json"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


def test_json_on_strings_mode_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    # --strings is v2-supported too (Phase E, PR2) -- must proceed past
    # the pre-flight check and reach open_dump()'s own failure mode.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--strings", "0x1000", "--json", "out.json"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


def test_json_on_report_mode_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    # --report is v2-supported too (Phase E, PR3) -- must proceed past
    # the pre-flight check and reach open_dump()'s own failure mode.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--report", "--report-tid", "1",
                              "--json", "out.json"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


def test_json_on_diff_mode_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    # --diff is v2-supported too -- must proceed past the pre-flight check
    # and reach open_dump()'s failure mode for the (nonexistent) PRIMARY
    # dump, same as any other v2 mode. main() opens args.dumpfile before
    # args.diff, so a bad primary path's error surfaces first (deliberate,
    # not a gap -- see cli.py's own comment at the mf_reference= line).
    code = _run(monkeypatch, ["/nonexistent.dmp", "--diff", "/other.dmp", "--json", "out.json"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


def test_json_on_hunt_is_not_rejected_reaches_open_dump(monkeypatch, capsys):
    code = _run(monkeypatch, ["/nonexistent.dmp", "--hunt", "injection", "--json", "out.json"])
    assert code == 1
    assert "File not found" in capsys.readouterr().out


# ── v2 vs v1.1 routing + exit codes, via a real (fake-backed) run ────────

def _make_dump_file() -> str:
    fd, path = tempfile.mkstemp(suffix=".dmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(b"synthetic dump content")
    return path


def test_modules_json_produces_v2_shaped_document(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.modules = FakeStream([Module(0x140000000, 0x5000, r"C:\Windows\System32\ntdll.dll")],
                                 "modules")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--modules", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == SCHEMA_VERSION
        assert isinstance(doc["meta"]["evidence"], list)
        assert doc["result"]["kind"] == "modules"
        assert doc["result"]["data"]["records"][0]["name"] == "ntdll.dll"
        assert "hunt" not in doc
    finally:
        os.remove(dump_path)


def test_extract_json_produces_v2_shaped_document_with_artifact(monkeypatch, tmp_path):
    # --extract (Phase E, PR1) is the first v2-routed command to populate
    # result.artifacts/diagnostics for real -- both were plumbed end to
    # end (CommandResult -> V2Output.set_command_result()) since Phase B
    # but had no real producer until now.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.filename = dump_path
        import dumpex.commands.extract as extract_mod
        from tests.fixtures.fakes import mem_reader
        monkeypatch.setattr(extract_mod, "read_region",
                             mem_reader({0x1000: b"MZ" + b"\x90" * 62}))
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        extract_out = str(tmp_path / "extracted.bin")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--extract", "0x1000", "--size", "0x40",
                              "--output", extract_out, "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == SCHEMA_VERSION
        assert doc["result"]["kind"] == "extract"
        assert doc["result"]["coverage"]["status"] == "complete"
        assert doc["result"]["data"]["records"][0]["mz_header_detected"] is True
        assert doc["artifacts"][0]["path"] == extract_out
        assert doc["artifacts"][0]["size_bytes"] == 64
        assert doc["diagnostics"]["warnings"][0]["code"] == "EXTRACT_MZ_HEADER_DETECTED"
        assert os.path.exists(extract_out)
    finally:
        os.remove(dump_path)


def test_strings_json_produces_v2_shaped_document(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.filename = dump_path
        import dumpex.commands.extract as extract_mod
        from tests.fixtures.fakes import mem_reader
        data = b"hello world!\x00\x00" + b"another string here" + b"\x00" * 10
        monkeypatch.setattr(extract_mod, "read_region", mem_reader({0x1000: data}))
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--strings", "0x1000",
                              "--size", str(hex(len(data))), "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == SCHEMA_VERSION
        assert doc["result"]["kind"] == "strings"
        assert doc["result"]["coverage"]["status"] == "complete"
        records = doc["result"]["data"]["records"]
        assert len(records) == 2
        assert records[0]["text"] == "hello world!"
        assert records[0]["matched_grep"] is None
        assert "hunt" not in doc
        assert doc["result"]["summary"]["requested_address"] == "0x0000000000001000"
    finally:
        os.remove(dump_path)


def test_report_json_produces_v2_shaped_document_with_triage_card(monkeypatch, tmp_path):
    # --report (Phase E, PR3) -- the last of the three Phase E commands to
    # populate result.records for real, one TriageCardRecord per card.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.filename = dump_path
        mf.modules = FakeStream([], "modules")
        mf.thread_info = FakeStream([], "infos")
        mf.memory_info = FakeStream(
            [Region(0x6000, 0x6000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
            "infos")
        import dumpex.commands.report as report_mod
        import dumpex.core.memory as core_memory_mod
        from tests.fixtures.fakes import mem_reader
        reader = mem_reader({0x6000: b"boring data here nothing to see".ljust(0x1000, b"\x00")})
        monkeypatch.setattr(report_mod, "read_region", reader)
        monkeypatch.setattr(core_memory_mod, "read_region", reader)
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--report", "--report-addr", "0x6000",
                              "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == SCHEMA_VERSION
        assert doc["result"]["kind"] == "report"
        assert doc["result"]["coverage"]["status"] == "complete"
        records = doc["result"]["data"]["records"]
        assert len(records) == 1
        assert records[0]["verdict"] == "SUSPICIOUS"
        assert records[0]["findings"] == ["rwx_private"]
        assert doc["result"]["summary"]["mode"] == "addr"
        assert "hunt" not in doc
    finally:
        os.remove(dump_path)


def test_extract_short_read_exits_partial_and_json_shows_truncation(monkeypatch, tmp_path, capsys):
    # P1-4 remediation: a short read (read_region() returned fewer bytes
    # than requested) must surface as exit code 3 (EXIT_PARTIAL), not the
    # 0 a full "complete" read gets -- a SOC script checking `$?` on a
    # bare `dumpex --extract ...` (no --json) must be able to detect
    # this without parsing JSON at all. P2 remediation: it must ALSO be
    # visible on the console itself, not just the exit code/JSON.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.filename = dump_path
        import dumpex.commands.extract as extract_mod
        from tests.fixtures.fakes import mem_reader
        monkeypatch.setattr(extract_mod, "read_region", mem_reader({0x1000: b"only 5by"}))
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        extract_out = str(tmp_path / "extracted.bin")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--extract", "0x1000", "--size", "0x40",
                              "--output", extract_out, "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 3
        assert "[~] Requested memory region was only partially read" in capsys.readouterr().out

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["coverage"]["status"] == "partial"
        codes = {lim["code"] for lim in doc["result"]["coverage"]["limitations"]}
        assert "REGION_READ_TRUNCATED" in codes
        assert doc["result"]["data"]["records"][0]["bytes_read"] == 8
    finally:
        os.remove(dump_path)


def test_strings_short_read_exits_partial_and_console_shows_truncation(monkeypatch, tmp_path, capsys):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.filename = dump_path
        import dumpex.commands.extract as extract_mod
        from tests.fixtures.fakes import mem_reader
        monkeypatch.setattr(extract_mod, "read_region",
                             mem_reader({0x1000: b"only a short string here"}))
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--strings", "0x1000", "--size", "0xc8",
                              "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 3
        assert "[~] Requested memory region was only partially read" in capsys.readouterr().out

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["coverage"]["status"] == "partial"
    finally:
        os.remove(dump_path)


def test_list_json_produces_v2_shaped_document(monkeypatch, tmp_path):
    # --list had zero CLI-integration-level coverage before this test --
    # only collect_regions()/cmd_list() were exercised directly in
    # tests/unit/test_list_cmd.py.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.memory_info = FakeStream(
            [Region(0x1000, 0x1000, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
            "infos")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--list", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "memory_regions"
        assert doc["result"]["coverage"]["status"] == "complete"
        assert doc["result"]["data"]["records"][0]["base_address"] == "0x0000000000001000"
    finally:
        os.remove(dump_path)


def test_list_missing_stream_json_is_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # MemoryInfoListStream absent entirely
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--list", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["coverage"]["status"] == "not_evaluated"
        assert doc["result"]["data"]["records"] == []
    finally:
        os.remove(dump_path)


def test_threads_complete_json_exits_zero(monkeypatch, tmp_path):
    # Fills the missing "threads, fully complete" exit-code combo -- the
    # existing threads tests here only cover the degraded/partial case.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.threads     = FakeStream([Thread(1, Ctx(0))], "threads")
        mf.thread_info = FakeStream([ThreadInfo(1, 0x7ffe0000)], "infos")
        mf.modules     = FakeStream([Module(0x7ffe0000, 0x1000, "legit.dll")], "modules")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--threads", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["coverage"]["status"] == "complete"
        assert doc["result"]["data"]["records"][0]["tid"] == 1
    finally:
        os.remove(dump_path)


def test_threads_neither_stream_present_json_is_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # neither ThreadListStream nor ThreadInfoListStream present
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--threads", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["coverage"]["status"] == "not_evaluated"
        assert doc["result"]["coverage"]["reasons"] == [
            "Neither ThreadListStream nor ThreadInfoListStream present in this dump"]
    finally:
        os.remove(dump_path)


# ── process / handles / profile (--process/--handles/--profile, issue #43:
# atomic v2.13 cutover replacing --pid/--peb) ─────────────────────────────

def test_process_complete_json_exits_zero(monkeypatch, tmp_path):
    # "Complete" requires every one of PID/start-time/path/command-line/
    # image-base to be available AND the PEB-reported main image's PE
    # header to actually read/validate -- reuses
    # tests/unit/test_process_cmd.py's own fully-populated fixture (a
    # real synthetic PE image with one import) rather than re-building
    # that machinery here.
    from tests.unit.test_process_cmd import _complete_mf
    dump_path = _make_dump_file()
    try:
        mf = _complete_mf()
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--process", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == SCHEMA_VERSION
        assert doc["result"]["kind"] == "process"
        assert doc["result"]["coverage"]["status"] == "complete"
        record = doc["result"]["data"]["records"][0]
        assert record["pid"] == 4242
        assert record["iat"]["entries"][0]["dll"] == "KERNEL32.dll"
        assert "peb_extended" not in record   # --verbose not given
    finally:
        os.remove(dump_path)


def test_process_verbose_adds_peb_extended(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.peb = Peb(0x140000000, r"C:\test.exe")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--process", "--verbose", "--json", out_json])
        with pytest.raises(SystemExit):
            cli.main()   # not_evaluated (no MiscInfo) -> exit 4, still writes JSON

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "process"
        assert doc["result"]["data"]["records"][0]["peb_extended"] is not None
    finally:
        os.remove(dump_path)


def test_process_empty_dump_json_is_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # misc_info/peb/modules all absent
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--process", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "process"
        assert doc["result"]["coverage"]["status"] == "not_evaluated"
        # §3: --process always emits exactly one record, even when every
        # field is null.
        assert len(doc["result"]["data"]["records"]) == 1
        assert doc["result"]["data"]["records"][0]["process_name"] is None
    finally:
        os.remove(dump_path)


def test_process_partial_json_exits_3(monkeypatch, tmp_path):
    # PEB present with a path but no command line, no image base -- a real
    # gap (PROCESS_COMMAND_LINE_UNAVAILABLE/PROCESS_IMAGE_BASE_UNAVAILABLE),
    # not the "nothing evaluated at all" case -- exit 3, not 4.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.misc_info = MiscInfo(process_id=100, process_create_time=1786670105)
        mf.peb = Peb(None, r"C:\test.exe")   # image_base_address=None, command_line=None
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--process", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_PARTIAL == 3

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "process"
        assert doc["result"]["coverage"]["status"] == "partial"
        assert doc["result"]["data"]["records"][0]["pid"] == 100
    finally:
        os.remove(dump_path)


def test_handles_complete_json_exits_zero(monkeypatch, tmp_path):
    from tests.fixtures.fakes import Handle
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.handles = FakeStream(
            [Handle(0x10, "File", r"\Device\HarddiskVolume1\notes.txt")], "handles")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--handles", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == SCHEMA_VERSION
        assert doc["result"]["kind"] == "handles"
        assert doc["result"]["coverage"]["status"] == "complete"
        record = doc["result"]["data"]["records"][0]
        assert record["handle"] == "0x0000000000000010"
        # #102 decodes this mask for the CONSOLE. On the wire it stays the
        # raw integer the descriptor carried, and the record gains no
        # derived field -- v2.13's schema is frozen, and a consumer that
        # needs a stable machine value reads `granted_access`.
        assert record["granted_access"] == 0x0012019F
        assert isinstance(record["granted_access"], int)
        assert set(record) == {
            "handle", "type_name", "type_name_status", "object_name",
            "object_name_status", "attributes", "granted_access",
            "handle_count", "pointer_count"}
        assert "ReadData" not in json.dumps(doc)
    finally:
        os.remove(dump_path)


def test_handles_absent_stream_json_is_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # no HandleDataStream at all
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--handles", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "handles"
        assert doc["result"]["coverage"]["status"] == "not_evaluated"
        assert doc["result"]["data"]["records"] == []
    finally:
        os.remove(dump_path)


def test_handles_partial_json_exits_3(monkeypatch, tmp_path):
    # A descriptor whose name RVA points past the end of the captured
    # stream body -- an unreadable (not merely unnamed) name, real
    # HANDLE_STRING_READ_FAILED evidence a genuine dump can produce --
    # reuses tests/unit/test_handles_cmd.py's own real-parser fixture
    # builder (_mf_with/BAD_RVA) rather than hand-shaping bytes here.
    from tests.unit.test_handles_cmd import _mf_with, BAD_RVA
    dump_path = _make_dump_file()
    try:
        mf = _mf_with([{"handle": 0x10, "type_name": "File", "object_name": BAD_RVA}])
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--handles", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_PARTIAL == 3

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "handles"
        assert doc["result"]["coverage"]["status"] == "partial"
        assert len(doc["result"]["data"]["records"]) == 1   # descriptor kept, name lost
        assert doc["result"]["data"]["records"][0]["object_name_status"] == "unreadable"
    finally:
        os.remove(dump_path)


def test_handles_verbose_is_wired_end_to_end_without_changing_the_json(monkeypatch, tmp_path, capsys):
    """#98: `--handles --verbose` used to be silently ignored -- the CLI
    never forwarded the flag. It must now reach the renderer, show the
    rows the default projection folds, and leave the structured result
    byte-identical."""
    from tests.unit.test_handles_cmd import _mf_with
    descriptors = ([{"handle": 0x10 + i, "type_name": "Event", "object_name": None}
                    for i in range(4)]
                   + [{"handle": 0x100, "type_name": "File",
                       "object_name": r"\Device\HarddiskVolume1\notes.txt"}])
    dump_path = _make_dump_file()
    try:
        monkeypatch.setattr(cli, "open_dump", lambda path: _mf_with(descriptors))

        default_json = str(tmp_path / "default.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--handles",
                                          "--json", default_json])
        cli.main()
        default_console = capsys.readouterr().out

        verbose_json = str(tmp_path / "verbose.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--handles", "--verbose",
                                          "--json", verbose_json])
        cli.main()
        verbose_console = capsys.readouterr().out
    finally:
        os.remove(dump_path)

    default_doc = json.loads(open(default_json, encoding="utf-8").read())
    verbose_doc = json.loads(open(verbose_json, encoding="utf-8").read())

    # Console verbosity NEVER removes or mutates a structured record.
    assert default_doc["result"]["data"] == verbose_doc["result"]["data"]
    assert len(default_doc["result"]["data"]["records"]) == len(descriptors)
    assert default_doc["result"]["coverage"] == verbose_doc["result"]["coverage"]
    # ... and the flag IS recorded as an execution option either way.
    assert default_doc["meta"]["execution"]["options"]["verbose"] is False
    assert verbose_doc["meta"]["execution"]["options"]["verbose"] is True

    # The console, and only the console, differs.
    assert "not shown" in default_console
    assert "use --verbose to show all" in default_console
    assert "0x0000000000000010" not in default_console      # a folded anonymous Event
    assert "0x0000000000000010" in verbose_console
    assert "not shown" not in verbose_console


class _FakeMinidumpHeader:
    """Minimal stand-in for the dump's own header -- only `.Flags`
    (MINIDUMP_TYPE), the one field collect_profile() reads from it."""
    def __init__(self, flags=0):
        self.Flags = flags


def test_profile_complete_json_exits_zero(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.header = _FakeMinidumpHeader(0)
        mf.sysinfo = SysInfo()
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--profile", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == SCHEMA_VERSION
        assert doc["result"]["kind"] == "profile"
        assert doc["result"]["coverage"]["status"] == "complete"
        # #95's own explicit acceptance case: a successfully profiled
        # sparse dump stays complete even though some capabilities are
        # unavailable.
        assert any(c["status"] == "unavailable"
                   for c in doc["result"]["data"]["records"][0]["capabilities"])
    finally:
        os.remove(dump_path)


def test_profile_partial_json_exits_3(monkeypatch, tmp_path):
    # A real header/directory table (profile_directory is PRESENT, so
    # coverage can never fall to not_evaluated) but no SystemInfoStream --
    # PROFILE_ARCHITECTURE_UNAVAILABLE, a genuine partial gap.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.header = _FakeMinidumpHeader(0)   # no mf.sysinfo
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--profile", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_PARTIAL == 3

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "profile"
        assert doc["result"]["coverage"]["status"] == "partial"
        assert doc["result"]["data"]["records"][0]["architecture"] is None
    finally:
        os.remove(dump_path)


def test_profile_no_header_json_is_not_evaluated(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # header defaults to None -- no defensible profile at all
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--profile", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "profile"
        assert doc["result"]["coverage"]["status"] == "not_evaluated"
        assert doc["result"]["data"]["records"] == []
    finally:
        os.remove(dump_path)


# ── --txt for the three new commands (issue #43's own "--txt, --json,     │
#    output collision safety, case metadata, and path-redaction plumbing   │
#    continue to work for all three new modes" requirement) -- --txt's own │
#    mechanism (AtomicTextTee wrapping sys.stdout, ANSI-stripped on write) │
#    is command-agnostic and already unit-tested at that level             │
#    (tests/unit/test_safe_io.py); these prove it actually engages for     │
#    --process/--handles/--profile specifically, not just in principle. ───

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


def test_process_txt_writes_a_real_ansi_free_transcript(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.peb = Peb(0x140000000, r"C:\test.exe")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_txt = str(tmp_path / "out.txt")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--process", "--txt", out_txt])
        with pytest.raises(SystemExit):
            cli.main()   # not_evaluated (no MiscInfo) -> exit 4, --txt still commits

        assert os.path.exists(out_txt)
        text = open(out_txt, encoding="utf-8").read()
        assert text   # something was actually written, not an empty placeholder
        assert not _ANSI_ESCAPE_RE.search(text)
    finally:
        os.remove(dump_path)


def test_handles_txt_writes_a_real_ansi_free_transcript(monkeypatch, tmp_path):
    from tests.fixtures.fakes import Handle
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.handles = FakeStream(
            [Handle(0x10, "File", r"\Device\HarddiskVolume1\notes.txt")], "handles")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_txt = str(tmp_path / "out.txt")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--handles", "--txt", out_txt])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        assert os.path.exists(out_txt)
        text = open(out_txt, encoding="utf-8").read()
        assert text
        assert not _ANSI_ESCAPE_RE.search(text)
        # #102: the transcript an analyst keeps carries BOTH the exact
        # captured mask (once, in the Access column) and, on the row's own
        # Rights line, what it permitted for the recorded object type --
        # with no ANSI in between.
        assert text.count("0x0012019f") == 1
        assert "      └─ Rights   FileGenericRead · FileGenericWrite" in text
    finally:
        os.remove(dump_path)


def test_handles_json_and_txt_together_keep_the_raw_mask_and_the_decode_apart(
        monkeypatch, tmp_path):
    """#102's acceptance in one run: the console/TXT projection decodes
    the mask, the structured record does not, and the two describe the
    same captured value.

    There is no CSV surface to check alongside them -- `--csv` was
    removed from this codebase before the recon redesign (contract §7.1),
    and tests/unit/test_cli_args.py already pins that argparse rejects
    it."""
    from tests.fixtures.fakes import Handle
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.handles = FakeStream([
            Handle(0x10, "File", r"\Device\HarddiskVolume1\notes.txt"),
            # The same mask under a second type -- the one thing a raw
            # hexadecimal column could never say.
            Handle(0x20, "Process", r"\proc", access=0x0012019F),
        ], "handles")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        out_txt = str(tmp_path / "out.txt")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--handles",
                                           "--json", out_json, "--txt", out_txt])
        cli.main()

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert [r["granted_access"] for r in doc["result"]["data"]["records"]] == [
            0x0012019F, 0x0012019F]

        text = open(out_txt, encoding="utf-8").read()
        # File bit 0x0001 is ReadData; the same bit on a Process is
        # Terminate -- and each reading sits under its own row, so the
        # transcript never asks the reader to match a mask to a type.
        # One (row, rights) pair per handle. A long decode splits into a
        # `Type` and a `Standard` group under the same row, so the groups
        # are collected per row rather than per line.
        head = re.compile(r"^ {6}(?:└─ |   )(Rights|Type|Standard) +(\S.*)$")
        rows = []
        # A continuation counts only while it immediately follows its own
        # group: the `Aliases used` block below the table is indented
        # past the same column.
        open_group = None
        for line in text.splitlines():
            matched = head.match(line)
            if line.strip().startswith("0x"):
                rows.append([line, []])
                open_group = None
            elif matched and rows:
                rows[-1][1].append([matched.group(1), matched.group(2)])
                open_group = rows[-1][1][-1]
            elif open_group is not None and line.startswith(" " * 18) and line.strip():
                # A wrapped rights line, rejoined with the one above it.
                open_group[1] += " " + line.strip()
            else:
                open_group = None

        assert len(rows) == 2
        # The same captured mask, decoded against each row's own recorded
        # type -- the one thing a raw hexadecimal column could not say.
        assert " File " in rows[0][0]
        assert rows[0][1] == [["Rights", "FileGenericRead · FileGenericWrite"]]
        assert " Process " in rows[1][0]
        assert [label for label, _ in rows[1][1]] == ["Type", "Standard"]
        assert rows[1][1][0][1].startswith("Terminate · CreateThread · SetSessionId ·")
        assert rows[1][1][1][1] == "ReadControl · Synchronize"
        # Each row prints the captured mask once, in its own Access
        # column; the derived reading never repeats it.
        assert all("0x0012019f" in row for row, _ in rows)
        assert not any("0x" in group for _row, groups in rows for _label, group in groups)
    finally:
        os.remove(dump_path)


def test_profile_txt_writes_a_real_ansi_free_transcript(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.header = _FakeMinidumpHeader(0)
        mf.sysinfo = SysInfo()
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_txt = str(tmp_path / "out.txt")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--profile", "--txt", out_txt])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        assert os.path.exists(out_txt)
        text = open(out_txt, encoding="utf-8").read()
        assert text
        assert not _ANSI_ESCAPE_RE.search(text)
    finally:
        os.remove(dump_path)


def test_process_json_and_txt_together_both_produced_correctly(monkeypatch, tmp_path):
    from tests.unit.test_process_cmd import _complete_mf
    dump_path = _make_dump_file()
    try:
        mf = _complete_mf()
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        out_txt = str(tmp_path / "out.txt")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--process", "--json", out_json, "--txt", out_txt])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "process"
        assert doc["result"]["coverage"]["status"] == "complete"

        text = open(out_txt, encoding="utf-8").read()
        assert not _ANSI_ESCAPE_RE.search(text)
        # The --txt transcript is the SAME run's console output, so it must
        # show the same process identity the --json document reports --
        # not two independent collections that could disagree.
        assert "4242" in text   # _complete_mf()'s own PID
    finally:
        os.remove(dump_path)


def test_process_txt_path_colliding_with_json_path_is_refused(monkeypatch, tmp_path, capsys):
    same = str(tmp_path / "same.out")
    code = _run(monkeypatch, [str(tmp_path / "sample.dmp"), "--process",
                              "--json", same, "--txt", same])
    assert code == 1
    out = capsys.readouterr().out
    assert "would both write to the same file" in out
    assert "--txt" in out


def test_removed_pid_flag_is_rejected_by_argparse(monkeypatch, capsys):
    # A valid mode flag (--modules) is also given so the mutually-
    # exclusive group's own "one of the arguments ... is required" check
    # doesn't fire first and mask the unrecognized --pid.
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules", "--pid"])
    assert code == 2
    assert "unrecognized arguments: --pid" in capsys.readouterr().err


def test_removed_peb_flag_is_rejected_by_argparse(monkeypatch, capsys):
    code = _run(monkeypatch, ["/nonexistent.dmp", "--modules", "--peb"])
    assert code == 2
    assert "unrecognized arguments: --peb" in capsys.readouterr().err


def test_threads_json_produces_v2_shaped_document_via_command_result_adapter(monkeypatch, tmp_path):
    # threads.py is migrated onto CommandResult (unlike this file's other
    # v2 commands at the time this test was added) -- this proves the
    # real CLI path (cli.main -> _apply_command_result ->
    # V2Output.set_command_result, not the older set_result adapter)
    # actually gets exercised end to end, not just collect_threads()
    # called directly in a unit test.
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--threads", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_PARTIAL == 3   # degraded: no thread_info stream

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == SCHEMA_VERSION
        assert doc["result"]["kind"] == "threads"
        assert doc["result"]["execution_status"] == "completed"
        assert doc["result"]["coverage"]["status"] == "partial"
        assert doc["result"]["coverage"]["reasons"] == [
            "ThreadInfoListStream not present; StartAddress/CreateTime/ExitTime/KernelTime/"
            "UserTime unavailable (TID/SuspendCount/Priority/TEB only)",
            "ModuleListStream not present; thread backing-module classification unavailable "
            "(cannot confirm whether a start address is backed by a known module)",
        ]
        assert doc["result"]["data"]["records"][0]["tid"] == 1
        assert doc["artifacts"] == []
        assert doc["diagnostics"] == {"warnings": [], "errors": []}
    finally:
        os.remove(dump_path)


def test_sysinfo_missing_streams_json_produces_v2_shaped_document_via_command_result_adapter(
        monkeypatch, tmp_path):
    # sysinfo.py's collect_sysinfo is migrated onto CommandResult -- the
    # last of the six original recon commands to migrate. Proves the real
    # CLI path (cli.main -> _apply_command_result ->
    # V2Output.set_command_result) for the "all five sources missing"
    # case, whose five dedicated codes never render as not_evaluated
    # (dump_file is always real).
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # sysinfo/misc_info/peb/threads/modules all absent
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--sysinfo", "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_PARTIAL == 3

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "sysinfo"
        assert doc["result"]["execution_status"] == "completed"
        assert doc["result"]["coverage"]["status"] == "partial"
        # §4.7's section order: DUMP's (threads, modules), then SYSTEM
        # INFO's (sysinfo, misc_info), then ENVIRONMENT's (peb).
        assert doc["result"]["coverage"]["reasons"] == [
            "ThreadListStream not present (thread_count unavailable)",
            "ModuleListStream not present (module_count unavailable)",
            "SystemInfoStream not present",
            "MiscInfo stream not present",
            "PEB not available (requires sysinfo + thread list)",
        ]
        assert doc["result"]["data"]["records"][0]["dump_file"] is not None
    finally:
        os.remove(dump_path)


def test_sysinfo_normal_json_produces_complete_status(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.sysinfo = SysInfo()   # SysInfo()'s own default is PROCESSOR_ARCHITECTURE.AMD64
        mf.misc_info = MiscInfo(process_id=1234)
        mf.peb = Peb(0x140000000, r"C:\test.exe")
        mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
        mf.modules = FakeStream([Module(0, 0, "a")], "modules")
        _wire_environment_walk(mf, b"\x00\x00\x00\x00")   # verified-empty environment block
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--sysinfo", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "sysinfo"
        assert doc["result"]["coverage"]["status"] == "complete"
        assert doc["result"]["coverage"]["reasons"] == []
    finally:
        os.remove(dump_path)


def test_diff_json_produces_comparison_document_with_two_evidence_entries(monkeypatch, tmp_path):
    # diff.py's cmd_diff is migrated onto CommandResult via
    # V2Output.from_evidence() -- the multi-dump counterpart to every
    # other test in this file, which all use the single dump_path
    # constructor. open_dump must be PATH-AWARE here (unlike every other
    # test's path-ignoring lambda) since --diff opens two distinct dumps.
    baseline_path = _make_dump_file()
    target_path = _make_dump_file()
    try:
        mf_baseline = FakeMF()
        mf_baseline.modules = FakeStream(
            [Module(0x1000, 0x1000, r"C:\a.dll")], "modules")
        mf_baseline.filename = baseline_path
        mf_target = FakeMF()
        mf_target.modules = FakeStream(
            [Module(0x1000, 0x1000, r"C:\a.dll"), Module(0x2000, 0x1000, r"C:\b.dll")],
            "modules")
        mf_target.filename = target_path
        mfs = {baseline_path: mf_baseline, target_path: mf_target}
        monkeypatch.setattr(cli, "open_dump", lambda path: mfs[path])

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", target_path, "--diff", baseline_path,
                              "--diff-mode", "modules", "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == SCHEMA_VERSION
        assert [e["id"] for e in doc["meta"]["evidence"]] == ["baseline", "target"]
        assert [e["role"] for e in doc["meta"]["evidence"]] == ["baseline", "target"]
        assert [e["file_name"] for e in doc["meta"]["evidence"]] == [
            os.path.basename(baseline_path), os.path.basename(target_path)]
        assert doc["result"]["kind"] == "comparison"
        assert doc["result"]["coverage"]["status"] == "complete"
        added = [r for r in doc["result"]["data"]["records"] if r["change_type"] == "added"]
        assert len(added) == 1
        assert added[0]["entity_type"] == "module"
        assert added[0]["name"] == "b.dll"
    finally:
        os.remove(baseline_path)
        os.remove(target_path)


def test_diff_json_partial_when_one_entity_not_evaluated_among_others_complete(
        monkeypatch, tmp_path):
    # A single not_evaluated entity (ModuleListStream absent on BOTH sides)
    # among otherwise-complete entities (threads/memory) must roll the
    # OVERALL coverage into "partial", not "not_evaluated" outright, and
    # exit code 3 -- combine_coverage_reports' unanimous-not_evaluated-
    # required rule (see dumpex.output.coverage) exercised end to end
    # through the real CLI path (mode="all") for the first time; the
    # collect_comparison()-level version of this rule is already covered
    # directly in tests/unit/test_comparison_cmd.py.
    baseline_path = _make_dump_file()
    target_path = _make_dump_file()
    try:
        mf_baseline = FakeMF()   # ModuleListStream absent
        mf_baseline.thread_info = FakeStream([], "infos")
        mf_baseline.memory_info = FakeStream([], "infos")
        mf_baseline.filename = baseline_path
        mf_target = FakeMF()   # ModuleListStream absent
        mf_target.thread_info = FakeStream([], "infos")
        mf_target.memory_info = FakeStream([], "infos")
        mf_target.filename = target_path
        mfs = {baseline_path: mf_baseline, target_path: mf_target}
        monkeypatch.setattr(cli, "open_dump", lambda path: mfs[path])

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", target_path, "--diff", baseline_path,
                              "--json", out_json])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_PARTIAL == 3

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "comparison"
        assert doc["result"]["coverage"]["status"] == "partial"
        assert doc["result"]["data"]["records"] == []
    finally:
        os.remove(baseline_path)
        os.remove(target_path)


def test_hunt_json_now_produces_v2_4_shaped_document(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--hunt", "injection", "--json", out_json])
        # A bare FakeMF() has no memory/thread streams at all -> injection
        # is NOT_EVALUATED -> exit_code_for("not_evaluated") == 4, same
        # coverage-based exit code the other v2-routed commands already
        # use (see EXIT_NOT_EVALUATED) -- --hunt no longer always exits 0
        # regardless of coverage now that it's v2-routed too.
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["meta"]["schema_version"] == SCHEMA_VERSION
        assert "hunt" not in doc
        assert doc["result"]["kind"] == "hunt"
        assert [r["hunter"] for r in doc["result"]["data"]["records"]] == ["injection"]
    finally:
        os.remove(dump_path)


def _oversized_skip_mf():
    """A minimal `--hunt all`-safe FakeMF with exactly one committed
    MEM_PRIVATE region, real enough for `dumpex.hunt.pipe`'s own memory
    scan to run and (with PIPE_SCAN_MAX shrunk below the region's size,
    see the caller) emit a genuine SCAN_REGION_OVERSIZED_SKIPPED
    limitation -- same fixture shape as tests/hunt/test_pipe_collect.py's
    own test_oversized_region_is_skipped(), reused here so `--hunt all`
    end-to-end (all seven hunters, not just pipe, over ONE shared MF) has
    a real, non-empty metadata-only investigation_actions queue. No
    memory_segments_64/memory_segments stream is set, so the skipped target's
    own file_offset is None (evidence_availability == "not_captured")."""
    region_base = 0x3000000
    regions = [Region(region_base, region_base, 0x10000, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream([], "handles")

    return MF()


def _run_hunt_all_with_oversized_skip(monkeypatch, tmp_path, *, label: str):
    import dumpex.hunt.pipe as pipemod
    import dumpex.hunt.pipe.memory_scan as memory_scan_mod
    from tests.fixtures.fakes import mem_reader

    monkeypatch.setattr(memory_scan_mod, "PIPE_SCAN_MAX", 0x100)
    monkeypatch.setattr(pipemod, "read_region", mem_reader({}))

    dump_path = _make_dump_file()
    try:
        mf = _oversized_skip_mf()
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / f"{label}.json")
        argv = ["dumpex", dump_path, "--hunt", "all", "--json", out_json]
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as exc:
            cli.main()
        exit_code = exc.value.code
        doc = json.loads(open(out_json, encoding="utf-8").read())
        return exit_code, doc
    finally:
        os.remove(dump_path)


@pytest.mark.parametrize("command", [
    ["--hunt", "all"],
    ["--hunt", "injection"],
    ["--modules"],
])
def test_triage_skipped_is_rejected_before_io_rules_or_scans(
        monkeypatch, tmp_path, capsys, command):
    json_path = tmp_path / "result.json"
    txt_path = tmp_path / "result.txt"
    output_path = tmp_path / "result.bin"

    def forbidden(*_args, **_kwargs):
        raise AssertionError("preflight rejection must happen before runtime work")

    monkeypatch.setattr(cli, "open_dump", forbidden)
    monkeypatch.setattr(cli, "configure_rules_source", forbidden)
    monkeypatch.setattr(cli, "get_rules", forbidden)
    monkeypatch.setattr(cli, "cmd_hunt", forbidden)
    monkeypatch.setattr(sys, "argv", [
        "dumpex", str(tmp_path / "missing.dmp"), *command,
        "--triage-skipped", "--rules-file", str(tmp_path / "rules.yaml"),
        "--json", str(json_path), "--txt", str(txt_path),
        "--output", str(output_path),
    ])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2
    stderr = " ".join(capsys.readouterr().err.split())
    assert "--triage-skipped is temporarily unavailable" in stderr
    assert "cannot close hunter-specific coverage gaps" in stderr
    assert not json_path.exists()
    assert not txt_path.exists()
    assert not output_path.exists()


def test_hunt_all_default_investigation_queue_remains_metadata_only(
        monkeypatch, tmp_path, capsys):
    exit_code, doc = _run_hunt_all_with_oversized_skip(
        monkeypatch, tmp_path, label="baseline")

    assert exit_code == cli.EXIT_PARTIAL == 3
    coverage = dict(doc["result"]["coverage"])
    missed = coverage.pop("missed_bytes")
    assert coverage == {"status": "partial", "reasons": [], "sources": {}, "limitations": []}
    # The document-level rollup measures the RECORDS' gaps, not its own
    # (deliberately empty) limitations. Every gap this dump produces names
    # a region it captured no bytes for, so each is measured and each
    # measures zero -- an exact "nothing capturable was missed", not an
    # unknown. How MANY such gaps there are depends on which hunters this
    # build can run (yara needs yara-python), so the count is not pinned
    # here; what is pinned is that they are all measured and all zero.
    assert missed["state"] == "exact"
    assert missed["bytes"] == 0
    assert missed["complete"] is True
    assert missed["unquantified_gaps"] == 0
    assert missed["distinct_ranges"] == 0
    assert missed["quantified_gaps"] >= 1
    assert doc["result"]["summary"]["overall_status"] == "INCONCLUSIVE"
    assert doc["meta"]["execution"]["options"]["triage_skipped"] is False
    actions = doc["result"]["summary"]["investigation_actions"]
    assert len(actions) == 1
    assert actions[0]["triage"] == {
        "mode": "metadata", "status": "completed", "bytes_examined": 0,
        "region_fully_examined": False, "content_reason_codes": [],
        "findings": [], "finding_count": 0, "findings_truncated": False,
    }
    console = capsys.readouterr().out
    assert "Deep triage:" not in console
    assert "Deep triage found:" not in console
    assert "DEEP TRIAGE NOTES" not in console


def test_threads_degraded_exits_with_partial_code_even_without_json(monkeypatch):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")   # no thread_info -> degraded
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--threads"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_PARTIAL == 3
    finally:
        os.remove(dump_path)


def test_modules_complete_coverage_exits_zero(monkeypatch):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.modules = FakeStream([], "modules")   # stream present (not missing) -> "complete"
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--modules"])
        cli.main()   # must NOT raise SystemExit at all (falsy EXIT_OK)
    finally:
        os.remove(dump_path)


def test_modules_stream_missing_exits_not_evaluated(monkeypatch):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()   # ModuleListStream entirely absent
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)
        monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--modules"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4
    finally:
        os.remove(dump_path)


# ── --redact-paths for --process/--handles/--profile (issue #44: the      ─
#    mechanism itself is command-agnostic (StructuredOutput redacts        │
#    meta.evidence[].path regardless of which command produced the         │
#    document -- already proven for modules/hunt_stomping/hunt_yara in     │
#    tests/integration/test_json_metadata.py) -- these prove it isn't      │
#    accidentally bypassed for the three v2.13 commands specifically. ──────

def test_process_redact_paths_hides_absolute_dump_path(monkeypatch, tmp_path):
    from tests.unit.test_process_cmd import _complete_mf
    dump_path = _make_dump_file()
    try:
        mf = _complete_mf()
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--process", "--redact-paths",
                              "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "process"
        assert "path" not in doc["meta"]["evidence"][0]
        assert doc["meta"]["evidence"][0]["file_name"] == os.path.basename(dump_path)
        assert os.path.dirname(dump_path) not in json.dumps(doc)
    finally:
        os.remove(dump_path)


def test_handles_redact_paths_hides_absolute_dump_path(monkeypatch, tmp_path):
    from tests.fixtures.fakes import Handle
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.handles = FakeStream(
            [Handle(0x10, "File", r"\Device\HarddiskVolume1\notes.txt")], "handles")
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--handles", "--redact-paths",
                              "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "handles"
        assert "path" not in doc["meta"]["evidence"][0]
        assert doc["meta"]["evidence"][0]["file_name"] == os.path.basename(dump_path)
        assert os.path.dirname(dump_path) not in json.dumps(doc)
    finally:
        os.remove(dump_path)


def test_profile_redact_paths_hides_absolute_dump_path(monkeypatch, tmp_path):
    dump_path = _make_dump_file()
    try:
        mf = FakeMF()
        mf.header = _FakeMinidumpHeader(0)
        mf.sysinfo = SysInfo()
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--profile", "--redact-paths",
                              "--json", out_json])
        cli.main()   # no SystemExit -- coverage is complete, exit code 0

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "profile"
        assert "path" not in doc["meta"]["evidence"][0]
        assert doc["meta"]["evidence"][0]["file_name"] == os.path.basename(dump_path)
        assert os.path.dirname(dump_path) not in json.dumps(doc)
    finally:
        os.remove(dump_path)


# ── --handles: SourceState.FAILED (stream present but unparseable) through ─
#    the real CLI, with --verbose --txt engaged -- tests/unit/            │
#    test_handles_cmd.py already covers this state at the collect_handles()│
#    level (test_parse_failure_is_never_a_clean_zero_handle_result); this  │
#    proves the same state also renders cleanly (no crash, no ANSI) through│
#    the verbose console/--txt path, not only the default one. ────────────

def test_handles_failed_stream_verbose_txt_renders_without_crashing(monkeypatch, tmp_path):
    from tests.unit.test_handles_cmd import _mf as _handles_mf
    detail = "HandleStreamFramingError: HandleDataStream SizeOfDescriptor 33 is neither 32 nor 40"
    dump_path = _make_dump_file()
    try:
        mf = _handles_mf(failure=detail)
        monkeypatch.setattr(cli, "open_dump", lambda path: mf)

        out_json = str(tmp_path / "out.json")
        out_txt = str(tmp_path / "out.txt")
        monkeypatch.setattr(sys, "argv",
                             ["dumpex", dump_path, "--handles", "--verbose",
                              "--json", out_json, "--txt", out_txt])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_NOT_EVALUATED == 4

        doc = json.loads(open(out_json, encoding="utf-8").read())
        assert doc["result"]["kind"] == "handles"
        assert doc["result"]["coverage"]["status"] == "not_evaluated"
        assert doc["result"]["coverage"]["sources"]["handles"]["state"] == "failed"
        assert detail in doc["result"]["coverage"]["sources"]["handles"]["detail"]

        text = open(out_txt, encoding="utf-8").read()
        assert not _ANSI_ESCAPE_RE.search(text)
        assert "HandleDataStream present but could not be read" in text
    finally:
        os.remove(dump_path)

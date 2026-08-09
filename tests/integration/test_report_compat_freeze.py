"""
Compatibility-freeze suite for `--report` (Phase E, PR3) -- the hardest of
the three Phase E migrations (a 357-line, self-recursive, three-trigger-
mode alert-triage command with zero pre-existing tests). Every scenario
runs the real `cli.main()` end to end against a FakeMF and asserts exit
code, the full console text, and the JSON document's kind/coverage/record
shape -- same discipline as test_extract_strings_compat_freeze.py.

Expected console text was captured by actually running the ORIGINAL
(pre-migration) `cmd_report` via a scratchpad script (see the Phase E
plan's own capture-script discipline note) before report.py was
flattened, not hand-guessed.

Every scenario here supplies modules=[]/threads=[]/regions=[...] (all
three admin sources genuinely present, even if empty), so
result.coverage.status stays "complete" and no coverage.reasons lines
print -- keeping the console-body assertion exactly byte-identical to the
captured ground truth. The NEW coverage-visibility behavior (printing
coverage.reasons when a source genuinely IS absent, the same convention
already established for --extract/--strings) is covered separately in
tests/unit/test_report_cmd.py, not duplicated here.
"""
import datetime
import json
import os
import sys

import pytest

import dumpex.cli as cli
import dumpex.output.collector as collector_mod
import dumpex.commands.report as report_mod
import dumpex.core.memory as core_memory_mod
from dumpex.rules_pkg.loader import configure_rules_source
from tests.fixtures.fakes import FakeMF, FakeStream, Module, Region, ThreadInfo, mem_reader


class _FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2024, 1, 1, tzinfo=tz)


_real_timezone = datetime.timezone
_real_timedelta = datetime.timedelta


class _FrozenDateTimeModule:
    datetime = _FixedDateTime
    timezone = _real_timezone
    timedelta = _real_timedelta


def _run(monkeypatch, tmp_path, argv_extra, *, modules=None, threads=None, regions=None,
         read_map=None):
    monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(collector_mod, "datetime", _FrozenDateTimeModule)
    configure_rules_source(None)   # force a fresh "Rules loaded" print, like a real process

    dump_path = str(tmp_path / "test.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(b"synthetic dump content")
    mf = FakeMF()
    mf.filename = dump_path
    mf.modules = FakeStream(modules if modules is not None else [], "modules")
    mf.thread_info = FakeStream(threads if threads is not None else [], "infos")
    mf.memory_info = FakeStream(regions if regions is not None else [], "infos")
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)
    if read_map:
        reader = mem_reader(read_map)
        monkeypatch.setattr(report_mod, "read_region", reader)
        monkeypatch.setattr(core_memory_mod, "read_region", reader)

    out_json = str(tmp_path / "out.json")
    argv = ["dumpex", dump_path, "--report", *argv_extra, "--json", out_json, "--force"]
    monkeypatch.setattr(sys, "argv", argv)

    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    doc = json.loads(open(out_json, encoding="utf-8").read())
    return exit_code, doc


def _split_console_body(console_text: str) -> str:
    write_start = console_text.find("  [·] JSON written")
    assert write_start != -1, "missing JSON write confirmation line"
    return console_text[:write_start]


def test_tid_not_found(monkeypatch, tmp_path, capsys):
    exit_code, doc = _run(
        monkeypatch, tmp_path, ["--report-tid", "5"],
        threads=[ThreadInfo(1, 0x1000)])
    body = _split_console_body(capsys.readouterr().out)
    assert body == (
        "  [·] Rules loaded from <dumpex.rules_pkg>/data/rules.yaml  "
        "(sha256_prefix=f4b1140fc4606821…)\n"
        "\n══════════════════════════════════════════\n"
        "  dumpex TRIAGE REPORT\n"
        "══════════════════════════════════════════\n"
        "  File : test.dmp\n"
        "  TID  : 5\n"
        "\n[ 1 ] THREAD ANALYSIS\n"
        "──────────────────────────────────────────────────\n"
        "  [!] TID 0x5 not found in dump.\n"
        "      Thread may have exited before dump was taken.\n"
        "\n[ VERDICT ]\n"
        "──────────────────────────────────────────────────\n"
        "  CLEAN — no suspicious indicators found\n\n\n"
    )
    assert exit_code == 0
    assert doc["meta"]["schema_version"] == "2.9"
    assert doc["result"]["kind"] == "report"
    assert doc["result"]["coverage"]["status"] == "complete"
    assert len(doc["result"]["data"]["records"]) == 1
    rec = doc["result"]["data"]["records"][0]
    assert rec["anchor_tid"] == 5
    assert rec["thread"] is None
    warnings = doc["diagnostics"]["warnings"]
    assert any(w["code"] == "REPORT_TID_NOT_FOUND" for w in warnings)


def test_addr_not_found(monkeypatch, tmp_path, capsys):
    exit_code, doc = _run(
        monkeypatch, tmp_path, ["--report-addr", "0x9999000"])
    body = _split_console_body(capsys.readouterr().out)
    assert body == (
        "  [·] Rules loaded from <dumpex.rules_pkg>/data/rules.yaml  "
        "(sha256_prefix=f4b1140fc4606821…)\n"
        "\n══════════════════════════════════════════\n"
        "  dumpex TRIAGE REPORT\n"
        "══════════════════════════════════════════\n"
        "  File : test.dmp\n"
        "  Addr : 0x9999000\n"
        "\n[ 2 ] MEMORY REGION AT TARGET ADDRESS\n"
        "──────────────────────────────────────────────────\n"
        "  [!] No committed region found at 0x9999000\n"
        "      Address may not be in a page captured by this dump.\n"
        "\n[ VERDICT ]\n"
        "──────────────────────────────────────────────────\n"
        "  CLEAN — no suspicious indicators found\n\n\n"
    )
    assert exit_code == 0
    assert doc["result"]["coverage"]["status"] == "complete"


def test_verdict_suspicious_rwx_private(monkeypatch, tmp_path, capsys):
    # Padded to the full 0x1000 region size -- a short read is itself now a
    # coverage-affecting fact (see the P1-3 review fix / tests/unit/
    # test_report_cmd.py's own coverage matrix tests), and this test's own
    # purpose is the verdict/console text, not read-truncation semantics.
    exit_code, doc = _run(
        monkeypatch, tmp_path, ["--report-addr", "0x6000"],
        regions=[Region(0x6000, 0x6000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        read_map={0x6000: (b"boring data here nothing to see").ljust(0x1000, b"\x00")})
    body = _split_console_body(capsys.readouterr().out)
    assert "SUSPICIOUS — 1 independent indicator" in body
    assert "RWX + MEM_PRIVATE" in body
    assert exit_code == 0
    rec = doc["result"]["data"]["records"][0]
    assert rec["verdict"] == "SUSPICIOUS"
    assert rec["findings"] == ["rwx_private"]
    assert rec["region"]["is_rwx_private"] is True


def test_verdict_high_confidence_malicious(monkeypatch, tmp_path, capsys):
    ioc_data = (b"MZ" + b"\x90" * 62
                + b"cmd.exe /c powershell -enc ZZZZZZZZZZZZZZZZZZ" + b"\x00" * 20)
    exit_code, doc = _run(
        monkeypatch, tmp_path, ["--report-addr", "0x8000"],
        regions=[Region(0x8000, 0x8000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        read_map={0x8000: ioc_data})
    body = _split_console_body(capsys.readouterr().out)
    assert "HIGH CONFIDENCE MALICIOUS — 3 independent indicators" in body
    rec = doc["result"]["data"]["records"][0]
    assert rec["verdict"] == "HIGH_CONFIDENCE_MALICIOUS"
    assert set(rec["findings"]) == {"rwx_private", "injected_pe", "ioc_strings"}


def test_string_mode_one_private_hit(monkeypatch, tmp_path, capsys):
    # Padded to the full 0x1000 region size -- see
    # test_verdict_suspicious_rwx_private's own note on why.
    exit_code, doc = _run(
        monkeypatch, tmp_path, ["--report-string", "MYSECRETNEEDLE12"],
        regions=[Region(0xa000, 0xa000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
        read_map={0xa000: (b"header MYSECRETNEEDLE12 trailer" + b"\x00" * 20).ljust(0x1000, b"\x00")})
    body = _split_console_body(capsys.readouterr().out)
    assert "Searching memory for: 'MYSECRETNEEDLE12'" in body
    assert "[+] Found in 1 region(s):" in body
    assert "dumpex TRIAGE REPORT" in body
    assert exit_code == 0
    assert doc["result"]["summary"]["mode"] == "string"
    assert doc["result"]["summary"]["card_count"] == 1
    assert len(doc["result"]["data"]["records"]) == 1
    assert doc["result"]["data"]["records"][0]["anchor_source"] == "string_hit"


def test_string_mode_zero_hits_exits_zero_with_diagnostic(monkeypatch, tmp_path, capsys):
    # Padded to the full 0x1000 region size -- see
    # test_verdict_suspicious_rwx_private's own note on why (a short read
    # is itself now a coverage-affecting fact, and this test's own purpose
    # is the zero-hit path, not truncation semantics).
    exit_code, doc = _run(
        monkeypatch, tmp_path, ["--report-string", "TOTALLYABSENTNEEDLE"],
        regions=[Region(0x9000, 0x9000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
        read_map={0x9000: b"nothing interesting at all here".ljust(0x1000, b"\x00")})
    body = _split_console_body(capsys.readouterr().out)
    assert "String not found in the memory regions that could be scanned." in body
    assert exit_code == 0
    assert doc["result"]["data"]["records"] == []
    warnings = doc["diagnostics"]["warnings"]
    assert any(w["code"] == "REPORT_STRING_NOT_FOUND" for w in warnings)


def test_tid_resolved_to_module_shows_module_range(monkeypatch, tmp_path, capsys):
    exit_code, doc = _run(
        monkeypatch, tmp_path, ["--report-tid", "9"],
        modules=[Module(0x2000, 0x1000, r"C:\Windows\System32\ntdll.dll")],
        threads=[ThreadInfo(9, 0x2000)])
    body = _split_console_body(capsys.readouterr().out)
    assert "Backed By" in body
    assert r"C:\Windows\System32\ntdll.dll" in body
    assert "Module Range" in body
    assert "0x2000" in body and "0x3000" in body
    assert exit_code == 0
    rec = doc["result"]["data"]["records"][0]
    assert rec["thread"]["module_context"] == "resolved"
    assert rec["thread"]["backing_module_base"] == "0x0000000000002000"
    assert rec["thread"]["backing_module_end"] == "0x0000000000003000"


def test_section3_sharing_threads_and_network_pattern_hexdump(monkeypatch, tmp_path, capsys):
    # Exercises two console-only branches with no other coverage: Section
    # 3's "other threads executing in this region" listing (a second
    # unregistered thread sharing the anchor's region), and the
    # network-pattern IOC hit's ±128-byte hexdump context (an IP address
    # embedded in the IOC string, matching NET_PATTERNS on top of
    # IOC_PATTERNS).
    # Padded to the full 0x1000 region size -- see
    # test_verdict_suspicious_rwx_private's own note on why.
    ioc_data = (b"cmd.exe /c curl 10.0.0.5:8080/beacon" + b"\x00" * 200).ljust(0x1000, b"\x00")
    exit_code, doc = _run(
        monkeypatch, tmp_path, ["--report-tid", "5", "--report-addr", "0x4000"],
        threads=[ThreadInfo(5, 0x4000), ThreadInfo(6, 0x4100)],
        regions=[Region(0x4000, 0x4000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")],
        read_map={0x4000: ioc_data})
    body = _split_console_body(capsys.readouterr().out)
    assert "[ 3 ] THREADS EXECUTING IN THIS REGION" in body
    assert "TID=0x6" in body
    assert "← report TID" in body
    assert "Network pattern" in body
    assert exit_code == 0
    rec = doc["result"]["data"]["records"][0]
    assert len(rec["other_threads_in_region"]) == 2   # includes the anchor itself
    assert rec["ioc_strings"][0]["is_network_pattern"] is True


def test_report_requires_at_least_one_anchor(monkeypatch, tmp_path, capsys):
    # sys.exit(1) fires before any structured output is ever written --
    # unlike every other scenario in this suite, out_json never
    # get created, so this can't go through the shared _run() helper
    # (which assumes both files exist once cli.main() returns/raises).
    configure_rules_source(None)
    dump_path = str(tmp_path / "test.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(b"synthetic dump content")
    mf = FakeMF()
    mf.filename = dump_path
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)
    monkeypatch.setattr(sys, "argv", ["dumpex", dump_path, "--report"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    err = capsys.readouterr().out
    assert "requires at least one of" in err

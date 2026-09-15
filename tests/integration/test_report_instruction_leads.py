"""How `--report` presents an instruction window an analyst has to act on.

These are console assertions, deliberately. The decode-stop location and
the static-analysis lead are presentation state: neither is part of the
JSON contract, and one test here pins that the published document is
unchanged by both.

Two facts have to reach the console without being confused for each
other. WHERE linear decoding ended is one line; WHY it ended there is a
separate limitation sentence, because three different reasons end a
decode short of the window -- an undecodable byte mid-window, an
incomplete instruction at the end of the capture, and the 512-byte cap
cutting a real instruction. A summary that named one of them would
contradict the other two.

The second is that a window carrying a recognizable instruction shape
says so in the ASSESSMENT block, beside the findings and visibly not one
of them, under a name that claims only what its own rule established.

Collector-level semantics, including the lead ladder's demotions, are
tests/unit/test_report_pe_enrichment.py.
"""
import datetime
import json
import re
import sys

import pytest

import dumpex.cli as cli
import dumpex.commands.report as report_mod
import dumpex.core.memory as core_memory_mod
import dumpex.output.collector as collector_mod
from dumpex.core.disasm import MAX_DECODE_BYTES, disasm_available
from dumpex.rules_pkg.loader import configure_rules_source
from tests.fixtures.fakes import (
    Ctx, EnvBufferedReader, EnvReader, FakeMF, FakeStream, Module, Region, Segment,
    SysInfo, Thread, ThreadInfo, mem_reader,
)

REGION_BASE = 0x1000
REGION_SIZE = 0x1000
ANCHOR_TID = 0x11

_needs_capstone = pytest.mark.skipif(not disasm_available(),
                                     reason="no disassembler backend installed")

# A call/pop pair leaves this code's own address in rax, an in-place xor
# transforms bytes at it, a backward branch closes the loop around that
# write, and control leaves through a register.
SELF_DECODING_STUB = bytes.fromhex(
    "e800000000" "58" "4883c010" "803041" "48ffc0" "4883e901" "75f4" "ffd0" "c3")

# Seven multi-byte NOPs, then 0x06 -- invalid in 64-bit mode -- for the
# rest of the region: decoding stops 70 bytes in, 442 short of the cap.
_NOP11 = b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00"
STOPS_AT_70_BYTES = _NOP11 * 6 + b"\x0f\x1f\x40\x00" + b"\x06" * (REGION_SIZE - 70)

# 46 eleven-byte NOPs reach offset 506, then a seven-byte call crosses
# the 512-byte cap: decoding ends at 506 because of the boundary, and the
# six bytes after it are a recognised instruction prefix, not unread
# bytes.
STOPS_AT_THE_BYTE_CAP = (_NOP11 * 46 + b"\xff\x14\x25\x11\x22\x33\x44"
                         + b"\x90" * (REGION_SIZE - 513))

# A window with no write loop at all: the control case for every lead
# assertion below.
PLAIN_CODE = b"\x48\x83\xc0\x10\x48\xff\xc0\xc3" + b"\x90" * (REGION_SIZE - 8)


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


def _build_mf(tmp_path, code):
    dump_path = str(tmp_path / "test.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(b"synthetic dump content")
    mf = FakeMF()
    mf.filename = dump_path
    # One loaded module, so an address outside it resolves as positively
    # unregistered rather than as "no module list was available".
    mf.modules = FakeStream([Module(0x140000000, 0x4000, "app.exe")], "modules")
    mf.thread_info = FakeStream([ThreadInfo(ANCHOR_TID, REGION_BASE)], "infos")
    mf.memory_info = FakeStream([
        Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
               "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")], "infos")
    # The instruction window is read through the dump's own reader, not
    # the command-level one the string scan uses, so both are populated
    # with the same bytes.
    mf.memory_segments_64 = FakeStream([Segment(REGION_BASE, 0, len(code))],
                                       "memory_segments")
    # The anchor is in unbacked private memory and the card is
    # address-anchored, so the decode width comes from the dump's own
    # SystemInfo -- the last signal in the architecture chain.
    mf.sysinfo = SysInfo()
    mf._reader = EnvReader(EnvBufferedReader({REGION_BASE: code}))
    mf.directories = []
    mf._dumpex_stream_failures = {}
    return mf, dump_path


def _with_anchor_thread(mf):
    """Give the dump a thread whose context points into the region, so a
    `--report-tid` card carries a correlated thread. `Teb` is present and
    null: the environment-block walk reads it, fails cleanly, and reports
    that rather than raising."""
    thread = Thread(ANCHOR_TID, Ctx(REGION_BASE))
    thread.Teb = 0
    mf.threads = FakeStream([thread], "threads")
    return mf


def _run(monkeypatch, tmp_path, code, *, argv_extra=None, with_thread=False):
    code = code.ljust(REGION_SIZE, b"\x00")
    mf, dump_path = _build_mf(tmp_path, code)
    if with_thread:
        _with_anchor_thread(mf)
    monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(collector_mod, "datetime", _FrozenDateTimeModule)
    configure_rules_source(None)
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)
    reader = mem_reader({REGION_BASE: code})
    monkeypatch.setattr(report_mod, "read_region", reader)
    monkeypatch.setattr(core_memory_mod, "read_region", reader)

    out_json = str(tmp_path / "out.json")
    argv_extra = ["--report-addr", hex(REGION_BASE)] if argv_extra is None else argv_extra
    monkeypatch.setattr(sys, "argv",
                        ["dumpex", dump_path, "--report", *argv_extra,
                         "--json", out_json, "--force"])
    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    with open(out_json, encoding="utf-8") as fh:
        return exit_code, json.load(fh)


def _assessment(console_text: str) -> str:
    start = console_text.index("ASSESSMENT")
    return console_text[start:console_text.index("COVERAGE SUMMARY", start)]


# Every section header is immediately followed by its own full-width rule
# line, so one block runs to the line before the next such rule.
_HEADER_RULE = re.compile("\n([─=]{50})\n")


def _instruction_block(console_text: str) -> str:
    start = console_text.index("INSTRUCTION CONTEXT")
    body_start = _HEADER_RULE.search(console_text, start).end()
    next_rule = _HEADER_RULE.search(console_text, body_start)
    if next_rule is None:
        return console_text[body_start:]
    return console_text[body_start:console_text.rfind("\n", body_start, next_rule.start())]


def _limitations(doc) -> tuple:
    return tuple(doc["result"]["data"]["records"][0]
                 ["instruction_context"]["section"]["limitations"])


# ── where decoding ended, and why, kept apart ───────────────────────────

@_needs_capstone
def test_a_stop_short_of_the_cap_names_its_address_and_not_the_cap(
        monkeypatch, tmp_path, capsys):
    _exit_code, doc = _run(monkeypatch, tmp_path, STOPS_AT_70_BYTES)
    block = _instruction_block(capsys.readouterr().out)

    assert f"0x{REGION_BASE + 70:016x}" in block
    assert f"70/{MAX_DECODE_BYTES} byte(s) decoded" in block

    (stop_note,) = [note for note in _limitations(doc) if "linear decoding stopped" in note]
    assert f"not the {MAX_DECODE_BYTES}-byte cap" in stop_note
    assert "cut short" not in stop_note
    assert f"{MAX_DECODE_BYTES - 70} byte(s) were not decoded" in stop_note
    # The cap is a real, separate limit on this window and keeps its own
    # sentence; it is never the reason decoding stopped where it did.
    assert any("the region holds more than the" in note for note in _limitations(doc))


@_needs_capstone
def test_a_boundary_stop_never_calls_its_recognised_tail_unevaluated(
        monkeypatch, tmp_path, capsys):
    """Decoding ends at 506 of 512 because an instruction crosses the
    cap. Those last six bytes WERE evaluated -- they are a recognised
    instruction prefix -- so nothing in the block may describe them as
    unevaluated, unread, or not decoded. The summary states only where
    decoding ended; the cap sentence explains it."""
    _exit_code, doc = _run(monkeypatch, tmp_path, STOPS_AT_THE_BYTE_CAP)
    block = _instruction_block(capsys.readouterr().out)

    assert f"506/{MAX_DECODE_BYTES} byte(s) decoded" in block
    assert f"0x{REGION_BASE + 506:016x}" in block
    summary = [line for line in block.splitlines() if "byte(s) decoded" in line]
    assert len(summary) == 1
    for contradiction in ("not evaluated", "were not decoded", "the rest"):
        assert contradiction not in summary[0]

    (cap_note,) = [note for note in _limitations(doc)
                   if "linear decoding ran the whole" in note]
    assert "beginning an instruction that crosses it" in cap_note
    assert all("invalid opcode" not in note for note in _limitations(doc))


@_needs_capstone
def test_the_listing_says_it_is_linear_and_not_an_executed_path(
        monkeypatch, tmp_path, capsys):
    """Rows are printed in byte order from the anchor. A reader must not
    take the row after a branch as the branch's successor, and must not
    take every row as an instruction the code reaches."""
    _run(monkeypatch, tmp_path, SELF_DECODING_STUB)
    block = _instruction_block(capsys.readouterr().out)
    assert "linear decode" in block and "not an" in block and "executed path" in block
    assert "may be data" in block


@_needs_capstone
def test_a_branch_target_no_module_owns_is_placed_by_its_region(
        monkeypatch, tmp_path, capsys):
    _exit_code, doc = _run(monkeypatch, tmp_path, SELF_DECODING_STUB)
    block = _instruction_block(capsys.readouterr().out)
    targets = doc["result"]["data"]["records"][0]["instruction_context"]["branch_targets"]

    assert [t for t in targets if t["kind"] == "direct"]
    assert "MEM_PRIVATE (unregistered)" in block
    # No branch-target row falls back to the unknown mark: a destination
    # in private memory is placed, and a register-indirect branch says it
    # has no static destination at all.
    target_rows = [line for line in block.splitlines()
                   if line.strip().startswith(("direct", "indirect_register"))]
    assert len(target_rows) == len(targets)
    assert all(not line.rstrip().endswith(" ?") for line in target_rows)
    assert "destination is run-time state" in block


# ── the lead reaches the assessment, and changes nothing there ──────────

@_needs_capstone
def test_the_stub_lead_is_surfaced_in_the_assessment_and_next_steps(
        monkeypatch, tmp_path, capsys):
    _run(monkeypatch, tmp_path, SELF_DECODING_STUB)
    assessment = _assessment(capsys.readouterr().out)

    assert "Static-analysis leads" in assessment
    assert "possible position-independent self-decoding stub" in assessment
    assert "not findings" in assessment

    next_block = assessment[assessment.index("Next:"):]
    assert "extract the region and analyse it offline" in next_block
    assert "not that it ran" in next_block


@_needs_capstone
def test_a_plain_transform_loop_is_not_called_a_self_decoding_stub(
        monkeypatch, tmp_path, capsys):
    """The console name is the collector's name. A loop with no get-PC
    evidence reaches the analyst as a transform loop and nothing more."""
    #   xor byte ptr [rbx], 0x41 / inc rbx / dec rcx / jne back / ret
    code = bytes.fromhex("803341" "48ffc3" "48ffc9" "75f5" "c3")
    _run(monkeypatch, tmp_path, code)
    assessment = _assessment(capsys.readouterr().out)
    assert "possible in-place memory transform loop" in assessment
    assert "self-decoding" not in assessment
    assert "position-independent" not in assessment


@_needs_capstone
def test_the_next_step_does_not_invent_a_thread_the_card_has_not_got(
        monkeypatch, tmp_path, capsys):
    """An address-anchored card carries no correlated thread, so the
    advice cannot tell an analyst to read "the anchor thread's" start
    address. It says what to establish instead, and still names the
    region-level step, which needs no thread."""
    _exit_code, doc = _run(monkeypatch, tmp_path, SELF_DECODING_STUB)
    assessment = _assessment(capsys.readouterr().out)
    assert doc["result"]["data"]["records"][0]["anchor_tid"] is None

    next_block = assessment[assessment.index("Next:"):]
    assert "no thread is correlated with this card" in next_block
    assert "which thread or control flow reaches this region" in next_block
    assert "anchor thread" not in next_block
    assert "extract the region and analyse it offline" in next_block


@_needs_capstone
def test_the_next_step_names_the_thread_when_the_card_has_one(
        monkeypatch, tmp_path, capsys):
    """A `--report-tid` card does correlate a thread, and the advice then
    names it rather than telling the analyst to go and find one."""
    _exit_code, doc = _run(monkeypatch, tmp_path, SELF_DECODING_STUB,
                           argv_extra=["--report-tid", str(ANCHOR_TID)], with_thread=True)
    assessment = _assessment(capsys.readouterr().out)
    assert doc["result"]["data"]["records"][0]["anchor_tid"] == ANCHOR_TID

    next_block = assessment[assessment.index("Next:"):]
    assert f"TID 0x{ANCHOR_TID:x}'s start address" in next_block
    assert "no thread is correlated" not in next_block
    assert "extract the region and analyse it offline" in next_block


@_needs_capstone
def test_a_lead_moves_no_verdict_finding_or_exit_code(monkeypatch, tmp_path, capsys):
    """The same RWX private region, with and without the stub: the lead
    appears, and the verdict, the finding set, the indicator count, and
    the exit code are identical."""
    stub_exit, stub_doc = _run(monkeypatch, tmp_path, SELF_DECODING_STUB)
    stub_out = capsys.readouterr().out
    plain_exit, plain_doc = _run(monkeypatch, tmp_path, PLAIN_CODE)
    plain_out = capsys.readouterr().out

    assert "Static-analysis leads" in _assessment(stub_out)
    assert "Static-analysis leads" not in _assessment(plain_out)

    stub_card = stub_doc["result"]["data"]["records"][0]
    plain_card = plain_doc["result"]["data"]["records"][0]
    assert stub_exit == plain_exit
    assert stub_card["verdict"] == plain_card["verdict"]
    assert stub_card["findings"] == plain_card["findings"]
    assert stub_card["finding_details"] == plain_card["finding_details"]
    assert stub_doc["result"]["coverage"]["status"] == plain_doc["result"]["coverage"]["status"]

    # The lead is not counted as an indicator: the verdict line, which
    # carries the count, is the same line in both runs.
    verdict_line = re.compile(r"^\s*(CLEAN|SUSPICIOUS|LIKELY MALICIOUS|"
                              r"HIGH CONFIDENCE MALICIOUS).*$", re.MULTILINE)
    assert (verdict_line.search(_assessment(stub_out)).group(0)
            == verdict_line.search(_assessment(plain_out)).group(0))


@_needs_capstone
def test_presentation_state_stays_out_of_the_published_document(
        monkeypatch, tmp_path, capsys):
    """The decode-stop location and the lead are console output. The JSON
    contract is closed and unchanged: a consumer pinned to the published
    schema sees the same keys it saw before."""
    _exit_code, doc = _run(monkeypatch, tmp_path, SELF_DECODING_STUB)
    assert "Static-analysis leads" in _assessment(capsys.readouterr().out)

    context = doc["result"]["data"]["records"][0]["instruction_context"]
    for absent in ("bytes_decoded", "decode_stop_address", "leads"):
        assert absent not in context
    for target in context["branch_targets"]:
        assert "in_window_region" not in target

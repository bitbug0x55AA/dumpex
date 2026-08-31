"""`--hunt <TTP> --hunt-addr ADDR --size SIZE` end to end.

The targeted rescan is one atomic public surface: the flag combination, the
capability decision, the range arithmetic, the console card, the structured
document, and the exit code all have to agree, and the full-scope shapes around
them have to stay exactly where they were. This file drives the real
`cli.main()` against synthetic dumps and pins all of that.

Validation ordering matters as much as the outcomes: everything a targeted
invocation can be refused for is decided BEFORE the dump is opened, so an
unsupported hunter or an impossible range never reaches a scanner.
"""
import json

import pytest

jsonschema = pytest.importorskip("jsonschema")

import dumpex.cli as cli
import dumpex.hunt.encoding.targeted as encoding_targeted
import dumpex.hunt.pipe.targeted as pipe_targeted
import dumpex.hunt.stomping.targeted as stomping_targeted
from dumpex.schemas import CURRENT_SCHEMA, schema_path

from tests.fixtures.fakes import FakeMF, FakeReader, FakeStream, Region, Segment
from tests.fixtures.hunt_cli_harness import run_cli

_BASE = 0x10000000
_SIZE = 0x2000
_FILE_OFFSET = 0x3000
_STRONG_TOKEN = b"meterpreter-stage\x00"


@pytest.fixture(scope="module")
def validator():
    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        return jsonschema.Draft202012Validator(json.load(fh))


def _payload(size=_SIZE, token=_STRONG_TOKEN, offset=0x200):
    data = bytearray(b"\x00" * size)
    if token is not None:
        data[offset:offset + len(token)] = token
    return bytes(data)


def _mf(*, regions=None, segments=None, module_list=()):
    """A dump holding one executable MEM_IMAGE allocation, captured in full --
    the shape a targeted stomping or obfuscation rescan is eligible for.

    The keyword is `module_list`, not `modules`: a class body that ASSIGNS a
    name cannot also read the enclosing function's variable of that name."""
    if regions is None:
        regions = [Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]
    if segments is None:
        segments = [Segment(_BASE, _FILE_OFFSET, _SIZE)]

    class MF(FakeMF):
        memory_info = FakeStream(list(regions), "infos")
        memory_segments_64 = FakeStream(list(segments), "memory_segments")
        modules = FakeStream(list(module_list), "modules")
    return MF()


def _reader(captured):
    def _read(mf, addr, size):
        for base, data in captured.items():
            if base <= addr < base + len(data):
                offset = addr - base
                return data[offset:offset + size]
        return b""
    return _read


def _run_stomping(monkeypatch, tmp_path, argv_extra, *, mf=None, captured=None):
    monkeypatch.setattr(stomping_targeted, "read_region_spanning",
                        _reader(captured if captured is not None else {_BASE: _payload()}))
    return run_cli(monkeypatch, tmp_path, argv_extra, mf if mf is not None else _mf())


def _flat(console_text):
    """Console text with every run of whitespace collapsed. The scope statement
    is word-wrapped to the terminal width, so asserting on a sentence has to be
    independent of where it wrapped."""
    return " ".join(console_text.split())


def _record(doc):
    records = doc["result"]["data"]["records"]
    assert len(records) == 1, "a targeted invocation names exactly one analyzer"
    return records[0]


# ── flag relationships (argument shape, exit 2, before the dump opens) ───

def _expect_usage_error(monkeypatch, tmp_path, argv_extra):
    """A targeted argument-shape failure is argparse's own error path: exit 2,
    message on stderr, and no dump ever opened."""
    dump_path = tmp_path / "test.dmp"
    dump_path.write_bytes(b"synthetic dump content")

    def _never(path):
        raise AssertionError("the dump was opened despite an invalid targeted request")

    monkeypatch.setattr(cli, "open_dump", _never)
    monkeypatch.setattr("sys.argv", ["dumpex", str(dump_path), *argv_extra])
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    assert exc_info.value.code == 2


def test_hunt_addr_without_hunt_is_a_usage_error(monkeypatch, tmp_path, capsys):
    _expect_usage_error(monkeypatch, tmp_path, ["--list", "--hunt-addr", "0x1000"])
    assert "--hunt-addr is a --hunt modifier" in capsys.readouterr().err


def test_hunt_addr_without_size_is_a_usage_error(monkeypatch, tmp_path, capsys):
    _expect_usage_error(
        monkeypatch, tmp_path, ["--hunt", "stomping", "--hunt-addr", "0x1000"])
    assert "--hunt-addr requires --size" in capsys.readouterr().err


@pytest.mark.parametrize("addr, size, fragment", [
    ("nonsense", "0x1000", "not a 0x-prefixed hexadecimal"),
    ("0x1000", "nonsense", "not a 0x-prefixed hexadecimal"),
    ("0x1000", "0", "must be a positive byte count"),
    ("0xffffffffffffffff", "0x10", "runs past the end of the 64-bit address space"),
    ("0x1000", hex(257 * (1 << 20)), "exceeds the stomping targeted request ceiling"),
])
def test_invalid_ranges_are_usage_errors(monkeypatch, tmp_path, capsys, addr, size, fragment):
    _expect_usage_error(
        monkeypatch, tmp_path,
        ["--hunt", "stomping", "--hunt-addr", addr, "--size", size])
    assert fragment in capsys.readouterr().err


def test_a_range_ending_exactly_at_the_top_of_the_address_space_is_accepted(
        monkeypatch, tmp_path):
    """The end is exclusive and never dereferenced, so an end of exactly 2**64
    is a legal request -- it simply finds no captured region."""
    top = (1 << 64) - 0x1000
    code, doc, _console = _run_stomping(
        monkeypatch, tmp_path,
        ["--hunt", "stomping", "--hunt-addr", hex(top), "--size", "0x1000"],
        captured={})
    assert code == 4
    assert _record(doc)["coverage"]["status"] == "not_evaluated"


# ── capability refusals (exit 1, before the dump opens) ──────────────────

@pytest.mark.parametrize("ttp, fragment", [
    ("all", "'all' is a selection mode, not an analyzer"),
    ("injection", "has no targeted-scan capability"),
    ("hollowing", "has no targeted-scan capability"),
    ("nosuchhunter", "Unknown TTP"),
])
def test_unsupported_hunters_are_refused_before_any_scan_work(
        monkeypatch, tmp_path, capsys, ttp, fragment):
    dump_path = tmp_path / "test.dmp"
    dump_path.write_bytes(b"synthetic dump content")

    def _never(path):
        raise AssertionError("the dump was opened for an unsupported targeted hunter")

    monkeypatch.setattr(cli, "open_dump", _never)
    monkeypatch.setattr(
        "sys.argv",
        ["dumpex", str(dump_path), "--hunt", ttp, "--hunt-addr", "0x1000", "--size", "0x100"])
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    assert exc_info.value.code == 1
    out = capsys.readouterr().out
    assert fragment in out
    # The supported set is rendered from the registry, so a refusal always
    # tells the analyst what they CAN run.
    assert "stomping, pipe, cs-beacon, yara, obfuscation" in out


def test_size_with_hunt_but_no_hunt_addr_is_a_usage_error(monkeypatch, tmp_path, capsys):
    """The pair is required in both directions. `--size` alone is a targeted
    invocation missing its address; running an unbounded whole-dump hunt and
    silently discarding `--size` would give the analyst a different scan cost
    and a different scope than the one they asked for."""
    _expect_usage_error(monkeypatch, tmp_path, ["--hunt", "stomping", "--size", "0x10"])
    err = capsys.readouterr().err
    assert "--hunt-addr" in err
    assert "--size is only meaningful" in err


@pytest.mark.parametrize("mode", ["--extract", "--strings"])
def test_size_still_belongs_to_extract_and_strings(monkeypatch, tmp_path, capsys, mode):
    """The gate is scoped to `--hunt`: `--size` is these commands' own region
    extent, and neither is refused for carrying it."""
    dump_path = tmp_path / "test.dmp"
    dump_path.write_bytes(b"synthetic dump content")
    monkeypatch.setattr(cli, "open_dump", lambda path: _mf())
    # --extract writes its bytes somewhere; keep that inside tmp_path rather
    # than the working directory this test happens to run from.
    output = ["--output", str(tmp_path / "region.bin")] if mode == "--extract" else []
    monkeypatch.setattr(
        "sys.argv",
        ["dumpex", str(dump_path), mode, hex(_BASE), "--size", "0x10", *output])
    try:
        cli.main()
    except SystemExit:
        pass
    assert "--size is only meaningful" not in capsys.readouterr().err


# ── the targeted document ───────────────────────────────────────────────

def test_a_complete_targeted_rescan_validates_and_reports_its_scope(
        monkeypatch, tmp_path, validator):
    code, doc, console = _run_stomping(
        monkeypatch, tmp_path,
        ["--hunt", "stomping", "--hunt-addr", hex(_BASE), "--size", hex(_SIZE)])
    assert list(validator.iter_errors(doc)) == []
    assert code == 0

    summary = doc["result"]["summary"]
    assert summary["scan_scope"] == {
        "kind": "targeted", "hunter": "stomping", "source": "ioc_string_scan",
        "scopes": [], "base_address": f"0x{_BASE:016x}", "size": _SIZE}
    assert summary["selected"] == "stomping"
    assert summary["hunter_count"] == 1
    # The skipped-target queue is `--hunt all`'s cross-hunter view of a whole
    # dump; one range's result is not evidence for it.
    assert summary["investigation_actions"] == []

    record = _record(doc)
    assert record["details"]["targeted_scope"] == [{
        "source": "ioc_string_scan", "scope": None, "base_address": f"0x{_BASE:016x}",
        "size": _SIZE, "captured_size": _SIZE, "capture_state": "complete",
        "coverage_status": "complete"}]
    assert record["coverage"]["status"] == "complete"
    # The completeness claim covers ioc_string_scan alone. Every other stomping
    # source is in the roster as absent AND carries its own limitation, so a
    # consumer keying on hunter + coverage.status cannot read this as "stomping
    # is completely covered".
    sources = record["coverage"]["sources"]
    assert sources["targeted_scan"]["state"] == "present"
    assert sources["ioc_string_scan"]["state"] == "present"
    out_of_scope = {limitation["source"] for limitation in record["coverage"]["limitations"]
                    if limitation["code"] == "TARGETED_SOURCE_NOT_EVALUATED"}
    assert {"module_headers", "reference_files", "section_content_diff",
            "modules"} == out_of_scope
    assert all(sources[name]["state"] == "absent" for name in out_of_scope)
    # MemoryInfo is NOT among them: the rescan reads the region table to
    # resolve the containing descriptor and to decide source eligibility, so
    # claiming it was never evaluated would invent a gap.
    assert sources["memory_info"]["state"] == "present"
    assert "0x0000000010000000" in console
    assert "applies to [0x0000000010000000, 0x0000000010002000) only" in _flat(console)


def test_the_requested_range_is_recorded_in_execution_options(monkeypatch, tmp_path):
    _code, doc, _console = _run_stomping(
        monkeypatch, tmp_path,
        ["--hunt", "stomping", "--hunt-addr", str(_BASE), "--size", str(_SIZE)])
    options = doc["meta"]["execution"]["options"]
    # Normalized, not the raw argument text: the decimal spelling above and the
    # hex one elsewhere in this file describe the same scan.
    assert options["hunt_addr"] == f"0x{_BASE:016x}"
    assert options["size"] == _SIZE
    assert doc["meta"]["execution"]["command"] == f"hunt_stomping_addr_0x{_BASE:x}"


def test_an_address_outside_every_region_is_not_evaluated_not_clean(
        monkeypatch, tmp_path, validator):
    """An address the dump holds nothing for is valid investigator input. It
    produces a not-evaluated closure and exit 4 -- never a clean result."""
    outside = _BASE + 0x100000
    code, doc, console = _run_stomping(
        monkeypatch, tmp_path,
        ["--hunt", "stomping", "--hunt-addr", hex(outside), "--size", "0x100"],
        captured={})
    assert list(validator.iter_errors(doc)) == []
    assert code == 4
    record = _record(doc)
    assert record["status"] == "NOT_EVALUATED"
    assert record["verdict_level"] == "not_evaluated"
    assert record["coverage"]["status"] == "not_evaluated"
    assert [item["coverage_status"] for item in record["details"]["targeted_scope"]] == [
        "not_evaluated"]
    assert "TARGETED_SOURCE_NOT_EVALUATED" in {
        limitation["code"] for limitation in record["coverage"]["limitations"]}
    assert "was NOT fully evaluated" in _flat(console)


def test_a_cross_boundary_request_is_partial_and_exits_three(
        monkeypatch, tmp_path, validator):
    """Capture continues across the whole request while evaluation stops at the
    containing descriptor's end, so a fully captured cross-boundary range is
    never reported as fully evaluated."""
    regions = [Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE"),
               Region(_BASE + _SIZE, _BASE + _SIZE, _SIZE, "MEM_COMMIT", "PAGE_EXECUTE_READ",
                       "MEM_IMAGE")]
    segments = [Segment(_BASE, _FILE_OFFSET, _SIZE * 2)]
    code, doc, console = _run_stomping(
        monkeypatch, tmp_path,
        ["--hunt", "stomping", "--hunt-addr", hex(_BASE), "--size", hex(_SIZE * 2)],
        mf=_mf(regions=regions, segments=segments),
        captured={_BASE: _payload(_SIZE * 2)})
    assert list(validator.iter_errors(doc)) == []
    assert code == 3
    record = _record(doc)
    assert record["coverage"]["status"] == "partial"
    scope = record["details"]["targeted_scope"][0]
    assert scope["capture_state"] == "complete" and scope["coverage_status"] == "partial"
    assert "SCAN_REGION_EVALUATION_TRUNCATED" in {
        limitation["code"] for limitation in record["coverage"]["limitations"]}
    assert "was NOT fully evaluated" in _flat(console)


def test_an_obfuscation_rescan_projects_one_entry_per_layer(
        monkeypatch, tmp_path, validator):
    """Obfuscation always attempts its three layers in fixed order, as one
    request over one capture -- there is no public per-layer selection."""
    regions = [Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    monkeypatch.setattr(encoding_targeted, "read_region_spanning",
                        _reader({_BASE: _payload()}))
    code, doc, _console = run_cli(
        monkeypatch, tmp_path,
        ["--hunt", "obfuscation", "--hunt-addr", hex(_BASE), "--size", hex(_SIZE)],
        _mf(regions=regions))
    assert list(validator.iter_errors(doc)) == []
    assert code in (0, 3)
    record = _record(doc)
    assert [item["scope"] for item in record["details"]["targeted_scope"]] == [
        "sleep_mask", "entropy", "decode"]
    assert doc["result"]["summary"]["scan_scope"]["scopes"] == [
        "decode", "entropy", "sleep_mask"]


# ── full-scope compatibility ────────────────────────────────────────────

def test_a_full_scope_hunt_carries_the_full_tag_and_no_targeted_scope(
        monkeypatch, tmp_path, validator):
    _code, doc, _console = _run_stomping(monkeypatch, tmp_path, ["--hunt", "stomping"])
    assert list(validator.iter_errors(doc)) == []
    assert doc["result"]["summary"]["scan_scope"] == {"kind": "full"}
    # Omitted entirely, never emitted as null -- a full-scope details object
    # has no targeted scope to report.
    assert "targeted_scope" not in _record(doc)["details"]


def test_full_scope_hunt_all_still_carries_every_hunter(monkeypatch, tmp_path, validator):
    _code, doc, _console = _run_stomping(monkeypatch, tmp_path, ["--hunt", "all"])
    assert list(validator.iter_errors(doc)) == []
    assert doc["result"]["summary"]["scan_scope"] == {"kind": "full"}
    assert doc["result"]["summary"]["hunter_count"] == 7
    assert all("targeted_scope" not in record["details"]
               for record in doc["result"]["data"]["records"])


# ── YARA: detection, rule provenance, and the scoped negative ───────────

def _yara_dump(data, seg_va=_BASE, seg_fo=_FILE_OFFSET):
    """A dump whose one captured segment holds `data`. YARA's scanner reads
    through `MinidumpFile.get_reader().read(va, size)`, which is exactly what
    `FakeReader` stands in for."""
    class MF(FakeMF):
        memory_info = FakeStream(
            [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")],
            "infos")
        memory_segments_64 = FakeStream([Segment(seg_va, seg_fo, len(data))],
                                         "memory_segments")
        modules = FakeStream([], "modules")
        _reader = FakeReader({seg_va: data})
    return MF()


def test_a_targeted_yara_rescan_detects_and_names_its_rules(monkeypatch, tmp_path, validator):
    pytest.importorskip("yara")
    (tmp_path / "hit.yar").write_text(
        'rule HitRule { strings: $a = "FINDME_MARKER" condition: $a }')
    data = b"A" * 0x100 + b"FINDME_MARKER" + b"B" * 0x100

    code, doc, console = run_cli(
        monkeypatch, tmp_path,
        ["--hunt", "yara", "--hunt-addr", hex(_BASE), "--size", hex(len(data)),
         "--yara-dir", str(tmp_path)],
        _yara_dump(data))
    assert list(validator.iter_errors(doc)) == []
    assert code == 0

    record = _record(doc)
    assert record["status"] == "DETECTED"
    assert record["details"]["rules_hit"] == ["HitRule"]
    assert record["details"]["targeted_scope"][0]["coverage_status"] == "complete"
    # Rule provenance comes from THIS invocation's own report, so a targeted
    # verdict names the rule content behind it.
    assert [f["name"] for f in doc["meta"]["yara_rules"]["files"]] == ["hit.yar"]
    assert "HitRule" in console


def test_a_targeted_yara_rescan_over_clean_bytes_is_a_scoped_negative(
        monkeypatch, tmp_path, validator):
    pytest.importorskip("yara")
    (tmp_path / "hit.yar").write_text(
        'rule HitRule { strings: $a = "FINDME_MARKER" condition: $a }')
    data = b"A" * 0x200

    code, doc, console = run_cli(
        monkeypatch, tmp_path,
        ["--hunt", "yara", "--hunt-addr", hex(_BASE), "--size", hex(len(data)),
         "--yara-dir", str(tmp_path)],
        _yara_dump(data))
    assert list(validator.iter_errors(doc)) == []
    assert code == 0
    record = _record(doc)
    assert record["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert record["verdict_level"] == "clean"
    # The negative is stated against the requested range, never the dump.
    assert "evaluated that range completely through segment_scan" in _flat(console)


def test_a_successful_yara_rescan_never_disowns_the_sources_behind_its_verdict(
        monkeypatch, tmp_path, validator):
    """`yara_rules` and `yara_context` ARE the targeted verdict: the rescan
    resolves and compiles the rule files and classifies each hit's memory
    context. Reporting them absent would invent a coverage gap on the
    analyzer's own detection path -- and would do so exactly when they
    succeeded, since a failure has its own real limitation."""
    pytest.importorskip("yara")
    (tmp_path / "hit.yar").write_text(
        'rule HitRule { strings: $a = "FINDME_MARKER" condition: $a }')
    data = b"A" * 0x100 + b"FINDME_MARKER" + b"B" * 0x100

    code, doc, console = run_cli(
        monkeypatch, tmp_path,
        ["--hunt", "yara", "--hunt-addr", hex(_BASE), "--size", hex(len(data)),
         "--yara-dir", str(tmp_path)],
        _yara_dump(data))
    assert list(validator.iter_errors(doc)) == []
    assert code == 0

    record = _record(doc)
    assert record["status"] == "DETECTED" and record["details"]["rules_hit"] == ["HitRule"]
    sources = record["coverage"]["sources"]
    assert sources["yara_rules"]["state"] == "present"
    assert sources["yara_context"]["state"] == "present"
    assert not [limitation for limitation in record["coverage"]["limitations"]
                if limitation["code"] == "TARGETED_SOURCE_NOT_EVALUATED"]
    # Nothing to disown, so no out-of-scope block at all.
    assert "NOT COVERED BY THIS RESCAN" not in console


def test_a_yara_rescan_whose_rules_fail_to_compile_still_reports_the_real_gap(
        monkeypatch, tmp_path, validator):
    """The counterpart: a source that actually failed keeps its own code, and
    is not replaced by the out-of-scope claim."""
    pytest.importorskip("yara")
    (tmp_path / "broken.yar").write_text("rule Broken { this is not yara }")
    data = b"A" * 0x200

    _code, doc, _console = run_cli(
        monkeypatch, tmp_path,
        ["--hunt", "yara", "--hunt-addr", hex(_BASE), "--size", hex(len(data)),
         "--yara-dir", str(tmp_path)],
        _yara_dump(data))
    assert list(validator.iter_errors(doc)) == []
    limitations = _record(doc)["coverage"]["limitations"]
    assert "YARA_RULE_COMPILE_FAILED" in {l["code"] for l in limitations}
    # No rule compiled, so the closure did not run and says so -- sourced to
    # the rescan itself. `yara_rules` keeps its own real gap and is never
    # relabelled as a source this rescan does not cover.
    disowned = {l["source"] for l in limitations
                if l["code"] == "TARGETED_SOURCE_NOT_EVALUATED"}
    assert disowned == {"targeted_scan"}


# ── the schema rejects a document whose scan_scope contradicts the rest ──
#
# A consumer decides "was this whole dump or one range" from `scan_scope`
# alone, so the tag has to be checkable rather than merely present. Each case
# below starts from a real targeted document and breaks exactly one agreement.

def _targeted_doc(monkeypatch, tmp_path):
    _code, doc, _console = _run_stomping(
        monkeypatch, tmp_path,
        ["--hunt", "stomping", "--hunt-addr", hex(_BASE), "--size", hex(_SIZE)])
    return doc


def test_a_scan_scope_naming_another_analyzer_is_rejected(
        monkeypatch, tmp_path, validator):
    doc = _targeted_doc(monkeypatch, tmp_path)
    doc["result"]["summary"]["scan_scope"].update(
        {"hunter": "obfuscation", "source": "encoding_scan", "scopes": ["decode"]})
    assert list(validator.iter_errors(doc)), "scan_scope.hunter must agree with selected"


def test_an_invented_targeted_source_is_rejected(monkeypatch, tmp_path, validator):
    doc = _targeted_doc(monkeypatch, tmp_path)
    doc["result"]["summary"]["scan_scope"]["source"] = "invented_source"
    assert list(validator.iter_errors(doc))


def test_an_invented_targeted_scope_is_rejected(monkeypatch, tmp_path, validator):
    """Both an unknown name and a real name belonging to another analyzer:
    stomping runs one unscoped source, so any scope at all is wrong for it."""
    for scopes in (["invented_scope"], ["sleep_mask"]):
        doc = _targeted_doc(monkeypatch, tmp_path)
        doc["result"]["summary"]["scan_scope"]["scopes"] = scopes
        assert list(validator.iter_errors(doc)), scopes


def test_a_targeted_tag_without_targeted_scope_is_rejected(
        monkeypatch, tmp_path, validator):
    doc = _targeted_doc(monkeypatch, tmp_path)
    doc["result"]["data"]["records"][0]["details"].pop("targeted_scope")
    assert list(validator.iter_errors(doc))


def test_a_full_tag_carrying_targeted_scope_is_rejected(
        monkeypatch, tmp_path, validator):
    """The other direction: a targeted result relabelled as a whole-dump one
    would widen every negative conclusion in it to the entire dump."""
    doc = _targeted_doc(monkeypatch, tmp_path)
    doc["result"]["summary"]["scan_scope"] = {"kind": "full"}
    assert list(validator.iter_errors(doc))


# ── hunt options a targeted invocation never reads ──────────────────────

@pytest.mark.parametrize("flag", ["--ref-dir", "--yara-dir"])
def test_an_option_the_targeted_analyzer_never_reads_is_refused(
        monkeypatch, tmp_path, capsys, flag):
    """Accepting `--ref-dir` here would record a directory in
    `meta.execution.options` that nothing read, which reads as "the reference
    files were compared" when a targeted stomping rescan runs
    `ioc_string_scan` alone."""
    supplied = tmp_path / "supplied"
    supplied.mkdir()
    _expect_usage_error(
        monkeypatch, tmp_path,
        ["--hunt", "stomping", "--hunt-addr", hex(_BASE), "--size", hex(_SIZE),
         flag, str(supplied)])
    assert f"{flag} has no effect" in capsys.readouterr().err


def test_the_option_a_targeted_analyzer_does_read_is_accepted(
        monkeypatch, tmp_path, validator):
    """`--yara-dir` is refused for stomping and accepted for yara from the one
    registered capability declaration, not from a command-surface table."""
    pytest.importorskip("yara")
    (tmp_path / "hit.yar").write_text(
        'rule HitRule { strings: $a = "FINDME_MARKER" condition: $a }')
    data = b"A" * 0x100 + b"FINDME_MARKER" + b"B" * 0x100

    code, doc, _console = run_cli(
        monkeypatch, tmp_path,
        ["--hunt", "yara", "--hunt-addr", hex(_BASE), "--size", hex(len(data)),
         "--yara-dir", str(tmp_path)],
        _yara_dump(data))
    assert list(validator.iter_errors(doc)) == []
    assert code == 0
    assert doc["meta"]["execution"]["options"]["yara_dir"] == str(tmp_path)


# ── the closure list is pinned, not merely well-formed ──────────────────
#
# `details.targeted_scope` is what a consumer reconciles a rescan back to an
# originating gap with, so a dropped, extra, reordered, or invented closure has
# to be rejected rather than accepted as a differently-shaped result. These
# drive obfuscation, whose three layers make every case visible at once.

def _obfuscation_doc(monkeypatch, tmp_path):
    regions = [Region(_BASE, _BASE, _SIZE, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    monkeypatch.setattr(encoding_targeted, "read_region_spanning",
                        _reader({_BASE: _payload()}))
    _code, doc, _console = run_cli(
        monkeypatch, tmp_path,
        ["--hunt", "obfuscation", "--hunt-addr", hex(_BASE), "--size", hex(_SIZE)],
        _mf(regions=regions))
    return doc


def test_a_scan_scope_naming_only_some_of_the_scopes_that_ran_is_rejected(
        monkeypatch, tmp_path, validator):
    doc = _obfuscation_doc(monkeypatch, tmp_path)
    doc["result"]["summary"]["scan_scope"]["scopes"] = ["decode"]
    assert list(validator.iter_errors(doc)), "obfuscation always runs all three layers"


def test_a_scan_scope_in_another_order_is_rejected(monkeypatch, tmp_path, validator):
    """`scopes` is the sorted set; another order is a different document for a
    consumer diffing two results."""
    doc = _obfuscation_doc(monkeypatch, tmp_path)
    doc["result"]["summary"]["scan_scope"]["scopes"] = ["sleep_mask", "entropy", "decode"]
    assert list(validator.iter_errors(doc))


def test_an_invented_closure_source_or_scope_is_rejected(
        monkeypatch, tmp_path, validator):
    for field, value in (("source", "invented_source"), ("scope", "invented_scope")):
        doc = _obfuscation_doc(monkeypatch, tmp_path)
        doc["result"]["data"]["records"][0]["details"]["targeted_scope"][0][field] = value
        assert list(validator.iter_errors(doc)), field


def test_a_dropped_or_extra_closure_is_rejected(monkeypatch, tmp_path, validator):
    dropped = _obfuscation_doc(monkeypatch, tmp_path)
    dropped["result"]["data"]["records"][0]["details"]["targeted_scope"].pop(0)
    assert list(validator.iter_errors(dropped)), "a layer that ran must not vanish"

    extra = _obfuscation_doc(monkeypatch, tmp_path)
    scopes = extra["result"]["data"]["records"][0]["details"]["targeted_scope"]
    scopes.append(dict(scopes[0]))
    assert list(validator.iter_errors(extra))


def test_reordered_closures_are_rejected(monkeypatch, tmp_path, validator):
    """The order is the adapter's own fixed one -- sleep_mask, entropy, decode
    -- and each position names the closure it belongs to."""
    doc = _obfuscation_doc(monkeypatch, tmp_path)
    details = doc["result"]["data"]["records"][0]["details"]
    details["targeted_scope"] = list(reversed(details["targeted_scope"]))
    assert list(validator.iter_errors(doc))


def test_a_pipe_rescan_must_carry_both_of_its_closures(monkeypatch, tmp_path, validator):
    """Pipe's grant is unscoped, but its invocation closes `pipe_name` and
    `c2_context` independently and both must be present, in that order."""
    monkeypatch.setattr(pipe_targeted, "read_region_spanning",
                        _reader({_BASE: _payload()}))
    _code, doc, _console = run_cli(
        monkeypatch, tmp_path,
        ["--hunt", "pipe", "--hunt-addr", hex(_BASE), "--size", hex(_SIZE)], _mf())
    assert list(validator.iter_errors(doc)) == []
    assert [item["scope"] for item in _record(doc)["details"]["targeted_scope"]] == [
        "pipe_name", "c2_context"]
    assert doc["result"]["summary"]["scan_scope"]["scopes"] == ["c2_context", "pipe_name"]

    doc["result"]["data"]["records"][0]["details"]["targeted_scope"].pop()
    assert list(validator.iter_errors(doc))

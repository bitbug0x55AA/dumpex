"""
Analyst-first console hierarchy for `--report`.

The report banner is the first substantive block; the current assessment
and a coverage summary follow it immediately; every other block --
anchor context, key evidence, correlation, and whole-run background --
comes after that. A retained string chosen for both the IOC inventory and
anchor-proximity context prints its full text exactly once, and
overlapping network-hit byte windows print exactly one combined hexdump.
No section header carries a number, so no conditional section can leave a
numbering gap.

Section reordering and the compatibility freeze for sections 1-4 are
tests/integration/test_report_compat_freeze.py; the two console detail
levels are tests/integration/test_report_verbose_detail.py.
"""
import datetime
import json
import re
import sys

import dumpex.cli as cli
import dumpex.commands.report as report_mod
import dumpex.core.memory as core_memory_mod
import dumpex.output.collector as collector_mod
from dumpex.output.records import (
    ENRICHMENT_COMPLETE, ENRICHMENT_SCOPE_CARD, EnrichmentSection,
    ReportStringContext, ReportStringContextEntry,
)
from dumpex.rules_pkg.loader import configure_rules_source
from tests.fixtures.fakes import (
    FakeMF, FakeStream, MiscInfo, Module, Peb, Region, ThreadInfo, mem_reader,
)

REGION_BASE = 0x1000
REGION_SIZE = 0x1000
ANCHOR_TID = 0x11

_NUMBERED_HEADER = re.compile(r"\[\s*(?:\d+|[A-Z]{1,2})\s*\]")


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


def _build_mf(tmp_path, *, regions=None, image_base=None, modules=None):
    dump_path = str(tmp_path / "test.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(b"synthetic dump content")
    mf = FakeMF()
    mf.filename = dump_path
    mf.modules = FakeStream(modules if modules is not None else [], "modules")
    mf.thread_info = FakeStream([ThreadInfo(ANCHOR_TID, REGION_BASE)], "infos")
    mf.memory_info = FakeStream(regions if regions is not None else [], "infos")
    mf.directories = []
    mf._dumpex_stream_failures = {}
    if image_base is not None:
        mf.peb = Peb(image_base, "C:\\Windows\\System32\\synthetic.exe",
                     command_line="synthetic.exe --run")
        mf.misc_info = MiscInfo(process_id=4321, process_create_time=1700000000)
    return mf, dump_path


def _run(monkeypatch, tmp_path, mf, dump_path, argv_extra, *, read_map=None, reader=None):
    monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(collector_mod, "datetime", _FrozenDateTimeModule)
    configure_rules_source(None)
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)
    reader = reader if reader is not None else mem_reader(read_map or {})
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
        doc = json.load(fh)
    return exit_code, doc


# ── the banner leads, and the run-wide background trails ────────────────

def test_the_banner_is_the_first_substantive_block(monkeypatch, tmp_path, capsys):
    """Process-wide and main-image PE context are internal report detail
    that comes after the banner and the assessment, never before it."""
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READWRITE", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region], image_base=REGION_BASE)
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-addr", hex(REGION_BASE)],
         read_map={REGION_BASE: b"\x00" * REGION_SIZE})
    out = capsys.readouterr().out

    banner_at = out.index("dumpex TRIAGE REPORT")
    assessment_at = out.index("ASSESSMENT")
    process_at = out.index("PROCESS CONTEXT")
    assert banner_at < assessment_at < process_at


def test_assessment_precedes_anchor_context_and_key_evidence(monkeypatch, tmp_path, capsys):
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-addr", hex(REGION_BASE)],
         read_map={REGION_BASE: b"cmd.exe /c calc.exe" + b"\x00" * (REGION_SIZE - 19)})
    out = capsys.readouterr().out

    assessment_at = out.index("ASSESSMENT")
    anchor_at = out.index("ANCHOR CONTEXT")
    evidence_at = out.index("KEY EVIDENCE")
    assert assessment_at < anchor_at < evidence_at
    # The finding that drives the verdict is visible in that top block,
    # not only rediscoverable by reading every section beneath it.
    assert "RWX + MEM_PRIVATE" in out[assessment_at:anchor_at]


def test_no_section_header_carries_a_number(monkeypatch, tmp_path, capsys):
    """Every header is a plain name. A conditional section that is absent
    this run leaves no gap in a numbering scheme, because there is no
    numbering scheme to leave a gap in."""
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region], image_base=REGION_BASE)
    for verbose in ([], ["--verbose"]):
        _run(monkeypatch, tmp_path, mf, dump_path,
             ["--report-addr", hex(REGION_BASE), *verbose],
             read_map={REGION_BASE: b"cmd.exe /c beacon" + b"\x00" * (REGION_SIZE - 17)})
        out = capsys.readouterr().out
        assert _NUMBERED_HEADER.search(out) is None


# ── deduplicated string evidence ─────────────────────────────────────────

def test_a_string_selected_as_both_ioc_and_context_prints_its_text_once(
        monkeypatch, tmp_path, capsys):
    """One retained string can be selected both as IOC evidence (Section
    4's own inventory) and as anchor-proximity context (STRING CONTEXT
    AROUND THE ANCHOR): its full text is not printed a second time, and
    the second appearance is a short cross-reference back to the first."""
    needle = "cmd.exe /c powershell -enc beacon-overlap-marker"
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    data = needle.encode() + b"\x00" * (REGION_SIZE - len(needle))
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)],
                          read_map={REGION_BASE: data})
    out = capsys.readouterr().out
    card = doc["result"]["data"]["records"][0]

    assert card["ioc_strings"], "fixture must produce at least one IOC match"
    assert any(e["selection_reason"] == "ioc_pattern"
               for e in card["string_context"]["entries"])
    # Printed once, as IOC evidence -- not a second time as context text.
    assert out.count(needle) == 1
    assert "also retained as evidence under" in out


# ── coalesced overlapping byte context ───────────────────────────────────

def test_overlapping_network_hit_windows_render_one_combined_hexdump(
        monkeypatch, tmp_path, capsys):
    """Two network-pattern IOC hits close enough that their retained
    ±128-byte windows overlap substantially render ONE combined byte
    range, marking both contributing hit addresses, rather than two
    separate hexdumps repeating the shared bytes."""
    hit_a = b"cmd.exe /c curl 10.0.0.5:8080/beacon"
    hit_b = b"cmd.exe /c curl 10.0.0.6:9090/beacon"
    data = hit_a + b"\x00" * 20 + hit_b + b"\x00" * (REGION_SIZE - len(hit_a) - 20 - len(hit_b))
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)],
                          read_map={REGION_BASE: data})
    out = capsys.readouterr().out
    card = doc["result"]["data"]["records"][0]

    net_hits = [s for s in card["ioc_strings"] if s["is_network_pattern"]]
    assert len(net_hits) == 2   # collection itself is untouched
    windows = [(int(s["context_base_address"], 16),
               int(s["context_base_address"], 16) + len(s["context_hex"]) // 2)
              for s in net_hits]
    assert windows[0][1] > windows[1][0]   # the fixture's own premise: they overlap

    assert out.count("Network pattern —") == 1
    assert "combined byte context for 2 overlapping hit(s)" in out
    assert "part of the combined byte context above" in out
    for s in net_hits:
        assert f"0x{int(s['address'], 16):016x}" in out


def test_non_overlapping_network_hits_still_render_their_own_hexdump(
        monkeypatch, tmp_path, capsys):
    """Two network-pattern hits far enough apart that their windows do
    not overlap are not merged -- each keeps its own single-hit hexdump,
    exactly as a lone hit always has."""
    hit_a = b"cmd.exe /c curl 10.0.0.5:8080/beacon"
    hit_b = b"cmd.exe /c curl 10.0.0.6:9090/beacon"
    gap = b"\x00" * 4096
    data = hit_a + gap + hit_b + b"\x00" * 512
    region = Region(REGION_BASE, REGION_BASE, len(data), "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)],
                          read_map={REGION_BASE: data})
    out = capsys.readouterr().out

    assert out.count("Network pattern — ±128 byte context:") == 2
    assert "combined byte context" not in out


# ── string-mode title-first ordering ─────────────────────────────────────

def test_string_mode_banner_leads_the_search_preamble_and_never_repeats(
        monkeypatch, tmp_path, capsys):
    """String mode's report title is the invocation's own banner, printed
    once before the search preamble -- not the per-hit banner repeated
    once per card, and not preceded by anything else."""
    hit_a = Region(0x2000, 0x2000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    hit_b = Region(0x3000, 0x3000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[hit_a, hit_b])
    needle = b"MULTIHITNEEDLE77"
    data = needle + b"\x00" * (REGION_SIZE - len(needle))
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-string", "MULTIHITNEEDLE77"],
         read_map={0x2000: data, 0x3000: data})
    out = capsys.readouterr().out

    assert out.count("dumpex TRIAGE REPORT") == 1
    banner_at = out.index("dumpex TRIAGE REPORT")
    preamble_at = out.index("Searching memory for:")
    assert banner_at < preamble_at
    assert out.index("Rules loaded") < banner_at


def test_string_mode_provenance_and_additional_context_appear_once_for_the_whole_run(
        monkeypatch, tmp_path, capsys):
    """A multi-hit --report-string run is one report, not N transcripts
    appended together: LIMITATIONS AND PROVENANCE and the allocation-
    neighborhood ADDITIONAL CONTEXT each appear exactly once for the whole
    run, not once per hit -- their rows are prefixed by region instead."""
    hit_a = Region(0x2000, 0x2000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    hit_b = Region(0x3000, 0x3000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[hit_a, hit_b])
    needle = b"MULTIHITNEEDLE77"
    data = needle + b"\x00" * (REGION_SIZE - len(needle))
    _run(monkeypatch, tmp_path, mf, dump_path,
         ["--report-string", "MULTIHITNEEDLE77", "--verbose"],
         read_map={0x2000: data, 0x3000: data})
    out = capsys.readouterr().out

    assert out.count("LIMITATIONS AND PROVENANCE") == 1
    assert out.count("ADDITIONAL CONTEXT") == 1
    assert "region 0x2000 — " in out
    assert "region 0x3000 — " in out


def test_multi_card_coverage_caveat_appears_once_not_once_per_card(
        monkeypatch, tmp_path, capsys):
    """Two string-search hits become two cards; a third region cannot be
    read at all, making the aggregate coverage partial. The incomplete-
    coverage caveat is a fact about the RUN's own coverage, not about any
    one card's own findings -- it belongs in the coverage summary and
    must appear once, not once per card."""
    needle = b"MULTICARDNEEDLE99"
    good_data = needle + b"\x00" * (REGION_SIZE - len(needle))
    hit_a = Region(0x2000, 0x2000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    hit_b = Region(0x3000, 0x3000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    unreadable = Region(0x4000, 0x4000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[hit_a, hit_b, unreadable])

    def reader(mf_, addr, size):
        if addr == 0x4000:
            raise RuntimeError("region unreadable")
        return mem_reader({0x2000: good_data, 0x3000: good_data})(mf_, addr, size)

    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-string", "MULTICARDNEEDLE99"], reader=reader)
    out = capsys.readouterr().out

    assert doc["result"]["summary"]["card_count"] == 2
    assert doc["result"]["coverage"]["status"] == "partial"
    assert out.count("COVERAGE SUMMARY") == 1
    assert out.count("treat every finding below") == 1


# ── coverage is never hidden behind an early return ──────────────────────

def test_coverage_summary_survives_the_zero_hit_early_return(monkeypatch, tmp_path, capsys):
    """A string search that finds nothing must not read as an exhaustive
    negative when a region could not be read at all: the coverage
    summary and its actual reason are visible even though the run prints
    "not found" and returns immediately after."""
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])

    def _unreadable(mf_, addr, size):
        raise RuntimeError("region unreadable")

    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-string", "NEEDLE-NOT-PRESENT"], reader=_unreadable)
    out = capsys.readouterr().out

    assert doc["result"]["coverage"]["status"] == "partial"
    assert doc["result"]["coverage"]["reasons"]
    assert "String not found" in out
    assert "COVERAGE SUMMARY" in out
    reason = doc["result"]["coverage"]["reasons"][0]
    assert reason in out
    banner_at = out.index("dumpex TRIAGE REPORT")
    coverage_at = out.index("COVERAGE SUMMARY")
    not_found_at = out.index("String not found")
    assert banner_at < coverage_at < not_found_at


def test_coverage_summary_survives_the_all_image_hits_early_return(
        monkeypatch, tmp_path, capsys):
    """Every hit landing in a known system module is routine, not
    incomplete -- but the run may STILL be incomplete for unrelated
    reasons (here, a second, unreadable private region), and that must
    still be visible even though card_count is 0."""
    image_region = Region(0xb000, 0xb000, REGION_SIZE, "MEM_COMMIT",
                          "PAGE_READONLY", "MEM_IMAGE")
    unreadable_region = Region(0xc000, 0xc000, REGION_SIZE, "MEM_COMMIT",
                               "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(
        tmp_path, regions=[image_region, unreadable_region],
        modules=[Module(0xb000, REGION_SIZE, "C:\\Windows\\System32\\kernel32.dll")])
    needle = b"SHAREDNEEDLE9999"
    data = needle + b"\x00" * (REGION_SIZE - len(needle))

    def _reader(mf_, addr, size):
        if addr == 0xc000:
            raise RuntimeError("region unreadable")
        return mem_reader({0xb000: data})(mf_, addr, size)

    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-string", "SHAREDNEEDLE9999"], reader=_reader)
    out = capsys.readouterr().out

    assert doc["result"]["summary"]["card_count"] == 0
    assert doc["result"]["coverage"]["status"] == "partial"
    assert "All hits are in known system modules" in out
    assert "COVERAGE SUMMARY" in out
    coverage_at = out.index("COVERAGE SUMMARY")
    all_image_at = out.index("All hits are in known system modules")
    assert coverage_at < all_image_at


def test_complete_coverage_states_its_own_status(monkeypatch, tmp_path, capsys):
    """Complete coverage is its own visible state, not the absence of a
    block: an analyst must never have to infer "complete" from silence,
    which is indistinguishable from a hidden gap."""
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)],
                          read_map={REGION_BASE: b"\x00" * REGION_SIZE})
    out = capsys.readouterr().out

    assert doc["result"]["coverage"]["status"] == "complete"
    assert "COVERAGE SUMMARY" in out
    assert "Status: COMPLETE" in out
    assert "No known collection limitations." in out


# ── normal detail is a bounded IOC preview, verbose is the full set ──────

def test_normal_detail_caps_the_ioc_preview_and_discloses_the_omission(
        monkeypatch, tmp_path, capsys):
    """Normal detail shows a bounded preview of retained IOC evidence,
    discloses what it left out, and never repeats a byte range for a hit
    it did not show; verbose expands to every retained match."""
    from dumpex.commands.report import CONSOLE_IOC_STRINGS

    hits = [f"cmd.exe /c beacon-marker-{i:02d}".encode() for i in range(CONSOLE_IOC_STRINGS + 3)]
    data = b"\x00".join(hits) + b"\x00"
    data = data.ljust(REGION_SIZE, b"\x00")
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])

    results = {}
    for label, extra in (("normal", []), ("verbose", ["--verbose"])):
        mf, dump_path = _build_mf(tmp_path, regions=[region])
        exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                              ["--report-addr", hex(REGION_BASE), *extra],
                              read_map={REGION_BASE: data})
        results[label] = (doc, capsys.readouterr().out)

    normal_doc, normal_out = results["normal"]
    verbose_doc, verbose_out = results["verbose"]
    card = normal_doc["result"]["data"]["records"][0]
    assert len(card["ioc_strings"]) == CONSOLE_IOC_STRINGS + 3

    for s in card["ioc_strings"][:CONSOLE_IOC_STRINGS]:
        assert s["text"] in normal_out
    for s in card["ioc_strings"][CONSOLE_IOC_STRINGS:]:
        assert s["text"] not in normal_out
    assert f"this section shows {CONSOLE_IOC_STRINGS} of" in normal_out
    for s in card["ioc_strings"]:
        assert s["text"] in verbose_out
    assert "this section shows" not in verbose_out
    # Both runs collected -- and JSON retains -- the identical full set;
    # only the console preview differs.
    assert normal_doc["result"]["data"]["records"][0]["ioc_strings"] == (
        verbose_doc["result"]["data"]["records"][0]["ioc_strings"])


# ── notable strings are deduplicated too, not just IOC strings ──────────

def test_a_notable_string_selected_as_context_prints_its_text_once(
        monkeypatch, tmp_path, capsys):
    """A routine (non-IOC) string long enough to be a notable string, and
    also close enough to the anchor to be selected as proximity context,
    is one presentation identity -- its full text is not printed twice."""
    notable = "a perfectly ordinary routine string of no particular interest"
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    data = notable.encode() + b"\x00" * (REGION_SIZE - len(notable))
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)],
                          read_map={REGION_BASE: data})
    out = capsys.readouterr().out
    card = doc["result"]["data"]["records"][0]

    assert card["notable_strings"], "fixture must produce at least one notable string"
    assert not card["ioc_strings"]
    assert any((e["address"], e["encoding"]) ==
              (card["notable_strings"][0]["address"], card["notable_strings"][0]["encoding"])
              for e in card["string_context"]["entries"])
    assert out.count(notable) == 1
    assert "also retained as evidence under" in out


# ── the assessment names a concrete next step ────────────────────────────

def test_assessment_names_a_finding_specific_next_step(monkeypatch, tmp_path, capsys):
    """The top-level assessment names a next step grounded in the actual
    finding, not a generic "investigate further"."""
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")
    # A module backing the fixture's own anchor thread keeps this run's
    # only finding the one this test is actually about -- the thread
    # section on its own is not this test's concern.
    mf, dump_path = _build_mf(
        tmp_path, regions=[region],
        modules=[Module(REGION_BASE, REGION_SIZE, "C:\\Windows\\System32\\ntdll.dll")])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)],
                          read_map={REGION_BASE: b"\x00" * REGION_SIZE})
    out = capsys.readouterr().out

    assert doc["result"]["data"]["records"][0]["findings"] == ["rwx_private"]
    assessment_at = out.index("ASSESSMENT")
    anchor_at = out.index("ANCHOR CONTEXT")
    assessment_block = out[assessment_at:anchor_at]
    assert "Next:" in assessment_block
    assert "instruction and IAT context" in assessment_block


def test_assessment_names_no_anomalies_when_clean_and_complete(
        monkeypatch, tmp_path, capsys):
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(
        tmp_path, regions=[region],
        modules=[Module(REGION_BASE, REGION_SIZE, "C:\\Windows\\System32\\ntdll.dll")])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)],
                          read_map={REGION_BASE: b"\x00" * REGION_SIZE})
    out = capsys.readouterr().out

    assert doc["result"]["data"]["records"][0]["findings"] == []
    assessment_at = out.index("ASSESSMENT")
    anchor_at = out.index("ANCHOR CONTEXT")
    assessment_block = out[assessment_at:anchor_at]
    assert "no anomalies were found within this rule set's current coverage" in assessment_block


# ── a cross-reference never points at a section that didn't render it ────

def test_string_context_never_cross_references_evidence_shown_nowhere(
        monkeypatch, tmp_path, capsys):
    """STRINGS IN REGION previews IOC matches in scan (address) order;
    STRING CONTEXT selects by distance from the anchor. When the anchor
    sits near the tail of the region those two orderings disagree -- the
    hits STRING CONTEXT ranks closest are the ones STRINGS IN REGION's
    own address-ordered preview cut. Deduplication is keyed off what
    STRINGS IN REGION actually renders, not off the wider retained set:
    an IOC match outside that preview is still new information from
    STRING CONTEXT's own perspective, and prints there in full -- never
    as a cross-reference pointing at a section that does not show it."""
    hits = [f"cmd.exe /c beacon-marker-{i:02d}".encode()
            for i in range(report_mod.CONSOLE_IOC_STRINGS + 3)]
    data = b"\x00".join(hits) + b"\x00"
    data = data.ljust(REGION_SIZE, b"\x00")
    anchor = REGION_BASE + REGION_SIZE - 1   # farthest possible from hit 0
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(anchor)],
                          read_map={REGION_BASE: data})
    out = capsys.readouterr().out
    card = doc["result"]["data"]["records"][0]

    all_ioc_texts = [s["text"] for s in card["ioc_strings"]]
    assert len(all_ioc_texts) == report_mod.CONSOLE_IOC_STRINGS + 3
    # STRING CONTEXT's own distance ranking favors the LAST few hits (the
    # closest to a tail anchor) -- the opposite end from STRINGS IN
    # REGION's address-ordered preview of the FIRST few -- so this only
    # proves something if the two previews would otherwise disagree.
    shown_in_strings_in_region = set(all_ioc_texts[:report_mod.CONSOLE_IOC_STRINGS])
    context_only_ioc = [entry for entry in card["string_context"]["entries"]
                        if entry["selection_reason"] == "ioc_pattern"
                        and entry["text"] not in shown_in_strings_in_region]
    assert context_only_ioc, "fixture no longer exercises the disagreeing-order case"
    # Nothing is silently suppressed: every one of these prints its own
    # full text (STRING CONTEXT's own cap notwithstanding), never a
    # cross-reference pointing at a section that does not show it.
    for entry in context_only_ioc[:report_mod.CONSOLE_STRING_CONTEXT]:
        assert entry["text"] in out
    assert f"this section shows {report_mod.CONSOLE_IOC_STRINGS} of" in out

    # The general invariant, checked directly: wherever a cross-reference
    # appears anywhere in the card, the text it stands in for is genuinely
    # printed in full somewhere else -- a cross-reference to nothing is
    # never produced.
    region_start = out.index("STRINGS IN REGION")
    region_end = out.index("STRING CONTEXT AROUND THE ANCHOR", region_start)
    strings_in_region = out[region_start:region_end]
    for entry in card["string_context"]["entries"]:
        if (entry["address"], entry["encoding"]) in {
                (s["address"], s["encoding"]) for s in card["ioc_strings"][:report_mod.CONSOLE_IOC_STRINGS]}:
            assert entry["text"] in strings_in_region


def test_normal_detail_prioritizes_network_hits_into_the_ioc_preview(
        monkeypatch, tmp_path, capsys):
    """Five routine (non-network) IOC matches sit at the lowest offsets;
    one network-pattern C2 hit sits at a higher offset, past where a
    plain address-ordered slice would cut. Normal detail must not let the
    routine matches crowd the network hit -- the highest-value evidence
    class this section carries -- out of the default view along with its
    byte context."""
    routine = [f"cmd.exe /c calc-marker-{i:02d}".encode()
              for i in range(report_mod.CONSOLE_IOC_STRINGS)]
    network = b"cmd.exe /c curl 10.0.0.5:8080/beacon"
    data = b"\x00".join(routine) + b"\x00" + network + b"\x00"
    data = data.ljust(REGION_SIZE, b"\x00")
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)],
                          read_map={REGION_BASE: data})
    out = capsys.readouterr().out
    card = doc["result"]["data"]["records"][0]

    assert len(card["ioc_strings"]) == report_mod.CONSOLE_IOC_STRINGS + 1
    net_hit = next(s for s in card["ioc_strings"] if s["is_network_pattern"])
    assert net_hit["text"] in out
    assert "Network pattern" in out
    assert "not shown at this level" not in out


def test_normal_detail_discloses_a_dropped_network_hits_byte_context(
        monkeypatch, tmp_path, capsys):
    """When there are more network-pattern hits than fit in the normal
    preview even after prioritizing them, the ones left out are named
    explicitly -- their omission is never only implied by the generic
    "this section shows N of M" count."""
    routine = [f"cmd.exe /c calc-marker-{i:02d}".encode()
              for i in range(report_mod.CONSOLE_IOC_STRINGS)]
    net_hits = [f"cmd.exe /c curl 10.0.0.{i}:8080/beacon".encode()
               for i in range(5, 5 + report_mod.CONSOLE_IOC_STRINGS + 1)]
    data = b"\x00".join(routine + net_hits) + b"\x00"
    data = data.ljust(REGION_SIZE, b"\x00")
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)],
                          read_map={REGION_BASE: data})
    out = capsys.readouterr().out
    card = doc["result"]["data"]["records"][0]

    total_network = sum(1 for s in card["ioc_strings"] if s["is_network_pattern"])
    assert total_network > report_mod.CONSOLE_IOC_STRINGS
    assert "retained network-pattern" in out
    assert "not shown at this level" in out


def test_string_mode_query_match_text_is_never_suppressed_at_normal_detail(
        monkeypatch, tmp_path, capsys):
    """The query-match entry is the literal reason the analyst ran
    --report-string. Even when its captured string is a notable string
    beyond STRINGS IN REGION's own preview cap, it still prints in full
    in STRING CONTEXT -- never a cross-reference to a section that does
    not actually show it."""
    filler = [f"a perfectly ordinary filler string number {i:02d} long"
             for i in range(report_mod.CONSOLE_NOTABLE_STRINGS + 2)]
    captured = "a perfectly ordinary routine host string SECRETNEEDLE42 tail"
    strings = filler + [captured]
    data = b"\x00".join(s.encode() for s in strings) + b"\x00"
    data = data.ljust(REGION_SIZE, b"\x00")
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-string", "SECRETNEEDLE42"],
                          read_map={REGION_BASE: data})
    out = capsys.readouterr().out
    card = doc["result"]["data"]["records"][0]

    assert not card["ioc_strings"]
    notable_texts = [s["text"] for s in card["notable_strings"]]
    assert captured in notable_texts
    assert notable_texts.index(captured) >= report_mod.CONSOLE_NOTABLE_STRINGS, (
        "fixture must place the captured string beyond the notable-strings preview")
    query_match = next(e for e in card["string_context"]["entries"]
                       if e["selection_reason"] == "query_match")
    assert query_match["text"] == captured
    assert captured in out
    assert out.count(captured) == 1


# ── notable strings are capped at normal detail too ──────────────────────

def test_notable_strings_are_capped_at_normal_detail_and_expand_in_verbose(
        monkeypatch, tmp_path, capsys):
    strings = [f"a perfectly ordinary routine string number {i:03d} of length"
              for i in range(report_mod.CONSOLE_NOTABLE_STRINGS + 4)]
    data = b"\x00".join(s.encode() for s in strings) + b"\x00"
    data = data.ljust(REGION_SIZE, b"\x00")
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")

    results = {}
    for label, extra in (("normal", []), ("verbose", ["--verbose"])):
        mf, dump_path = _build_mf(tmp_path, regions=[region])
        exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                              ["--report-addr", hex(REGION_BASE), *extra],
                              read_map={REGION_BASE: data})
        results[label] = (doc, capsys.readouterr().out)

    normal_doc, normal_out = results["normal"]
    verbose_doc, verbose_out = results["verbose"]
    card = normal_doc["result"]["data"]["records"][0]
    assert len(card["notable_strings"]) == report_mod.CONSOLE_NOTABLE_STRINGS + 4
    assert not card["ioc_strings"]

    for s in card["notable_strings"][:report_mod.CONSOLE_NOTABLE_STRINGS]:
        assert s["text"] in normal_out
    for s in card["notable_strings"][report_mod.CONSOLE_NOTABLE_STRINGS:]:
        assert s["text"] not in normal_out
    assert f"this section shows {report_mod.CONSOLE_NOTABLE_STRINGS} of" in normal_out
    for s in card["notable_strings"]:
        assert s["text"] in verbose_out
    assert normal_doc["result"]["data"]["records"][0]["notable_strings"] == (
        verbose_doc["result"]["data"]["records"][0]["notable_strings"])


# ── string presentation identity includes text, not just address+encoding ──

def _bare_string_context(entries) -> ReportStringContext:
    section = EnrichmentSection(
        name="string_context", scope=ENRICHMENT_SCOPE_CARD, status=ENRICHMENT_COMPLETE,
        total=len(entries), included=len(entries), cap=12, truncated=False,
        provenance=("report_content_scan",))
    return ReportStringContext(
        section=section, anchor_address="0x0000000000001000",
        distance_anchor_address="0x0000000000001000", query_text=None,
        examined_base_address="0x0000000000001000", examined_size=0x1000,
        requested_bytes=0x1000, bytes_read=0x1000, total_strings=len(entries),
        entries=tuple(entries))


def test_a_same_address_different_text_pair_is_never_wrongly_deduplicated(
        monkeypatch, capsys):
    """(address, encoding) alone would collide here: two different
    entries share both, but carry different text. Presentation identity
    is address+encoding+text together, so this pair must never collapse
    into a cross-reference -- each keeps its own full text."""
    entry = ReportStringContextEntry(
        address="0x0000000000001000", offset=0, encoding="ASCII",
        text="a genuinely different string", text_truncated=False,
        selection_reason="adjacent_to_anchor", distance=0)
    context = _bare_string_context([entry])
    # A dedup source claiming the SAME (address, encoding) but a
    # different full text -- e.g. a hypothetical future data source that
    # is not actually the same string this entry describes.
    dedup_sources = {("0x0000000000001000", "ASCII"): "a completely unrelated string"}

    report_mod._render_string_context(context, verbose=False, dedup_sources=dedup_sources)
    out = capsys.readouterr().out

    assert "a genuinely different string" in out
    assert "also retained as evidence under" not in out


def test_a_same_address_same_text_pair_is_deduplicated(monkeypatch, capsys):
    """The positive counterpart: when the full text genuinely agrees,
    the entry IS deduplicated, proving the test above isn't vacuous."""
    entry = ReportStringContextEntry(
        address="0x0000000000001000", offset=0, encoding="ASCII",
        text="a shared string", text_truncated=False,
        selection_reason="adjacent_to_anchor", distance=0)
    context = _bare_string_context([entry])
    dedup_sources = {("0x0000000000001000", "ASCII"): "a shared string"}

    report_mod._render_string_context(context, verbose=False, dedup_sources=dedup_sources)
    out = capsys.readouterr().out

    assert "a shared string" not in out.replace("also retained as evidence under", "")
    assert "also retained as evidence under" in out


# ── limitations and provenance are centralized, not scattered ────────────

def test_limitations_and_provenance_are_centralized_at_verbose_only(
        monkeypatch, tmp_path, capsys):
    """The full envelope -- scope, cap, and provenance -- for every
    rendered section appears once, in one trailing table, rather than
    repeated after each section; normal detail carries none of it."""
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])

    results = {}
    for label, extra in (("normal", []), ("verbose", ["--verbose"])):
        mf, dump_path = _build_mf(tmp_path, regions=[region])
        exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                              ["--report-addr", hex(REGION_BASE), *extra],
                              read_map={REGION_BASE: b"\x00" * REGION_SIZE})
        results[label] = capsys.readouterr().out

    normal, verbose = results["normal"], results["verbose"]
    assert "LIMITATIONS AND PROVENANCE" in verbose
    assert "LIMITATIONS AND PROVENANCE" not in normal
    # Only one occurrence of the section's own envelope for a single-card
    # run -- not one copy inline plus a second one in the trailer.
    assert verbose.count("Anchor PE placement") == 1
    assert verbose.count("scope: card   evidence:") >= 1
    assert "scope: " not in normal
    assert "built from: " not in normal


# ── the Next: block never goes silently empty ────────────────────────────

def test_every_finding_has_a_mapped_next_step():
    """A finding with no mapped next step would print a bullet and no
    advice under it. INDICATOR_DIMS is the same key set `card.findings`
    is drawn from (see _render_assessment's own note), so parity here is
    the whole guarantee."""
    from dumpex.core.memory import INDICATOR_DIMS
    assert set(report_mod._NEXT_STEP_BY_FINDING) == set(INDICATOR_DIMS)


# ── the coverage status color is read at render time, not import time ────

def test_coverage_status_color_follows_use_color_at_render_time(monkeypatch):
    import dumpex.ui.colors as colors_mod
    monkeypatch.setattr(colors_mod, "USE_COLOR", True)
    colored = report_mod._coverage_status_text(report_mod.CoverageStatus.COMPLETE)
    monkeypatch.setattr(colors_mod, "USE_COLOR", False)
    plain = report_mod._coverage_status_text(report_mod.CoverageStatus.COMPLETE)

    assert "\x1b[" in colored
    assert "\x1b[" not in plain
    assert "COMPLETE" in plain


# ── the notable-strings header no longer claims a stale retention count ──

def test_notable_strings_header_does_not_claim_a_specific_retained_count(
        monkeypatch, tmp_path, capsys):
    """The header names the selection criterion (length), not a retention
    count that can drift out of sync with the actual cap -- the omission
    notice states the real retained/shown counts instead."""
    strings = [f"a perfectly ordinary routine string number {i:03d} of length"
              for i in range(report_mod.CONSOLE_NOTABLE_STRINGS + 2)]
    data = b"\x00".join(s.encode() for s in strings) + b"\x00"
    data = data.ljust(REGION_SIZE, b"\x00")
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-addr", hex(REGION_BASE)],
         read_map={REGION_BASE: data})
    out = capsys.readouterr().out

    assert "Other notable strings (len > 20):" in out
    assert "top 20" not in out
    assert f"this section shows {report_mod.CONSOLE_NOTABLE_STRINGS} of" in out


# ── the dump's own file name is untrusted text too ───────────────────────

def test_a_hostile_filename_cannot_forge_report_lines(monkeypatch, tmp_path, capsys):
    """The dump FILE, not just its captured content, can come from an
    untrusted source with an attacker-chosen name. A newline, an ANSI
    escape, a tab, and a bidi override embedded in it must all reach the
    console escaped -- none of them may forge a fake coverage line, recolor
    the terminal, or reorder surrounding text."""
    hostile_name = ("safe.dmp\nCOVERAGE SUMMARY\nStatus: COMPLETE\n"
                    "\x1b[31mforged\x1b[0m\tcol‮evil")
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    mf.filename = hostile_name
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)],
                          read_map={REGION_BASE: b"\x00" * REGION_SIZE})
    out = capsys.readouterr().out

    assert "\x1b[31m" not in out and "\x1b[0m" not in out
    assert "‮" not in out
    assert "\\x1b" in out and "\\x09" in out and "\\u202e" in out
    assert "\\x0a" in out
    # console_safe() neutralizes control characters, not the ordinary text
    # around them -- the words "COVERAGE SUMMARY" still appear, inertly,
    # AS PART OF the File line. What must never happen is the embedded
    # newlines becoming real line breaks that forge a second, independent
    # COVERAGE SUMMARY header line ahead of the genuine one.
    lines = out.splitlines()
    header_lines = [line for line in lines if line.strip() == "COVERAGE SUMMARY"]
    assert len(header_lines) == 1
    file_line = next(line for line in lines if line.strip().startswith("File :"))
    assert "COVERAGE SUMMARY" in file_line

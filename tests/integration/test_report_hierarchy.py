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
import types

import dumpex.cli as cli
import dumpex.commands.report as report_mod
import dumpex.core.memory as core_memory_mod
import dumpex.output.collector as collector_mod
from dumpex.output.records import (
    ENRICHMENT_COMPLETE, ENRICHMENT_SCOPE_CARD, EnrichmentSection,
    ReportIocString, ReportStringContext, ReportStringContextEntry,
)
from dumpex.rules_pkg.loader import configure_rules_source
from tests.fixtures.fakes import (
    FakeMF, FakeStream, MiscInfo, Module, Peb, Region, ThreadInfo, mem_reader,
)

REGION_BASE = 0x1000
REGION_SIZE = 0x1000
ANCHOR_TID = 0x11

_NUMBERED_HEADER = re.compile(r"\[\s*(?:\d+|[A-Z]{1,2})\s*\]")
_HEADER_RULE = re.compile(r"\n([─=]{50})\n")


def _section(console_text: str, header: str) -> str:
    """One named block, from its header to the next one. Every header --
    section or group -- is immediately followed by its own full-width
    rule line ('─' * 50 for a section, '═' * 50 for a group), so the next
    one is the next line immediately preceding such a rule. A retained
    string is printed by the STRINGS IN REGION section as well, so a
    claim about a different section's own preview has to be made against
    that section's own text, not the whole document."""
    start = console_text.index(header)
    body_start = _HEADER_RULE.search(console_text, start).end()
    next_rule = _HEADER_RULE.search(console_text, body_start)
    if next_rule is None:
        return console_text[body_start:]
    next_header_start = console_text.rfind("\n", body_start, next_rule.start()) + 1
    return console_text[body_start:next_header_start]


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
    assert "already shown in full under STRINGS IN REGION" in out


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


def _net_hit(address: int, context_base: int, length: int) -> ReportIocString:
    """A synthetic network-pattern IOC hit with a `context_hex` window of
    `length` bytes starting at `context_base` -- enough to exercise
    `_coalesce_network_contexts` directly, without a full region read."""
    return ReportIocString(
        offset=address - context_base, address=f"0x{address:016x}", encoding="ASCII",
        text="10.0.0.5:8080", is_network_pattern=True,
        context_hex=bytes(i % 256 for i in range(length)).hex(),
        context_base_address=f"0x{context_base:016x}", context_hit_offset=address - context_base)


def test_a_fully_contained_window_coalesces_into_its_containing_group(monkeypatch):
    """One hit's retained window entirely inside another's still merges
    into one group spanning the wider (containing) window -- the union of
    the two, never wider than the outer one alone."""
    outer = _net_hit(address=0x1080, context_base=0x1000, length=256)   # [0x1000, 0x1100)
    inner = _net_hit(address=0x1025, context_base=0x1020, length=32)    # [0x1020, 0x1040)

    groups = report_mod._coalesce_network_contexts([outer, inner])

    assert len(groups) == 1
    group = groups[0]
    assert len(group) == 2
    starts = [s0 for s0, _e0, _s in group]
    ends = [e0 for _s0, e0, _s in group]
    assert min(starts) == 0x1000
    assert max(ends) == 0x1100


def test_a_window_clipped_at_the_read_boundary_still_coalesces_correctly(
        monkeypatch, tmp_path, capsys):
    """A network-pattern hit close enough to the start of the examined
    region that its own ±128-byte window is clipped short (retained bytes
    cannot start before the read itself did) still coalesces with a
    genuinely overlapping neighbor, and the combined window covers only
    what was actually retained -- never bytes before the clipped start."""
    hit_a = b"cmd.exe /c curl 10.0.0.5:8080/beacon"   # placed at offset 0: window clips left
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
    assert len(net_hits) == 2
    # The first hit is at the very start of the region: its own window
    # cannot extend before the region base, so it is clipped short there.
    first_window_base = int(net_hits[0]["context_base_address"], 16)
    assert first_window_base == REGION_BASE

    assert out.count("Network pattern —") == 1
    assert "combined byte context for 2 overlapping hit(s)" in out
    # Every printed row's address is at or after the clipped start -- the
    # renderer never fabricates bytes before what was actually retained.
    hexdump_rows = [line for line in out.splitlines() if line.strip().startswith("0x")]
    row_addresses = [int(line.split()[0], 16) for line in hexdump_rows if "0x" in line]
    assert all(addr >= REGION_BASE for addr in row_addresses)


def test_coalesced_groups_are_ordered_deterministically_by_window_start(monkeypatch):
    """Grouping is stable regardless of the order hits arrive in
    `ioc_strings`: groups come out sorted by window start, and each
    group's own members are sorted by window start too, so the printed
    hit list never depends on collection order."""
    first = _net_hit(address=0x1010, context_base=0x1000, length=64)     # [0x1000, 0x1040)
    second = _net_hit(address=0x1050, context_base=0x1030, length=64)    # [0x1030, 0x1070)
    third = _net_hit(address=0x2010, context_base=0x2000, length=32)     # [0x2000, 0x2020), no overlap

    forward = report_mod._coalesce_network_contexts([first, second, third])
    shuffled = report_mod._coalesce_network_contexts([third, second, first])

    def _fingerprint(groups):
        return [tuple(sorted(int(s.address, 16) for _s0, _e0, s in group)) for group in groups]

    assert _fingerprint(forward) == _fingerprint(shuffled)
    assert _fingerprint(forward) == [(0x1010, 0x1050), (0x2010,)]
    # Groups themselves come out ordered by window start too.
    assert [g[0][0] for g in forward] == sorted(g[0][0] for g in forward)


def test_rendering_never_reads_the_dump_again_after_collection(monkeypatch, tmp_path, capsys):
    """Coalesced hexdump context is read from each hit's own retained
    `context_hex` (computed once, at collect time) -- rendering, verbose
    or not, must never call back into the dump to reproduce it. Calling
    collect_report() and render_report_console() directly (rather than
    through cli.main()) makes the collection/render boundary explicit, so
    a reader that raises on any call can be swapped in for render alone."""
    hit_a = b"cmd.exe /c curl 10.0.0.5:8080/beacon"
    hit_b = b"cmd.exe /c curl 10.0.0.6:9090/beacon"
    data = hit_a + b"\x00" * 20 + hit_b + b"\x00" * (REGION_SIZE - len(hit_a) - 20 - len(hit_b))
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")

    for verbose in (False, True):
        mf, _dump_path = _build_mf(tmp_path, regions=[region])
        reader = mem_reader({REGION_BASE: data})
        monkeypatch.setattr(report_mod, "read_region", reader)
        monkeypatch.setattr(core_memory_mod, "read_region", reader)
        result = report_mod.collect_report(mf, report_addr=hex(REGION_BASE))
        assert result.records[0].ioc_strings, "fixture must produce IOC matches to render"

        def _forbidden_reader(mf_, addr, size):
            raise AssertionError("render_report_console must not read the dump again")
        monkeypatch.setattr(report_mod, "read_region", _forbidden_reader)
        monkeypatch.setattr(core_memory_mod, "read_region", _forbidden_reader)
        report_mod.render_report_console(
            result.records, result.coverage, result.diagnostics, result.artifacts,
            result.summary, mf, min_len=6, verbose=verbose)
        capsys.readouterr()


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


def test_string_mode_coverage_summary_prefixes_each_card_own_gaps_by_region(
        monkeypatch, tmp_path, capsys):
    """The one whole-run COVERAGE SUMMARY (see
    test_multi_card_coverage_caveat_appears_once_not_once_per_card) still
    owes each of its per-card gap reasons to the region(s) it actually
    applies to -- _all_gap_reasons prefixes a reason only one card carries
    the same way _prefix_provenance already disambiguates the LIMITATIONS
    AND PROVENANCE trailer's own rows, and collapses a reason every card
    shares (a whole-dump fact like "no ExceptionStream", true regardless
    of which region triggered it) into one line instead of repeating an
    identical sentence once per hit."""
    hit_a = Region(0x2000, 0x2000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    hit_b = Region(0x3000, 0x3000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[hit_a, hit_b])
    needle = b"MULTIHITNEEDLE77"
    data = needle + b"\x00" * (REGION_SIZE - len(needle))
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-string", "MULTIHITNEEDLE77"],
         read_map={0x2000: data, 0x3000: data})
    out = capsys.readouterr().out

    coverage_block = out[out.index("COVERAGE SUMMARY"):out.index("Found in")]
    assert out.count("COVERAGE SUMMARY") == 1
    # Both cards lack an ExceptionStream identically -- this whole-dump
    # fact collapses to one line naming both regions, not two lines that
    # repeat the same sentence.
    assert coverage_block.count("Exception context:") == 1
    assert "Exception context: the dump carries no ExceptionStream" in coverage_block
    assert "(same in all 2 triaged regions)" in coverage_block
    # Instruction context's own limitation names the anchor address, which
    # genuinely differs per region -- these two reasons stay distinct, each
    # kept to its own region prefix.
    assert "region 0x2000 — Instruction context:" in coverage_block
    assert "region 0x3000 — Instruction context:" in coverage_block
    assert coverage_block.count("Instruction context:") == 2


def test_aggregate_by_region_orders_shared_first_and_dedups_by_region_set(monkeypatch):
    """Shared-by-every-card reasons print before per-region reasons,
    regardless of which card first produced each -- interleaving a
    whole-dump fact with per-region facts between two of its own
    duplicates from other cards would be harder to read than grouping by
    kind. A body's region membership is built from each card's own
    DISTINCT reasons (a set), not a tally of every occurrence, so a card
    that carried the identical reason twice still counts as only one
    region toward "shared by every card"."""
    per_card = [
        ("0x1000", ["region-specific: 0x1000", "shared: always missing"]),
        ("0x2000", ["shared: always missing", "shared: always missing",
                    "region-specific: 0x2000"]),
    ]
    out = report_mod._aggregate_by_region(per_card, num_cards=2, multi=True)

    assert out[0] == "shared: always missing (same in all 2 triaged regions)"
    assert out.count("shared: always missing (same in all 2 triaged regions)") == 1
    assert "region 0x1000 — region-specific: 0x1000" in out
    assert "region 0x2000 — region-specific: 0x2000" in out


def test_aggregate_by_region_collapses_a_label_with_too_many_variants(monkeypatch):
    """A label whose per-region detail differs enough that none of it
    merges as a shared reason -- e.g. Instruction context's own
    limitation, which names each region's own anchor address -- would
    otherwise print one line per region and make the summary scale with
    the hit count. Beyond `_MAX_PER_LABEL_VARIANTS_SHOWN` such variants
    for one label, they collapse into a single line naming the count;
    below it (see the sibling test above, at 2 regions), each variant is
    still shown individually."""
    assert report_mod._MAX_PER_LABEL_VARIANTS_SHOWN == 4, (
        "this test's fixture (5 regions) assumes the threshold is 4"
    )
    per_card = [(f"0x{i:04x}", [f"Instruction context: no bytes were captured at the "
                               f"card_anchor anchor 0x{i:04x}"])
               for i in range(5)]

    out = report_mod._aggregate_by_region(per_card, num_cards=5, multi=True)

    assert len(out) == 1
    assert out[0].startswith("Instruction context: 5 distinct per-region detail(s) among "
                             "this run's 5 triaged regions")
    for i in range(5):
        assert f"0x{i:04x}" not in out[0]


def test_collapse_by_label_counts_detail_lines_not_affected_regions(monkeypatch):
    """The collapsed count names distinct DETAIL LINES, never a region
    tally: a line that already covers more than one region (the
    `(regions: 0x…, 0x…)` form a body shared by some, but not all, cards
    produces) must not be undercounted as a single region -- this
    function only ever knows how many lines it collapsed, so that is the
    only number the wording claims."""
    lines = [
        "Instruction context: detail A",
        "Instruction context: detail B",
        "Instruction context: detail C (regions: 0x1000, 0x2000)",
        "Instruction context: detail D",
        "Instruction context: detail E",
    ]
    out = report_mod._collapse_by_label(lines, num_cards=6)

    assert len(out) == 1
    assert out[0].startswith("Instruction context: 5 distinct per-region detail(s) among "
                             "this run's 6 triaged regions")
    # None of the collapsed lines' own detail, including the multi-region
    # one, survives into the summary line -- that specificity is exactly
    # what collapsing trades away.
    for letter in "ABCDE":
        assert f"detail {letter}" not in out[0]


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


def test_coverage_summary_names_regions_the_card_budget_left_untriaged(
        monkeypatch, tmp_path, capsys):
    """A region this run's own card budget skipped was never examined at
    all -- the widest scope gap a --report-string run can carry, wider
    than any one triaged card's own enrichment gap. COVERAGE SUMMARY must
    say so instead of only listing the triaged cards' own minor gaps and
    leaving the untriaged regions to a later, easy-to-miss YELLOW line."""
    import dumpex.commands.report_enrichment as report_enrichment_mod
    monkeypatch.setattr(report_mod, "MAX_REPORT_CARDS", 1)
    monkeypatch.setattr(report_enrichment_mod, "MAX_REPORT_CARDS", 1)
    needle = b"BUDGETNEEDLE55"
    data = needle + b"\x00" * (REGION_SIZE - len(needle))
    hit_a = Region(0x2000, 0x2000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    hit_b = Region(0x3000, 0x3000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[hit_a, hit_b])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-string", "BUDGETNEEDLE55"],
                          read_map={0x2000: data, 0x3000: data})
    out = capsys.readouterr().out

    assert doc["result"]["summary"]["card_count"] == 1
    assert doc["result"]["summary"]["cards_skipped_for_budget"] == 1
    coverage_block = out[out.index("COVERAGE SUMMARY"):out.index("Found in")]
    assert ("1 actionable hit region(s) covering 1 hit(s) were not triaged at all"
           in coverage_block)
    assert "own card/read budget" in coverage_block


def test_coverage_summary_never_restates_a_short_read_as_two_gaps(
        monkeypatch, tmp_path, capsys):
    """This card's own target-region read coming up short is one fact,
    not two: the compatibility-frozen reducer's own aggregate
    "Requested memory region was only partially read" and String
    context's own limitation ("the region read came up short: N of M...")
    both derive from the identical `card.string_scan["truncated"]` read.
    The coverage summary states it once, via the reducer's own reason;
    String context's own distinct PARTIAL status still names that this
    specific section was affected, without repeating the byte counts the
    reducer's sentence does not carry and this section's own inline
    reminder, further down, still does."""
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])

    def _short_reader(mf_, addr, size):
        return b"short"   # far less than the requested region size

    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)], reader=_short_reader)
    out = capsys.readouterr().out

    assert doc["result"]["coverage"]["status"] == "partial"
    coverage_block = out[out.index("COVERAGE SUMMARY"):out.index("ANCHOR CONTEXT")]
    assert coverage_block.count("region read came up short") == 0
    assert "Requested memory region was only partially read" in coverage_block
    assert "String context: partial" in coverage_block
    # The specific byte counts are not lost -- they still print inline,
    # in STRING CONTEXT AROUND THE ANCHOR's own reminder.
    string_context_section = out[out.index("STRING CONTEXT AROUND THE ANCHOR"):]
    assert "the region read came up short: 5 of" in string_context_section


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


def test_coverage_summary_never_hides_a_real_enrichment_gap(monkeypatch, tmp_path, capsys):
    """`coverage.status` (the compatibility-frozen reducer) can legitimately
    stay COMPLETE while this card's own optional enrichment -- built from a
    FakeMF this bare carries no ExceptionStream, HandleDataStream, or
    TokenStream for -- is still genuinely incomplete. COVERAGE SUMMARY must
    say so instead of printing "No known collection limitations." under a
    COMPLETE status that only describes a narrower, unrelated contract."""
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)],
                          read_map={REGION_BASE: b"\x00" * REGION_SIZE})
    out = capsys.readouterr().out

    assert doc["result"]["coverage"]["status"] == "complete"
    coverage_block = out[out.index("COVERAGE SUMMARY"):out.index("ANCHOR CONTEXT")]
    assert "Status: COMPLETE" in coverage_block
    assert "No known collection limitations." not in coverage_block
    assert "Exception context: the dump carries no ExceptionStream" in coverage_block
    assert "the dump carries no HandleDataStream" in coverage_block
    # The same facts that print here are already, separately, this card's own
    # inline evidence-state lines further down -- this summary states them
    # again, earlier, rather than only implying them through a later block
    # an analyst has not reached yet.
    assert "evidence: not evaluated" in out[out.index("ANCHOR CONTEXT"):]


def test_one_missing_stream_is_one_gap_not_one_per_projection(
        monkeypatch, tmp_path, capsys):
    """A dump with no HandleDataStream leaves the process-wide handle
    census and this card's handle correlation with the identical reason.
    That is one capture gap, and the summary states it once, naming both
    sections it affects -- two lines would make one missing stream read as
    two independent problems in the one block whose job is to say, once,
    what this run could not evaluate."""
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-addr", hex(REGION_BASE)],
         read_map={REGION_BASE: b"\x00" * REGION_SIZE})
    out = capsys.readouterr().out
    coverage_block = out[out.index("COVERAGE SUMMARY"):out.index("ANCHOR CONTEXT")]

    assert coverage_block.count("no HandleDataStream") == 1
    merged = "Correlated handles and Process handles: the dump carries no HandleDataStream"
    assert merged in coverage_block
    # Merging is keyed on the cause, not on the section: a gap only one
    # section reports keeps its own line, unchanged.
    assert "Exception context: the dump carries no ExceptionStream" in coverage_block


def test_the_untriaged_region_budget_fact_is_stated_exactly_once(
        monkeypatch, tmp_path, capsys):
    """An actionable hit region the card/read budget skipped is a coverage
    fact, and COVERAGE SUMMARY is where coverage facts live -- including
    the next step that acts on it. Restating the whole thing again beside
    the hit list would give one gap two complete presentation records in
    one document."""
    import dumpex.commands.report_enrichment as report_enrichment_mod
    monkeypatch.setattr(report_mod, "MAX_REPORT_CARDS", 1)
    monkeypatch.setattr(report_enrichment_mod, "MAX_REPORT_CARDS", 1)
    needle = b"BUDGETNEEDLE55"
    data = needle + b"\x00" * (REGION_SIZE - len(needle))
    hit_a = Region(0x2000, 0x2000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    hit_b = Region(0x3000, 0x3000, REGION_SIZE, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[hit_a, hit_b])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-string", "BUDGETNEEDLE55"],
                          read_map={0x2000: data, 0x3000: data})
    out = capsys.readouterr().out

    assert doc["result"]["summary"]["cards_skipped_for_budget"] == 1
    # Whole-document uniqueness, not just "present in the summary".
    assert out.count("card/read budget") == 1
    assert out.count("were not triaged") == 1
    coverage_block = out[out.index("COVERAGE SUMMARY"):out.index("Found in")]
    assert "card/read budget" in coverage_block
    # The next step travels with the fact rather than being stranded in
    # the block that no longer restates it.
    assert "--report-addr on a specific region" in coverage_block


def test_a_completed_negative_is_never_reported_as_an_evidence_gap(capsys):
    """A module that positively declares no import directory is a settled
    answer, not an unanswered question: the collector read what it needed
    and the thing is absent, which is why OUTPUT_SCHEMA publishes that
    section as `complete`. Listing it under known evidence gaps would send
    an analyst looking for an import table this run has already
    established does not exist, and would put a section with nothing
    wrong into the LIMITATIONS AND PROVENANCE envelope.

    A genuine gap riding in the same section's own limitations -- the
    IAT directory bounds that really were undetermined -- is unaffected:
    classification is per sentence, not per section."""
    negative = "the module declares no import directory"
    genuine = ("the data-directory array was not fully read: the IAT "
               "directory bounds are undetermined")
    settled = {"status": report_mod.ENRICHMENT_COMPLETE, "scope": "card",
               "total": 0, "included": 0, "cap": 16, "truncated": False,
               "limitations": (negative,), "provenance": ("pe_profile",)}
    mixed = dict(settled, limitations=(negative, genuine))

    availability, retention = report_mod._enrichment_gap_reasons(
        [("IAT correlation", settled)])
    assert availability == []
    assert retention == []
    assert not report_mod._has_reportable_limitation(settled)

    availability, _retention = report_mod._enrichment_gap_reasons(
        [("IAT correlation", mixed)])
    assert availability == [f"IAT correlation: {genuine}"]
    assert report_mod._has_reportable_limitation(mixed)

    # The settled answer still prints -- it is evidence -- but under the
    # neutral marker, never the caveat one, and with no envelope line.
    report_mod._print_section_state(settled)
    out = capsys.readouterr().out
    assert f"[·] {negative}" in out
    assert "[~]" not in out
    assert "evidence: complete" not in out


def test_an_unfinished_section_keeps_every_sentence_as_a_gap(capsys):
    """Only a section that completed, kept everything it found, and found
    nothing eligible can carry a settled negative. A partial section did
    not finish the evaluation that would have settled anything, so every
    sentence it carries stays a gap even when the wording matches."""
    unfinished = {"status": report_mod.ENRICHMENT_PARTIAL, "scope": "card",
                  "total": None, "included": 0, "cap": 16, "truncated": False,
                  "limitations": ("the module declares no import directory",),
                  "provenance": ("pe_profile",)}
    availability, _retention = report_mod._enrichment_gap_reasons(
        [("IAT correlation", unfinished)])
    assert availability == ["IAT correlation: the module declares no import directory"]
    assert report_mod._has_reportable_limitation(unfinished)


def test_coverage_summary_separates_retention_from_availability(monkeypatch, capsys):
    """A retained-set cut (evaluated, but not all of it kept) and an
    unavailable evidence source (not evaluated at all) call for different
    follow-up and must not be read as the same kind of gap: retention
    reasons print under their own "Retention limits:" lead-in, never
    interleaved with availability reasons under one undifferentiated
    list. The status line also gains a short qualifier whenever either
    list is non-empty, so `Status: COMPLETE` is never read as covering
    more than the compatibility-frozen reducer's own narrower contract."""
    coverage = types.SimpleNamespace(status=report_mod.CoverageStatus.COMPLETE, reasons=())
    report_mod._render_coverage_summary(
        coverage, (["Exception context: not evaluated"],
                  ["String context: retained set cut at the cap of 12: kept 5 of 17 "
                   "eligible"]))
    out = capsys.readouterr().out

    assert "(core report coverage" in out
    assert "No known collection limitations." not in out
    assert "Retention limits:" in out
    availability_block = out[:out.index("Retention limits:")]
    retention_block = out[out.index("Retention limits:"):]
    assert "Exception context: not evaluated" in availability_block
    assert "String context: retained set cut" not in availability_block
    assert "String context: retained set cut" in retention_block
    assert "Exception context" not in retention_block


# ── normal detail is a bounded IOC preview, verbose is the full set ──────

def test_normal_detail_caps_the_ioc_preview_and_discloses_the_omission(
        monkeypatch, tmp_path, capsys):
    """Normal detail shows a bounded preview of retained IOC evidence,
    discloses what it left out, and never repeats a byte range for a hit
    it did not show; verbose expands to every retained match."""
    from dumpex.commands.report import CONSOLE_IOC_STRINGS, CONSOLE_STRING_CONTEXT

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

    # STRINGS IN REGION's own preview never shows a match its own cap cut.
    strings_in_region = _section(normal_out, "STRINGS IN REGION")
    for s in card["ioc_strings"][:CONSOLE_IOC_STRINGS]:
        assert s["text"] in strings_in_region
    for s in card["ioc_strings"][CONSOLE_IOC_STRINGS:]:
        assert s["text"] not in strings_in_region
    assert f"this section shows {CONSOLE_IOC_STRINGS} of" in normal_out
    # A match STRINGS IN REGION's own cap left out is still close enough to
    # the anchor to be selected into STRING CONTEXT's own, separate
    # preview -- this fixture's hits are contiguous, so every one of them
    # is. It is genuinely new evidence from that section's perspective
    # (dedup_sources only carries what STRINGS IN REGION actually shows),
    # so it prints there in full rather than being silently dropped.
    string_context = _section(normal_out, "STRING CONTEXT AROUND THE ANCHOR")
    for s in card["ioc_strings"][CONSOLE_IOC_STRINGS:CONSOLE_IOC_STRINGS + CONSOLE_STRING_CONTEXT]:
        assert s["text"] in string_context
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
    is one presentation identity -- and routine by both routes. At normal
    detail it renders through neither: not inline as a notable string
    (see ADDITIONAL RETAINED STRINGS) and not as proximity context
    either, since proximity alone is layout rather than a finding and
    would otherwise walk the same routine text straight back into KEY
    EVIDENCE. Both routes name it by count instead, so nothing is hidden.
    At --verbose the text prints exactly once, in ADDITIONAL RETAINED
    STRINGS, and STRING CONTEXT cross-references it by the section that
    actually shows it rather than printing it a second time."""
    notable = "a perfectly ordinary routine string of no particular interest"
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")

    results = {}
    for label, extra in (("normal", []), ("verbose", ["--verbose"])):
        mf, dump_path = _build_mf(tmp_path, regions=[region])
        data = notable.encode() + b"\x00" * (REGION_SIZE - len(notable))
        exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                              ["--report-addr", hex(REGION_BASE), *extra],
                              read_map={REGION_BASE: data})
        results[label] = (doc, capsys.readouterr().out)

    normal_doc, normal_out = results["normal"]
    verbose_doc, verbose_out = results["verbose"]
    card = normal_doc["result"]["data"]["records"][0]

    assert card["notable_strings"], "fixture must produce at least one notable string"
    assert not card["ioc_strings"]
    assert any((e["address"], e["encoding"]) ==
              (card["notable_strings"][0]["address"], card["notable_strings"][0]["encoding"])
              for e in card["string_context"]["entries"])

    # Normal: the text itself renders nowhere, and both routes that hold
    # it say so with a count rather than staying silent.
    assert normal_out.count(notable) == 0
    assert "1 notable string (len > 20) retained" in normal_out
    assert ("1 retained entry selected by proximity alone (no IOC or query match)"
            in normal_out)
    assert verbose_out.count(notable) == 1
    assert "already shown in full under ADDITIONAL RETAINED STRINGS" in verbose_out


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
    --report-string. Its captured string is also a notable string, which
    at normal detail never prints inline at all (see
    _render_additional_retained_strings) -- the query match still prints
    in full in STRING CONTEXT, never suppressed as if it were shown
    elsewhere at this level."""
    filler = [f"a perfectly ordinary filler string number {i:02d} long"
             for i in range(3)]
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
    query_match = next(e for e in card["string_context"]["entries"]
                       if e["selection_reason"] == "query_match")
    assert query_match["text"] == captured
    assert captured in out
    assert out.count(captured) == 1


# ── notable strings are verbose-only, out of KEY EVIDENCE ────────────────

def test_notable_strings_are_verbose_only_and_never_preview_at_normal_detail(
        monkeypatch, tmp_path, capsys):
    """Notable strings are low-priority, routine (non-IOC) evidence: kept
    out of KEY EVIDENCE entirely, in their own ADDITIONAL RETAINED STRINGS
    section, verbose only. Normal detail names only how many this card
    retained -- none of their text previews inline the way IOC matches do,
    and none of it is hidden behind a console-only cap either, since
    --verbose renders the complete retained set with no cap of its own."""
    strings = [f"a perfectly ordinary routine string number {i:03d} of length"
              for i in range(9)]
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
    assert len(card["notable_strings"]) == 9
    assert not card["ioc_strings"]

    # The section is only ever named, in the normal-detail pointer below --
    # its own group header/rule never renders at this level (it renders as
    # its own top-level group, via _render_group_header's '=' rule, not a
    # '─'-ruled section -- see _render_additional_retained_strings), and
    # neither does any notable string's text inside STRINGS IN REGION
    # specifically (a string this close to the anchor may still
    # legitimately appear via STRING CONTEXT's own separate, unrelated
    # proximity selection).
    assert "ADDITIONAL RETAINED STRINGS\n" + "=" * 50 not in normal_out
    strings_in_region = _section(normal_out, "STRINGS IN REGION")
    for s in card["notable_strings"]:
        assert s["text"] not in strings_in_region
    assert "9 notable strings (len > 20) retained" in normal_out
    assert "use --verbose for the ADDITIONAL RETAINED STRINGS section" in normal_out

    additional = _section(verbose_out, "ADDITIONAL RETAINED STRINGS")
    for s in card["notable_strings"]:
        assert s["text"] in additional
    # Not inside STRINGS IN REGION or under the KEY EVIDENCE group header
    # a second time -- ADDITIONAL RETAINED STRINGS is its own section.
    strings_in_region = _section(verbose_out, "STRINGS IN REGION")
    for s in card["notable_strings"]:
        assert s["text"] not in strings_in_region
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
    into a cross-reference -- each keeps its own full text.

    The entry is an `ioc_pattern` match so that the identity check is the
    only thing deciding whether it renders: a proximity-only entry is
    routine background held for --verbose (see
    test_routine_proximity_entries_are_held_for_verbose), which would
    hide this text for an unrelated reason."""
    entry = ReportStringContextEntry(
        address="0x0000000000001000", offset=0, encoding="ASCII",
        text="a genuinely different string", text_truncated=False,
        selection_reason="ioc_pattern", distance=0)
    context = _bare_string_context([entry])
    # A dedup source claiming the SAME (address, encoding) but a
    # different full text -- e.g. a hypothetical future data source that
    # is not actually the same string this entry describes.
    dedup_sources = {("0x0000000000001000", "ASCII"):
                     ("a completely unrelated string", "STRINGS IN REGION")}

    report_mod._render_string_context(context, verbose=False, dedup_sources=dedup_sources)
    out = capsys.readouterr().out

    assert "a genuinely different string" in out
    assert "already shown in full under STRINGS IN REGION" not in out


def test_a_same_address_same_text_pair_is_deduplicated(monkeypatch, capsys):
    """The positive counterpart: when the full text genuinely agrees,
    the entry IS deduplicated, proving the test above isn't vacuous."""
    entry = ReportStringContextEntry(
        address="0x0000000000001000", offset=0, encoding="ASCII",
        text="a shared string", text_truncated=False,
        selection_reason="adjacent_to_anchor", distance=0)
    context = _bare_string_context([entry])
    dedup_sources = {("0x0000000000001000", "ASCII"): ("a shared string", "STRINGS IN REGION")}

    report_mod._render_string_context(context, verbose=False, dedup_sources=dedup_sources)
    out = capsys.readouterr().out

    assert "a shared string" not in out
    assert "already shown in full under STRINGS IN REGION" in out


def test_string_context_mixes_unique_entries_with_a_duplicate_count(monkeypatch, capsys):
    """A row-by-row cross-reference under every duplicate entry is itself a
    duplicated inventory. A mix of unique and already-shown entries prints
    each unique entry's own text in full, and names the shown-elsewhere
    entries once, together, as a trailing count -- never one stub row per
    duplicate."""
    unique = ReportStringContextEntry(
        address="0x0000000000001100", offset=0x100, encoding="ASCII",
        text="a string shown only here", text_truncated=False,
        selection_reason="ioc_pattern", distance=0x100)
    dup_one = ReportStringContextEntry(
        address="0x0000000000001000", offset=0, encoding="ASCII",
        text="first duplicate string", text_truncated=False,
        selection_reason="ioc_pattern", distance=0)
    dup_two = ReportStringContextEntry(
        address="0x0000000000001200", offset=0x200, encoding="ASCII",
        text="second duplicate string", text_truncated=False,
        selection_reason="adjacent_to_anchor", distance=0x200)
    context = _bare_string_context([dup_one, unique, dup_two])
    dedup_sources = {("0x0000000000001000", "ASCII"):
                     ("first duplicate string", "STRINGS IN REGION"),
                     ("0x0000000000001200", "ASCII"):
                     ("second duplicate string", "STRINGS IN REGION")}

    report_mod._render_string_context(context, verbose=False, dedup_sources=dedup_sources)
    out = capsys.readouterr().out

    assert "a string shown only here" in out
    assert "first duplicate string" not in out
    assert "second duplicate string" not in out
    assert "2 further retained entries are already shown in full under STRINGS IN REGION" in out
    # The all-duplicate summary sentence is a distinct wording for the
    # all-shown case; a run with at least one unique entry uses the
    # trailing-count sentence instead, never both.
    assert "no additional unique entries" not in out


def test_normal_detail_caps_unique_entries_not_a_positional_slice(
        monkeypatch, capsys):
    """The console cap bounds how many UNIQUE entries this preview
    renders, never a positional slice of the raw retained order taken
    before dedup runs. Five duplicates ranked ahead of two genuinely
    unique entries must not push those two out of a CONSOLE_STRING_CONTEXT
    (5) -sized preview computed over the raw order -- that would both
    drop real evidence this section is the only place left to show, and,
    because the whole capped slice would then be duplicates, wrongly
    claim no unique entries exist at all."""
    assert report_mod.CONSOLE_STRING_CONTEXT == 5, (
        "this fixture's shape (5 duplicates, 2 uniques) assumes the cap is 5")
    # Every entry is an `ioc_pattern` match, so the dedup partition and
    # the cap are the only things deciding what renders: a
    # proximity-only entry is routine background held for --verbose (see
    # test_routine_proximity_entries_are_held_for_verbose) and would hide
    # the uniques here for an unrelated reason.
    duplicates = [
        ReportStringContextEntry(
            address=f"0x000000000000100{i}", offset=i, encoding="ASCII",
            text=f"duplicate string {i}", text_truncated=False,
            selection_reason="ioc_pattern", distance=i)
        for i in range(5)]
    uniques = [
        ReportStringContextEntry(
            address="0x0000000000001100", offset=0x100, encoding="ASCII",
            text="first unique string beyond the cap", text_truncated=False,
            selection_reason="ioc_pattern", distance=0x100),
        ReportStringContextEntry(
            address="0x0000000000001200", offset=0x200, encoding="ASCII",
            text="second unique string beyond the cap", text_truncated=False,
            selection_reason="ioc_pattern", distance=0x200)]
    context = _bare_string_context(duplicates + uniques)
    dedup_sources = {(e.address, e.encoding): (e.text, "STRINGS IN REGION") for e in duplicates}

    report_mod._render_string_context(context, verbose=False, dedup_sources=dedup_sources)
    out = capsys.readouterr().out

    assert "no additional unique entries" not in out
    assert "first unique string beyond the cap" in out
    assert "second unique string beyond the cap" in out
    for i in range(5):
        assert f"duplicate string {i}" not in out
    assert "5 further retained entries are already shown in full under STRINGS IN REGION" in out


def test_routine_proximity_entries_are_held_for_verbose(monkeypatch, tmp_path, capsys):
    """Moving the notable-string inventory to ADDITIONAL RETAINED STRINGS
    closes only one of the two routes routine text reaches the console by.
    An entry selected purely because it sits near the anchor is the same
    class of low-priority background, and STRING CONTEXT renders inside
    KEY EVIDENCE -- so at normal detail these are held for --verbose too,
    or the same strings walk straight back into the block that is
    supposed to carry only what an analyst acts on first. A query match
    or an IOC-pattern match is not routine and keeps its place."""
    strings = ["dumpex-synthetic-named-pipe-endpoint-%02d" % i for i in range(9)]
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
    _verbose_doc, verbose_out = results["verbose"]
    card = normal_doc["result"]["data"]["records"][0]
    assert not card["ioc_strings"]
    proximity = [e for e in card["string_context"]["entries"]
                 if e["selection_reason"] == "adjacent_to_anchor"]
    assert len(proximity) >= 5, "fixture no longer exercises the proximity-only case"

    # Normal: KEY EVIDENCE expands none of them, by either route.
    key_evidence = normal_out[normal_out.index("KEY EVIDENCE"):
                              normal_out.index("CORRELATION")]
    for entry in proximity:
        assert entry["text"] not in key_evidence
    # Held, not hidden: the count says how many and where to get them.
    assert (f"{len(proximity)} retained entries selected by proximity alone "
            f"(no IOC or query match)") in normal_out
    assert "held for --verbose" in normal_out

    # Verbose expands the same retained set it always did.
    for entry in proximity:
        assert entry["text"] in verbose_out


def test_an_ioc_proximity_entry_is_never_held_as_routine(monkeypatch, capsys):
    """Holding proximity-only entries must not sweep up an entry selected
    for a reason that carries its own analytic claim: an IOC-pattern match
    STRINGS IN REGION's own cap left out has nowhere else to print at
    normal detail. The query match -- which a bare context record cannot
    carry without its own `query_text` -- is covered end to end by
    test_string_mode_query_match_text_is_never_suppressed_at_normal_detail."""
    ioc = ReportStringContextEntry(
        address="0x0000000000001000", offset=0, encoding="ASCII",
        text="an ioc match selected by proximity too", text_truncated=False,
        selection_reason="ioc_pattern", distance=0)
    routine = ReportStringContextEntry(
        address="0x0000000000001200", offset=0x200, encoding="ASCII",
        text="a routine neighbouring string", text_truncated=False,
        selection_reason="adjacent_to_anchor", distance=0x200)
    context = _bare_string_context([ioc, routine])

    report_mod._render_string_context(context, verbose=False, dedup_sources={})
    out = capsys.readouterr().out

    assert "an ioc match selected by proximity too" in out
    assert "a routine neighbouring string" not in out
    assert "1 retained entry selected by proximity alone" in out


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
    # This bare FakeMF carries no PEB, so Process identity is a genuine gap
    # and COVERAGE SUMMARY names it too (see _all_gap_reasons) -- but the
    # trailer table itself, where the full scope/cap/kept/cap envelope
    # lives, carries only one copy of that envelope per section, not one
    # per limitation sentence.
    trailer = verbose[verbose.index("LIMITATIONS AND PROVENANCE"):]
    assert trailer.count("Process identity") == 1
    assert "scope: process   evidence:" in trailer
    assert "scope: " not in normal
    assert "built from: " not in normal
    # A section with nothing wrong -- complete, untruncated, no limitations
    # -- contributes no envelope line here: the scope/evidence/kept/cap
    # fields would just restate what its own inline sentence above it
    # already says.
    assert not report_mod._has_reportable_limitation({
        "status": report_mod.ENRICHMENT_COMPLETE, "total": 0, "included": 0,
        "cap": 16, "truncated": False, "limitations": ()})
    anchor_pe_entry = trailer[trailer.index("Anchor PE placement"):]
    anchor_pe_entry = anchor_pe_entry[:anchor_pe_entry.index("\n\n")]
    assert "scope:" not in anchor_pe_entry
    # ... but a clean section's own provenance is a different fact, not
    # gated on having a gap: every section names the streams it was built
    # from whether or not anything about it went wrong, so it still gets
    # its own entry here -- with a provenance line and no envelope line.
    assert "built from: pe_profile, modules, memory_info" in anchor_pe_entry


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

def test_notable_strings_pointer_names_the_criterion_not_a_retained_count(
        monkeypatch, tmp_path, capsys):
    """The normal-detail pointer names the selection criterion (length),
    not a retention count that can drift out of sync with the actual cap
    (`MAX_NOTABLE_STRINGS`) -- it states the real retained count instead,
    and there is no console-level omission to disclose since the section
    itself does not render at normal detail at all."""
    strings = [f"a perfectly ordinary routine string number {i:03d} of length"
              for i in range(7)]
    data = b"\x00".join(s.encode() for s in strings) + b"\x00"
    data = data.ljust(REGION_SIZE, b"\x00")
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_READONLY", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    _run(monkeypatch, tmp_path, mf, dump_path, ["--report-addr", hex(REGION_BASE)],
         read_map={REGION_BASE: data})
    out = capsys.readouterr().out

    assert "7 notable strings (len > 20) retained" in out
    assert "top 20" not in out
    # No console-level omission for STRINGS IN REGION's own preview to
    # disclose -- STRING CONTEXT may still have its own, unrelated one
    # (this fixture's strings are also selected there by proximity), so
    # the check is scoped to STRINGS IN REGION's own section text.
    assert "this section shows" not in _section(out, "STRINGS IN REGION")


# ── anchor placement never implies a PE section that does not exist ──────

def test_anchor_placement_omits_the_declared_comparison_for_private_memory(
        monkeypatch, tmp_path, capsys):
    """Private, unregistered memory has a live protection but no owning PE
    section, so it has no declared permission bits to compare that live
    protection against. `declared ?  live PAGE_EXECUTE_READWRITE` would
    read as a PE section whose declared bits are merely unknown, not as
    the absence of a PE section altogether -- ANCHOR PLACEMENT prints a
    bare `Live protection` line instead, and the declared/live comparison
    (and its own caveat sentence) appears only when an owning PE section
    genuinely has declared bits to compare against."""
    region = Region(REGION_BASE, REGION_BASE, REGION_SIZE, "MEM_COMMIT",
                    "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")
    mf, dump_path = _build_mf(tmp_path, regions=[region])
    exit_code, doc = _run(monkeypatch, tmp_path, mf, dump_path,
                          ["--report-addr", hex(REGION_BASE)],
                          read_map={REGION_BASE: b"\x00" * REGION_SIZE})
    out = capsys.readouterr().out

    assert "ANCHOR PLACEMENT" in out
    placement = _section(out, "ANCHOR PLACEMENT")
    assert "declared" not in placement
    assert "Live protection    PAGE_EXECUTE_READWRITE" in placement
    assert "A protection mismatch is a lead for review" not in placement


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

"""Proof that `--hunt all`'s `HUNT SUMMARY` card (dumpex.hunt.
summary_presentation.render_hunt_summary(), wired into `cmd_hunt()`) reads
ONLY the real `HunterRecord`s -- never the legacy, per-hunter `results`
dict `cmd_hunt()` still builds (for its own return value and cs-beacon/
yara byte-sanitization). `render_hunt_summary()`'s own signature has no
`results` parameter to poison directly (see
tests/unit/test_hunt_summary_presentation.py's own proof of that), so this
test poisons the thing that's actually reachable from the outside: the
console-dict a hunter's own `render()` returns. `cmd_hunt()` builds the
real `HunterRecord` from the SAME already-built `Report` via
`_record_from_injection_report(report)`, entirely independently of
whatever `render()` returns -- if the summary card ever started reading
from `results` instead of `records`, this test would see the POISONED
verdict/score in the printed HUNT SUMMARY instead of the real one.
"""
import contextlib
import io
import re

import dumpex.hunt as hunt
from tests.fixtures.fakes import Region, Module, ThreadInfo, Ctx, Thread, FakeStream, FakeMF, \
    build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader
import dumpex.hunt.injection as injection
import dumpex.hunt.pipe as pipe_module
import dumpex.hunt.region_correlation as region_correlation
from dumpex.core.memory import get_memory_regions


def _full_correlation_mf():
    alloc_base = 0x7ff700000000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [
        Region(alloc_base, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(alloc_base + 0x2000, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mods = [Module(0x7ffe00000000, 0x10000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x1, alloc_base + 0x2000)]
    thread_list = [Thread(0x1, Ctx(alloc_base + 0x2000))]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        threads        = FakeStream(thread_list, "threads")
    injection.read_region = mem_reader({alloc_base + 0x2000: pe_bytes})
    return MF()


def _correlated_two_hunter_mf():
    """injection AND pipe both produce real evidence resolved to the SAME
    normalized MemoryInfo region (`alloc_base`, the RWX region) --
    injection via its own RWX-region check (protection-based, needs no
    content), pipe via a real `'\\pipe\\'` string sitting IN that region's
    own memory content (memory_scan.scan_pipe_names()'s own real string
    scan, not a stand-in). Two independently-scored real hunters, one
    shared region -- exactly the scenario CORRELATED REGIONS exists for."""
    alloc_base = 0x7ff700000000
    pipe_bytes = b"\\pipe\\evilpipe1234"
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [
        Region(alloc_base, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(alloc_base + 0x2000, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mods = [Module(0x7ffe00000000, 0x10000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x1, alloc_base + 0x2000)]
    thread_list = [Thread(0x1, Ctx(alloc_base + 0x2000))]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        threads        = FakeStream(thread_list, "threads")

    reader = mem_reader({alloc_base: pipe_bytes, alloc_base + 0x2000: pe_bytes})
    injection.read_region = reader
    pipe_module.read_region = reader
    return MF(), alloc_base


def test_poisoned_console_dict_cannot_leak_into_hunt_summary(monkeypatch, tmp_path, capsys):
    real_render = injection._render_injection_console

    def poisoned_render(report, verbose=False):
        # Print exactly what the real renderer would (so this test only
        # tampers with the RETURN VALUE, the thing `results["injection"]`
        # actually becomes -- not the console text render() itself prints,
        # which is a separate, already-covered concern in test_injection.py).
        real_render(report, verbose)
        return {
            "score": 0, "max_score": 3, "status": "NOT_DETECTED_IN_SCANNED_SCOPE",
            "verdict_level": "clean", "confidence": "none", "coverage_status": "complete",
            "lead_count": 0, "review_priority": "none", "findings": [],
            "rwx": [], "hidden_pe_validated": [], "hidden_pe_unvalidated": [],
            "suspicious_validated_pe_hits": [], "informational_validated_pe_hits": [],
            "threads": [], "thread_contexts": [], "rwx_and_pe_alloc_bases": [],
            "rip_hits": [], "rip_full_correlation": [], "start_hits": [],
            "coverage": {}, "coverage_reasons": [], "pe_read_failed": 0, "pe_short_reads": 0,
        }

    monkeypatch.setattr(hunt, "_render_injection_console", poisoned_render)

    rules_dir = tmp_path / "empty_rules"
    rules_dir.mkdir()
    mf = _full_correlation_mf()

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        results, records, _actions, _diagnostics = hunt.cmd_hunt(
            mf, "all", verbose=False, yara_dir=str(rules_dir), collect_records=True)
    out = buf.getvalue()

    # The legacy per-hunter results dict WAS poisoned (sanity check that
    # the monkeypatch actually took effect the way this test intends).
    assert results["injection"]["score"] == 0
    assert results["injection"]["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"

    # The real HunterRecord, built independently from the same Report,
    # stays correct.
    injection_record = next(r for r in records if r.hunter == "injection")
    assert injection_record.score == 3
    assert injection_record.status == "DETECTED"
    assert injection_record.verdict_level == "high"

    # And the printed HUNT SUMMARY reflects the REAL record, not the
    # poisoned console dict -- proving render_hunt_summary() never reads
    # `results`.
    summary_card = out.split("HUNT SUMMARY", 1)[1]
    assert "Process Injection" in summary_card
    review_first_or_whole = (summary_card.split("REVIEW FIRST", 1)[1]
                              if "REVIEW FIRST" in summary_card else summary_card)
    assert "HIGH" in review_first_or_whole.split("NEEDS ATTENTION")[0]


# ── CORRELATED REGIONS is built from real HunterRecord + real MemoryInfo ──

def test_correlated_regions_end_to_end_from_two_real_hunters(tmp_path):
    """injection and pipe each independently detect real evidence in the
    SAME MemoryInfo region of one real scan -- `--hunt all`'s printed
    CORRELATED REGIONS section must show both."""
    mf, alloc_base = _correlated_two_hunter_mf()
    rules_dir = tmp_path / "empty_rules"
    rules_dir.mkdir()

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        results, records, _actions, _diagnostics = hunt.cmd_hunt(
            mf, "all", verbose=False, yara_dir=str(rules_dir), collect_records=True)
    out = buf.getvalue()

    injection_record = next(r for r in records if r.hunter == "injection")
    pipe_record = next(r for r in records if r.hunter == "pipe")
    assert injection_record.status == "DETECTED"
    assert (pipe_record.lead_count or 0) > 0

    assert "CORRELATED REGIONS" in out
    block = out.split("CORRELATED REGIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    assert f"0x{alloc_base:016x}" in block
    assert "Process Injection" in block
    assert "Named Pipe C2 / Lat. Move." in block


def test_correlated_regions_source_is_real_records_and_real_memory_info_not_results(
        monkeypatch, tmp_path):
    """Proof by construction (not just inference from the code): spy on
    `build_region_correlations()` itself and confirm it was called with the
    EXACT `records` list `cmd_hunt()` returns and the EXACT MemoryInfo list
    `get_memory_regions(mf)` returns -- called exactly once (no re-scan) --
    even while the legacy per-hunter `results` dict is simultaneously
    poisoned (proving that poisoning has no path into this function's
    inputs at all, not merely that its OUTPUT happens to look right, which
    `test_poisoned_console_dict_cannot_leak_into_hunt_summary` above already
    covers for the rest of the card)."""
    real_render = injection._render_injection_console

    def poisoned_render(report, verbose=False):
        real_render(report, verbose)
        return {
            "score": 0, "max_score": 3, "status": "NOT_DETECTED_IN_SCANNED_SCOPE",
            "verdict_level": "clean", "confidence": "none", "coverage_status": "complete",
            "lead_count": 0, "review_priority": "none", "findings": [],
            "rwx": [], "hidden_pe_validated": [], "hidden_pe_unvalidated": [],
            "suspicious_validated_pe_hits": [], "informational_validated_pe_hits": [],
            "threads": [], "thread_contexts": [], "rwx_and_pe_alloc_bases": [],
            "rip_hits": [], "rip_full_correlation": [], "start_hits": [],
            "coverage": {}, "coverage_reasons": [], "pe_read_failed": 0, "pe_short_reads": 0,
        }

    monkeypatch.setattr(hunt, "_render_injection_console", poisoned_render)

    captured = {}
    real_build = region_correlation.build_region_correlations

    def spy_build(records, memory_regions):
        captured["records"] = records
        captured["memory_regions"] = memory_regions
        captured["call_count"] = captured.get("call_count", 0) + 1
        return real_build(records, memory_regions)

    monkeypatch.setattr(hunt, "build_region_correlations", spy_build)

    get_regions_calls = []
    real_get_regions = hunt.get_memory_regions

    def counting_get_regions(mf_):
        get_regions_calls.append(mf_)
        return real_get_regions(mf_)

    monkeypatch.setattr(hunt, "get_memory_regions", counting_get_regions)

    mf, alloc_base = _correlated_two_hunter_mf()
    rules_dir = tmp_path / "empty_rules"
    rules_dir.mkdir()

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        results, records, _actions, _diagnostics = hunt.cmd_hunt(
            mf, "all", verbose=False, yara_dir=str(rules_dir), collect_records=True)

    # results was poisoned (sanity check the setup actually took effect).
    assert results["injection"]["score"] == 0

    # build_region_correlations() was called EXACTLY once, with the SAME
    # records object cmd_hunt() returned (not a re-derived/poisoned copy)
    # and the SAME MemoryInfo list get_memory_regions(mf) itself returns --
    # i.e. no re-scan, no second, independent read of the dump.
    assert captured["call_count"] == 1
    assert captured["records"] is records
    assert captured["memory_regions"] == get_memory_regions(mf)
    assert len(get_regions_calls) == 1

    # And the correlation actually built from those real inputs reflects
    # the REAL (non-poisoned) injection score/status, not the poisoned one.
    injection_record = next(r for r in records if r.hunter == "injection")
    assert injection_record.score == 3
    correlated = [c for c in real_build(records, get_memory_regions(mf))
                  if c.region_base == alloc_base]
    assert correlated, "expected a real correlation at the RWX region shared by injection/pipe"


# ── --txt gets exactly the same CORRELATED REGIONS content as console ────

def test_txt_output_matches_console_for_correlated_regions(tmp_path):
    from dumpex.core.safe_io import AtomicTextTee

    mf, alloc_base = _correlated_two_hunter_mf()
    rules_dir = tmp_path / "empty_rules"
    rules_dir.mkdir()
    ansi_re = re.compile(r"\x1b\[[0-9;]*m")

    console_buf = io.StringIO()
    tee = AtomicTextTee(str(tmp_path / "out.txt"), "hunt_all", "test.dmp", True,
                         console_buf, ansi_re)
    import sys
    old_stdout = sys.stdout
    sys.stdout = tee
    try:
        hunt.cmd_hunt(mf, "all", verbose=False, yara_dir=str(rules_dir), collect_records=True)
    finally:
        sys.stdout = old_stdout
    txt_path, _ = tee.finalize()

    console_text = console_buf.getvalue()
    txt_text = open(txt_path, encoding="utf-8").read()

    assert "CORRELATED REGIONS" in console_text
    assert "CORRELATED REGIONS" in txt_text
    # The TXT file is exactly the console text with ANSI color codes
    # stripped -- no second, independently-built TXT renderer exists.
    assert ansi_re.sub("", console_text) == txt_text

    console_block = console_text.split("CORRELATED REGIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    txt_block = txt_text.split("CORRELATED REGIONS", 1)[1].split("NEXT INVESTIGATION", 1)[0]
    assert ansi_re.sub("", console_block) == txt_block
    assert f"0x{alloc_base:016x}" in txt_block
    assert "Process Injection" in txt_block
    assert "Named Pipe C2 / Lat. Move." in txt_block

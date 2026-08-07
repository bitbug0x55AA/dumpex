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

import dumpex.hunt as hunt
import dumpex.hunt.injection.presentation as injection_presentation
from tests.fixtures.fakes import Region, Module, ThreadInfo, Ctx, Thread, FakeStream, FakeMF, \
    build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, mem_reader
import dumpex.hunt.injection as injection


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


def test_poisoned_console_dict_cannot_leak_into_hunt_summary(monkeypatch, tmp_path, capsys):
    real_render = injection_presentation.render

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
        results, records = hunt.cmd_hunt(mf, "all", verbose=False, yara_dir=str(rules_dir),
                                          collect_records=True)
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

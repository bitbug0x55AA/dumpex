"""Hunter-level tests for dumpex.hunt.injection (Process Injection detection)."""
from tests.fixtures.fakes import (Region, Module, ThreadInfo, Ctx, Thread, FakeStream, FakeMF,
                                   build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
                                   mem_reader)

import dumpex.hunt.injection as injection
import dumpex.hunt.injection.report_legacy as injection_report_legacy


# ── embedded PE inside a loaded module's own range -> NOT hidden PE ───────

def test_embedded_pe_inside_module_not_hidden():
    mod_base = 0x7ffe10000000
    module = Module(mod_base, 0x10000, r"C:\Windows\System32\legit.dll")
    embedded_base = mod_base + 0x2000  # inside the module, not at its exact base

    regions = [
        Region(mod_base, mod_base, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE"),
        Region(embedded_base, mod_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE"),
    ]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([module], "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = mem_reader({embedded_base: b'MZ' + b'\x90' * 0x1000})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert len(f["hidden_pe_validated"]) == 0
    assert len(f["hidden_pe_unvalidated"]) == 0
    assert len(f["rwx"]) == 0, "WRITECOPY on MEM_IMAGE must not count as suspicious RWX"


# ── no thread context at all -> partial coverage ───────────────────────────

def test_no_thread_context_is_partial():
    dummy_regions = [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
        threads        = None   # no ThreadListStream at all -> no contexts possible

    injection.read_region = mem_reader({})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert f["verdict_level"] == "inconclusive"


# ── Bonus: full correlation (RWX + validated PE + live RIP) still detects ─

def test_full_correlation_still_detects():
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

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 3
    assert f["confidence"] == "high"


# ── MZ prefix read succeeds but the deeper PE-validation read fails ───────
# must not be silently treated as a completed check: the MZ observation is
# still reported (parse_pe_header falls back to the 2-byte prefix), but
# pe_read_failed must count it, coverage must go partial, and with nothing
# else to score, the overall result must be INCONCLUSIVE.

def test_mz_prefix_ok_deep_read_fails_is_inconclusive():
    region_base = 0x8000000
    dummy_regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT",
                             "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    def flaky_reader(mf, addr, size):
        if addr == region_base and size <= 2:
            return b'MZ'
        raise OSError("simulated deep-read failure")

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = flaky_reader

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert f["pe_read_failed"] == 1
    assert len(f["hidden_pe_unvalidated"]) == 1, "MZ observation must still be reported"
    assert len(f["hidden_pe_validated"]) == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("failed to read" in r for r in f["coverage_reasons"])


# ── MZ prefix read succeeds and the deeper PE-validation read succeeds ────
# but SHORT-reads (returns fewer bytes than requested, no exception) —
# must not be silently treated as a completed check either: pe_read_failed
# stays 0 in this scenario, but pe_short_reads must count it, and coverage
# must still go partial/INCONCLUSIVE, not silently claim full coverage.

def test_mz_prefix_ok_deep_read_short_reads_is_inconclusive():
    region_base = 0x9000000
    dummy_regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT",
                             "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    def short_reader(mf, addr, size):
        # Prefix read (size<=2) succeeds fully; the deep validation read
        # (size > 2) returns fewer bytes than requested WITHOUT raising —
        # exactly what a real short read from a partially-paged-out or
        # truncated capture looks like.
        if addr == region_base and size <= 2:
            return b'MZ'
        return b'MZ'   # deep read: only 2 bytes back, even though more were requested

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = short_reader

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert f["pe_read_failed"] == 0, "no exception was raised, so this must stay 0"
    assert f["pe_short_reads"] == 1
    assert len(f["hidden_pe_unvalidated"]) == 1, "MZ observation must still be reported"
    assert len(f["hidden_pe_validated"]) == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("short read" in r.lower() or "fewer bytes" in r for r in f["coverage_reasons"])


# ── context-only (informational) validated PE hits must not drive score ───
# See dumpex/hunt/injection/memory_scan.py's pe_hit_is_context_scoreable and
# aggregate.py's _split_scoreable_pe_hits: a structurally-valid PE header
# that sits in read-only/non-executable, uncorrelated memory is real
# evidence worth keeping visible, but must not by itself produce a
# DETECTED/score>0 result — this is exactly the clean-Notepad false
# positive (7 PAGE_READONLY MEM_MAPPED/MEM_IMAGE PE headers, none RWX, none
# thread-correlated, previously still scored 1/POSSIBLE).

def test_valid_pe_in_readonly_mem_mapped_is_observation_not_scored():
    region_base = 0xA0000000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = mem_reader({region_base: pe_bytes})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert len(f["hidden_pe_validated"]) == 1, "compat: full validated list unchanged"
    assert len(f["suspicious_validated_pe_hits"]) == 0
    assert len(f["informational_validated_pe_hits"]) == 1
    obs = [x for x in f["findings"]
           if x["check"] == "injection.hidden_pe_validated_context_only"]
    assert obs and obs[0]["tag"] == "observation"
    leads = [x for x in f["findings"] if x["check"] == "injection.hidden_pe_validated"]
    assert not leads, "no scoreable-lead finding should be emitted when only context-only PE exists"


def test_valid_pe_in_unbacked_mem_image_readonly_is_observation_not_scored():
    region_base = 0xB0000000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_IMAGE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = mem_reader({region_base: pe_bytes})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert len(f["suspicious_validated_pe_hits"]) == 0
    assert len(f["informational_validated_pe_hits"]) == 1


def test_valid_pe_in_mem_private_is_lead_score_1():
    region_base = 0xC0000000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = mem_reader({region_base: pe_bytes})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 1
    assert len(f["suspicious_validated_pe_hits"]) == 1
    assert len(f["informational_validated_pe_hits"]) == 0
    leads = [x for x in f["findings"]
             if x["check"] == "injection.hidden_pe_validated" and x["tag"] == "lead"]
    assert leads


def test_rwx_and_pe_same_allocation_without_rip_still_scores_2():
    # Same-allocation RWX + validated PE, but no thread context at all (no
    # RIP correlation possible) — must still reach score 2 via
    # rwx_and_pe_alloc_bases, exactly as before this change.
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

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = mem_reader({alloc_base + 0x2000: pe_bytes})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 2


def test_only_informational_pe_with_partial_coverage_is_inconclusive_not_detected():
    region_base = 0xD0000000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000,
                                  "rawptr": 0x400, "rawsize": 0x1000,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_MAPPED")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")   # present but empty -> partial coverage
    injection.read_region = mem_reader({region_base: pe_bytes})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["status"] != "DETECTED"
    assert f["coverage_status"] == "partial"


# ── --verbose must still surface file offset -- Finding.facts for RWX/ ────
# hidden-PE/unbacked-thread never carried it (only --json's own facts
# fields: VA/AllocationBase/size/type/protect); it used to come from
# presentation.py's own hand-written verbose expansion. Regression test
# for that loss being silently reintroduced when rendering was
# centralized on Finding.print().

def test_verbose_shows_file_offset_for_rwx_not_shown_normally(capsys, monkeypatch):
    # va_to_file_offset() returns None whenever the fake dump has no memory
    # segment table (true of every other fixture in this file) -- asserting
    # only the *label* "File_offset" is present would pass even if the
    # value printed is always the vacuous "(not captured)" placeholder.
    # Monkeypatched here to a real, non-None value so the assertion below
    # actually exercises the printed offset text, not just its label.
    # Patched on dumpex.hunt._location (the ONE shared resolver import
    # point resolve_location() calls into) rather than on aggregate --
    # aggregate.py no longer imports va_to_file_offset at all; resolution
    # now happens in memory_scan.py's rwx_locations(), the scan layer,
    # before aggregate.py ever sees it (see that function's own comment).
    monkeypatch.setattr("dumpex.hunt._location.va_to_file_offset", lambda mf, va: 0x1234)

    rwx_base = 0x7ffe20000000
    regions = [Region(rwx_base, rwx_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")

    injection._hunt_injection(MF(), verbose=False)
    normal_out = capsys.readouterr().out
    assert "File_offset" not in normal_out
    assert "0x1234" not in normal_out

    injection._hunt_injection(MF(), verbose=True)
    verbose_out = capsys.readouterr().out
    assert "File_offset=0x1234" in verbose_out


def test_verbose_file_offset_zero_is_not_mistaken_for_not_captured(capsys, monkeypatch):
    # va_to_file_offset() can legitimately return 0 (a region mapped at the
    # very start of the dump file) -- the printed-offset logic must branch
    # on `fo is not None`, not on `fo` being truthy, or a real offset of 0
    # would misprint as "(not captured)".
    monkeypatch.setattr("dumpex.hunt._location.va_to_file_offset", lambda mf, va: 0)

    rwx_base = 0x7ffe20000000
    regions = [Region(rwx_base, rwx_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")

    injection._hunt_injection(MF(), verbose=True)
    out = capsys.readouterr().out
    assert "File_offset=0x0" in out
    assert "(not captured)" not in out


def test_verbose_lists_every_rwx_region_beyond_the_facts_cap(capsys):
    # injection.rwx_regions' Finding.facts (built for --json) cap the
    # region list at 20 with a "... and N more" sentinel entry --
    # --verbose is supposed to mean "the complete list". Finding.
    # verbose_facts (not Finding.facts) is now the --verbose detail source
    # for this check, and it's built from the full, uncapped `rwx` list --
    # see aggregate.py's _rwx_verbose_fact().
    n = 21
    rwx_base = 0x7ffe30000000
    regions = [Region(rwx_base + i * 0x2000, rwx_base + i * 0x2000, 0x1000,
                       "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")
               for i in range(n)]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")

    injection._hunt_injection(MF(), verbose=False)
    normal_out = capsys.readouterr().out
    last_va = rwx_base + (n - 1) * 0x2000
    assert f"0x{last_va:016x}" not in normal_out

    injection._hunt_injection(MF(), verbose=True)
    verbose_out = capsys.readouterr().out
    assert "... and" not in verbose_out, \
        "verbose_facts must fully replace the capped Finding.facts sentinel, not coexist with it"
    for i in range(n):
        va = rwx_base + i * 0x2000
        assert f"0x{va:016x}" in verbose_out, \
            f"region {i} (VA 0x{va:x}) missing from --verbose output"


# ── console presentation patch (Step 1.5): verdict-first shape ────────────

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


def test_verdict_precedes_first_finding_in_console(capsys):
    # verbose mode shows the machine check id alongside the human title
    # (dim, in parens -- see render_finding_lines' title= handling); use
    # it here so the assertion doesn't depend on any particular title text.
    injection._hunt_injection(_full_correlation_mf(), verbose=True)
    out = capsys.readouterr().out
    verdict_idx = out.index("VERDICT")
    first_check_idx = min(out.index(check) for check in
                           ("injection.rwx_regions", "injection.allocation_correlation")
                           if check in out)
    assert verdict_idx < first_check_idx


def test_detection_key_signal_precedes_lead_key_signal(capsys):
    injection._hunt_injection(_full_correlation_mf(), verbose=False)
    out = capsys.readouterr().out
    detection_title_idx = out.index("Live execution in a correlated allocation")
    lead_title_idx = out.index("RWX memory")
    assert detection_title_idx < lead_title_idx


def test_coverage_reason_appears_exactly_once_normal_and_verbose(capsys):
    dummy_regions = [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
        threads        = None
    injection.read_region = mem_reader({})

    f = injection._hunt_injection(MF(), verbose=False)
    normal_out = capsys.readouterr().out
    reason = next(r for r in f["coverage_reasons"] if "live-execution correlation could not run" in r)
    assert normal_out.count(reason) == 1

    f2 = injection._hunt_injection(MF(), verbose=True)
    verbose_out = capsys.readouterr().out
    assert verbose_out.count(reason) == 1


def test_finding_limitations_never_duplicate_coverage_reasons(capsys):
    dummy_regions = [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
        threads        = None
    injection.read_region = mem_reader({})

    f = injection._hunt_injection(MF(), verbose=False)
    capsys.readouterr()
    coverage_reasons = set(f["coverage_reasons"])
    finding_limitations = {l for finding in f["findings"] for l in finding["limitations"]}
    assert not (coverage_reasons & finding_limitations), (
        "a Finding limitation must never be the same text as a coverage_reasons entry -- "
        "the two are meant to stay structurally disjoint sources, not merely deduplicated by luck")


def _collapse_ws(text: str) -> str:
    """Join wrapped console lines back into one run of text so a
    substring assertion doesn't depend on exactly where wrap_text
    happened to insert a line break."""
    return " ".join(text.split())


def _no_thread_context_mf():
    """memory_info/thread_info/modules all present, but no ThreadListStream
    at all -- score stays 0 and the ONLY Finding this hunter builds is the
    coverage-only injection.rip_correlation_unavailable observation (no
    RWX, no hidden PE, no unbacked thread -- see
    test_key_signals_omitted_entirely_when_only_coverage_only_findings_exist)."""
    dummy_regions = [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
        threads        = None
    injection.read_region = mem_reader({})
    return MF()


def _mixed_coverage_only_and_real_signal_mf():
    """A coverage-only finding (injection.rip_correlation_unavailable, via
    threads=None) co-existing with two REAL KEY SIGNALS findings (an RWX
    region, an unbacked thread via ThreadInfoListStream) -- the scenario
    that actually exercises the exclusion rule, as opposed to
    _no_thread_context_mf's degenerate "only the coverage-only finding
    exists" case."""
    rwx_base = 0x7ffe40000000
    unbacked_start = 0x7ffe50000000
    regions = [Region(rwx_base, rwx_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x2, unbacked_start)]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        threads        = None   # no ThreadListStream -> no contexts -> coverage-only finding fires
    injection.read_region = mem_reader({})
    return MF()


def test_key_signals_omitted_entirely_when_only_coverage_only_findings_exist(capsys):
    f = injection._hunt_injection(_no_thread_context_mf(), verbose=False)
    out = capsys.readouterr().out
    checks = {x["check"] for x in f["findings"]}
    assert checks == {"injection.rip_correlation_unavailable"}, (
        "sanity check on the scenario itself: the ONLY finding must be the coverage-only one")
    assert "KEY SIGNALS" not in out
    assert "WHY THIS VERDICT" not in out
    assert "COVERAGE" in out


def test_coverage_only_check_never_appears_in_key_signals_or_why_this_verdict(capsys):
    for verbose in (False, True):
        f = injection._hunt_injection(_mixed_coverage_only_and_real_signal_mf(), verbose=verbose)
        out = capsys.readouterr().out
        checks = {x["check"] for x in f["findings"]}
        # sanity: this scenario really does mix a coverage-only finding
        # with real KEY SIGNALS-worthy findings.
        assert "injection.rip_correlation_unavailable" in checks
        assert checks & {"injection.rwx_regions", "injection.unbacked_thread_startaddress"}

        assert "KEY SIGNALS" in out
        key_signals_body = out.split("KEY SIGNALS", 1)[1]
        for stop_marker in ("WHY THIS VERDICT", "COVERAGE"):
            if stop_marker in key_signals_body:
                key_signals_body = key_signals_body.split(stop_marker, 1)[0]
                break
        # structural check: the coverage-only check's OWN identity (both
        # its human title and, under --verbose, its machine check id) is
        # absent from the KEY SIGNALS section -- not a comparison of two
        # arbitrary text blobs.
        assert "RIP/EIP correlation unavailable" not in key_signals_body
        assert "injection.rip_correlation_unavailable" not in key_signals_body

        if "WHY THIS VERDICT" in out:
            why_body = out.split("WHY THIS VERDICT", 1)[1].split("COVERAGE", 1)[0]
            assert "RIP/EIP correlation unavailable" not in why_body
            assert "injection.rip_correlation_unavailable" not in why_body


def test_coverage_only_finding_still_present_in_json_findings_and_legacy_dict(capsys):
    # Presentation-only exclusion: --json (via f["findings"]) must
    # still carry this Finding in full, untouched by KEY SIGNALS filtering.
    f = injection._hunt_injection(_mixed_coverage_only_and_real_signal_mf(), verbose=False)
    capsys.readouterr()
    checks = {x["check"] for x in f["findings"]}
    assert "injection.rip_correlation_unavailable" in checks


def test_coverage_only_finding_limitation_surfaces_once_under_coverage_as_impact(capsys):
    f = injection._hunt_injection(_no_thread_context_mf(), verbose=False)
    out = capsys.readouterr().out
    rip_finding = next(x for x in f["findings"] if x["check"] == "injection.rip_correlation_unavailable")
    limitation_text = rip_finding["limitations"][0]
    coverage_body = out.split("COVERAGE", 1)[1]
    assert _collapse_ws(limitation_text) in _collapse_ws(coverage_body)
    assert f"Impact: {_collapse_ws(limitation_text)}" in _collapse_ws(coverage_body)
    # exactly once -- collapse first so a mid-sentence wrap can't make the
    # same caveat look like two different occurrences.
    assert _collapse_ws(coverage_body).count(_collapse_ws(limitation_text)) == 1


def test_legacy_findings_dict_called_on_normal_return_path(monkeypatch):
    calls = []
    real = injection_report_legacy.project_legacy_dict

    def spy(report):
        result = real(report)
        calls.append(result)
        return result
    monkeypatch.setattr(injection_report_legacy, "project_legacy_dict", spy)

    f = injection._hunt_injection(_full_correlation_mf(), verbose=False)
    assert len(calls) == 1
    assert f is calls[0]
    assert isinstance(f["rwx"][0], dict)   # never an Evidence dataclass leaking through


def test_legacy_findings_dict_called_on_not_evaluated_path(monkeypatch):
    calls = []
    real = injection_report_legacy.project_legacy_dict

    def spy(report):
        result = real(report)
        calls.append(result)
        return result
    monkeypatch.setattr(injection_report_legacy, "project_legacy_dict", spy)

    f = injection._hunt_injection(FakeMF(), verbose=False)
    assert f["status"] == "NOT_EVALUATED"
    assert len(calls) == 1
    assert f is calls[0]


# ── issue #26: a hidden PE is searched for THROUGHOUT eligible memory ─────
# The scan used to read 2 bytes at each region's own BaseAddress and stop
# there, so a structurally valid PE mapped at a nonzero offset inside a
# private/unbacked allocation -- loader metadata or padding ahead of the
# image, several objects in one allocation, a manual map not aligned to
# the MemoryInfo region boundary -- produced NO finding at all, no
# correlation with RWX/live execution in its own allocation, and a clean
# verdict when nothing else fired.

_PE_SECTION = {"name": b".text", "vaddr": 0x1000, "vsize": 0x1000, "rawptr": 0x400,
                "rawsize": 0x1000, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}


def _valid_pe_bytes():
    return build_pe_header([dict(_PE_SECTION)], size_of_image=0x2000, trailing_padding=0x300)


def _region_bytes_with_pe_at(offset: int, region_size: int) -> bytes:
    """Region content whose first `offset` bytes are loader-ish padding and
    which carries a structurally-valid PE image starting at `offset` --
    the exact shape issue #26 describes."""
    pe = _valid_pe_bytes()
    body = bytearray(b"\xcc" * region_size)
    body[offset:offset + len(pe)] = pe
    return bytes(body)


def _private_region_mf(region_base, region_size, content, threads=None):
    """A dump with ONE eligible MEM_PRIVATE region plus an unrelated known
    module, so a hidden-PE hit can only come from that region's own
    content."""
    regions = [Region(region_base, region_base, region_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    if content is not None:
        injection.read_region = mem_reader({region_base: content})
    return MF()


def test_hidden_pe_at_nonzero_offset_in_private_region_is_found():
    region_base, pe_offset = 0x30000000, 0x2000
    mf = _private_region_mf(region_base, 0x8000,
                             _region_bytes_with_pe_at(pe_offset, 0x8000))

    f = injection._hunt_injection(mf, verbose=False)
    assert len(f["hidden_pe_validated"]) == 1, "a PE past the region base must be examined"
    # MEM_PRIVATE is scoreable on its own memory context, so this is a real
    # lead rather than an informational-only observation.
    assert len(f["suspicious_validated_pe_hits"]) == 1
    assert f["score"] >= 1
    # Region identity still describes the CONTAINING region, unchanged --
    # allocation correlation is keyed on it (see the correlation test below).
    assert f["hidden_pe_validated"][0]["region"]["base_address"] == region_base


def test_hidden_pe_evidence_keeps_the_candidate_va_not_the_region_base():
    from dumpex.hunt.injection import memory_scan
    region_base, pe_offset = 0x30000000, 0x3000
    content = _region_bytes_with_pe_at(pe_offset, 0x8000)
    mf = _private_region_mf(region_base, 0x8000, content=None)

    scan = memory_scan._hunt_hidden_pe(mf, mem_reader({region_base: content}),
                                        module_list_available=True)
    assert len(scan.hits) == 1
    hit = scan.hits[0]
    assert hit.pe.valid is True
    assert hit.location.va == region_base + pe_offset, "carving address must be the PE's own"
    assert hit.location.region_base == region_base
    assert hit.location.region_offset == pe_offset


def test_nonbase_hidden_pe_correlates_with_rwx_and_live_rip_in_its_allocation():
    # The PE sits 0x2000 into the SECOND sub-region of an allocation whose
    # first sub-region is RWX, and a thread's current RIP executes inside
    # it: page type + structural validation + live execution all converge
    # on one AllocationBase -- unreachable unless the non-base PE is seen.
    alloc_base = 0x7ff700000000
    pe_region, pe_offset = alloc_base + 0x10000, 0x2000
    regions = [
        Region(alloc_base, alloc_base, 0x1000, "MEM_COMMIT",
                "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(pe_region, alloc_base, 0x8000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mods = [Module(0x7ffe00000000, 0x10000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x1, pe_region + pe_offset)]
    thread_list   = [Thread(0x1, Ctx(pe_region + pe_offset))]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        threads        = FakeStream(thread_list, "threads")
    injection.read_region = mem_reader({pe_region: _region_bytes_with_pe_at(pe_offset, 0x8000)})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 3
    assert f["confidence"] == "high"
    assert f["rwx_and_pe_alloc_bases"] == [alloc_base], \
        "correlation must use the CONTAINING allocation, not the PE's own VA"
    assert len(f["rip_full_correlation"]) == 1


def test_two_hidden_pes_in_one_region_are_reported_separately():
    region_base = 0x40000000
    pe = _valid_pe_bytes()
    body = bytearray(b"\x00" * 0x8000)
    body[0x1000:0x1000 + len(pe)] = pe
    body[0x4000:0x4000 + len(pe)] = pe
    mf = _private_region_mf(region_base, 0x8000, bytes(body))

    f = injection._hunt_injection(mf, verbose=False)
    assert len(f["hidden_pe_validated"]) == 2, \
        "one allocation can host more than one image -- neither may mask the other"


def test_non_page_aligned_hidden_pe_is_found():
    # The search looks for 'MZ' at EVERY byte offset, not at page (or any
    # other) stride: nothing about a manual map obliges its header to sit
    # on a page boundary, and an alignment assumption is exactly the kind
    # of unstated scope limit issue #26 is about.
    region_base = 0x50000000
    pe = _valid_pe_bytes()
    body = bytearray(b"\x00" * 0x8000)
    body[0x1000:0x1000 + len(pe)] = pe        # page-aligned
    body[0x2010:0x2010 + len(pe)] = pe        # 0x10 into a page
    body[0x4001:0x4001 + len(pe)] = pe        # odd offset
    mf = _private_region_mf(region_base, 0x8000, bytes(body))

    f = injection._hunt_injection(mf, verbose=False)
    assert len(f["hidden_pe_validated"]) == 3


def test_mz_straddling_two_discovery_reads_is_found_exactly_once(monkeypatch):
    # Discovery reads overlap by one byte precisely so a marker split
    # across the boundary is whole in the LATER read -- and in only that
    # one, so the candidate is neither missed nor reported twice.
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_WINDOW", 0x1000)
    region_base = 0x50000000
    pe = _valid_pe_bytes()
    body = bytearray(b"\x00" * 0x4000)
    straddle = 0x1000 - 1      # 'M' ends read 0, 'Z' begins read 1
    body[straddle:straddle + len(pe)] = pe
    mf = _private_region_mf(region_base, 0x4000, bytes(body))

    f = injection._hunt_injection(mf, verbose=False)
    assert len(f["hidden_pe_validated"]) == 1


def test_bulk_read_failure_degrades_to_smaller_reads_and_still_finds_the_pe():
    # A minidump's buffered reader raises for a span crossing the end of a
    # captured segment while still serving smaller reads inside it, so a
    # failed bulk discovery read must be retried at the next read size
    # down rather than writing the whole region off -- that is what keeps
    # this search a strict superset of the region-base-only one.
    region_base, pe_offset = 0x60000000, 0x5000
    content = _region_bytes_with_pe_at(pe_offset, 0x8000)

    def segment_bound_reader(mf, addr, size):
        if size > 0x1000:
            raise OSError("would read over segment boundaries")
        off = addr - region_base
        return content[off:off + size]

    mf = _private_region_mf(region_base, 0x8000, content=None)
    injection.read_region = segment_bound_reader

    f = injection._hunt_injection(mf, verbose=False)
    assert len(f["hidden_pe_validated"]) == 1
    assert f["score"] >= 1


def test_scan_truncated_by_read_budget_is_reported_not_treated_as_clean(monkeypatch):
    # The per-region read budget is what bounds this search. A region it
    # stops inside has an UNSEARCHED remainder, so the result must go
    # partial/INCONCLUSIVE instead of presenting itself as a clean
    # negative -- the same rule the read_failed/short_read counters follow.
    # The production budget is a safety net sized so ordinary regions never
    # reach it (see config.PE_SCAN_MAX_READS_PER_REGION); a small one is
    # patched in here so the scenario costs a few reads instead of gigabytes
    # -- memory_scan looks both tunables up at call time, so patching them
    # on that module is what the scan actually reads.
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_WINDOW", 0x1000)
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_READS_PER_REGION", 3)
    region_base = 0x70000000
    region_size = 0x8000        # 8 windows, only 3 of them affordable

    def zero_reader(mf, addr, size):
        return b"\x00" * size

    mf = _private_region_mf(region_base, region_size, content=None)
    injection.read_region = zero_reader

    f = injection._hunt_injection(mf, verbose=False)
    assert f["pe_scan_truncated"] == 1
    assert f["pe_read_failed"] == 0 and f["pe_short_reads"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("not searched" in reason for reason in f["coverage_reasons"])


def test_fully_read_region_with_no_mz_is_still_a_complete_clean_scan():
    # The counterpart of the test above: a region the search covered end
    # to end must NOT acquire a coverage caveat merely because it is now
    # read in full rather than probed at its base.
    region_base = 0x80000000
    regions = [Region(region_base, region_base, 0x4000, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x1, 0x20000)]
    thread_list   = [Thread(0x1, Ctx(0x20000))]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        threads        = FakeStream(thread_list, "threads")
    injection.read_region = mem_reader({region_base: b"\x00" * 0x4000})

    f = injection._hunt_injection(MF(), verbose=False)
    assert f["score"] == 0
    assert f["pe_read_failed"] == 0 and f["pe_short_reads"] == 0
    assert f["pe_scan_truncated"] == 0
    assert f["coverage_status"] == "complete"


def test_verbose_shows_the_pe_va_and_its_offset_inside_the_region(capsys):
    region_base, pe_offset = 0x90000000, 0x2000
    mf = _private_region_mf(region_base, 0x8000,
                             _region_bytes_with_pe_at(pe_offset, 0x8000))

    injection._hunt_injection(mf, verbose=True)
    out = capsys.readouterr().out
    assert f"VA (process)=0x{region_base + pe_offset:016x}" in out
    assert f"Region_base=0x{region_base:016x}" in out
    assert f"Region_offset=0x{pe_offset:x}" in out


# ── the candidate search runs under explicit budgets ──────────────────────
# A dump is attacker-supplied input: a region carrying 'MZ' every other
# byte would otherwise dictate how much this hunter reads, parses, and
# reports. Every bound below is bounded AND stated -- what stopped early
# reaches coverage, what was found but not kept reaches the check that
# would have listed it.

def _mz_flooded_region(size: int) -> bytes:
    """A region of nothing but 'MZ' pairs -- the adversarial shape: one
    candidate every two bytes, none of them a valid PE header."""
    return b"MZ" * (size // 2)


def test_validation_budget_stops_the_search_and_reports_partial_coverage(monkeypatch):
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_VALIDATIONS_TOTAL", 10)
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_VALIDATIONS_PER_REGION", 10)
    region_base = 0xA1000000
    mf = _private_region_mf(region_base, 0x2000, _mz_flooded_region(0x2000))

    f = injection._hunt_injection(mf, verbose=False)
    # 0x1000 candidates are present; only the budgeted 10 were validated,
    # and the region is reported as searched only that far.
    assert f["pe_scan_truncated"] == 1
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("not searched" in reason for reason in f["coverage_reasons"])


def test_whole_hunt_validation_budget_is_shared_across_regions(monkeypatch):
    # The per-hunt budget must not reset per region, or a dump could
    # multiply its total cost by declaring the same pathological memory as
    # many small regions instead of one big one.
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_VALIDATIONS_TOTAL", 4)
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_VALIDATIONS_PER_REGION", 4)
    bases = [0xA2000000, 0xA2100000, 0xA2200000]
    regions = [Region(b, b, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE") for b in bases]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    flood = _mz_flooded_region(0x1000)
    injection.read_region = mem_reader({b: flood for b in bases})

    f = injection._hunt_injection(mf := MF(), verbose=False)
    # Region 1 spends the whole-hunt budget; regions 2 and 3 get nothing,
    # and every one of the three says so rather than reading as clean.
    assert f["pe_scan_truncated"] == 3
    assert f["coverage_status"] == "partial"


def test_byte_budget_stops_the_search_and_reports_partial_coverage(monkeypatch):
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_WINDOW", 0x1000)
    monkeypatch.setattr(memory_scan, "PE_SCAN_TOTAL_BYTES_MAX", 0x2000)
    region_base = 0xA3000000
    mf = _private_region_mf(region_base, 0x20000, b"\x00" * 0x20000)

    f = injection._hunt_injection(mf, verbose=False)
    assert f["pe_scan_truncated"] == 1
    assert f["coverage_status"] == "partial"
    assert any("not searched" in reason for reason in f["coverage_reasons"])


def test_unvalidated_evidence_cap_bounds_the_list_without_marking_coverage_partial(monkeypatch):
    # Incidental 'MZ' bytes occur ~16 times per MB of ordinary memory, so
    # the unvalidated cap has to bound the reported list WITHOUT making
    # every real dump report partial coverage -- it is stated on the check
    # instead, with the count.
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_UNVALIDATED_EVIDENCE", 5)
    region_base = 0xA4000000
    regions = [Region(region_base, region_base, 0x100, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x1, 0x20000)]
    thread_list   = [Thread(0x1, Ctx(0x20000))]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        threads        = FakeStream(thread_list, "threads")
    injection.read_region = mem_reader({region_base: _mz_flooded_region(0x100)})

    f = injection._hunt_injection(MF(), verbose=False)
    assert len(f["hidden_pe_unvalidated"]) == 5
    assert f["coverage_status"] == "complete", \
        "everything was examined -- only the informational list was trimmed"
    mz_finding = next(x for x in f["findings"] if x["check"] == "injection.mz_prefix_unvalidated")
    assert any("not retained" in limitation and "not exhaustive" in limitation
                for limitation in mz_finding["limitations"])


def test_validated_evidence_cap_is_stated_and_counts_against_coverage(monkeypatch):
    # A validated hidden PE header that was found but is not in the report
    # IS detection-relevant, so unlike the unvalidated cap above it also
    # marks coverage partial.
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_VALIDATED_EVIDENCE", 2)
    region_base = 0xA5000000
    pe = _valid_pe_bytes()
    body = bytearray(b"\x00" * 0x8000)
    for offset in (0x0, 0x1000, 0x2000, 0x3000, 0x4000):
        body[offset:offset + len(pe)] = pe
    mf = _private_region_mf(region_base, 0x8000, bytes(body))

    f = injection._hunt_injection(mf, verbose=False)
    assert len(f["hidden_pe_validated"]) == 2
    assert f["coverage_status"] == "partial"
    assert any("not retained" in reason and "not exhaustive" in reason
                for reason in f["coverage_reasons"])
    pe_finding = next(x for x in f["findings"] if x["check"] == "injection.hidden_pe_validated")
    assert any("3 further validated hidden-PE candidate(s)" in limitation
                for limitation in pe_finding["limitations"])
    # Detection itself is unaffected: what was kept still scores.
    assert f["score"] >= 1


def test_validated_hits_are_kept_in_preference_to_unvalidated_ones(monkeypatch):
    # The two caps draw on separate pools, so a flood of unvalidated 'MZ'
    # encountered FIRST can never crowd out a validated PE header found
    # later in the same region.
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_MAX_UNVALIDATED_EVIDENCE", 2)
    region_base = 0xA6000000
    pe = _valid_pe_bytes()
    body = bytearray(_mz_flooded_region(0x2000) + b"\x00" * 0x2000)
    body[0x2000:0x2000 + len(pe)] = pe
    mf = _private_region_mf(region_base, 0x4000, bytes(body))

    f = injection._hunt_injection(mf, verbose=False)
    assert len(f["hidden_pe_unvalidated"]) == 2, "flood is trimmed to its own cap"
    assert len(f["hidden_pe_validated"]) == 1, "the real PE survives the flood"
    assert f["score"] >= 1


# ── review follow-up: degraded-read overshoot duplicated candidates ───────
# The degraded-read fallback used to bound its own read size only by
# region_size, not by the recursive slice's own `end` -- so a read near
# that slice's boundary could still read (and scan) bytes belonging to
# the PARENT's next window, and the same candidate got reported twice:
# once by the overshooting degraded read, once by the parent's own
# subsequent window.

def test_degraded_read_overshoot_reports_candidate_exactly_once(monkeypatch):
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_WINDOW", 0x2000)
    monkeypatch.setattr(memory_scan, "PE_SCAN_DEGRADED_READ", 0x1000)
    region_base = 0x1000000
    region_size = 0x8000
    pe_offset = 10000   # inside the degraded fallback's overshoot span,
                         # and inside the parent's own next window

    content = bytearray(b"\x00" * region_size)
    content[pe_offset:pe_offset + 2] = b"MZ"
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]
    regions = [Region(region_base, region_base, region_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    fail_count = [0]
    def flaky_reader(mf, addr, size):
        off = addr - region_base
        # Fail only the FIRST bulk-window read -- simulates a buffered
        # reader raising for a span crossing a captured-segment boundary,
        # forcing exactly one degradation to the smaller read size.
        if size > 0x1000 and fail_count[0] == 0:
            fail_count[0] += 1
            raise OSError("would read over segment boundaries")
        return bytes(content[off:off + size])

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
    injection.read_region = flaky_reader

    f = injection._hunt_injection(MF(), verbose=False)
    assert len(f["hidden_pe_unvalidated"]) == 1, \
        "the same MZ marker at one offset must never be reported twice"


def test_scan_region_for_pe_never_reports_the_same_candidate_twice(monkeypatch):
    # Lower-level companion: exercises _scan_region_for_pe directly so the
    # assertion is about candidate offsets, independent of validation/
    # evidence-cap policy above it.
    from dumpex.hunt.injection import memory_scan

    region_base, region_size, pe_offset = 0x1000000, 0x8000, 10000
    content = bytearray(b"\x00" * region_size)
    content[pe_offset:pe_offset + 2] = b"MZ"
    content = bytes(content)

    fail_count = [0]
    def flaky_reader(mf, addr, size):
        off = addr - region_base
        if size > 0x1000 and fail_count[0] == 0:
            fail_count[0] += 1
            raise OSError("would read over segment boundaries")
        return content[off:off + size]

    budget = memory_scan._ScanBudget()
    reader = memory_scan._BudgetedReader(flaky_reader, None, budget)
    hits = []
    memory_scan._scan_region_for_pe(
        reader, budget, region_base, region_size,
        lambda offset, data: hits.append(offset),
        window=0x2000, degraded_read=0x1000)
    assert hits == [pe_offset]


# ── review follow-up: the whole-hunt byte budget must be a hard ceiling ───
# _BudgetedReader used to only check whether ANY budget remained, then
# still issue the FULL requested read -- a 10-byte budget could still
# trigger a real 1&nbsp;MB read, with `bytes_left` merely going negative
# to record the overshoot rather than preventing it.

def test_byte_budget_caps_the_actual_read_size_requested(monkeypatch):
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_WINDOW", 1024 * 1024)

    region_base, region_size = 0x2000000, 0x10000
    max_want_seen = [0]
    def spying_reader(mf, addr, size):
        max_want_seen[0] = max(max_want_seen[0], size)
        return b"\x00" * size

    budget = memory_scan._ScanBudget(total_bytes=10, reads_per_region=100)
    reader = memory_scan._BudgetedReader(spying_reader, None, budget)
    gaps = memory_scan._scan_region_for_pe(
        reader, budget, region_base, region_size, lambda offset, data: None,
        window=1024 * 1024, degraded_read=0x1000)

    assert max_want_seen[0] <= 10, \
        f"a 10-byte budget must never let a single read ask for {max_want_seen[0]} bytes"
    assert budget.bytes_left >= 0, "the byte budget must never go negative"
    assert gaps.truncated


def test_byte_budget_partial_data_is_still_scanned_before_stopping(monkeypatch):
    # A read capped by the byte budget still returns real bytes (just
    # fewer than asked for) -- those bytes were actually read and must
    # still be examined for a candidate before the scan gives up, not
    # discarded just because the budget ran out mid-read.
    from dumpex.hunt.injection import memory_scan
    monkeypatch.setattr(memory_scan, "PE_SCAN_WINDOW", 1024 * 1024)

    region_base, region_size = 0x3000000, 0x1000
    content = b"\x00\x00\x00" + b"MZ" + b"\x00" * (region_size - 5)

    def reader(mf, addr, size):
        off = addr - region_base
        return content[off:off + size]

    # Budget covers exactly enough bytes to reach past the marker.
    budget = memory_scan._ScanBudget(total_bytes=5, reads_per_region=100)
    budgeted_reader = memory_scan._BudgetedReader(reader, None, budget)
    hits = []
    gaps = memory_scan._scan_region_for_pe(
        budgeted_reader, budget, region_base, region_size,
        lambda offset, data: hits.append(offset),
        window=1024 * 1024, degraded_read=0x1000)

    assert hits == [3], "bytes returned before the budget ran out must still be scanned"
    assert gaps.truncated

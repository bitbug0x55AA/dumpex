"""Hunter-level tests for dumpex.hunt.injection (Process Injection detection)."""
from tests.fixtures.fakes import (Region, Module, ThreadInfo, Ctx, Thread, FakeStream, FakeMF,
                                   build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
                                   mem_reader)

import dumpex.hunt.injection as injection
import dumpex.hunt.injection.presentation as injection_presentation
import dumpex.hunt.injection.legacy as injection_legacy


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
    # injection.rwx_regions' Finding.facts (built for --json/--csv) cap the
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
    # Presentation-only exclusion: --json/--csv (via f["findings"]) must
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
    real = injection_legacy.legacy_findings_dict

    def spy(findings):
        result = real(findings)
        calls.append(result)
        return result
    monkeypatch.setattr(injection_presentation, "legacy_findings_dict", spy)

    f = injection._hunt_injection(_full_correlation_mf(), verbose=False)
    assert len(calls) == 1
    assert f is calls[0]
    assert isinstance(f["rwx"][0], dict)   # never an Evidence dataclass leaking through


def test_legacy_findings_dict_called_on_not_evaluated_path(monkeypatch):
    calls = []
    real = injection_legacy.legacy_findings_dict

    def spy(findings):
        result = real(findings)
        calls.append(result)
        return result
    monkeypatch.setattr(injection_presentation, "legacy_findings_dict", spy)

    f = injection._hunt_injection(FakeMF(), verbose=False)
    assert f["status"] == "NOT_EVALUATED"
    assert len(calls) == 1
    assert f is calls[0]

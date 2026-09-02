"""Hunter-level tests for dumpex.hunt.pipe (Named Pipe C2 / Lateral Movement)."""
import pytest

from minidump.constants import MINIDUMP_STREAM_TYPE

from tests.fixtures.fakes import (
    Region, ThreadInfo, Handle, FakeStream, FakeMF, mem_reader,
    mf_with_handle_stream, parsed_handle_stream,
)

import dumpex.hunt.pipe as pipemod
from dumpex.core.memory import handle_stream_evidence, truncated_descriptor_count
from dumpex.hunt.pipe import handle_scan


# ── empty HandleDataStream -> COMPLETE/CLEAN ───────────────────────────────

def test_empty_handle_stream_is_complete_clean():
    dummy_regions = [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream([], "handles")   # stream PRESENT, zero handles
    pipemod.read_region = mem_reader({})

    f = pipemod._hunt_pipe(MF(), verbose=False)
    assert f["score"] == 0
    assert f["coverage_status"] == "complete"
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"


# ── HandleDataStream missing entirely -> partial/INCONCLUSIVE ─────────────

def test_missing_handle_stream_is_partial():
    dummy_regions = [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = None   # stream ABSENT
    pipemod.read_region = mem_reader({})

    f = pipemod._hunt_pipe(MF(), verbose=False)
    assert f["score"] == 0
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"


# ── truncated HandleDataStream -> partial, with the dropped tail counted ──

def handle_stream(handle_list, declared=None):
    """A HandleDataStream carrying `handle_list` and declaring `declared`
    descriptors -- by default exactly as many as it delivered. Pass more
    to model a stream whose descriptor array was cut off."""
    return FakeStream(handle_list, "handles", declared=declared)


def mf_with_handles(stream):
    """A dump whose only interesting stream is `stream`: one ordinary
    region that reads back empty, so nothing the string scan finds can
    move the verdict."""
    regions = [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = stream
    pipemod.read_region = mem_reader({})
    return MF()


def test_truncated_handle_stream_is_partial_and_keeps_the_head():
    """A dropped descriptor is simply not in the handle list, so the head
    still scores -- but the run must say the tail was never read."""
    delivered = [Handle(0x99, "File", r"\Device\NamedPipe\msagent_42")]
    f = pipemod._hunt_pipe(mf_with_handles(handle_stream(delivered, declared=4)), verbose=False)

    assert f["score"] >= 1, "the delivered head is still evidence"
    assert f["coverage_status"] == "partial"
    assert any("3 declared handle descriptor(s) were not read" in r
               for r in f["coverage_reasons"])


def test_truncation_survives_the_real_parser_end_to_end():
    """The whole hunter over an object `dumpex.core.memory.parse_handle_stream`
    actually produced, from real HandleDataStream bytes -- not a
    hand-shaped stand-in that could agree with the reader while both
    disagree with what the parser really returns.

    Two named descriptors reach the scan and one of them is a framework
    pipe, so the delivered head still scores; the header declares five,
    so three are missing and the run says so."""
    parsed = parsed_handle_stream(
        [{"handle": 0x10, "type_name": "File",
          "object_name": r"\Device\NamedPipe\msagent_42"},
         {"handle": 0x20, "type_name": "File",
          "object_name": r"\Device\NamedPipe\ordinary"}],
        number_of_descriptors=5)
    assert parsed.header.NumberOfDescriptors == 5
    assert len(parsed.handles) == 2
    assert parsed.handles[0].ObjectName == r"\Device\NamedPipe\msagent_42", (
        "the names must survive the real parse, or the head cannot score")

    f = pipemod._hunt_pipe(mf_with_handles(parsed), verbose=False)

    assert f["score"] >= 1, "the two delivered descriptors are still evidence"
    assert f["coverage_status"] == "partial"
    assert any("3 declared handle descriptor(s) were not read" in r
               for r in f["coverage_reasons"])


def test_truncation_is_read_off_the_header_not_recomputed_from_the_framing():
    """AC2, in the only shape that can falsify it, over real bytes.

    This stream's own framing claims room for five descriptors -- its
    directory DataSize covers `16 + 5 * 32` -- but the FILE ends after
    two. Reading `NumberOfDescriptors - len(handles)` off the parsed
    object gives the true 3; recomputing from the framing gives
    `5 - min(5, MAX_HANDLE_DESCRIPTORS, (176 - 16) // 32)` == 0, i.e. no
    truncation at all and a silent complete/exit-0 on a dump that lost
    handles. Every other truncation fixture stops at the DataSize bound,
    where both answers agree.

    The descriptors carry no names on purpose: a name would put a string
    area after the array that the parser's own byte-count bound would
    then read descriptors out of, which is a different (and fabricated)
    shape. #86's fourth bound is what this fixture is about."""
    declared_data_size = 16 + 5 * 32
    parsed = parsed_handle_stream(
        [{"handle": 0x10 * (i + 1)} for i in range(2)],
        number_of_descriptors=5, declared_data_size=declared_data_size)
    framing_fits = ((declared_data_size - parsed.header.SizeOfHeader)
                    // parsed.header.SizeOfDescriptor)
    assert framing_fits == 5, "the framing really does claim room for five"
    assert len(parsed.handles) == 2, "but the file only ever held two"
    assert parsed.header.NumberOfDescriptors - framing_fits == 0, (
        "recomputing from the framing would report no truncation at all")

    assert truncated_descriptor_count(parsed) == 3
    f = pipemod._hunt_pipe(mf_with_handles(parsed), verbose=False)
    assert f["coverage_status"] == "partial"
    assert any("3 declared handle descriptor(s) were not read" in r
               for r in f["coverage_reasons"])


def test_an_untruncated_real_stream_stays_complete():
    """The same real-parser path with the header and the file in
    agreement: no gap, no reason, nothing acquired."""
    parsed = parsed_handle_stream(
        [{"handle": 0x99, "type_name": "File",
          "object_name": r"\Device\NamedPipe\ipc"}])
    assert parsed.header.NumberOfDescriptors == len(parsed.handles) == 1

    f = pipemod._hunt_pipe(mf_with_handles(parsed), verbose=False)
    assert f["coverage_status"] == "complete"
    assert f["coverage_reasons"] == []


def test_an_unparseable_handle_stream_is_not_reported_as_never_captured():
    """A dump that DID carry a HandleDataStream whose framing could not be
    parsed must not be described as one captured without
    MiniDumpWithHandleData. The two send an analyst to different next
    steps -- re-capture with handle data, versus treat this dump's stream
    as corrupt -- and only one of them is available to someone whose dump
    already has the stream."""
    mf = mf_with_handle_stream(
        failure="HandleDataStream SizeOfDescriptor 24 is neither 32 nor 40")
    mf.memory_info = FakeStream(
        [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")],
        "infos")
    mf.modules     = FakeStream([], "modules")
    mf.thread_info = FakeStream([], "infos")
    pipemod.read_region = mem_reader({})

    f = pipemod._hunt_pipe(mf, verbose=False)

    assert f["coverage_status"] == "partial"
    reasons = " ".join(f["coverage_reasons"])
    assert "could not be parsed" in reasons
    assert "SizeOfDescriptor 24" in reasons, "the parser's own detail is what says why"
    assert "MiniDumpWithHandleData" not in reasons, (
        "re-capturing with handle data is not the next step for a corrupt stream")


def test_a_parse_failure_with_no_detail_is_refused_not_mis_advised():
    """The one state the (bool, detail) pair cannot express: a recorded
    parse failure whose detail is empty. Inferring "never captured" from
    it would print exactly the re-capture advice that is wrong for a
    corrupt stream, so it is rejected instead.

    `--handles` already refuses the same value -- SourceObservation will
    not take an empty detail -- and one dump must not make one command
    fail loudly and the other quietly mis-advise. Unreachable through
    `open_dump()`, whose recorded detail always carries at least the
    exception's own type name; enforced here rather than assumed, because
    `aggregate.build_report` takes this as a loose keyword argument."""
    mf = mf_with_handle_stream(has_directory=True)
    # Straight into the failures map: the fixture helper treats an empty
    # detail as "no failure", which is the very conflation under test.
    mf._dumpex_stream_failures = {MINIDUMP_STREAM_TYPE.HandleDataStream: ""}
    mf.memory_info = FakeStream([], "infos")
    mf.modules      = FakeStream([], "modules")
    mf.thread_info   = FakeStream([], "infos")
    pipemod.read_region = mem_reader({})

    assert handle_stream_evidence(mf) == ("failed", None, "")
    with pytest.raises(ValueError, match="must be None or a non-empty reason"):
        pipemod._build_pipe_report(mf)


def test_a_recorded_parse_failure_discards_handles_that_did_parse():
    """A dump can carry two HandleDataStream directory entries, one of
    which parsed. `mf.handles` then holds whichever entry won a
    last-writer-wins race, so which entry it came from is not knowable --
    and a recorded parse failure takes precedence, exactly as `--handles`
    already resolves it.

    The conservative result is pinned here: those handles do not score,
    and the run says why rather than reading clean."""
    parsed = parsed_handle_stream(
        [{"handle": 0x99, "type_name": "File",
          "object_name": r"\Device\NamedPipe\msagent_42"}])
    mf = mf_with_handle_stream(parsed=parsed,
                                failure="HandleDataStream SizeOfHeader 4 is out of bounds")
    mf.memory_info = FakeStream(
        [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")],
        "infos")
    mf.modules      = FakeStream([], "modules")
    mf.thread_info   = FakeStream([], "infos")
    pipemod.read_region = mem_reader({})

    f = pipemod._hunt_pipe(mf, verbose=False)

    assert f["score"] == 0, "a handle from an untrustworthy stream must not score"
    assert f["handle_pipes"] == []
    assert f["status"] == "INCONCLUSIVE", "and the result must not read as clean"
    assert any("could not be parsed" in r for r in f["coverage_reasons"])


def test_scan_handles_will_not_run_without_the_stream_to_measure_against():
    """The handle list alone cannot show a dropped descriptor, so the
    stream is a required argument: a caller that forgets it must fail
    loudly rather than silently report a truncated dump as complete."""
    with pytest.raises(TypeError):
        handle_scan.scan_handles([], (), )


def test_a_descriptor_array_cut_off_entirely_is_not_a_clean_empty_result():
    """The dangerous shape: a stream declaring handles whose array never
    arrived must never read like the checked-and-clean empty stream."""
    f = pipemod._hunt_pipe(mf_with_handles(handle_stream([], declared=7)), verbose=False)

    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"
    assert any("7 declared handle descriptor(s) were not read" in r
               for r in f["coverage_reasons"])


# ── generic (non-framework) pipe + C2 -> Finding matches verdict ──────────

def test_generic_pipe_corroboration_matches_verdict():
    region_base = 0x1230000
    pipe_name = b"\\\\.\\pipe\\my_custom_ipc_channel"   # not a known framework pattern
    data = b"A" * 0x100 + pipe_name + b"\x00" + b"http://198.51.100.7:8080/submit.php" + b"B" * 0x200
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    handle_list = [Handle(0x99, "File", r"\Device\NamedPipe\my_custom_ipc_channel")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream(handle_list, "handles")
    pipemod.read_region = mem_reader({region_base: data})

    f = pipemod._hunt_pipe(MF(), verbose=False)
    tags = {finding["check"]: (finding["tag"], finding["confidence"]) for finding in f["findings"]}
    assert f["score"] >= 2
    assert tags.get("pipe.corroboration", (None,))[0] == "detection"
    assert "pipe.handle_framework_match" not in tags, "must not fabricate a framework match"


# ── pipe name + C2 string 1 MiB apart in the SAME region -> no correlation ─

def test_pipe_and_c2_1mib_apart_no_correlation():
    region_base = 0x1000000
    region_size = 0x200000   # 2 MiB region
    pipe_name = b"\\\\.\\pipe\\my_custom_ipc_channel"
    data = bytearray(region_size)
    data[0x100:0x100 + len(pipe_name)] = pipe_name
    c2_offset = 0x180000   # ~1.5 MiB away — far past PIPE_CONTEXT_DISTANCE
    data[c2_offset:c2_offset + 40] = b"http://198.51.100.7:8080/submit.php\x00\x00\x00"
    regions = [Region(region_base, region_base, region_size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    handle_list = [Handle(0x99, "File", r"\Device\NamedPipe\my_custom_ipc_channel")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream(handle_list, "handles")
    pipemod.read_region = mem_reader({region_base: bytes(data)})

    f = pipemod._hunt_pipe(MF(), verbose=False)
    assert f["score"] == 0, "1 MiB apart must not correlate"


# ── pipe name + C2 string ~100 bytes apart -> score 2 ──────────────────────

def test_pipe_and_c2_100_bytes_apart_scores_2():
    region_base = 0x1000000
    region_size = 0x10000
    pipe_name = b"\\\\.\\pipe\\my_custom_ipc_channel"
    data = bytearray(region_size)
    data[0x100:0x100 + len(pipe_name)] = pipe_name
    c2_offset = 0x100 + len(pipe_name) + 100   # ~100 bytes after the pipe name
    data[c2_offset:c2_offset + 40] = b"http://198.51.100.7:8080/submit.php\x00\x00\x00"
    regions = [Region(region_base, region_base, region_size, "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    handle_list = [Handle(0x99, "File", r"\Device\NamedPipe\my_custom_ipc_channel")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream(handle_list, "handles")
    pipemod.read_region = mem_reader({region_base: bytes(data)})

    f = pipemod._hunt_pipe(MF(), verbose=False)
    assert f["score"] == 2


# ── 5 unrelated C2 matches earlier in scan order must not evict the 6th, ───
# proximity-relevant match from the bounded per-region retention (issue #24:
# the per-region C2 cap used to stop scanning in SCAN ORDER, before
# proximity to the pipe name was even known)

def test_c2_beyond_scan_order_cap_still_corroborates():
    region_base = 0x1000000
    region_size = 0x10000
    data = bytearray(region_size)

    # Five unrelated C2-pattern matches, first in scan order, each isolated
    # by null bytes (separate printable runs) and each far beyond
    # PIPE_CONTEXT_DISTANCE from where the pipe name sits below.
    unrelated_token = b"http://x"
    for off in (0x10, 0x110, 0x210, 0x310, 0x410):
        data[off:off + len(unrelated_token)] = unrelated_token

    pipe_name = b"\\\\.\\pipe\\my_custom_ipc_channel"
    pipe_offset = 0x3000
    data[pipe_offset:pipe_offset + len(pipe_name)] = pipe_name

    # The SIXTH C2-pattern match, within PIPE_CONTEXT_DISTANCE of the pipe
    # name -- this is the record the old first-N-in-scan-order cap would
    # never even see, since the 5 unrelated matches above already exhausted
    # it.
    c2_offset = pipe_offset + len(pipe_name) + 50
    c2_token = b"http://198.51.100.7:8080/submit.php"
    data[c2_offset:c2_offset + len(c2_token)] = c2_token

    regions = [Region(region_base, region_base, region_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    handle_list = [Handle(0x99, "File", r"\Device\NamedPipe\my_custom_ipc_channel")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream(handle_list, "handles")
    pipemod.read_region = mem_reader({region_base: bytes(data)})

    f = pipemod._hunt_pipe(MF(), verbose=False)
    tags = {finding["check"]: (finding["tag"], finding["confidence"]) for finding in f["findings"]}
    assert tags.get("pipe.corroboration", (None,))[0] == "detection", (
        "the proximity-relevant 6th C2 match must be retained even though "
        "5 unrelated matches occurred earlier in scan order")
    assert f["score"] == 2


# ── same regression, but with 200 unrelated matches -- past the OLD, ───────
# now-removed PIPE_C2_MAX_SCAN_PER_REGION=200 "matches examined" ceiling.
# That ceiling was itself a P1 follow-up to issue #24: capping the EXAMINE
# phase at a fixed count reintroduces the identical scan-order false
# negative at a higher threshold, invisibly to c2_budget/coverage. There is
# now no such cap at all -- the 201st match must still be scanned and
# retained, and default-sized budgets must not be exhausted by getting
# there.

def test_c2_beyond_200_unrelated_matches_still_corroborates():
    region_base = 0x1000000
    region_size = 0x10000
    data = bytearray(region_size)

    unrelated_token = b"http://x"
    for i in range(200):
        off = 0x10 + i * 0x20
        data[off:off + len(unrelated_token)] = unrelated_token

    pipe_name = b"\\\\.\\pipe\\my_custom_ipc_channel"
    pipe_offset = 0x8000
    data[pipe_offset:pipe_offset + len(pipe_name)] = pipe_name

    # The 201st C2-pattern match, within PIPE_CONTEXT_DISTANCE of the pipe
    # name -- the record a fixed "matches examined" cap of 200 would never
    # even see.
    c2_offset = pipe_offset + len(pipe_name) + 50
    c2_token = b"http://198.51.100.7:8080/submit.php"
    data[c2_offset:c2_offset + len(c2_token)] = c2_token

    regions = [Region(region_base, region_base, region_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    handle_list = [Handle(0x99, "File", r"\Device\NamedPipe\my_custom_ipc_channel")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream(handle_list, "handles")
    pipemod.read_region = mem_reader({region_base: bytes(data)})

    f = pipemod._hunt_pipe(MF(), verbose=False)
    tags = {finding["check"]: (finding["tag"], finding["confidence"]) for finding in f["findings"]}
    assert tags.get("pipe.corroboration", (None,))[0] == "detection", (
        "the proximity-relevant 201st C2 match must still be retained even "
        "though 200 unrelated matches occurred earlier in scan order")
    assert f["score"] == 2
    assert f["coverage_status"] == "complete", (
        "200 unrelated matches must not itself exhaust a whole-hunt budget "
        "on default-sized budgets -- this scenario must remain fully "
        "covered, not just correctly scored")


# ── c2_budget already exhausted -> partial coverage, never a silently ──────
# lower score as though the full scoring scope had been evaluated (issue
# #24's own acceptance criteria). Proximity evidence is now gated ENTIRELY
# by the whole-hunt c2_budget (no separate per-region cap of its own), so
# its exhaustion must be visible end to end.

def test_c2_budget_exhaustion_marks_coverage_partial(monkeypatch):
    region_base = 0x1000000
    region_size = 0x10000
    pipe_name = b"\\\\.\\pipe\\my_custom_ipc_channel"
    data = bytearray(region_size)
    data[0x100:0x100 + len(pipe_name)] = pipe_name
    c2_offset = 0x100 + len(pipe_name) + 50
    c2_token = b"http://198.51.100.7:8080/submit.php"
    data[c2_offset:c2_offset + len(c2_token)] = c2_token

    regions = [Region(region_base, region_base, region_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    handle_list = [Handle(0x99, "File", r"\Device\NamedPipe\my_custom_ipc_channel")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream(handle_list, "handles")
    pipemod.read_region = mem_reader({region_base: bytes(data)})

    # Force the whole-hunt C2 budget to already be exhausted before the
    # scan begins -- `dumpex.hunt.pipe.__init__` binds this constant into
    # its own module namespace at import time (`from ...config import
    # PIPE_C2_BUDGET_MAX_HITS`), so patching it here, like this module's
    # existing `pipemod.read_region`/`pipemod.get_thread_contexts`
    # monkeypatches, changes what `_build_pipe_report()` actually
    # constructs.
    monkeypatch.setattr(pipemod, "PIPE_C2_BUDGET_MAX_HITS", 0)

    f = pipemod._hunt_pipe(MF(), verbose=False)
    assert f["coverage_status"] == "partial"
    tags = {finding["check"] for finding in f["findings"]}
    assert "pipe.corroboration" not in tags, (
        "with c2_budget exhausted before any hit could be taken, no C2 "
        "record could have been retained to corroborate anything")


# ── pipe + nearby C2 + nearby RIP -> score 3 ────────────────────────────────

def test_pipe_nearby_c2_and_rip_scores_3():
    region_base = 0x1000000
    region_size = 0x10000
    pipe_name = b"\\\\.\\pipe\\my_custom_ipc_channel"
    data = bytearray(region_size)
    data[0x100:0x100 + len(pipe_name)] = pipe_name
    c2_offset = 0x100 + len(pipe_name) + 100
    data[c2_offset:c2_offset + 40] = b"http://198.51.100.7:8080/submit.php\x00\x00\x00"
    regions = [Region(region_base, region_base, region_size, "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    handle_list = [Handle(0x99, "File", r"\Device\NamedPipe\my_custom_ipc_channel")]
    pipe_va = region_base + 0x100

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream(handle_list, "handles")
    pipemod.read_region = mem_reader({region_base: bytes(data)})
    pipemod.get_thread_contexts = lambda mf: [{"ThreadId": 1, "ip": pipe_va + 50,
                                                 "ip_reg": "RIP", "is_wow64": False}]

    f = pipemod._hunt_pipe(MF(), verbose=False)
    assert f["score"] == 3


# ── Bonus: framework-matched pipe + full corroboration -> score 3 ─────────

def test_framework_plus_full_corroboration_scores_3():
    region_base = 0x1230000
    pipe_name = b"\\\\.\\pipe\\msagent_1337"
    pipe_off  = 0x100
    data = (b"A" * pipe_off + pipe_name + b"\x00"
            + b"http://198.51.100.7:8080/submit.php" + b"B" * 0x200)
    # must be executable for a RIP hit to corroborate (see region_is_executable)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_PRIVATE")]
    handle_list = [Handle(0x88, "File", r"\Device\NamedPipe\msagent_1337")]
    thread_infos = [ThreadInfo(0x999, region_base + 0x10)]
    pipe_va = region_base + pipe_off

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        handles        = FakeStream(handle_list, "handles")
    pipemod.read_region = mem_reader({region_base: data})
    # RIP within PIPE_CONTEXT_DISTANCE of the pipe name's own VA — StartAddress
    # alone (thread_infos above) is no longer enough to score, only a lead.
    pipemod.get_thread_contexts = lambda mf: [{"ThreadId": 0x999, "ip": pipe_va + 5,
                                                 "ip_reg": "RIP", "is_wow64": False}]

    f = pipemod._hunt_pipe(MF(), verbose=False)
    assert f["score"] == 3
    assert f["confidence"] == "high"


# ── a region that returns FEWER bytes than its own declared RegionSize ────
# (a short read, no exception raised) must not be treated as a complete
# scan -- the unread tail could hide a real pipe name or C2 string.

def test_short_read_region_makes_result_inconclusive():
    region_base = 0x2000000
    declared_size = 0x4000
    actual_bytes  = b'\x00' * 0x1000   # far less than RegionSize claims
    regions = [Region(region_base, region_base, declared_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]
    handle_list = [Handle(0x77, "File", r"\Device\NamedPipe\some_pipe")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream(handle_list, "handles")
    pipemod.read_region = mem_reader({region_base: actual_bytes})

    f = pipemod._hunt_pipe(MF(), verbose=False)
    assert f["coverage_status"] == "partial"
    assert f["status"] == "INCONCLUSIVE"
    assert any("short read" in r for r in f["coverage_reasons"])


# ── HandleDataStream missing AND a short-read region gap co-occurring ─────
# must not have the console silently drop the short-read note just because
# the "no HandleDataStream" gap is also present — --json's
# coverage_reasons already carried both, but a prior version had the
# console re-derive a narrower reason string of its own. Since the
# canonical-report migration (issue #7) there is only one source: every
# gap comes from `report_facts.project_coverage_v1`, and the console
# renders that ONE list in its unified COVERAGE section (see
# dumpex/hunt/pipe/report_console.py).

def test_missing_handle_stream_and_short_read_both_reported(capsys):
    region_base = 0x2100000
    declared_size = 0x4000
    actual_bytes  = b'\x00' * 0x1000   # far less than RegionSize claims
    regions = [Region(region_base, region_base, declared_size, "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = None   # HandleDataStream stream ABSENT
    pipemod.read_region = mem_reader({region_base: actual_bytes})

    f = pipemod._hunt_pipe(MF(), verbose=False)
    assert f["status"] == "INCONCLUSIVE"
    assert any("HandleDataStream" in r for r in f["coverage_reasons"])
    assert any("short read" in r for r in f["coverage_reasons"])

    out = capsys.readouterr().out
    assert "HandleDataStream" in out
    assert "short read" in out, (
        "the short-read coverage gap must still be visible in the console verdict "
        "even when HandleDataStream is also missing"
    )


# ── --verbose must list EVERY open pipe handle, not just the first 20 ─────
# pipe.open_handles' Finding.facts (built for --json) cap the list
# at 20 with a "... and N more" sentinel -- --verbose is supposed to mean
# "the complete list"; that expansion now lives in
# `report_console._verbose_facts_for`, which renders every evidence item
# uncapped. Regression test for that completeness claim silently becoming
# false again.

def test_verbose_lists_every_handle_beyond_the_facts_cap(capsys):
    region_base = 0x2200000
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    handle_list = [Handle(i, "File", rf"\Device\NamedPipe\test_{i}") for i in range(25)]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream(handle_list, "handles")
    pipemod.read_region = mem_reader({region_base: b""})

    pipemod._hunt_pipe(MF(), verbose=False)
    normal_out = capsys.readouterr().out
    assert r"\Device\NamedPipe\test_24" not in normal_out

    pipemod._hunt_pipe(MF(), verbose=True)
    verbose_out = capsys.readouterr().out
    for i in range(25):
        assert rf"\Device\NamedPipe\test_{i}" in verbose_out, \
            f"handle {i} (beyond the 20-item Finding.facts cap) missing from --verbose output"

"""Hunter-level tests for dumpex.hunt.pipe (Named Pipe C2 / Lateral Movement)."""
from tests.fixtures.fakes import Region, ThreadInfo, Handle, FakeStream, FakeMF, mem_reader

import dumpex.hunt.pipe as pipemod


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

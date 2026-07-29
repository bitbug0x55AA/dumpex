"""
Cross-hunter invariant: a hunter reporting status="DETECTED" must always
be backed by at least one tag="detection" Finding in its own
findings["findings"] list -- a nonzero score/DETECTED status that isn't
traceable to a specific structurally-corroborated piece of evidence is a
hunter-side bug (dumpex.hunt._finding.overall_confidence() already treats
this as one, silently degrading to "low" rather than guessing "high" --
this test makes the same expectation an explicit, enforced regression
rather than a quiet fallback).

Only covers hunters on the shared Finding/tag model (injection, cs-beacon,
pipe, stomping, encoding, hollowing) -- yara_hunt reports "matches",
not tag=observation/lead/detection Finding objects, and is architecturally
a different (legacy) model; out of scope here.
"""
import base64
import os
import tempfile

from tests.fixtures.fakes import (Region, Segment, FakeStream, FakeReader, FakeMF,
                                   Module, ThreadInfo, Thread, Ctx, Handle, Peb,
                                   build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
                                   mem_reader, cs_beacon_config_bytes)

import dumpex.hunt.injection as injection
import dumpex.hunt.cs_beacon as cs_beacon
import dumpex.hunt.pipe as pipe
import dumpex.hunt.stomping as stomping
import dumpex.hunt.encoding as encoding
import dumpex.hunt.hollowing as hollowing


def _assert_detected_has_detection_tag(findings: dict):
    assert findings["status"] == "DETECTED", \
        f"fixture expected to produce DETECTED, got {findings['status']!r}"
    tags = {f["tag"] for f in findings["findings"]}
    assert "detection" in tags, (
        f"status=DETECTED but no tag=detection Finding is present — "
        f"tags found: {sorted(tags)}"
    )


def test_injection_detected_has_detection_tag():
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
    _assert_detected_has_detection_tag(f)


def test_cs_beacon_detected_has_detection_tag():
    seg_va, seg_fo = 0x21000, 0x2100
    config = cs_beacon_config_bytes(0x69)
    data = b'\x00' * 0x100 + config + b'\x00' * 0x100
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    _assert_detected_has_detection_tag(f)


def test_pipe_detected_has_detection_tag():
    region_base = 0x1230000
    pipe_name = b"\\\\.\\pipe\\msagent_1337"
    pipe_off  = 0x100
    data = (b"A" * pipe_off + pipe_name + b"\x00"
            + b"http://198.51.100.7:8080/submit.php" + b"B" * 0x200)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_PRIVATE")]
    handle_list = [Handle(0x88, "File", r"\Device\NamedPipe\msagent_1337")]
    thread_infos = [ThreadInfo(0x999, region_base + 0x10)]
    pipe_va = region_base + pipe_off

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        handles        = FakeStream(handle_list, "handles")
    pipe.read_region = mem_reader({region_base: data})
    pipe.get_thread_contexts = lambda mf: [{"ThreadId": 0x999, "ip": pipe_va + 5,
                                             "ip_reg": "RIP", "is_wow64": False}]

    f = pipe._hunt_pipe(MF(), verbose=False)
    _assert_detected_has_detection_tag(f)


def test_stomping_detected_has_detection_tag():
    module_base = 0x7ff600000000
    timestamp = 0x11111111
    sections = [{"name": b".text", "vaddr": 0x1000, "vsize": 0x2000, "rawptr": 0x400,
                 "rawsize": 0x2000, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}]
    header = build_pe_header(sections, timestamp=timestamp, size_of_image=0x5000,
                              image_base=module_base)

    text_original = bytes((i * 7) % 251 for i in range(0x2000))
    ref_file = bytearray(header)
    ref_file += b'\x00' * (sections[0]["rawptr"] - len(ref_file))
    ref_file += text_original

    mem_text = bytearray(text_original)
    mem_text[0x100:0x110] = b'\xCC' * 0x10   # simulated stomp

    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + 0x1000, module_base, 0x2000, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")]
    read_map = {module_base: header, module_base + 0x1000: bytes(mem_text)}

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "legit.dll"), "wb") as fh:
            fh.write(bytes(ref_file))

        stomping.read_region = mem_reader(read_map)
        stomping.get_thread_contexts = lambda mf: []
        f = stomping._hunt_stomping(MF(), verbose=False, ref_dir=d)
        _assert_detected_has_detection_tag(f)


def test_encoding_detected_has_detection_tag():
    region_base = 0x300000
    pe_bytes = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                  "rawptr": 0x400, "rawsize": 0x200,
                                  "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                                size_of_image=0x2000, trailing_padding=0x300)
    b64_pe = base64.b64encode(pe_bytes)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: b64_pe.ljust(0x1000, b'\x00')})

    f = encoding._hunt_encoding(MF(), verbose=False)
    _assert_detected_has_detection_tag(f)


def test_hollowing_detected_has_detection_tag():
    image_base = 0x140000000
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([], "modules")
        memory_info = FakeStream(regions, "infos")
    hollowing.read_region = mem_reader({image_base: b'\x00' * 64})   # zeroed MZ

    f = hollowing._hunt_hollowing(MF(), verbose=False)
    _assert_detected_has_detection_tag(f)

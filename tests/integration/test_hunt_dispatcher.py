"""
Integration tests for dumpex.hunt.cmd_hunt() -- the --hunt CLI dispatcher
that wraps each individual hunter's findings and sanitizes them for JSON
serialization (int-keyed field dicts -> str keys, bytes -> hex).

The CS Beacon sanitization step used to hand-reconstruct each config dict
field-by-field, which silently dropped any field _hunt_cs_beacon added
that this dispatcher didn't already know about (context_corroborated,
cs_version_note) -- these tests pin that every field a hunter reports
survives the dispatcher unchanged.
"""
from tests.fixtures.fakes import Region, Segment, FakeReader, FakeStream, FakeMF, cs_beacon_config_bytes

import dumpex.hunt as hunt


def _mk_segment_data(config_bytes: bytes, pad_before: int = 0x100, pad_after: int = 0x100) -> bytes:
    return b'\x00' * pad_before + config_bytes + b'\x00' * pad_after


def test_cs_beacon_config_fields_survive_dispatcher():
    seg_va, seg_fo = 0x20000, 0x2000
    config = cs_beacon_config_bytes(0x69)
    data = _mk_segment_data(config)
    seg = Segment(seg_va, seg_fo, len(data))
    # executable + private -> context-corroborated, so context_corroborated
    # is not just present but actually True, and cs_version_note is set.
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})

    results = hunt.cmd_hunt(MF(), "cs-beacon", verbose=False)
    cfg = results["cs-beacon"]["configs"][0]
    assert cfg["context_corroborated"] is True
    assert "cs_version_note" in cfg and cfg["cs_version_note"]
    assert cfg["cs_version"]
    assert cfg["xor_key"] == 0x69
    # fields dict must still be JSON-safe (str keys, no raw bytes objects)
    assert all(isinstance(k, str) for k in cfg["fields"].keys())
    assert isinstance(cfg["fields"]["1"]["raw"], str)

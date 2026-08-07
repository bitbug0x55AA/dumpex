"""Legacy StructuredOutput JSON regression tests."""
from dumpex.ui.structured import StructuredOutput


def test_obfuscation_to_json_round_trip_has_no_leaked_objects():
    import io
    import json as _json
    import base64 as _base64
    import sys as _sys

    import dumpex.hunt.encoding as encoding
    from tests.fixtures.fakes import Region as _Region, FakeStream, FakeMF, mem_reader

    plaintext = b"c2 callback: http://185.220.101.5:8080/gate.php" + b"A" * 40
    payload = _base64.b64encode(plaintext)
    region_base = 0x950000
    regions = [_Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: payload.ljust(0x1000, b'\x00')})

    real_stdout = _sys.stdout
    _sys.stdout = io.StringIO()
    try:
        findings = encoding._hunt_encoding(MF(), verbose=False)
    finally:
        _sys.stdout = real_stdout

    out = StructuredOutput("/tmp/fake.dmp", mf=None)
    out.add("hunt", {"obfuscation": findings})
    json_text = out.to_json()

    assert findings["base64"], "scenario must actually produce a base64 hit to be meaningful"
    assert " object at 0x" not in json_text, "a raw object leaked into JSON via str(obj) fallback"
    assert "Hit(" not in json_text, "a raw Hit dataclass repr leaked into JSON"
    assert "b'" not in json_text, "a raw bytes literal repr leaked into JSON (should be hex-encoded)"

    parsed = _json.loads(json_text)
    hit = parsed["hunt"]["obfuscation"]["base64"][0]
    assert isinstance(hit["region"], dict)
    assert hit["region"]["BaseAddress"] == region_base
    assert isinstance(hit["decoded"], str)   # hex string, not a bytes repr
    assert bytes.fromhex(hit["decoded"]) == plaintext   # round-trips to the exact original bytes
    assert isinstance(hit["raw"], str)
    assert bytes.fromhex(hit["raw"]) == payload

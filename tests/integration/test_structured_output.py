"""
Output-path integration tests: does dumpex.ui.structured.StructuredOutput's
CSV/JSON summary row faithfully reflect a hunter's OWN verdict_level /
confidence / coverage_status, rather than re-deriving a (possibly
disagreeing) verdict from score/confidence arithmetic on its own?
"""
from dumpex.ui.structured import StructuredOutput
from dumpex.hunt.encoding.models import Hit, EntropyHit
from tests.fixtures.fakes import Region


# ── stomping 1/2 stays at its own verdict_level in the summary row, ───────
# not re-derived/inflated by structured.py ─────────────────────────────────

def test_stomping_verdict_not_inflated_in_summary_row():
    out = StructuredOutput("/tmp/fake.dmp", mf=None)
    stomping_findings = {
        "score": 1, "max_score": 2, "status": "DETECTED", "confidence": "medium",
        "verdict_level": "likely",
        "coverage_status": "complete", "coverage_reasons": [],
        "protection_leads": [], "verified_changes": [], "findings": [],
    }
    row = out._section_to_tables("hunt", {"stomping": stomping_findings})["summary"][0]
    # verdict must equal the hunter's OWN verdict_level, uppercased — not a
    # generically re-derived "POSSIBLE" from score/confidence arithmetic.
    assert row["verdict"] == "LIKELY"
    assert row["verdict_level"] == "likely"
    assert row["confidence"] == "medium"


# ── DETECTED and partial coverage representable simultaneously ────────────

def test_detected_and_partial_coverage_coexist():
    out = StructuredOutput("/tmp/fake.dmp", mf=None)
    stomping_findings = {
        "score": 1, "max_score": 2, "status": "DETECTED", "confidence": "medium",
        "verdict_level": "likely",
        "coverage_status": "partial",
        "coverage_reasons": ["2 module header(s) failed PE structural validation"],
        "protection_leads": [], "verified_changes": [], "findings": [],
    }
    row = out._section_to_tables("hunt", {"stomping": stomping_findings})["summary"][0]
    assert row["status"] == "DETECTED"
    assert row["verdict"] == "LIKELY"
    assert row["coverage_complete"] is False
    assert "module header" in row["coverage_reason"]


# ── verdict_level is consistent between the hunter's own field and what ───
# structured.py's CSV/JSON summary row reports — for every level and every
# phase-two hunter, not just stomping.

def test_verdict_level_consistent_across_hunters():
    out = StructuredOutput("/tmp/fake.dmp", mf=None)
    cases = [
        ("injection", 1, "possible"), ("injection", 2, "likely"), ("injection", 3, "high"),
        ("stomping",  1, "likely"),   ("stomping",  2, "high"),
        ("pipe",      1, "possible"), ("pipe",      2, "likely"),   ("pipe", 3, "high"),
        ("obfuscation", 1, "likely"), ("obfuscation", 2, "high"),
        ("cs-beacon", 1, "likely"),   ("cs-beacon", 2, "high"),
    ]
    for ttp, score, expected_level in cases:
        mock = {
            "score": score, "max_score": 3, "status": "DETECTED",
            "confidence": "high", "verdict_level": expected_level,
            "coverage_status": "complete", "coverage_reasons": [], "findings": [],
        }
        row = out._section_to_tables("hunt", {ttp: mock})["summary"][0]
        assert row["verdict_level"] == expected_level, (ttp, score, row)
        assert row["verdict"] == expected_level.upper(), (ttp, score, row)


# ── verdict_level must never render as "clean" for INCONCLUSIVE/ ──────────
# NOT_EVALUATED rows, regardless of what the hunter's own verdict_level
# field says (a defense-in-depth check on top of _finding.verdict_level()
# itself already refusing to emit "clean" in that case).

def test_inconclusive_and_not_evaluated_never_show_as_clean():
    out = StructuredOutput("/tmp/fake.dmp", mf=None)
    for status, verdict_level in (("INCONCLUSIVE", "inconclusive"), ("NOT_EVALUATED", "not_evaluated")):
        mock = {
            "score": 0, "max_score": 2, "status": status,
            "confidence": "none", "verdict_level": verdict_level,
            "coverage_status": "partial" if status == "INCONCLUSIVE" else "not_evaluated",
            "coverage_reasons": ["some coverage gap"], "findings": [],
        }
        row = out._section_to_tables("hunt", {"stomping": mock})["summary"][0]
        assert row["verdict"] != "CLEAN", (status, row)
        assert row["verdict_level"] != "clean", (status, row)


# ── obfuscation's sleep_mask/entropy/hidden_pe/hidden_shellcode CSV rows ──
# read the dict shape dumpex.hunt.encoding.models.Hit/EntropyHit.to_dict()
# produces -- NOT the Hit/EntropyHit objects themselves, which
# aggregate.py always converts before returning `findings` (see
# aggregate.build_report's final conversion pass, and models.py's own
# docstring on why: raw objects reaching _json_safe would embed a live
# memory address and the full undecoded `decoded` bytes into --json
# output). This CSV path had NO test coverage at all before this test —
# an earlier version unpacked these as tuples/dicts with a different
# shape, which would raise or silently misbehave. Exercise all four
# rather than just one, since each was a separately-shaped bug.

def test_obfuscation_csv_rows_read_to_dict_shape_correctly():
    out = StructuredOutput("/tmp/fake.dmp", mf=None)
    region = Region(0x140000, 0x140000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")

    sleep_mask_hit = Hit(layer="sleep_mask", region=region, offset=0, decoded=b"A" * 20,
                         cls={"type": "plaintext", "is_pe": False, "is_shellcode": False, "ioc_strings": []},
                         key=bytes.fromhex("00c80ad214dc1ee628f032fa3c"), key_offset=0)
    entropy_hit = EntropyHit(region=region, entropy=7.5, threshold=7.2)
    pe_hit = Hit(layer="gzip", region=region, offset=0x10, decoded=b"MZ" + b"\x90" * 60,
                cls={"type": "pe", "is_pe": True, "is_shellcode": False, "ioc_strings": []}, complete=True)
    shellcode_hit = Hit(layer="base64", region=region, offset=0x20,
                        decoded=b"\xe8\x00\x00\x00\x00\x58" + b"\x90" * 10,
                        cls={"type": "shellcode", "is_pe": False, "is_shellcode": True, "ioc_strings": []})

    obfuscation_findings = {
        "score": 1, "max_score": 2, "status": "DETECTED", "confidence": "high",
        "verdict_level": "high", "coverage_status": "complete", "coverage_reasons": [],
        "findings": [],
        "sleep_mask": [sleep_mask_hit.to_dict()],
        "entropy": [entropy_hit.to_dict()],
        "hidden_pe": [pe_hit.to_dict()],
        "hidden_shellcode": [shellcode_hit.to_dict()],
    }
    tables = out._section_to_tables("hunt", {"obfuscation": obfuscation_findings})
    rows = {r["finding_type"]: r for r in tables["findings"]}

    assert "obfuscation_sleep_mask_confirmed" in rows
    assert "00c80ad2" in rows["obfuscation_sleep_mask_confirmed"]["details"]
    assert "obfuscation_entropy_observation" in rows
    assert "entropy=7.500" in rows["obfuscation_entropy_observation"]["details"]
    assert "obfuscation_structural_pe_payload" in rows
    assert "encoding=gzip" in rows["obfuscation_structural_pe_payload"]["details"]
    assert "obfuscation_structural_shellcode_payload" in rows
    assert "encoding=base64" in rows["obfuscation_structural_shellcode_payload"]["details"]


# ── a REAL to_json() round trip: no Hit/EntropyHit object (or anything ────
# derived from one -- memory address, raw undecoded bytes) may leak into
# the actual serialized JSON string. Runs the real hunter, not a
# hand-built findings dict, so this catches the exact P1 this was written
# for: aggregate.py putting live objects straight into `findings` and
# relying on structured.py's str(obj) fallback for it.

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

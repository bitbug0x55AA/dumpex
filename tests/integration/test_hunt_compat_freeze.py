"""
Pre-migration compatibility freeze for `--hunt` (v2.4 output migration,
PR1). Every scenario here is built from `tests/fixtures/hunt_cases.py`
(synthetic `FakeMF`-backed input only — never `tests/corpus/`, which is
`.gitignore`d, local-only, and may hold real process memory/paths/hashes
that must never be committed; see that directory's own `.gitignore`
entry) and is fully deterministic: no wall clock, no host filesystem path
outside pytest's own `tmp_path`. Every module-attribute override
(`read_region`/`get_thread_contexts`) goes through pytest's `monkeypatch`
fixture, passed down into each `hunt_cases` builder — nothing here leaks
global state between tests regardless of execution order.

This file, not a static reference file, IS the frozen baseline: it fails
in CI the moment PR2+ changes a judgment field's value or a console
verdict's wording without updating the corresponding assertion here. Every
scenario asserts the FULL key set of the returned dict (`assert set(f) ==
{...}`), not just a handful of judgment fields, so an added/removed/
renamed top-level key is caught even if its value was never separately
asserted. This file's own nested-`details` assertions are deliberately
SHALLOW (counts, a handful of stable sub-fields — see e.g.
`test_pipe_detected_full_corroboration`), not full structural equality:
the deep, full-dict freeze of every hunter's complete `details` shape
(including nested findings/facts/coverage dicts) lives in
tests/integration/test_hunt_cli_compat_freeze.py, which compares each
hunter's ENTIRE returned dict against a golden JSON snapshot after
normalizing the one genuinely non-reproducible defect (raw-object
`str(obj)` addresses — see below). That file is the one to extend if a
future change needs deeper nested-structure coverage than this one
provides; do not read this file's shallow checks as "PR1 already froze
every hunter's details shape byte-for-byte" — it does not, by itself.

What this deliberately does NOT pin, and why:
  - `meta.rules`/`meta.yara_rules`/`meta.evidence`/timestamps — these come
    from the full CLI envelope (`dumpex.ui.structured.StructuredOutput`/
    `dumpex.output.collector.V2Output`), not from a hunter's own
    `_hunt_*()` return value, and embed `datetime.now()` plus real
    filesystem paths — inherently non-reproducible across runs/machines.
    Every scenario below calls a hunter function (or `hunt.cmd_hunt()`)
    directly instead. The CLI-layer envelope (JSON/CSV/exit code) IS
    frozen separately, in tests/integration/test_hunt_cli_compat_freeze.py.
  - `dumpex.ui.structured._json_safe`'s `str(obj)` fallback for raw
    Region/ThreadInfo/Handle objects (e.g. `pipe`'s `handle_pipes`/
    `private_pipes`/`c2_context`/`unbacked_in_rgn`) embeds the *Python
    interpreter's own runtime heap address* of the object (`<...Region
    object at 0x0000020AC1D769D0>`) — different every single run, even
    with identical input. Assertions on these fields check count/type/
    stable sub-fields, never the raw object's identity or its
    `_json_safe()` string form. `injection`'s `rwx`/`hidden_pe_validated`/
    `hidden_pe_unvalidated`/`threads`/`rip_hits`/`rip_full_correlation`/
    `start_hits` fields no longer have this defect at all: internally,
    aggregate.py now builds these from frozen Evidence dataclasses (see
    dumpex/hunt/injection/models.py), but presentation.render() never
    returns those dataclasses (or their repr) to a caller -- dumpex.hunt.
    injection.legacy.legacy_findings_dict() projects every one of them
    into a plain, JSON-safe dict (stable keys: base_address/
    allocation_base/size/type/protect for a region, plus region/
    in_module_list/pe for a hidden-PE hit, etc. -- see that module's own
    docstring) before `_hunt_injection()`/`cmd_hunt()` ever hand the
    result back. `test_injection_detected_...` below asserts the actual
    dict shape directly, not `_json_safe()`'s fallback behavior.
"""
import json

import pytest

from tests.fixtures import hunt_cases
from dumpex.ui.structured import _json_safe


_INJECTION_KEYS = {
    "confidence", "coverage", "coverage_reasons", "coverage_status", "findings",
    "hidden_pe_unvalidated", "hidden_pe_validated", "informational_validated_pe_hits",
    "lead_count", "max_score", "pe_read_failed", "pe_short_reads", "review_priority",
    "rip_full_correlation", "rip_hits", "rwx", "rwx_and_pe_alloc_bases", "score",
    "start_hits", "status", "suspicious_validated_pe_hits", "thread_contexts", "threads",
    "verdict_level",
}
_HOLLOWING_KEYS = {
    "confidence", "coverage_reasons", "coverage_status", "findings", "lead_count",
    "max_score", "review_priority", "score", "status", "verdict_level",
}
_STOMPING_KEYS = {
    "confidence", "coverage_counts", "coverage_reasons", "coverage_status", "findings",
    "lead_count", "max_score", "protection_leads", "review_priority", "score", "status",
    "verdict_level", "verified_changes",
}
_PIPE_KEYS = {
    "budget_exhausted", "c2_context", "confidence", "coverage_reasons", "coverage_status",
    "findings", "framework_pipes", "handle_pipes", "lead_count", "max_score",
    "private_pipes", "review_priority", "scan_complete", "score", "status",
    "unbacked_in_rgn", "verdict_level",
}
_CS_BEACON_KEYS = {
    "confidence", "config_count", "configs", "coverage", "coverage_reasons",
    "coverage_status", "findings", "lead_count", "max_score", "review_priority", "score",
    "status", "verdict_level",
}
_YARA_NOT_EVALUATED_KEYS = {"coverage_status", "matches", "score", "status", "verdict_level"}
_YARA_DETECTED_KEYS = {
    "coverage", "coverage_status", "matches", "rules_hit", "scan_complete", "score",
    "status", "verdict_level",
}
_OBFUSCATION_KEYS = {
    "base64", "budget_exhausted", "compressed", "confidence", "coverage_reasons",
    "coverage_status", "entropy", "findings", "hidden_pe", "hidden_shellcode",
    "lead_count", "max_score", "review_priority", "score", "sleep_mask", "status",
    "verdict_level", "xor",
}


# ── injection ────────────────────────────────────────────────────────────

def test_injection_detected_full_correlation(monkeypatch):
    f, console = hunt_cases.injection_detected_full_correlation(monkeypatch)
    assert set(f) == _INJECTION_KEYS
    assert f["score"] == 3
    assert f["max_score"] == 3
    assert f["status"] == "DETECTED"
    assert f["coverage_status"] == "partial"
    assert f["verdict_level"] == "high"
    assert f["confidence"] == "high"
    assert f["lead_count"] == 3
    assert f["review_priority"] == "high"
    assert "HUNT: Process Injection" in console
    assert len(f["rwx"]) == 1
    # Post-migration (see module docstring): findings["rwx"] no longer
    # holds a raw minidump Region (the old defect this assertion used to
    # pin the shape of) NOR an internal Evidence dataclass/its repr --
    # dumpex.hunt.injection.legacy.legacy_findings_dict() projects it into
    # a plain, JSON-safe dict before presentation.render() ever returns
    # it, so this checks the dict's actual keys directly rather than
    # relying on _json_safe()'s str(obj) fallback at all.
    assert f["rwx"][0] == {
        "base_address": 0x7ff700000000, "allocation_base": 0x7ff700000000,
        "size": 0x1000, "type": "MEM_PRIVATE", "protect": "PAGE_EXECUTE_READWRITE",
    }
    for key in ("rwx", "hidden_pe_validated", "hidden_pe_unvalidated",
                "suspicious_validated_pe_hits", "informational_validated_pe_hits",
                "threads", "rip_hits", "rip_full_correlation", "start_hits"):
        for item in f[key]:
            assert isinstance(item, dict), f"{key} still holds a non-dict item: {item!r}"
    json.dumps(_json_safe(f))  # must not raise


def test_injection_inconclusive_no_thread_context(monkeypatch):
    f, console = hunt_cases.injection_inconclusive_no_thread_context(monkeypatch)
    assert set(f) == _INJECTION_KEYS
    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"
    assert f["verdict_level"] == "inconclusive"
    assert "INCONCLUSIVE" in console


# ── hollowing ────────────────────────────────────────────────────────────

def test_hollowing_detected_mem_private_and_rwx(monkeypatch):
    f, console = hunt_cases.hollowing_detected_mem_private_and_rwx(monkeypatch)
    assert set(f) == _HOLLOWING_KEYS
    assert f["score"] == 1
    assert f["max_score"] == 2
    assert f["status"] == "DETECTED"
    assert f["coverage_status"] == "complete"
    assert f["verdict_level"] == "likely"
    assert f["confidence"] == "medium"
    assert f["lead_count"] == 2
    assert f["review_priority"] == "high"
    assert "LIKELY HOLLOWING" in console
    checks = {finding["check"] for finding in f["findings"]}
    assert "hollowing.structural_correlation" in checks
    json.dumps(_json_safe(f))


def test_hollowing_not_evaluated(monkeypatch):
    f, console = hunt_cases.hollowing_not_evaluated(monkeypatch)
    assert set(f) == _HOLLOWING_KEYS
    assert f["score"] == 0
    assert f["status"] == "NOT_EVALUATED"
    assert f["coverage_status"] == "not_evaluated"
    assert f["verdict_level"] == "not_evaluated"
    assert f["lead_count"] == 0
    assert f["review_priority"] == "none"
    assert f["findings"] == []
    assert "PEB not available" in console


# ── stomping ─────────────────────────────────────────────────────────────

def test_stomping_detected_tampered_content(monkeypatch, tmp_path):
    f, console = hunt_cases.stomping_detected_tampered_content(monkeypatch, tmp_path)
    assert set(f) == _STOMPING_KEYS
    assert f["score"] == 1
    assert f["max_score"] == 2
    assert f["status"] == "DETECTED"
    assert f["coverage_status"] == "complete"
    assert f["verdict_level"] == "possible"
    assert f["confidence"] == "medium"
    assert f["lead_count"] == 0
    assert len(f["verified_changes"]) == 1
    assert f["verified_changes"][0]["rip_in_changed_range"] is False
    assert "VERIFIED MODULE CODE MODIFICATION" in console


def test_stomping_clean_matching_reference(monkeypatch, tmp_path):
    f, console = hunt_cases.stomping_clean_matching_reference(monkeypatch, tmp_path)
    assert set(f) == _STOMPING_KEYS
    assert f["score"] == 0
    assert f["status"] == "NOT_DETECTED_IN_SCANNED_SCOPE"
    assert f["coverage_status"] == "complete"


def test_stomping_inconclusive_no_ref_dir(monkeypatch):
    f, console = hunt_cases.stomping_inconclusive_no_ref_dir(monkeypatch)
    assert set(f) == _STOMPING_KEYS
    assert f["score"] == 0
    assert f["status"] == "INCONCLUSIVE"
    assert f["coverage_status"] == "partial"
    assert any("ref-dir not supplied" in r for r in f["coverage_reasons"])


# ── pipe ─────────────────────────────────────────────────────────────────

def test_pipe_detected_full_corroboration(monkeypatch):
    f, console = hunt_cases.pipe_detected_full_corroboration(monkeypatch)
    assert set(f) == _PIPE_KEYS
    assert f["score"] == 3
    assert f["max_score"] == 3
    assert f["status"] == "DETECTED"
    assert f["coverage_status"] == "partial"
    assert f["verdict_level"] == "high"
    assert f["confidence"] == "high"
    assert f["lead_count"] == 1
    assert "HIGH CONFIDENCE C2 PIPE" in console

    # details fields: count + stable sub-fields, never the raw
    # Handle/Region/ThreadInfo objects' own identity (see module docstring).
    assert len(f["handle_pipes"]) == 1
    hp = f["handle_pipes"][0]
    assert hp["canonical_name"] == "msagent_1337"
    assert hp["framework_match"] == (
        "Cobalt Strike", "SMB Beacon peer-to-peer pipe — default msagent pipe name",
        "T1090.001")
    assert len(f["private_pipes"]) == 1
    pp = f["private_pipes"][0]
    assert pp["name"] == "\\.\\pipe\\msagent_1337"
    assert pp["encoding"] == "ascii"
    assert pp["truncated"] is False
    assert len(f["framework_pipes"]) == 1
    assert len(f["unbacked_in_rgn"]) == 1
    assert len(f["c2_context"]) == 1
    assert f["c2_context"][0][1] == "\\.\\pipe\\msagent_1337"
    assert [m["match"] for m in f["c2_context"][0][2]] == ["http://", "198.51.100.7:8080", "submit.php"]

    json.dumps(_json_safe(f))


# ── cs-beacon ────────────────────────────────────────────────────────────

def test_cs_beacon_detected(monkeypatch):
    f, console = hunt_cases.cs_beacon_detected(monkeypatch)
    assert set(f) == _CS_BEACON_KEYS
    assert f["score"] == 2
    assert f["max_score"] == 2
    assert f["status"] == "DETECTED"
    assert f["coverage_status"] == "complete"
    assert f["verdict_level"] == "high"
    assert f["confidence"] == "high"
    assert f["config_count"] == 1
    assert f["configs"][0]["xor_key"] == 0x69
    # Confirmed pre-migration shape: va/file_offset/region_base are plain
    # JSON ints today, NOT the fixed-16-hex-string format the v2.4 contract
    # requires (see docs/hunt_migration_field_matrix.md) -- pinned here so
    # PR2's conversion to hex strings is a visible, intentional diff.
    assert isinstance(f["configs"][0]["va"], int)
    assert isinstance(f["configs"][0]["file_offset"], int)
    assert all(isinstance(k, str) for k in f["configs"][0]["fields"].keys())
    assert isinstance(f["configs"][0]["fields"]["1"]["raw"], str)
    json.dumps(f)  # cs-beacon's dispatcher-level sanitization already makes this JSON-safe as-is


# ── yara ─────────────────────────────────────────────────────────────────
# Note: pytest.importorskip("yara") is scoped to test_yara_detected() only
# (see hunt_cases.yara_not_evaluated's own docstring for why the
# NOT_EVALUATED path never imports yara-python at all) -- an environment
# without the optional yara-python dependency installed must still run
# every other test in this file, including test_yara_not_evaluated.

def test_yara_not_evaluated(monkeypatch, tmp_path):
    f, console = hunt_cases.yara_not_evaluated(monkeypatch, tmp_path)
    assert set(f) == _YARA_NOT_EVALUATED_KEYS
    assert f["score"] == 0
    assert f["status"] == "NOT_EVALUATED"
    assert f["coverage_status"] == "not_evaluated"
    assert f["verdict_level"] == "not_evaluated"
    assert f["matches"] == []
    # Confirmed: YARA has no confidence/lead_count/review_priority/max_score
    # at all today -- matches the v2.4 contract's "YARA allowed null" rule.
    for absent in ("confidence", "lead_count", "review_priority", "max_score"):
        assert absent not in f


def test_yara_detected(tmp_path):
    pytest.importorskip("yara")
    f, console = hunt_cases.yara_detected(tmp_path)
    assert set(f) == _YARA_DETECTED_KEYS
    assert f["score"] == 1
    assert f["status"] == "DETECTED"
    assert f["coverage_status"] == "complete"
    assert f["verdict_level"] == "likely"
    assert f["rules_hit"] == ["HitRule"]
    assert len(f["matches"]) == 1
    for absent in ("confidence", "lead_count", "review_priority", "max_score"):
        assert absent not in f
    json.dumps(_json_safe(f))


# ── obfuscation ──────────────────────────────────────────────────────────

def test_obfuscation_detected_validated_pe(monkeypatch):
    f, console = hunt_cases.obfuscation_detected_validated_pe(monkeypatch)
    assert set(f) == _OBFUSCATION_KEYS
    assert f["score"] == 1
    assert f["max_score"] == 2
    assert f["status"] == "DETECTED"
    assert f["coverage_status"] == "complete"
    assert f["verdict_level"] == "likely"
    assert f["confidence"] == "high"
    assert f["lead_count"] == 0
    assert len(f["hidden_pe"]) == 1
    # obfuscation's Hit.to_dict() (encoding/models.py) converts the region
    # BY VALUE (BaseAddress/RegionSize/... as a plain dict) instead of
    # leaving a raw Region object for _json_safe's str(obj) fallback to
    # mangle -- but State/Protect/Type are deliberately left as whatever
    # enum-like object the caller passed in, for _json_safe to reduce to
    # .name at serialization time (see that module's own docstring), so
    # this still needs _json_safe, just never touches str(obj)-on-a-raw-
    # Region the way injection's rwx/threads/rip_hits do above.
    json.dumps(_json_safe(f))


# ── dispatcher-level: --hunt all order and count ────────────────────────

def test_hunt_all_produces_seven_entries_in_fixed_order():
    """A fully empty FakeMF (every stream None) -> all 7 hunters
    NOT_EVALUATED, but the dispatcher must still produce exactly 7 dict
    entries in a fixed key order -- this order is what PR2's `--hunt all`
    -> 7 `HunterRecord`s must preserve."""
    import dumpex.hunt as hunt
    from tests.fixtures.fakes import FakeMF

    results = hunt.cmd_hunt(FakeMF(), "all", verbose=False)
    assert list(results.keys()) == [
        "injection", "hollowing", "stomping", "pipe", "cs-beacon", "yara", "obfuscation"]
    assert all(v["status"] == "NOT_EVALUATED" for v in results.values())

"""
Unit tests for dumpex.hunt.yara_hunt.scanner.scan_segments's resource-budget
handling (match() timeout, whole-scan hit cap, per-match string-instance
cap) and for _hunt_yara's yara-python-missing early return.

Deliberately does NOT use pytest.importorskip("yara") anywhere in this
file, unlike the end-to-end tests in tests/hunt/test_yara_hunt.py and
tests/unit/test_yara_hunt.py (which need the real yara-python package to
actually compile a .yar file on disk). Every test here drives
scan_segments with a fake compiled-rule object standing in for a compiled
yara.Rules instance, and fake match objects standing in for yara.Match --
no real YARA engine involved anywhere, so these tests run identically
whether or not yara-python (an optional "full" dependency) happens to be
installed.
"""
import sys

from tests.fixtures.fakes import Segment, FakeReader, FakeMF

from dumpex.hunt.yara_hunt.scanner import scan_segments
from dumpex.hunt.yara_hunt.config import YaraConfig
from dumpex.hunt.yara_hunt import aggregate
from dumpex.hunt._ui import DETECTED, INCONCLUSIVE
import dumpex.hunt.yara_hunt as yara_hunt


class FakeTimeoutError(Exception):
    """Stands in for yara.TimeoutError. scanner.py classifies a match()
    failure as a timeout by checking whether "timeout" appears in the
    exception CLASS NAME (case-insensitive) -- not by catching
    yara.TimeoutError specifically -- precisely so this can be tested
    without the real yara-python package. See scanner.py's own comment on
    why it does this (yara-python's exact exception type isn't a stable
    contract across versions)."""


class FakeInstance:
    """Stands in for one yara.StringMatchInstance (yara-python >= 4.3)."""
    def __init__(self, offset, matched_data=b"X"):
        self.offset = offset
        self.matched_data = matched_data


class FakeStringMatch:
    """Stands in for one yara.StringMatch (yara-python >= 4.3): an
    identifier plus every instance where that string matched. This is the
    branch scanner.py takes when hasattr(s, 'instances') is True."""
    def __init__(self, identifier, instances):
        self.identifier = identifier
        self.instances = instances


class FakeMatch:
    """Stands in for one yara.Match object -- everything scanner.py reads
    off a match (.rule, .tags, .meta, .strings)."""
    def __init__(self, rule, tags=None, meta=None, strings=None):
        self.rule = rule
        self.tags = tags if tags is not None else []
        self.meta = meta if meta is not None else {}
        self.strings = strings if strings is not None else []


class FakeCompiled:
    """Stands in for one compiled yara.Rules object. Returns `results`
    (a list of FakeMatch) on every match() call, or raises `exc` on every
    call instead if given."""
    def __init__(self, results=None, exc=None):
        self._results = results if results is not None else []
        self._exc = exc
        self.call_count = 0

    def match(self, data, timeout):
        self.call_count += 1
        if self._exc is not None:
            raise self._exc
        return self._results


def _mf_with_segment(seg_va, seg_fo, data):
    seg = Segment(seg_va, seg_fo, len(data))
    mf = FakeMF()
    mf._reader = FakeReader({seg_va: data})
    return mf, seg


# ── match() timeout: a coverage gap, not a silent "ran, no match" ────────

def test_match_timeout_marks_partial_and_inconclusive():
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0x1000, 0x100, data)
    compiled = FakeCompiled(exc=FakeTimeoutError("simulated yara timeout"))
    config = YaraConfig()

    outcome = scan_segments(mf, [seg], [("good.yar", compiled)], modules=[], regions=[],
                             modules_available=False, mem_info_available=False, config=config)

    assert outcome.timed_out == 1
    assert outcome.match_failed == 0
    assert outcome.all_hits == []

    coverage = aggregate.build_coverage(outcome, compile_failed=0)
    assert coverage["matches_completed"] is False

    report = aggregate.build_report(outcome, compile_failed=0)
    assert report.findings["status"] == INCONCLUSIVE
    assert report.findings["coverage_status"] == "partial"
    assert "timed out" in report.verdict_reason


# ── a confirmed hit must not be erased by a LATER rule file timing out ───

def test_detected_hit_survives_later_timeout():
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0x2000, 0x200, data)
    hit_compiled     = FakeCompiled(results=[FakeMatch("HitRule")])
    timeout_compiled = FakeCompiled(exc=FakeTimeoutError("simulated yara timeout"))
    config = YaraConfig()

    outcome = scan_segments(mf, [seg],
                             [("hit.yar", hit_compiled), ("slow.yar", timeout_compiled)],
                             modules=[], regions=[], modules_available=False,
                             mem_info_available=False, config=config)

    assert outcome.timed_out == 1
    assert "HitRule" in outcome.triggered_rules
    assert len(outcome.all_hits) == 1

    report = aggregate.build_report(outcome, compile_failed=0)
    assert report.findings["status"] == DETECTED
    assert report.findings["coverage_status"] == "partial"
    assert "HitRule" in report.findings["rules_hit"]


# ── whole-scan hit cap truncates collection rather than growing unbounded ─

def test_total_hit_cap_marks_scan_truncated():
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0x3000, 0x300, data)
    matches = [FakeMatch("CapRule") for _ in range(5)]
    compiled = FakeCompiled(results=matches)
    config = YaraConfig(max_total_hits=2)

    outcome = scan_segments(mf, [seg], [("cap.yar", compiled)], modules=[], regions=[],
                             modules_available=False, mem_info_available=False, config=config)

    assert outcome.truncated is True
    assert len(outcome.all_hits) == 2   # never more than the configured cap

    coverage = aggregate.build_coverage(outcome, compile_failed=0)
    assert coverage["hit_cap_not_reached"] is False

    report = aggregate.build_report(outcome, compile_failed=0)
    assert report.findings["coverage_status"] == "partial"


# ── per-match string-instance cap ─────────────────────────────────────────

def test_string_instance_cap():
    data = b'\x00' * 0x100
    mf, seg = _mf_with_segment(0x4000, 0x400, data)
    instances = [FakeInstance(offset=i * 4, matched_data=b"AA") for i in range(10)]
    match = FakeMatch("StringyRule", strings=[FakeStringMatch("$a", instances)])
    compiled = FakeCompiled(results=[match])
    config = YaraConfig(max_strings_per_match=3)

    outcome = scan_segments(mf, [seg], [("stringy.yar", compiled)], modules=[], regions=[],
                             modules_available=False, mem_info_available=False, config=config)

    assert len(outcome.all_hits) == 1
    annotated = outcome.all_hits[0]["strings"]
    assert len(annotated) == 3   # capped, not all 10 instances
    assert annotated[0]["offset"] == 0
    assert annotated[0]["va"] == seg.start_virtual_address
    assert annotated[0]["fo"] == seg.start_file_address
    assert annotated[2]["offset"] == 8
    assert annotated[2]["va"] == seg.start_virtual_address + 8


# ── yara-python missing: NOT_EVALUATED, prior provenance cleared ─────────
# Uses sys.modules['yara'] = None to force `import yara` to raise
# ImportError (standard import-system behavior for a None sentinel) --
# this works identically whether or not yara-python is actually
# installed in the environment running this test, so no
# pytest.importorskip is needed (or wanted) here.

def test_yara_missing_returns_not_evaluated(monkeypatch, capsys):
    yara_hunt._LAST_YARA_PROVENANCE = {"rules_dir": "stale", "files": []}
    monkeypatch.setitem(sys.modules, "yara", None)

    f = yara_hunt._hunt_yara(FakeMF(), rules_dir="/does_not_matter", verbose=False)

    assert f["status"] == "NOT_EVALUATED"
    assert f["coverage_status"] == "not_evaluated"
    assert f["verdict_level"] == "not_evaluated"
    assert f["score"] == 0
    assert yara_hunt.get_yara_provenance() is None

    out = capsys.readouterr().out
    assert "yara-python is not installed" in out

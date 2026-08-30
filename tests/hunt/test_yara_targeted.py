"""Targeted YARA rescan adapter (dumpex.hunt.yara_hunt.targeted).

One targeted invocation matches every compiled rule against a single requested
virtual-address range, resolved to a slice of the captured segment containing
its base. Hit addresses and dump-file offsets stay absolute; a match is judged
where it actually sits rather than by where the range begins; only
YARA_MAX_SEG_SCAN is bypassed and every other budget stays enforced; a budget
stop names a target never narrower than the work it left undone.

Needs the real yara-python package to actually compile a rule file -- it's an
optional ("full") dependency, so this whole module is skipped when absent.
"""
import os
import tempfile

import pytest

pytest.importorskip("yara")

from dumpex.core.va_range import CaptureState, VirtualRange
from dumpex.hunt._execution import build_execution_context
from dumpex.hunt._observation import ObservationResult
from dumpex.hunt._request import HuntRequest
from dumpex.output.coverage import LimitationCode

import dumpex.hunt.yara_hunt as yara_hunt
import dumpex.hunt.yara_hunt.targeted as targeted

from tests.fixtures.fakes import FakeMF, FakeReader, FakeStream, Module, Region, Segment

_SEG_VA = 0x10000000
_SEG_FO = 0x4000
_MARKER = b"targeted_marker_zz"


@pytest.fixture
def rules_dir():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "marker.yar"), "w") as fh:
            fh.write('rule Marker { strings: $a = "%s" condition: $a }'
                     % _MARKER.decode())
        yield d


def _mf(segments, read_map):
    class MF(FakeMF):
        memory_segments_64 = FakeStream(list(segments), "memory_segments")
        _reader = FakeReader(dict(read_map))
    return MF()


def _run(mf, requested, *, rules_dir=None):
    request = HuntRequest.targeted("yara", "segment_scan", requested,
                                   rules_dir=rules_dir)
    ctx = build_execution_context(mf, request)
    return ctx, targeted.run_targeted_yara(ctx)


def _one(result):
    assert len(result.closures) == 1
    return result.closures[0]


# ── request validation ──────────────────────────────────────────────────

def test_a_full_scope_request_is_refused_before_any_read():
    ctx = build_execution_context(_mf([], {}), HuntRequest.full("yara"))
    with pytest.raises(targeted.TargetedYaraError):
        targeted.run_targeted_yara(ctx)


def test_another_analyzers_targeted_request_is_refused():
    request = HuntRequest.targeted("cs-beacon", "segment_scan",
                                   VirtualRange(_SEG_VA, 0x1000))
    ctx = build_execution_context(_mf([], {}), request)
    with pytest.raises(targeted.TargetedYaraError):
        targeted.run_targeted_yara(ctx)


# ── structure, provenance, and absolute addresses ───────────────────────

def test_slice_scan_reports_absolute_hit_addresses_and_file_offsets(rules_dir):
    size = 0x2000
    data = bytearray(b"\x00" * size)
    data[0x1200:0x1200 + len(_MARKER)] = _MARKER
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: bytes(data)})

    # Request the second half only: the marker sits 0x200 bytes into it.
    requested = VirtualRange(_SEG_VA + 0x1000, 0x1000)
    ctx, result = _run(mf, requested, rules_dir=rules_dir)

    assert isinstance(result, ObservationResult)
    assert result.key.analyzer == "yara" and result.key.is_targeted
    assert result.key.requested_range == requested

    matches = result.payload.matches
    assert matches, "the marker inside the requested slice produced no match"
    m = matches[0]
    assert m.rule == "Marker"
    # The slice's own identity, not the whole segment's.
    assert m.seg_va == _SEG_VA + 0x1000
    assert m.seg_fo == _SEG_FO + 0x1000
    assert m.seg_size == 0x1000
    string = m.strings[0]
    assert string.offset == 0x200
    assert string.va == _SEG_VA + 0x1200
    assert string.fo == _SEG_FO + 0x1200


class _OverServingReader:
    """A reader that ignores the requested size and hands back everything it
    holds from `addr` on -- models a reader over-serving past the extent of the
    unit being scanned."""

    def __init__(self, base, data):
        self._base, self._data = base, data

    def read(self, addr, size):
        off = addr - self._base
        return self._data[off:] if 0 <= off < len(self._data) else b""


def test_a_match_past_the_requested_range_is_never_returned(rules_dir):
    # The marker sits beyond the end of the requested slice. Even handed more
    # bytes than it asked for, the scan must not match on them: evidence
    # outside the requested range is not this closure's to report, and a
    # `complete` closure carrying it would be actively false.
    size = 0x2000
    data = bytearray(b"\x00" * size)
    data[0x1100:0x1100 + len(_MARKER)] = _MARKER

    class MF(FakeMF):
        memory_segments_64 = FakeStream([Segment(_SEG_VA, _SEG_FO, size)], "memory_segments")
        _reader = _OverServingReader(_SEG_VA, bytes(data))

    requested = VirtualRange(_SEG_VA, 0x1000)
    ctx, result = _run(MF(), requested, rules_dir=rules_dir)

    closure = _one(result)
    assert result.payload.matches == ()
    assert result.payload.diagnostics.total_bytes_scanned == 0x1000
    assert closure.coverage_status == "complete"
    assert closure.read_slice.read_bytes == 0x1000


def test_fully_captured_slice_with_no_match_is_complete_and_clean(rules_dir):
    size = 0x2000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: b"\x00" * size})
    ctx, result = _run(mf, VirtualRange(_SEG_VA, size), rules_dir=rules_dir)

    closure = _one(result)
    assert closure.source == "segment_scan" and closure.scope is None
    assert closure.capture_state == CaptureState.COMPLETE
    assert closure.coverage_status == "complete"
    assert closure.limitations == ()
    assert closure.read_slice.read_bytes == size


def test_rules_provenance_reaches_the_payload(rules_dir):
    size = 0x1000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: b"\x00" * size})
    ctx, result = _run(mf, VirtualRange(_SEG_VA, size), rules_dir=rules_dir)

    rules = result.payload.rules
    assert rules.rules_dir == rules_dir
    assert rules.compiled_ok == 1
    assert rules.provenance is not None
    assert [f.name for f in rules.provenance.files] == ["marker.yar"]


# ── the bypassed cap, and the ones that stay ────────────────────────────

def test_oversized_slice_is_scanned_where_full_scope_would_skip_it(monkeypatch, rules_dir):
    size = 0x2000
    data = bytearray(b"\x00" * size)
    data[0x40:0x40 + len(_MARKER)] = _MARKER
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: bytes(data)})
    # Full-scope this segment is far over the cap and would be skipped outright.
    monkeypatch.setattr(yara_hunt, "YARA_MAX_SEG_SCAN", 0x100)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size), rules_dir=rules_dir)

    closure = _one(result)
    assert closure.coverage_status == "complete"
    assert not [l for l in closure.limitations
                if l.code == LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED]
    assert result.payload.matches


def test_total_byte_budget_still_stops_the_slice_and_names_it(monkeypatch, rules_dir):
    size = 0x2000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: b"\x00" * size})
    monkeypatch.setattr(yara_hunt, "YARA_MAX_TOTAL_BYTES_SCANNED", 0x10)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size), rules_dir=rules_dir)

    closure = _one(result)
    # The bytes never reached a match() call, so this is not a clean negative.
    assert closure.coverage_status == "not_evaluated"
    budget = [l for l in closure.limitations
              if l.code == LimitationCode.YARA_SCAN_BUDGET_EXHAUSTED]
    assert budget and budget[0].scope == "max_total_bytes_scanned"
    # The whole request is still unexamined, named exactly.
    target = budget[0].targets[0]
    assert (target.base_address, target.size) == (_SEG_VA, size)


def test_scan_deadline_still_stops_the_slice(monkeypatch, rules_dir):
    size = 0x2000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: b"\x00" * size})
    # Already expired before the scan starts.
    monkeypatch.setattr(yara_hunt, "YARA_SCAN_DEADLINE_SECONDS", -1)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size), rules_dir=rules_dir)

    closure = _one(result)
    assert closure.coverage_status == "not_evaluated"
    budget = [l for l in closure.limitations
              if l.code == LimitationCode.YARA_SCAN_BUDGET_EXHAUSTED]
    assert budget and budget[0].scope == "scan_deadline_seconds"


class _RaisingRule:
    """A compiled-rule stand-in whose match() raises -- the scanner classifies
    the failure by the exception's own type name."""

    def __init__(self, exc):
        self._exc = exc

    def match(self, data=None, timeout=None):
        raise self._exc


def _fake_rules(monkeypatch, exc):
    diagnostics = yara_hunt.RulesDiagnostics(
        yara_available=True, rules_dir="/fake", attempted=True, compiled_ok=1)
    monkeypatch.setattr(
        yara_hunt, "_resolve_rule_files",
        lambda rules_dir=None: ([("fake.yar", _RaisingRule(exc))], diagnostics))


def test_a_match_timeout_is_retained_as_its_own_limitation(monkeypatch):
    class TimeoutError_(Exception):
        pass
    TimeoutError_.__name__ = "TimeoutError"

    size = 0x1000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: b"\x00" * size})
    _fake_rules(monkeypatch, TimeoutError_("too slow"))

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    closure = _one(result)
    assert closure.coverage_status == "partial"
    assert LimitationCode.YARA_MATCH_TIMED_OUT in {l.code for l in closure.limitations}


def test_a_failed_match_call_is_retained_as_its_own_limitation(monkeypatch):
    size = 0x1000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: b"\x00" * size})
    _fake_rules(monkeypatch, ValueError("broken rule"))

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size))

    closure = _one(result)
    assert closure.coverage_status == "partial"
    assert LimitationCode.YARA_MATCH_FAILED in {l.code for l in closure.limitations}


def test_hits_none_of_which_could_be_classified_keep_the_slice_partial():
    # A scoped rule whose hit cannot be context-classified at all (no ModuleList
    # and no MemoryInfoListStream): the negative around it is not trustworthy,
    # so coverage is partial and the gap counts distinct RULES, as full-scope
    # does -- never the raw hit count.
    size = 0x2000
    data = bytearray(b"\x00" * size)
    data[0x40:0x40 + len(_MARKER)] = _MARKER
    data[0x400:0x400 + len(_MARKER)] = _MARKER   # two hits, one rule
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: bytes(data)})

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "pe.yar"), "w") as fh:
            fh.write('rule PE_In_Private_Memory { strings: $a = "%s" condition: $a }'
                     % _MARKER.decode())
        ctx, result = _run(mf, VirtualRange(_SEG_VA, size), rules_dir=d)
        full = yara_hunt._build_yara_report(mf, rules_dir=d)

    closure = _one(result)
    assert result.payload.matches, "the scoped rule did not match"
    assert all(m.context_unverified for m in result.payload.matches)
    assert closure.coverage_status == "partial"
    assert closure.coverage_status == full.coverage_status
    unverified = [l for l in closure.limitations
                  if l.code == LimitationCode.YARA_MATCH_CONTEXT_UNVERIFIED]
    # One distinct rule, not two hits -- the same unit full-scope reports.
    assert unverified and unverified[0].affected_count == 1
    assert unverified[0].affected_count == len(full.unverified_rules)


def _scoped_rule(directory):
    with open(os.path.join(directory, "scoped.yar"), "w") as fh:
        fh.write('rule Scoped { meta: dumpex_scope = "private_or_unbacked" '
                 'strings: $a = "%s" condition: $a }' % _MARKER.decode())


def _two_region_mf(data, size):
    """A slice spanning a module-backed image region and a private one."""
    regions = [
        Region(_SEG_VA, _SEG_VA, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE"),
        Region(_SEG_VA + 0x1000, _SEG_VA + 0x1000, 0x1000,
               "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
    ]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([Segment(_SEG_VA, _SEG_FO, size)], "memory_segments")
        memory_info = FakeStream(regions, "infos")
        modules = FakeStream(
            [Module(_SEG_VA, 0x1000, r"C:\Windows\System32\ntdll.dll")], "modules")
        _reader = FakeReader({_SEG_VA: bytes(data)})
    return MF()


def test_a_private_memory_hit_survives_an_image_region_at_the_range_start():
    # The requested range starts in a module-backed image region and the scoped
    # rule matches in the PRIVATE region later in it. The match is judged where
    # it actually sits, so the hit is REPORTED with its real address -- not
    # discarded on the strength of where the range happens to begin.
    size = 0x2000
    data = bytearray(b"\x00" * size)
    data[0x1400:0x1400 + len(_MARKER)] = _MARKER

    with tempfile.TemporaryDirectory() as d:
        _scoped_rule(d)
        ctx, result = _run(_two_region_mf(data, size), VirtualRange(_SEG_VA, size),
                           rules_dir=d)

    closure = _one(result)
    assert result.payload.diagnostics.suppressed_scoped == 0
    assert len(result.payload.matches) == 1
    match = result.payload.matches[0]
    assert match.rule == "Scoped"
    assert match.memory_context == "private"
    assert match.context_unverified is False
    assert match.strings[0].va == _SEG_VA + 0x1400
    assert match.strings[0].fo == _SEG_FO + 0x1400
    assert closure.coverage_status == "complete"


def test_memory_context_and_backing_module_name_the_same_address():
    # The rule matches in BOTH regions. The classification survives at the
    # private instance, so the backing-module lookup must be anchored there
    # too: one match cannot report private memory and a containing module at
    # the same time.
    size = 0x2000
    data = bytearray(b"\x00" * size)
    data[0x100:0x100 + len(_MARKER)] = _MARKER      # inside the loaded module
    data[0x1400:0x1400 + len(_MARKER)] = _MARKER    # in private memory

    with tempfile.TemporaryDirectory() as d:
        _scoped_rule(d)
        ctx, result = _run(_two_region_mf(data, size), VirtualRange(_SEG_VA, size),
                           rules_dir=d)

    match = result.payload.matches[0]
    assert [hex(s.va) for s in match.strings] == [hex(_SEG_VA + 0x100),
                                                  hex(_SEG_VA + 0x1400)]
    assert match.memory_context == "private"
    assert match.backing_module is None


def test_a_hit_wholly_inside_the_image_region_is_still_suppressed():
    # The counterpart: judged at its real address the match IS module-backed,
    # so the scoped rule's own suppression still applies and no noise reaches
    # the payload.
    size = 0x2000
    data = bytearray(b"\x00" * size)
    data[0x400:0x400 + len(_MARKER)] = _MARKER

    with tempfile.TemporaryDirectory() as d:
        _scoped_rule(d)
        ctx, result = _run(_two_region_mf(data, size), VirtualRange(_SEG_VA, size),
                           rules_dir=d)

    assert result.payload.matches == ()
    assert result.payload.diagnostics.suppressed_scoped == 1


def _run_with_repeated_marker(image_half):
    """Fill the image half with non-overlapping copies of the marker (stride
    wider than the needle, so every copy survives intact) and return
    `(planted, classifier_calls, result)`.

    The classifier is saved and restored around the run rather than left to
    `monkeypatch`, so two calls in one test each count their OWN classifier
    calls instead of the second spy chaining onto the first.
    """
    size = image_half * 2
    stride = 0x20
    assert stride > len(_MARKER)
    data = bytearray(b"\x00" * size)
    planted = 0
    for off in range(0, image_half - stride, stride):
        data[off:off + len(_MARKER)] = _MARKER
        planted += 1

    calls = []
    real = yara_hunt.context.classify_memory_context
    yara_hunt.context.classify_memory_context = (
        lambda addr, *a, **k: (calls.append(addr), real(addr, *a, **k))[1])
    try:
        with tempfile.TemporaryDirectory() as d:
            _scoped_rule(d)
            _, result = _run(_two_region_mf(data, size), VirtualRange(_SEG_VA, size),
                             rules_dir=d)
    finally:
        yara_hunt.context.classify_memory_context = real
    return planted, calls, result


def test_instance_classification_does_not_scale_with_instance_count():
    # Instance COUNT is attacker-controlled: a crafted buffer repeats the
    # needle as often as the range allows. Every instance here sits in the
    # image half, so the reduction cannot short-circuit on a confirmed-private
    # address -- the worst case. Classifier calls must stay at the cap, not
    # track the instance count.
    cap = yara_hunt.YARA_MAX_STRINGS_PER_MATCH
    small_planted, small_calls, _ = _run_with_repeated_marker(0x1000)
    large_planted, large_calls, _ = _run_with_repeated_marker(0x20000)

    assert large_planted > small_planted * 8, "fixture must scale the instance count"
    assert len(small_calls) == cap
    assert len(large_calls) == cap


def test_a_truncated_instance_list_downgrades_suppression_instead_of_discarding():
    # Every instance examined was module-backed, but the cap means the rest
    # were never looked at. Suppression is the one conclusion needing them all,
    # so the match is kept as unverifiable rather than discarded on evidence
    # that was never fully examined.
    planted, calls, result = _run_with_repeated_marker(0x1000)
    assert planted > yara_hunt.YARA_MAX_STRINGS_PER_MATCH

    assert len(result.payload.matches) == 1
    assert result.payload.matches[0].context_unverified is True
    assert result.payload.diagnostics.suppressed_scoped == 0
    assert _one(result).coverage_status == "partial"


def test_full_scope_match_context_anchoring_is_unchanged():
    # The per-instance policy is targeted-only: a whole-dump scan still judges
    # a hit at the segment base it reports the hit against.
    size = 0x2000
    data = bytearray(b"\x00" * size)
    data[0x1400:0x1400 + len(_MARKER)] = _MARKER
    mf = _two_region_mf(data, size)

    with tempfile.TemporaryDirectory() as d:
        _scoped_rule(d)
        report = yara_hunt._build_yara_report(mf, rules_dir=d)

    assert report.evidence.matches == ()
    assert report.coverage.scan.suppressed_scoped == 1


def test_hit_cap_still_bites_and_leaves_the_slice_partial(monkeypatch, rules_dir):
    size = 0x2000
    data = bytearray(b"\x00" * size)
    for i in range(4):
        off = 0x100 * (i + 1)
        data[off:off + len(_MARKER)] = _MARKER
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: bytes(data)})
    monkeypatch.setattr(yara_hunt, "YARA_MAX_TOTAL_HITS", 0)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size), rules_dir=rules_dir)

    closure = _one(result)
    assert closure.coverage_status == "partial"
    caps = [l for l in closure.limitations
            if l.code == LimitationCode.YARA_HIT_CAP_REACHED]
    assert caps and caps[0].scope == "max_total_hits"


# ── prerequisites and capture semantics ─────────────────────────────────

def test_a_rule_that_never_compiled_keeps_the_slice_partial():
    # One rule compiles, one does not: the compiled rule found nothing, but the
    # failed one was never applied to these bytes, so the closure must not
    # claim complete coverage -- exactly as full-scope does not.
    size = 0x2000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: b"\x00" * size})
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "good.yar"), "w") as fh:
            fh.write('rule Good { strings: $a = "zzz_nomatch" condition: $a }')
        with open(os.path.join(d, "bad.yar"), "w") as fh:
            fh.write("rule Bad { condition: this is not valid yara }")
        ctx, result = _run(mf, VirtualRange(_SEG_VA, size), rules_dir=d)
        full = yara_hunt._build_yara_report(mf, rules_dir=d)

    closure = _one(result)
    assert closure.coverage_status == "partial"
    assert closure.coverage_status == full.coverage_status
    assert LimitationCode.YARA_RULE_COMPILE_FAILED in {l.code for l in closure.limitations}


def test_every_rule_failing_to_compile_keeps_the_gap_and_the_provenance():
    size = 0x1000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: b"\x00" * size})
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "bad.yar"), "w") as fh:
            fh.write("rule Bad { condition: this is not valid yara }")
        ctx, result = _run(mf, VirtualRange(_SEG_VA, size), rules_dir=d)

    closure = _one(result)
    assert closure.coverage_status == "not_evaluated"
    compile_failed = [l for l in closure.limitations
                      if l.code == LimitationCode.YARA_RULE_COMPILE_FAILED]
    assert compile_failed and compile_failed[0].affected_count == 1
    # Which file, and that it was a COMPILE failure rather than an empty
    # directory, both survive.
    assert [f.name for f in result.payload.rules.provenance.files] == ["bad.yar"]
    assert any("failed to compile" in d for d in closure.diagnostics)


def test_missing_rule_files_is_not_evaluated_never_clean():
    size = 0x1000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: b"\x00" * size})
    with tempfile.TemporaryDirectory() as empty:
        ctx, result = _run(mf, VirtualRange(_SEG_VA, size), rules_dir=empty)
    closure = _one(result)
    assert closure.coverage_status == "not_evaluated"
    assert closure.read_slice is None
    assert any("no usable .yar/.yara files" in d for d in closure.diagnostics)


def test_address_outside_every_captured_segment_is_not_evaluated(rules_dir):
    mf = _mf([Segment(_SEG_VA, _SEG_FO, 0x1000)], {_SEG_VA: b"\x00" * 0x1000})
    ctx, result = _run(mf, VirtualRange(0x9EEE0000, 0x1000), rules_dir=rules_dir)

    closure = _one(result)
    assert closure.coverage_status == "not_evaluated"
    assert closure.capture_state == CaptureState.NONE
    assert any("no captured segment contains" in d for d in closure.diagnostics)


def test_short_read_is_partial_and_names_the_unexamined_suffix(rules_dir):
    size = 0x2000
    # The segment table claims 0x2000 bytes; the reader hands back 0x800.
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: b"\x00" * 0x800})
    ctx, result = _run(mf, VirtualRange(_SEG_VA, size), rules_dir=rules_dir)

    closure = _one(result)
    assert closure.capture_state == CaptureState.COMPLETE
    assert closure.coverage_status == "partial"
    assert LimitationCode.SCAN_REGION_SHORT_READ in {l.code for l in closure.limitations}
    assert closure.read_slice.read_bytes == 0x800
    assert closure.read_slice.unread_suffix == VirtualRange(_SEG_VA + 0x800, 0x1800)
    assert any("never reached a match() call" in d for d in closure.diagnostics)


def test_a_budget_stop_after_a_short_read_still_names_the_whole_evaluated_slice(
        monkeypatch, rules_dir):
    # The read came back short AND the hit cap fired over what was read. The
    # rules that did not finish across the read prefix are unresolved too, so
    # the budget gap must name the whole slice -- narrowing it to the unread
    # suffix would send a rescan past the bytes that actually stopped early.
    size = 0x2000
    data = bytearray(b"\x00" * 0x800)
    data[0x100:0x100 + len(_MARKER)] = _MARKER
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: bytes(data)})
    monkeypatch.setattr(yara_hunt, "YARA_MAX_TOTAL_HITS", 0)

    ctx, result = _run(mf, VirtualRange(_SEG_VA, size), rules_dir=rules_dir)

    closure = _one(result)
    caps = [l for l in closure.limitations
            if l.code == LimitationCode.YARA_HIT_CAP_REACHED]
    assert caps and [(t.base_address, t.size) for t in caps[0].targets] == [(_SEG_VA, size)]
    # The unread suffix is still disclosed, on the gap that actually owns it.
    short = [l for l in closure.limitations
             if l.code == LimitationCode.SCAN_REGION_SHORT_READ]
    assert short
    assert closure.read_slice.unread_suffix == VirtualRange(_SEG_VA + 0x800, 0x1800)


def test_range_past_the_segment_end_truncates_evaluation_but_not_capture(rules_dir):
    # Two adjacent segments back the whole request, but evaluation is anchored
    # to the one containing the base.
    segs = [Segment(_SEG_VA, _SEG_FO, 0x1000),
            Segment(_SEG_VA + 0x1000, _SEG_FO + 0x1000, 0x1000)]
    mf = _mf(segs, {_SEG_VA: b"\x00" * 0x2000})
    ctx, result = _run(mf, VirtualRange(_SEG_VA, 0x2000), rules_dir=rules_dir)

    closure = _one(result)
    assert closure.capture_state == CaptureState.COMPLETE
    assert closure.coverage_status == "partial"
    trunc = [l for l in closure.limitations
             if l.code == LimitationCode.SCAN_REGION_EVALUATION_TRUNCATED]
    assert trunc and trunc[0].targets[0].size == 0x2000
    assert any("clipped to containing segment end" in d for d in closure.diagnostics)


def test_sub_segment_request_names_the_containing_segment(rules_dir):
    size = 0x40000
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: b"\x00" * size})
    ctx, result = _run(mf, VirtualRange(_SEG_VA + 0x1000, 0x1000), rules_dir=rules_dir)

    closure = _one(result)
    assert closure.coverage_status == "complete"
    assert any("containing captured segment" in d for d in closure.diagnostics)
    assert result.payload.containing_segment.base_address == _SEG_VA
    assert result.payload.containing_segment.size == size


def test_partial_capture_is_partial_not_a_negative(rules_dir):
    mf = _mf([Segment(_SEG_VA, _SEG_FO, 0x800)], {_SEG_VA: b"\x00" * 0x800})
    ctx, result = _run(mf, VirtualRange(_SEG_VA, 0x2000), rules_dir=rules_dir)

    closure = _one(result)
    assert closure.capture_state == CaptureState.PARTIAL
    assert closure.coverage_status == "partial"


def test_overlapping_capture_makes_a_negative_non_authoritative(rules_dir):
    # Two segment entries place the same virtual address at two file offsets.
    segs = [Segment(_SEG_VA, _SEG_FO, 0x2000),
            Segment(_SEG_VA + 0x800, _SEG_FO + 0x9000, 0x800)]
    mf = _mf(segs, {_SEG_VA: b"\x00" * 0x2000})
    ctx, result = _run(mf, VirtualRange(_SEG_VA, 0x2000), rules_dir=rules_dir)

    closure = _one(result)
    assert closure.coverage_status == "partial"
    incomplete = [l for l in closure.limitations
                  if l.code == LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE]
    assert incomplete and incomplete[0].detail == "overlapping_capture"


# ── full-scope behaviour is untouched ───────────────────────────────────

def test_full_scope_records_a_reader_returning_nothing_usable_as_a_read_failure(rules_dir):
    # The read clamp is defensive, but it also means a reader handing back
    # something with no extent is dispositioned as a failed read rather than
    # escaping the scan loop as an unhandled error -- pinned on the full-scope
    # path, which the clamp also governs.
    class NoneReader:
        def read(self, addr, size):
            return None

    class MF(FakeMF):
        memory_segments_64 = FakeStream([Segment(_SEG_VA, _SEG_FO, 0x1000)], "memory_segments")
        _reader = NoneReader()

    report = yara_hunt._build_yara_report(MF(), rules_dir=rules_dir)
    assert report.coverage.scan.read_failed == 1
    assert report.coverage.scan.scanned == 0
    assert report.coverage_status != "complete"


def test_full_scope_still_skips_an_oversized_segment(monkeypatch, rules_dir):
    size = 0x2000
    data = bytearray(b"\x00" * size)
    data[0x40:0x40 + len(_MARKER)] = _MARKER
    mf = _mf([Segment(_SEG_VA, _SEG_FO, size)], {_SEG_VA: bytes(data)})
    monkeypatch.setattr(yara_hunt, "YARA_MAX_SEG_SCAN", 0x100)

    report = yara_hunt._build_yara_report(mf, rules_dir=rules_dir)
    assert report.coverage.scan.skipped_oversize == 1
    assert report.coverage.scan.scanned == 0

"""Targeted rescan evidence: applicability, retained measurements, and windowed
entropy.

A targeted result has to be actionable on its own. Three things make it so, and
each is pinned here:

* a source that declined the target says so as ``not_applicable`` with the gate
  that declined it, separately from a source that would have applied and could
  not -- and an inapplicable closure never drags a completed sibling down;
* a closure that completed without a hit still records what it did, so a
  negative is bounded rather than unexplained;
* entropy over a sparse range is measured in bounded windows, so a payload the
  whole-range average hides is located rather than lost.

The measurements are observations throughout: they create no finding, move no
score, and speak for no source other than the closure carrying them.
"""
import base64
import os

import pytest

from dumpex.core.va_range import CaptureState, VirtualRange
from dumpex.hunt._execution import build_execution_context
from dumpex.hunt._request import HuntRequest
from dumpex.hunt._targeted import CONTEXT_MEASUREMENT_NAMES
from dumpex.hunt._targeted_record import build_targeted_coverage, targeted_scope_records
from dumpex.hunt.encoding.config import EncodingConfig
from dumpex.hunt.encoding.entropy import scan_entropy_windows
from dumpex.output.coverage import CoverageStatus, LimitationCode

import dumpex.hunt.encoding.targeted as targeted

from tests.fixtures.fakes import (FakeStream, Region, Segment, build_pe_header,
                                  IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ)

_BASE = 0x10000000
_FILE_OFFSET = 0x2000


def _mf(regions, segments, modules=()):
    class MF:
        memory_info = FakeStream(regions, "infos")
        memory_segments_64 = FakeStream(segments, "memory_segments")
        memory_segments = None
    MF.modules = FakeStream(list(modules), "modules")
    return MF()


def _run(monkeypatch, data, *, region=None, size=None, captured=None, enc_override=None):
    """One obfuscation rescan over ``data``, mapped at ``_BASE``.

    ``size`` is the requested extent and ``captured`` how many of those bytes
    the dump backs; leaving ``captured`` unset backs the whole request, which
    keeps a short capture something a test has to ask for rather than something
    it can produce by accident."""
    size = len(data) if size is None else size
    captured = size if captured is None else captured
    region = region or Region(_BASE, _BASE, size, "MEM_COMMIT", "PAGE_READWRITE",
                              "MEM_PRIVATE")
    mf = _mf([region], [Segment(_BASE, _FILE_OFFSET, captured)])
    monkeypatch.setattr(
        targeted, "read_region_spanning",
        lambda _mf, addr, n: data[addr - _BASE:addr - _BASE + n])
    for name, value in (enc_override or {}).items():
        monkeypatch.setattr("dumpex.hunt.encoding." + name, value)
    request = HuntRequest.targeted("obfuscation", "encoding_scan",
                                   VirtualRange(_BASE, size))
    ctx = build_execution_context(mf, request)
    return ctx, targeted.run_targeted_encoding(ctx)


def _closures(result):
    return {closure.scope: closure for closure in result.closures}


def _measured(closure):
    """``{name: [values]}`` for one closure -- a list because a ranked list
    repeats its name."""
    out = {}
    for measurement in closure.measurements:
        out.setdefault(measurement.name, []).append(measurement)
    return out


def _sparse_with_payload(total=1 << 21, offset=0x40000, payload=0x20000):
    """A mostly-zero allocation with one bounded high-entropy payload inside
    it: the shape whose whole-range average sits far under the threshold while
    a window inside it sits far above."""
    buffer = bytearray(total)
    buffer[offset:offset + payload] = os.urandom(payload)
    return bytes(buffer), _BASE + offset


# ── windowed entropy ───────────────────────────────────────────────────

def test_a_sparse_range_hides_its_payload_from_the_whole_range_average():
    # The premise the window pass exists for. If this ever stopped holding,
    # windowing would be measuring nothing the average did not already say.
    data, _payload_va = _sparse_with_payload()
    config = EncodingConfig()
    measured = scan_entropy_windows(data, _BASE, config.entropy_private_threshold, config)

    assert measured.whole_range_entropy < config.entropy_private_threshold
    assert measured.max_window.entropy >= config.entropy_private_threshold


def test_windows_are_measured_exhaustively_and_ranked_by_value():
    data, payload_va = _sparse_with_payload()
    config = EncodingConfig()
    measured = scan_entropy_windows(data, _BASE, config.entropy_private_threshold, config)

    assert measured.exhaustive
    assert measured.windows_evaluated == measured.windows_total
    assert measured.windows_total == len(data) // config.entropy_window_size
    assert len(measured.top_windows) == config.entropy_top_windows
    values = [window.entropy for window in measured.top_windows]
    assert values == sorted(values, reverse=True)
    assert measured.max_window is measured.top_windows[0]
    # The maximum sits inside the payload, not merely somewhere in the range.
    assert payload_va <= measured.max_window.base_address < payload_va + 0x20000


def test_ranking_ties_break_on_address_so_the_same_bytes_rank_the_same_way():
    config = EncodingConfig(entropy_window_size=1024, entropy_max_windows=64,
                            entropy_top_windows=4)
    data = b"\x00" * (1024 * 8)
    measured = scan_entropy_windows(data, _BASE, 7.2, config)

    addresses = [window.base_address for window in measured.top_windows]
    assert addresses == sorted(addresses)
    assert scan_entropy_windows(data, _BASE, 7.2, config) == measured


def test_more_windows_than_the_cap_are_strided_across_the_whole_range():
    # A sampled pass must still span the range: truncating at the cap would
    # leave the tail unmeasured while reporting the same window count.
    config = EncodingConfig(entropy_window_size=256, entropy_max_windows=4,
                            entropy_top_windows=8)
    data = os.urandom(256 * 20)
    measured = scan_entropy_windows(data, _BASE, 7.2, config)

    assert not measured.exhaustive
    assert measured.windows_total == 20
    assert measured.windows_evaluated <= 4
    span = max(w.base_address for w in measured.top_windows) - _BASE
    assert span >= 256 * 12


def test_a_trailing_remainder_under_the_minimum_input_is_not_measured():
    config = EncodingConfig(entropy_window_size=1024, entropy_min_input=256)
    measured = scan_entropy_windows(b"\x00" * (1024 * 3 + 8), _BASE, 7.2, config)
    assert measured.windows_total == 3

    measured = scan_entropy_windows(b"\x00" * (1024 * 3 + 300), _BASE, 7.2, config)
    assert measured.windows_total == 4


def test_a_windowed_rescan_locates_the_sub_range_a_single_value_misses(monkeypatch):
    data, payload_va = _sparse_with_payload()
    _ctx, result = _run(monkeypatch, data)

    entropy = _closures(result)["entropy"]
    assert entropy.coverage_status == "complete"

    hits = result.payload.entropy.hits
    assert hits, "a sparse range with a high-entropy window produced no entropy hit"
    # Every retained hit is a bounded window, not the whole allocation: the
    # allocation's own average is under the threshold.
    assert all(hit.size == result.payload.windowed_entropy.window_size for hit in hits)
    assert any(payload_va <= hit.location.va < payload_va + 0x20000 for hit in hits)


def test_a_uniformly_high_entropy_range_still_reports_itself_not_its_parts(monkeypatch):
    # Full-scope parity: when the whole-range average clears the threshold, the
    # range is the hit. Reporting its windows instead would turn one lead into
    # five for the case that already worked.
    data = os.urandom(1 << 20)
    _ctx, result = _run(monkeypatch, data)

    hits = result.payload.entropy.hits
    assert len(hits) == 1
    assert hits[0].size is None
    assert hits[0].location.va == _BASE


def test_a_sampled_window_pass_cannot_close_the_entropy_layer(monkeypatch):
    # A window between two measured ones could hold a payload nobody looked at,
    # so the layer's negative is not a full-search negative.
    monkeypatch.setattr("dumpex.hunt.encoding.ENTROPY_MAX_WINDOWS", 2)
    monkeypatch.setattr("dumpex.hunt.encoding.ENTROPY_WINDOW_SIZE", 4096)
    _ctx, result = _run(monkeypatch, b"\x00" * (4096 * 16))

    entropy = _closures(result)["entropy"]
    assert entropy.coverage_status == "partial"
    details = {limitation.detail for limitation in entropy.limitations
               if limitation.code == LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE}
    assert "entropy_window_sampled" in details
    assert any("windows" in note for note in entropy.diagnostics)


# ── retained measurements on a completed no-hit closure ────────────────

def test_a_completed_no_hit_layer_still_records_what_it_measured(monkeypatch):
    _ctx, result = _run(monkeypatch, b"\x00" * (1 << 20))

    entropy = _closures(result)["entropy"]
    assert entropy.coverage_status == "complete"
    assert not result.payload.entropy.hits

    measured = _measured(entropy)
    assert measured["bytes_evaluated"][0].value == 1 << 20
    assert measured["entropy_windows_evaluated"][0].value > 0
    assert measured["entropy_window_coverage"][0].value == "exhaustive"
    assert measured["whole_range_entropy"][0].value == pytest.approx(0.0)
    assert measured["entropy_threshold"][0].value > 0
    assert measured["entropy_top_window"][0].base_address is not None


def test_a_no_hit_decode_layer_records_its_attempts_and_its_budget(monkeypatch):
    _ctx, result = _run(monkeypatch, b"\x00" * (1 << 16))

    measured = _measured(_closures(result)["decode"])
    assert measured["base64_retained"][0].value == 0
    assert measured["xor_retained"][0].value == 0
    assert measured["compressed_retained"][0].value == 0
    assert measured["xor_sublayer"][0].value == "applied"
    # Every resource the budget actually bounds is reported as consumption AND
    # limit -- including the decoded-output cap, which is otherwise a reason a
    # run can stop for with no number beside it.
    for resource in ("attempts", "decoded_bytes", "retained_bytes", "hits"):
        assert measured[f"budget_{resource}_limit"][0].value > 0
        assert measured[f"budget_{resource}_spent"][0].value >= 0
    assert measured["budget_exhausted_reason"][0].value is None


def test_a_retained_count_alone_cannot_say_how_much_was_tried(monkeypatch):
    """The question a bare `base64_retained` cannot answer: a range where
    nothing looked like a candidate and one where many were decoded and most
    were rejected are two different results an analyst acts on differently."""
    empty = b"\x00" * (1 << 16)
    # Long Base64-shaped runs, each decoding to distinct non-printable bytes:
    # the sub-layer decodes every one of them, and the classifier rejects most.
    decoys = b"".join(
        base64.b64encode(bytes((i * 7 + j) % 256 for j in range(96))) + b"\x00" * 8
        for i in range(24))

    _ctx, quiet = _run(monkeypatch, empty)
    _ctx, busy = _run(monkeypatch, decoys, size=len(decoys))

    quiet_measured = _measured(_closures(quiet)["decode"])
    busy_measured = _measured(_closures(busy)["decode"])

    # Nothing in the quiet range even resembled a candidate.
    assert quiet_measured["base64_candidates"][0].value == 0
    assert quiet_measured["base64_attempts"][0].value == 0
    assert quiet_measured["base64_retained"][0].value == 0

    # The busy range tried every one of them and kept a minority, which the
    # retained count on its own would have reported as a nearly clean result.
    candidates = busy_measured["base64_candidates"][0].value
    attempts = busy_measured["base64_attempts"][0].value
    retained = busy_measured["base64_retained"][0].value
    assert candidates == 24
    assert attempts == candidates
    assert retained < candidates


def test_each_decode_sub_layer_counts_its_own_work(monkeypatch):
    """One shared attempt total cannot stand in for three sub-layers: it is
    spent by all of them and by sleep-mask too."""
    _ctx, result = _run(monkeypatch, b"\x00" * (1 << 16))

    measured = _measured(_closures(result)["decode"])
    for name in ("base64_candidates", "base64_attempts", "xor_keys_scored",
                 "xor_text_candidates", "xor_structural_candidates", "xor_attempts",
                 "compressed_candidates", "compressed_attempts"):
        assert measured[name][0].value >= 0, name
    # The 255-key text sweep runs over any eligible private range and spends no
    # decode attempt, so it is visible work the attempt budget never shows.
    assert measured["xor_keys_scored"][0].value > 0


def test_a_layers_budget_measurements_are_its_own_spend_not_the_invocations(monkeypatch):
    """The shared budget is one mutable object all three layers spend from.
    Read after they have all run, it attributes the whole invocation's spend --
    and the last layer's exhaustion -- to every layer alike."""
    pe = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                           "rawptr": 0x400, "rawsize": 0x200,
                           "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                         size_of_image=0x2000, trailing_padding=0x300)
    blob = base64.b64encode(pe)
    data = blob.ljust(1 << 16, b"\x00")
    _ctx, result = _run(monkeypatch, data, size=len(data))

    closures = _closures(result)
    decode = _measured(closures["decode"])
    sleep_mask = _measured(closures["sleep_mask"])

    # Decode did the work: it decoded and retained a Base64-wrapped PE.
    assert decode["base64_retained"][0].value >= 1
    assert decode["budget_attempts_spent"][0].value >= 1
    assert decode["budget_hits_spent"][0].value >= 1
    assert decode["budget_decoded_bytes_spent"][0].value > 0

    # Sleep-mask ran first over the same bytes and spent none of it. Its own
    # measurements must say so rather than repeat decode's.
    assert sleep_mask["budget_attempts_spent"][0].value == 0
    assert sleep_mask["budget_hits_spent"][0].value == 0
    assert sleep_mask["budget_retained_bytes_spent"][0].value == 0


def test_a_layer_that_finished_inside_the_allowance_reports_no_exhaustion(monkeypatch):
    """A budget a LATER layer exhausts is not an earlier, completed layer's
    exhaustion reason."""
    data = b"".join(base64.b64encode(b"MEOW%03d" % i * 24) + b"\x00" * 16
                    for i in range(6))
    _ctx, result = _run(monkeypatch, data, size=len(data),
                        enc_override=dict(ENCODING_BUDGET_MAX_HITS=1))

    closures = _closures(result)
    assert closures["decode"].coverage_status == "partial"
    assert _measured(closures["decode"])["budget_exhausted_reason"][0].value == "max_hits"
    # Sleep-mask completed before the budget ran out and owns none of it.
    assert closures["sleep_mask"].coverage_status in ("complete", "partial")
    assert _measured(closures["sleep_mask"])["budget_exhausted_reason"][0].value is None


def test_an_inapplicable_layer_reports_no_execution_measurements(monkeypatch):
    """A layer whose gate declined the target ran no search, so it must not
    describe one -- an "exhaustive" window coverage and a "complete" candidate
    list beside a `not_applicable` closure contradict each other."""
    region = Region(_BASE, _BASE, 1 << 16, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE",
                    "MEM_PRIVATE")
    _ctx, result = _run(monkeypatch, b"\x00" * (1 << 16), region=region)

    sleep_mask = _closures(result)["sleep_mask"]
    assert sleep_mask.coverage_status == "not_applicable"
    measured = _measured(sleep_mask)
    assert measured["bytes_evaluated"][0].value == 0
    for name in ("sleep_mask_window_coverage", "sleep_mask_candidate_list",
                 "sleep_mask_keys_recovered", "budget_attempts_spent",
                 "budget_exhausted_reason"):
        assert name not in measured, name
    # The structural context still travels: where the range sits is true
    # whether or not this layer looked at it.
    assert measured["containing_region_protection"][0].value == "PAGE_EXECUTE_READWRITE"


def test_measurements_never_create_a_finding_or_a_score(monkeypatch):
    _ctx, result = _run(monkeypatch, b"\x00" * (1 << 16))
    context = build_execution_context(
        _mf([Region(_BASE, _BASE, 1 << 16, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")],
            [Segment(_BASE, _FILE_OFFSET, 1 << 16)]),
        HuntRequest.targeted("obfuscation", "encoding_scan",
                             VirtualRange(_BASE, 1 << 16)))
    report = targeted.project_targeted_report(context, result)

    assert all(closure.measurements for closure in result.closures)
    assert report.score == 0
    assert report.results == ()


def test_every_closure_carries_the_same_structural_target_context(monkeypatch):
    # One repeated fact, not three different ones: a closure read on its own is
    # still self-explanatory, and no two closures may disagree about where the
    # range sits.
    _ctx, result = _run(monkeypatch, b"\x00" * (1 << 16))

    per_closure = []
    for closure in result.closures:
        per_closure.append(tuple(
            (m.name, m.value, m.base_address, m.size) for m in closure.measurements
            if m.name in CONTEXT_MEASUREMENT_NAMES))
    assert len(set(per_closure)) == 1

    context = dict((m.name, m) for m in result.closures[0].measurements
                   if m.name in CONTEXT_MEASUREMENT_NAMES)
    assert context["containing_region"].base_address == f"0x{_BASE:016x}"
    assert context["containing_region_type"].value == "MEM_PRIVATE"
    assert context["containing_region_protection"].value == "PAGE_READWRITE"
    assert context["containing_module"].value is None
    assert context["capture_file_offset"].value == f"0x{_FILE_OFFSET:016x}"
    assert context["captured_bytes"].value == 1 << 16


def _names_emitted_by(builder):
    """The literal measurement names one context builder constructs, read off
    its own source. The builders take live dump objects, so calling them to
    enumerate a name list would mean building a dump per builder."""
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(builder)))
    names = []
    for node in ast.walk(tree):
        callee = getattr(node, "func", None)
        if not isinstance(node, ast.Call):
            continue
        if getattr(callee, "attr", None) == "_module_measurement" or \
                getattr(callee, "id", None) == "_module_measurement":
            # This one resolves its own name rather than taking it.
            names.append("containing_module")
        elif node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str):
            names.append(node.args[0].value)
    return names


def test_the_declared_context_names_are_exactly_what_the_builders_emit():
    """The console tells structural context from per-closure work by this set
    alone. A name the builders emit but the set omits is repeated on every
    closure of the default card; a name the set claims but no builder emits is
    a promise nothing keeps."""
    from dumpex.hunt import _targeted

    emitted = (set(_names_emitted_by(_targeted.region_context_measurements))
               | set(_names_emitted_by(_targeted.segment_context_measurements))
               | set(_names_emitted_by(_targeted._capture_context)))
    assert emitted == CONTEXT_MEASUREMENT_NAMES


# ── minimum input: whose shortness is it? ──────────────────────────────

def test_a_short_request_and_a_short_capture_are_different_answers(monkeypatch):
    """One minimum, two gates. A range the algorithm cannot be applied to is a
    property of the target and no capture of it would help; a range that clears
    the minimum but is only partly backed is a gap a re-collection closes. An
    analyst told the first reaches for a different address, one told the second
    reaches for a better dump, so the two must never collapse."""
    minimum = EncodingConfig().entropy_min_input

    _ctx, short_request = _run(monkeypatch, b"\x00" * (minimum - 1))
    _ctx, short_capture = _run(
        monkeypatch, b"\x00" * (minimum - 1), size=minimum * 8,
        captured=minimum - 1)

    asked = _closures(short_request)["entropy"]
    backed = _closures(short_capture)["entropy"]

    assert asked.coverage_status == "not_applicable"
    assert asked.applicability_reason == "range_below_source_minimum"
    assert asked.capture_state is CaptureState.COMPLETE   # nothing is missing

    assert backed.coverage_status == "not_evaluated"
    assert backed.applicability_reason is None
    assert backed.capture_state is CaptureState.PARTIAL
    # The number a re-collection has to beat survives either way.
    assert backed.captured_bytes == minimum - 1


def test_a_request_exactly_at_the_minimum_applies(monkeypatch):
    """The boundary is inclusive: the shortest range the algorithm can be
    applied to is one it applies to."""
    minimum = EncodingConfig().entropy_min_input
    _ctx, result = _run(monkeypatch, b"\x00" * minimum)

    entropy = _closures(result)["entropy"]
    assert entropy.coverage_status == "complete"
    assert entropy.applicability_reason is None


def test_the_extent_gate_is_the_targeted_executors_not_the_shared_scanners(monkeypatch):
    """Full scope accounts for a region under the minimum as an eligible item
    with a not-applicable disposition on its own ledger. That accounting is a
    different fact from a targeted closure's status, and moving the extent
    check into the shared scanner would silently drop such a region out of
    `eligible_total` for every full-scope run."""
    from dumpex.hunt.encoding.entropy import _scan_entropy, entropy_region_ineligible_reason

    minimum = EncodingConfig().entropy_min_input
    region = Region(_BASE, _BASE, minimum - 1, "MEM_COMMIT", "PAGE_READWRITE",
                    "MEM_PRIVATE")
    mf = _mf([region], [Segment(_BASE, _FILE_OFFSET, minimum - 1)])

    # The shared descriptor gate accepts it -- the extent is not its business.
    assert entropy_region_ineligible_reason(region, []) is None

    layer = _scan_entropy([region], [], mf, (),
                          lambda _mf, addr, n: b"\x00" * min(n, minimum - 1),
                          EncodingConfig())
    assert layer.coverage.eligible_total == 1
    assert layer.coverage.not_applicable == 1
    assert layer.coverage.reconciled


# ── applicability, end to end through the record ───────────────────────

def test_an_inapplicable_layer_reaches_the_record_with_its_reason(monkeypatch):
    region = Region(_BASE, _BASE, 1 << 16, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE",
                    "MEM_PRIVATE")
    ctx, result = _run(monkeypatch, b"\x00" * (1 << 16), region=region)

    entries = {entry.scope: entry for entry in
               targeted_scope_records(ctx.request, result)}
    assert entries["sleep_mask"].coverage_status == "not_applicable"
    assert entries["sleep_mask"].applicability_reason == "region_protection_ineligible"
    assert entries["entropy"].applicability_reason is None
    # Console and JSON read the same measurements off the same closure.
    assert entries["entropy"].measurements == _closures(result)["entropy"].measurements


def test_the_record_states_inapplicability_without_calling_it_a_gap(monkeypatch):
    region = Region(_BASE, _BASE, 1 << 16, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE",
                    "MEM_PRIVATE")
    _ctx, result = _run(monkeypatch, b"\x00" * (1 << 16), region=region)
    coverage = build_targeted_coverage(result, "obfuscation")

    assert coverage.status is CoverageStatus.COMPLETE
    applicable = [limitation for limitation in coverage.limitations
                  if limitation.code == LimitationCode.TARGETED_SOURCE_NOT_APPLICABLE]
    assert len(applicable) == 1
    assert applicable[0].source == "targeted_scan"
    assert applicable[0].scope == "sleep_mask"
    assert applicable[0].detail == "region_protection_ineligible"


@pytest.mark.parametrize("protection,mtype,layer,reason", [
    ("PAGE_EXECUTE_READWRITE", "MEM_PRIVATE", "sleep_mask",
     "region_protection_ineligible"),
    ("PAGE_READWRITE", "MEM_IMAGE", "entropy", "region_type_ineligible"),
])
def test_an_inapplicable_layer_leaves_its_siblings_alone(monkeypatch, protection,
                                                         mtype, layer, reason):
    region = Region(_BASE, _BASE, 1 << 16, "MEM_COMMIT", protection, mtype)
    _ctx, result = _run(monkeypatch, b"\x00" * (1 << 16), region=region)

    closures = _closures(result)
    assert closures[layer].coverage_status == "not_applicable"
    assert closures[layer].applicability_reason == reason
    assert closures["decode"].coverage_status == "complete"
    # And the sibling's own measurements are untouched by the neighbour's gate.
    assert _measured(closures["decode"])["bytes_evaluated"][0].value == 1 << 16

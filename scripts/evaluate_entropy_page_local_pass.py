"""Measurement harness for a candidate bounded page-local entropy pass.

This is an evaluation prototype, not a shipped feature: it is not imported
by `dumpex.hunt.encoding`, and it changes no production JSON output, score,
confidence, or verdict. It exists so the design it models can be measured
before anything is committed to production behaviour.

What it measures, and what the measurements support, is recorded in
docs/developer/hunt_entropy_full_scope_page_pass_evaluation.md. Run it
directly:

    python scripts/evaluate_entropy_page_local_pass.py

Design under evaluation
------------------------
The candidate pass reuses `_scan_entropy`'s own eligibility gate
(`entropy_region_ineligible_reason`) and its own already-read region bytes
(no second dump read), then measures VA-aligned, non-overlapping windows the
same way `scan_entropy_windows` does for a targeted rescan -- but across
every eligible region in one pass, under ONE shared whole-hunt budget
(pages, bytes, wall-clock) instead of `scan_entropy_targeted`'s per-request
`ENTROPY_MAX_WINDOWS` ceiling, which does not bound cumulative work across a
whole dump.

Two design choices this harness pins down rather than leaving as free
parameters:

  * A region whose whole-region average ALREADY reaches its threshold is
    never windowed here -- mirrors `scan_entropy_targeted`'s existing
    mutual-exclusivity rule ("a high-entropy range never reports both
    itself and its own parts"), and is strictly cheaper: an already-flagged
    region has nothing left for a page-local pass to add.
  * Regions are visited RWX MEM_PRIVATE first, in ascending address order,
    then (policy `all_eligible` only) every other entropy-eligible region
    the same way -- so a shared budget that runs out always drops the
    lowest-priority work first, deterministically.

Two eligibility-scope policies are compared:

  * `rwx_only`      -- only RWX `MEM_PRIVATE` regions ever get windowed.
  * `all_eligible`   -- every entropy-eligible region gets windowed,
                        RWX-prioritized first.
"""
import heapq
import json
import time
from dataclasses import dataclass, field

from dumpex.hunt.encoding.config import EncodingConfig, ENTROPY_TOP_WINDOWS
from dumpex.hunt.encoding.entropy import (
    _shannon_entropy, _window_spans, entropy_region_ineligible_reason,
    entropy_threshold_for, region_ref,
)
from dumpex.hunt.encoding.report_facts import _entropy_item_fact
from dumpex.hunt.encoding.report_record import _entropy_hit_dict

# `obfuscation.entropy_observation`'s own cap in
# `dumpex.hunt.encoding.aggregate` -- only this many per-item `facts`
# strings are rendered, plus one "... and N more" summary line. Retained
# observations past it cost `details.entropy` bytes but no fact string.
ENTROPY_EVIDENCE_LIMIT = 15

POLICIES = ("rwx_only", "all_eligible")

# Upper edges of the entropy bands every measured window is counted into.
# A distribution, not just a threshold crossing: "how close does benign
# content get to the bar" cannot be answered by counting only the windows
# that already cleared it.
ENTROPY_BANDS = (4.0, 6.0, 6.5, 7.2, 8.0)

# Large enough that no ENTROPY_SCAN_MAX-bounded region (10 MiB / 4 KiB =
# 2560 windows) ever hits it -- this harness's OWN shared budget is what
# bounds work across regions, not a per-region window cap.
_NO_PER_REGION_WINDOW_CAP = 10 ** 9


@dataclass
class _Budget:
    """One shared page/byte/time allowance across every region a run
    visits, charged per window rather than per region -- the resource
    the candidate design bounds cumulative work with.

    The page and byte allowances are deterministic: the same input always
    stops at the same window. The wall-clock deadline is NOT -- it stops
    wherever the machine happened to be. Because page order is fixed
    (see `run_page_local_pass`), every budget still yields a PREFIX of the
    same deterministic page sequence; only the time budget makes the
    prefix's LENGTH vary between runs."""
    max_pages: int
    max_bytes: int
    deadline_seconds: float
    pages_used: int = 0
    bytes_used: int = 0
    stopped_on_time: bool = False
    spent: bool = False
    _deadline_at: float = field(default=0.0, repr=False)

    def start(self):
        self._deadline_at = time.perf_counter() + self.deadline_seconds

    def take(self, n_bytes: int) -> bool:
        if self.spent:
            return False
        # Deadline first: a run that exhausts pages and time together
        # stopped on time too, and a consumer deciding whether the stop was
        # reproducible needs to know that.
        if time.perf_counter() >= self._deadline_at:
            self.stopped_on_time = True
            self.spent = True
            return False
        if self.pages_used >= self.max_pages:
            self.spent = True
            return False
        if self.bytes_used + n_bytes > self.max_bytes:
            # Latched rather than per-window: without this a window too
            # large for the remaining byte allowance would be skipped while
            # a smaller one later still fit, and the examined set would no
            # longer be a prefix of the page order.
            self.spent = True
            return False
        self.pages_used += 1
        self.bytes_used += n_bytes
        return True


@dataclass(frozen=True)
class PageObservation:
    base_address: int
    size: int
    entropy: float


class _TopN:
    """A bounded retention set, filled during the scan rather than
    gathered-then-truncated at the end.

    Peak memory is bounded by a constant in BOTH dimensions -- pages
    examined and regions scanned -- and each mode holds only what it reads:

        flat (per_region == 0)       n + 1
        per-region (per_region > 0)  n + per_region + n * per_region

    the global heap, the region currently being scanned, and -- in
    per-region mode only -- the reserved set of finished regions, capped at
    `n` regions. Flat mode's retained set comes entirely from the global
    heap, so it keeps one entry for the region in progress, which is all
    `regions_with_hits` needs, and no reserved set at all.

    Keeping one open heap per region instead would bound entries per region
    while letting the number of heaps grow with the region count, so a dump
    with thousands of eligible regions would hold thousands of them for a
    retained set that can never exceed `n`. Regions are scanned one at a
    time, so a region's candidates are folded into the reserved set as soon
    as the scan leaves it and its working heap is dropped.

    Ordering is the one `scan_entropy_windows` already uses -- descending
    entropy, ascending address."""

    def __init__(self, n: int, per_region: int = 0):
        self._n = n
        # 0 means one flat global heap. A positive value reserves that many
        # slots per region, so a single noisy region cannot evict every
        # observation from every other region -- a global cap alone is
        # deterministic but not unbiased, and the addresses it drops are the
        # thing an investigator would have extracted.
        self._per_region = per_region
        # min-heap entries are (entropy, -base_address, size, region_ref,
        # threshold). `-base_address` is unique per observation, so
        # comparison never reaches the two trailing payload fields.
        self._heap = []
        # The region currently being offered pages, and the reserved set of
        # regions already finished. Both bounded; neither grows with the
        # number of regions scanned.
        self._current_region = None
        self._current = []
        self._reserved = {}
        self._regions_with_hits = 0

    def _push(self, heap, entry, limit) -> None:
        if len(heap) < limit:
            heapq.heappush(heap, entry)
        else:
            heapq.heappushpop(heap, entry)

    @staticmethod
    def _rank(entries):
        """A region's standing: its best entry, in retention order.

        Entries already carry `-base_address`, so retention order -- higher
        entropy, then LOWER address -- is `(entropy, -base_address)` read
        straight off the entry. Negating the second field again here would
        rank the HIGHER address first on a tie, which pages of identical
        content (a maximal 8.0 page, a repeated buffer) produce readily."""
        return max(entries, key=lambda e: (e[0], e[1]))[:2]

    def _close_current_region(self) -> None:
        """Count the region just finished and drop its working heap.

        In per-region mode the region is also folded into the reserved set,
        which holds at most `n` regions -- no retained set of size `n` can
        represent more -- so a weaker region is evicted whole rather than
        accumulated. Flat mode reserves nothing: its retained set is the
        global heap, so ranking and evicting regions here would cost a
        `_rank()` and a weakest-region scan per region for a structure
        nothing reads.

        Called only from `offer()`, when the scan moves to a new region.
        Every read is pure: a read that advanced this state machine would
        make merely LOOKING at the retained set (a progress line, a debug
        print, a mid-scan snapshot) split one region into two and inflate
        `regions_with_hits` -- a trap laid for the next person to add
        instrumentation, not a property anyone would expect to have to
        check."""
        if not self._current:
            self._current_region = None
            return
        self._regions_with_hits += 1
        entries = self._current
        self._current = []
        self._current_region = None
        if self._per_region <= 0:
            return

        if len(self._reserved) < self._n:
            self._reserved[entries[0][3].base_address] = entries
            return
        weakest = min(self._reserved, key=lambda key: self._rank(self._reserved[key]))
        if self._rank(entries) > self._rank(self._reserved[weakest]):
            del self._reserved[weakest]
            self._reserved[entries[0][3].base_address] = entries

    def _region_entries(self) -> list:
        """Every region's entries, reserved plus the one being scanned.

        The in-progress region participates as a SNAPSHOT -- read, never
        closed -- so the result is the same whether this is called during
        the scan or after it."""
        entries = list(self._reserved.values())
        if self._current:
            entries.append(list(self._current))
        return entries

    def offer(self, entropy: float, base_address: int, size: int, ref, threshold: float) -> None:
        if self._n <= 0:
            return
        entry = (entropy, -base_address, size, ref, threshold)
        if ref.base_address != self._current_region:
            self._close_current_region()
            self._current_region = ref.base_address
        # One slot is enough to know the region produced a hit; `per_region`
        # slots are what a reservation needs.
        self._push(self._current, entry, max(self._per_region, 1))
        self._push(self._heap, entry, self._n)

    def __len__(self) -> int:
        return len(self._merged())

    def _merged(self) -> list:
        """The retained set, filled breadth-first.

        Every region that produced a hit gets its best observation before
        any region gets a second, then per-region depth, then whatever
        global capacity is left. Taking each region's full reservation
        first and truncating afterwards would re-apply global entropy order
        across regions and drop whole regions' reservations once
        `regions x per_region` exceeded `n` -- reintroducing exactly the
        bias the reservation exists to remove, silently.

        The guarantee is therefore: every region with a hit is represented
        while `regions_with_hits <= n`. Past that no retention set of size
        `n` can represent them all, and `regions_dropped_from_retention`
        reports how many go unrepresented.

        Pure: the region being scanned is read, not closed."""
        if self._per_region <= 0:
            return list(self._heap)

        by_region = sorted(
            (sorted(entries, key=lambda e: (-e[0], -e[1]))
             for entries in self._region_entries()),
            key=lambda entries: (-entries[0][0], -entries[0][1]))

        kept = {}
        for depth in range(self._per_region):
            for entries in by_region:
                if len(kept) >= self._n:
                    break
                if depth < len(entries):
                    kept[entries[depth][1]] = entries[depth]
            if len(kept) >= self._n:
                break
        for entry in sorted(self._heap, key=lambda e: (-e[0], -e[1])):
            if len(kept) >= self._n:
                break
            kept.setdefault(entry[1], entry)
        return sorted(kept.values(), key=lambda e: (-e[0], -e[1]))[:self._n]

    def regions_with_hits(self) -> int:
        """Regions that produced at least one hit, counting the one being
        scanned. Pure, like every other read here."""
        return self._regions_with_hits + (1 if self._current else 0)

    def regions_dropped_from_retention(self) -> int:
        """Regions that produced an above-threshold page and are not
        represented in the retained set at all. Non-zero means the cap is
        smaller than the number of regions with hits, so some region's
        addresses are absent rather than merely truncated."""
        return max(0, self.regions_with_hits() - self.distinct_regions())

    def _sorted(self) -> list:
        return sorted(self._merged(), key=lambda e: (-e[0], -e[1]))

    def distinct_regions(self) -> int:
        return len({entry[3].base_address for entry in self._merged()})

    def hits(self) -> list:
        """The retained set, materialized once. Everything a caller needs
        is derived from the returned list rather than by re-merging."""
        return [_HitShim(ref, entropy, threshold, -neg_addr, size)
                for entropy, neg_addr, size, ref, threshold in self._sorted()]

    def ordered(self) -> tuple:
        return observations_from(self.hits())

    def output_bytes(self) -> tuple:
        """`(details_entropy_bytes, facts_bytes)` for the retained set,
        built with the SAME projectors `--json` uses -- the CURRENT
        `report_record._entropy_hit_dict` (which carries a `window`
        sub-object for a bounded observation, the shape a page pass emits)
        and `report_facts._entropy_item_fact`, capped exactly as
        `obfuscation.entropy_observation` caps it.

        `report_legacy._entropy_hit_dict` is deliberately NOT used: it
        predates the `window` key and would understate a page-local
        observation by roughly a third."""
        return output_bytes_from(self.hits())


def observations_from(hits) -> tuple:
    """`PageObservation`s for an already-materialized retained set."""
    return tuple(PageObservation(hit.location.va, hit.size, hit.entropy) for hit in hits)


def output_bytes_from(hits) -> tuple:
    """`(details_entropy_bytes, facts_bytes)` for an already-materialized
    retained set, built with the SAME projectors `--json` uses -- the
    CURRENT `report_record._entropy_hit_dict` (which carries a `window`
    sub-object for a bounded observation, the shape a page pass emits) and
    `report_facts._entropy_item_fact`, capped exactly as
    `obfuscation.entropy_observation` caps it.

    `report_legacy._entropy_hit_dict` is deliberately NOT used: it predates
    the `window` key and would understate a page-local observation by
    roughly a third."""
    facts = [_entropy_item_fact(h, None) for h in hits[:ENTROPY_EVIDENCE_LIMIT]]
    if len(hits) > ENTROPY_EVIDENCE_LIMIT:
        facts.append(f"... and {len(hits) - ENTROPY_EVIDENCE_LIMIT} more")

    def _growth(items) -> int:
        # Over an EMPTY-array baseline, so a retention set that kept nothing
        # reports 0 growth rather than the two bytes an empty JSON array
        # happens to serialize to.
        return (len(json.dumps(items, separators=(",", ":")).encode("utf-8"))
                - len(json.dumps([], separators=(",", ":")).encode("utf-8")))

    return _growth([_entropy_hit_dict(h) for h in hits]), _growth(facts)


def record_delta(observations) -> dict:
    """How many bytes the given retained observations actually add to the
    hunter's whole `HunterRecord`, measured as a baseline/candidate
    difference through the real
    `aggregate.build_report` -> `report_record.project_hunter_record`
    pipeline.

    `observations` is the retention set's own metadata -- each entry
    carries its real `RegionRef`, address, size, entropy, and threshold --
    so the measurement reflects the actual set rather than a stand-in.
    Synthesizing N observations inside one region instead would both lose
    the per-observation differences that change the serialized size (region
    protection strings, address widths, entropy digits) and, once the
    retained set spans several small regions, fabricate addresses past the
    first region's end, which `Location` rejects outright.

    `details.entropy` and `findings[].facts` are only part of the cost: the
    FIRST observation also materializes an entire
    `obfuscation.entropy_observation` finding -- `inference`, `rationale`,
    `limitations`, `id`, `confidence`, `tag`, and the rest -- which alone is
    far larger than the per-observation arrays.

    Serialized compactly; the shipped `--json` writer uses `indent=2`, so
    real on-disk growth is larger still. This is a floor, not a ceiling.

    Returns the size delta together with the record's own triage-facing
    fields for both the empty baseline and the candidate. "Entropy is
    observation-only" is a claim about those fields, and a claim about
    fields is settled by reading them, not by noting that no production
    code changed.
    """
    from dataclasses import asdict

    from dumpex.hunt._location import Location
    from dumpex.hunt.encoding.aggregate import build_report
    from dumpex.hunt.encoding.models import EntropyHit
    from dumpex.hunt.encoding.report_record import project_hunter_record

    observations = tuple(observations)
    region_count = len({o.region.base_address for o in observations}) or 1
    shape = dict(memory_info_stream=True, region_count=region_count,
                 any_region_scanned=True)

    fields = ("score", "confidence", "verdict_level", "lead_count",
              "review_priority", "status")

    def _measure(entropy_hits):
        record = project_hunter_record(build_report((), entropy_hits, (), (), (), **shape))
        size = len(json.dumps(asdict(record), default=str,
                              separators=(",", ":")).encode("utf-8"))
        return size, {name: getattr(record, name) for name in fields}

    hits = tuple(
        EntropyHit(region=o.region,
                   location=Location(va=o.location.va, region_base=o.region.base_address,
                                     file_offset=None, region_size=o.region.size),
                   entropy=o.entropy, threshold=o.threshold, size=o.size)
        for o in observations)
    baseline_size, baseline_fields = _measure(())
    candidate_size, candidate_fields = _measure(hits)
    return {
        "growth_bytes": candidate_size - baseline_size,
        "baseline": baseline_fields,
        "candidate": candidate_fields,
        "moved": {name: (baseline_fields[name], candidate_fields[name])
                  for name in fields if baseline_fields[name] != candidate_fields[name]},
    }


def record_growth_bytes(observations) -> int:
    """Just the size half of `record_delta()`."""
    return record_delta(observations)["growth_bytes"]


class _Loc:
    def __init__(self, va: int):
        self.va = va


class _HitShim:
    """The read surface `report_record._entropy_hit_dict` and
    `report_facts._entropy_item_fact` take off an `EntropyHit` -- enough to
    project one, without building the validated `Location` a real
    `EntropyHit` would also require. `size` is always set here: every
    observation a page pass retains is a bounded window, which is exactly
    the case that adds the `window` key to the projected dict and
    `window_size=` to the fact string."""

    def __init__(self, region, entropy: float, threshold: float, va: int, size: int):
        self.region = region
        self.entropy = entropy
        self.threshold = threshold
        self.location = _Loc(va)
        self.size = size

    @property
    def measured_size(self) -> int:
        return self.size


@dataclass(frozen=True)
class PagePassResult:
    policy: str
    regions_in_scope: int
    regions_gated_by_whole_region_hit: int
    regions_touched: int
    regions_partially_examined: int
    regions_unexamined: int
    # Regions in scope that produced no usable bytes at all, and regions
    # that produced fewer than they declared. A read failure makes the
    # region's page count UNKNOWN rather than zero, which is why it gets
    # its own counter instead of being folded into `pages_missed`.
    read_failed_regions: int
    short_read_regions: int
    short_read_unexamined_bytes: int
    # Eligible by protection and type, past the per-region size cap, so no
    # page of them is measured. Not a page gap that a bigger page budget
    # would close -- a size-cap gap, the one production already reports.
    oversized_regions: int
    oversized_bytes: int
    eligible_pages_in_scope: int
    pages_examined: int
    pages_missed: int
    pages_above_threshold: int
    # Above-threshold observations ONLY -- what would become retained
    # evidence. A window measured below its region's threshold is counted
    # (see `band_counts`) but never retained, matching what
    # `scan_entropy_targeted` already emits as an `EntropyHit`.
    retained_observations: tuple
    distinct_regions_retained: int
    # Regions that produced an above-threshold page and are absent from
    # the retained set entirely. Non-zero means the cap is smaller than
    # the number of regions with hits.
    regions_dropped_from_retention: int
    # The single highest window measured, above threshold or not: "measured
    # 512 windows, highest 3.9" and "did not measure" are different answers,
    # and only this field can tell them apart when nothing was retained.
    highest_window: "PageObservation | None"
    band_counts: tuple   # ((upper_edge, count), ...) over ENTROPY_BANDS
    exhaustive: bool
    stopped_on_time: bool
    elapsed_seconds: float
    # Marginal cost of the page pass: span computation, window
    # measurement, and the retention/projection finalization -- i.e.
    # everything production `_scan_entropy` does NOT already pay for.
    # Excludes the region read and whole-region average, which it does.
    window_seconds: float
    # What `record_growth_bytes()` cost to MEASURE the record growth --
    # two full build_report/project/serialize round trips that no scan,
    # production or candidate, would ever perform. Kept strictly out of
    # `elapsed_seconds` so a scan-cost figure never silently includes the
    # harness's own instrumentation.
    instrumentation_seconds: float
    bytes_read: int
    details_entropy_json_bytes: int   # `details.entropy` growth, current projector
    facts_json_bytes: int             # `findings[].facts` growth, capped as shipped
    # Whole-`HunterRecord` growth, including the entire finding the first
    # observation materializes -- the two arrays above are only part of it.
    record_growth_bytes: int
    # Triage-facing record fields that MOVE when these observations are
    # added, as {name: (baseline, candidate)}. Empty means the record's
    # verdict surface is untouched.
    record_fields_moved: dict


def run_page_local_pass(regions, modules, mf, susp_prots, read_region,
                        config: EncodingConfig, policy: str,
                        max_pages: int, max_bytes: int, deadline_seconds: float,
                        top_n: int = 64, per_region_top_n: int = 0) -> PagePassResult:
    """Run one candidate bounded full-scope page-local entropy pass.

    Page order is fixed for a given input: regions RWX-first then by
    ascending address, windows within a region by ascending address. Under
    the page and byte budgets the run is therefore fully deterministic --
    the same input stops at the same window and retains the same set. Under
    the wall-clock deadline it stops wherever the machine happened to be,
    so the retained set is a deterministic PREFIX of the same sequence
    whose length can vary between runs (`stopped_on_time` says when that
    happened).

    The walk visits every in-scope region even after the budget is spent:
    a spent budget stops window MEASUREMENT, not the region walk, so
    `eligible_pages_in_scope` and `pages_missed` describe the whole scope
    rather than only the part that was reached. In a real integration this
    costs nothing extra -- production `_scan_entropy` already reads and
    averages every eligible region on the same pass.
    """
    if policy not in POLICIES:
        raise ValueError(f"unknown policy: {policy!r}")
    start = time.perf_counter()
    budget = _Budget(max_pages, max_bytes, deadline_seconds)
    budget.start()

    # Building and ordering the priority list is work the page pass adds --
    # production `_scan_entropy` walks regions in stream order and sorts
    # nothing -- so it belongs inside the marginal-cost measurement.
    window_seconds = 0.0
    prioritize_start = time.perf_counter()
    prioritized = []
    oversized_regions = 0
    oversized_bytes = 0
    for r in regions:
        if entropy_region_ineligible_reason(r, modules) is not None:
            continue
        if r.RegionSize <= 0:
            continue
        ref = region_ref(r, susp_prots)
        if policy == "rwx_only" and not ref.is_rwx:
            continue
        if r.RegionSize > config.entropy_scan_max:
            # Past the size cap: eligible memory this pass does not look
            # at. Production `_scan_entropy` records the same region as an
            # explicit oversize skip; dropping it before any counter here
            # would report a clean page-level negative over memory nobody
            # examined -- the same shape as an unread region, one filter
            # earlier.
            oversized_regions += 1
            oversized_bytes += r.RegionSize
            continue
        prioritized.append((r, ref))
    prioritized.sort(key=lambda pair: (0 if pair[1].is_rwx else 1, pair[1].base_address))
    window_seconds += time.perf_counter() - prioritize_start

    # Counts only regions this pass could window. Oversized regions passed
    # every eligibility filter but the size cap, so they are tracked in
    # `oversized_regions` instead and are NOT part of this total: the
    # dispositions below reconcile against this number, not against the
    # policy's whole eligible set.
    regions_in_scope = len(prioritized)
    regions_gated = 0
    regions_touched = 0
    regions_partial = 0
    regions_unexamined = 0
    read_failed_regions = 0
    short_read_regions = 0
    short_read_unexamined_bytes = 0
    eligible_pages = 0
    pages_examined = 0
    pages_above = 0
    bytes_read = 0
    retained = _TopN(top_n, per_region=per_region_top_n)
    highest = None
    band_counts = [0] * len(ENTROPY_BANDS)

    for r, ref in prioritized:
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            # In scope, not a byte of it read. How many pages it held is
            # not merely zero, it is UNKNOWN -- folding that into
            # `pages_missed == 0` would report an unreadable region as a
            # clean, complete negative.
            read_failed_regions += 1
            continue
        if not data:
            read_failed_regions += 1
            continue
        if len(data) < r.RegionSize:
            # An ANNOTATION on a region that WAS scanned, not a
            # disposition -- the same split production `_scan_entropy`
            # makes. The tail that never arrived still has to be counted:
            # its pages are outside `eligible_pages_in_scope`, which is
            # computed from the bytes actually in hand.
            short_read_regions += 1
            short_read_unexamined_bytes += r.RegionSize - len(data)
        if len(data) < config.entropy_min_input:
            # Read (possibly short), just not enough data to window. The
            # part that arrived is fully accounted for; any part that did
            # not is already counted above.
            continue
        bytes_read += len(data)
        threshold = entropy_threshold_for(ref, config)

        # A region already at/above its own whole-region threshold has
        # nothing for a page pass to add -- `scan_entropy_targeted`
        # applies the identical mutual-exclusivity rule.
        if _shannon_entropy(data) >= threshold:
            regions_gated += 1
            continue

        window_start = time.perf_counter()
        spans, total, _ = _window_spans(len(data), r.BaseAddress, config.entropy_window_size,
                                        _NO_PER_REGION_WINDOW_CAP, config.entropy_min_input)
        if not spans:
            window_seconds += time.perf_counter() - window_start
            continue
        # Counted for EVERY in-scope region, reached by the budget or not:
        # "how many pages were never evaluated" is unanswerable otherwise.
        eligible_pages += total
        regions_touched += 1
        region_examined = 0
        for offset, size in spans:
            if not budget.take(size):
                break
            value = _shannon_entropy(data[offset:offset + size])
            pages_examined += 1
            region_examined += 1
            for band_index, upper in enumerate(ENTROPY_BANDS):
                # The top band is closed, not half-open: a page holding all
                # 256 byte values in equal proportion measures EXACTLY 8.0,
                # which is common enough that leaving it to an implicit
                # overflow bucket would mislabel the most interesting
                # windows in the distribution.
                if value < upper or band_index == len(ENTROPY_BANDS) - 1:
                    band_counts[band_index] += 1
                    break
            address = r.BaseAddress + offset
            if highest is None or (value, -address) > (highest.entropy, -highest.base_address):
                highest = PageObservation(address, size, value)
            if value >= threshold:
                pages_above += 1
                retained.offer(value, address, size, ref, threshold)
        window_seconds += time.perf_counter() - window_start
        if region_examined == 0:
            # Had eligible pages, got none of them measured -- the budget
            # was already spent before this region came up.
            regions_unexamined += 1
        elif region_examined < total:
            regions_partial += 1

    # Every in-scope region is walked regardless of budget, so the counts
    # below cover the WHOLE scope: what was eligible for page-local
    # evaluation, and how much of it never got evaluated.
    #
    # A SUCCESSFUL read with too little analyzable data, no windows, or a
    # whole-region hit that gates the region out is an accounted-for
    # outcome: it contributes no eligible pages and is not a gap. A FAILED
    # read, an empty read, or a short read's unreturned tail is a coverage
    # gap and makes the pass non-exhaustive -- those regions never reach
    # `eligible_pages_in_scope` at all, so `pages_missed` alone cannot see
    # them.
    # Materialize the retained set ONCE. Every derived figure below reads
    # that one list: calling `ordered()`, `output_bytes()`, `hits()`,
    # `distinct_regions()` and `regions_dropped_from_retention()`
    # separately would re-merge and re-sort the reservations each time, and
    # any of those calls made while building the result object would run
    # outside every timer.
    finalize_start = time.perf_counter()
    hits = retained.hits()
    regions_with_hits = retained.regions_with_hits()
    retained_observations = observations_from(hits)
    details_bytes, facts_bytes = output_bytes_from(hits)
    distinct_regions = len({hit.region.base_address for hit in hits})
    dropped_regions = max(0, regions_with_hits - distinct_regions)
    window_seconds += time.perf_counter() - finalize_start
    # Freeze the scan's own cost BEFORE measuring record growth: that
    # measurement builds and serializes two whole HunterRecords, which is
    # instrumentation, not scanning.
    elapsed = time.perf_counter() - start
    instrumentation_start = time.perf_counter()
    delta = record_delta(hits)
    growth = delta["growth_bytes"]
    fields_moved = delta["moved"]
    instrumentation_seconds = time.perf_counter() - instrumentation_start

    pages_missed = eligible_pages - pages_examined
    # Complete means every eligible page was measured AND every in-scope
    # region actually delivered the bytes it declared. A region nobody
    # could read, or a tail that never arrived, is an unanswered question
    # about memory in scope -- it must not read as a clean negative just
    # because the pages it would have held were never counted.
    exhaustive = (pages_missed == 0 and read_failed_regions == 0
                  and short_read_unexamined_bytes == 0 and oversized_regions == 0)

    return PagePassResult(
        policy=policy, regions_in_scope=regions_in_scope,
        regions_gated_by_whole_region_hit=regions_gated, regions_touched=regions_touched,
        regions_partially_examined=regions_partial, regions_unexamined=regions_unexamined,
        read_failed_regions=read_failed_regions, short_read_regions=short_read_regions,
        short_read_unexamined_bytes=short_read_unexamined_bytes,
        oversized_regions=oversized_regions, oversized_bytes=oversized_bytes,
        eligible_pages_in_scope=eligible_pages,
        pages_examined=pages_examined, pages_missed=pages_missed,
        pages_above_threshold=pages_above,
        retained_observations=retained_observations,
        distinct_regions_retained=distinct_regions,
        regions_dropped_from_retention=dropped_regions,
        highest_window=highest,
        band_counts=tuple(zip(ENTROPY_BANDS, band_counts)),
        exhaustive=exhaustive, stopped_on_time=budget.stopped_on_time,
        elapsed_seconds=elapsed, window_seconds=window_seconds,
        instrumentation_seconds=instrumentation_seconds,
        bytes_read=bytes_read,
        details_entropy_json_bytes=details_bytes, facts_json_bytes=facts_bytes,
        record_growth_bytes=growth, record_fields_moved=fields_moved)


# ── Synthetic fixtures ──────────────────────────────────────────────────
# Plain (region, bytes) pairs, independent of tests/fixtures/fakes.py's
# minidump-shaped fakes, so this script has no test-tree import at all.

class _Region:
    def __init__(self, base, size, state, protect, mtype):
        self.BaseAddress = base
        self.AllocationBase = base
        self.RegionSize = size
        self.State = type("P", (), {"name": state})()
        self.Protect = type("P", (), {"name": protect})()
        self.Type = type("P", (), {"name": mtype})()


class _MF:
    """Bare enough to satisfy `va_range_captured_bytes()`'s direct
    attribute reads when this script also times the EXISTING
    `_scan_entropy()` for a before/after comparison -- an empty segment
    table so every region reads as uncaptured for coverage-byte purposes,
    which does not affect entropy values (only `read_region` supplies
    bytes here, not the segment table)."""
    memory_segments_64 = None
    memory_segments = None


def _reader(read_map):
    def _read(mf, addr, size):
        for base, data in read_map.items():
            if base <= addr < base + len(data):
                off = addr - base
                return data[off:off + size]
        return b"\x00" * size
    return _read


def sparse_blind_spot_fixture():
    """One 4 MiB RWX MEM_PRIVATE allocation, almost
    entirely zero, with one deterministic page-aligned 4 KiB high-entropy
    block -- the case a whole-region average hides."""
    import random
    base = 0x10000000
    size = 4 * 1024 * 1024
    hot_offset = 0x100000
    data = bytearray(size)
    data[hot_offset:hot_offset + 4096] = random.Random(1234).randbytes(4096)
    region = _Region(base, size, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")
    return [region], [], _reader({base: bytes(data)})


STRESS_HOT_REGIONS = 3


def stress_fixture(n_regions=12, region_size=8 * 1024 * 1024,
                   n_hot_regions=STRESS_HOT_REGIONS):
    """Many regions sized near ENTROPY_SCAN_MAX (10 MiB), each RWX
    MEM_PRIVATE. The bulk of each region is a sparse, LOW-entropy filler
    (a short structured marker stamped once per page over an otherwise
    zero-filled region -- representative of a real sparse allocation with
    occasional pointers/headers, real scan work rather than an all-zero
    fast path, but not itself entropy-eligible on its own). A handful of
    regions additionally carry one hot page each, so this fixture is the
    sparse blind-spot fixture's shape at whole-hunt scale: a shared budget
    has to find needles in a haystack of otherwise-boring regions rather
    than in one region alone."""
    import random
    import struct
    regions = []
    read_map = {}
    base = 0x20000000
    stride = region_size + 0x100000
    for i in range(n_regions):
        addr = base + i * stride
        data = bytearray(region_size)
        marker = struct.pack("<Q", 0x0000000140000000 + i) + b"\x00" * 8
        for off in range(0, region_size, 4096):
            data[off:off + len(marker)] = marker
        if i < n_hot_regions:
            hot_offset = (i + 1) * 4096
            data[hot_offset:hot_offset + 4096] = random.Random(9000 + i).randbytes(4096)
        regions.append(_Region(addr, region_size, "MEM_COMMIT",
                               "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"))
        read_map[addr] = bytes(data)
    return regions, [], _reader(read_map)


def benign_noise_fixtures():
    """Stand-ins for benign memory classes, used for a noise check only.

    Two of these have an entropy fixed by their own construction and carry
    NO calibration weight: a uniform alphabet of `k` symbols measures
    exactly log2(k) bits/byte, so the band a tiled-alphabet fixture lands
    in is an identity chosen by whoever picked the alphabet, not a
    property of benign memory. They are kept because "does the pass invent
    observations here" is still worth answering, and marked
    `calibrates=False` so no threshold argument can rest on them.

    The `zlib_stream` entries are different: their byte distribution is
    produced by a real compression algorithm over synthetic structured
    input rather than by a chosen alphabet, so their entropy is measured
    rather than decided. Neither is memory captured from a real process.

    Each entry is (label, regions, modules, reader, calibrates).
    """
    import random
    import zlib
    fixtures = []

    # Already-encrypted-looking benign buffer (a TLS session cache, say):
    # uniformly high entropy across the WHOLE region, so the whole-region
    # average already reports it and the gate skips page-windowing it.
    base = 0x30000000
    size = 2 * 1024 * 1024
    data = random.Random(1).randbytes(size)
    fixtures.append((
        "already_flagged_whole_region",
        [_Region(base, size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")],
        [], _reader({base: data}), False))

    # One 16-byte block repeated. A 16-symbol alphabet measures exactly
    # log2(16) = 4.0 bits/byte, nowhere near the 7.2 private threshold:
    # this says the pass does not invent observations from repetition, and
    # nothing about where benign content sits relative to a threshold.
    base = 0x31000000
    size = 2 * 1024 * 1024
    block = random.Random(2).randbytes(16)
    data = block * (size // 16)
    fixtures.append((
        "periodic_block_structured",
        [_Region(base, size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")],
        [], _reader({base: data}), False))

    # Tiled 64-symbol alphabet with a few random stretches. The 64-symbol
    # tiling measures exactly log2(64) = 6.0, so this fixture's proximity
    # to the 6.5 RWX threshold is arithmetic, not evidence about JIT
    # memory. Real instruction streams are what would settle that.
    base = 0x32000000
    size = 3 * 1024 * 1024
    rnd = random.Random(3)
    body = bytearray(bytes(range(64)) * (size // 64 + 1))[:size]
    for _ in range(20):
        off = rnd.randrange(0, size - 64)
        body[off:off + 64] = rnd.randbytes(64)
    fixtures.append((
        "uniform_alphabet_tiling",
        [_Region(base, size, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        [], _reader({base: bytes(body)}), False))

    # A real zlib stream over structured input, zero-padded into a private
    # allocation -- the byte distribution comes from the compressor, so its
    # entropy is measured rather than chosen. This is the one benign
    # content here that can carry any calibration weight, and even it is
    # one content class, not a corpus.
    #
    # Registered twice, under both protections, because the RESULT turns on
    # which one it is placed in: ordinary benign compressed data lives in
    # PAGE_READWRITE, which `rwx_only` never windows, while the RWX variant
    # models compressed content staged in an executable allocation (a JIT
    # cache or unpacker buffer). Publishing only one would make a
    # protection choice look like a property of compressed content.
    size = 2 * 1024 * 1024
    source = b"".join(
        f"<record id={i} name=item{i} value={i * 7 % 1000}>\n".encode()
        for i in range(20000))
    stream = zlib.compress(source, 9)
    body = bytearray(size)
    body[0:len(stream)] = stream[:size]
    for label, base, protect in (("zlib_stream_rwx", 0x33000000, "PAGE_EXECUTE_READWRITE"),
                                 ("zlib_stream_readwrite", 0x34000000, "PAGE_READWRITE")):
        fixtures.append((
            label,
            [_Region(base, size, "MEM_COMMIT", protect, "MEM_PRIVATE")],
            [], _reader({base: bytes(body)}), True))

    return fixtures


def retention_bias_fixture():
    """Two RWX regions, both sparse enough that the whole-region gate lets
    them through: one holding 64 near-maximal pages at low addresses, one
    holding a single lower-but-still-above-threshold page at a higher
    address.

    65 pages clear their threshold. A flat global top-64 keeps the 64
    loudest and drops the other region's page entirely -- the count
    survives, the address does not. Whether that matters is what a
    per-region reservation is for."""
    import random
    rng = random.Random(7)
    loud_base = 0x80000000
    quiet_base = 0x90000000

    loud = bytearray(1200 * 4096)
    for index in range(64):
        loud[index * 4096:(index + 1) * 4096] = rng.randbytes(4096)
    # A 180-symbol alphabet measures ~log2(180) = 7.49: above every
    # threshold, below the near-maximal pages competing with it.
    quiet = bytearray(200 * 4096)
    quiet[0:4096] = bytes(rng.choice(range(180)) for _ in range(4096))

    regions = [
        _Region(loud_base, len(loud), "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        _Region(quiet_base, len(quiet), "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
    ]
    return regions, [], _reader({loud_base: bytes(loud), quiet_base: bytes(quiet)}), quiet_base


def _print_result(label, res: PagePassResult, redact_addresses: bool = False):
    print(f"  [{res.policy:11s}] {label}")
    print(f"    regions_in_scope={res.regions_in_scope} "
          f"gated_by_whole_region_hit={res.regions_gated_by_whole_region_hit} "
          f"touched={res.regions_touched} partial={res.regions_partially_examined} "
          f"unexamined={res.regions_unexamined}")
    print(f"    read_failed={res.read_failed_regions} "
          f"short_read={res.short_read_regions} "
          f"short_read_unexamined_bytes={res.short_read_unexamined_bytes} "
          f"oversized={res.oversized_regions}")
    print(f"    eligible_pages={res.eligible_pages_in_scope} "
          f"examined={res.pages_examined} missed={res.pages_missed} "
          f"above_threshold={res.pages_above_threshold} "
          f"retained_observations={len(res.retained_observations)} "
          f"distinct_regions_retained={res.distinct_regions_retained} "
          f"regions_dropped_from_retention={res.regions_dropped_from_retention}")
    print(f"    exhaustive={res.exhaustive} stopped_on_time={res.stopped_on_time} "
          f"elapsed={res.elapsed_seconds:.4f}s window_only={res.window_seconds:.4f}s "
          f"bytes_read={res.bytes_read}")
    print(f"    instrumentation_only={res.instrumentation_seconds:.4f}s "
          f"(harness measurement, excluded from elapsed)")
    print(f"    details_entropy_json_bytes={res.details_entropy_json_bytes} "
          f"facts_json_bytes={res.facts_json_bytes} "
          f"record_growth_bytes={res.record_growth_bytes}")
    moved = ", ".join(f"{name}: {before} -> {after}"
                      for name, (before, after) in sorted(res.record_fields_moved.items()))
    print(f"    record_fields_moved: {moved or '(none)'}")
    bands = " ".join(
        f"{'<=' if index == len(res.band_counts) - 1 else '<'}{upper}:{count}"
        for index, (upper, count) in enumerate(res.band_counts))
    print(f"    entropy_bands: {bands}")
    if res.highest_window is not None:
        where = "" if redact_addresses else f"addr=0x{res.highest_window.base_address:x} "
        print(f"    highest_window: {where}size={res.highest_window.size} "
              f"entropy={res.highest_window.entropy:.3f}")


def _run_synthetic_scenarios():
    config = EncodingConfig()

    print("=== Scenario 1: sparse blind-spot fixture ===")
    regions, modules, reader = sparse_blind_spot_fixture()
    for policy in POLICIES:
        res = run_page_local_pass(regions, modules, _MF(), ("PAGE_EXECUTE_READWRITE",), reader,
                                  config, policy, max_pages=10_000, max_bytes=64 * 1024 * 1024,
                                  deadline_seconds=30.0)
        _print_result("sparse_blind_spot", res)

    print()
    print("=== Scenario 2: stress fixture, generous ('unbounded-in-practice') budget ===")
    regions, modules, reader = stress_fixture()

    from dumpex.hunt.encoding.entropy import _scan_entropy
    before_start = time.perf_counter()
    before = _scan_entropy(regions, modules, _MF(), ("PAGE_EXECUTE_READWRITE",), reader, config)
    before_elapsed = time.perf_counter() - before_start
    print("  [production  ] _scan_entropy (whole-region average only)")
    print(f"    hits={len(before.hits)} elapsed={before_elapsed:.4f}s "
          f"(full-scope obfuscation reports this many entropy hits over a "
          f"fixture holding {STRESS_HOT_REGIONS} planted hot pages)")

    generous = dict(max_pages=1_000_000, max_bytes=1024 * 1024 * 1024, deadline_seconds=60.0)
    for policy in POLICIES:
        res = run_page_local_pass(regions, modules, _MF(), ("PAGE_EXECUTE_READWRITE",), reader,
                                  config, policy, **generous)
        _print_result("stress_fixture/generous", res)
        print(f"    duration_delta_vs_production: +{res.elapsed_seconds - before_elapsed:.4f}s")

    print()
    print("=== Scenario 3: stress fixture, forced budget exhaustion ===")
    regions, modules, reader = stress_fixture()
    tight = dict(max_pages=50, max_bytes=16 * 1024 * 1024, deadline_seconds=30.0)
    first_run = {}
    for policy in POLICIES:
        res = run_page_local_pass(regions, modules, _MF(), ("PAGE_EXECUTE_READWRITE",), reader,
                                  config, policy, **tight)
        first_run[policy] = res
        _print_result("stress_fixture/tight_budget", res)
    print("  -- re-running to confirm deterministic retention under the same page budget --")
    for policy in POLICIES:
        rerun = run_page_local_pass(regions, modules, _MF(), ("PAGE_EXECUTE_READWRITE",), reader,
                                    config, policy, **tight)
        same = (rerun.retained_observations == first_run[policy].retained_observations
                and rerun.pages_examined == first_run[policy].pages_examined)
        print(f"  [{policy:11s}] identical retained set + pages_examined across reruns: {same}")

    print()
    print("=== Scenario 4: retention policy -- flat global top-N vs per-region floor ===")
    regions, modules, reader, quiet_base = retention_bias_fixture()
    for per_region in (0, ENTROPY_TOP_WINDOWS):
        res = run_page_local_pass(regions, modules, _MF(), ("PAGE_EXECUTE_READWRITE",), reader,
                                  config, "rwx_only", max_pages=1_000_000,
                                  max_bytes=1024 * 1024 * 1024, deadline_seconds=60.0,
                                  top_n=64, per_region_top_n=per_region)
        label = "flat global top-N" if per_region == 0 else f"per-region {per_region} + global"
        _print_result(label, res)
        kept = sum(1 for o in res.retained_observations if o.base_address >= quiet_base)
        print(f"    quieter region's above-threshold page retained: {bool(kept)}")

    print()
    print("=== Scenario 5: benign/clean-like synthetic corpus (noise check) ===")
    for label, regions, modules, reader, _calibrates in benign_noise_fixtures():
        for policy in POLICIES:
            res = run_page_local_pass(regions, modules, _MF(), ("PAGE_EXECUTE_READWRITE",), reader,
                                      config, policy, max_pages=10_000,
                                      max_bytes=64 * 1024 * 1024, deadline_seconds=30.0)
            _print_result(label, res)


def _open_dump_redacted(path, label: str, show_paths: bool = False):
    """`open_dump(path)`, with every path it would print replaced by
    `label`. Returns the parsed dump, or `None` when it could not be
    opened.

    `dumpex.core.memory.open_dump` prints the path it was given on both of
    its failure paths ("File not found: <path>", "Could not parse <path>
    as a minidump file") and then `sys.exit(1)`s. On an analyst host that
    path can itself be the sensitive part -- `D:\\Cases\\<client>\\<case
    id>\\proc.dmp` names a customer and an engagement even when the dump
    never opens -- so a harness that promises quotable output has to
    redact the failure text too, not just the success text. Whatever
    `open_dump` writes is captured and scrubbed rather than filtered by
    message, so a new message added there cannot leak by default.
    """
    import contextlib
    import io
    import os

    def _scrub(text: str) -> str:
        raw = str(path)
        for variant in (os.path.abspath(raw), raw, os.path.dirname(os.path.abspath(raw))):
            if variant:
                text = text.replace(variant, label)
        return text

    if not os.path.exists(path):
        print(f"  [!] {label}: file not found")
        return None

    from dumpex.core.memory import open_dump

    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            mf = open_dump(str(path))
    except SystemExit:
        mf = None
    except Exception as exc:                      # noqa: BLE001 -- evaluation harness
        print(f"  [!] {label}: could not be opened ({type(exc).__name__})")
        return None
    finally:
        noise = captured.getvalue()
        if noise.strip():
            print(_scrub(noise) if not show_paths else noise, end="")
    if mf is None:
        print(f"  [!] {label}: could not be opened as a minidump")
    return mf


def run_corpus(paths, susp_prots=None, show_paths: bool = False):
    """Replay the comparison against real .dmp files.

    Prints aggregate counts, timings, and entropy values only -- never a
    recovered string, never a window address, and (unless `show_paths`)
    never the sample's own path, which can itself carry a customer, case,
    host, or analyst name. Samples are labelled `sample A`, `sample B`, ...
    in argument order, so a run against private corpus samples can be
    quoted in a public evaluation record as it stands. The samples are
    never read into the repository, only from wherever the caller points
    this.
    """
    from dumpex.core.memory import read_region
    from dumpex.hunt.encoding.entropy import _scan_entropy
    from dumpex.rules_pkg.loader import get_rules

    if susp_prots is None:
        # The same rules-derived list production resolves `is_rwx` from, so
        # a customized rules file moves this harness's scope and threshold
        # pick exactly as it moves production's.
        susp_prots = tuple(get_rules(announce=False)["suspicious_protections"])
    config = EncodingConfig()
    for index, path in enumerate(paths):
        label = f"sample {chr(ord('A') + index)}" if index < 26 else f"sample #{index + 1}"
        print(f"=== {path if show_paths else label} ===")
        mf = _open_dump_redacted(path, label, show_paths)
        if mf is None:
            continue
        regions = list(mf.memory_info.infos) if mf.memory_info else []
        modules = list(mf.modules.modules) if mf.modules else []

        started = time.perf_counter()
        production = _scan_entropy(regions, modules, mf, susp_prots, read_region, config)
        print(f"  [production  ] whole-region only: hits={len(production.hits)} "
              f"scanned={production.coverage.scanned} "
              f"elapsed={time.perf_counter() - started:.4f}s")
        print(f"    entropy layer ledger (policy-independent): "
              f"read_failed={production.coverage.read_failed} "
              f"short_reads={production.coverage.short_reads} "
              f"oversize_skipped={len(production.coverage.skipped_oversize_targets)}")

        for policy in POLICIES:
            res = run_page_local_pass(regions, modules, mf, susp_prots, read_region, config,
                                      policy, max_pages=200_000, max_bytes=512 * 1024 * 1024,
                                      deadline_seconds=120.0)
            _print_result(label, res, redact_addresses=True)
        print()


GROWTH_TABLE_COUNTS = (1, 2, 15, 16, 64)

# The region every growth-table observation is attributed to. Fixed here so
# the published table regenerates byte-for-byte: the serialized size depends
# on this shape (address width, protection string, region size).
GROWTH_TABLE_REGION = dict(base_address=0x10000000, allocation_base=0x10000000,
                           size=4 * 1024 * 1024, state="MEM_COMMIT",
                           protect="PAGE_EXECUTE_READWRITE", type="MEM_PRIVATE",
                           is_rwx=True)


def run_growth_table():
    """Whole-`HunterRecord` growth against retained-observation count.

    A committed code path rather than a hand-run snippet, so the published
    table can be regenerated and audited. Observations are one page apart
    inside one region, each above the RWX threshold.
    """
    from dumpex.hunt.encoding.models import RegionRef

    ref = RegionRef(**GROWTH_TABLE_REGION)
    print("retained_observations,record_growth_bytes")
    for count in GROWTH_TABLE_COUNTS:
        retained = _TopN(count)
        for index in range(count):
            retained.offer(entropy=7.9 - index / 1000,
                           base_address=ref.base_address + index * 4096,
                           size=4096, ref=ref, threshold=6.5)
        print(f"{count},{record_growth_bytes(retained.hits())}")


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--corpus", nargs="+", metavar="DMP",
                        help="replay against these .dmp files instead of the synthetic "
                             "scenarios. Output is redacted -- samples are labelled "
                             "'sample A', 'sample B', ... and no window address is "
                             "printed -- so it can be quoted in a public record.")
    parser.add_argument("--growth-table", action="store_true",
                        help="print the record-growth-vs-observation-count table "
                             "the evaluation publishes, and exit")
    parser.add_argument("--show-paths", action="store_true",
                        help="print each --corpus sample's real path instead of its "
                             "redacted label. A dump path can itself name a customer, "
                             "case, host, or analyst: do not use this for output that "
                             "leaves the analysis host.")
    args = parser.parse_args(argv)
    if args.growth_table:
        run_growth_table()
    elif args.corpus:
        run_corpus(args.corpus, show_paths=args.show_paths)
    else:
        _run_synthetic_scenarios()


if __name__ == "__main__":
    main()

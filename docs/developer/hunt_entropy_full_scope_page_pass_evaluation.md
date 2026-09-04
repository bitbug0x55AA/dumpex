# Evaluation: bounded page-local entropy observations for full-scope scans

Whether full-scope obfuscation scanning should measure VA-aligned page-local
entropy in addition to its existing one-value-per-region average.

**Outcome: no.** Retain whole-region entropy for full-scope scans, keep
page-local localization targeted-only (`--hunt-addr`), and document the
limitation.

The blind spot is real and is confirmed on real dumps. What the measurements
do not establish is that closing it is worth the cost:

- Every dump on which the pass retains one observation moves
  `review_priority` from `none` to `low`. That is measured through the real
  projection pipeline and holds under every policy, so any dump with a
  single retained page -- clean or not -- gains a triage-priority bump it
  does not have today.
- Benign compressed content clears the threshold on dozens of pages once it
  is in scope: a synthetic buffer holding a real zlib stream produces 35
  pages / 12,486 B in an RWX allocation and 19 pages / 7,686 B in ordinary
  read/write memory under the wider policy. This demonstrates a plausible
  benign-noise mechanism; it is **not** an observed regression on a real
  clean dump, because no clean dump was available to observe.
- Real RWX memory crowds the bar: 76 windows on sample A sit in [6.0, 6.5),
  directly under the RWX threshold, with no margin quantified.
- The benefit is a triage prompt, not a detection: `scan_entropy_targeted`
  already localizes, and does so on request.

The evidence that could overturn this -- a real clean-DMP corpus establishing
that benign RWX content stays clear of the threshold -- is not obtainable in
this environment. On what is measurable here, the pass does not earn its
place.

This is an evaluation record, not an implementation change: nothing in
`dumpex/` changed, and no `--hunt obfuscation` JSON field, score, confidence,
verdict, or `review_priority` moved. The candidate pass is a measurement
prototype only.

## The limitation being accepted

`_scan_entropy()` computes one Shannon value per eligible region -- that
region's average. A bounded high-entropy payload inside an otherwise sparse
multi-megabyte `MEM_PRIVATE` allocation is diluted by the zero-filled
majority, so the region-level average can sit well below threshold even
though a single 4 KiB page inside it sits well above.

**Full-scope scans therefore do not localize high entropy inside a region,
and a sparse allocation whose average stays under threshold produces no
entropy observation at all.** This is confirmed on real memory: on two
ground-truth-malicious dumps carrying reflectively injected Cobalt Strike
shellcode, production `_scan_entropy` reports **zero** entropy hits while the
injected payload measures **7.999-8.000 bits/byte** page-locally.

Entropy is observation-only, so this is not a scoring false negative. It is a
triage gap: where no other analyzer produces a finding or a skipped-target
action, the investigator gets no prompt to run the targeted rescan that
*would* localize the payload. `scan_entropy_targeted` remains the supported
route, and it works -- it is the discovery step that is missing, not the
capability.

## What was built to decide this

1. **A regression fixture** pinning the gap against shipped code --
   [`tests/hunt/test_entropy_full_scope_blind_spot.py`](../../tests/hunt/test_entropy_full_scope_blind_spot.py).
   A synthetic 4 MiB RWX `MEM_PRIVATE` allocation, mostly zero, carries one
   deterministic 4 KiB high-entropy page. `_scan_entropy()` reports no hit;
   `scan_entropy_targeted()` over the identical bytes localizes the page.

2. **A measurement prototype** --
   [`scripts/evaluate_entropy_page_local_pass.py`](../../scripts/evaluate_entropy_page_local_pass.py),
   covered by
   [`tests/unit/test_entropy_page_local_pass_prototype.py`](../../tests/unit/test_entropy_page_local_pass_prototype.py).
   It reuses `_scan_entropy`'s eligibility gate and
   `scan_entropy_windows`'s window math. It is not imported by
   `dumpex.hunt.encoding`. Every figure below regenerates from it:

   ```bash
   python scripts/evaluate_entropy_page_local_pass.py
   python scripts/evaluate_entropy_page_local_pass.py --growth-table
   python scripts/evaluate_entropy_page_local_pass.py --corpus <dmp> [<dmp> ...]
   ```

   `--corpus` output is redacted by construction: samples are labelled
   `sample A`, `sample B`, ... rather than by path (a dump path can itself
   name a customer, case, host, or analyst), no window address is printed,
   and no recovered content ever is. Failure output is redacted too, since
   `open_dump` prints the path it was given on both of its failure paths.
   `--show-paths` opts back in for local use.

## Measurements

Single-run, uninstrumented wall-clock on one machine -- indicative of
relative cost, not a calibrated benchmark, consistent with
`tests/perf/test_benchmarks.py`'s own generous-threshold policy.

`window_only` is the pass's *marginal* cost: region prioritization and
sorting, span computation, window measurement, and retention/projection
finalization -- everything production `_scan_entropy` does not already pay
for. It excludes the region read and the whole-region average, which
production pays either way. `elapsed` is frozen before the harness measures
record growth; that measurement is reported separately as
`instrumentation_only`, since building and serializing two whole
`HunterRecord`s is something no scan does.

### The blind spot, and what closing it costs

| | production `_scan_entropy` | candidate pass |
|---|---|---|
| sparse 4 MiB fixture, 1 hot page | 0 hits | 1 observation, `window_only` 0.09s |
| stress fixture (12 x 8 MiB, 3 hot pages) | 0 hits | 3 observations, `window_only` 1.94s |
| real sample A (3 RWX regions) | 0 hits | 5 observations, `window_only` 0.10s |
| real sample B (1 RWX region) | 0 hits | 2 observations, `window_only` 0.007s |

The pass does what it was proposed to do. Marginal cost on real dumps is
small in absolute terms, but the rate matters more than the samples: **~20 ms
per MiB** of windowed memory (1.94s over 96 MiB). The two real samples had 1
and 3 RWX regions; a process with a few hundred MiB of eligible private
memory would add seconds to tens of seconds, against an existing shared
`ENCODING_BUDGET_TIME_SECONDS` of 60s that this prototype does not share.

### Benign noise

Three of the four benign fixtures are **construction artifacts and carry no
calibration weight**: a uniform alphabet of *k* symbols measures exactly
log2(*k*) bits/byte, so the band a tiled-alphabet fixture lands in is chosen
by whoever picked the alphabet. They are retained only to show the pass does
not invent observations from repetition, and are marked `calibrates=False`
in the harness.

| fixture | entropy is | above-threshold pages | record growth |
|---|---|---|---|
| already-encrypted-looking (uniform random) | chosen | 0 (gated: whole-region average already flags it) | 0 |
| 16-byte block repeated | chosen (log2 16 = 4.0) | 0 | 0 |
| 64-symbol tiling + random stretches | chosen (log2 64 = 6.0) | 0 | 0 |
| real zlib stream (`zlib_stream_rwx`, `zlib_stream_readwrite`) | **produced by a real compressor** over synthetic input | see below | see below |

The fourth is a real zlib stream over synthetic structured input, padded
into a synthetic region. Its byte distribution is produced by a real
compression algorithm rather than chosen by an alphabet, which is what makes
it worth measuring -- but it is still a constructed fixture, not memory
captured from a browser, JIT, or managed runtime. Its result also depends on
the region protection it is placed in, so it is registered under both and all
four rows are published -- the protection is a choice, exactly as the
alphabet was for the three fixtures above, and a result that turns on it must
say so:

| protection | policy | in scope | above-threshold pages | record growth | `review_priority` |
|---|---|---|---|---|---|
| `PAGE_EXECUTE_READWRITE` | `rwx_only` | yes | 35 | 12,486 B | none -> low |
| `PAGE_EXECUTE_READWRITE` | `all_eligible` | yes | 35 | 12,486 B | none -> low |
| `PAGE_READWRITE` | `rwx_only` | **no** | 0 | 0 | unchanged |
| `PAGE_READWRITE` | `all_eligible` | yes | 19 | 7,686 B | none -> low |

All four rows are emitted by the plain harness run. The page counts are
**environment-dependent to within a page or two**: `zlib.compress` output
differs between zlib builds (stock zlib and zlib-ng do not agree byte for
byte), and page entropy is measured on 4 KiB boundaries, so a few bytes of
difference move pages across the threshold. These were measured on
CPython 3.14 with zlib-ng 1.3.1; stock zlib 1.3.2 gives 18 rather than 19 on
the `PAGE_READWRITE` row. The test cited below therefore asserts the shape
that is invariant -- in scope versus not, and a higher threshold yielding
fewer pages -- rather than the exact counts. Nothing in the argument turns
on the difference.

Ordinary benign compressed data lives in `PAGE_READWRITE` private memory,
which `rwx_only` never windows -- so under the policy this evaluation would
otherwise ship, that content contributes nothing. The RWX rows model
compressed content staged in an RWX allocation, which is a real case (JIT
code caches and unpacker staging buffers both do it) but a narrower one, and
it is not demonstrated on real memory here. The `PAGE_READWRITE` /
`all_eligible` row -- 19 pages, 7,686 B on plainly benign content -- is the
figure that stands without a protection argument.

Pinned by
[`test_the_compressed_stream_result_depends_on_the_region_protection`](../../tests/unit/test_entropy_page_local_pass_prototype.py)
so the dependence stays visible.

### `review_priority` moves; nothing else does

Measured through the real `build_report` -> `project_hunter_record` pipeline,
baseline (no entropy evidence) against candidate:

| field | baseline | candidate |
|---|---|---|
| `score` | 0 | 0 |
| `confidence` | `none` | `none` |
| `verdict_level` | `clean` | `clean` |
| `lead_count` | 0 | 0 |
| `status` | `NOT_DETECTED_IN_SCANNED_SCOPE` | unchanged |
| **`review_priority`** | **`none`** | **`low`** |

`obfuscation.entropy_observation` carries `TAG_OBSERVATION`, and
`review_priority()` returns `PRIORITY_LOW` for any observation
(`dumpex/hunt/_finding.py`). So any dump on which the pass retains one
above-threshold window -- including the synthetic benign zlib fixture, whose
single region is enough -- gains a finding where production emits none, and
its `review_priority` moves in both JSON and the console summary table.
Entropy stays observation-only in the sense the design question asks about
(score, confidence, verdict), but the field analysts sort a triage table by
does move. That demonstrates a plausible benign-noise mechanism and a
triage-impact risk in the most directly triage-facing field available; how
often it would fire on real clean memory is unmeasured here. Pinned by
[`test_entropy_observations_move_review_priority_and_nothing_else`](../../tests/unit/test_entropy_page_local_pass_prototype.py).

### Structured-output growth

Measured against the projectors `--json` uses today
(`report_record._entropy_hit_dict`, which emits a `window` sub-object for a
bounded observation, and `report_facts._entropy_item_fact`, capped at
`evidence_limit=15` plus one `"... and N more"` line). The first observation
also materializes an entire finding -- `inference`, `rationale` (319 B),
`limitations` (299 B) and the rest -- which dominates a small retained set.

Regenerate with `--growth-table`:

| retained observations | 1 | 2 | 15 | 16 | 64 |
|---|---|---|---|---|---|
| `HunterRecord` growth (bytes) | 1,428 | 1,799 | 6,709 | 7,009 | 20,250 |

Serialized compactly; the shipped writer uses `indent=2`, so on-disk growth
is larger. Worst case measured on a real dump: 10,176 B (`all_eligible`,
sample B). A top-N cap of 64 bounds it to ~20 KB regardless of dump size.

### Eligibility policies

| | `rwx_only` | `all_eligible` |
|---|---|---|
| above-threshold pages, sample A | 5 | 7 |
| above-threshold pages, sample B | 2 | **28** |
| record growth, sample B | 1,824 B | 10,176 B |
| marginal cost, real samples | <0.1s | ~0.1-0.3s |

`all_eligible` multiplied sample B's observations 14x while adding nothing
`rwx_only` missed on either sample. If the pass were to ship, it would ship
`rwx_only`.

A coverage argument for `rwx_only` does **not** hold and is not made here.
The page pass reports `exhaustive=False` under `all_eligible` on both samples
because unreadable regions fall inside its wider scope -- but the entropy
layer's own ledger already records `read_failed=4` (sample A) and
`read_failed=6` (sample B) **regardless of page policy**. Narrowing scope did
not examine that memory; it stopped counting it. The harness prints the
layer ledger alongside every policy so the two cannot be conflated again.

### Retention policy

A flat global top-N is deterministic but not unbiased. With 65 pages over
threshold across two regions -- 64 near-maximal in one, a single 7.46 page in
another -- a flat top-64 keeps only the loud region:

| | flat global top-N | per-region 5 + global |
|---|---|---|
| above-threshold pages | 65 | 65 |
| retained observations | 64 | 64 |
| **distinct regions retained** | **1** | **2** |
| regions dropped from retention | 1 | 0 |
| quieter region's page retained | no | yes |

The count survives; the addresses -- the thing an investigator extracts --
are lost for a whole region.

A floor has two requirements of its own, and both are easy to miss:

- **Fill breadth-first** -- every region's best observation before any
  region's second. Collecting each region's full reservation and truncating
  to the cap afterwards re-applies global entropy order across regions, so
  the floor silently collapses back into a plain global cap as soon as
  `regions_with_hits x per_region` exceeds the cap. At a cap of 64 and a
  reservation of 5 that threshold is ~13 regions, well inside the 34 regions
  sample A puts in scope under `all_eligible`.
- **Report the overrun.** Filled breadth-first the floor holds to `n`
  regions; past that no retained set of size `n` can represent them all.
  How many regions go unrepresented has to be a reported number -- here
  `regions_dropped_from_retention`, tracked in both retention modes so a
  flat cap's own bias is visible too -- rather than something a reader has
  to infer from a count that looks complete.

Both properties are pinned:
[`test_flat_global_retention_drops_whole_regions_a_per_region_floor_keeps`](../../tests/unit/test_entropy_page_local_pass_prototype.py)
and
[`test_the_per_region_floor_holds_to_the_global_cap_and_reports_its_overrun`](../../tests/unit/test_entropy_page_local_pass_prototype.py).

### Entropy band distributions

Every measured window binned, so "how close does content sit to the bar" is
answerable rather than inferred from threshold crossings alone. The top band
is closed (a page holding all 256 values in equal proportion measures exactly
8.0).

| | <4.0 | [4.0,6.0) | [6.0,6.5) | [6.5,7.2) | [7.2,8.0] |
|---|---|---|---|---|---|
| sample A, `rwx_only` | 988 | 34 | 76 | 1 | 4 |
| sample A, `all_eligible` | 2,241 | 43 | 77 | 1 | 6 |
| sample B, `rwx_only` | 21 | 16 | 39 | 0 | 2 |
| sample B, `all_eligible` | 1,204 | 48 | 79 | 28 | 28 |
| zlib stream (benign) | 476 | 1 | 0 | 16 | 19 |

76 real RWX windows on sample A sit in [6.0, 6.5) -- directly under the RWX
threshold, with no margin to spare. These are malicious samples, so their
non-payload regions are indicative rather than a clean baseline; a proper
calibration needs a clean corpus. What the data does show is that real memory
crowds the threshold at page granularity in a way no whole-region average
ever exposed.

## Answers to the design questions

**1. Which regions should receive page-local evaluation?** If it were added:
RWX `MEM_PRIVATE` only. `all_eligible` multiplies observations without
adding detections.

**2. Are VA-aligned 4 KiB windows appropriate for full scope?** Yes -- the
existing `_window_spans`/`scan_entropy_windows` math was reused unmodified
throughout.

**3. Are the existing thresholds calibrated for 4 KiB samples?**
**Unresolved.** The band data shows real RWX memory clustering immediately
below 6.5 and a benign zlib stream clearing 7.2 on 35 pages, but a threshold
cannot be calibrated against malicious samples and synthetic fixtures. This
is the single largest open question and it needs a clean corpus.

**4. Which resources should bound the pass?** Cumulative pages, cumulative
bytes, and a wall-clock deadline, checked per window, plus a retention cap
enforced during the scan and a per-region floor beneath it.

Retention has to be bounded in **two** dimensions, and only one of them is
obvious. Bounding entries per region still lets the number of per-region
structures track the region count, so a dump with thousands of eligible
regions holds thousands of them for a retained set that can never exceed the
cap. Regions are scanned one at a time, so a region's candidates should be
folded into a reserved set -- itself capped at the retention size, since no
set of `n` observations can represent more than `n` regions -- as soon as the
scan leaves that region, and its working heap dropped. Peak then holds at
`n + per_region + n x per_region` regardless of how many regions or pages the
scan sees. Pinned by
[`test_retention_memory_is_bounded_in_region_count_not_only_page_count`](../../tests/unit/test_entropy_page_local_pass_prototype.py).

**5. Should an already-above-threshold region also retain page locations?**
The prototype says no, mirroring `scan_entropy_targeted`'s mutual-exclusivity
rule, and that keeps cost and noise down. **This answer is not settled on
localization grounds.** A 10 MiB RWX region averaging just over the bar
produces one region-level hit and no page observations, so the analyst's
extraction target stays 10 MiB when a 4 KiB one existed -- localization
withheld exactly where it is worth most. That rule exists to avoid
double-reporting one hit, not to suppress sub-range localization inside a
large flagged region, and an implementation should re-examine it.

**6. How do priority ordering and incomplete coverage stay deterministic?**
Regions RWX-first then by address; windows by address; retention by
(descending entropy, ascending address). Under the page and byte budgets the
run is fully deterministic. Under the wall-clock deadline it is not: it stops
wherever the machine happened to be, so it guarantees a deterministic
*prefix* of the same page order, of varying length. `stopped_on_time` says
which kind of stop occurred.

## Coverage semantics, if a page pass is ever added

Recorded because the next attempt will need it, and because getting it wrong
is easy: three separate accounting bugs in this prototype each reported
unexamined memory as a complete, clean page-level negative.

- Count `eligible_pages` / `evaluated_pages` / `missed_pages` across the
  **whole** scope, including regions a spent budget never reached. A budget
  must stop window measurement, not the region walk.
- `exhaustive` is true **only** when all of:

  ```text
  missed_pages                == 0
  read_failed_regions         == 0
  short_read_unexamined_bytes == 0
  oversized_regions           == 0
  ```

  `missed_pages == 0` alone is **not** sufficient and must not be used. A
  region whose read failed, or that sits past `ENTROPY_SCAN_MAX`, never
  contributes eligible pages, so it leaves `missed_pages` at zero while a
  whole region in scope went unexamined.
- Keep "cut off mid-region" distinct from "never measured at all", and
  distinguish a time-budget stop from a page/byte-budget stop -- only the
  latter is reproducible.
- **Reuse `ScanBudget` and `CoverageTracker` rather than adding a parallel
  budget and a parallel `page_pass_*` vocabulary.** This prototype has its
  own `_Budget` because it runs standalone, and that is the one part of its
  shape that should not be copied: two independent wall-clock deadlines over
  one hunt, neither aware of the other, is structural debt. Encoding layers
  0 and 2-4 already share one `ScanBudget` whose exhaustion surfaces as
  `coverage_status="partial"`; a page pass belongs inside it. If `ScanBudget`
  cannot express a page or byte allowance, the right move is a minimal
  extension to it, not a second subsystem.

## What this evaluation could not establish

- **No authorized clean-DMP corpus.** `tests/corpus/clean/` holds no
  manifest in this environment, so no measurement here touches real benign
  browser, JIT, or managed-runtime memory, and **the benign noise rate on a
  real clean dump remains unmeasured**. The zlib fixture shows that benign
  compressed content is *capable* of clearing the threshold in volume; it
  does not show that any real clean dump does. It supports a risk judgement
  and does not substitute for the corpus.
- **The originally-reported private regression case was not available**, and
  no attempt was made to identify it. The real-dump replay used two public
  HTB Sherlock challenge artifacts held in the local evil corpus; they
  independently reproduce the blind spot, but they are not that case.
- The replay drove the entropy layer directly, not a full `--hunt
  obfuscation` CLI run.
- Timings are single-run, not statistically characterized.

## Revisiting

The decision above rests on benign-noise evidence, and one clean-corpus run
could overturn it. What would justify reopening:

1. Run `scripts/evaluate_entropy_page_local_pass.py --corpus` against a real
   clean corpus on the protected runner, covering browser, JIT, and
   managed-runtime processes, and publish the band distributions.
2. If benign RWX content stays clear of 6.5 with margin and the retained
   volume on clean dumps is small, the pass becomes justifiable -- scoped to
   `rwx_only`, with a per-region retention floor, the coverage semantics
   above, and `ScanBudget` reuse. The `review_priority` movement would still
   need an explicit decision: either accept it, or make entropy observations
   not raise triage priority on their own.
3. If benign RWX content crowds or crosses 6.5 -- which the sample-A band
   data hints at, 76 windows in [6.0, 6.5) -- the answer stays no, and the
   next question is whether page-sized samples need their own threshold
   rather than inheriting the region-level one.

Until then: whole-region entropy for full-scope scans, `--hunt-addr` for
localization.

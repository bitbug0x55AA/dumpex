# Changelog

User-facing changes only. For the full field-by-field migration rationale
and JSON Schema details, see [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md);
for how to read the new fields as a triage analyst, see
[docs/SOC_QUICKSTART.md](docs/SOC_QUICKSTART.md).

## Fixed: `minidump` dependency now pinned; HandleDataStream descriptor sizing made symmetric

`pip install dumpex` (or `pip install --upgrade minidump` into an existing
dumpex environment) could previously pull in ANY release of the `minidump`
library ([issue #86](https://github.com/bitbug0x55AA/dumpex/issues/86)):
`pyproject.toml` declared the dependency with no version bound at all. An
upstream rename or removal of any of the structures `dumpex/core/memory.py`
imports at module scope would break `import dumpex.core.memory` and, with
it, every dumpex command (`--list`, `--modules`, `--threads`, `--hunt`, ...)
— not just `--handles`. `minidump` is now pinned to the exact version
dumpex's HandleDataStream parser was validated against
(`minidump>=0.0.24,<0.0.25`); widening that range requires re-validating
both the parser's own reasoning and the descriptor sizes below against the
new ceiling.

Separately, `--handles`' internal v1/v2 descriptor-size selection compared
the v1 branch against its struct class's own size but the v2 branch
against a hardcoded literal `40` — so an upstream size change to the v2
descriptor could either misdiagnose valid `--handles` output as corrupted,
or silently select the wrong parser and misread every field
(`GrantedAccess`, `HandleCount`, `TypeName`, `ObjectName`, ...) for every
handle in the stream, with no error and no coverage caveat. Both branches
now derive their size the same way, and the layout is validated (raising a
clear, attributable error naming the affected structure) the first time a
dump with a `HandleDataStream` is opened, rather than assumed.

## Fixed: `--hunt cs-beacon --verbose` no longer truncates binary TLV field values

The console renderer silently cut off any non-text type-3 TLV field value
after 64 hex characters (32 bytes) and appended `...`, in both the
**Full Config Field Table** and **Process Injection** sections
([issue #46](https://github.com/bitbug0x55AA/dumpex/issues/46), the same
fixed-slice pattern as [issue #30](https://github.com/bitbug0x55AA/dumpex/issues/30)).
The cut was silent and deterministic — unaffected by terminal width,
redirected output, or `--verbose` itself — even though normal-mode output
tells the analyst to pass `--verbose` for "the complete field table".

```
# before (40-byte ProcInject_Transform_x64, 80 hex chars total)
ProcInject_Transform_x64  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20...

# after
ProcInject_Transform_x64  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021
                           22232425262728
```

A binary field's complete hex now always renders, wrapped across as many
lines as needed with a hanging indent aligned under the value column, and
never split mid-byte (`dumpex/hunt/cs_beacon/report_console.py`'s new
`_wrap_hex_value()`/`_value_lines()`, shared by both sections). Terminal
width changes only how the value wraps, never how much of it is shown.
Detection, scoring, coverage, and every structured (`--json`) field are
unaffected — this was a console-rendering-only bug.

## Fixed: Process Injection finding facts now zero-pad virtual addresses

`--hunt injection`'s normal (non-`--verbose`) finding facts rendered
virtual addresses with variable-width hex (`VA=0x270000`), while the same
addresses were already fixed-width, 16-hex-digit values in this same
hunter's own verbose console renderer and structured `HunterRecord`/
`--json` `details` (`HuntPeHeaderHit.va`/`.image_base`,
`HuntRegionRef.base_address`, etc. are all validated as hex-address
strings there). A low address like `0x270000` read as though it might be
truncated next to a `0x00007ff700000000`-shaped address from the same
run, and made cross-referencing a console finding against its own
`--json` record or verbose output unnecessarily error-prone
([issue #31](https://github.com/bitbug0x55AA/dumpex/issues/31)). Some
other hunters' facts (encoding, stomping) still render addresses with
this same variable-width `:x` form -- unaffected by this fix, which is
scoped to `injection.*` findings only.

```
# before
VA=0x270000 AllocationBase=0x270000 size=0xbe000 ... PE_VA=0x278dd0 region_offset=0x8dd0
... declared_image_base=0x140000000

# after
VA=0x0000000000270000 AllocationBase=0x0000000000270000 size=0xbe000 ... PE_VA=0x0000000000278dd0 region_offset=0x8dd0
... declared_image_base=0x0000000140000000
```

Every address-like field in `injection.*` finding facts now goes through
the same `hex_address()` helper the rest of dumpex already used: `VA`,
`AllocationBase`, `PE_VA`, `declared_image_base` (the PE header's own
declared base -- a real address, per `HuntPeHeaderHit.image_base`'s own
docstring, not itself an RVA), thread `StartAddress`, current `RIP`/
`EIP`, and correlated allocation/region addresses. Non-address numeric
fields -- `size`, `TID`, `entrypoint_rva` (an RVA is relative to a
not-yet-established image base, not itself a memory address),
`region_offset` -- are unaffected and keep their existing compact form.

**This is a one-time, expected `Finding.id` change for every
`injection.*` finding whose facts contain an address shorter than 16 hex
digits** (roughly, any process/allocation address below `0x1000000000000000`
under a full 64-bit address space, which in practice is most of them).
`Finding.id` is a hash of the Finding's own content, including `facts`
(see `Finding.id`'s own docstring in `dumpex/hunt/_finding.py`), so this
fix changes those ids even against an unchanged dump. A downstream
consumer that treats Finding IDs as a re-scan dedup/idempotency key will
see affected `--hunt injection` findings as "new" once on upgrade, for a
previously-seen dump; this is expected, not a regression, and does not
indicate a change in what was detected -- re-running affected pipelines'
dedup baselines is the only action needed. No other hunter's Finding IDs
are affected, and `Finding.id`'s hash basis, computation, and format
(`finding-<32 hex chars>`) are unchanged.

**Schema is unaffected** -- this is a text-formatting fix to `facts`
(a free-text string array, not a distinct schema field), not a field
addition, removal, or shape change. The structured, already-fixed-width
address fields (`details.*.region.base_address`, `details.*.va`, etc.)
were correct before this fix and are unchanged by it.

## Cross-hunter coverage gaps keep target identity (schema v2.12)

Every hunter's region/segment scan could report *how many* things failed
to read, read short, or (injection only) hit a scan budget before
finishing -- but not *which* ones. The region/segment's own identity
(base address, size, allocation base, state/type/protection, `.dmp` file
offset) was known at the failure site and then reduced to a count before
it ever reached `coverage.limitations`, so `--hunt all`'s automatic
investigation queue ([schema v2.9](#--hunt-all-automatically-triages-skipped-targets-schema-v29))
only ever picked up oversized-skip targets -- a known unread region could
sit right next to an oversized one without ever becoming an actionable
entry ([issue #28](https://github.com/bitbug0x55AA/dumpex/issues/28)).

```jsonc
// before -- a bare count, nothing to extract/rescan/recollect
{ "code": "PE_HEADER_READ_FAILED", "source": "hidden_pe_scan", "affected_count": 1 }

// after -- the exact region, same shape SCAN_REGION_OVERSIZED_SKIPPED already used
{
  "code": "PE_HEADER_READ_FAILED", "source": "hidden_pe_scan", "affected_count": 1,
  "targets": [{ "kind": "memory_region", "base_address": "0x00007ff000001000",
                "size": 4096, "size_limit": null, "file_offset": 4096,
                "allocation_base": "0x00007ff000000000", "state": "MEM_COMMIT",
                "type": "MEM_PRIVATE", "protection": "PAGE_EXECUTE_READWRITE" }]
}
```

- **`coverageLimitation.targets` is no longer exclusive to
  `SCAN_REGION_OVERSIZED_SKIPPED`.** `PE_HEADER_READ_FAILED`/
  `PE_HEADER_SHORT_READ`/`PE_HEADER_SCAN_TRUNCATED`/
  `PE_HEADER_SCAN_NOT_STARTED` (injection) and `SCAN_REGION_READ_FAILED`/
  `SCAN_REGION_SHORT_READ` (pipe, cs-beacon, yara, obfuscation, and
  stomping's unscored IOC-string scan -- every hunter sharing
  `dumpex.hunt._coverage.CoverageTracker`, plus yara's own equivalent
  target-carrying plumbing) may now carry it too. `targets` stays
  OPTIONAL on these six codes -- a producer that cannot resolve a
  target's identity still emits a bare `affected_count`, exactly as
  before -- but when non-empty, its length must equal `affected_count`
  exactly, same rule `SCAN_REGION_OVERSIZED_SKIPPED` already enforced.
- **New: `PE_HEADER_SCAN_NOT_STARTED`, distinct from
  `PE_HEADER_SCAN_TRUNCATED`.** The whole-hunt hidden-PE scan budget
  (bytes/validations) carries over between regions, so a LATER region can
  start already out of budget -- its search never issues a single read.
  That is a different fact from a region whose OWN search got partway
  through before running out (an unfinished remainder, still
  `PE_HEADER_SCAN_TRUNCATED`): a rescan of a not-started region has to
  start from scratch, not resume a partial one.
- **`scanTarget.size_limit` is now nullable.** A read-failed/short-read/
  scan-truncated/not-started region was never skipped for *being*
  oversized -- the gap is an I/O failure or a scan-budget exhaustion, not
  a size cap it exceeded -- so `size_limit` is `null` for one of these;
  it stays non-null only for an actual oversized-skip target.
- **`--hunt all`'s investigation queue now consumes all six codes**,
  not only `SCAN_REGION_OVERSIZED_SKIPPED`: a region injection failed to
  read and a region pipe skipped for being oversized both surface in
  `result.summary.investigation_actions` and the console's `SKIPPED
  TARGET ACTIONS` on equal footing.
- **`skipRelationship` gains a required `cause`** (`oversized_skipped`/
  `read_failed`/`short_read`/`scan_truncated`/`scan_not_started`).
  `hunter`/`source`/`scope` alone cannot tell these apart -- the same
  scan source can skip different targets for different reasons, and (for
  injection specifically) can even skip the SAME physical region for two
  different reasons across different reads within its own search -- so
  deduplication in the investigation queue now keys on all four
  together, and the same physical region skipped by two hunters for two
  different reasons becomes one queue entry with both relationships and
  both causes retained. `skipRelationship.size_limit` is correspondingly
  nullable, non-null only when `cause` is `oversized_skipped`. Console
  output shows the cause alongside each `Skipped by:` entry.
- **Fixed: a target skipped twice under the same scope no longer looks
  like cross-hunter correlation.** `MULTIPLE_SCOPES_SKIPPED` (one of the
  two priority-boosting signals) is now derived from the count of
  *distinct* `(hunter, source, scope)` triples in `skipped_by`, not from
  `skipped_by`'s own length -- the fix for exactly the case `cause`
  introduces: injection's hidden-PE scan can legitimately report both a
  read failure AND a short read for the SAME region (different reads
  within its own search), which must not be mistaken for two different
  hunters/scopes correlating on that region.
- **Evidence caps are unaffected.** `PE_HEADER_EVIDENCE_CAPPED` (a
  validated hidden PE that WAS found and read, just not retained past
  the evidence cap) still never contributes a queue entry -- that memory
  was examined, unlike a skipped/failed/truncated/not-started target, and
  remains out of scope for this queue by design.
- **`scanTarget` gains `captured_size`/`capture_state`.** `file_offset`
  alone only proves a target's START address is in the dump -- for a
  short-read target specifically, that is not the same claim as "the
  whole requested size is captured". `captured_size` is a STRUCTURAL fact
  from the dump's own segment table (`captured_size` bytes of `size`,
  counting from `base_address`, are actually present), independent of
  whether the failing hunter's own read attempt succeeded; `capture_state`
  (`"none"`/`"partial"`/`"complete"`) is derived from it.
  `evidence_availability` on an `investigation_actions[]` entry gains a
  matching `"partial"` value, and its `recommended_actions` now offers
  BOTH `extract_captured_range` (the real prefix already in hand) AND
  `recollect_dump` (the rest genuinely isn't captured) rather than only
  one of the two.
- **Obfuscation's three scan layers keep separate scoped limitations for
  read-failed/short-read too**, mirroring the per-layer shape
  `SCAN_REGION_OVERSIZED_SKIPPED` already had -- a region all three
  layers (sleep_mask/entropy/decode) fail to read now surfaces as three
  `scope`-tagged limitations, not one that silently merges all three
  layers' attempts into an unscoped target list (the same double-counting
  class of bug the oversized-skip code was fixed against previously).
- **`PE_HEADER_SCAN_TRUNCATED`'s target now names the unexamined
  remainder, not the whole region.** A truncated region's own search may
  already have fully read a real PREFIX of it before the scan budget ran
  out -- reporting the whole region as the gap was inaccurate (part of it
  genuinely came up clean) and would send a targeted rescan back over
  bytes that don't need it; the target's `base_address`/`size` now name
  only `[examined so far, region end)`. `PE_HEADER_SCAN_NOT_STARTED`
  targets are unaffected (nothing was examined, so the whole region is
  already the correct answer).
- **`size_limit` is now cross-validated against the limitation code it's
  attached to**, both in the Python model and the JSON Schema: every
  target on `SCAN_REGION_OVERSIZED_SKIPPED` must have `size_limit` set (an
  oversized skip always has the cap it exceeded), and every target on the
  six read-failed/short-read/scan-truncated/not-started codes must have
  `size_limit: null` (none of those causes involves a cap). Previously
  only `SkipRelationship`'s own separate construction caught a mismatch,
  which meant an invalid `CoverageLimitation` a hunter built directly
  could exist for a while before `--hunt all`'s investigation queue ever
  tried to fold its target into a relationship.
- **Fixed: a validation-budget stop mid-window used to over-claim how much
  of a region was examined.** The hidden-PE scan's candidate search
  advanced `examined_until` to the end of the whole read window (up to
  `PE_SCAN_WINDOW`, 1 MiB by default) *before* validating the candidates
  found inside it -- if the validation budget ran out on the very FIRST
  candidate, the truncated target still reported starting a full window
  past it, silently excluding up to ~1 MiB of genuinely-unvalidated
  memory from the investigation queue. It now advances only as far as the
  last candidate actually finished (validated or confirmed absent), never
  past an unvalidated one.
- **Fixed: the same physical range reported by two different hunters
  under two different `ScanTarget.kind`s used to produce two separate,
  lower-priority investigation actions instead of one.** A
  `memory_region` target (pipe/injection/encoding/stomping) and a
  `memory_segment` target (cs-beacon/yara) naming the identical
  `(base_address, size)` now dedup into ONE `investigation_actions[]`
  entry, correctly triggering `MULTIPLE_SCOPES_SKIPPED`/priority
  escalation. A segment-only group with no matching region-kind target is
  now also enriched with this dump's own MemoryInfo facts
  (type/protection/allocation_base) when a covering region exists in the
  already-passed `memory_regions` list -- previously a bare segment
  target could never carry the exec-signal priority check at all.
- **The hidden-PE scan's own budget attribution is now visible on the
  wire, correctly split per budget.** `PE_HEADER_SCAN_TRUNCATED`/
  `PE_HEADER_SCAN_NOT_STARTED` may optionally set `scope` to WHICH of the
  scan's four independent budgets (`reads_per_region`/`total_bytes`/
  `validations_per_region`/`validations_total`) stopped the affected
  region(s), with `detail` (`"limit=<int> consumed=<int>"`) carrying that
  budget's own configured limit and how much was consumed -- an analyst
  can now tell "raise `PE_SCAN_MAX_VALIDATIONS_TOTAL` and rescan" apart
  from "raise `PE_SCAN_TOTAL_BYTES_MAX` and rescan" instead of only
  knowing *that* something stopped the scan. **Fixed same round:** an
  initial version of this recorded only the FIRST region's own
  attribution for the WHOLE scan, so a later region stopped by a
  DIFFERENT budget within the same run had its target silently
  misattributed to the first budget too (e.g. region 1 truncated by
  `validations_per_region`, region 2 truncated later by
  `validations_total`, both reported under one
  `scope=validations_per_region` limitation). Truncated/not-started
  targets are now grouped by their OWN budget kind, each producing its
  own correctly-scoped `CoverageLimitation`. `size_limit` stays `null`
  throughout, unchanged -- this is a separate axis from "was this target
  oversized."
- **`investigation_actions[].skipped_by[]` now carries the budget's
  numeric limit/consumed as structured fields, not just free text.**
  `SkipRelationship` gains `budget_kind`/`budget_limit`/`budget_consumed`
  -- a JSON consumer previously had to parse `detail`'s "limit=N
  consumed=M" text itself to get a number a targeted-rescan tool could
  act on; it can now read `budget_limit` directly. All three stay `null`
  together for every cause except `scan_truncated`/`scan_not_started`/
  `hit_cap_reached`/`scan_budget_exhausted`.
- **YARA's `YARA_MATCH_FAILED`/`YARA_MATCH_TIMED_OUT` now optionally carry
  `targets` too**, the same segment-identity shape every other
  read-failed/short-read/scan-gap code already has -- a segment a
  `match()` call raised or timed out against is no longer only a bare
  count. Because these two counters count CALLS, not segments (a segment
  failing against two different rule files still counts as 2), a segment
  affected by more than one failing call contributes its target more than
  once, keeping `len(targets) == affected_count` exactly rather than
  silently switching to per-segment counting.
- **YARA's `YARA_HIT_CAP_REACHED`/`YARA_SCAN_BUDGET_EXHAUSTED` and CS
  Beacon's `CS_BEACON_SCAN_BUDGET_EXHAUSTED` now name the segments they
  stopped on too** -- previously fully count-only (or, for CS Beacon,
  reason-text-only), these three codes now optionally carry
  `affected_count`/`targets`: the segment mid-processing when the
  stop happened, plus every later segment in the scan's own segment table
  that never started at all. Segment granularity, not a byte remainder
  (both hunters examine a segment as one atomic unit, unlike injection's
  own byte-wise PE scan). New `SkipCause` values `hit_cap_reached`/
  `scan_budget_exhausted` (the latter shared by YARA and CS Beacon, since
  it is the same underlying fact for both) let these two now flow into
  `--hunt all`'s investigation queue for the first time.
- **Fixed: a configured scan budget of exactly `0` crashed `--hunt all`'s
  investigation queue.** `SkipRelationship.budget_limit`/
  `budget_consumed` required a POSITIVE int, but a scan budget can
  legitimately be configured as `0` (e.g. "no validations at all") --
  reproducible with `PE_SCAN_MAX_VALIDATIONS_TOTAL=0`. Now validated as
  non-negative, matching every other budget-bearing field in this
  feature.
- **Fixed: a whole-scan deadline noticed only after YARA's very last
  (segment, rule_file) pairing, or CS Beacon's very last segment, had
  already finished cleanly used to still downgrade a fully-examined run
  to `INCONCLUSIVE`/`"partial"`.** YARA could name the CURRENT segment as
  an unexamined `YARA_SCAN_BUDGET_EXHAUSTED` target even when that
  segment's own last rule-file `match()` call had already returned
  successfully and was about to be fully processed; CS Beacon's
  `CS_BEACON_SCAN_BUDGET_EXHAUSTED` could fire with an empty `targets`
  list purely because the post-segment deadline recheck happened to land
  after the scan's last segment. Both scanners' `budget_exhausted` (the
  plain boolean) still become `True` in this case, since the wall-clock
  deadline genuinely was exceeded and that remains worth recording at the
  `ScanOutcome` level -- but a `CoverageLimitation` with an empty
  `targets` list is no longer constructed at all, since its mere presence
  (regardless of `affected_count`) was enough to make `coverage.status`,
  the hunter's own `status`, and `verdict_level` report a coverage gap
  that did not exist. A clean run in this exact situation now correctly
  reports `coverage.status: "complete"` and a clean
  `NOT_DETECTED_IN_SCANNED_SCOPE`/no-hit `status`, and the console's own
  "Scan complete" note and `--verbose` reason text no longer claim
  segments were left unscanned. A genuine mid-scan deadline/hit-cap stop
  (a non-empty `targets` list) is unaffected and still correctly reports
  `"partial"`/`INCONCLUSIVE`.
- **Fixed: `budget_consumed` was always populated with the configured
  `budget_limit`, not the real measured consumption.** YARA and CS Beacon
  both increment/accumulate a resource counter (`total_candidates`,
  `total_decoded_bytes`, bytes scanned) *before* checking it against the
  configured cap, so actual consumption at the moment a budget is
  attributed can exceed the limit (e.g. `total_candidates` reaching
  `max_candidates + 1`); wall-clock elapsed time is now measured directly
  rather than assumed to equal the configured `scan_deadline_seconds`.
  `budget_consumed` on `CoverageLimitation`/`SkipRelationship` now
  carries that real value, which may land on either side of
  `budget_limit` -- the two are no longer required to be equal.
- **`CoverageLimitation`/`SkipRelationship` gain dedicated
  `budget_limit`/`budget_consumed` fields, and structured budget
  attribution now extends to YARA's `YARA_HIT_CAP_REACHED`/
  `YARA_SCAN_BUDGET_EXHAUSTED` and CS Beacon's own
  `CS_BEACON_SCAN_BUDGET_EXHAUSTED`.** Both scanners now track WHICH of
  their own independent resource budgets stopped the scan (YARA:
  `max_total_hits`/`scan_deadline_seconds`/`max_total_bytes_scanned`; CS
  Beacon: `scan_deadline_seconds`/`max_total_scanned_bytes`/
  `max_candidates`/`max_decoded_bytes`/`max_hits`) via `scope`, with that
  budget's own configured limit/consumed via the two new fields -- CS
  Beacon's own pre-existing free-text `detail` (its human-readable
  budget_reason) is untouched, since it is a genuinely separate fact
  from the structured kind/limit/consumed. An earlier version of this
  session's own work packed "limit=N consumed=M" text into `detail`
  instead; that broke the moment a code (CS_BEACON_SCAN_BUDGET_EXHAUSTED)
  that ALSO uses `detail` for its own free-text reason needed both at
  once, so injection's own `PE_HEADER_SCAN_TRUNCATED`/
  `PE_HEADER_SCAN_NOT_STARTED` were migrated onto the same two dedicated
  fields for consistency.
- **Finding IDs and scores are unchanged; `status`/`coverage_status`/
  `verdict_level` are corrected, not merely re-labeled.** This is a
  coverage-actionability change: a hunter's own detection EVIDENCE
  (`score`, `matches`/`configs`, Finding IDs) is identical before and
  after. `status`/`coverage_status`/`verdict_level` DO change for the two
  false-`INCONCLUSIVE`/`"partial"` cases fixed above (YARA's last
  pairing, CS Beacon's last segment) -- those were incorrect before this
  fix, not a stable baseline this change preserves.

`dumpex-output-v2.11.schema.json` stays packaged and frozen for
validating output captured before this change.

## Injection: hidden PE headers are searched for throughout memory (schema v2.11)

`--hunt injection`'s hidden-PE check used to read two bytes at each
memory region's own base address and stop there. A structurally valid PE
mapped at a nonzero offset inside a private or unbacked allocation --
loader metadata or padding ahead of the image, several objects in one
allocation, a manual map aligned to nothing in particular -- produced no
finding at all, could not correlate with RWX or live execution in its own
allocation, and left a clean verdict when nothing else fired
([issue #26](https://github.com/bitbug0x55AA/dumpex/issues/26)).

Every eligible region is now searched end to end for candidate `MZ`
headers at every byte offset, and each candidate is structurally
validated where it was actually found.

- **Evidence carries the candidate's own location.** New in
  `schema_version 2.11`: each `huntPeHeaderHit` (the entries of
  `hidden_pe_validated`, `hidden_pe_unvalidated`,
  `suspicious_validated_pe_hits`, `informational_validated_pe_hits`)
  gains a required `va`, `region_offset`, and `file_offset` -- the
  address the header was found at, how far into its region that is, and
  where those bytes sit in the `.dmp` (`null` when the VA is not covered
  by a captured segment). `region` still describes the CONTAINING region,
  and allocation correlation is still keyed on it, so a PE found partway
  into an allocation correlates with RWX and live RIP/EIP in that same
  allocation exactly as a base-address one always did. Console output
  shows the PE's own VA, adding its region base and offset when the two
  differ.
- **Bounded, because a dump is untrusted input.** A region crafted to
  carry `MZ` every other byte cannot dictate how much dumpex reads,
  parses, or reports: the search runs under a whole-run byte budget,
  per-region and whole-run structural-validation budgets, a per-region
  read budget, and separate caps on retained validated and unvalidated
  evidence (validated hits are kept in preference to unvalidated `MZ`
  prefixes, which occur incidentally in ordinary memory).
- **What a budget cut short is never silent.** A region whose search
  stopped early is reported as partial coverage
  (`PE_HEADER_SCAN_TRUNCATED`), alongside the existing failed-read and
  short-read limitations. Validated headers that were found but not
  retained are reported too (`PE_HEADER_EVIDENCE_CAPPED`); dropped
  unvalidated `MZ` candidates are stated with their count on the
  informational check that would have listed them, without marking
  coverage partial.

`dumpex-output-v2.10.schema.json` stays packaged and frozen for
validating output captured before this change.

## `--triage-skipped`: opt-in budgeted deep-content triage (schema v2.10)

Issue #19 Phase 1 (previous entry below) gave `--hunt all` a default,
metadata-only investigation queue for oversized skipped targets — real,
but limited to facts already on hand, with zero additional dump reads.
Phase 2 adds the follow-up piece that entry deliberately deferred: an
explicit, opt-in `--triage-skipped` flag that performs a REAL, budgeted
content read of each queued target, reusing `--report`'s own triage
collector directly (never spawning a second `dumpex` process) under
explicit limits — never the unbounded, up-to-256-MiB-per-region behavior
`--report` itself uses.

```bash
dumpex --hunt all --triage-skipped sample.dmp --json out.json
```

- **Budgeted, not unbounded.** Three independent, fixed limits bound the
  whole pass: a per-target byte cap, a whole-run byte cap, and a maximum
  target count — once either budget is exhausted, every remaining
  (already lower-priority, by construction) target in the queue is marked
  `budget_deferred` rather than silently skipped or silently read past
  the intended cap.
- **`investigation_actions[].triage` becomes real.** Where the metadata
  pass always emits `mode: "metadata"`, `bytes_examined: 0`, a
  `--triage-skipped` run emits `mode: "deep"` with the real outcome:
  `completed` (fully examined), `partial` (the dump had fewer bytes than
  requested — a real evidence gap), `clamped` (deep triage's own budget
  intentionally capped the read), `unreadable` (the read failed), or
  `not_captured` (nothing to read — same meaning as before).
- **New: `triage.content_reason_codes` and `triage.findings`.**
  `content_reason_codes` is a closed, structured summary of what the deep
  read itself found in the examined bytes — an IOC-pattern string match,
  a network-pattern string match, a bare MZ header, and/or an MZ header
  CONFIRMED to sit in unregistered memory (`MZ_HEADER_DETECTED` and
  `INJECTED_PE_HEADER` are independent: the former surfaces even when
  module classification is unavailable, e.g. no `ModuleListStream`).
  `findings` is the bounded (at most 20 entries), structured EVIDENCE
  behind that summary — the actual IOC string text (truncated to 256
  characters — a lead, not the full match) with its address/offset/
  encoding, or the MZ header's own address and module context. Both are
  empty for the metadata pass (nothing was read) and empty for any
  deep-triage outcome that didn't actually complete a read. When a target
  produces more than 20 findings, the array is filled
  representative-first (the MZ finding, then one network-pattern IOC
  finding, then one plain IOC finding, then the rest in offset order) so
  a reason code is never left without any backing evidence just because
  plain IOC hits filled every slot first — `triage.finding_count` reports
  the true total and `triage.findings_truncated` flags when the array
  doesn't carry all of it.
- **Never a verdict.** A deep-triage pass that finds nothing is reported
  as "no generic indicators in examined bytes" — never "clean" — and
  `coverage_effect` stays `"original_hunter_gap_not_resolved"` regardless
  of what the deep read found. A generic content scan cannot substitute
  for the specific hunter logic (pipe/YARA/encoding/etc.) that originally
  skipped the target; only a real targeted rescan of that hunter closes
  its own coverage gap.
- **`chunked_analysis` is now actually emitted** on any target the deep
  pass could not fully examine (`partial`/`clamped`/`budget_deferred`/
  `unreadable`), alongside whatever recommendations the metadata pass
  already produced.
- **Console**: each SKIPPED TARGET ACTIONS entry gains a `Deep triage:
  ...` line, plus a bounded DEEP TRIAGE NOTES block (budget-exhausted /
  read-failed / a one-line run summary) — every word printed is backed by
  a field already in `--json`, same parity rule the rest of this section
  already follows. When a real signal was found, the entry also prints a
  bounded preview of `triage.findings` itself — the actual IOC value/
  address/encoding or the MZ finding's own `module_context`, not just the
  reason-code label — up to 3 entries by default, all retained entries
  (still capped at 20) with `--verbose`. If the read produced more
  findings than the JSON's own 20-entry cap retained, a `Showing 20 of 47
  deep-triage findings.` line appears regardless of `--verbose`, since
  that reflects a data-level truncation, not a console-only one.
  `MZ_HEADER_DETECTED` and `INJECTED_PE_HEADER` each get their own
  distinct, human-readable label — neither prints as the raw enum name.
- **Advisory only, same as Phase 1.** Detection verdicts, hunt summary
  reduction, and exit codes are never changed by `--triage-skipped` —
  confirmed identical to the same run without the flag.
- **No effect outside `--hunt all`.** A single-hunter `--hunt <name>` run
  never has an investigation queue to begin with, so `--triage-skipped`
  is a harmless no-op there.

This is schema v2.10: the only shape change is `triageInfo` gaining the
new, closed-enum `content_reason_codes` array, the new, bounded `findings`
array, and the new `finding_count`/`findings_truncated` fields
(`investigation_actions` itself and everything else are unchanged from
v2.9). Reads correctly regardless of a skipped target's
own kind — including a `memory_segment` target (YARA/CS-beacon's own
oversized-skip targets, which carry no MemoryInfoListStream entry at
all) and a `memory_region` target that only covers part of a larger
MemoryInfo region — by reading from the target's own recorded address
rather than resolving a region first.

See [docs/SOC_QUICKSTART.md](docs/SOC_QUICKSTART.md#skipped-target-investigation-queue-hunt-all)
for the field-by-field reading guide, including how to interpret a
`mode: "deep"` entry.

## `--hunt all` automatically triages skipped targets (schema v2.9)

Issues #16/#17/#18 made partial coverage from oversized skipped
regions/segments *visible* (`targets[]` on `SCAN_REGION_OVERSIZED_SKIPPED`),
but an analyst still had to manually copy each address into `--report
--report-addr`, dedupe overlapping skips across hunters by hand, and
reconstruct priority/next-steps themselves.

`--hunt all` now builds that investigation queue automatically, from data
already collected during the scan — **no additional bytes are read from
the dump.** `result.summary.investigation_actions` is a new array,
deduplicated on the physical region/segment (one entry even when several
hunters or scan layers skipped the same target) and sorted by priority:

```jsonc
{
  "investigation_actions": [
    {
      "target": { "kind": "memory_region", "base_address": "0x00007ff000001000",
                  "size": 16777216, "size_limit": 8388608, "file_offset": 4096,
                  "allocation_base": "0x00007ff000000000", "state": "MEM_COMMIT",
                  "type": "MEM_PRIVATE", "protection": "PAGE_EXECUTE_READWRITE" },
      "skipped_by": [
        { "hunter": "pipe", "source": "pipe_name_scan", "scope": null, "size_limit": 8388608 },
        { "hunter": "obfuscation", "source": "encoding_scan", "scope": "entropy", "size_limit": 10485760 }
      ],
      "priority": "high",
      "priority_reason_codes": ["PRIVATE_EXECUTABLE_MEMORY", "RWX_PROTECTION", "MULTIPLE_SCOPES_SKIPPED"],
      "evidence_availability": "captured",
      "triage": { "mode": "metadata", "status": "completed", "bytes_examined": 0,
                  "region_fully_examined": false },
      "recommended_actions": [
        { "type": "inspect_metadata" },
        { "type": "extract_captured_range" },
        { "type": "targeted_hunter_rescan", "hunters": ["pipe", "obfuscation"] },
        { "type": "preserve_artifact" }
      ],
      "coverage_effect": "original_hunter_gap_not_resolved"
    }
  ]
}
```

- **Two independent priority/evidence axes**, never collapsed into one
  score: `priority` (`low`/`medium`/`high`) comes from deterministic
  MemoryInfo facts (private/executable memory) and cross-hunter
  correlation signals (multiple scopes skipped it, or it coincides with
  an existing `CORRELATED REGIONS` entry); `evidence_availability`
  (`captured`/`not_captured`) only says whether the bytes are already in
  this dump file — a missing capture means "recollect," never "more
  malicious."
- **`recommended_actions` are structured, not prose** — a renderer may
  turn `targeted_hunter_rescan.hunters` plus the target's own
  `base_address`/`size` into a safe command suggestion.
- **Advisory only.** `coverage_effect` is always
  `"original_hunter_gap_not_resolved"`: no score, verdict, coverage
  status, or exit code is ever upgraded because this queue was built.
  Only a real rerun of the specific hunter that skipped a target closes
  its own gap.
- **`--hunt all` only.** A single-hunter run (`--hunt pipe`, ...) always
  reports `investigation_actions: []` — this feature does not change
  single-hunter output.
- **Console**: a new bounded `SKIPPED TARGET ACTIONS` section in the
  `HUNT SUMMARY` card, printed after `CORRELATED REGIONS`. `--verbose`
  only expands how much of each already-computed entry is shown (full
  `skipped_by`/reason/action lists, more entries) — it never changes
  which entries exist, their order, or `--json`, preserving the existing
  rule that console verbosity cannot change structured output.

This is a `--triage-skipped`-free, metadata-only pass by design — a
budgeted, opt-in deep-content triage (reusing `--report`'s own triage
collector under an explicit byte/read budget) is tracked as a follow-up
and is not part of this change.

See [docs/SOC_QUICKSTART.md](docs/SOC_QUICKSTART.md#skipped-target-investigation-queue-hunt-all)
for the full field-by-field reading guide.

## Fixed: truncated hash prefixes were mislabeled `sha256=` in console/fact text

Several console displays truncated a SHA-256 digest to its first 16 hex
characters and appended an ellipsis, but still labeled the value
`sha256=`/`disk_sha256=`/`mem_sha256=` — indistinguishable, at a glance,
from a complete digest suitable for exact verification or copy/paste into
another forensic tool. A 16-hex-character value is only a 64-bit prefix.

Every such display is now labeled with an explicit `_prefix` suffix
instead:

- `--hunt pipe --verbose`'s C2-context lines: `sha256=<16 hex>…` →
  `sha256_prefix=<16 hex>…`.
- Rules-loader announcements (`Rules loaded from ... (sha256=...)`, both
  `--rules-file` and packaged/auto-discovered rules): → `sha256_prefix=`.
- The `stomping.verified_content_change` Finding's `facts` entry:
  `disk_sha256=<16 hex>… mem_sha256=<16 hex>…` →
  `disk_sha256_prefix=<16 hex>… mem_sha256_prefix=<16 hex>…`.

**This is a one-time, expected `Finding.id` change for
`stomping.verified_content_change` findings.** `Finding.id` is a hash of
the Finding's own content, including `facts`, so relabeling that fact
string changes the id of every `stomping.verified_content_change` Finding
this version produces, even against an unchanged dump. No other hunter's
Finding IDs are affected — no other hunter embeds a truncated hash in
`facts`. A downstream consumer that treats Finding IDs as a re-scan
dedup/idempotency key (see `Finding.id`'s own docstring in
`dumpex/hunt/_finding.py`) will see this version's
`stomping.verified_content_change` findings as "new" even for a
previously-seen dump; this is expected, not a regression, and does not
indicate a change in what was detected — re-running affected pipelines'
dedup baselines is the only action needed.

**Schema stays at v2.8** — this is a text/labeling fix, not a field
addition, removal, or shape change. **The complete, untruncated SHA-256
values already exist in structured output and are unchanged**:
`meta.evidence[].sha256`, rule/YARA provenance hashes, and the full
`disk_sha256`/`mem_sha256`/pipe `sha256` fields in each hunter's
structured `details` all remain full 64-hex digests with no truncation —
only the free-text display strings above were mislabeled and are fixed
here.

## Fixed: `--hunt stomping` no longer reports a clean IOC scan over memory it never read

The stomping hunter's IOC-string scan skips executable `MEM_IMAGE` regions
larger than 5 MB — string extraction over a huge mapping is expensive and
can never contribute to the score. Those skips were dropped silently: no
count, no addresses, no coverage record, and the check still printed

```text
[✓] IOC strings in module code regions
    Status : CLEAN — no IOC patterns in executable module memory
```

even when a 40 MB executable mapping had never been looked at. Large
executable regions are exactly where planted strings can hide, so this
read as evidence of absence where there was no evidence at all.

Every otherwise-eligible region skipped for size is now recorded before it
is skipped, with the same `targets` identity every other hunter's
oversized skips carry (VA, size, the 5 MB cap it exceeded, dump-file
offset, allocation base, state/type/protection) under a new
`ioc_string_scan` coverage source:

```jsonc
{
  "code": "SCAN_REGION_OVERSIZED_SKIPPED", "source": "ioc_string_scan",
  "affected_count": 1,
  "targets": [{ "kind": "memory_region", "base_address": "0x00007ff600100000",
                "size": 6291456, "size_limit": 5242880, "file_offset": null,
                "allocation_base": "0x00007ff600000000", "state": "MEM_COMMIT",
                "type": "MEM_IMAGE", "protection": "PAGE_EXECUTE_READWRITE" }]
}
```

- **The check reports `INCOMPLETE`, never `CLEAN`,** when an eligible
  region was skipped or failed to read, and the console names the
  region(s) to follow up on with `--extract`/`--strings` or an external
  scanner.
- **`coverage_status` is `"partial"`** with the skipped regions in
  `coverage.reasons`, and a score-0 run is therefore `INCONCLUSIVE`
  instead of `NOT_DETECTED_IN_SCANNED_SCOPE` — the status/coverage pair
  the output contract requires, and a scan that examined part of its own
  scope is not a clean bill of health. IOC-scan **read failures** were
  already counted on the console but likewise left coverage reading
  `"complete"`; they now downgrade it too.
- **Scores, verdicts, and findings are unchanged.** A verified content
  change still scores and still reports `DETECTED` (with
  `coverage_status: "partial"`), so an oversized region can neither invent
  nor hide a detection; when the IOC lead does fire, its `limitations` now
  say how much of the scope the hit list came from.

## Skipped oversized scan targets are identified, not just counted (schema v2.8)

A hunt that skipped memory for exceeding a scan's size cap used to report
only a tally, which told an investigator the result was incomplete but not
which addresses to act on:

```jsonc
// before (schema v2.7)
{ "code": "SCAN_REGION_OVERSIZED_SKIPPED", "source": "pipe_name_scan", "affected_count": 2 }
```

Every such limitation now carries a `targets` array naming exactly what
was skipped — kind (memory region vs. memory segment), virtual address,
size, dump-file offset, allocation base/state/type/protection where
MemoryInfo is available, and the configured cap the target exceeded:

```jsonc
// after (schema v2.8)
{
  "code": "SCAN_REGION_OVERSIZED_SKIPPED", "source": "pipe_name_scan",
  "affected_count": 1,
  "targets": [{ "kind": "memory_region", "base_address": "0x00007ff000001000",
                "size": 16777216, "size_limit": 8388608, "file_offset": 4096,
                "allocation_base": "0x00007ff000000000", "state": "MEM_COMMIT",
                "type": "MEM_PRIVATE", "protection": "PAGE_EXECUTE_READWRITE" }]
}
```

The gap can now be dispositioned directly: check whether it covers
executable private memory or an ordinary large mapping, run `--extract`/
`--strings` against the address, rescan it with another tool, or decide a
broader recollection is needed. Applies to `--hunt pipe` (regions over
8 MB), `--hunt cs-beacon` and `--hunt yara` (segments over 50 MB), and
`--hunt obfuscation` (sleep-mask/entropy regions over 10 MB, decode
regions over 2 MB).

- **`affected_count` now has one unambiguous meaning** — it equals
  `targets`' length exactly.
- **Console and `--txt`** show a bounded preview (address, size, and the
  limit it exceeded) with `+N more (see coverage.limitations[].targets in
  --json output)` when the list is abbreviated; `--json` always carries
  the complete list.
- **Every other limitation code emits `targets: []`.** A consumer that
  ignores the new key sees the v2.7 shape unchanged.
- **The rendered noun matches what was actually skipped.** `--hunt
  cs-beacon` and `--hunt yara` attach this code to Memory64List/MemoryList
  *segments*, not MemoryInfo regions — the rendered text (both
  `coverage.reasons` and the console verdict line) now says `segment(s)`
  there, not `region(s)`.

### Fixed: `--hunt obfuscation` no longer double-counts skipped regions

Obfuscation runs three region scans with three different size caps
(sleep-mask 10 MB, entropy 10 MB, decode 2 MB) over overlapping candidate
sets, and used to sum their counters into a single `N oversized region(s)
skipped`. One 12 MB private region exceeds all three caps, so that sum
reported **three regions** where there was one. It now emits one
limitation per scan layer, each carrying `scope`
(`sleep_mask`/`entropy`/`decode`), its own targets, and its own
threshold — three region × layer skips over one physical region, which is
what actually happened. Deduplicate on `targets[*].base_address` to count
distinct regions. Coverage status, scores, verdicts, and findings are
unchanged.

`dumpex-output-v2.7.schema.json` stays frozen and installable for
validating output produced before this change; see
[docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md) for the full `scanTarget`
shape.

## CSV output removed

The `--csv` option has been removed. Structured results are now exported
only through `--json`; human-readable output remains available in the
console and through `--txt`. This also removes the CSV conversion layer,
whose nested values were JSON-encoded inside cells and whose single-file
mode concatenated multiple table shapes into one non-standard CSV file.

## `--hunt all` console/`--txt` gains a `CORRELATED REGIONS` section

`--hunt all`'s printed `HUNT SUMMARY` card (and its `--txt` copy) can now
end with a `CORRELATED REGIONS` section, shown after `OTHER HUNTERS` and
before `NEXT INVESTIGATION`: whenever two or more *different* hunters
each produced real, structured evidence that resolves to the exact same
normalized MemoryInfo region (`BaseAddress`/`RegionSize`, half-open
containment), that region's evidence is listed together, region base and
allocation base in dumpex's usual fixed-width hex, hunter verdict badges,
and a short evidence line per hunter. See
[docs/SOC_QUICKSTART.md](docs/SOC_QUICKSTART.md#correlated-regions-console-and-txt-output-only)
for the full read on what this section does and does not mean.

- **Console/`--txt` presentation only.** `--json`,
  `schema_version`, and every finding id are unchanged; no hunter's own
  `score`/`confidence`/`verdict_level`/`coverage` is recomputed or
  affected in any way — co-location is never treated as a scoring
  signal.
- **No re-scan.** The correlation is built entirely from the same
  `HunterRecord`s and the same already-parsed MemoryInfo list `--hunt
  all` already had in hand for this run
  ([`dumpex/hunt/region_correlation.py`](dumpex/hunt/region_correlation.py)).
- **Same allocation is not the same region.** Two MemoryInfo sub-regions
  that only share an `AllocationBase` (routine after a `VirtualProtect`
  split) are never merged into one entry.
- **Omitted when nothing correlates.** A run with no cross-hunter
  overlap prints exactly what it always did — no empty section, no other
  change to `HUNT SUMMARY`.

## `--hunt cs-beacon` structured fields keyed by name (schema v2.7)

`--hunt cs-beacon`/`--hunt all --json`/`--csv` output re-keys each parsed
Cobalt Strike beacon config's `details.configs[*].fields` by field NAME
(e.g. `"BeaconType"`) instead of the raw TLV field ID string (`"1"`), and
drops the now-redundant `name` property from each field's own value — a
consumer no longer needs to already know that field ID 1 means
BeaconType before it can look anything up:

```jsonc
// before (schema v2.6)
"fields": { "1": { "name": "BeaconType", "type": 1, "value": 0 } }
// after (schema v2.7)
"fields": { "BeaconType": { "type": 1, "value": 0 } }
```

An unrecognized field ID still renders as `"field_0xNNNN"`, unchanged.

This is a public-output-only change:

- **Internal parsing, detection, and scoring are unchanged** (console
  DISPLAY changed in two spots — see "Console-only" below). CS Beacon
  config identification, the sanity check, DER public-key validation,
  Malleable C2 instruction decoding, scoring, and status/verdict/
  confidence/findings are all unaffected — the internal parser
  ([`dumpex/hunt/cs_beacon/parser.py`](dumpex/hunt/cs_beacon/parser.py))
  still keys its own field dict by integer field ID
  (`fields[0x0007]["raw"]`); only the value reshaped into the public v2
  record
  ([`dumpex/hunt/cs_beacon/collect.py`](dumpex/hunt/cs_beacon/collect.py)'s
  `_config_dict()`/`_field_dict()`) changed.
- **A name collision fails loudly, not silently.** If a future edit to
  `CS_FIELD_NAMES` ever mapped two different field IDs to the same name,
  `_config_dict()` raises `ValueError` at collect time instead of letting
  the second field silently overwrite the first in the output.
- **`meta.schema_version` moves from `"2.6"` to `"2.7"`** — every
  producer now stamps `"2.7"`. `dumpex-output-v2.6.schema.json` remains
  shipped and installable for validating output produced before this
  change. Unlike the prior (`raw`-removal) bump, this one IS visible as a
  schema `$defs` diff: `configs[*].fields` now structurally rejects the
  old numeric-key/`name`-carrying shape, not just the new shape's own
  documentation.

**Console-only, no schema impact** (two spots share the same new
`_field_display_value()` rendering rule — see
[`dumpex/hunt/cs_beacon/presentation.py`](dumpex/hunt/cs_beacon/presentation.py)):

1. `--hunt cs-beacon --verbose`'s "Full Config Field Table" no longer
   shows the hex field-ID column (redundant once the table is
   name-keyed) and no longer prints a near-duplicate raw-hex preview
   alongside `value` for binary fields (e.g. PublicKey used to show
   almost the same hex string twice, in two different formats).
2. The "Process Injection" inline section (`ProcInject_Transform_x86`/
   `ProcInject_Transform_x64`, and any other type-3 field in that group)
   now uses the SAME rendering rule, replacing its own, slightly
   different prior logic — this is a real, visible change to that
   section specifically, not merely a side effect of the field-table
   cleanup:
   - a printable value now prints as `repr(value)` (quoted, escape
     sequences visible) instead of the bare decoded string — deliberate:
     tab/CR/LF count as "printable" for a type-3 field, and an
     unescaped embedded newline previously broke the one-field-per-line
     layout;
   - a binary value now always shows a truncated hex encoding of the
     field's FULL raw bytes (64 hex chars, `...` if longer) instead of
     the previous `raw.hex()[:60]` fallback (only reached when the
     decoded/stripped text was empty, no truncation marker, 60 not 64
     chars) — trailing NUL bytes, previously stripped from what small
     amount was shown, are now included in that hex (truncation-permitting).

Both spots show `value`/`raw` exactly once, never a value alongside a
separate raw-hex preview that says the same thing. Console output was
never part of any `schema_version` contract, so none of this needed a
version bump.

See [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md#hunt-records) for the
full versioning rationale.

## `--hunt cs-beacon` structured fields drop raw hex bytes (schema v2.6)

`--hunt cs-beacon`/`--hunt all --json`/`--csv` output no longer includes a
`raw` field on `details.configs[*].fields[*]` for each parsed Cobalt
Strike beacon config TLV field. PublicKey, Malleable C2, and
inject-transform fields could carry very long hex strings there,
degrading JSON, CSV, and any downstream tool's display for no benefit —
`value` already carries the same field's decoded (or hex-rendered, for
non-printable `bytes` fields) content. Each field entry now carries only
`name`, `type`, and `value`.

This is a public-output-only change:

- **Internal parsing and console behavior are unchanged.** CS Beacon
  config identification, the sanity check, DER public-key validation,
  Malleable C2 instruction decoding, scoring, status/verdict/confidence,
  findings, and both normal and verbose console output are all
  unaffected — the internal parser
  ([`dumpex/hunt/cs_beacon/parser.py`](dumpex/hunt/cs_beacon/parser.py))
  still returns `raw` as `bytes` on its own internal field dicts, and DER
  validation / instruction decoding still consume it directly.
- **`meta.schema_version` moves from `"2.5"` to `"2.6"`** — every producer
  now stamps `"2.6"`. `dumpex-output-v2.5.schema.json` remains shipped and
  installable for validating output produced before this change; it still
  describes `configs[*].fields[*]` as carrying `raw`.

See [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md#hunt-records) for the
full versioning rationale.

## `--hunt` findings now carry a normalized-SIEM-alert shape (schema v2.5)

Every entry in a hunter's `findings[]` array (`--hunt --json`/`--csv`)
now carries seven additional fields, so one finding can be consumed
directly as a SIEM alert instead of first being hand-mapped onto one:

- `id` — deterministic, stable across repeated `--hunt` runs against the
  same dump (a 128-bit hash covering check/rule id/rule version/tag/
  confidence/technique ids/evidence refs/iocs/facts, unambiguously
  encoded) — a re-scan dedup key for that dump; combine with
  `meta.evidence[].sha256` for a key unique across dumps.
- `severity` — `info`/`low`/`medium`/`high`/`critical`, always derived
  from `tag`+`confidence` — a producer cannot set it independently, and
  the schema itself pins the exact mapping.
- `technique_ids` — MITRE ATT&CK IDs, populated where a hunter has a real
  mapping (today: `pipe`'s own `rules.yaml`-driven framework matches).
- `evidence_refs` — structured pointers into that hunter's own `details`.
- `iocs` — indicator-of-compromise values extracted from this finding.
- `rule_id` / `rule_version` — detection-logic provenance.

`meta.schema_version` moves from `"2.4"` to `"2.5"` — every producer now
stamps `"2.5"`. `dumpex-output-v2.4.schema.json` remains shipped and
installable for validating output produced before this change; it does
NOT accept these seven new `finding` properties (a closed `finding` $def
must never silently start accepting fields it didn't originally define).
See [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md#hunt-records) for the
full field table and versioning rationale, and
[docs/SOC_QUICKSTART.md](docs/SOC_QUICKSTART.md#reading-a-finding) for
the analyst-facing explanation.

## `--diff` now treats the positional dump as the analysis target

For `dumpex suspect.dmp --diff clean-reference.dmp`, `suspect.dmp` is now
the target and `clean-reference.dmp` is the baseline. Console additions,
new threads, and protection changes therefore describe the suspicious
dump relative to the reference. Structured output follows the same rule:
`meta.evidence[target]` points to the positional dump and
`meta.evidence[baseline]` points to the `--diff` argument.

The comparison filter is now shown in help as `--diff-scope` to make clear
that it is an optional modifier, not a second comparison command. The old
`--diff-mode` spelling remains available as a hidden compatibility alias.

CLI help is now grouped by purpose (commands, memory/extraction, string
scanning, diff, display, hunt, report, and output/case metadata) instead of
placing every flag in one undifferentiated list. The string encoding filter
is now shown as `--strings-encoding`; the older `--encoding` spelling remains
available as a hidden compatibility alias.

## `--hunt` output migrated to the v2.4 contract

`--hunt` was the last command still writing the older v1.1 JSON contract.
It has now moved onto the same v2.4 envelope every other command
(`--list`, `--modules`, `--threads`, `--pid`, `--sysinfo`, `--peb`,
`--diff`, `--extract`, `--strings`, `--report`) already uses. **`--hunt`
no longer produces v1.1 output at all** — every `--json`/`--csv` result it
writes now stamps `schema_version: "2.4"`.

If you have automation (a SIEM/SOAR integration, a parsing script, a case
management hook) that reads `dumpex --hunt ... --json`, it needs to be
updated for this release. The `dumpex-output-v1.1.schema.json` file is
still shipped (wheel, sdist, and the Windows EXE bundle) so existing
archived v1.1 results can still be validated, but no command produces
that shape anymore.

### JSON: root structure change

**v1.1** (old): a bare top-level `hunt` object, keyed by hunter name:

```json
{ "meta": { "schema_version": "1.1", ... },
  "hunt": { "pipe": { "score": 3, "status": "DETECTED", "coverage_status": "complete", ... },
            "stomping": { "score": 0, "status": "INCONCLUSIVE", "coverage_status": "partial", ... } } }
```

**v2.4** (current): the same shared envelope every other command uses —
`result.kind == "hunt"`, and each hunter is now one entry in
`result.data.records[]`, discriminated by its own `hunter` field. The
former bare `coverage_status`/`coverage_reasons` strings are now a
structured `coverage` object (`coverage.status`/`coverage.reasons`, plus
new `coverage.sources`/`coverage.limitations` detail) on each record,
*and* rolled up across every selected hunter into `result.coverage.status`
(see [Exit codes](#exit-codes-for---hunt-are-no-longer-always-0) below).
A new `result.summary` object (`selected`, `hunter_count`,
`detected_count`, `inconclusive_count`, `not_evaluated_count`,
`overall_status`, `highest_verdict_level`, `lead_count`) replaces the
console-only summary table as a machine-readable cross-hunter rollup:

```json
{ "meta": { "schema_version": "2.4", ... },
  "result": {
    "kind": "hunt",
    "coverage": { "status": "partial", "reasons": [...] },
    "summary": { "selected": "all", "hunter_count": 7, "detected_count": 1, ... },
    "data": { "records": [
      { "hunter": "pipe", "score": 3, "status": "DETECTED",
        "coverage": { "status": "complete", "reasons": [] }, "findings": [...], "details": {...} },
      { "hunter": "stomping", "score": 0, "status": "INCONCLUSIVE",
        "coverage": { "status": "partial", "reasons": [...] }, "findings": [], "details": {...} }
    ] }
  } }
```

`meta.evidence` also changed shape: it's now an array (`role: "primary"`
for `--hunt`'s single dump) rather than a bare object, matching every
other command — see docs/OUTPUT_SCHEMA.md for the full `meta` shape.

### CSV: table changes

`--csv` for `--hunt` now writes the same table-per-shape convention every
other v2 command uses, instead of its old bespoke layout:

- `summary` — one row: `kind`/`execution_status`/`coverage`/record count.
- `hunters` — one row per hunter (`status`/`score`/`coverage_status`/
  `verdict_level`/`confidence`/... — the judgment fields every hunter
  carries).
- `findings` — one row per structured `Finding`, across every hunter
  (empty for `yara`, which has none).
- Per-hunter evidence tables, populated only for hunters that produce
  that kind of evidence: `injection_evidence`, `stomping_changes`,
  `pipe_evidence`, `beacon_configs`, `yara_matches`, `obfuscation_hits`.

A CSV consumer keyed on the old single-table `--hunt` layout will need
updating to read from these tables instead.

### Exit codes for `--hunt` are no longer always `0`

`--hunt` previously always exited `0` regardless of what it found or
whether it could fully evaluate the dump. It now uses the same
coverage-based exit code every other v2-routed command uses, derived from
`result.coverage.status`:

| Exit code | `result.coverage.status` | Meaning |
|---|---|---|
| `0` | `complete` | Every selected hunter's evidence was fully covered |
| `3` | `partial` | At least one selected hunter had a coverage gap (unreadable stream, missing `--ref-dir`, a scan budget hit, ...) |
| `4` | `not_evaluated` | No selected hunter could evaluate at all |

This is independent of `--json`/`--csv` being requested at all — a bare
`dumpex sample.dmp --hunt all` now exits `0`/`3`/`4` accordingly, so a
script checking `$?` can detect incomplete coverage without parsing JSON.
It's also independent of whether anything was *detected* — exit code
tracks coverage completeness, not verdict severity.

### Windows EXE release bundle now ships the current schema

The downloadable Windows EXE release bundle (`dumpex-vX.Y.Z-windows-x64.zip`)
previously only included `dumpex-output-v1.1.schema.json` — stale from
before this migration, and not the contract `--hunt` (or any other
command) actually produces. The bundle now includes every packaged
`dumpex-output-v*.schema.json` file (current v2.4 plus the frozen
historical v1.1/v2.0/v2.1/v2.2/v2.3 files), matching what `pip install
dumpex` already ships.

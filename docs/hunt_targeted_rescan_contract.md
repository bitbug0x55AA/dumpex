# Hunt targeted-rescan contract (issue #59)

**Status: frozen decision record — self-contained.**

Parent: #58 (targeted-rescan delivery tracker). Blocked by: #44 (closed).
Blocks #60 (neutral virtual-address/capture-range primitives) and,
transitively, #61 (`HuntRequest`/`HuntExecutionContext`/
`ObservationRegistry` convergence), #62/#63/#64 (scanner adapters), #65
(atomic CLI/schema cutover), and #66 (investigation-action wiring and
final QA). This document **adds no production code** — it is the matrix
and rule set those six issues implement against and verify against,
exactly as `docs/hunt_analyzer_registry_contract.md` (issue #70) is for
#71/#72/#73, and as `docs/recon_profile_contract.md` (issue #95) was for
#43. Every fact below is read off the current tree (`dumpex/cli.py`,
`dumpex/hunt/*/report_facts.py`, `dumpex/hunt/*/config.py`,
`dumpex/hunt/_investigation.py`, `dumpex/output/coverage.py`,
`dumpex/output/records.py`, `dumpex/output/envelope.py`,
`dumpex/core/memory.py`, `dumpex/core/pe_utils.py`) — where a decision
genuinely belongs to a later issue (#60's own `Range`/`CapturedRange`
Python type, #61's `HuntRequest`/`HuntExecutionContext` shape, #65's
literal schema-file diff), this document says so explicitly instead of
guessing at their shape.

This document is a **companion** to #70's `hunt_analyzer_registry_contract.md`,
not a competitor to it: #70 froze `TargetedScanUnit` and the
`TargetedGrant`/`TargetedCapability` value objects but deliberately left
every analyzer's `grants` field empty, stating "#59 decides the grant's
contents" (#70 §0.2, §1, §5 field 10). §4 below is that decision. Nothing
here renames, replaces, or re-shapes `TargetedScanUnit`, `TargetedGrant`,
or `TargetedCapability` — it only supplies the field values #70 reserved.

---

## Table of contents

- §0 Scope, non-goals, and dependency order
- §1 Vocabulary
- §2 CLI contract: `--hunt-addr` and targeted `--size`
- §3 Range semantics: half-open range and checked 64-bit arithmetic
- §4 The five-row targeted-capability matrix
- §5 Budget semantics: bypassed cap vs. retained budgets
- §6 Evidence and coverage semantics
- §7 Output shape: console, JSON, and CSV
- §8 Diagnostics, ordering, and exit-code behavior
- §9 CLI failure behavior
- §10 Compatibility considerations
- §11 Acceptance gate

---

## §0 Scope, non-goals, and dependency order

### 0.1 What this contract covers

1. The exact CLI grammar for a targeted single-hunter scan, its required-
   together arguments, its accepted value shapes, and every validation
   failure's shape and exit behavior — §2, §9.
2. The half-open virtual-address range `[addr, addr + size)`, its checked
   64-bit arithmetic, and what "chunk" means when a hunter's normal
   region/segment reader is pointed at a requested range instead of a
   `MemoryInfo` region or scanned segment — §3.
3. One row per targeted-capable analyzer, populating #70's
   `TargetedCapability.grants` with the real `TargetedGrant(source, scopes)`
   values, and restating (not re-deciding) that `injection`/`hollowing`
   keep `targeted_capability=None` — §4.
4. Exactly which per-target size cap a targeted invocation bypasses, and
   the closed list of every other budget that stays enforced, per hunter
   — §5.
5. Closure identity, `NOT_DETECTED_IN_SCANNED_SCOPE`, explicit-gap
   semantics, cross-boundary-signature handling, and stomping's
   source-independence rule — §6.
6. What a targeted invocation's console text, JSON document, and CSV
   export must contain — reusing existing schema surface wherever it
   already suffices, and freezing the exact shape of the one new,
   declared schema field it does not — §7.
7. Ordering and exit-code behavior for a targeted invocation — §8.
8. The checklist #60/#61/#62/#63/#64/#65/#66 must each satisfy without
   inventing new public semantics — §11.

### 0.2 Non-goals (frozen)

- **No production CLI wiring.** `--hunt-addr` is not added to
  `dumpex/cli.py`'s `argparse` setup by this issue — #65 does that, atomically,
  at the public cutover. This document fixes the flag's name, placement,
  validation, and error shape so #65 implements against a decided
  contract instead of inventing one under cutover time pressure.
- **No `Range`/`CapturedRange` Python type.** #60 owns the actual
  immutable virtual-address-range and captured-range-slicing primitive.
  §3 freezes only the *semantics* that primitive must satisfy (half-open
  bounds, checked-arithmetic overflow behavior, one canonical
  `_UINT64_MAX`) — not its module location, its field names, or its
  slicing API.
- **No `HuntRequest`, `HuntExecutionContext`, or `ObservationRegistry`
  implementation.** #61 owns those, converging this contract's grant
  matrix (§4) with #60's range primitive into an invocation-local object
  graph. This document supplies the two things #61 needs as fixed inputs
  — the populated grant matrix (§4) and the closure-identity tuple shape
  (§6.1) — without prescribing how #61 stores or threads them.
- **No scanner-adapter changes.** Nothing in `dumpex/hunt/pipe/`,
  `stomping/`, `yara_hunt/`, `cs_beacon/`, or `encoding/` changes here.
  #62/#63/#64 adapt each hunter's own region/segment/layer reader to
  accept a requested range in place of a `MemoryInfo` region — this
  document fixes what that adapter must guarantee (§3.3–§3.6, §5), not
  how it is wired into each package.
- **No schema-version cutover.** v2.13 remains frozen per #44. The public
  schema version for the targeted-scan cutover is selected only at #65's
  atomic cutover (tentatively v2.14 if no earlier public schema lands, per
  #58's own compatibility considerations) — this document's §7 JSON shape
  is the target #65 cuts over *to*, not a schema-file diff itself.
- **No change to full-scope (`--hunt <identity>` / `--hunt all`) behavior,
  scoring, Finding IDs, ordering, console output, JSON output, or exit
  codes — genuinely none, not merely a disclosed exception.** Two earlier
  drafts of this bullet each accepted a full-scope JSON delta (an
  always-present, `null`-on-full-scope `targeted_scope` key) as a
  necessary cost of discriminating a targeted result from a full-scope
  one, and spent real effort making that delta *survivable* (golden-
  fixture regeneration, schema `required`-list additions). That effort
  was solving the wrong problem: **`targeted_scope` (§7.2) is present in
  the JSON `details` object if and only if the invocation was targeted —
  omitted entirely, not present-and-`null`, for every full-scope
  result.** JSON Schema already supports this exactly: the five
  targeted-capable hunters' own `*Details` schema `$def`s gain
  `targeted_scope` in `properties` **but not in `required`**, and each
  dataclass's own `to_dict()` includes the key only when the invocation
  actually produced closures (`if self.targeted_scope is not None:
  d["targeted_scope"] = [...]`, never an unconditional `d["targeted_scope"]
  = self.targeted_scope`). A full-scope `--hunt`/`--hunt all` result's
  `details` dict is therefore **byte-for-byte identical** to today's
  output — no golden-fixture regeneration, no schema `required`-list
  change for any existing consumer to notice, no version-gated behavior
  change of any kind. `targeted_scope`'s presence, not any value it
  might hold, remains the discriminator §7.2 needs — this is *stronger*
  than the null-based design, not merely different, since a consumer
  checking `"targeted_scope" in details` never needs to also check
  whether the value is `null` versus a real list.

  This also means §65's own schema/CLI cutover carries **no forced
  full-scope compatibility work** for this field specifically — but it
  still lands only at #65's own schema-version cutover, never inside the
  v2.13 schema file itself. An earlier draft of this paragraph floated
  landing it "in principle" inside the still-frozen v2.13 schema as an
  optional, unused property, reasoning that nothing full-scope would
  break — that reasoning is correct about compatibility but wrong about
  scope: it contradicts this section's own opening line ("v2.13 remains
  frozen") and §10's "historical schemas remain frozen — nothing here
  retroactively reshapes a v2.13 or earlier document," neither of which
  carves out an exception for an additive, currently-unused property.
  "Frozen" means the v2.13 schema *file* does not change at all, for any
  reason, not merely that its meaning stays backward-compatible.
  `targeted_scope` (and every other new surface this contract defines —
  `--hunt-addr`, `TARGETED_SOURCE_NOT_EVALUATED`, §8) lands exclusively
  in whichever schema version #65's own cutover selects (§0.2's
  schema-version bullet above) — never as a retrofit to v2.13.
- **No investigation-action / copyable-command wiring.** #58's "the
  investigation queue should eventually render one copyable targeted
  command per supported skipping hunter" is #61/#66's job. This document
  only guarantees the CLI grammar (§2) and closure identity (§6.1) that
  such a rendering would need to already exist and be stable — plus
  §5.8's frozen policy for an oversized original target (one capped,
  explicitly partial/supplementary command, `coverage_effect` left
  unresolved, no chunking plan that implies closure) — this is not a
  design choice left open for #66, only a rendering left for #66 to
  implement. §3.6 adds exactly one concrete obligation to that same #66
  bucket, stated there and restated in §10: the
  `_TARGET_BEARING_LIMITATION_CAUSES` entry for
  `SCAN_REGION_EVALUATION_TRUNCATED` **plus** the queue-reachability gate
  it needs to fire at all (`build_investigation_queue()` runs today only
  for `selected == "all"`, `hunt/__init__.py:82-84`, `:291`+`:310`, which
  no targeted invocation ever is) and the output-contract consequence that
  `summary.investigation_actions` stops being unconditionally `[]` for a
  single-hunter run. That is an addition to #66's scope, deliberately kept
  out of #65's — #65 registers the two new `LimitationCode`s themselves
  (§8), it does not touch the queue.
- **Does not fix the pre-existing gap** (found during this contract's own
  research, §5.6) that pipe's and obfuscation's generic
  `SCAN_BUDGET_EXHAUSTED` limitations carry no `ScanTarget` today (only
  `YARA_SCAN_BUDGET_EXHAUSTED`/`CS_BEACON_SCAN_BUDGET_EXHAUSTED` are
  target-bearing, per `_investigation.py`'s
  `_TARGET_BEARING_LIMITATION_CAUSES` map) — that remains a pre-existing
  fact, not a defect this issue authorizes fixing.

### 0.3 Dependency order

```text
Recon QA #44 (closed)
  |-> #59 (this contract) -> #60 (range/capture primitives) --|
                                                                |-> #61 -> #62 -> #63 -> #64 -> #65 -> #66
  |-> #70 -> #71 -> #72 -> #73 -------------------------------|
```

#59's own output (§4's populated grant matrix, §2's CLI grammar, §6's
closure identity) is the fixed input #60 designs its range primitive
against and #61 later converges with #70–#73's static registry branch.
Both branches must converge before #61, exactly as #70 §0.3 already
states from the registry side.

---

## §1 Vocabulary

Terms already frozen by #70 §1 (`TargetedScanUnit`, `TargetedGrant`,
`TargetedCapability`, "targeted capability") are reused here verbatim,
not redefined. New or narrowed terms for this contract:

- **Targeted invocation** — a single `dumpex <dump> --hunt <identity>
  --hunt-addr <address> --size <size>` run, as opposed to a **full-scope
  invocation** (`--hunt <identity>` or `--hunt all` without `--hunt-addr`).
  A targeted invocation always selects exactly one `identity` (§2.2) —
  there is no targeted analog of `--hunt all`.
- **Requested range** — the half-open `[addr, addr + size)` an
  investigator supplies. Distinguished from a **region** (a `MemoryInfo`
  entry) and a **segment** (a contiguous captured byte run, §0's
  `TargetedScanUnit` vocabulary) because a requested range need not equal
  either — it is typically a strict sub-range of the region/segment whose
  own size cap caused the original skip (§3.4).
- **Grant** — one `TargetedGrant(source, scopes)` value from #70's own
  type (§1 there), now populated per analyzer in §4 below. "Granted
  source/scope" means a `(source, scope)` pair present in an analyzer's
  `TargetedCapability.grants`, checked the same way #70 §6's
  `select_targeted()` pseudocode already specifies.
- **Closure** / **closure identity** — the tuple `(hunter, source, scope,
  base_address, size)` that identifies one targeted invocation's evaluated
  scope, per #58's own "Evidence and coverage semantics" section. Frozen
  precisely in §6.1. One targeted invocation produces **one closure per
  granted scope it actually attempts** — exactly one for
  `pipe`/`stomping`/`yara`/`cs-beacon` (§4.1's empty-`scopes` grants), and
  exactly three (one per `OVERSIZE_SCAN_LAYERS` member, always all three,
  §4.2) for `obfuscation` — never a single closure covering multiple
  scopes at once, and never a partial subset of `obfuscation`'s three.
- **Bypassed cap(s)** — the **closed set** of per-region/per-segment/
  per-layer size constants (§5) a targeted invocation skips for the
  requested range only, per granted scope. This is exactly one constant
  for four of the five granted sources/scopes — `pipe_name_scan`
  (`PIPE_SCAN_MAX`), `ioc_string_scan` (`IOC_SCAN_MAX`), `yara`/`cs-beacon`
  `segment_scan` (their own `MAX_SEG_SCAN`), and each of `obfuscation`'s
  `sleep_mask`/`entropy` layers (`SLEEP_MASK_REGION_MAX`/
  `ENTROPY_SCAN_MAX`) — but **exactly two** for `obfuscation`'s `decode`
  layer: `DECODE_SCAN_MAX` **and** `XOR_SCAN_MAX` (§5.5's own correction —
  `decode`'s structural-XOR sub-scan has a second, independent, narrower
  per-region cap that must be bypassed alongside the general one, or the
  bypass is incomplete for that one layer). An earlier draft of this
  vocabulary entry, the §5.5 matrix footnote, and §11's own acceptance
  bullet all said "one bypassed cap" or "the single per-target cap"
  uniformly — each is corrected to say "closed set," with `decode` as the
  one documented two-member case, so no later implementer reads any of
  the three in isolation and bypasses only `DECODE_SCAN_MAX`.
  **Retained budget** — every other resource limit (time, total bytes,
  candidates, matches, decode output, retained evidence) that stays
  enforced exactly as in a full-scope run (§5).
- **`NOT_DETECTED_IN_SCANNED_SCOPE`** — not a new value. Reuses the
  existing `_HUNT_STATUSES` member and `_ui.py:23-34` label/color
  ("ran to completion, found nothing") verbatim, produced by the same
  `derive_status()`/`derive_coverage_status()` reduction
  (`dumpex/hunt/_coverage.py:24-32`) a full-scope run already uses. §6.2.
- **Explicit gap** — a coverage shortfall reported through the existing
  `SkipCause` vocabulary (`dumpex/hunt/_investigation.py:85-103`:
  `oversized_skipped`, `read_failed`, `short_read`, `scan_truncated`,
  `scan_not_started`, `match_failed`, `match_timed_out`, `hit_cap_reached`,
  `scan_budget_exhausted`) — no new `SkipCause` value is introduced for
  targeted mode (§6.3). This contract does add exactly **two** new
  `LimitationCode`s — `TARGETED_SOURCE_NOT_EVALUATED` (§6.7, §8: gate
  1/gate 2 failed entirely, `absent_capable`) and
  `SCAN_REGION_EVALUATION_TRUNCATED` (§3.6, §8: evaluation stopped at a
  descriptor boundary while capture continued, `caller_buildable`) — a
  distinct, closed vocabulary from `SkipCause`; the "no new cause value"
  guarantee above is about `SkipCause` specifically, not a claim that
  `LimitationCode` is entirely unchanged. This is the single place that
  fact is recorded — §3.6, §6.7, and §8 all reference it from here rather than
  each maintaining an independent count.
- **Cross-boundary signature** — a match or decode candidate whose
  reported location or extent falls partly or wholly outside the
  requested range. §6.4 defines how these are handled.

---

## §2 CLI contract: `--hunt-addr` and targeted `--size`

### 2.1 Grammar

```text
dumpex <dump> --hunt <identity> --hunt-addr <address> --size <size>
```

`identity` is exactly one of the five approved targeted-capable
identities (§4): `pipe`, `stomping`, `cs-beacon`, `yara`, `obfuscation`.
No other value of `--hunt` may be combined with `--hunt-addr` (§2.2).

### 2.2 Flag placement and reuse

- **`--hunt-addr`** is a **new** flag, following the existing
  `--report-addr` precedent (`cli.py:190`, a sibling modifier flag next to
  its mode flag, `metavar='ADDR'`, dest `hunt_addr`) rather than the
  `--extract ADDR`/`--strings ADDR` precedent (where the address is the
  mode flag's own value) — `--hunt`'s own value is already the hunter
  identity (`metavar="TTP"`, `cli.py:130`), so it cannot also carry the
  address. `--hunt-addr` belongs in the same non-mutually-exclusive
  argument group as `--size` (`region_group`, `cli.py:132-138`, "memory
  and extraction options"), never in the `mode` mutually-exclusive group
  (`cli.py:114-116`: `command_group = parser.add_argument_group(...)`,
  `mode = command_group.add_mutually_exclusive_group(required=True)`) —
  it is a modifier of `--hunt`, not a mode selector of its own.
- **`--size`/`-s`** is **reused**, not duplicated. It is the same flag
  `--extract`/`--strings` already share (`cli.py:135-136`,
  `region_group.add_argument("-s", "--size", metavar="SIZE", ...)`),
  parsed by the same `parse_hex_or_int()` (`dumpex/core/memory.py:39-40`:
  `0x`-prefixed hex or decimal). This is #58's own instruction ("existing
  `--size` behavior belongs to extract/strings") read correctly: the
  *flag* is shared across commands, its *requiredness* is per-command —
  extract/strings already auto-derive a missing `--size` from the
  containing region via `_resolve_size()` (`memory.py:1211-1226`, capped
  at `MAX_REGION_READ = 256 MiB`, `memory.py:1200`); a targeted hunt does
  **not** get that auto-derive fallback (§2.3), and — new in this
  contract, §2.4 — does not get extract/strings' own "explicit `--size`
  is never clamped" policy either.

### 2.3 Required-together rule

`--hunt-addr` and `--size` are **required together** for a targeted hunt,
exactly as #58 states. Concretely:

- `--hunt-addr` present, `--size` absent → validation failure (§9.1, not
  §9.2 — this is a pure argument-shape problem, detectable before any
  dump is opened, the same category as every other §9.1 bullet): a
  targeted hunt's range is deliberate investigator-supplied scope, never
  inferred the way extract/strings' region-derived default is
  (`memory.py:1200-1208`'s own comment on `MAX_REGION_READ`: "An explicit
  `--size` is deliberate user intent and is NOT clamped here" — a
  targeted hunt's `--size` must be **present**, not merely
  *un-clamped-when-present*).
- `--size` present, `--hunt-addr` absent, `--hunt` also present → **no
  change to today's behavior, and not a failure at all** (§9 restates
  this explicitly to avoid ambiguity with §9.1's own required-together
  bullet, which runs in the other direction only): this is an ordinary
  full-scope hunt invocation that happens to also pass `--size`. Today,
  `--size` only takes runtime effect for `--extract`/`--strings`, inside
  `_run()` (`cli.py:454-464`: `parse_hex_or_int(args.size) if args.size
  else None`, then `_resolve_size()`) — `--hunt`'s own `_run()` branch
  never reads `args.size` at all, and `_build_options()`
  (`cli.py:292-316`) does not record a `size` option key for *any* mode
  today, `--hunt` included. This document does **not** change any of
  that for a full-scope invocation — `--size` without `--hunt-addr`
  remains exactly as inert for `--hunt` as it is today.
- Both present, but `--hunt all` or `--hunt` absent → validation failure
  (§9.1/§9.2, distinguished by cause).

### 2.4 Address and size value shapes

- `--hunt-addr` accepts exactly the same value shape `--size` already
  does: `0x`-prefixed hex or plain decimal, parsed with the identical
  `parse_hex_or_int()` (`memory.py:39-40`) — no new parser. Unlike
  `--size`, `--hunt-addr` may parse to a mathematically negative Python
  `int` if given a bare negative decimal (`parse_hex_or_int()` places no
  floor on its own) — §3.2 below closes this, since a negative address is
  not a valid 64-bit virtual address regardless of whether `addr + size`
  happens to overflow.
- `addr` must satisfy `0 <= addr <= _UINT64_MAX` (§3.2) — checked
  independently of the `addr + size` overflow check below, precisely
  because a value such as `addr = -1, size = 2` produces `end = 1`, which
  is neither negative nor `> _UINT64_MAX` and would otherwise pass an
  end-only check while `addr` itself is not a real address.
- `size` must be a **positive** integer. Unlike today's `--size` for
  extract/strings (which relies implicitly on `int()`'s own parse errors
  and never explicitly rejects zero/negative, per this contract's own
  research of `cli.py:457,464`), a targeted hunt's `--size` is explicitly
  validated `> 0` — a zero- or negative-size targeted scan has no
  half-open range to describe and is rejected before any dump is opened
  (§9.1).
- `end = addr + size` must not exceed `2**64` (§3.2) — the half-open
  upper bound is permitted to equal `2**64` exactly (one past the last
  representable 64-bit address, `_UINT64_MAX + 1`), since `end` is never
  itself dereferenced; it must not exceed it. Overflow is a validation
  failure (§9.1), not a silently wrapped or truncated range.
- `size` must not exceed the applicable ceiling — `TARGETED_HUNT_MAX_REQUEST_BYTES`
  (256 MiB, §5.7) for `pipe`/`stomping`/`yara`/`cs-beacon`, or the lower
  `TARGETED_OBFUSCATION_MAX_REQUEST_BYTES` (32 MiB, §5.5) when `identity
  == "obfuscation"`. Both exist specifically to keep an explicit
  `--hunt-addr`/`--size` request from becoming the "unbounded-work
  switch" #58's own resource constraints forbid — §5.7 explains why the
  per-hunter budgets in §5.2–§5.6 do not, by themselves, bound the cost of
  an arbitrarily large requested range, and §5.5 explains specifically
  why `obfuscation` needs a lower ceiling than the other four. This is
  the one point in §2 where CLI validation depends on which identity was
  selected, not a hunter-independent check — `--hunt-addr`/`--size`'s
  other validations (§2.3, §3.2) apply identically regardless of
  identity.

### 2.5 Mutual exclusivity with other hunt modes

- `--hunt-addr` with `--hunt all` is rejected outright (§9.2) — #58's own
  rule ("Reject `--hunt all` … without an explicit targeted-scan
  capability") applies before any per-identity capability check runs,
  since `"all"` is a selection mode, never an analyzer identity (#70 §4),
  and therefore never a `select_targeted()` candidate (#70 §6).
- `--hunt-addr` with `--triage-skipped` is accepted but `--triage-skipped`
  has **no effect** on a targeted invocation, exactly mirroring today's
  existing rule that `--triage-skipped` is "only meaningful when `ttp ==
  'all'`" (`dumpex/hunt/__init__.py:175-176`, `cmd_hunt()`'s own
  docstring) — a targeted invocation is inherently single-hunter, so the
  `ttp == "all"` gate that already makes `--triage-skipped` a no-op for
  any single-identity `--hunt` today continues to make it a no-op here.
  No new validation failure is needed for this combination — it degrades
  the same way a single-identity full-scope `--hunt` with
  `--triage-skipped` already does.
- `--hunt-addr` combined with `--extract`, `--strings`, `--report`,
  `--list`, or `--diff` is rejected: these are mutually exclusive `mode`
  flags already (`cli.py`'s `mode` group), so `--hunt-addr` without
  `--hunt` present at all is unreachable through normal argparse mode
  exclusivity — but `--hunt-addr` is defined outside that group (§2.2), so
  it must be explicitly rejected when `args.hunt` is falsy (§9.1 — a pure
  argument-presence check, not a `HUNTERS`-validity check, so it belongs
  with §9.1's other pre-dump-open failures, not §9.2's identity-capability
  ones; an earlier draft of this section pointed to §9.2 while §9.1
  separately and correctly listed the same case, a direct contradiction
  this correction removes), the same way `--ref-dir`'s own semantic
  pairing is checked apart from argparse's own structural exclusivity.

---

## §3 Range semantics: half-open range and checked 64-bit arithmetic

### 3.1 Half-open range is the canonical shape

The requested range is `[addr, addr + size)` — inclusive of `addr`,
exclusive of `addr + size`. This is not a new idiom: it is the same
half-open comparison already used throughout the tree —
`va_to_file_offset()` (`memory.py:1125`: `start <= va < end`),
`va_range_captured_bytes()` (`memory.py:1159-1171`), and
`_find_matching_memory_info()` (`_investigation.py:825-827`: `end = base
+ size`). #60's `Range`/`CapturedRange` primitive must implement exactly
this half-open convention — this document does not invent a new one for
targeted scanning to use instead.

### 3.2 Checked 64-bit arithmetic

Two independent checks, not one, adapting the checked-overflow discipline
`_addr()` already uses for `base + rva`
(`dumpex/core/pe_utils.py:1007-1025`, written for issue #39's "integer
overflow" requirement) to a half-open range's two endpoints:

1. `addr` itself: `0 <= addr <= _UINT64_MAX`. `_addr()`'s own single
   `if va < 0 or va > _UINT64_MAX` check is sufficient for a single
   address; it is applied here to `addr` unchanged (§2.4).
2. `end = addr + size`: `end <= 2**64` (equivalently `end <= _UINT64_MAX
   + 1`) — **not** `end <= _UINT64_MAX`, because `end` is a half-open,
   never-dereferenced exclusive bound, and a range reaching the very top
   of the 64-bit address space (`addr = _UINT64_MAX, size = 1`) legally
   produces `end = 2**64`. `_addr()`'s own check does not need this
   distinction (a decoded RVA-relative address is always itself
   dereferenced), so this contract does not reuse `_addr()` verbatim —
   it adapts the same discipline to the one place a plain address check
   would be one-off-by-one too strict.

`_UINT64_MAX = 0xffffffffffffffff` is the frozen value (matching
`dumpex/output/coverage.py:185`'s own lowercase-hex spelling) — this
document does not pick which of the four existing independent
redefinitions (`pe_utils.py:637`, `process_info.py:61`, `handles.py:73`,
`coverage.py:185`) #60 should reuse or where its own canonical constant
should live (that is #60's own module-layout decision), but requires that
#60 **not** add a fifth independent redefinition for range arithmetic —
it must consume one of the existing four or its own single new constant,
never both a new one and a duplicate.

### 3.3 Chunk semantics

Targeted scanning does not introduce a new chunking scheme. Each hunter
already reads/scans by its own native unit — region reads for
pipe/stomping, segment reads for yara/cs-beacon, per-layer reads for
obfuscation (§4's `scan_unit` column, reusing #70 §3's matrix). A targeted
invocation substitutes the requested `[addr, addr+size)` range for the
region/segment boundary that unit's own size-cap check would otherwise
use — it does not change how bytes within that boundary are read, scanned,
or decoded. A read failure or short read against the requested range uses
the identical `SCAN_REGION_READ_FAILED`/`SCAN_REGION_SHORT_READ` codes
(§1) a full-scope run already emits for its own region/segment reads —
applied to the requested range's own bounds, not to the underlying
`MemoryInfo` region's bounds.

### 3.4 Requested range vs. underlying region/segment boundaries

The requested range is typically a strict sub-range of the larger region
or segment whose own cap (§5) caused the original skip — this is the
expected, common case (an investigator targeting exactly the target
recorded in the investigation queue, §0.2). A targeted invocation:

- Reads/scans **exactly** the requested bytes, never silently expanding
  to the full containing region (that would defeat the investigator's own
  explicit budget expectation, per #58's own resource constraint) and
  never silently contracting the requested size down to what a smaller
  underlying region happens to offer.
- Treats "fewer captured bytes than requested" as `short_read` (§1), never
  as a silent resize — the requested size is deliberate intent (§2.3),
  and a targeted invocation that got fewer bytes than asked for reports
  that fact explicitly rather than quietly evaluating a smaller range and
  calling it complete.

### 3.5 Address not contained in any known region or segment

An `addr` that falls outside every `MemoryInfo` region (or, for
yara/cs-beacon, outside every captured segment) is **not** a CLI
validation error — CLI validation checks the range's *shape* (§2.4), never
its *plausibility* against dump content, since a legitimately absent
region is itself useful negative information (per #58: "Explicit
targeting never converts missing bytes into a negative result"). This
case reports as `read_failed` (§1) with zero captured bytes — the same
gap category a real region that failed to capture would produce, not a
distinct error path.

### 3.6 A requested range spanning more than one region/segment descriptor

**Nothing before this section addresses what happens when the requested
range crosses from one `MemoryInfo`/segment descriptor into an adjacent
one — e.g. `[addr, addr+size)` starts inside a `PAGE_READWRITE`
`MEM_PRIVATE` region and extends past its end into a neighboring
`PAGE_EXECUTE_READ` region, or into unmapped space, or into a region a
source's own eligibility filter (§6.5's `eligible_for_source` column)
would have excluded on its own.** §3.4 already establishes the common
case (a sub-range of one region) but silently assumed a single
descriptor governs the whole request; §6.5's `eligible_for_source`
column likewise assumed one set of `State`/`Type`/`Protect` values
applies to the entire range. Neither holds once the range crosses a
boundary, and this contract does not leave that case to be discovered
under implementation pressure.

**Frozen rule: eligibility, and everything gate 2 depends on, is
evaluated against the single descriptor containing `base_address` only
— never a second descriptor the range happens to extend into.** This
reuses machinery §3.4 already established rather than inventing a
cross-region merge/split primitive:

- `eligible_for_source` (§6.5) is computed from the `State`/`Type`/
  `Protect` of whichever `MemoryInfo`/segment descriptor contains
  `base_address` — the *first* (lowest-address) descriptor the request
  touches, exclusively. A second, third, etc. descriptor the requested
  range extends into is never separately consulted for eligibility.
- **`captured_size`/`capture_state` are never artificially bounded at
  that descriptor boundary — an earlier draft of this rule conflated
  "capture" with "evaluation" and got this wrong.** `captured_size` is a
  purely structural fact, already defined independently of any hunter's
  own scanning logic: `va_range_captured_bytes()` (`dumpex/core/memory.py:1130-1144`,
  confirmed by direct read of its own docstring) reports "how many of the
  `size` bytes ... are actually present in the .dmp file, per the dump's
  own segment table — a STRUCTURAL fact ... independent of whether any
  hunt's own live-memory read attempt at that address succeeded or
  failed," walking **contiguous dump-file segments**, which do not
  necessarily align with `MemoryInfo` descriptor boundaries at all.
  Forcing `captured_size` to stop at the first descriptor's own end —
  when the underlying dump segment(s) genuinely extend further — would
  report *fewer* captured bytes than truly exist, exactly the failure
  mode §6.3 exists to prevent in the other direction: it would mislead an
  investigator into believing a re-capture is needed when the bytes are
  already present, they simply were not *evaluated* by this source.
  `captured_size`/`capture_state` therefore always reflect the true,
  full structural extent, computed exactly as `va_range_captured_bytes()`
  already does, with **no** descriptor-boundary adjustment.
- **Evaluation, not capture, is what stops at the first descriptor's own
  boundary — and this is reported through a new, dedicated
  `LimitationCode`, never a reuse of `SCAN_REGION_SHORT_READ`.** An
  earlier draft of this bullet proposed reusing `short_read`'s existing
  `CoverageLimitation` shape "for its already-general meaning," reasoning
  that a `ScanTarget` attached to it already distinguishes "evaluation
  stopped early" from "the read itself failed." That reasoning does not
  survive contact with the actual renderer: `_render_scan_region_short_read()`
  (`coverage.py:1668-1672`, confirmed by direct read) unconditionally
  produces `"{affected_count} region(s) returned fewer bytes than
  declared (short read){layer} -- not fully scanned"` — a specific,
  factual claim about the *read* itself coming back short, which is
  false whenever `capture_state == "complete"` (every requested byte up
  to the descriptor boundary, and beyond it, was genuinely captured; only
  *evaluation* stopped early). Reusing this code would put a false
  statement in the console/JSON output the moment capture and evaluation
  diverge — exactly the class of defect §6.7's own `TARGETED_SOURCE_NOT_EVALUATED`
  correction already exists to prevent, now recurring one section later
  because a *different* code was reused without checking its renderer.

  This contract therefore freezes a second new `LimitationCode`, following
  the identical, already-established pattern:

  ```python
  LimitationCode.SCAN_REGION_EVALUATION_TRUNCATED  # new, caller_buildable=True
  ```

  registered `caller_buildable=True` (not `absent_capable` — this is a
  hand-built `completeness_checks` entry, describing a real, known gap
  the adapter constructs directly, exactly like `SCAN_REGION_SHORT_READ`/
  `SCAN_REGION_READ_FAILED` already are — never auto-generated from a
  `SourceObservation`), `allowed_fields=frozenset({"scope", "targets"})`.

  **`targets` is not merely "allowed" — its shape is frozen precisely,
  not left open, because `build_investigation_queue()` reads a field
  directly off each target that this contract's own general rules would
  otherwise forbid.** `targets` must contain **exactly one** `ScanTarget`
  — the untouched remainder, `[boundary, requested_end)` — never zero
  (the renderer, below, cannot even name `{boundary}` without one) and
  never more than one (a single evaluation-boundary event has exactly one
  remainder by construction, §3.6). That one `ScanTarget` has
  **`size_limit = None`**, mandatorily, not merely by convention:
  `build_investigation_queue()`'s own loop (`_investigation.py:918`,
  confirmed by direct read) constructs each `SkipRelationship` with
  `size_limit=target.size_limit` — read from the *target*, not the
  limitation — and `SkipRelationship.__post_init__` already rejects any
  non-`None` `size_limit` for a cause other than `oversized_skipped`
  (`_investigation.py:432-436`, pre-existing validation, confirmed). This
  contract's own mapping (below) assigns this code's cause as
  `scan_truncated`, never `oversized_skipped` — a target carrying a
  non-`None` `size_limit` here would make `build_investigation_queue()`
  **crash**, not merely render imprecise text, the moment this
  limitation reaches it. `kind` is `memory_region` for
  `pipe`/`stomping`/`obfuscation` or `memory_segment` for
  `yara`/`cs-beacon`, matching §4/§70's own `scan_unit` column for the
  closure's granted source — never guessed per limitation. **`obfuscation`
  belongs on the region side of this split, not the segment side**, and an
  earlier draft of both this bullet and the renderer paragraph below put it
  with `yara`/`cs-beacon`: §4's own matrix gives it `scan_unit` =
  `region+layer` (`TargetedScanUnit.REGION_LAYER`), and all three of its
  layers construct their targets through `region_scan_target(mf, r, ...)`
  (`encoding/sleep_mask.py:360`, `encoding/entropy.py:51`,
  `encoding/decoding.py:488`, each confirmed by direct read), which sets
  `kind=ScanTargetKind.MEMORY_REGION` and fills `allocation_base`/`state`/
  `type`/`protection` from the `MemoryInfo` entry (`_coverage.py:45-70`).
  Building a `memory_segment` target for an `obfuscation` layer would
  therefore drop exactly that `MemoryInfo` metadata — `segment_scan_target()`
  leaves state/type/protection unset by construction, since a segment-table
  entry carries no `MemoryInfo` (`_coverage.py:89-96`) — and pair it with a
  factually wrong "segment" word in the rendered sentence. Only `yara` and
  `cs-beacon` scan captured *segments*.

  **The renderer names the boundary's own real kind — "region" for
  `pipe`/`stomping`/`obfuscation`, "segment" for `yara`/`cs-beacon` —
  rather than a single hardcoded term, and it derives that word from the
  limitation's own `ScanTarget.kind`, never from `TargetedScanUnit`.** An
  earlier draft's proposed text said "eligible region boundary"
  unconditionally, which is imprecise for `yara`/`cs-beacon` (§4's own
  `scan_unit` = `segment`, not `region` — these two scan captured
  *segments*, not `MemoryInfo` *regions*, a distinction this contract's
  own §1 vocabulary already draws and #70's seven-row matrix already
  encodes per hunter). A second draft proposed branching on
  `TargetedScanUnit` at render time, reasoning that "whichever adapter
  constructs this limitation already knows which hunter/source it is
  building for" — that reasoning conflates *construction* time with
  *render* time and does not survive contact with the actual call graph:
  `render_limitation()` (`coverage.py:2995`, confirmed by direct read)
  takes only a `CoverageLimitation` and dispatches to
  `_CODE_SPECS[limitation.code].render(limitation)` — no hunter
  identity, no `TargetedScanUnit`, no adapter context of any kind
  reaches that call. `CoverageLimitation` itself has no
  `TargetedScanUnit` field (`coverage.py:2855-2905`, confirmed), and
  `dumpex.output.coverage` must not import the hunt analyzer registry to
  add one — the same domain-model/output-adapter dependency direction
  `_hex_address()`'s own docstring already states elsewhere in this
  module. The renderer instead branches on `limitation.targets[0].kind`
  — a plain `ScanTargetKind`, already present on the limitation's own,
  single required target (frozen above: exactly one `ScanTarget`, never
  zero or more than one) — `ScanTargetKind.MEMORY_REGION` renders
  "region", `ScanTargetKind.MEMORY_SEGMENT` renders "segment". This is
  not a new mechanism: it is the same derivation
  `_render_scan_region_oversized_skipped()`'s own `scan_target_noun()`
  helper (`coverage.py:1276-1290`, confirmed by direct read) already
  uses for the identical region-vs-segment ambiguity on
  `SCAN_REGION_OVERSIZED_SKIPPED`, and the new renderer should reuse that
  helper (or the equivalent direct `targets[0].kind` check) rather than
  inventing a second implementation of the same rule. Concretely: `"the
  requested range extends past the eligible region boundary for
  {source}{layer} -- bytes from {boundary} onward were not evaluated"`
  for a `MEMORY_REGION` target (`pipe`/`stomping`/`obfuscation`), or the
  same sentence with "segment" in place of "region" for a
  `MEMORY_SEGMENT` target (`yara`/`cs-beacon`) — never a single generic
  word claiming precision neither side of the five hunters uniformly
  has. The `{layer}` suffix is populated only for `obfuscation`'s three
  closures (§4.2), which is exactly why its own boundary text must still
  say "region": the layer names a scope *within* one `MemoryInfo`
  region, it does not turn that region into a segment. No claim about
  read success or failure is made either way. A closure carrying this
  limitation has
  `complete = False` (a real gap) and, per §6.5's own gate-2 formula,
  `evaluated = True` whenever the eligible prefix itself satisfied gate 2
  — `capture_state` and this limitation's own presence are now free to
  vary independently, exactly as they honestly should.

  **This limitation is mapped into the existing investigation-queue
  machinery — and the mapping alone is not enough to reach it, so #66,
  not #65, owns both halves.** An earlier draft of this contract froze
  the limitation's own construction but never connected it to
  `dumpex/hunt/_investigation.py`'s `_TARGET_BEARING_LIMITATION_CAUSES`
  map (`_investigation.py:111-124`, confirmed by direct read) — a closed
  dict `build_investigation_queue()` consults via `.get(limitation.code)`,
  silently `continue`-ing past (`:895-896`) any `LimitationCode` not
  listed. A second draft added the entry and claimed it was sufficient to
  make the truncation remainder actionable; that claim is **false against
  today's tree** and is corrected here rather than left to be discovered
  at implementation time. `build_investigation_queue()` is called from
  exactly two places, both gated on the multi-hunter selection:
  `_investigation_actions_json()` returns `[]` outright unless `selected
  == "all"` (`hunt/__init__.py:82-83`, confirmed by direct read), and
  `cmd_hunt()` builds the queue only inside its own `if ttp == "all":`
  block (`hunt/__init__.py:291` gate, `:310` call). A targeted invocation names exactly
  one identity by construction and `--hunt all` is explicitly forbidden
  with `--hunt-addr` (§1, §2.2) — so with the map entry and nothing else,
  the queue is never built for a targeted run at all, and the entry stays
  dead code for this whole delivery.

  This contract therefore freezes **two** required changes, and assigns
  both to #66 (whose own scope is already investigation-action wiring per
  §0.2 and §10), not to #65:

  1. The map entry itself:

     ```python
     LimitationCode.SCAN_REGION_EVALUATION_TRUNCATED: SkipCause.SCAN_TRUNCATED,
     ```

  2. Reaching it: #66 makes the single-hunter **targeted** queue
     reachable — `build_investigation_queue()` runs for a targeted
     invocation over that one hunter's own record — and owns the
     resulting output-contract consequence, namely that
     `summary.investigation_actions` is **no longer necessarily `[]` for
     a single-hunter run**. That field's current "empty for anything but
     `--hunt all`" behavior is documented in
     `_investigation_actions_json()`'s own docstring and in
     `dumpex/hunt/_investigation.py`'s module docstring; both are #66's
     to update alongside the gate. This changes **nothing** for a
     full-scope single-hunter run (`--hunt <identity>` without
     `--hunt-addr` still returns `[]`, keeping every existing fixture
     byte-identical) — only a targeted invocation, a shape that does not
     exist before this delivery, gains a populated queue.

  `scan_truncated` is the correct existing `SkipCause` — "ran, but hit a
  gap along the way" (§1's own vocabulary already reuses this cause's
  established meaning) — not a new cause value, consistent with §1's own
  "no new `SkipCause` value" guarantee. `budget_kind`/`budget_limit`/
  `budget_consumed` stay all-`None` on the resulting `SkipRelationship`
  (legal for `scan_truncated`, §1's own research on that field's
  all-or-nothing shape — this is a structural boundary event, not a
  budget-exhaustion one, so none of the three apply).

  Until #66 lands both halves, the untouched remainder is still fully
  reported and fully actionable by hand — the limitation's own single
  `ScanTarget` (`[boundary, requested_end)`, frozen above) carries the
  exact base address and size an investigator pastes into the next
  `--hunt-addr`/`--size` invocation, rendered in both console (§7.1) and
  JSON (§7.2). The queue action is the ergonomic surface on top of that
  evidence, never its only carrier; this contract's own deliverable is
  the evidence.

  **Every targeted closure whose evaluation can be boundary-truncated
  (§3.6) includes this code in its own `completeness_checks` — the §6.7
  table below is updated accordingly, not left to imply it is optional.**
  Without it in a given hunter's own `completeness_checks` list, that
  hunter's targeted `CoverageReport.status` would reduce to `complete`
  the moment gate 2 itself is satisfied for the eligible prefix — directly
  contradicting `targeted_scope[].coverage_status` (§7.2), which §6.5's
  own gate-2/`complete` formula already correctly reports as `partial`
  for the same closure. This applies to all five granted sources
  identically, since §3.6's boundary rule is hunter-independent.
- This holds **regardless of whether the second descriptor would itself
  have been eligible** — even a range crossing into a second, perfectly
  well-formed, equally-eligible region of the *same* `Type`/`Protect`
  stops at the first descriptor's boundary *for evaluation purposes* (not
  capture) for this contract. A future issue may extend evaluation across
  compatible adjacent descriptors as a real enhancement; this contract
  does not authorize it implicitly by silence, and treating a
  cross-boundary evaluation as automatically supported without deciding
  so explicitly is exactly the kind of gap this section exists to close.
- No new closure, no per-region split, and no merge logic is introduced
  by this rule — the *existing* single-closure-per-granted-source model
  (§6.1) is unaffected; a cross-boundary request simply produces a
  `SCAN_REGION_EVALUATION_TRUNCATED`-flavored `partial` (or
  `not_evaluated`, if gate 2 fails entirely within the first descriptor)
  evaluation result, alongside a fully honest `captured_size`, using
  facilities this contract already froze.
  An investigator who genuinely needs the second descriptor's own bytes
  evaluated issues a separate targeted invocation for it — mechanically
  identical to §5.8's own resolution for an oversized target spanning
  more than one invocation's worth of range, not a new mechanism.

---

## §4 The five-row targeted-capability matrix

This section populates `TargetedCapability.grants` (#70 §5 field 10,
frozen empty there) for each of the five analyzers #58 approves for the
first release. It changes nothing about `TargetedScanUnit` (#70 §1's
`scan_unit` column, reproduced here only for readability) or about
`injection`/`hollowing` staying `targeted_capability=None` (#70 §3, §5
field 10 — restated, not re-decided, here).

| Identity | `scan_unit`¹ | Granted `source` | Granted `scopes` | Bypassed per-target cap² | Skip cause when the cap would otherwise trip |
|---|---|---|---|---|---|
| `injection` | — | — (no grant; `targeted_capability=None`) | — | — | — |
| `hollowing` | — | — (no grant; `targeted_capability=None`) | — | — | — |
| `pipe` | region | `pipe_name_scan` | `frozenset()` | `PIPE_SCAN_MAX` = 8 MiB (`pipe/config.py:3`) | `oversized_skipped` |
| `stomping` | region | `ioc_string_scan` | `frozenset()` | `IOC_SCAN_MAX` = 5 MiB (`stomping/config.py:10`) | `oversized_skipped` |
| `cs-beacon` | segment | `segment_scan` | `frozenset()` | `CS_MAX_SEG_SCAN` = 50 MiB (`cs_beacon/config.py:17`) | `oversized_skipped` |
| `yara` | segment | `segment_scan` | `frozenset()` | `YARA_MAX_SEG_SCAN` = 50 MiB (`yara_hunt/config.py:49`) | `oversized_skipped` |
| `obfuscation` | region+layer | `encoding_scan` | `frozenset({"sleep_mask", "entropy", "decode"})` | per layer (§5.5) | `oversized_skipped` (per layer) |

¹ Identical to #70 §3's own column — reproduced for cross-reference only,
not redecided.
² The per-target cap(s) this contract authorizes bypassing for the
requested range — a single constant for every row except `decode`
(`obfuscation`'s third layer), whose own bypass set has **two** members,
`DECODE_SCAN_MAX` and `XOR_SCAN_MAX` (§5.5, §1's "Bypassed cap(s)"
vocabulary entry). §5 lists every budget that is **not** bypassed.

The literal frozen values, in #70 §1's own type shape:

```python
GRANTS = {
    "pipe":        TargetedCapability(scan_unit=TargetedScanUnit.REGION,
                                       grants=frozenset({TargetedGrant(source="pipe_name_scan", scopes=frozenset())})),
    "stomping":    TargetedCapability(scan_unit=TargetedScanUnit.REGION,
                                       grants=frozenset({TargetedGrant(source="ioc_string_scan", scopes=frozenset())})),
    "cs-beacon":   TargetedCapability(scan_unit=TargetedScanUnit.SEGMENT,
                                       grants=frozenset({TargetedGrant(source="segment_scan", scopes=frozenset())})),
    "yara":        TargetedCapability(scan_unit=TargetedScanUnit.SEGMENT,
                                       grants=frozenset({TargetedGrant(source="segment_scan", scopes=frozenset())})),
    "obfuscation": TargetedCapability(scan_unit=TargetedScanUnit.REGION_LAYER,
                                       grants=frozenset({TargetedGrant(
                                           source="encoding_scan",
                                           scopes=frozenset({"sleep_mask", "entropy", "decode"}))})),
}
# injection, hollowing: targeted_capability stays None (#70 §3, §5 field 10) — no entry here.
```

Every `source` string above is the analyzer's own public
coverage-source key, read directly off each `report_facts.py`'s `sources
= {...}` dict — never a `CoverageSnapshot` internal field name, exactly
the distinction #70 §1 already draws and corrects an earlier draft over.
`obfuscation`'s `scopes` set is exactly `OVERSIZE_SCAN_LAYERS`
(`dumpex/hunt/encoding/domain.py:57`) — this contract does not invent a
fourth layer or drop one of the three; it is the complete, closed set,
matching #70 §7.1 failure #5's construction-time validation
(`set(grant.scopes) <= set(OVERSIZE_SCAN_LAYERS)`).

This table is the closed, exhaustive satisfaction of #70 §7.1 failure
#5's exact-set-equality check:

```python
{identity for identity, cap in GRANTS.items() if cap is not None} \
    == {"pipe", "stomping", "cs-beacon", "yara", "obfuscation"}
```

No sixth identity may gain a grant, and none of these five may lose one,
without a reviewed amendment to **both** this document and #70.

### 4.1 Why `pipe`/`stomping`/`yara`/`cs-beacon` have empty `scopes`

The one bypassable limitation code, `SCAN_REGION_OVERSIZED_SKIPPED`
(§4's "skip cause" column), carries no `scope` for any of these four
today (confirmed by direct read: `pipe/report_facts.py:239-242`,
`yara_hunt/report_facts.py:106-108`, `cs_beacon/report_facts.py:178-180`;
`stomping`'s own `ioc_string_scan` limitations, §5.3, likewise never
carry one) — each of `pipe_name_scan`, `ioc_string_scan`, and both
`segment_scan` sources has exactly one oversized-skip shape, unsubdivided
by scope. (Three of these four sources *do* carry a `scope` on a
*different*, non-bypassable limitation code — `pipe_name_scan` on its own
`SCAN_BUDGET_EXHAUSTED` entries, `scope="c2_context"`/`"pipe_name"`
(`pipe/report_facts.py:255-262`); `segment_scan` on
`YARA_HIT_CAP_REACHED`/`YARA_SCAN_BUDGET_EXHAUSTED`,
`scope="max_total_hits"`/`<budget_exhausted_kind>`
(`yara_hunt/report_facts.py:125-136`); `segment_scan` again on
`CS_BEACON_SCAN_BUDGET_EXHAUSTED`, `scope=<budget_exhausted_kind>`
(`cs_beacon/report_facts.py:189-197`) — but none of these three codes is
the one this contract authorizes bypassing (§4's table, §5.6), so they do
not bear on whether the *granted* `scopes` should be non-empty.) An empty
`scopes` frozenset on the grant is therefore the correct "this grant has
no finer subdivision" state (#70 §1) for the capability actually being
granted, not an omission to fill in later.

### 4.2 Why `obfuscation` has one grant with three scopes, and why the CLI needs no scope flag to use it

`obfuscation` reports one `CoverageLimitation` **per layer**
(`encoding/report_facts.py:176-196`, `domain.py:188-191`'s `_by_layer()`
— "never merged"), each `source="encoding_scan", scope=<layer>`. A single
`TargetedGrant(source="encoding_scan", scopes={"sleep_mask", "entropy",
"decode"})` — rather than three separate `TargetedGrant`s each with a
one-element `scopes` — mirrors that existing shape exactly: one source,
three selectable layers, matching `TargetedGrant.scopes`'s own documented
purpose (#70 §1: "a source is not always the finest targetable unit").

§2's frozen CLI grammar has no `--hunt-scope`/`--hunt-layer` flag, and
this contract does not add one — #58's own proposed grammar is exactly
`--hunt <hunter> --hunt-addr <addr> --size <size>`, with no per-analyzer
exception. A targeted `obfuscation` invocation therefore **always
attempts every scope in the grant** — all three of `sleep_mask`,
`entropy`, `decode`, in `OVERSIZE_SCAN_LAYERS` order — over the requested
range, never a single caller-selected layer. Concretely: #61's eventual
convergence of this contract iterates `grant.scopes` and calls
`select_targeted("obfuscation", "encoding_scan", scope=layer)` (#70 §6)
once per layer — never once with `scope=None` (which #70 §6's own
symmetric matching rule already correctly rejects against a non-empty-
`scopes` grant). One targeted `obfuscation` invocation therefore always
produces **exactly three closures** (§6.1), never fewer — the only one
of the five approved hunters where a single invocation is multi-closure;
the other four (§4.1's empty-`scopes` grants) always produce exactly
one. All three layers run regardless of which one originally caused the
skip that motivated the investigator's request: §5.5's per-layer cap
bypass only *bypasses* the one layer whose region exceeds its own cap
for this range — a layer whose cap the requested range does not exceed
simply runs normally (its own cap was never going to trip) and still
contributes its own closure. This is deliberate, not incidental: it is
what lets a single, scope-free `--hunt obfuscation --hunt-addr --size`
invocation (§4.2's own CLI-grammar constraint) fully close the gap
regardless of which specific layer's `SkipRelationship` prompted the
request — at a real, bounded, and explicitly accounted-for cost of
redundant re-evaluation of layers that already completed in the original
full-scope run, quantified in §5.7 (this is **not** free: it is
specifically a **processing**-cost multiplier, never a capture-I/O one —
§5.7 requires the requested range be captured exactly once and shared
across all three layers, §5.1's own reuse rule; an earlier draft of this
paragraph said "triples the read cost," which contradicts that shared-
capture rule and is corrected here).

---

## §5 Budget semantics: bypassed cap vs. retained budgets

"Bypass" means precisely: for the one granted `(source, scope)` pair and
the one requested range, skip the `if region/segment size > CAP: skip`
guard that would otherwise fire, substituting the requested
`[addr, addr+size)` for the region/segment the guard normally measures.
It does **not** mean deriving a larger cap, and it does **not** mean
suspending accounting against any other budget — a targeted invocation
still consumes its own fresh (§5.1) hit/candidate/byte/time budgets
exactly as a full-scope run would for the same source.

### 5.1 Budgets are per-invocation, never cumulative across repeats

Per #58's own rule ("A new invocation supplies supplementary evidence; it
does not mutate a prior result document"), every budget below resets at
the start of each targeted invocation. Two targeted rescans of the same
range in separate invocations each get a full, fresh budget — this
contract does not introduce any cross-invocation budget ledger, and #61
must not add one under the guise of "reusing one invocation-local scan
result" (#58's resource constraint, which is about de-duplicating
observations *within* one invocation, not budget-sharing *across*
invocations).

### 5.2 `pipe` — bypasses `PIPE_SCAN_MAX` only

| Retained budget | Value | Source |
|---|---|---|
| `PIPE_C2_BUDGET_MAX_HITS` | 200 | `pipe/config.py:54` |
| `PIPE_C2_BUDGET_MAX_RETAINED` | 2 MiB | `config.py:55` |
| `PIPE_C2_BUDGET_TIME_SECONDS` | 30.0 s | `config.py:56` |
| `PIPE_NAME_BUDGET_MAX_HITS` | 500 | `config.py:61` |
| `PIPE_NAME_BUDGET_MAX_RETAINED` | 1 MiB | `config.py:62` |
| `PIPE_NAME_BUDGET_TIME_SECONDS` | 30.0 s | `config.py:64` |
| `PIPE_MAX_MATCHES_PER_REGION` | 50 | `config.py:19` |
| `PIPE_C2_MAX_CONTEXT_ONLY_PER_REGION` | 5 | `config.py:31` |
| `PIPE_C2_CONTEXT_BYTES` | 512 bytes (context window kept per match) | `config.py:41` |
| `PIPE_C2_TOKEN_PREVIEW` | 256 bytes (retained-evidence bound on the match token itself) | `config.py:42` |
| `PIPE_NAME_MAX_CHARS` | 512 chars (retained pipe-name preview bound) | `config.py:58` |

Three retained-evidence/preview bounds — an earlier draft of this table
omitted all three, confirmed missing by direct search. These are exactly
the "console/JSON preview" and "retained evidence" caps §58's own
Resource and safety constraints require frozen ("Freeze limits for
address arithmetic, bytes, time, matches, candidates, decoded output,
retained evidence, and console/JSON previews") — `PIPE_C2_CONTEXT_BYTES`/
`PIPE_C2_TOKEN_PREVIEW` bound how much surrounding/matched text a C2
context hit retains; `PIPE_NAME_MAX_CHARS` bounds the retained preview of
a matched pipe name itself, distinct from the *detection* threshold
(§6.5's own gate-2 table) — none of the three is a per-target size cap
(§4) or a whole-hunt budget (the tables above); all three remain
enforced, unbypassed, for a targeted invocation exactly as today.

The granted source is `pipe_name_scan` only (§4) — a targeted pipe
rescan is scoped to the pipe-name detection path. It retains both the
`PIPE_C2_BUDGET_*` and `PIPE_NAME_BUDGET_*` limits exactly as today; it
does not widen, merge, or bypass either.

### 5.3 `stomping` — bypasses `IOC_SCAN_MAX` only

| Retained budget | Value | Source |
|---|---|---|
| `PE_VALIDATE_READ_MAX` | 4096 bytes | `stomping/config.py:3` |
| `REF_FILE_MAX_READ` | 64 MiB | `config.py:6` |
| `MAX_DIFF_RANGES` | 20 | `config.py:23` |
| `MAX_DIFF_RANGES_SCAN` | 200,000 | `config.py:28` |

`ioc_string_scan` has no separate time/hit/candidate budget beyond
`IOC_SCAN_MAX` itself today (confirmed absent from `memory_scan.py`/
`report_facts.py`) — the other four constants above govern stomping's
`modules`/`reference_files`/`section_content_diff` sources, which a
targeted invocation never touches (§6.6) and therefore never consumes
budget against, granted or not.

### 5.4 `yara` and `cs-beacon` — bypass their own `MAX_SEG_SCAN` only

| Hunter | Retained budget | Value | Source |
|---|---|---|---|
| yara | `YARA_MATCH_TIMEOUT` (per `match()` call) | 30 s | `yara_hunt/config.py:35` |
| yara | `YARA_MAX_TOTAL_HITS` | 2000 | `config.py:37` |
| yara | `YARA_MAX_STRINGS_PER_MATCH` | 50 | `config.py:36` |
| yara | `YARA_SCAN_DEADLINE_SECONDS` (whole-scan) | 300 s | `config.py:46` |
| yara | `YARA_MAX_TOTAL_BYTES_SCANNED` | 512 MiB | `config.py:47` |
| cs-beacon | `CS_MAX_CANDIDATES` | 20,000 | `cs_beacon/config.py:31` |
| cs-beacon | `CS_MAX_DECODED_BYTES` | 64 MiB | `config.py:32` |
| cs-beacon | `CS_MAX_HITS` | 100 | `config.py:33` |
| cs-beacon | `CS_SCAN_DEADLINE_SECONDS` | 60 s | `config.py:34` |
| cs-beacon | `CS_MAX_TOTAL_SCANNED_BYTES` | 500 MiB | `config.py:35` |
| cs-beacon | `CS_CONFIG_DECODE_MAX` (per-candidate) | 8192 bytes | `config.py:25` |

### 5.5 `obfuscation` — bypasses exactly one layer's own cap per granted scope

| Layer | Bypassed cap | Value | Source |
|---|---|---|---|
| `sleep_mask` | `SLEEP_MASK_REGION_MAX` | 10 MiB | `encoding/config.py:86` |
| `entropy` | `ENTROPY_SCAN_MAX` | 10 MiB | `config.py:30` |
| `decode` | `DECODE_SCAN_MAX` **and** `XOR_SCAN_MAX` | 2 MiB / 512 KiB | `config.py:76` / `config.py:34` |

**`decode` has two independent per-region size caps, not one — an
earlier draft of this table listed only `DECODE_SCAN_MAX` and missed
the second entirely.** `decode`'s own XOR *structural* sub-scan
(`_scan_xor_structural`, called from `decoding.py:515-516`) is gated by
its **own**, narrower, `DECODE_SCAN_MAX`-independent check: `if
prot_str(r.Type) == 'MEM_PRIVATE' and r.RegionSize <= config.xor_scan_max:`
— confirmed by direct read. `XOR_SCAN_MAX = 512 * 1024` (512 KiB,
`config.py:34`) is a quarter of `DECODE_SCAN_MAX` (2 MiB) and completely
independent of it: bypassing `DECODE_SCAN_MAX` alone (as an earlier
draft's own bypass table implied) leaves this narrower cap fully in
force, silently skipping the XOR structural path for any targeted range
above 512 KiB while `base64`/`gzip`/`zlib` (which have no equivalent
per-region cap — confirmed, no matching gate exists for either)
continue normally. Worse: **this skip is completely untracked at the
domain level** — the `if RegionSize <= xor_scan_max:` check has no
`else` branch recording a skip, unlike every size-cap check this
contract has otherwise relied on (`note_skipped_oversize()` and
similar) — so a targeted `decode` closure could report `complete` (gate
2 satisfied, no read-failed/short-read/budget-exhausted) while the XOR
structural sub-path silently never ran at all, for a range this
contract's own §4/§5 already promise "bypasses the cap."

**Frozen resolution: `XOR_SCAN_MAX`'s own gate is bypassed for a
targeted `decode` closure exactly as `DECODE_SCAN_MAX` already is** —
substituting the requested range for `r.RegionSize` in that one
check too (§3.3's already-established "requested range substitutes for
the region boundary" principle, applied to the second cap the same way
it already applies to the first). This is the natural reading of what
"bypass `decode`'s own cap" already meant — an investigator requesting a
targeted rescan of `decode` reasonably expects its full pipeline
(`base64`+`xor`+`gzip`/`zlib`), not one silently-excluded sub-algorithm.
`prot_str(r.Type) == 'MEM_PRIVATE'` (the *other* half of that same
check) is **not** bypassed — it is a real, narrower eligibility
condition specific to the XOR structural sub-path (narrower than
`decode`'s own general `MEM_PRIVATE`/`MEM_IMAGE` eligibility, §6.5's
table), and this contract does not extend a `MEM_IMAGE` region's own
XOR-structural eligibility, only lift its size gate. This is a disclosed
consequence, not a further gap: a targeted `decode` closure's own
`complete`/`coverage_status` (§6.5) still cannot distinguish "XOR
structural ran and found nothing" from "this range's own `Type` excluded
XOR structural specifically while `base64`/`gzip`/`zlib` still ran" —
the same category of per-sub-algorithm ambiguity §6.7's own filtered-
region rule already accepts for `obfuscation`'s three *layers*, now
also true one level deeper, within `decode`'s own three *sub-scans*.
This contract does not further fragment `decode` into three closures to
resolve it (that would repeat §6.7's own obfuscation-merge complexity a
third time, disproportionate to the value) — `decode` remains one
closure, as already frozen.

All four layer-0/2–4 budgets below are fields of the **same** shared
`ScanBudget` instance (`decode_budget`, `dumpex/hunt/encoding/__init__.py:161-167`),
but that does not mean all three layers consume all four fields — verified
call-by-call, not assumed from the sharing:

| `ScanBudget` field | Config source | Value | Consumed by |
|---|---|---|---|
| `deadline` | `ENCODING_BUDGET_TIME_SECONDS` (`config.py:119`) | 60.0 s | `sleep_mask` (`.poll()`/`.exhausted()` only) **and** `decode` |
| `max_attempts` | `ENCODING_BUDGET_MAX_ATTEMPTS` (`config.py:114`) | 2000 | `decode` only |
| `max_retained_bytes` | `ENCODING_BUDGET_MAX_RETAINED` (`config.py:116`) | 32 MiB | `decode` only |
| `max_hits` | `ENCODING_BUDGET_MAX_HITS` (`config.py:118`) | 500 | `decode` only |
| `max_bytes_read` | `ENCODING_BUDGET_MAX_RETAINED × 4` (`__init__.py:162`) | 128 MiB | `decode` only |
| `SLEEP_MASK_MAX_CANDIDATES` | own constant (`config.py:85`) | 10/region | `sleep_mask` only |
| `SLEEP_MASK_MAX_WINDOWS` | own constant (`config.py:102`) | 200,000/region (hard cap on windows counted **during candidate recovery only**, per alignment offset — `windows_per_offset_budget = max_windows // key_size`, `sleep_mask.py:130`) | `sleep_mask` only |
| `SLEEP_MASK_VALIDATE_SAMPLE` | own constant (`config.py:87`) | 2 MiB (streaming chunk size during candidate validation) | `sleep_mask` only |
| `XOR_STRUCTURAL_WINDOW` | own constant (`config.py:43`) | 128 KiB | `decode` only |
| `DECOMPRESS_MAX_OUTPUT` | own constant (`config.py:70`) | 8 MiB | `decode` only |

Two more `sleep_mask`-only constants — an earlier draft of this table
omitted both, confirmed missing by direct search. **`SLEEP_MASK_MAX_WINDOWS`'s
own scope is narrower than an earlier draft of this row claimed —
corrected here.** That earlier draft described it as bounding "every
candidate/rotation combination"; verified by direct read of
`_sm_recover_candidates()` (`sleep_mask.py:93-131`), it bounds **only**
the candidate-*recovery* phase's own per-alignment-offset window count
(one counting pass per `key_size` alignment offset, each capped at
`max_windows // key_size`) — the *later*, separate candidate×rotation
*validation* phase (`_sm_validate_and_decode`, the actual source of the
"~130 combinations" cost §5.5/§5.7 already cite) is governed by
`SLEEP_MASK_MAX_CANDIDATES × SLEEP_MASK_KEY_SIZE`, the shared deadline,
and `SLEEP_MASK_VALIDATE_SAMPLE`'s own chunk size — never by
`SLEEP_MASK_MAX_WINDOWS`, which has already finished its own job by the
time validation begins. Conflating the two would understate §5.7's own
worst-case CPU accounting, which already correctly attributes the
~130-combination cost to validation, not recovery — this correction
brings `SLEEP_MASK_MAX_WINDOWS`'s own description in line with what
§5.7 already gets right elsewhere, rather than contradicting it here.
`SLEEP_MASK_VALIDATE_SAMPLE` is the chunk size the
streamed-validation pass (§5.5's own "each now streamed in chunks across
the COMPLETE region" citation) reads at a time, not a separate
resource ceiling but the granularity at which `.poll()`'s own deadline
check actually happens during validation — relevant to §5.7's own
"cooperative, not preemptive, deadline" correction, since a smaller
sample size means more frequent poll opportunities, bounding (though not
eliminating) how far a single uninterruptible operation can overrun the
60-second deadline.

`max_bytes_read` — an earlier draft of this contract omitted it entirely —
is the cumulative decode/decompress *output volume produced*
(`_budget.py:79`, `note_bytes_read()`), a distinct cap from
`max_retained_bytes`'s *bytes actually kept for reporting* (`_budget.py`'s
own docstring: "distinct from `max_retained_bytes`, which only counts
bytes actually kept in a findings structure") — both apply to `decode`
only, never `sleep_mask`/`entropy`.

`sleep_mask` calls only `budget.poll()`/`budget.exhausted()`
(`sleep_mask.py:135,202,263,345`) — confirmed by the production code's
own comment at the construction site (`encoding/__init__.py:157-160`):
"Layer 0 only reads exhausted()/poll() (deadline), never
note_attempt()/take_hit() — those remain specific to what layers 2-4
actually decode/retain." It never calls `note_attempt()`,
`note_bytes_read()`, or `take_hit()` — so of the shared instance's five
tracked quantities, `sleep_mask` is gated by the deadline only, and by
its own `SLEEP_MASK_MAX_CANDIDATES` outside the shared budget entirely.
`decode` (`decoding.py`) calls all five (`exhausted()`, `note_attempt()`,
`note_bytes_read()`, `poll()`, `take_hit()`, confirmed throughout
`decoding.py`) — it is the only layer the shared budget's
attempts/retained-bytes/hits/decode-output limits actually gate. An
earlier draft of this contract attributed all four count-based fields to
both `sleep_mask` and `decode` together; this table corrects that.

**`entropy` shares none of the above.** `_scan_entropy(regions, modules,
mf, susp_prots, read_region, config)` (`dumpex/hunt/encoding/entropy.py:27`)
takes **no** `budget` parameter at all. `entropy` therefore has no
attempts/retained-bytes/hits/bytes-read/deadline budget of any kind
standing behind `ENTROPY_SCAN_MAX` today — bypassing that one cap (§4)
leaves `entropy` with **zero** retained resource limit, not a reduced
share of one, and not even the deadline `sleep_mask` at least retains.
This is not a defect this contract authorizes fixing (§0.2's "no
scanner-adapter changes"); it is a fact §5.7 below must account for
directly, since it is the single starkest instance of the "unbounded
work behind a bypassed cap" risk this contract exists to close.

Bypassing `SLEEP_MASK_REGION_MAX`/`DECODE_SCAN_MAX` for one requested
range does **not** grant `sleep_mask`/`decode` a larger share of the
budget they each actually draw on (deadline only, for `sleep_mask`; all
five shared-instance fields, for `decode`) — those remain exactly as
constraining as in a full-scope run, shared across the single targeted
invocation that always runs both layers (§4.2 — there is no CLI
mechanism to run fewer than all three layers, so this sharing is
unconditional, not scope-selected). `entropy` draws against no such pool,
shared or otherwise (above).

**`sleep_mask`'s own cost is neither "one pass" nor bounded by any byte
count — it is genuinely deadline-bound, and its retained-hit memory
scales with `size` in a way `TARGETED_HUNT_MAX_REQUEST_BYTES` (§5.7) does
not, by itself, control.** Two separate facts, both confirmed by direct
read, not assumed:

- **CPU cost**: `_scan_sleep_mask()`'s own docstring
  (`sleep_mask.py:308-314`) states plainly that "sleep-mask's candidate
  recovery + validation is genuinely expensive per region... up to ~130
  candidate/rotation combinations, each now streamed in chunks across the
  COMPLETE region" — and `_sm_xor()`'s own docstring
  (`sleep_mask.py:22-38`) confirms this is real, measured cost: "for a
  multi-MB region tried across ~130 candidate/rotation combinations...
  ~2MB took several seconds per call." A targeted invocation's `size` is
  not one XOR pass — it is up to ~130 XOR passes over the *entire*
  requested range, self-limited only by the shared deadline (`.poll()`
  checked once per chunk, above) — never by a per-region byte cap once
  that cap is bypassed for the requested range.
- **Retained memory**: confirmed hits are stored as `DecodedHit(decoded=
  decoded, ...)` (`sleep_mask.py:388-391`), where `decoded` is the
  **full-length** decoded region (`_sm_xor()` preserves input length) —
  not a preview, hash, or bounded excerpt. Up to `SLEEP_MASK_MAX_CANDIDATES`
  (10, per region) such full-length buffers can be retained in the
  invocation's `hits` list simultaneously. In full scope, this is bounded
  by `SLEEP_MASK_REGION_MAX` (10 MiB) to a worst case of `10 × 10 MiB =
  100 MiB` — already real, but small. Under the general
  `TARGETED_HUNT_MAX_REQUEST_BYTES` ceiling (256 MiB, §5.7) alone, the
  same math gives `10 × 256 MiB = 2.5 GiB` retained for `sleep_mask`
  hits from **one invocation** — an order of magnitude beyond anything
  else this contract bounds, and not an acceptable resource envelope for
  a single targeted request.

**This release deliberately does not route `sleep_mask`'s confirmed hits
through `budget.take_hit()`/`max_retained_bytes` — an earlier draft of
this paragraph floated that as an unresolved "natural production fix,"
leaving two incompatible resource models simultaneously implied; this
contract now picks one and forbids the other.** The two options are not
interchangeable:

- **Chosen: `sleep_mask` keeps consuming only the deadline** (§5.5's
  table above, unchanged from today's production behavior), and this
  contract bounds its retained-hit memory purely through the lower
  request ceiling below — `10 × 32 MiB = 320 MiB` worst case, computed
  against an algorithm this release does not modify. `decode` continues
  to be the sole consumer of `max_hits`/`max_retained_bytes`/
  `max_attempts`/`max_bytes_read` (§5.5's table), exactly as today.
- **Rejected for this release: routing `sleep_mask` hits through
  `budget.take_hit()`.** This would change which layer's hits get
  admitted once the shared pool is exhausted (a single 32 MiB
  `sleep_mask` hit could exhaust `max_retained_bytes` entirely, starving
  `decode`'s own retained-evidence budget for the rest of the
  invocation), would require re-deriving §5.5's entire budget-attribution
  table, and — since `sleep_mask.py` is shared code, not a
  targeted-only code path — could not be scoped to targeted invocations
  alone without a second, parallel budget-construction path, silently
  changing full-scope `--hunt obfuscation` behavior too (violating §0.2's
  "no change to full-scope behavior" non-goal in a way this contract has
  not authorized). #64 must not implement this for the targeted path in
  this release. A future issue may reconsider it, but only as its own
  deliberate, reviewed change — re-deriving the full budget-sharing
  order, the new retained-memory ceiling, the `budget_exhausted`
  attribution rule (§6.5), and whether full-scope behavior changes too —
  not as an incidental implementation choice inside #64.

This contract does not authorize modifying `sleep_mask.py`'s algorithm at
all (§0.2's "no scanner-adapter changes"). Instead, it freezes a
**second, lower, obfuscation-specific request ceiling** that keeps the
existing, unmodified algorithm's worst case bounded without touching its
code:

```python
TARGETED_OBFUSCATION_MAX_REQUEST_BYTES = 32 * 1024 * 1024   # 32 MiB
```

applied in place of the general `TARGETED_HUNT_MAX_REQUEST_BYTES` (§5.7)
**specifically when `--hunt obfuscation`** (§2.4, §9.1 both updated
accordingly) — since obfuscation's one shared `--size` value already
governs all three layers together (§4.2), a single ceiling covering the
whole invocation is the only mechanism available without introducing a
per-layer size selector (which §4.2's own resolution already declined to
add). At 32 MiB, `sleep_mask`'s worst-case retained-hit memory becomes
`10 × 32 MiB = 320 MiB` — still real, disclosed, and larger than any
other hunter's own worst case, but within the same rough order of
magnitude as the existing whole-hunt `MAX_TOTAL_SCANNED_BYTES`-class
budgets (§5.4: 512 MiB/500 MiB for `yara`/`cs-beacon`) rather than an
outlier nearly 5× beyond them. This value is chosen, not derived from an
existing constant the way `TARGETED_HUNT_MAX_REQUEST_BYTES` reuses
`MAX_REGION_READ` — but it is frozen exactly the same way that one is:
32 MiB is the value, full stop, for this release. An earlier draft of
this paragraph left #61/#65 free to "revise it if capacity planning
demands a different balance," which is exactly the kind of unresolved
public-CLI behavior this document's own §11 forbids leaving to a later
child (a different accepted `--size` range is public, CLI-visible
behavior, no less than the general ceiling is) — corrected here. If a
future capacity-planning exercise genuinely needs a different value, that
is a change to *this* contract, made and reviewed as such, not a
discretionary call inside #61 or #65's own implementation work.

### 5.6 Pre-existing gap: budget-exhaustion skips are not targetable today

Per §0.2, pipe's and obfuscation's own generic `SCAN_BUDGET_EXHAUSTED`
limitations carry no `ScanTarget` (`_investigation.py`'s
`_TARGET_BEARING_LIMITATION_CAUSES` map omits the bare
`SCAN_BUDGET_EXHAUSTED` code entirely — only `YARA_SCAN_BUDGET_EXHAUSTED`
and `CS_BEACON_SCAN_BUDGET_EXHAUSTED` are mapped). This contract does not
require fixing that gap. It follows directly, though, from §4's own
bypass rule (only `oversized_skipped` is bypassable — §4's table's last
column) that this gap is **inert**, not merely unfortunate: a
budget-exhaustion skip was never going to be targetable through
`--hunt-addr` regardless of whether it carried a `ScanTarget`, because
this contract only ever authorizes bypassing a *size cap*, never
retrying past an *exhausted budget*. #61/#66 should read this as
confirmation that no future work is blocked on closing that gap, not as
an open action item this document defers.

### 5.7 A ceiling on the requested size, independent of any hunter's own budget

Bypassing a per-target size cap (§4) removes the *only* per-request
control several of these paths have on how many bytes get read and
processed in a single pass, before any of §5.2–§5.5's own budgets get a
chance to fire:

- `stomping`'s `ioc_string_scan` has **no** time, total-byte, candidate,
  or hit budget of its own beyond `IOC_SCAN_MAX` itself (§5.3 — confirmed
  absent) — bypassing `IOC_SCAN_MAX` alone removes the only limit that
  path has.
- `obfuscation`'s `entropy` layer draws against **no** budget at all,
  shared or otherwise (§5.5, corrected) — it takes no `ScanBudget`
  parameter in production code today. Bypassing `ENTROPY_SCAN_MAX` alone
  removes the only limit this layer has, exactly like `stomping` above —
  the starkest instance of this section's own risk.
- `pipe`'s `PIPE_NAME_BUDGET_*`/`PIPE_C2_BUDGET_*` hit/time/retained
  budgets (§5.2) similarly gate *matching*, not the single upfront region
  read `PIPE_SCAN_MAX` would otherwise have gated.

None of this is a defect in those existing budgets — they were designed
assuming the size cap they sit behind already bounds the read itself
(exactly the assumption §4 asks this contract to lift for one target at a
time). Without a separate ceiling, an investigator-supplied `--size` of,
say, several hundred gigabytes would force a correspondingly huge single
read/allocation and per-byte scan pass **before** any of §5.2–§5.6's own
budgets could trigger — precisely the "unbounded-work switch" #58's own
Resource and safety constraints forbid ("Explicit targeting must not
become an unbounded-work switch").

This contract therefore freezes one new ceiling, checked at CLI
validation time (§2.4, §9.1) before any dump is opened, applying to
`pipe`/`stomping`/`yara`/`cs-beacon`:

```python
TARGETED_HUNT_MAX_REQUEST_BYTES = 256 * 1024 * 1024   # 256 MiB
```

`obfuscation` uses its own, separately-derived, lower ceiling instead —
`TARGETED_OBFUSCATION_MAX_REQUEST_BYTES` (§5.5) — for reasons specific to
`sleep_mask`'s own cost profile, not covered by reusing the general value
(below).

matching `MAX_REGION_READ`'s own existing value (`memory.py:1200`) — reusing
an already-established ceiling rather than inventing an arbitrary new
number, while applying it as a **hard rejection** (§9.1, `parser.error()`,
exit 2) rather than `MAX_REGION_READ`'s own silent-clamp behavior, since a
clamp would silently narrow the investigator's own explicit requested
range (§3.4 already forbids silently narrowing a requested range). This
ceiling is comfortably above every real per-target *cap* being bypassed
(largest is `YARA_MAX_SEG_SCAN`/`CS_MAX_SEG_SCAN` at 50 MiB, §4) — **but
that establishes nothing about the *skipped target itself*, and an
earlier draft of this section wrongly inferred that it did.** A skipped
target is, by construction, larger than the cap that skipped it — "the
ceiling exceeds every cap" says nothing about whether it exceeds the
region that tripped the cap, and it deliberately is not guaranteed to:
nothing in today's tree bounds how large a `MemoryInfo` region or
captured segment can be, so a real skipped target can exceed 256 MiB by
an arbitrary amount. §5.8 exists precisely because this ceiling *does*
interfere with rescanning some legitimate, real, original skipped
targets in one invocation — it is not "comfortably above" every case,
only above every *cap*. This ceiling exists to bound a single request's
worst-case cost, deliberately independent of whether any given skipped
target happens to fit under it; §5.8 owns what an investigator does when
one doesn't.

**`obfuscation` uses its own, lower ceiling — `TARGETED_OBFUSCATION_MAX_REQUEST_BYTES`
= 32 MiB (§5.5), not the general 256 MiB above — and its real worst case
must be stated per resource, never as one collapsed number.** Two earlier
drafts of this section got this wrong in different ways: one stated a
single "768 MiB" figure that overstated capture cost (there is only ever
one capture, §5.5) while understating that this is primarily a CPU-time
risk; a later draft correctly split capture from CPU cost but still
assumed each layer runs "one full pass" and still used the general 256
MiB ceiling — both wrong for `sleep_mask` specifically, which is neither
one-pass nor bounded to the general ceiling's own order of magnitude
(§5.5's verified findings: ~130 XOR passes per region, gated only by a
shared deadline; confirmed hits retain full-length decoded buffers,
`10 × size` in the worst case). §4.2 freezes that a targeted
`obfuscation` invocation always runs all three layers over the *same*
requested range, with no CLI mechanism to run fewer. That range is one
`[addr, addr+size)` capture, not three independent ones — #61's
convergence of this contract (§0.2) and #62/#63/#64's own adapter work
**must** capture the requested bytes once per invocation and feed all
three layers from that one buffer, never re-reading the dump three
times for the same range, per #58's own resource constraint ("Reuse one
invocation-local scan result where several consumers need the same
expensive observation" — `sleep_mask`/`entropy`/`decode` are exactly
three such consumers of one observation).

With that reuse rule and the 32 MiB ceiling (§5.5) both in place, the
real per-resource worst case is:

- **Capture I/O**: bounded by `TARGETED_OBFUSCATION_MAX_REQUEST_BYTES`
  (32 MiB), performed **once** per invocation.
- **`entropy`'s CPU cost**: one genuine linear pass over the 32 MiB
  buffer (`sleep_mask.py:311`'s own comment independently confirms
  entropy is "cheap linear per-region scan," distinct from sleep-mask's
  own cost) — fast in absolute terms, still gated by nothing but the
  capture size itself (§5.5's "zero retained resource limit" finding),
  which at 32 MiB is no longer a meaningful practical risk the way it
  would have been at 256 MiB.
- **`sleep_mask` + `decode`'s CPU cost**: bounded by their **shared,
  cooperatively-polled 60-second deadline** (`ENCODING_BUDGET_TIME_SECONDS`,
  §5.5), never by a fixed multiple of `size` — but **60 seconds is not a
  hard wall-clock ceiling on total elapsed time, and an earlier draft of
  this paragraph stated it as if it were.** `ScanBudget.exhausted()`
  (`_budget.py:43-53`) only *checks* `time.monotonic() >= deadline` when
  something calls `poll()`/`exhausted()`/`note_attempt()` — it cannot
  interrupt an already-running, uninterruptible operation. `sleep_mask`'s
  own confirmed-candidate decode (`_sm_xor()`, a single big-integer XOR
  over the *entire* region, §5.5) is exactly such an operation: the
  deadline is polled once per chunk *during* candidate recovery/validation,
  but a single already-in-flight XOR call over the full 32 MiB buffer
  runs to completion regardless of the deadline. Real elapsed time is
  therefore `(time already elapsed at the last poll) + (one
  uninterruptible operation's own duration)` — which can exceed 60
  seconds by up to roughly one XOR-pass's worth of time (§5.5's own cited
  measurement: "~2MB took several seconds per call" — scaled to 32 MiB,
  a single such pass is not instantaneous). #61/#65 must plan
  worker/timeout budgets for `obfuscation` around **60 seconds plus one
  uninterruptible operation's margin**, not around a strict 60-second
  hard cutoff — an external worker-level timeout (killing the process/
  thread after some longer ceiling) remains #61/#65's own responsibility
  if a true hard upper bound is required; `ENCODING_BUDGET_TIME_SECONDS`
  by itself is a cooperative target the algorithm honors between
  operations, not a preemptive one.
- **Peak memory**: the one 32 MiB captured buffer, plus `sleep_mask`'s own
  worst-case retained-hit memory (`10 × 32 MiB = 320 MiB`, §5.5 — the
  single largest term, and the reason the ceiling was lowered at all),
  plus `decode`'s own already-bounded state (`ENCODING_BUDGET_MAX_RETAINED`
  = 32 MiB, `DECOMPRESS_MAX_OUTPUT` = 8 MiB, §5.5) — **not** the 2.5 GiB
  an unmodified 256 MiB ceiling would have produced. Total worst-case
  peak for one targeted `obfuscation` invocation is therefore on the
  order of **~400 MiB**, not 256 MiB + 32 MiB (an earlier draft's
  estimate, which omitted `sleep_mask`'s own retained-hit term entirely)
  and not 2.5+ GiB (what the general ceiling alone would have allowed).
  #61/#65 must size shared worker memory against this ~400 MiB figure for
  `obfuscation`, distinct from the ≤256 MiB + bounded-evidence figure
  that holds for the other four hunters.

### 5.8 An oversized original target: bounded supplementary coverage, not gap closure

§5.7's/§5.5's ceilings are hard rejections (§9.1), with no exception for
a legitimately larger original skip. Minidump regions routinely exceed
256 MiB (or 32 MiB, for `obfuscation`) — nothing in today's tree bounds a
`MemoryInfo` region's or captured segment's own size, so an original
`SkipRelationship`'s recorded target (§6.1) may genuinely exceed the
applicable ceiling. This contract does not solve that by raising the
ceiling (§5.7/§5.5 already explain why a request-time-checked bound is
required) or by inventing a chunking/merge/overlap primitive inside this
issue's own scope (§0.2's non-goals already reserve range-primitive
design for #60, and no safe, universal overlap margin exists across five
hunters' differently-shaped signatures — a 64-byte YARA/string/decode
match anchored just before a chunk boundary can straddle it, missed by
every sub-range invocation individually, even though each independently
reports `coverage_status: "complete"` for its own bounded piece; §6.4's
own already-frozen anchor-based cross-boundary rule already accepts that
*any* bounded scan can miss a signature whose anchor falls outside its
own range — chunking an oversized target only adds more such boundaries
than a hypothetical single unbounded scan would have had).

**This contract therefore does not claim, and does not let #66 claim,
that a version-one targeted rescan closes an oversized original target —
an earlier draft's section title and body both overstated this, first as
outright "closing" the gap, then, after correction, as still implying
"covering" a target was a form of resolving it. Corrected here to a
single, explicit policy, decided now rather than left to #66:**

1. **When the recorded target's size is within the applicable ceiling**
   (the common case, §3.4), a single targeted invocation closes it
   exactly as §6.1–§6.5 describe — this is unaffected by anything below.
2. **When the recorded target's size exceeds the applicable ceiling**,
   this release does **not** attempt to close it via multiple sub-range
   invocations, and #66's investigation-action output must not generate,
   suggest, or imply a chunking plan that claims to do so. Instead, the
   investigation action for such a target:
   - Emits **one** copyable command, capped at the applicable ceiling
     from the target's own `base_address` (`[base, base + ceiling)`),
     labeled explicitly as **partial/supplementary** coverage of the
     recorded target, never as a resolution of it.
   - Leaves the original investigation action's own gap status exactly as
     it is today for every target this release does not yet support
     rescanning at all — `coverage_effect` stays
     `"original_hunter_gap_not_resolved"` (`_investigation.py:342`'s
     existing frozen placeholder, §0.1's research) — running the capped,
     partial command does **not** transition it to a resolved state,
     since this version has no way to make that claim honestly.
   - Does **not** recommend the investigator manually chain further
     `--hunt-addr` invocations to cover the remainder, since §5.8's own
     finding is that doing so still would not honestly close the gap —
     recommending a workflow that looks complete but structurally is not
     would be worse than declining to recommend one. An investigator who
     understands the boundary-signature limitation and wants best-effort
     additional coverage anyway may still issue further `--hunt-addr`
     calls themselves (§2's CLI grammar does not forbid it, §5.1) — this
     document does not prevent that, it only declines to automate or
     endorse it as gap closure.
3. A future issue (not #59, and not implicitly authorized by anything
   here) may add real overlap/carry/streaming support and a genuine
   multi-invocation closure claim once one is designed — this contract
   does not foreclose that, it only refuses to claim it exists in this
   release.

This is a deliberately conservative first-release choice, consistent
with the reasoning above: a system that visibly declines to close an
oversized gap is safer for an investigator to rely on than one that
silently overclaims it did. #66 implements this exact three-item policy
— it does not choose between "multiple commands" and "one capped
command with guidance" (an earlier draft of this section left that
choice to #66); this document now makes that choice itself, per §11's
own requirement that no later child invent public UX behavior this
contract could have decided.

---

## §6 Evidence and coverage semantics

### 6.1 Closure identity

The closure identity for a targeted invocation's result is exactly the
5-tuple #58 names:

```python
(hunter: str, source: str, scope: "str | None", base_address: int, size: int)
```

`hunter` is the `HUNTERS` identity (never a package name, per #70 §1).
`source` is the granted source from §4. `scope` is `None` for
`pipe`/`stomping`/`yara`/`cs-beacon` (empty-`scopes` grants, §4.1) and one
of `{"sleep_mask", "entropy", "decode"}` for `obfuscation` (§4.2) — never
`None` for obfuscation, since its grant has non-empty `scopes` and #70
§6's symmetric matching rule requires a real scope for such a grant.
`base_address`/`size` are **always** exactly the requested
`--hunt-addr`/`--size` values (§2), never a resolved, clamped, or
partial-capture-adjusted variant (§3.4) — they identify *what was asked
for*, unconditionally, regardless of what was actually captured. What
was actually captured is a separate fact, `captured_size` (§7.2), never
folded back into this identity — an earlier draft of this contract left
that distinction implicit and, as a result, self-contradicted about
whether these fields could vary with capture outcome; §7.2 now states it
explicitly.

A single targeted invocation produces **one closure per attempted
scope** (§1, §4.2) — exactly one for the four single-scope hunters, and
exactly three (one per `OVERSIZE_SCAN_LAYERS` member) for `obfuscation`.
"Attempted" here means *named by the invocation's grant*, not
*successfully evaluated* — correcting an earlier draft of this contract,
which claimed a listed closure could never be `NOT_EVALUATED` "by
definition." That claim was wrong: a closure is listed for every granted
scope the invocation names, and separately carries its own completeness
verdict (§6.5's `coverage_status`, reusing the real, existing three-value
`CoverageStatus` enum — `complete`/`partial`/`not_evaluated`,
`coverage.py:3009-3012` — the same vocabulary `derive_coverage_status()`
already reduces to via its own `(evaluated, complete)` two-bool input,
`dumpex/hunt/_coverage.py:119-132`, reused here unchanged rather than
re-derived). A closure can genuinely be `not_evaluated`: the requested
address may match no known region/segment (§3.5, zero bytes captured —
no scan loop ever ran), or the granted source's own prerequisite data may
be absent for this dump (mirroring the same `evaluated=False` gate a
full-scope run's `evaluation_sources`/`evaluation_groups` check already
uses). §6.5 freezes the exact per-closure and cross-closure reduction
rule.

This closure identity is **not** whole-hunter or whole-dump completion —
it identifies one source/scope evaluated over one exact range, and
correlates directly with one `SkipRelationship`
(`hunter, source, cause, scope, size_limit, budget_kind, budget_limit,
budget_consumed` — declaration order, `_investigation.py:384-419`) and
one `ScanTarget` (`base_address, size` — `coverage.py:1108-1257`) already
present in today's investigation queue (§0.1's "already fully present,
but split across two structures" finding).

### 6.2 Completed, no match: `NOT_DETECTED_IN_SCANNED_SCOPE`

A targeted invocation that evaluates its full requested range for its
granted source/scope and finds nothing reports the existing
`NOT_DETECTED_IN_SCANNED_SCOPE` status (§1) — produced by the same
reduction rule a full-scope run already uses
(`dumpex/hunt/_coverage.py:24-32`): `score == 0` and coverage complete.
No new status value, and no parallel status enum, is introduced for
targeted mode — this is the same closed `_HUNT_STATUSES` tuple
(`records.py:1283`) a full-scope invocation already produces from.

### 6.3 Explicit gaps stay gaps; fresh, self-contained report

A targeted invocation's own `CoverageLimitation` set reports exactly the
gaps encountered against the *requested* range, using the existing
`SkipCause` vocabulary (§1) — `read_failed`, `short_read`,
`scan_truncated`, etc. — never converting a gap into a negative result
(#58's own rule, restated). This report is fresh and self-contained: it
does not merge into, mutate, or supersede the original full-scope
invocation's own recorded limitations for the same target (§5.1's
per-invocation rule extends to evidence, not only budgets) — the original
full-scope result remains frozen historical evidence exactly as it was
produced.

### 6.4 Cross-boundary signatures

The rule is **anchor-based**, not extent-based: a finding is reportable
for this invocation if and only if the single address a hunter already
reports for that finding today (the match/candidate's own start —
already the sole location every hunter's existing finding shape carries;
none of the five reports a separate "extent" field today) lies inside
`[addr, addr+size)`. A finding's anchor inside the range is reportable
even if the underlying signature's full byte span extends past `addr +
size` — this contract does not require full-extent containment, since
that would demand a per-hunter notion of "extent" several of the five
granted sources do not structurally expose (§4's sources are string/
segment/layer scans, not all of which carry a match-length field the way
a YARA rule match does), and would make the rule hunter-dependent rather
than closed. A finding whose anchor itself falls outside the range is
discarded before being reported for this invocation — never partially
credited, never reported with a location clamped to the boundary.

Separately, and regardless of anchor placement: if a hunter's own
underlying reader must read a small number of bytes past the requested
end for structural reasons (e.g. a PE header field spanning the
boundary), that incidental read does **not** itself count as coverage of
the range those spillover bytes belong to — a *separate*, later targeted
request over that adjacent range must still run its own scan and produce
its own closure; it is never treated as already evaluated by the earlier
request's spillover read.

### 6.5 Per-closure and cross-closure completion: the real three-value reduction

**Per closure**, `coverage_status` (§7.2's field) is computed by feeding
two **independent** facts into the exact, existing
`derive_coverage_status(evaluated, complete)` two-bool reduction
(`dumpex/hunt/_coverage.py:119-132`, reused unchanged, not re-derived —
§6.1):

- `evaluated`/`complete` — **not** derived from `capture_state`, and
  **not** re-derived by this contract via `(source, scope)` pattern-
  matching against `CoverageLimitation.scope`. Two earlier drafts of this
  contract tried each of those in turn, and both are wrong:

  - `capture_state`-derivation is wrong because capture (did the
    requested bytes exist in the dump?) and evaluation (did this
    source/scope's own detection algorithm actually run?) are independent
    facts that can disagree in either direction (full capture with no
    evaluation — a missing prerequisite; zero capture with a trivial
    "ran but saw nothing" evaluation).
  - `(source, scope)` limitation-matching is wrong for two independently
    fatal reasons: **`CoverageLimitation.scope` is not one namespace**
    (`pipe`'s `pipe_name_scan` closure has `scope=None`, but its own
    budget limitation carries `scope="pipe_name"`/`"c2_context"`,
    `pipe/report_facts.py:255-262`; `yara`'s and `cs-beacon`'s own budget
    limitations similarly carry `scope="max_total_hits"`/
    `<budget_exhausted_kind>` against a `scope=None` closure — `scope`
    there encodes *which budget*, an entirely different namespace from
    `obfuscation`'s `scope=<layer>`); and **a relevant limitation can name
    a different `source` than the closure's own granted one while
    `build_coverage_report()`'s own `_validate_build_coverage_report_inputs()`
    (confirmed by direct read: `unknown = referenced_sources -
    sources.keys(); raise ValueError` if non-empty) rejects any
    completeness-check source not already present in `sources` — `yara`'s
    `YARA_RULE_COMPILE_FAILED` names `source="yara_rules"`, not
    `"segment_scan"`, and a `sources` dict artificially restricted to the
    granted source alone would crash construction the first time a
    targeted `yara` rescan hits a broken rule file.

  **`evaluated` is the conjunction of two independent gates, and
  `complete` (once `evaluated` holds) is read from a hunter-specific
  domain fact — neither reduces to a single pre-existing per-dump
  property, and an earlier draft of this contract got this wrong twice in
  two different ways for two different reasons:**

  1. **A prerequisite gate** — hunter-specific, config/rules/stream
     readiness that is genuinely independent of the requested range (only
     `yara` has a real one: `rules.ready`).
  2. **An input-sufficiency gate, invocation-local, never a per-dump
     property** — did *this specific requested range* actually produce
     enough bytes to be handed to the source's own detection pass. This
     is **not** the same as `capture_state != "none"` in general (an
     earlier draft used a per-dump stream-presence property —
     `self.memory_info_stream` — for `pipe`/`stomping`, and that is wrong
     for the same shape of reason the very first attempt was: a dump can
     have `MemoryInfoListStream` while the *one specific requested range*
     matches no known region at all (§3.5) — zero bytes ever reach the
     detection loop even though the stream itself is present dump-wide).
     Gate 2 must be computed **per invocation**, from whether *this*
     read actually produced input, not from any fact that is true or
     false for the whole dump regardless of which range was requested.

  `evaluated = gate 1 AND gate 2`. `complete` (only meaningful once
  `evaluated` is `True`, matching `derive_coverage_status()`'s own
  short-circuit) is read from that source's own already-existing,
  hunter-specific completeness fact — never the whole-`Report`/whole-
  `CoverageSnapshot` aggregate, which for three of the five hunters
  entangles an unrelated concern the granted source does not depend on:

  | Hunter | Granted source | Gate 1 (prerequisite) | Gate 2 (input-sufficiency, invocation-local) | `complete` | Why not the whole-`Report`/`CoverageSnapshot` property |
  |---|---|---|---|---|---|
  | `pipe` | `pipe_name_scan` | none (trivially true — no rules/config dependency beyond the captured bytes themselves) | **New, invocation-local**: the requested range's own read actually produced input to the region walk (not derivable from `self.memory_info_stream`, a dump-wide fact — §3.5's zero-region-match case has that stream present with zero input reaching the walk) | **Existing**: `CoverageSnapshot.region_scan_complete` (`pipe/domain.py:233-238`) — note this property's own `budget_exhausted` term (`pipe/domain.py:227-230`) is `c2_budget_exhausted OR pipe_name_budget_exhausted`, i.e. **both** budgets, not `PIPE_NAME_BUDGET_*` alone; §6.7's targeted `completeness_checks` for `pipe` must include both to keep `targeted_scope[].coverage_status` and `HunterRecord.coverage.status` in agreement (an earlier draft of §6.7 listed only `PIPE_NAME_BUDGET_*`, which would let `region_scan_complete` disagree with a targeted report built from an incomplete `completeness_checks` list) | `CoverageSnapshot.evaluated`/`.complete` are OR-of-presence/require `handle_data_stream` (`pipe/domain.py:242-258`) — both describe the *scored, handle-anchored* check, not the region walk `pipe_name_scan` itself performs; `region_scan_complete`'s own docstring is explicit: "Whether the `\pipe\` region walk itself got through every eligible region." |
  | `stomping` | `ioc_string_scan` | none (same reasoning as `pipe`) | **New, invocation-local**: same shape as `pipe`'s gate 2, scoped to the IOC scan's own read | **Existing**: `CoverageSnapshot.ioc_complete` (`stomping/domain.py:252-254`) | `CoverageSnapshot.evaluated` requires `memory_info_stream AND module_list_stream` (`stomping/domain.py:257-273`) — but that same docstring states outright the IOC scan "only needs MemoryInfoListStream... it can still run — and still find a real gap — while this hunter is NOT_EVALUATED." |
  | `yara` | `segment_scan` | **Existing, unchanged**: `rules.ready` (`yara_hunt/domain.py:279-283`, half of the existing `CoverageSnapshot.evaluated`) | **New, invocation-local**: replaces dump-wide `scan.segment_count > 0` with "this specific requested range produced a real segment to scan" | **Existing, unchanged**: `CoverageSnapshot.complete` (`yara_hunt/domain.py:285-291`: `evaluated and scan.scan_complete and rules.compile_failed == 0`) | `complete` deliberately folds in `rules.compile_failed == 0` **on purpose**, not by entanglement: a compiled-but-partial rule set genuinely means the scanned segment was checked against fewer signatures than intended — a real completeness fact about `segment_scan`'s own result, correctly sourced from `yara_rules`' own health. Only the dump-wide half of `evaluated` (`scan.segment_count > 0`) needed narrowing to gate 2; `rules.ready` and `complete` need no change. |
  | `cs-beacon` | `segment_scan` | none (no rules-style prerequisite for `cs-beacon`) | **New, invocation-local**: replaces dump-wide `scan.segment_count > 0` with this-range-specific input-sufficiency, same shape as `yara`'s gate 2 | **New, narrower than the whole snapshot**: `ScanDiagnostics.scan_complete` (`cs_beacon/domain.py:202-206`), **not** `CoverageSnapshot.complete(has_hits=, any_corroborated=)` | `CoverageSnapshot.complete()` is a *method*, not a pure property, precisely because it also folds in thread-context corroboration when hits exist and none is corroborated — a fact about *verifying a hit already found*, unrelated to whether `segment_scan` itself read every requested byte. `scan.scan_complete` is the one already-isolated property purely about the scan itself. |
  | `obfuscation` | `encoding_scan` (per layer) | none for any of the three layers | **New, does not exist today, but already the right shape**: `layer_coverage.scanned > 0` — `CoverageTracker.note_scanned()` is only called once a read has produced enough bytes for that layer's own minimum-input threshold (confirmed for `entropy`: `if len(data) < 256: continue` runs **before** `note_scanned()`, `encoding/entropy.py:57-60` — a short read below that floor never increments `scanned`, so `scanned > 0` already correctly encodes gate 2, not merely gate-2-shaped by analogy) | **New, does not exist today**: `not (layer_coverage.read_failed or layer_coverage.short_reads or layer_coverage.budget_exhausted)` | `LayerCoverage` (`encoding/models.py:241-255`) carries only `scanned`/`read_failed`/`short_reads`/`budget_exhausted`/target tuples — no `evaluated`/`complete`/`coverage_status` exists on it today. §64 must compute this formula (mirroring `ScanDiagnostics.scan_complete`'s already-established shape, §5.8's budget-attribution correction below) — a real, stated implementation obligation, not something #59 discharges by citing a property that does not exist. |

  **Gate 2 is the conjunction of two independent facts, not the byte
  threshold alone — an earlier draft of this contract defined gate 2 as
  only `captured_size >= T`, and that is incomplete: it does not account
  for a range a source's own type/protection filter excludes entirely,
  which §6.7 below separately (and correctly) requires to be
  `not_evaluated` regardless of how many bytes were captured.**

  ```text
  gate 2 = eligible_for_source AND captured_size >= T
  ```

  `eligible_for_source` is `True` iff the requested range's own
  `MemoryInfo`/segment metadata (state, type, protection) passes that
  source's own real region-selection filter — `False` otherwise, in
  which case gate 2 is `False` regardless of `T`, and the closure is
  `not_evaluated` (matching §6.7's filtered-region rule exactly, now
  folded into the same formula instead of living as a separately-stated,
  easy-to-miss exception). Both factors, per source, verified against the
  real filter/detection code where found, stated honestly as unverified
  where a filter was searched for and not found:

  | Source | `eligible_for_source` (verified filter) | Threshold `T` | Basis for `T` |
  |---|---|---|---|
  | `pipe_name_scan` | `State == MEM_COMMIT` only (`pipe/memory_scan.py:166-167`, confirmed by direct read: the loop's only `continue`-triggering region check). **Corrected**: an earlier draft claimed "and a real `Type` check" — wrong; `mtype = prot_str(r.Type)` is read in this function but only consulted *after* a pipe name is found, to classify whether the containing module is a system DLL — it never gates which regions are scanned in the first place. | `T = 1` (any non-zero capture) | **Corrected**: an earlier draft used `_MIN_RUN_LEN = 6` (`pipe/config.py:66`), which is wrong — that constant gates the *C2-context* extraction path (`_iter_c2_matches`, a different detection pass entirely), not pipe-name detection. Pipe-name matching itself runs `PIPE_PAT_ASCII.finditer(data)`/`PIPE_PAT_UTF16.finditer(data)` (`memory_scan.py:203`) directly against whatever was captured, with no minimum-length gate before the call — the regex engine runs (and can legitimately find zero matches) on input as short as 1 byte, so per this contract's own "was the algorithm actually handed input" gate-2 definition, `evaluated=True` the moment any byte was captured. |
  | `ioc_string_scan` | `State == MEM_COMMIT`, `Type` containing `MEM_IMAGE`, `Protect` containing `EXECUTE` (`stomping/memory_scan.py:163-168`, confirmed by direct read). **Corrected**: an earlier draft claimed no filter exists for this source — that claim was true of `pipe_name_scan` and was pasted into the wrong row; `stomping`'s own IOC scan has a real, three-part region filter this contract had entirely backwards relative to `pipe`. | `T = 1` (any non-zero capture) | **Refined, not reversed**: `_extract_ioc_strings()` (`dumpex/core/memory.py:1400-1402`, confirmed by direct read) does require 8+ printable characters (`rb'[ -~]{8,}'`) for a *candidate string* to be extracted — but that threshold gates which candidate strings the function finds *within* an already-scanned region, exactly the same "per-candidate, not per-invocation" distinction §6.5's table already draws for `decode`'s `B64_MIN_LEN`. `_extract_ioc_strings()` itself still runs, and can legitimately return zero results, on input as short as 1 byte — gate 2 asks only "did the requested range's own bytes reach the detection function at all," which they do the moment any byte is captured and the eligibility filter (left column) is satisfied; it does not ask "did a qualifying 8+-character IOC string exist." An earlier draft of this row said "no minimum-length constant exists," which is imprecise in the same way a prior review already corrected for `pipe`/`decode` — the constant exists, at the candidate-extraction level, and does not change `T`. |
  | `segment_scan` (`yara`) | No region-type/protection filter found beyond segment selection itself (`yara_hunt/scanner.py:36`'s `select_segments()` — a range not part of any selected segment fails capture, §3.5, before gate 2 is even reached, so `eligible_for_source` is trivially `True` for anything that was captured at all) | `T = 1` (any non-zero capture) | YARA rule matching is rule-dependent — a compiled rule can match on very short byte sequences — no universal region-level floor exists. |
  | `segment_scan` (`cs-beacon`) | Same shape as `yara` — segment selection, not a post-capture type/protection filter, gates applicability | `T = 1` (any non-zero capture) | No documented region-level minimum exists for CS Beacon candidate detection (only `CS_CONFIG_DECODE_MAX`, a per-candidate *ceiling*, not a floor). |
  | `encoding_scan` / `sleep_mask` | `State == MEM_COMMIT`, `Type == MEM_PRIVATE`, `Protect == PAGE_READWRITE`, not module-backed (`sleep_mask.py`, confirmed across multiple prior rounds' research) | `T = SLEEP_MASK_KEY_SIZE × SLEEP_MASK_MIN_REPEAT = 13 × 100 = 1300` | `config.py:79-80`: the key "must repeat ≥ N times to be a candidate" at a fixed key size — a *derived* floor from the algorithm's own documented requirement, not a literal `if len(data) < 1300` line today; #64 must verify against `_sm_recover_candidates`'s real behavior and amend this row if the derivation is wrong. |
  | `encoding_scan` / `entropy` | `State == MEM_COMMIT`, `Type == MEM_PRIVATE`, not module-backed (`entropy.py`, confirmed) — **no** `PAGE_READWRITE` requirement, unlike `sleep_mask` | `T = 256` | `encoding/entropy.py:57-60`, confirmed by direct read. |
  | `encoding_scan` / `decode` | `State == MEM_COMMIT`, `Type in (MEM_PRIVATE, MEM_IMAGE)`, excluding system-DLL `MEM_IMAGE` regions (`decoding.py:479-485`, confirmed by direct read — the one layer whose eligibility genuinely differs in *kind* from `sleep_mask`/`entropy`, per a prior review's own observation) | `T = 1` (any non-zero capture) | `decode`'s own per-candidate minimums (`B64_MIN_LEN`, etc.) operate at a finer, per-candidate-string granularity inside an already-scanned region, not as a region-level gate. |

  Every `T = 1` row above is not a placeholder — it is this contract's own
  closed, deliberate answer for that source, arrived at by confirming no
  stricter constant exists in the current tree, not by declining to look.
  Every `eligible_for_source` cell states exactly what was verified and
  where a filter search came back empty rather than blending "confirmed
  absent" with "not checked."

  **Attribution requirement for `budget_exhausted`, stated as an
  obligation on #64, not an assumption about code that exists today.** An
  earlier draft of this section worked through two deadline-interaction
  examples and *assumed* each layer's own `LayerCoverage.budget_exhausted`
  gets set correctly to match — that assumption does not hold against the
  real call sites. `sleep_mask` only checks `budget.exhausted()` at the
  **top of its per-region loop** (`sleep_mask.py:342-345`: `if budget is
  not None and budget.exhausted(): coverage.budget_exhausted = True;
  break`) — if the shared deadline expires *during* an in-flight
  candidate-validation pass rather than between regions (a real
  possibility for a single-region targeted invocation, where there is no
  "next region" loop-top to re-enter and discover the exhaustion at all),
  `budget_exhausted` can stay `False` on `sleep_mask`'s own tracker even
  though the invocation was genuinely cut short. `decoding.py` checks
  `budget.exhausted()` at multiple internal points across its several
  scan functions — this contract does not assert each one already
  threads through to setting that layer's own tracker correctly, only
  that #64 **must** guarantee it does. Concretely, #64 must ensure, for
  both layers:

  - Every point where a scan loop exits early because the shared budget
    is exhausted — whether discovered at a natural iteration boundary or
    mid-operation — sets *that layer's own* `LayerCoverage.budget_exhausted
    = True` before returning, not only the call sites that already happen
    to do so today.
  - A layer that already finished its own scan cleanly *before* a later
    layer discovers the shared budget exhausted keeps
    `budget_exhausted = False` — a later layer's own exhaustion must never
    retroactively mark an earlier, already-completed layer as exhausted.
  - A layer whose own loop never starts at all because the shared budget
    was *already* exhausted when that layer began needs no special case:
    its `scanned` stays `0`, and gate 2 above already correctly yields
    `not_evaluated` without any additional bookkeeping.

  With that guarantee in place, the two worked examples resolve exactly
  as expected: deadline exhausted *during* `sleep_mask` → `decode` never
  starts (`scanned == 0` → `not_evaluated`), `sleep_mask` itself →
  `evaluated=True` (assuming `scanned > 0` before exhaustion),
  `complete=False` (its own `budget_exhausted=True`, per the guarantee
  above) → `partial`. Deadline exhausted *during* `decode` after
  `sleep_mask` already finished cleanly → `sleep_mask` → `complete` (its
  own tracker genuinely never saw exhaustion, per the guarantee's second
  bullet), `decode` → `evaluated=True, complete=False` → `partial`. Both
  outcomes now depend on a stated implementation requirement, not an
  unverified assumption about existing call sites.

  Every "Existing"/"unchanged" property in the table above requires no
  new code (only wiring #62/#63/#64 must add to expose it to a targeted
  invocation's closure computation); every "New" formula/property,
  including the `budget_exhausted` attribution guarantee just above, is a
  real, stated obligation on the corresponding adapter issue, spelled out
  precisely enough that none of #62/#63/#64 has to invent its own shape
  for it.

giving exactly `derive_coverage_status()`'s own three outcomes per
closure: `not_evaluated` (gate 1 or gate 2 above failed — the algorithm
never received sufficient input to run, regardless of how many bytes were
captured), `partial` (both gates held, i.e. it ran, but hit a gap), or
`complete` (both gates held and it ran to completion with no gap). A
`capture_state: "partial"` short read does **not** always reduce to
`partial` — an earlier draft of this contract claimed exactly that, and
`entropy`'s own verified minimum-input floor (`encoding/entropy.py:57-60`:
`if len(data) < 256: continue` runs before `note_scanned()`) is a direct
counter-example: a short read that captures fewer bytes than the
algorithm's own gate-2 floor never reaches `evaluated=True` at all, and
correctly reduces to `not_evaluated`, not `partial`. The correct,
general rule: a short read always makes `complete=False` (a real gap was
hit), but only makes the closure `partial` — as opposed to `not_evaluated`
— when gate 2 (above) was still satisfied by whatever partial bytes were
captured; when the short read falls below the algorithm's own minimum
input floor, gate 2 fails and the closure is `not_evaluated` instead.
`capture_state` (§7.1, §7.2) remains a purely separate fact describing
byte availability only — never itself the source of `evaluated`, and not
guaranteed to agree with it in either direction.

**Across closures**, `HunterRecord.coverage.status` is the same
reduction applied one level up, over every closure this invocation
produced (§6.1) — `complete` iff every closure is `complete`; `partial`
if at least one closure is `evaluated` (partial or complete) but the set
is not uniformly `complete`; `not_evaluated` iff every closure is
`not_evaluated` (mirroring `derive_coverage_status()`'s own "not
evaluated" meaning "never got to scan at all," now applied to "no
granted closure ever got to scan," not merely one). For the four
single-closure hunters (§4.1) this is exactly one closure's own
three-value verdict; for `obfuscation` (§4.2) it is the reduction across
all three per-layer closures — e.g. `decode` short-reads (`partial`)
while `sleep_mask`/`entropy` both `complete` makes the whole invocation's
`coverage.status` `partial`; all three `not_evaluated` (e.g. the
requested address matches no known region at all, §3.5) makes it
`not_evaluated`, correctly reaching `EXIT_NOT_EVALUATED = 4` (§8) for a
targeted invocation exactly as it already does for a full-scope one —
this reachability was missing from an earlier, two-value-only draft of
this contract, which could never route a targeted invocation to exit
code 4. This is a narrower question than full-scope's per-hunter
aggregate, computed by the identical function, not a new computation.
Each individual closure's own three-value verdict is separately recorded
as `coverage_status` on its own `targeted_scope` entry (§7.2) —
`HunterRecord.coverage.status` alone cannot distinguish "layer A
complete, layer B not_evaluated" from "both layers partial," which is
exactly why §7.2 records a per-closure verdict rather than relying on the
aggregate alone.

### 6.6 Stomping: `ioc_string_scan` completion does not imply module/reference completion

Per #58's own rule, restated precisely: a targeted `ioc_string_scan`
closure for `stomping` says nothing about the `modules`,
`reference_files`, or `section_content_diff` sources' completion for the
same target. `stomping`'s own `evaluation_groups`
(`stomping/report_facts.py:297-298`, explained at `:219-224`) already
treats `memory_info` and `modules` as independent AND-of-presence groups
— a targeted invocation never fabricates presence for the
module-comparison sources it did not touch. This does **not** mean the
targeted `CoverageReport.sources` dict contains *only* `ioc_string_scan`
— §6.7's sources/observational-only split means `sources` legitimately
includes `memory_info`, `modules`, `module_headers`, `reference_files`,
and `section_content_diff` too, as pure observational entries that never
drive `.status` (§6.7 — none of these five is referenced by the targeted
`evaluation_sources`/`completeness_checks` §6.7 freezes) — the guarantee
is narrower and more precise than "one key only": `modules`/
`reference_files`/`section_content_diff` are never marked `present` from
data a targeted invocation never read, and no `CoverageLimitation`
referencing them is ever fabricated for a target this invocation did not
evaluate against those sources.

### 6.7 Full vs. targeted structured scope

Two named invocation shapes, both producing the existing `CoverageReport`/
`HunterRecord` structure (§7):

- **Full scope** — today's existing behavior, byte-for-byte unchanged
  (§0.2 — `details.targeted_scope` is omitted entirely, never present as
  `null`). `sources` reflects the hunter's own dump-wide source set (§3
  of #70's own seven-row matrix); `coverage.status` is the whole-hunter
  aggregate.
- **Targeted scope** — this contract's new invocation shape. **`coverage.status`
  is always a genuine reduction of `sources`/`limitations` through
  `build_coverage_report()` — it is never independently assigned, and it
  never reuses the hunter's own full-scope call's
  `evaluation_sources`/`completeness_checks` arguments unscoped.** Two
  earlier drafts of this section each got one half of this right and the
  other half wrong: reusing the full-scope call verbatim (draft one)
  makes `.status` disagree with the closure's own correct verdict, for
  exactly the reasons §6.5 identifies (`pipe`'s `handle_data`,
  `stomping`'s `module_list`, `cs-beacon`'s thread-context gap are the
  wrong completeness signal for the granted source alone). Bypassing the
  builder and assigning `.status` directly (draft two) fixes that but
  breaks a different, explicit architectural invariant:
  `dumpex/output/coverage.py`'s own module docstring (`:9-13`) defines
  `CoverageReport` as "the reduction of **all** of a command's sources +
  limitations into one status" — a report whose `.limitations` still
  contains an observational entry (e.g. `YARA_MATCH_CONTEXT_UNVERIFIED`)
  while `.status` was independently forced to `"complete"` is exactly the
  kind of object this invariant forbids. **The precise invariant is
  `status == "complete"` implies `limitations == []`** — not the converse
  ("any limitation present implies `partial`"), which an earlier draft of
  this paragraph stated and which is false: `build_coverage_report()`'s
  own `retain_completeness_checks_when_not_evaluated=True` path (§6.7
  below, frozen for every targeted call) deliberately produces
  `not_evaluated` results that still carry real limitations (e.g. a
  genuine `SCAN_REGION_READ_FAILED` alongside the auto-generated
  `SOURCE_ABSENT`) — `not_evaluated` **with** limitations present is a
  legal, expected, frozen shape (§6.3's own "explicit gaps stay gaps"
  requires it), and downstream consumers/tests must not reject it as
  malformed. Only `complete` genuinely forbids any limitation; draft two
  still violates even this narrower, correct invariant, since it could
  set `.status = "complete"` while `.limitations` retained an
  observational entry.

  **The correct fix is a third option: construct a *targeted-specific*
  `evaluation_sources`/`completeness_checks` input — scoped to exactly
  what §6.5 says gates the closure — and pass it through the same,
  unmodified `build_coverage_report()` reducer.** This keeps the reducer
  canonical (draft two's problem, solved) while never asking it to
  reduce over the full-scope path's own unrelated prerequisites (draft
  one's problem, solved). Concretely, per hunter:

  | Hunter | Targeted `evaluation_sources` | Targeted `completeness_checks` | `sources` entries present but referenced by neither (observational only) |
  |---|---|---|---|
  | `pipe` | `("pipe_name_scan",)` — **not** `pipe`'s own full-scope `("memory_info", "handle_data")` group | region read-failed/short-read + **both** `PIPE_NAME_BUDGET_*` (`scope="pipe_name"`) **and** `PIPE_C2_BUDGET_*` (`scope="c2_context"`) exhaustion on the requested range — corrected from an earlier draft, which omitted the C2 budget entirely: `region_scan_complete` (§6.5's table, `pipe/domain.py:227-238`) is `not (... or budget_exhausted)` where `budget_exhausted = c2_budget_exhausted OR pipe_name_budget_exhausted`, so a targeted `completeness_checks` list containing only the pipe-name budget would let `CoverageReport.status` read `complete` while `targeted_scope[0].coverage_status` (computed from the real `region_scan_complete`, which does see the C2 exhaustion) reads `partial` — the exact same disagreement bug this section exists to prevent for every other hunter — **plus `SCAN_REGION_EVALUATION_TRUNCATED` (§3.6) when the requested range crosses a descriptor boundary** | `memory_info`, `handle_data` |
  | `stomping` | `("ioc_string_scan",)` — **not** `stomping`'s own full-scope `evaluation_groups` | IOC read-failed/short-read on the requested range (§5.3: no budget concept for this source) **plus `SCAN_REGION_EVALUATION_TRUNCATED` (§3.6) when applicable** | `memory_info`, `modules`, `module_headers`, `reference_files`, `section_content_diff` |
  | `yara` | `("segment_scan",)` | segment read-failed/short-read/match-failed/timed-out/hit-cap/budget-exhausted on the requested range, **plus** `YARA_RULE_COMPILE_FAILED` (§6.5's deliberate inclusion), `YARA_MATCH_CONTEXT_UNVERIFIED` (an earlier draft of this table listed `yara_context` as purely observational and excluded this limitation entirely — wrong, and self-contradictory with this section's own earlier discussion of it as an example of a real limitation that must remain in `.limitations`: full-scope already includes this limitation in its own `completeness_checks`, and it is a genuine fact about *this targeted scan's own hits*, not a dump-wide prerequisite like `handle_data`/`module_list` — targeted mode keeps it, matching full-scope), **and `SCAN_REGION_EVALUATION_TRUNCATED` (§3.6) when applicable** | none — `yara_context` is referenced only via the `YARA_MATCH_CONTEXT_UNVERIFIED` limitation above, never separately observational |
  | `cs-beacon` | `("segment_scan",)` | segment read-failed/short-read/budget-exhausted on the requested range **plus `SCAN_REGION_EVALUATION_TRUNCATED` (§3.6) when applicable** | `memory_info`, `thread_context` |
  | `obfuscation` (per layer) | `("encoding_scan",)` per closure | that layer's own read-failed/short-read/budget-exhausted, scoped to the requested range (§6.5), **plus `SCAN_REGION_EVALUATION_TRUNCATED` (§3.6) when applicable, per layer** | `memory_info` |

  `SCAN_REGION_EVALUATION_TRUNCATED` is conditional in every row above —
  present in `completeness_checks` only when the requested range actually
  crosses a descriptor boundary (§3.6); a targeted invocation whose range
  lies entirely within one descriptor never constructs it, exactly as
  every other conditional limitation in this table already works (a
  budget-exhaustion limitation is likewise only ever present when that
  budget was actually exhausted).

  **Every targeted `build_coverage_report()` call passes
  `retain_completeness_checks_when_not_evaluated=True`** (the existing,
  real, opt-in parameter, `coverage.py:3401-3413`, confirmed by direct
  read: "the pre-built `CoverageLimitation` entries in
  `completeness_checks` are no longer dropped" once this is set). Without
  it, `build_coverage_report()`'s own default behavior silently discards
  every hand-built `completeness_checks` entry whenever the evaluation
  source is absent (i.e., whenever gate 1 or gate 2 fails and the closure
  is `not_evaluated`) — meaning a genuine `SCAN_REGION_READ_FAILED`/
  `SCAN_REGION_SHORT_READ` limitation for the exact requested range would
  silently vanish from the targeted `CoverageReport` the moment gate 2
  fails, directly contradicting §6.3's "explicit gaps stay gaps" rule. An
  earlier draft of this contract never set this parameter and would have
  produced exactly that silent loss for the most common `not_evaluated`
  case (a genuine read failure, not merely a filtered-out region). With
  it set, the real gap-producing limitation is retained in `.limitations`
  even when `.status` becomes `not_evaluated` — this document's own §6.3
  requirement, now actually achievable through the existing API rather
  than merely asserted.

  **`pipe_name_scan`/`ioc_string_scan`/`segment_scan`/`encoding_scan`'s
  own `present` field means something different in targeted mode than in
  full-scope, and this is a deliberate, hunter-scoped redefinition, not
  an inconsistency.** In full-scope, each of these is documented as "a
  synthetic, always-present source (the scan attempt itself...)"
  (`pipe/report_facts.py`'s own docstring, confirmed identically worded
  for the other three) — `present=True` unconditionally, since the
  *mechanism* always exists dump-wide. In targeted mode, that same
  source's `present` field instead carries §6.5's own gate-1-AND-gate-2
  result for *this specific closure* — `True` only if this invocation's
  own scan attempt actually received sufficient input, `False`
  otherwise — precisely because `evaluation_sources` now references this
  source (not `memory_info`/`handle_data`/etc.) as the one whose absence
  drives `not_evaluated`. This redefinition is scoped to targeted
  invocations only and never applies to full-scope's own use of the same
  source key (§0.2's "no change to full-scope behavior").

  **The absence-triggering limitation this produces must not be the
  generic `SOURCE_ABSENT` — a new, dedicated `LimitationCode` is frozen
  here for exactly this case, using an existing extension mechanism, not
  a novel one.** `_render_source_absent()` (`coverage.py:1461-1469`,
  confirmed by direct read) never reads `limitation.scope` at all and
  unconditionally renders `"{source} not present in this dump"` — both
  wrong for a targeted gate-2 failure: the *scope* is invisible in the
  text (two failed layers would both render identically, indistinguishable
  even with different `scope` values), and "not present in this dump" is
  a category error for a synthetic scan-attempt source that always exists
  as a mechanism — what actually happened is "this specific requested
  range did not produce sufficient/eligible input," never "this stream is
  missing from the dump." An earlier draft of this contract relied on the
  bare default `SOURCE_ABSENT` rendering for this case and did not
  catch either problem.

  The fix reuses an **already-existing** extension point, following an
  **already-existing** precedent, rather than inventing new machinery:
  `EvaluationRequirement.all_absent_code` (`coverage.py:3132`, confirmed
  by direct read) already lets a caller select a *different*,
  dedicated `LimitationCode` for the whole-group-absent case instead of
  the generic default — exactly how `MODULE_CLASSIFICATION_UNAVAILABLE`
  (`coverage.py:2397-2399`, `absent_capable=True`,
  `allowed_fields=frozenset({"scope"})`) already exists as a real,
  shipped dedicated-absence code with its own renderer, precisely because
  a bare `SOURCE_ABSENT` sentence would have been wrong for *its* case
  too. This contract freezes one new code of the same kind:

  ```python
  LimitationCode.TARGETED_SOURCE_NOT_EVALUATED  # new, absent_capable ONLY
  ```

  **`absent_capable=True` only — deliberately `caller_buildable=False`.**
  An earlier draft of this contract marked the new code
  "caller-buildable, absent_capable" without checking whether any
  existing code is genuinely both; verified now: none is (a mechanical
  scan of `_CODE_SPECS` for `caller_buildable=True` and
  `absent_capable=True` together on the same entry found zero real
  matches — an initial grep appeared to find five, but each was a
  regex-boundary artifact matching across two separate `_CodeSpec`
  entries, confirmed false by direct read of e.g.
  `ENCODING_ALL_REGIONS_FILTERED`, which is `caller_buildable=True` only).
  This absence is not incidental: `absent_capable` means the reducer
  itself constructs the limitation from `SourceObservation.state ==
  ABSENT`, one single source of truth; `caller_buildable` means a caller
  hand-constructs one and hands it to `completeness_checks` directly. A
  code with *both* would let a caller assert `TARGETED_SOURCE_NOT_EVALUATED`
  by hand even while the same source's own `SourceObservation` reports
  `present=True` — exactly the "two sources of truth that could silently
  disagree" this whole coverage model exists to prevent (the same
  principle §5's own "execution order is not a field" discussion and
  #70's own analyzer-registry contract both already invoke). This code is
  **exclusively** reducer-generated, mirroring `MODULE_CLASSIFICATION_UNAVAILABLE`'s
  own `absent_capable=True`-only shape precisely, not partially.

  Registered with `allowed_fields=frozenset({"scope"})` — **not**
  `"targets"`. An earlier draft claimed this code could carry the exact
  requested range as an attached `ScanTarget`, "matching every other
  range-bearing limitation in this contract," without any actual data
  path to populate it: `EvaluationRequirement` (real definition,
  `coverage.py:3130-3131`: `sources: tuple, all_absent_code:
  "LimitationCode | None" = None`) has no `targets` field today, and the
  absent-group construction site (`coverage.py:3459-3461`) passes only
  `code`/`source`/`scope`/`related_sources` — no target of any kind flows
  through it. Rather than adding a third new field to
  `EvaluationRequirement` purely to carry a fact `details.targeted_scope`
  (§7.2) already carries in full — `base_address`/`size` are already
  part of every `targeted_scope` entry, keyed by the same
  `source`/`scope` this limitation itself carries — this contract drops
  the `targets` claim entirely: the exact requested range for a
  `TARGETED_SOURCE_NOT_EVALUATED` limitation is read from
  `targeted_scope`, cross-referenced by `source`/`scope`, never from the
  limitation's own (nonexistent) `targets` field.

  **The renderer's text is neutral about *why* gate 1 or gate 2 failed,
  not "insufficient input" specifically — an earlier draft's proposed
  wording overclaimed a single cause.** `TARGETED_SOURCE_NOT_EVALUATED`
  fires whenever gate 1 (prerequisite) **or** gate 2 (input-sufficiency)
  fails (§6.5) — for `yara`, gate 1 alone can fail with the requested
  range fully captured (`rules.ready == False`, e.g. no compiled rules at
  all), for which "received insufficient input" would misstate what
  actually happened. The frozen render text is instead:

  ```text
  "{source} ({scope}) was not evaluated for the requested range"   # scope set
  "{source} was not evaluated for the requested range"             # scope is None
  ```

  — accurate regardless of which gate failed, and consistent with this
  contract's own `NOT_EVALUATED` vocabulary (§1: "did not run at all")
  rather than asserting a specific mechanism. A reader who needs to know
  *which* gate failed and why already has the means to: for `yara`
  specifically, `yara_rules`' own `SourceObservation` (present in
  `sources`, §6.7's observational-source list) independently reports
  `present=False` when gate 1 is the cause, distinguishable from a
  `present=True` `yara_rules` entry alongside this limitation (gate 2
  alone failed) — no new reason-code taxonomy is introduced here, since
  the sources already present in the report already carry enough to
  disambiguate the one hunter (`yara`) where gate 1 is a real,
  independent possibility at all.

  Every targeted closure's own `EvaluationRequirement` supplies
  `all_absent_code=LimitationCode.TARGETED_SOURCE_NOT_EVALUATED` (already
  a legal, existing parameter — no change needed to accept it) instead of
  the default.

  **`EvaluationRequirement.scope` needs a real "not provided" sentinel,
  distinct from an explicitly-passed `None` — a bare `scope: "str | None"
  = None` default cannot distinguish the two, and an earlier draft of
  this contract used exactly that ambiguous shape.** Two genuinely
  different callers both need to reach this one field: every *existing*
  full-scope call site across the tree, which knows nothing about `scope`
  and must keep getting today's unchanged `"dump"` output; and this
  contract's own *targeted* `pipe`/`stomping`/`yara`/`cs-beacon` calls,
  whose closure `scope` is genuinely, explicitly `None` (§6.1 — no layer
  concept for these four) and must render as JSON `null`, never silently
  become `"dump"`. A bare `None`-default field cannot tell "caller didn't
  pass anything" from "caller passed `None` on purpose" apart — both look
  identical once inside `__post_init__`. The field is instead:

  ```python
  _UNSET_SCOPE = object()   # module-private sentinel, coverage.py's own convention

  @dataclass(frozen=True)
  class EvaluationRequirement:
      sources: tuple
      all_absent_code: "LimitationCode | None" = None
      scope: "str | None" = _UNSET_SCOPE
  ```

  with construction logic distinguishing all three states: `scope is
  _UNSET_SCOPE` → the group-limitation keeps today's literal `"dump"`,
  byte-identical to every existing caller, none of which is touched by
  this change; `scope is None` → the group-limitation's own `scope`
  field is set to `None` (renders as JSON `null`), exactly what `pipe`'s/
  `stomping`'s/`yara`'s/`cs-beacon`'s targeted closures require; `scope`
  is a real string → set to that value, exactly what `obfuscation`'s
  per-layer closures require. `obfuscation`'s own targeted construction
  passes `scope=<layer>`; `pipe`/`stomping`/`yara`/`cs-beacon`'s targeted
  construction passes `scope=None` explicitly (not omitted); every
  full-scope caller omits the parameter entirely and is unaffected.

  Every earlier passage in this document that described this mechanism as
  producing a `SOURCE_ABSENT` limitation (§6.5's gate discussion, the
  obfuscation merge design below) means `TARGETED_SOURCE_NOT_EVALUATED`
  wherever it says `SOURCE_ABSENT` — the underlying "an evaluation source
  reported absent, driving `not_evaluated`" *mechanism* is unchanged
  (still `SourceObservation.state == ABSENT` triggering the same
  absent-group construction path in `build_coverage_report()`), only the
  *code and rendered text* selected for it differ from the generic
  default, exactly as `all_absent_code` already exists to allow.

  **`obfuscation`'s `HunterRecord.coverage` is not the output of a single
  `build_coverage_report()` call at all — it is the one explicit exception
  in this contract, and it must be, because a single `sources` dict has
  only one `"encoding_scan"` key and cannot represent three independent
  layer states through it.** Consider the case a prior review posed:
  `sleep_mask` closure `complete` (ran, no gap), `entropy` and `decode`
  both `not_evaluated` (gate 2 failed for both — filtered out or zero
  input), with no read-failed/short-read/budget-exhausted limitation
  recorded for any of the three. §6.5's own cross-closure rule requires
  the document-level result to be `partial` (at least one closure
  evaluated, not all `complete`). But a *single* `build_coverage_report()`
  call, given one `sources={"encoding_scan": observe_source(...,
  present=True)}` (true because `sleep_mask` did run) and zero
  limitations (because "filtered out" produces no `CoverageLimitation`,
  §6.7 below), would reduce to `complete` — `build_coverage_report()`'s
  own generic two-input rule ("not_evaluated if sources absent, else
  partial if any limitation, else complete") cannot see the internal
  three-way split at all through one combined source, and gives the
  wrong answer. This is a real limitation of collapsing three states
  into one key, not a bug in the reducer.

  The frozen resolution: **three separate `build_coverage_report()`
  calls, one per layer, each with its own `sources={"encoding_scan":
  observe_source("encoding_scan", present=<that layer's gate 1 AND gate
  2>)}` plus that layer's own observational `memory_info` entry,
  `evaluation_sources=("encoding_scan",)`, and `completeness_checks`
  limited to that layer's own read-failed/short-read/budget-exhausted on
  the requested range (each tagged `scope=<layer>`, matching the
  existing full-scope convention of one `CoverageLimitation` per layer
  under the shared `encoding_scan` source name, §4.2) — producing three
  independently valid, invariant-preserving mini-`CoverageReport`s, one
  per closure.** `HunterRecord.coverage`, the single object that actually
  appears in the JSON document, is then constructed as an explicit,
  frozen **merge** of those three, not a fourth independent computation:

  - `.status` = §6.5's own cross-closure reduction, applied directly to
    the three mini-reports' own `.status` values (`complete` iff all
    three `complete`; `not_evaluated` iff all three `not_evaluated`;
    `partial` otherwise) — a deterministic function of three already-
    correct, already-invariant-preserving sub-verdicts, not an
    independently asserted value (distinguishing this from the "direct
    assignment" design this contract rejected above: there, `.status`
    was disconnected from any real reduction; here, it is a *defined,
    principled combination* of three reductions that are each themselves
    real).
  - `.limitations` = the concatenation of all three mini-reports' own
    `.limitations` — both the hand-built `completeness_checks` entries
    (read-failed/short-read/budget-exhausted, each already `scope=<layer>`)
    **and** each mini-report's own auto-generated `TARGETED_SOURCE_NOT_EVALUATED`
    entry (the dedicated code frozen above — never bare `SOURCE_ABSENT`)
    when that layer's `evaluation_sources=("encoding_scan",)` is absent.

    **A prior draft of this section excluded the auto-generated entries
    from the merge entirely, reasoning (correctly, at the time) that
    `build_coverage_report()` hardcodes `scope="dump"` on them, making two
    `not_evaluated` layers' own absence limitations identical once merged.
    That exclusion traded one bug for another: it stopped the collision,
    but left the merged, document-level `CoverageReport` unable to explain
    its own `.status` from its own `.sources`/`.limitations` — a `partial`
    result with an empty `.limitations` list and
    `sources["encoding_scan"].present == True` reduces, by
    `build_coverage_report()`'s own stated rule, to `complete`, not
    `partial`. The `scope` field and `TARGETED_SOURCE_NOT_EVALUATED` code
    frozen above resolve this at the root instead: each layer's own
    absence limitation is now both distinguishable
    (`TARGETED_SOURCE_NOT_EVALUATED(source="encoding_scan",
    scope="entropy")` vs. `scope="decode"` are two different, real facts,
    not a collision) and semantically accurate (no false "not present in
    this dump" claim about a source that is, in fact, a mechanism that
    always exists), so excluding them from the merge is no longer
    necessary — including them is what makes the merged report honestly
    self-reducible.**

    With both fixes in place, feeding the merged report's own final
    `sources`/`limitations` back through `build_coverage_report()`'s
    stated rule ("`complete` unless a limitation exists, in which case
    `partial`, unless every evaluation source is absent, in which case
    `not_evaluated`") reproduces the same `.status` this section's own
    merge already computes via §6.5's cross-closure reduction — the two
    are no longer
    two independent claims that merely happen to usually agree; they
    provably agree, by construction, for every case.
  - `.sources` = the three mini-reports' own `encoding_scan` observations
    are **not** merged into one dict key (that would silently overwrite
    two of the three) — the merged `.sources["encoding_scan"]` instead
    reflects the OR of all three layers' own `present` values (`True` if
    *any* layer's gate 1 AND gate 2 held), while `targeted_scope` (§7.2)
    remains the authoritative place a reader finds each individual
    layer's own `coverage_status` — `.sources`/`.limitations` on the
    merged, document-level report answer "what happened overall, and
    why, self-containedly," `targeted_scope` answers "what happened per
    layer, with byte-availability detail `.limitations` alone doesn't
    carry (`capture_state`/`captured_size`, §7.2)" — neither is a
    substitute for the other, but only `targeted_scope` was ever meant to
    be, not `.limitations` itself.

  This is the only hunter where the document-level `CoverageReport` is
  built from a merge of several sub-reductions rather than one direct
  reducer call — a necessary, explicitly frozen exception given one
  source name covering three independently-variable closures — but, with
  the `scope`-override fix above, the *merged result itself* remains a
  genuine, self-explanatory reduction, not an exception to that
  principle, only to the "one reducer call" mechanism used to reach it.

  **`yara`/`cs-beacon` do not use their existing full-scope
  single-key not-evaluated shape (`{"yara_scan": ...}` /
  `{"memory64_list": ...}`) for a targeted invocation.** An earlier draft
  of this contract did not address this at all. Those single-key shapes
  exist because full-scope genuinely has nothing further to report at
  the source level once nothing ran; a targeted closure's `yara_rules`
  state (gate 1, independent of the requested range) remains meaningful
  and worth reporting even when `segment_scan` itself never received
  input (gate 2 failed) — so targeted mode always uses the full,
  multi-key shape (`yara_rules`/`segment_scan`/`yara_context`;
  `memory_info`/`segment_scan`/`thread_context`), never the collapsed
  one-key shape, regardless of whether the closure ends up `not_evaluated`.

  **A region/range a layer's own type/protection filter excludes
  entirely is `not_evaluated` for that layer's closure, never a clean
  `complete`/negative result — frozen explicitly to prevent divergent
  implementations, since the five hunters' own filters genuinely differ**
  (`sleep_mask`/`entropy` require `MEM_COMMIT`+`MEM_PRIVATE`+ (for
  `sleep_mask`) `PAGE_READWRITE`; `decode` additionally accepts some
  `MEM_IMAGE` ranges) — the same requested range can therefore be
  `not_evaluated` for one `obfuscation` layer while `complete` for
  another in the same invocation, which is correct and expected (§6.5's
  own cross-closure reduction already handles a mixed result), **not** a
  bug to paper over by treating "filtered out, never handed to the
  algorithm" as though the algorithm ran and found nothing. §1's own
  vocabulary already settles which of the two applies: `not_evaluated`
  means "did not run at all," and a range a filter excludes categorically
  never runs — gate 2 (§6.5) already produces this outcome by
  construction (`scanned` stays `0` when a region never passes the
  layer's own filter), and no adapter may substitute a
  `NOT_DETECTED_IN_SCANNED_SCOPE`-style clean negative for it.

  The *requested* range is echoed in `meta.execution.options` (§7.2),
  while the authoritative per-closure record of what was actually
  *evaluated* — including a clean, no-gap result `sources`/`limitations`
  alone cannot fully disambiguate from "never attempted" without
  `targeted_scope`'s own `coverage_status` field — lives in
  `HunterRecord.details.targeted_scope` (§7.2). `HunterRecord.coverage.status`
  and every `targeted_scope[].coverage_status` are computed from the
  identical gate-1/gate-2/`complete` facts (§6.5), one via
  `build_coverage_report()`'s real reduction (this section), the other
  directly (§7.2) — they cannot disagree by construction, since both are
  deterministic functions of the same underlying facts, never two
  independent computations that merely happen to usually agree.

---

## §7 Output shape: console, JSON, and CSV

This section reuses existing schema surface wherever it already
expresses the needed fact, and declares exactly one new, closed field —
`targeted_scope` (§7.2) — where existing surface genuinely cannot express
a targeted invocation's clean, no-gap result. This field is a real
schema/dataclass addition, owned by #65's own cutover, not a free
extension of an already-open structure — `HunterRecord.details` is
strictly closed (§7.2 explains exactly why, correcting an earlier draft
of this contract that wrongly claimed otherwise and wrongly attributed
that claim to #70). §7.2 freezes `targeted_scope`'s exact shape and which
five `*Details` dataclasses/schema `$def`s gain it, the same way #70
freezes `AnalyzerSpec`'s field shape for #71 to implement — this document
does not write the dataclass or schema-file diff itself. The request
itself (`--hunt-addr`/`--size` as supplied) is separately echoed in
`meta.execution.options`, which already exists precisely to record
arbitrary per-command CLI arguments
(`dumpex/output/envelope.py:267-341`, `build_meta_v2()`).

### 7.1 Console

A targeted invocation's console output must show, in addition to the
hunter's own existing console body (unchanged — §0.2):

- The selected hunter identity (already shown today).
- The exact requested range, both bounds hex-formatted with the existing
  `hex_address()`/`_hex_address()` convention (`0x` + 16 lowercase hex
  digits, `records.py:34-43`/`coverage.py:1083-1091`) — `[0x..., 0x...)`.
- The requested size (decimal, matching how `--size` is already echoed
  elsewhere).
- Capture/read outcome, reusing the existing `ScanTarget.capture_state`
  vocabulary (`coverage.py:1213-1225`: `None` unset/never computed,
  `"none"` zero bytes, `"partial"` some but not all of `size`,
  `"complete"` all of `size`) verbatim — no new capture-state value.
- The evaluated source and scope(s) — for `obfuscation`, all three layers
  (§4.2), each named exactly as its `sources` dict key /
  `OVERSIZE_SCAN_LAYERS` member — shown per closure (§6.1), not merged
  into one line.
- Remaining limitations, rendered through the existing single dispatch
  point `render_limitation()` (`coverage.py:2995-3003`) — no parallel
  rendering path for targeted-mode limitations.
- Each closure's own `coverage_status` (§6.5, §7.2 — `complete`/`partial`/
  `not_evaluated`), shown per closure alongside its source/scope, not
  only as the aggregate.
- The overall completion verdict, reusing `_ui.py`'s existing `DETECTED`/
  `NOT_DETECTED_IN_SCANNED_SCOPE`/`INCONCLUSIVE`/`NOT_EVALUATED` labels
  and colors verbatim (§6.2) — computed from `HunterRecord.coverage.status`
  (§6.5's cross-closure reduction), the same aggregate a full-scope run's
  console already shows.

### 7.2 JSON

- **Request recording**: `_build_options()`'s existing `if args.hunt:`
  branch (`cli.py:294-299`) gains two keys, `opts["hunt_addr"] =
  args.hunt_addr` and `opts["size"] = args.size`, populated only when
  present — following the exact snake_case dest-name convention already
  used by every other key in that function (`yara_dir`, `ref_dir`,
  `rules_file`, `triage_skipped`). This lands in `meta.execution.options`
  (`envelope.py:331`) exactly like every other per-command CLI argument
  already does — no new top-level `meta` object.
- **Result recording**: `CoverageReport.limitations` is **not** a
  reliable place to reconstruct a closure's own range — an earlier draft
  of this bullet claimed "each limitation's own `targets:
  tuple[ScanTarget]` ... already carr[ies] a gap's closure identity,"
  which overgeneralizes from the limitation codes that happen to carry
  `targets` (`SCAN_REGION_OVERSIZED_SKIPPED`/`READ_FAILED`/`SHORT_READ`
  and the like) to every limitation a targeted invocation can produce.
  Several do not: `pipe`'s and `obfuscation`'s own generic
  `SCAN_BUDGET_EXHAUSTED` (§5.6) carries no target at all (a pre-existing
  fact, not new to targeted mode); the new
  `TARGETED_SOURCE_NOT_EVALUATED` (§6.7, §8) is registered with
  `allowed_fields=frozenset({"scope"})` only — no `targets` field exists
  for it to carry, by this contract's own explicit design (§6.7's
  "targets" correction). Reconstructing a closure's range from
  `.limitations` therefore requires knowing, per limitation code,
  whether it happens to carry `targets` — fragile, and the wrong place
  to look regardless: **`details.targeted_scope` (below) is always the
  authoritative record of every closure's own `base_address`/`size`/
  `captured_size`/`capture_state`, for every closure, gap or clean,
  target-bearing limitation or not — cross-referenced by that closure's
  own `source`/`scope`, never assumed reconstructable from
  `.limitations` alone.** A `CoverageLimitation` that does carry
  `targets` (e.g. a genuine short read) still does so as useful,
  additional evidence — this is not a claim that no limitation should
  carry a target, only that no consumer may treat `.limitations` as a
  substitute for `targeted_scope`, in either direction.

  Beyond that correction, `CoverageReport.sources`/`.limitations` also
  carry nothing at all for a *clean* closure, since no
  `CoverageLimitation` is emitted when a source/scope evaluates the full
  requested range with no shortfall (`build_coverage_report()` only ever
  appends a limitation for a detected gap). Relying on
  `sources`/`limitations` alone would therefore leave a fully-completed,
  no-gap targeted `obfuscation` invocation unable to state that all three
  layers actually ran, or distinguish "this layer ran and
  found nothing" from "this layer was never attempted" — exactly the
  ambiguity §1's `NOT_EVALUATED`-vs-`NOT_DETECTED_IN_SCANNED_SCOPE`
  distinction exists to prevent for full-scope results, and one this
  contract must not silently reintroduce for targeted ones.

  `HunterRecord.details` is **not** a free-form or extensible field —
  correcting an earlier draft of this contract, which claimed otherwise
  and wrongly attributed that claim to #70 (#70's own document contains
  the string "details" zero times and makes no claim about it at all).
  `details` is strictly typed and closed at both layers: `HunterRecord.
  __post_init__` requires `isinstance(self.details,
  _HUNTER_DETAILS_TYPES[self.hunter])` against seven fixed dataclasses
  (`records.py:1691-1699,1775-1779`), each with its own field-validating
  `__post_init__` and a `to_dict()` emitting exactly its declared fields
  (e.g. `ObfuscationDetails`, `records.py:1661-1688`, emits exactly
  `sleep_mask`/`entropy`/`base64`/`xor`/`compressed`/`hidden_pe`/
  `hidden_shellcode`); the schema mirrors this exactly — every
  `*Details` `$def` in `dumpex-output-v2.13.schema.json` (e.g.
  `obfuscationDetails`) carries `additionalProperties: false` and an
  exhaustive `required` list, as does `hunterRecord` itself. Neither
  layer has room for a new key without editing the dataclass and the
  schema `$def` — there is no way to add `targeted_scope` to `details`
  without a real, declared code and schema change.

  This contract does not pretend otherwise. It freezes the **shape** of
  that declared change and assigns it to #65 (whose entire purpose is
  the "atomic CLI/schema cutover," §0.2) — exactly the same relationship
  #70 has to #71 for `AnalyzerSpec`, and consistent with §0.2's own "not
  a schema-file diff itself" framing, which was never a claim that no
  schema diff is needed, only that this document does not write it:

  - Exactly the five targeted-capable hunters' own `*Details` dataclasses
    — `PipeDetails`, `StompingDetails`, `CsBeaconDetails`, `YaraDetails`,
    `ObfuscationDetails` (`records.py:1595,1574,1621,1643,1661`) — each
    gain one new field, `targeted_scope: "list | None" = None`, validated
    (list of dict, or `None`) the same way every other field in that
    dataclass already is. `InjectionDetails`/`HollowingDetails` do
    **not** gain this field — those two hunters have no targeted
    capability at all (§4) and can never produce a non-`None` value.
  - **`to_dict()` omits the `"targeted_scope"` key entirely when the
    field is `None` — it never emits `null`.** Two earlier drafts of this
    bullet required the opposite (an always-present,
    sometimes-`null` key, matching `HunterRecord.max_score`/`.confidence`'s
    own convention) specifically to avoid a "sometimes-absent key," then
    spent real effort making that full-scope JSON delta survivable. §0.2
    now freezes the simpler, zero-impact design instead: `d["targeted_scope"]
    = [...]` is added to the returned dict only `if self.targeted_scope
    is not None`, so a full-scope result's `to_dict()` output contains no
    `targeted_scope` key at all — identical, key-for-key, to today's
    output. This intentionally diverges from `max_score`/`.confidence`'s
    own always-null convention (those fields are governed by
    `HunterRecord.__post_init__`'s own yara-only null/non-null validation
    rule, a different, pre-existing invariant this field does not share)
    — there is no requirement that every optional field in this codebase
    use the same presence convention, only that each one's own convention
    is stated precisely, which this bullet now does.
  - The matching schema `$def` for each of the five gains
    `"targeted_scope": {"type": "array", "items": {...}}` in its
    `properties` — **not added to `required`** (an earlier draft added it
    to `required` with a `["array", "null"]` type, which is what forced
    the golden-fixture/full-scope-compatibility discussion §0.2 now
    removes) — an optional property a full-scope result's `details`
    object simply does not carry. **This lands exclusively in whichever
    schema version #65's own cutover selects, never inside the v2.13
    schema file** — an earlier draft of this bullet left landing it
    inside "the still-frozen v2.13 schema" as harmless-and-optional up to
    #65's own discretion, which directly contradicts §0.2's own "v2.13
    remains frozen" and §10's "historical schemas remain frozen — nothing
    here retroactively reshapes a v2.13 or earlier document" (neither
    carves out an exception for an additive, currently-unused property);
    §0.2 already corrects this same error once for this exact field —
    this occurrence is the second, independent copy of it, now fixed to
    match.
  - Each list entry has this closed shape:

    ```json
    {
      "source":          "encoding_scan",
      "scope":            "entropy",
      "base_address":     "0x0000000010000000",
      "size":             1048576,
      "captured_size":    524288,
      "capture_state":    "partial",
      "coverage_status":  "partial"
    }
    ```

    `source`/`scope`/`base_address`/`size` are **always** exactly §6.1's
    closure identity — the requested values, unconditionally, never
    adjusted for what was actually captured. `captured_size` is the
    separate, actually-captured byte count (`ScanTarget.captured_size`,
    `coverage.py`) that `capture_state` is itself derived from
    (`None`/`"none"`/`"partial"`/`"complete"`, §7.1) — an earlier draft of
    this contract conflated "requested" and "captured" by omitting this
    field and then claiming `base_address`/`size` "only agree with
    `meta.execution.options` when `capture_state == complete`," which was
    self-contradictory given identity fields that cannot vary by
    definition; `captured_size` resolves it, but describes **byte
    availability only** — the count of requested bytes the dump actually
    contained and the capture step actually read — **never** "bytes the
    scan algorithm examined." A second earlier draft of this section
    called it "the actually-evaluated extent," which overstates what it
    measures: a candidate/window/deadline-gated scanner (§5.2–§5.5 — hit
    caps, candidate caps, time deadlines) can stop processing partway
    through a fully-`captured` buffer, and none of the five hunters'
    scan loops reports a byte-precise "examined so far" extent distinct
    from what was captured — `captured_size` cannot, and does not claim
    to, distinguish "all of it was captured and all of it was
    algorithmically examined" from "all of it was captured but the scan
    stopped partway through it." That distinction is exactly what
    `coverage_status` (below) exists to carry instead, at the coarser
    but honest granularity every hunter's own coverage model already
    supports (§6.5) — this contract does not add a byte-precise
    "examined extent" field, since no hunter today can honestly populate
    one for every scan shape (candidate-based and window-based scanners
    included), and freezing a field no adapter could correctly fill would
    be worse than not having it.
    `coverage_status` (named to avoid colliding with the unrelated,
    differently-valued `HunterRecord.status` field, which uses the
    four-value `_HUNT_STATUSES` vocabulary — this field does not) is the
    **three**-value `CoverageStatus` vocabulary (`complete`/`partial`/
    `not_evaluated`, §6.5) — an earlier draft of this contract limited it
    to two values and could not express a closure that never got to scan
    at all (§6.1, §6.5); this is corrected here. `coverage_status` and
    `capture_state` are deliberately not merged: `capture_state` can read
    `"complete"` (every requested byte was captured) while
    `coverage_status` reads `"partial"` (the scan over those captured
    bytes was itself truncated by a retained, non-bypassable budget —
    `scan_truncated`, `hit_cap_reached`, `match_timed_out`,
    `scan_budget_exhausted`, §5.2–§5.5) — collapsing the two into one
    field would silently misreport a budget-truncated scan as fully
    complete, which is exactly the ambiguity these two separate fields
    exist to remove. `coverage_status` as a name is not new to this
    codebase — it is the pre-migration v1.1 dict's own top-level field for
    exactly this three-value reduction, retired from the current v2
    `HunterRecord.to_dict()` shape and folded into `coverage.status`
    specifically to avoid "two sources of truth that could silently
    disagree" (`records.py:1711`'s own comment; `docs/hunt_analyzer_registry_contract.md`
    §5 cites the identical principle for execution order). Reusing the
    name here is not a regression of that migration: this field has no
    existing v2 counterpart to duplicate — it names a genuinely new,
    per-closure fact (§6.1) that v1.1 never had (v1.1 predates targeted
    scanning entirely), not a second copy of `HunterRecord.coverage.status`
    (which remains the single source of truth for the *aggregate*, §6.5).

  `targeted_scope` carries one entry per closure (§6.1) — exactly one
  for the four single-scope hunters, exactly three (in
  `OVERSIZE_SCAN_LAYERS` order) for `obfuscation` (§4.2) — including a
  clean, no-gap, fully-`"complete"` result, which is precisely the case
  §6.3's `limitations`-only shape cannot express on its own. A non-`null`
  `targeted_scope` is the authoritative way a schema consumer
  distinguishes a targeted result from a full-scope one — never
  `meta.execution.options.hunt_addr`, which is a general CLI-echo
  facility, not a result-shape discriminator. §6.1's closure identity
  (`base_address`/`size`) for evidentiary/coverage purposes is always
  read from `targeted_scope`, never reconstructed from
  `meta.execution.options` — the latter records what was *requested* as a
  bare CLI echo with no validation guarantee about how it was normalized,
  the former is the schema-validated identity `capture_state`/
  `captured_size`/`coverage_status` are anchored to; the two are expected
  to carry the same numeric values (§3.4 already forbids a targeted
  invocation from silently narrowing or resizing the requested range), but
  only `targeted_scope` is the field a schema consumer should read.

### 7.3 CSV

No CSV exporter exists for `--hunt` output today (confirmed: no `csv`
references in `dumpex/cli.py`). This contract has nothing to freeze for
CSV — if a hunt CSV exporter is added by a future issue, it must derive
its columns from the same existing `HunterRecord`/`CoverageReport`
fields §7.2 reuses, never from a parallel targeted-only field set.

---

## §8 Diagnostics, ordering, and exit-code behavior

- **Diagnostics**: every diagnostic a targeted invocation can produce is
  one of the existing `LimitationCode`/`SkipCause` values already
  enumerated in §1/§5, **with exactly two additions**:
  `LimitationCode.TARGETED_SOURCE_NOT_EVALUATED` (§6.7) and
  `LimitationCode.SCAN_REGION_EVALUATION_TRUNCATED` (§3.6) — an earlier
  draft of this bullet claimed no new diagnostic code is introduced at
  all, which directly contradicts both frozen designs and would wrongly
  license #65 to skip registering either; a later draft caught the first
  omission but not the second, introduced in a subsequent correction to
  §3.6 after this bullet was already written. These are the **only** two
  new `LimitationCode`s this contract adds; `SkipCause` gains nothing
  new, and no exit code changes (§8's own "Exit codes" bullet below).
  Landing them requires, all as part of the same reviewed change, for
  **each**: adding the enum member; a `_CODE_SPECS` entry —
  `absent_capable=True`/`caller_buildable` unset for
  `TARGETED_SOURCE_NOT_EVALUATED` (§6.7's own construction-time
  requirement — never both), `caller_buildable=True`/`absent_capable`
  unset for `SCAN_REGION_EVALUATION_TRUNCATED` (§3.6 — the opposite
  assignment, since this one is hand-built from a known gap, never
  auto-generated from source absence); `allowed_fields=frozenset({"scope"})`
  for the former, `frozenset({"scope", "targets"})` for the latter; the
  dedicated renderer each section specifies verbatim; and the same
  `test_output_coverage.py`-style construction-time coverage every other
  `LimitationCode` already has (`set(_CODE_SPECS) == set(LimitationCode)`
  already enforces the entries exist, per that test module's own
  mechanism, §0.1's research — but the *renderer text* and
  *construction-time validation* for each need their own dedicated tests
  the same way every other code's own PID_*/SYSINFO_* precedent already
  has, §0.1). #65 owns landing both alongside the rest of its own
  schema/CLI cutover (§0.2) — the same declared-delta category as
  `retain_completeness_checks_when_not_evaluated=True` and
  `EvaluationRequirement.scope`, not left to be silently rediscovered
  from §3.6/§6.7 alone without §8 also saying so. **#65's ownership here
  covers the two codes' own registration only** — the enum members,
  `_CODE_SPECS` entries, renderers, and their tests. The
  `_TARGET_BEARING_LIMITATION_CAUSES` entry for
  `SCAN_REGION_EVALUATION_TRUNCATED`, and the targeted queue-reachability
  gate without which that entry can never fire, are **#66's** (§3.6,
  §0.2, §10) — a deliberate split, not an oversight: a map entry landed at
  #65 with no reachable caller would be dead code until #66 anyway. §1's own vocabulary
  list is updated to match (below) so this fact lives in exactly one
  place, not four independently-maintained ones.
- **Ordering**: a targeted invocation always names exactly one identity
  (§2.1) — there is no multi-hunter ordering question for `--hunt-addr`
  the way `--hunt all`'s fixed `HUNTERS` order (#70 §2) answers for
  full-scope. Nothing about `HUNTERS`' order, `region_correlation`'s
  ordering, or `summary.py`'s ordering changes for a targeted invocation,
  since a targeted invocation never produces a multi-hunter summary. The
  one new multi-entry ordering this contract introduces is
  `obfuscation`'s three closures (§4.2, §6.1): both console output (§7.1)
  and `details.targeted_scope` (§7.2) list them in `OVERSIZE_SCAN_LAYERS`
  fixed order (`sleep_mask`, `entropy`, `decode`) — the same order
  `encoding/domain.py:57` and its own `_by_layer()` already use, never a
  score- or gap-severity-sorted order.
- **Exit codes**: unchanged. A targeted invocation's exit code is
  computed by the same `exit_code_for(coverage.status)`
  (`coverage.py:3616-3629`: `EXIT_OK=0` complete, `EXIT_PARTIAL=3`
  partial, `EXIT_NOT_EVALUATED=4` not_evaluated) applied to
  `HunterRecord.coverage.status` — §6.5's own cross-closure reduction
  (the single closure's completion for the four single-scope hunters; the
  reduction across all three per-layer closures for `obfuscation`, never
  a single caller-selected one) — no new exit code, and no special-cased
  exit-code path for targeted mode.

---

## §9 CLI failure behavior

Today's `cli.py` already has three distinct validation-failure shapes
(confirmed by direct read, §4 of this contract's own research):

- **(a) `parser.error(...)`** — argparse-level, `exit(2)`, printed before
  any dump is opened. Today's only example: `--ref-dir` not an existing
  directory (`cli.py:217-218`).
- **(b) `print(RED(...)); sys.exit(1)`** — semantic/business validation,
  after parsing, before or during dump handling. Today's examples: bad
  `--hunt` TTP (`hunt/__init__.py:202-203`), `--report` with no anchor
  (`cli.py:417-419`).
- **(c) `exit_code_for(coverage.status)`** — 0/3/4, only for a
  successfully-run command's own coverage result.

This contract assigns each targeted-hunt failure category to the shape
whose existing precedent it matches:

### 9.1 Pure argument-shape failures → shape (a), `parser.error()`, exit 2

Detectable before any dump is opened, exactly like `--ref-dir`'s own
check:

- `--hunt-addr` present without `--size` (§2.3 — the one required-together
  direction this contract enforces; `--size` present without
  `--hunt-addr` is explicitly **not** a failure, §2.3).
- `--hunt-addr`/`--size` not parseable by `parse_hex_or_int()`.
- `addr < 0` or `addr > _UINT64_MAX` (§2.4, §3.2).
- `size <= 0` (§2.4).
- `size` exceeds the applicable ceiling — `TARGETED_HUNT_MAX_REQUEST_BYTES`
  (256 MiB) for `pipe`/`stomping`/`yara`/`cs-beacon`,
  `TARGETED_OBFUSCATION_MAX_REQUEST_BYTES` (32 MiB) for `obfuscation`
  (§2.4, §5.5, §5.7) — the one identity-dependent check in this list;
  every other bullet here applies uniformly regardless of `identity`.
- `addr + size` exceeds `2**64` (§2.4, §3.2).
- `--hunt-addr` present without `--hunt` (§2.5).
- `--hunt-addr` present alongside any mode flag other than `--hunt`
  (`--extract`/`--strings`/`--report`/`--list`/`--diff`) (§2.5).

### 9.2 Hunter-capability failures → shape (b), `print(RED(...)); sys.exit(1)`

Require checking the requested identity against `HUNTERS`/the grant
matrix (§4), the same category as today's bad-TTP check, not a raw
argparse-level problem:

- `--hunt-addr` with `--hunt all` (§2.5, #58's and #70 §4's own rule that
  `"all"` is never `select_targeted()`-eligible).
- `--hunt-addr` with an identity outside `HUNTERS` (unknown hunter) — same
  message shape as today's `"Unknown TTP '{ttp}'. Choose from: ..."`
  (`hunt/__init__.py:202-203`), reusing that exact wording pattern.
- `--hunt-addr` with `injection` or `hollowing` — a **known**, valid
  `HUNTERS` member with **no targeted capability** (§4's `None` rows).
  This is a distinct message from "unknown hunter" (it names a real
  hunter that simply cannot be targeted-rescanned), matching #70 §6's own
  `select_targeted()` failure #10 shape (`targeted_capability is None`)
  rather than its failure #9 shape (unknown identity entirely) — the two
  must not be collapsed into one generic error, since an investigator
  needs to know "this hunter exists but doesn't support this mode" is a
  different fact from "you misspelled the hunter name."

`--triage-skipped` combined with `--hunt-addr` is **not** a failure (§2.5)
— it is accepted and silently inert, matching today's existing
single-identity full-scope behavior.

---

## §10 Compatibility considerations

- Blocked by #44 (closed).
- v2.13 remains frozen; the public schema version for this cutover is
  selected only at #65 (§0.2).
- Historical schemas remain frozen — nothing here retroactively reshapes
  a v2.13 or earlier document.
- Normal full-scope `--hunt`/`--hunt all` behavior, scoring, Finding IDs,
  ordering, console output, JSON output, exit codes, and every existing
  compatibility fixture (§0.2's named test modules) remain **genuinely,
  fully stable — no exception, declared or otherwise.** Two earlier
  drafts of this bullet named a declared full-scope JSON delta (an
  always-present, `null`-on-full-scope `targeted_scope` key); §0.2 now
  freezes the omitted-key design instead, under which no full-scope
  `details` object gains any new key at all. This contract adds a new
  invocation shape; it does not reinterpret or extend the existing one in
  any way, declared or otherwise.
- This document does not authorize changing any of #70's own frozen facts
  (the `cs-beacon`/`obfuscation` package-name mismatches, `TargetedScanUnit`'s
  three values, `AnalyzerSpec`'s closed field set). It supplies two things
  #70 left for this issue to decide: the populated `grants` field (§4,
  #70's own explicitly reserved field, §0.2 there) and the `targeted_scope`
  field on the five `*Details` dataclasses (§7.2, a field #70 never
  mentions or reserves — #70's document contains the string "details"
  zero times — so this is this contract's own addition, not a second
  reserved-field handoff from #70).
- #60 designs the `Range`/`CapturedRange` primitive against §3's frozen
  semantics; #61 converges #4's grant matrix with #70–#73's static
  registry and #60's range primitive into `HuntRequest`/
  `HuntExecutionContext`, sourcing each closure's `evaluated` fact from
  each adapter's own real execution outcome, never from `capture_state`
  (§6.5); #62/#63/#64 adapt each hunter's own reader to accept a
  requested range per §3.3–§3.6 and §5's per-hunter budget table,
  capturing the requested bytes once per invocation and reusing that
  capture across all three `obfuscation` layers rather than reading three
  times (§5.7); #65 performs the actual CLI/schema cutover per §2/§7 —
  **no golden-fixture regeneration is forced by `targeted_scope` itself**
  (§0.2/§7.2's omitted-key design leaves every existing full-scope golden
  fixture byte-identical; regeneration is only ever needed for whatever
  #65's own new targeted-mode scenarios add, never for full-scope ones);
  #66 wires
  investigation actions to emit the copyable command §58 describes,
  implementing §5.8's frozen policy verbatim for an oversized original
  target (one capped, explicitly partial/supplementary command;
  `coverage_effect` stays unresolved; no chunking plan implying gap
  closure), and — per §3.6 and §0.2 — lands the
  `_TARGET_BEARING_LIMITATION_CAUSES: {SCAN_REGION_EVALUATION_TRUNCATED:
  SCAN_TRUNCATED}` entry together with the change that makes
  `build_investigation_queue()` reachable for a single-hunter targeted
  invocation (today it runs only for `selected == "all"`,
  `hunt/__init__.py:82-84`, `:291`+`:310`), owning the one output-contract
  consequence that follows: `summary.investigation_actions` is no longer
  unconditionally `[]` for a single-hunter run. **Full-scope single-hunter
  runs still return `[]`** — every existing fixture stays byte-identical;
  only the new targeted shape gains a populated queue. #66 also completes
  compatibility/performance QA.
  None of the six may invent public CLI, schema, coverage, or exit-code
  behavior beyond what §2–§9 already fix.

---

## §11 Acceptance gate

- [x] Supported hunters and source/scope grants are complete and closed
      (§4 — the five-row matrix, with an exact-set equality against #70
      §7.1 failure #5's construction-time check).
- [x] CLI validation and range arithmetic are unambiguous (§2, §3, §9 —
      grammar, required-together rule, value shapes, half-open bounds,
      checked 64-bit arithmetic, and every failure's exact shape/exit
      code).
- [x] Size-cap bypass versus retained budgets is explicit (§5 — a closed
      bypassed-cap set per hunter/layer (two members for `decode`, one for
      every other row, §1/§5.5), every other budget's exact name and
      value listed and confirmed still enforced against real call-site
      behavior, not assumed from sharing; a separate, lower ceiling and
      honest per-resource worst case for `obfuscation` given
      `sleep_mask`'s real cost profile; §5.8's decided policy — bounded
      partial coverage, not claimed closure — for an original target
      larger than the applicable ceiling).
- [x] Full/targeted output and coverage semantics are frozen (§6, §7, §8 —
      closure identity with `captured_size` distinct from identity,
      `NOT_DETECTED_IN_SCANNED_SCOPE` reuse, the real three-value
      `coverage_status` reduction (reachable down to `EXIT_NOT_EVALUATED`),
      explicit gaps, cross-boundary handling, stomping source
      independence, console/JSON/CSV shape including the omitted-unless-
      targeted `targeted_scope` field (zero full-scope JSON impact),
      ordering, exit codes).
- [x] Every later child (#60, #61, #62, #63, #64, #65, #66) can implement
      without adding public behavior beyond §2–§9 (§0.2's non-goals list
      exactly what remains theirs to design, and §10 states the boundary
      each must not cross), and every declared delta to an existing module
      has exactly one named owner — including the split §3.6 freezes
      between #65 (the two new `LimitationCode`s' own registration, §8) and
      #66 (the `_TARGET_BEARING_LIMITATION_CAUSES` entry, the targeted
      queue-reachability gate that entry needs to fire, and the
      `summary.investigation_actions` output-contract consequence, §0.2,
      §3.6, §10).

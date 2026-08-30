# Hunt analyzer-registry contract

Status: **implemented**.

The built-in analyzer registry is the single ordered operational catalog used
by `--hunt`. This document describes the current registry and executor contract.
Hunter-domain ownership rules are in [Hunt architecture](hunt_architecture.md).

## Identity and ordering

`dumpex.output.records.HUNTERS` is the public identity vocabulary and order:

```text
injection, hollowing, stomping, pipe, cs-beacon, yara, obfuscation
```

`HUNTERS` is appropriate for CLI validation, schema enums, summaries, and other
places that need names. `dumpex.hunt._registry.AnalyzerRegistry` maps those names
to executable adapters and capabilities. Neither is a substitute for the other.

`all` is a selection mode accepted by `AnalyzerRegistry.select()`; it is never an
analyzer identity, never appears in `HUNTERS`, and never has an `AnalyzerSpec`.
Registration order must exactly equal `HUNTERS`. There is no independently
stored ordinal that can drift from the public order.

## Current built-in catalog

| Identity | Package | Report | Builder option names | Provenance | Full scope | Targeted unit |
|---|---|---|---|---|---|---|
| `injection` | `dumpex.hunt.injection` | `InjectionReport` | none | none | yes | none |
| `hollowing` | `dumpex.hunt.hollowing` | `HollowingReport` | none | none | yes | none |
| `stomping` | `dumpex.hunt.stomping` | `StompingReport` | `ref_dir` | none | yes | region |
| `pipe` | `dumpex.hunt.pipe` | `PipeReport` | none | none | yes | region |
| `cs-beacon` | `dumpex.hunt.cs_beacon` | `CSBeaconReport` | none | none | yes | segment |
| `yara` | `dumpex.hunt.yara_hunt` | `YaraReport` | `rules_dir` | report-local YARA rule provenance | yes | segment |
| `obfuscation` | `dumpex.hunt.encoding` | `EncodingReport` | none | none | yes | region+layer |

The five targeted-capable specs carry the grants frozen by the
[targeted-rescan contract](hunt_targeted_rescan_contract.md) capability matrix:
`pipe`/`pipe_name_scan`, `stomping`/`ioc_string_scan`,
`cs-beacon`/`segment_scan`, `yara`/`segment_scan`, and
`obfuscation`/`encoding_scan` with layer scopes `sleep_mask`, `entropy`,
`decode`. `select_targeted()` resolves a single granted `(source, scope)`;
`select_targeted_scopes()` resolves the whole scope SET one request will
attempt (empty for an unscoped source, the full granted layer set for
obfuscation -- there is no public per-layer selection). Every other
combination fails closed. Each `TargetedCapability` also carries a
`request_ceiling` (256 MiB for pipe/stomping/cs-beacon/yara, 32 MiB for
obfuscation) -- the per-analyzer safety bound the targeted-rescan matrix
freezes, kept on the capability rather than in a second identity-keyed table,
and cross-checked at import against `_EXPECTED_TARGETED_REQUEST_CEILINGS`.
`obfuscation`, `yara`, and `cs-beacon` carry a `targeted_adapter`
(`dumpex.hunt._run_targeted_obfuscation` /  `_run_targeted_yara` /
`_run_targeted_cs_beacon`, resolving to
`dumpex.hunt.encoding.targeted.run_targeted_encoding`,
`dumpex.hunt.yara_hunt.targeted.run_targeted_yara`, and
`dumpex.hunt.cs_beacon.targeted.run_targeted_cs_beacon`); `pipe` and `stomping`
do not yet, so `resolve_targeted_adapter()` still fails closed for those two
until their executors land. Injection and hollowing have
`targeted_capability=None`.

## `AnalyzerSpec`

`AnalyzerSpec` is a frozen dataclass with exactly these fields:

1. `identity: str`
2. `package: str`
3. `report_type: type`
4. `builder: Callable`
5. `renderer: Callable`
6. `record_projector: Callable`
7. `option_names: frozenset[str]`
8. `provenance_hook: Callable | None`
9. `full_scope_capable: bool`
10. `targeted_capability: TargetedCapability | None` — `scan_unit`, the closed
    grant set, and `request_ceiling` (bytes; the largest targeted range this
    analyzer may be asked for, cross-checked at import).
11. `targeted_adapter: Callable | None` — the executor a targeted-scan run
    calls as `adapter(context)`, or `None`. Non-`None` for `obfuscation`,
    `yara`, and `cs-beacon` today (each late-bound through its own
    `dumpex.hunt._run_targeted_*` facade name, exactly as the
    builder/renderer/projector are); `None` for the other four. Registered
    through `_register(..., targeted_adapter_attr=)`,
    which resolves the real target and checks it at construction for exactly
    one positionally-passable `context` parameter, the same way the
    builder/renderer/projector signatures are. A non-`None` adapter requires a
    non-`None` `targeted_capability`.
12. `builder_arg: "mf" | "context"` — the builder's first positional
    parameter. `"mf"` (every current spec) receives the raw dump handle;
    `"context"` receives the whole `HuntExecutionContext`, for a builder that
    consumes the shared observation registry or budgets. `_register()`
    validates it against the real builder signature; `AnalyzerSpec.__post_init__`
    additionally rejects a directly-constructed spec whose builder's first
    parameter name contradicts the declared `builder_arg`.

Construction validates non-empty strings, exact report types, callable adapter
fields and signatures, immutable option/capability sets, known option names,
and boolean capability flags. A spec must be usable in at least one execution
mode. A targeted capability is validated against the identity's fixed scan
unit, real public coverage-source vocabulary, and closed scope vocabulary.
Empty `TargetedGrant.scopes` means “the source has no finer subdivision,” not
“all scopes are allowed.” Empty `TargetedCapability.grants` means “not yet
granted,” not “unrestricted.” A `targeted_capability` authorizes routing only;
it does not imply an executable `targeted_adapter`.

Registry construction snapshots the sequence to a tuple and validates:

- every item is a valid `AnalyzerSpec`;
- identities are unique, complete, and in `HUNTERS` order;
- each report type is the expected domain report for that identity;
- the targeted-capable identity set is exactly `pipe`, `stomping`,
  `cs-beacon`, `yara`, and `obfuscation`;
- adapter signatures and defaults match the executor boundary; and
- dispatcher option names and registry option names are identical.

These are developer/configuration failures and therefore fail at construction
or import time. They are not converted into partial dump coverage.

## Lookup and selection

- `get(identity)` performs exact lookup of one registered identity. It rejects
  unknown names and `all` with `UnknownAnalyzerIdentity`.
- `select("all")` returns every full-scope-capable spec in registry order.
- `select(identity)` returns a one-item tuple for a known full-scope-capable
  analyzer. A known targeted-only analyzer raises
  `UnsupportedFullScopeRequest`.
- `select_targeted(identity, source, scope=None)` first resolves a real
  identity, then requires a non-null targeted capability, at least one grant,
  a matching source, and a symmetric scope match. It raises the specific
  `UnknownAnalyzerIdentity`, `UnsupportedTargetedCapability`,
  `UnpopulatedTargetedGrant`, `UnsupportedTargetedSource`, or
  `UnsupportedTargetedScope` failure and never guesses or broadens a grant.
- `select_targeted(identity, source, scope=None)` is the single-`(source,
  scope)` grant primitive. It does **not** authorize a whole invocation (a
  request carries a scope *set*, and obfuscation always attempts all three
  layers) — `HuntRequest` and `resolve_targeted_adapter` both use
  `select_targeted_scopes()` instead. Keep `select_targeted` only where a
  single grant genuinely is the question.
- `select_targeted_scopes(identity, source, scopes: frozenset)` validates the
  whole scope set one `HuntRequest` will attempt: an unscoped source requires
  an empty set, a scoped source (obfuscation) requires its full granted layer
  set. Identity / capability / grant / source are checked before the scope set
  (so an unknown identity is `UnknownAnalyzerIdentity` whatever `scopes` is),
  and a non-frozenset `scopes` is a `TypeError`, not a scope failure.
- `granted_scopes(identity, source)` resolves "the granted set" (empty for an
  unscoped source, obfuscation's three layers, empty for an unknown one) so a
  caller — `HuntRequest`, `#64` — never restates it.
- `resolve_targeted_adapter(identity, source, scopes: frozenset = frozenset())`
  resolves the grant **and the scope set** through `select_targeted_scopes()`
  (so the executor boundary and the `HuntRequest` boundary agree — a single
  obfuscation layer is illegal at both), then requires a `targeted_adapter` and
  returns `(spec, adapter)`. A granted capability with no adapter raises
  `UnsupportedTargetedExecution`.

Call sites keep their established user-facing validation and error wording.
Registry exceptions are typed internal boundaries; they do not license CLI,
diagnostic, or exit-code drift.

## Execution invariants

Builder, renderer, record-projector, and (where present) targeted-adapter
callables are late-bound by name through the `dumpex.hunt` facade on every call.
Existing monkeypatch seams therefore continue to work, and importing the
registry does not introduce a circular import through the facade — each
targeted adapter's own module (`dumpex.hunt.encoding.targeted`,
`dumpex.hunt.yara_hunt.targeted`, `dumpex.hunt.cs_beacon.targeted`) is imported
lazily inside its facade function for that reason.

`_execute_full_scope()` builds one `HuntRequest.full(...)` and one
`HuntExecutionContext` per invocation. Each builder receives the dump handle
(`builder_arg="mf"`) or the whole context (`builder_arg="context"`) by its
declared convention. Every current builder takes `"mf"`; a builder switches to
`"context"` when it needs the shared observation registry or budgets, and only
that builder and its spec change.

For each selected spec and invocation:

1. Validate the complete option view before calling any builder (fail closed;
   do not run some analyzers and then discover another cannot be called).
2. Call the builder exactly once with only the option names declared by that
   spec.
3. Pass that same report instance to the record projector.
4. Pass the same instance to the renderer only for a rendering command; the
   collection-only path stays silent.
5. Pass the same instance to its provenance hook, when present.

The registry chooses adapters. The request-scoped layer lives in separate
modules and never in `AnalyzerSpec` or the built-in catalog:

- `dumpex.hunt._request.HuntRequest` — normalized investigator intent
  (`full` or `targeted` scope, selected analyzer, approved `HuntOptions`, and
  for a targeted request the granted `source`, a `targeted_scopes` frozenset,
  and a `VirtualRange`). An empty `targeted_scopes` resolves to
  `REGISTRY.granted_scopes(...)` — empty for an unscoped source, obfuscation's
  three layers — so `#64` never restates them; an explicit set is kept and
  validated equal. Every constructor path — not only the `full()`/`targeted()`
  convenience methods — validates against the registry
  (`select_targeted_scopes()`) and the analyzer's `request_ceiling`, reading
  `_registry.REGISTRY` lazily so a test that patches it affects request
  validation too. `HuntOptions` normalizes a falsy value to `None` and an
  `os.PathLike` to its string form, so `--ref-dir ""` / `--yara-dir ""` behave
  exactly as before.
- `dumpex.hunt._execution.HuntExecutionContext` — one invocation's dump
  handle, `ObservationRegistry`, `HuntBudgetLedger`, and the
  `dumpex.core.va_range` captured-segment/region views, enumerated once and
  memoized. Built through `build_execution_context(mf, request)`; `eq=False`
  (it is an identity object). The context creates its own registry and ledger
  (they are `init=False` — cannot be handed in) and `claim()`s each; a
  registry or ledger reaching a second context raises. `ObservationKey`
  carries no dump identity, so this is what stops one dump's cached
  observations from being served for another. `context.observation_key(analyzer, algorithm_version=..., …)`
  is the canonical key factory: it fills `is_targeted` and the
  configuration/rule provenance from the request. An analyzer whose spec
  declares a `ref_dir` / `rules_dir` option always gets a provenance token —
  the explicit argument, the request's option value, or the fixed
  `"ref_dir:unset"` / `"rules_dir:unset"` sentinel — so a configured run and an
  unconfigured run produce different keys (the common unset case is encoded,
  not refused); an analyzer with no such option gets `None`. Read/runtime
  facades are deliberately not on the
  context — a context-aware builder builds its own `HunterRuntime` from its own
  (per-hunter monkeypatchable) facade globals. `_FullScopeExecution.context`
  carries the context out of `_execute_full_scope()`, so the observation
  instrumentation is reachable, not dropped.
- `dumpex.hunt._observation` — execution identity and closure attribution are
  two different types:
  - `ObservationKey` is *execution identity*: `analyzer`, `is_targeted`, the
    exact `requested_range` (`None` only for a genuinely dump-wide aggregate),
    `config_provenance`, `rule_provenance`, `algorithm_version`. It carries no
    `source` and no `scope` — an originating relationship's
    `source`/`scope`/`cause` is attribution, not a reason to re-run the same
    analyzer over the same bytes. Two relationships differing only in
    attribution build the same key, so the producer runs once. `coverage_locus`
    is `(analyzer, is_targeted, requested_range)` — two keys sharing a locus
    but not equal are the incompatible-cache case.
  - `ObservationClosure` is *closure attribution*: one independently validated
    `(source, scope)` closure with its own honest `coverage_status` /
    `read_slice` / `limitations` (structured `CoverageLimitation`) /
    `budget_outcomes` (structured `BudgetOutcome`). One `ObservationResult`
    holds a tuple of them; `result.closure_for(source, scope)` returns one
    closure's own status and raises for an unprojected one — never falls back
    to an aggregate. So one reused observation can expose a complete
    `pipe_name` closure and a partial `c2_context` closure at the same time,
    and reading `c2_context` never returns `complete`.
  - `ObservationResult` is immutable; capture/read/coverage facts are
    cross-checked: a closure's `read_slice` must match the key's range and its
    own `capture_state`; a short read or an incomplete capture cannot be
    `complete`; a range-local closure with no capture is `not_evaluated`,
    otherwise it carries its `read_slice`. **Capture is a per-key fact** —
    every closure of one key must agree on `capture_state` and share one
    `CapturedSlice` (the range is captured once and shared by every closure).
    Each closure's `source` is validated against its analyzer's real coverage
    vocabulary — read through `_registry.coverage_sources_for(identity)` /
    `closed_scope_vocab_for(identity, source)`, never the private tables. A
    closure's `scope` is checked only *if present*: a layer-agnostic
    `encoding_scan` closure (a whole-analyzer budget exhaustion belongs to no
    layer) is legitimate; only an invented layer name is rejected.
  - `ObservationRegistry.get_or_compute(key, producer)` runs the producer **at
    most once per key** — never after a success, a failure (tombstoned as a
    lightweight type/message pair; the fallback tombstone and `FAILED` event
    are written before any of the exception's own formatting, so even a
    `__str__` that raises, or a producer that raises `KeyboardInterrupt`,
    still tombstones and runs once), or a saturated refusal. Saturation is
    **never silent**: once the distinct-key count (retained results plus
    failure tombstones) reaches `max_entries`, `get_or_compute` records
    `SATURATED` and *raises* `ObservationBudgetExhausted` rather than return
    `None`, so a caller cannot fall through to a clean negative. There is no
    eviction. `_entries`, `_events`, and `_failures` are all `init=False`, so a
    shared/process-wide cache is not constructible. `counts()` is an exact
    running tally; `event_overflow` reports dropped history entries.

None of these may mutate the built-in catalog. Domain detection remains owned
by the hunter packages, not by the registry.

## Failure model

Construction-time failures include malformed specs, missing/duplicate/reordered
registrations, wrong report types, invalid callable signatures/defaults,
unknown option names, invalid capability/source/scope shapes, and disagreement
between the dispatcher and registry option vocabularies. They are hard failures
because they can only result from an in-tree programming/configuration error.

Call-time selection failures are the typed lookup/capability errors listed
above (`UnknownAnalyzerIdentity`, `UnsupportedFullScopeRequest`,
`UnsupportedTargetedCapability`, `UnpopulatedTargetedGrant`,
`UnsupportedTargetedSource`, `UnsupportedTargetedScope`, and
`UnsupportedTargetedExecution`). Adapter exceptions are not swallowed or
converted into a clean result.
Dump-evidence gaps belong in the hunter's ordinary coverage and diagnostic
model; registry/configuration defects do not.

## Extension checklist

To add a built-in analyzer:

1. Add its public identity once to `HUNTERS` at the intended fixed position.
2. Add and export its domain report, builder, console renderer, and typed record
   projector following [Hunt architecture](hunt_architecture.md).
3. Add its expected report type and one `AnalyzerSpec` in the same order.
4. Declare only real executor options and decide full-scope capability.
5. If targeted-capable, define the scan unit, public source vocabulary, closed
   scopes, and grants; otherwise use `None`.
6. Add focused construction, selection, late-binding, one-build, same-instance,
   output, failure, and compatibility coverage.
7. Update current docs and schema references without changing older public
   behavior accidentally.

The current registry is closed, ordered, and reviewed. It performs no dynamic
third-party discovery and exposes no runtime `register()` method. A future
external-analyzer framework may connect through a separate, explicit, validated
boundary; untrusted external code must not inject into or mutate the built-in
registry directly.

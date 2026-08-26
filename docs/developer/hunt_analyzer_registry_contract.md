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

The five targeted-capable specs currently carry empty grant sets. That means
their capability shape is declared but targeted selection fails closed until
the live [targeted-rescan contract](hunt_targeted_rescan_contract.md) is
implemented. Injection and hollowing have `targeted_capability=None`.

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
10. `targeted_capability: TargetedCapability | None`

Construction validates non-empty strings, exact report types, callable adapter
fields and signatures, immutable option/capability sets, known option names,
and boolean capability flags. A spec must be usable in at least one execution
mode. A targeted capability is validated against the identity's fixed scan
unit, real public coverage-source vocabulary, and closed scope vocabulary.
Empty `TargetedGrant.scopes` means “the source has no finer subdivision,” not
“all scopes are allowed.” Empty `TargetedCapability.grants` means “not yet
granted,” not “unrestricted.”

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

Call sites keep their established user-facing validation and error wording.
Registry exceptions are typed internal boundaries; they do not license CLI,
diagnostic, or exit-code drift.

## Execution invariants

Builder, renderer, and record-projector adapters are late-bound by name through
the `dumpex.hunt` facade on every call. Existing monkeypatch seams therefore
continue to work, and importing the registry does not introduce a circular
import through the facade.

For each selected spec and invocation:

1. Validate the complete option view before calling any builder (fail closed;
   do not run some analyzers and then discover another cannot be called).
2. Call the builder exactly once with only the option names declared by that
   spec.
3. Pass that same report instance to the record projector.
4. Pass the same instance to the renderer only for a rendering command; the
   collection-only path stays silent.
5. Pass the same instance to its provenance hook, when present.

The registry chooses adapters. A logical `HuntRequest` owns normalized
investigator intent; `HuntExecutionContext` owns per-invocation dump handles,
options, budgets, and captured data; `ObservationRegistry` owns reusable
observations. None of those request/runtime objects belongs in `AnalyzerSpec`,
and none may mutate the built-in catalog. Domain detection remains owned by the
hunter packages, not by the registry.

## Failure model

Construction-time failures include malformed specs, missing/duplicate/reordered
registrations, wrong report types, invalid callable signatures/defaults,
unknown option names, invalid capability/source/scope shapes, and disagreement
between the dispatcher and registry option vocabularies. They are hard failures
because they can only result from an in-tree programming/configuration error.

Call-time selection failures are the five typed lookup/capability errors listed
above. Adapter exceptions are not swallowed or converted into a clean result.
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

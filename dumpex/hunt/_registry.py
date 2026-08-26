"""Closed, immutable catalog of the seven hunt analyzers.

Each validated AnalyzerSpec defines its builder, projections, options,
provenance hook, and full-scope or targeted capability. Construction failures
represent developer configuration errors and fail at import.

Dispatcher callables are resolved late from the hunt facade to avoid circular
imports and preserve supported monkeypatch seams.
"""
import inspect
import sys
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Callable

from dumpex.output.records import HUNTERS

from dumpex.hunt.injection.domain import InjectionReport
from dumpex.hunt.hollowing.domain import HollowingReport
from dumpex.hunt.stomping.domain import StompingReport
from dumpex.hunt.pipe.domain import PipeReport
from dumpex.hunt.cs_beacon.domain import CSBeaconReport
from dumpex.hunt.yara_hunt.domain import YaraReport
from dumpex.hunt.encoding.domain import EncodingReport

from dumpex.hunt.encoding.domain import OVERSIZE_SCAN_LAYERS
from dumpex.hunt.pipe.report_facts import COVERAGE_SOURCE_NAMES as _PIPE_SOURCES
from dumpex.hunt.stomping.report_facts import COVERAGE_SOURCE_NAMES as _STOMPING_SOURCES
from dumpex.hunt.cs_beacon.report_facts import COVERAGE_SOURCE_NAMES as _CS_BEACON_SOURCES
from dumpex.hunt.yara_hunt.report_facts import COVERAGE_SOURCE_NAMES as _YARA_SOURCES
from dumpex.hunt.encoding.report_facts import COVERAGE_SOURCE_NAMES as _ENCODING_SOURCES


# ── Exceptions ──────────────────────────────────────────────────────────
# One exception type per §7 failure family -- never a bare Exception/
# ValueError, so a caller (or a test) can catch exactly the gate that
# fired rather than pattern-matching message text.

class InvalidAnalyzerSpec(Exception):
    """Construction-time failure (contract §7.1, failures #1-#8) -- raised
    while this module's own top-level registration code runs, which means
    it always fires at import time, never per-invocation."""


class UnknownAnalyzerIdentity(Exception):
    """Call-time failure #9 -- `identity`/`selected` is not a real
    `HUNTERS` member (or, for `get()`/`select_targeted()`, is `"all"`,
    which is a valid `select()` argument but never a registered spec)."""

    def __init__(self, value, valid):
        self.value = value
        self.valid = frozenset(valid)
        super().__init__(
            f"unknown analyzer identity {value!r} -- must be one of "
            f"{sorted(self.valid)}")


class UnsupportedTargetedCapability(Exception):
    """Call-time failure #10 -- `identity` is real but its
    `targeted_capability` is `None` (`injection`/`hollowing` today, or a
    future analyzer that never opted in)."""

    def __init__(self, identity):
        self.identity = identity
        super().__init__(f"{identity!r} has no targeted-scan capability")


class UnsupportedFullScopeRequest(Exception):
    """Call-time failure #11 -- `identity` is real but its
    `full_scope_capable` is `False`. Unreachable this release (all seven
    specs are `full_scope_capable=True`); exists for the first
    targeted-only analyzer (contract §10 item 4)."""

    def __init__(self, identity):
        self.identity = identity
        super().__init__(f"{identity!r} is not full-scope capable")


class UnpopulatedTargetedGrant(Exception):
    """Call-time failure #12 -- `targeted_capability` is non-`None` but its
    `grants` is empty. `frozenset()` means "not yet granted", never
    "unrestricted" -- see the contract's own §1/§7.2 discussion of why this
    must fail closed. Fires for all five targeted-capable identities this
    release, unconditionally (#59 decides grant contents, #61 writes
    them)."""

    def __init__(self, identity):
        self.identity = identity
        super().__init__(
            f"{identity!r} has a declared targeted capability but no "
            f"populated grants yet")


class UnsupportedTargetedSource(Exception):
    """Call-time failure #13 -- `source` matches no `TargetedGrant` in the
    resolved `targeted_capability.grants`."""

    def __init__(self, identity, source):
        self.identity = identity
        self.source = source
        super().__init__(f"{identity!r} has no targeted grant for source {source!r}")


class UnsupportedTargetedScope(Exception):
    """Call-time failure #14 -- `source` matched, but no matching grant's
    `scopes` authorizes the requested `scope` (symmetric: an empty
    `scopes` only authorizes `scope=None`; a non-empty `scopes` only
    authorizes a named member, never `None`)."""

    def __init__(self, identity, source, scope):
        self.identity = identity
        self.source = source
        self.scope = scope
        super().__init__(
            f"{identity!r}/{source!r} has no targeted grant for scope {scope!r}")


def _defaults_match(actual, expected) -> bool:
    """`actual == expected` is wrong for the two default values the
    contract actually freezes (`None`, `False`): both are singletons where
    Python's `==` is looser than the frozen-value identity this check
    needs (`0 == False` is `True`, and a badly-behaved `__eq__` could make
    an unrelated object compare equal to `None`). Every frozen default in
    this contract is one of those two singletons, so identity (`is`) is
    the correct comparison, not equality."""
    if expected is None or isinstance(expected, bool):
        return actual is expected
    return actual == expected


def _require_equal_sets(actual: set, expected: set, description: str) -> None:
    """A plain `if`/`raise`, deliberately NOT a bare `assert` -- `python
    -O`/`PYTHONOPTIMIZE` strips `assert` statements entirely, which would
    silently turn this module's own import-time fail-closed invariants
    (every one of them a developer-facing "did you forget to update a
    roster artifact" check, never something a dump/investigator input
    could trigger) into no-ops under an optimized interpreter -- exactly
    the guarantee contract §7.1 exists to make unconditional."""
    if actual != expected:
        raise InvalidAnalyzerSpec(
            f"{description}: expected {sorted(expected)}, got {sorted(actual)}")


def _require_subset(actual: set, allowed: set, description: str) -> None:
    """Same rationale as `_require_equal_sets` (a real `if`/`raise`, never
    a bare `assert`), for the weaker "no extra members" relationship a
    mapping that need not cover every approved identity still requires."""
    extra = actual - allowed
    if extra:
        raise InvalidAnalyzerSpec(
            f"{description}: {sorted(extra)} not in {sorted(allowed)}")


# ── TargetedScanUnit / TargetedGrant / TargetedCapability (contract §1) ──

class TargetedScanUnit(Enum):
    """Which existing gap vocabulary an analyzer already reports coverage
    gaps in -- a fact already true of the shipped code today (contract
    §1), not a new design decision. `REGION` -- a `MemoryInfo` range.
    `SEGMENT` -- a contiguous scanned byte run (YARA's/CS Beacon's own
    vocabulary). `REGION_LAYER` -- obfuscation's own three-tier decode
    model (`OVERSIZE_SCAN_LAYERS`)."""
    REGION = "region"
    SEGMENT = "segment"
    REGION_LAYER = "region+layer"


def _require_str(value, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise InvalidAnalyzerSpec(
            f"{field_name} must be a non-empty str, got {value!r}")


@dataclass(frozen=True)
class TargetedGrant:
    """One `(source, scopes)` pair naming a targetable unit of one
    analyzer's own public coverage-source vocabulary (contract §1).
    `source` is a `CoverageLimitation.source`-shaped public source name
    (e.g. `"ioc_string_scan"`), never a `CoverageSnapshot` internal field
    name. `scopes` is empty unless the source has named sub-scopes
    (obfuscation's `OVERSIZE_SCAN_LAYERS`); an empty `scopes` means "no
    finer subdivision", never "unrestricted"."""
    source: str
    scopes: frozenset

    def __post_init__(self):
        _require_str(self.source, "TargetedGrant.source")
        if not isinstance(self.scopes, frozenset) or not all(
                isinstance(s, str) for s in self.scopes):
            raise InvalidAnalyzerSpec(
                f"TargetedGrant.scopes must be a frozenset[str], got {self.scopes!r}")


@dataclass(frozen=True)
class TargetedCapability:
    """The value `AnalyzerSpec.targeted_capability` holds when non-`None`
    (contract §1) -- a `scan_unit` tag plus the closed set of grants
    populated so far (empty this release for all five targeted-capable
    analyzers; #59 decides contents, #61 writes them)."""
    scan_unit: TargetedScanUnit
    grants: frozenset

    def __post_init__(self):
        if not isinstance(self.scan_unit, TargetedScanUnit):
            raise InvalidAnalyzerSpec(
                f"TargetedCapability.scan_unit must be a TargetedScanUnit, "
                f"got {self.scan_unit!r}")
        if not isinstance(self.grants, frozenset) or not all(
                isinstance(g, TargetedGrant) for g in self.grants):
            raise InvalidAnalyzerSpec(
                f"TargetedCapability.grants must be a frozenset[TargetedGrant], "
                f"got {self.grants!r}")


# Approved first-release targeted-scan identity set (#58) -- checked as an
# exact-set equality over the full registration, both directions (contract
# §7.1 failure #5).
_APPROVED_TARGETED_IDENTITIES = frozenset({
    "pipe", "stomping", "cs-beacon", "yara", "obfuscation",
})

# Each targeted-capable analyzer's own frozen `scan_unit` (contract §3's
# matrix column) -- bound to identity here so a mis-registered
# `TargetedCapability(TargetedScanUnit.SEGMENT, ...)` on `stomping` (whose
# own gap vocabulary is region-shaped, per §1) is a construction-time
# failure, not a silent acceptance. Checked for exact-set equality against
# `_APPROVED_TARGETED_IDENTITIES` below -- `injection`/`hollowing` must
# never appear here, the same way they must never carry a
# `targeted_capability` at all.
_EXPECTED_TARGETED_SCAN_UNITS = {
    "pipe": TargetedScanUnit.REGION,
    "stomping": TargetedScanUnit.REGION,
    "cs-beacon": TargetedScanUnit.SEGMENT,
    "yara": TargetedScanUnit.SEGMENT,
    "obfuscation": TargetedScanUnit.REGION_LAYER,
}
_require_equal_sets(
    set(_EXPECTED_TARGETED_SCAN_UNITS), _APPROVED_TARGETED_IDENTITIES,
    "_EXPECTED_TARGETED_SCAN_UNITS must exactly match _APPROVED_TARGETED_IDENTITIES")

# Each targeted-capable analyzer's own real, public coverage-source
# vocabulary (contract §7.1 failure #5's ".source" gap-closing
# requirement) -- imported from each hunter's own report_facts.py, never
# duplicated here as a second literal. Completeness (no missing, no extra
# entry) is asserted once here -- see `_validate_targeted_capability_shape`
# below for why a MISSING per-identity entry must fail closed rather than
# silently skip source validation for that identity.
_COVERAGE_SOURCE_NAMES_BY_IDENTITY = {
    "pipe": _PIPE_SOURCES,
    "stomping": _STOMPING_SOURCES,
    "cs-beacon": _CS_BEACON_SOURCES,
    "yara": _YARA_SOURCES,
    "obfuscation": _ENCODING_SOURCES,
}
_require_equal_sets(
    set(_COVERAGE_SOURCE_NAMES_BY_IDENTITY), _APPROVED_TARGETED_IDENTITIES,
    "_COVERAGE_SOURCE_NAMES_BY_IDENTITY must exactly match _APPROVED_TARGETED_IDENTITIES")

# The one `(source, closed scope vocabulary)` pair with a CLOSED,
# statically-importable scope vocabulary today -- obfuscation's
# `encoding_scan` -> `OVERSIZE_SCAN_LAYERS`. Corrected from an earlier
# version of this mapping (`_SCOPED_TARGETED_SOURCE_BY_IDENTITY = {
# "obfuscation": "encoding_scan"}`) that named the source but left the
# ALLOWED-SCOPES value hard-wired to `OVERSIZE_SCAN_LAYERS` inside the
# validation loop below, regardless of which identity/source actually
# matched -- so a second entry (e.g. a future `"pipe":
# "pipe_name_scan"`) would have been validated against OBFUSCATION's own
# vocabulary instead of its own. The vocabulary now lives IN the mapping,
# keyed by the same (source, scopes) pair every entry carries, so a
# second entry brings its own scopes with it by construction and cannot
# silently borrow obfuscation's.
#
# `pipe`/`yara`/`cs-beacon` are deliberately absent -- corrected from an
# earlier version of this module's own comment, which claimed "only
# obfuscation emits a scope on any CoverageLimitation", a broader claim
# direct read of the tree disproves: pipe (`pipe_name_scan`,
# scope="c2_context"/"pipe_name"), yara (`segment_scan`,
# scope="max_total_hits"/a budget-exhaustion kind), and cs-beacon
# (`segment_scan`, scope=a budget-exhaustion kind) each already emit a
# non-`None` `scope` on some `CoverageLimitation` (see the
# `test_*_scope_emitting_branches_*` fixtures in
# tests/unit/test_analyzer_registry.py, which drive each of these
# branches directly and pin the real, observed values). What is actually
# true, and what this mapping actually encodes, is narrower: those other
# `scope` values are dynamic budget-kind/sub-signal tags with no fixed,
# closed, importable constant the way `OVERSIZE_SCAN_LAYERS` already is
# for obfuscation -- there is nothing yet for a `TargetedGrant.scopes`
# value to be validated against for pipe's own
# `"c2_context"`/`"pipe_name"` distinction (a real, and reasonable,
# candidate for a future `PIPE_SCAN_SCOPES` constant alongside
# `COVERAGE_SOURCE_NAMES`), so this release does not grant it. Extending
# this mapping to a source whose scope vocabulary becomes closed and
# importable is a `#59` capability-matrix decision (the same kind of
# decision contract §3's own matrix makes), not a forgotten update --
# nothing here should be read as "pipe's budget-kind scopes will never be
# targetable", only "they are not today". Any such extension must add its
# OWN vocabulary value here, never reuse `OVERSIZE_SCAN_LAYERS` -- the
# import-time checks below enforce the source half of that (the added
# source must be real for its identity); the scopes half is enforced by
# construction, since there is no shared hard-wired constant left to
# accidentally reuse.
#
# Keyed by identity -> (source, scopes), not merely by identity: an
# identity may have more than one targeted-capable source in the future,
# and a grant against a DIFFERENT source under the same identity (e.g. a
# hypothetical future obfuscation source other than `encoding_scan`) must
# still require empty `scopes` -- scoping is a property of the SOURCE, not
# of the identity as a whole (contract §1's own `TargetedGrant.scopes`
# discussion: "a source is not always the finest targetable unit").
_SCOPED_TARGETED_SOURCES = {
    "obfuscation": ("encoding_scan", frozenset(OVERSIZE_SCAN_LAYERS)),
}


def _validate_scoped_sources(mapping: dict) -> None:
    """Extracted into its own function (rather than a bare module-level
    `for`/`if`/`raise` block) for two reasons: (1) a bare loop's own
    control-flow variables (`_identity`/`_source`/`_scopes` in an earlier
    version of this code) leak into module scope once the loop ends, and a
    trailing `del` to clean them up crashes with an unrelated
    `NameError: name '_identity' is not defined` the day `mapping` is ever
    empty (the loop body -- and therefore the `for` target assignment --
    never runs) -- exactly the kind of import-time failure whose own
    diagnostic must name the actual bad field, per contract §7.1, not an
    accident of Python scoping; a function's own local variables need no
    such cleanup and have no such failure mode. (2) a named function is
    independently unit-testable against a synthetic mapping, without
    needing to reconstruct or monkeypatch this module's own real
    `_SCOPED_TARGETED_SOURCES`."""
    _require_subset(
        set(mapping), _APPROVED_TARGETED_IDENTITIES,
        "_SCOPED_TARGETED_SOURCES keys must be a subset of _APPROVED_TARGETED_IDENTITIES")
    for identity, entry in mapping.items():
        # Validate the entry's own SHAPE before unpacking it -- `for
        # identity, (source, scopes) in mapping.items():` unpacks the
        # value eagerly, so a malformed entry (a bare string, a one- or
        # three-element tuple, `None`, ...) raises a bare `ValueError`/
        # `TypeError` from the `for` statement itself, before this
        # function's own `InvalidAnalyzerSpec` checks ever run -- exactly
        # the class of leak `_safe_signature`/`_resolve_callable` already
        # closed for the adapter-resolution path, reproduced here for a
        # different reason (tuple unpacking instead of introspection).
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise InvalidAnalyzerSpec(
                f"_SCOPED_TARGETED_SOURCES[{identity!r}] must be a "
                f"(source, scopes) 2-tuple, got {entry!r}")
        source, scopes = entry
        if not isinstance(source, str) or not source:
            raise InvalidAnalyzerSpec(
                f"_SCOPED_TARGETED_SOURCES[{identity!r}] source must be a "
                f"non-empty str, got {source!r}")
        if not isinstance(scopes, frozenset) or not scopes or not all(
                isinstance(s, str) and s for s in scopes):
            raise InvalidAnalyzerSpec(
                f"_SCOPED_TARGETED_SOURCES[{identity!r}] scopes must be a "
                f"non-empty frozenset of non-empty str, got {scopes!r}")
        if source not in _COVERAGE_SOURCE_NAMES_BY_IDENTITY[identity]:
            raise InvalidAnalyzerSpec(
                f"_SCOPED_TARGETED_SOURCES[{identity!r}] names source "
                f"{source!r}, which is not one of {identity}'s real coverage "
                f"sources {sorted(_COVERAGE_SOURCE_NAMES_BY_IDENTITY[identity])}")


_validate_scoped_sources(_SCOPED_TARGETED_SOURCES)


# The full set of option keyword names `_execute_full_scope()`
# (`dumpex/hunt/__init__.py`) actually knows how to supply a value for --
# the single source of truth `AnalyzerSpec.option_names` (§5 field 7) must
# be a subset of. Finding (closed by #73): §7.1 failure #7's own
# `option_names`/builder-signature check only validates `option_names`
# against the BUILDER's own signature, in both directions -- it never
# validates `option_names` against what `_execute_full_scope()` itself
# can actually pass, since that dict (`{"ref_dir": ref_dir, "rules_dir":
# yara_dir}`) lives entirely inside `dumpex/hunt/__init__.py`, outside
# this module. A spec whose `option_names` names a real, correctly-
# defaulted builder keyword that is NOT one of these two names used to
# construct successfully -- passing every existing check -- and would
# only fail with a bare `KeyError` partway through `_execute_full_scope`'s
# own selection loop, AFTER every earlier-selected analyzer's builder had
# already run (see `dumpex/hunt/__init__.py`'s own `options[name] for name
# in spec.option_names` line), directly violating the "before any
# analyzer work begins" guarantee this whole section exists to provide.
# `dumpex/hunt/__init__.py` imports this constant rather than
# independently re-deriving its own `options` dict's key set, so the two
# can never silently drift apart again.
KNOWN_OPTION_NAMES = frozenset({"ref_dir", "rules_dir"})


# ── AnalyzerSpec (contract §5) ─────────────────────────────────────────

@dataclass(frozen=True)
class AnalyzerSpec:
    """One analyzer's closed, immutable operational boundary -- exactly
    the ten matrix columns of contract §3, no more. Deliberately NOT
    reusing `dumpex.hunt._domain.require_recursively_immutable`: that
    helper's own leaf-type allowlist rejects any callable outright, and
    fields 4-6/8 here are exactly that. `AnalyzerSpec.__post_init__`
    instead validates each field's own shape directly.

    Deliberately not a field: execution order (a spec's position is its
    index in the registry's own registration sequence, validated against
    `HUNTERS.index(identity)` at construction -- never a second,
    independently-settable ordinal). Deliberately never a field value: a
    dump handle, a raw scan buffer, or any other mutable parser object --
    every callable field is typed as a callable that ACCEPTS a
    `Report`/`mf` argument, never an already-invoked result. This is
    enforced STRUCTURALLY, by field typing (`type`/`frozenset[str]`/`bool`/
    `TargetedCapability | None`, plus `callable(...)` for the four
    function fields), not by a runtime scan of a callable's own closure --
    a `MinidumpFile` itself is none of those types and so cannot occupy
    any field directly, but a closure or `functools.partial` that has
    already CAPTURED an `mf` (e.g. `functools.partial(fn, mf)`) still
    passes `callable(...)` unchallenged, exactly like every other callable
    field. Nothing in this module's own registration code produces such a
    closure -- every real `builder`/`renderer`/`record_projector` is
    late-bound by NAME via `_late_bound()` (§8), never bound to a captured
    `mf` -- so this is a real, but so-far theoretical, gap left to
    registration discipline for any future direct `AnalyzerSpec(...)`
    construction, not something this module's own seven registrations can
    trigger.
    """
    identity: str
    package: str
    report_type: type
    builder: Callable
    renderer: Callable
    record_projector: Callable
    option_names: frozenset
    provenance_hook: "Callable | None"
    full_scope_capable: bool
    targeted_capability: "TargetedCapability | None"

    def __post_init__(self):
        if self.identity not in HUNTERS:
            raise InvalidAnalyzerSpec(
                f"AnalyzerSpec.identity must be one of {HUNTERS}, got "
                f"{self.identity!r}")
        _require_str(self.package, "AnalyzerSpec.package")
        if not isinstance(self.report_type, type):
            raise InvalidAnalyzerSpec(
                f"AnalyzerSpec.report_type must be a type, got {self.report_type!r}")
        for name in ("builder", "renderer", "record_projector"):
            if not callable(getattr(self, name)):
                raise InvalidAnalyzerSpec(
                    f"AnalyzerSpec.{name} must be callable, got "
                    f"{getattr(self, name)!r}")
        if self.provenance_hook is not None:
            _validate_provenance_hook_shape(self.provenance_hook)
        if not isinstance(self.option_names, frozenset) or not all(
                isinstance(o, str) for o in self.option_names):
            raise InvalidAnalyzerSpec(
                f"AnalyzerSpec.option_names must be a frozenset[str], got "
                f"{self.option_names!r}")
        if not self.option_names <= KNOWN_OPTION_NAMES:
            raise InvalidAnalyzerSpec(
                f"{self.identity}: option_names "
                f"{sorted(self.option_names - KNOWN_OPTION_NAMES)} are not known "
                f"to _execute_full_scope() -- must be a subset of "
                f"{sorted(KNOWN_OPTION_NAMES)}")
        if not isinstance(self.full_scope_capable, bool):
            raise InvalidAnalyzerSpec(
                f"AnalyzerSpec.full_scope_capable must be a bool, got "
                f"{self.full_scope_capable!r}")
        if (self.targeted_capability is not None
                and not isinstance(self.targeted_capability, TargetedCapability)):
            raise InvalidAnalyzerSpec(
                f"AnalyzerSpec.targeted_capability must be None or a "
                f"TargetedCapability, got {self.targeted_capability!r}")
        if not self.full_scope_capable and self.targeted_capability is None:
            raise InvalidAnalyzerSpec(
                f"{self.identity}: full_scope_capable=False and "
                f"targeted_capability=None together -- an analyzer that "
                f"could run in neither mode")
        if self.targeted_capability is not None:
            self._validate_targeted_capability_shape()

    def _validate_targeted_capability_shape(self) -> None:
        # Both lookups below are deliberately unconditional membership
        # checks (`not in`, never `.get(...) is None`) -- a MISSING
        # per-identity entry must fail closed here, at construction, even
        # when `grants` is still empty (this release's actual shipped
        # state for all five). A `.get()` that only validated inside the
        # `for grant in ...` loop below would never fire while `grants`
        # stays empty, silently reproducing the exact fail-open gap this
        # check exists to close the day someone adds an eighth identity to
        # `HUNTERS`/`_APPROVED_TARGETED_IDENTITIES` and forgets the
        # matching entry here.
        if self.identity not in _EXPECTED_TARGETED_SCAN_UNITS:
            raise InvalidAnalyzerSpec(
                f"{self.identity}: no expected targeted scan_unit on file -- "
                f"_EXPECTED_TARGETED_SCAN_UNITS is missing an entry for this "
                f"targeted-capable identity")
        expected_scan_unit = _EXPECTED_TARGETED_SCAN_UNITS[self.identity]
        if self.targeted_capability.scan_unit is not expected_scan_unit:
            raise InvalidAnalyzerSpec(
                f"{self.identity}: targeted_capability.scan_unit must be "
                f"{expected_scan_unit!r}, got {self.targeted_capability.scan_unit!r}")

        if self.identity not in _COVERAGE_SOURCE_NAMES_BY_IDENTITY:
            raise InvalidAnalyzerSpec(
                f"{self.identity}: no coverage-source vocabulary on file -- "
                f"_COVERAGE_SOURCE_NAMES_BY_IDENTITY is missing an entry for "
                f"this targeted-capable identity")
        allowed_sources = _COVERAGE_SOURCE_NAMES_BY_IDENTITY[self.identity]

        # The (source, allowed-scopes) pair that's closed/importable for
        # THIS identity (only `obfuscation`'s `("encoding_scan",
        # OVERSIZE_SCAN_LAYERS)` today) -- both halves come from
        # `_SCOPED_TARGETED_SOURCES` itself, never a shared/hard-wired
        # constant, so a grant against a DIFFERENT real source under the
        # same identity (e.g. a hypothetical `TargetedGrant("memory_info",
        # {"sleep_mask"})` under `obfuscation`) still requires empty
        # `scopes`, and a SECOND identity's own entry (a future `#59`
        # addition) is validated against ITS OWN scopes value, never
        # obfuscation's by accident.
        scoped_entry = _SCOPED_TARGETED_SOURCES.get(self.identity)
        for grant in self.targeted_capability.grants:
            if grant.source not in allowed_sources:
                raise InvalidAnalyzerSpec(
                    f"{self.identity}: TargetedGrant.source={grant.source!r} is "
                    f"not one of this analyzer's real coverage sources "
                    f"{sorted(allowed_sources)}")
            if scoped_entry is not None and grant.source == scoped_entry[0]:
                allowed_scopes = scoped_entry[1]
                # Empty `scopes` is legal for an UNSCOPED source (§1: "no
                # finer subdivision"), but this source is a KNOWN-scoped
                # one -- `_SCOPED_TARGETED_SOURCES` says so -- so an empty
                # grant here means the caller never picked a layer, not
                # "no layers exist". Accepting it would let
                # `select_targeted(identity, source, scope=None)` succeed
                # against a source the contract requires an explicit
                # layer choice for (§6's own symmetric-match rule), the
                # exact bypass this check exists to close: `set() <=
                # allowed_scopes` is vacuously true for ANY non-empty
                # `allowed_scopes`, so the subset check alone never
                # catches an empty grant.
                if not grant.scopes:
                    raise InvalidAnalyzerSpec(
                        f"{self.identity}: TargetedGrant.scopes must be "
                        f"non-empty for source {grant.source!r}, which has a "
                        f"closed scope vocabulary {sorted(allowed_scopes)} -- "
                        f"an explicit layer must be chosen")
                if not set(grant.scopes) <= allowed_scopes:
                    raise InvalidAnalyzerSpec(
                        f"{self.identity}: TargetedGrant.scopes={grant.scopes!r} "
                        f"must be a subset of {sorted(allowed_scopes)}")
            elif grant.scopes != frozenset():
                raise InvalidAnalyzerSpec(
                    f"{self.identity}: TargetedGrant.scopes must be empty for "
                    f"source {grant.source!r}, got {grant.scopes!r}")


# ── AnalyzerRegistry (contract §6) ─────────────────────────────────────

class AnalyzerRegistry:
    """Single, module-level, import-time-constructed catalog, closed over
    exactly the seven registrations `_build_registrations()` declares --
    no runtime `register()` method is exposed to any caller.

    `__init__` itself runs `_validate_registrations()` -- every
    `AnalyzerRegistry(...)` construction is validated, unconditionally,
    with no way to reach a live instance that skipped it. An earlier
    version of this module called `_validate_registrations()` as a
    separate, standalone module-level statement after building
    `REGISTRY` -- syntactically adjacent to the constructor call, but not
    actually PART of it, so nothing stopped a caller (or a future edit)
    from constructing an `AnalyzerRegistry` directly and skipping
    validation entirely. Binding it to `__init__` closes that gap at the
    type itself, not merely at this module's own current call site."""

    def __init__(self, specs: tuple):
        # Snapshotted to a real tuple BEFORE validation and BEFORE either
        # internal field is built -- a type hint of `specs: tuple` is not
        # enforced at runtime, so a caller passing a `list` (complete,
        # correctly ordered, and therefore accepted by
        # `_validate_registrations`) could otherwise keep a live reference
        # to the exact sequence backing `self._specs`, and later mutate it
        # out from under an already-"validated" registry -- `_by_identity`
        # (a `MappingProxyType` snapshot dict comprehension) would stay
        # correct, but `self._specs`/`select("all")`/`_all_specs()` would
        # silently drift out of sync with it and with `HUNTERS`, reopening
        # the exact "validated once, then mutated" gap binding validation
        # to `__init__` was meant to close.
        specs = tuple(specs)
        _validate_registrations(specs)
        self._specs = specs
        self._by_identity = MappingProxyType({spec.identity: spec for spec in specs})

    @classmethod
    def _construct_unvalidated(cls, specs: tuple) -> "AnalyzerRegistry":
        """Test-only escape hatch that skips `_validate_registrations()`.
        Exists so a unit test can build a deliberately small/partial
        synthetic registry (e.g. one spec, to exercise `select_targeted()`
        in isolation) without every such test needing a full, valid
        seven-spec roster. Never used by production registration code --
        `REGISTRY` below is always built through the validating
        `__init__`, and this method's own leading underscore marks it as
        the same kind of test-only seam `_all_specs()` already is (contract
        §6) -- production code must not reach for it. Skips content
        validation, but still snapshots `specs` to a tuple first, the same
        as the real `__init__` -- an unvalidated registry is allowed to be
        wrong on purpose (that's the point), but it must not additionally
        hold a live reference to a caller's own mutable container."""
        self = cls.__new__(cls)
        specs = tuple(specs)
        self._specs = specs
        self._by_identity = MappingProxyType({spec.identity: spec for spec in specs})
        return self

    def _all_specs(self) -> tuple:
        """The complete registration sequence, UNFILTERED by
        `full_scope_capable` or any other field. Leading underscore is
        load-bearing, not cosmetic (contract §6): this exists only for
        this module's own construction-time tests and the roster
        cross-check to assert completeness/order independently of
        `select("all")`'s own capability filtering -- never for
        `collect_hunt()`/`cmd_hunt()`, which must go through
        `select()`/`select_targeted()` only."""
        return self._specs

    def get(self, identity: str) -> AnalyzerSpec:
        """Exact-match single lookup. `identity` must be a real, actually-
        registered member of THIS registry; `"all"` is rejected (it is
        never a registered spec)."""
        if identity not in self._by_identity:
            raise UnknownAnalyzerIdentity(identity, set(self._by_identity))
        return self._by_identity[identity]

    def select(self, selected: str) -> tuple:
        """The one full-scope entry point `collect_hunt()`/`cmd_hunt()`
        call (after #72). `selected == "all"` returns every
        `full_scope_capable` registration in `HUNTERS` order. A single
        identity is gated the same way -- `full_scope_capable=False`
        fails exactly like the `"all"` branch's own filtering would."""
        if selected == "all":
            return tuple(spec for spec in self._specs if spec.full_scope_capable)
        if selected not in self._by_identity:
            raise UnknownAnalyzerIdentity(selected, set(self._by_identity) | {"all"})
        spec = self._by_identity[selected]
        if not spec.full_scope_capable:
            raise UnsupportedFullScopeRequest(selected)
        return (spec,)

    def select_targeted(self, identity: str, source: str, scope: "str | None" = None) -> AnalyzerSpec:
        """The one entry point a future targeted-scan call site (#61,
        after #59/#60) uses. Answers "is `source`/`scope` granted", not
        merely "does this analyzer have any grant at all" -- see the
        contract's own §6 discussion of the symmetric `scopes` match."""
        if identity not in self._by_identity:
            raise UnknownAnalyzerIdentity(identity, set(self._by_identity))
        spec = self._by_identity[identity]
        if spec.targeted_capability is None:
            raise UnsupportedTargetedCapability(identity)
        capability = spec.targeted_capability
        if not capability.grants:
            raise UnpopulatedTargetedGrant(identity)
        matching = [g for g in capability.grants if g.source == source]
        if not matching:
            raise UnsupportedTargetedSource(identity, source)
        authorized = any(
            (not g.scopes and scope is None)
            or (g.scopes and scope is not None and scope in g.scopes)
            for g in matching
        )
        if not authorized:
            raise UnsupportedTargetedScope(identity, source, scope)
        return spec


# ── Registration (contract §7.1, §8) ───────────────────────────────────

# Every domain `Report` class this release expects, by identity -- itself
# a roster artifact (contract §7.1 failure #6, §10 item 2): checked once,
# not per-spec.
EXPECTED_REPORT_TYPES = {
    "injection": InjectionReport,
    "hollowing": HollowingReport,
    "stomping": StompingReport,
    "pipe": PipeReport,
    "cs-beacon": CSBeaconReport,
    "yara": YaraReport,
    "obfuscation": EncodingReport,
}
_require_equal_sets(
    set(EXPECTED_REPORT_TYPES), set(HUNTERS),
    "EXPECTED_REPORT_TYPES must exactly match HUNTERS")

_DISPATCHER_MODULE = "dumpex.hunt"


def _late_bound(attr_name: str) -> Callable:
    """Resolve `attr_name` off `sys.modules["dumpex.hunt"]` on EVERY call,
    never once at import time -- the seam
    `monkeypatch.setattr(dumpex.hunt, attr_name, fake)` depends on
    (contract §8). Deliberately not a top-level `import dumpex.hunt`
    followed by attribute access -- see this module's own docstring on why
    that would risk a circular import."""
    def _call(*args, **kwargs):
        target = getattr(sys.modules[_DISPATCHER_MODULE], attr_name)
        return target(*args, **kwargs)
    return _call


_POSITIONALLY_PASSABLE = (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
_VAR_KINDS = (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)


_UNDEFINED = object()   # sentinel distinct from a real attribute value of None


def _safe_signature(target, label: str) -> inspect.Signature:
    """`inspect.signature()` raises `ValueError` for a callable with no
    introspectable signature (a C builtin like `range`/`type`/
    `itertools.repeat`) and can raise `TypeError` for certain uninspectable
    objects -- both must become `InvalidAnalyzerSpec`, never leak as a
    bare stdlib exception. This module's own header promises "One
    exception type per §7 failure family — never a bare Exception/
    ValueError, so a caller (or a test) can catch exactly the gate that
    fired" -- `_resolve_callable`'s own fix for a missing dispatcher
    attribute closed one manifestation of a stdlib exception leaking past
    that promise; this closes the rest, at the one place every one of
    `_resolve_and_validate_builder`/`_renderer`/`_projector`/
    `_validate_provenance_hook_shape` calls into `inspect.signature()`."""
    try:
        return inspect.signature(target)
    except (ValueError, TypeError) as exc:
        raise InvalidAnalyzerSpec(f"{label}: cannot introspect signature: {exc}") from exc


def _resolve_callable(attr_name: str):
    target = getattr(sys.modules[_DISPATCHER_MODULE], attr_name, _UNDEFINED)
    if target is _UNDEFINED:
        raise InvalidAnalyzerSpec(
            f"{attr_name} is not defined on {_DISPATCHER_MODULE} -- a typo'd "
            f"or removed facade name must fail registration, not raise a "
            f"bare AttributeError")
    if not callable(target):
        raise InvalidAnalyzerSpec(f"{attr_name} is not callable")
    return target


def _resolve_and_validate_builder(attr_name: str, option_defaults: dict) -> Callable:
    """Resolve the REAL target once, here, at registration time (facade
    imports are already complete by the time this module's top-level code
    runs -- contract §6's own import-ordering guarantee) to validate its
    full real signature -- not just parameter NAMES, and not just "has
    SOME default" -- against `option_defaults` (contract §7.1 failure #7).
    `spec.builder` itself stays late-bound (`_late_bound` above), so
    monkeypatching after construction is untouched by this signature check
    having already run once.

    `option_defaults` maps each declared option's name to the EXACT
    default value contract §3's matrix freezes for it (`{"ref_dir": None}`
    for stomping, `{"rules_dir": None}` for yara, `{}` for the other five)
    -- `AnalyzerSpec.option_names` (the field the contract actually
    defines) is `frozenset(option_defaults)`, derived here rather than
    passed twice.

    A name-only check (comparing declared names against
    `{p.name for p in params if p.name != "mf"}`) accepts several shapes
    that are not actually valid closed-option builders: `def builder():`
    (missing `mf` entirely), `def builder(mf, **kwargs):` (an open
    `**kwargs` bag defeats the whole point of a closed option set), `def
    builder(mf, ref_dir):` (a REQUIRED option, when the frozen matrix says
    `ref_dir: str | None = None`), a keyword-only `mf`, or -- the gap a
    "has *some* default" check alone still leaves open -- `def
    builder(mf, ref_dir="unexpected"):`, whose default is present but
    wrong. Every one of those must fail here, at construction, not with a
    `TypeError` (or a silently wrong default) the first time some caller
    invokes `spec.builder(mf)`/`spec.builder(mf, ref_dir=...)` -- which can
    be well after a dump is open.
    """
    target = _resolve_callable(attr_name)
    sig = _safe_signature(target, attr_name)
    params = list(sig.parameters.values())
    if not params or params[0].name != "mf" or params[0].kind not in _POSITIONALLY_PASSABLE:
        raise InvalidAnalyzerSpec(
            f"{attr_name}: first parameter must be a positionally-passable "
            f"'mf', got {[p.name for p in params]!r}")
    rest = params[1:]
    for param in rest:
        if param.kind in _VAR_KINDS:
            raise InvalidAnalyzerSpec(
                f"{attr_name}: builder must not declare *args/**kwargs "
                f"(found {param.name!r}, {param.kind}) -- a closed "
                f"option set cannot coexist with an open catch-all")
        if param.kind not in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY):
            raise InvalidAnalyzerSpec(
                f"{attr_name}: option parameter {param.name!r} must be "
                f"keyword-passable, got kind={param.kind}")
        if param.default is inspect.Parameter.empty:
            raise InvalidAnalyzerSpec(
                f"{attr_name}: option parameter {param.name!r} has no "
                f"default -- every declared option must be optional, since "
                f"not every caller supplies it")
    accepted = {param.name for param in rest}
    declared = set(option_defaults)
    if not declared <= accepted:
        raise InvalidAnalyzerSpec(
            f"{attr_name}: option_names {sorted(declared - accepted)} are not "
            f"real builder keyword(s)")
    if not accepted <= declared:
        raise InvalidAnalyzerSpec(
            f"{attr_name}: builder accepts keyword(s) {sorted(accepted - declared)} "
            f"missing from option_names")
    for param in rest:
        expected_default = option_defaults[param.name]
        if not _defaults_match(param.default, expected_default):
            raise InvalidAnalyzerSpec(
                f"{attr_name}: option {param.name!r} must default to "
                f"{expected_default!r} (the contract-frozen value), got "
                f"{param.default!r}")
    # Belt-and-suspenders: confirm the shape the late-bound wrapper (and
    # every real call site) actually uses -- builder(mf, **option_values)
    # -- binds cleanly against the real signature, not just that each
    # parameter individually looked right in isolation.
    try:
        sig.bind(object(), **{name: None for name in declared})
    except TypeError as exc:
        raise InvalidAnalyzerSpec(
            f"{attr_name}: cannot be called as builder(mf, **option_names): {exc}")
    return _late_bound(attr_name)


# The one default value contract §3's matrix freezes for every renderer's
# second parameter -- `(report, verbose: bool = False)`, all seven,
# confirmed by direct read (§3's own table). Not merely "must have some
# default": `def renderer(report, verbose=True):` must fail too.
_EXPECTED_RENDERER_VERBOSE_DEFAULT = False


def _resolve_and_validate_renderer(attr_name: str) -> Callable:
    """Same resolve-then-inspect treatment as the builder above --
    `callable(...)` alone (or a name-only check) would accept a renderer
    missing `verbose`, one with an unexpected third parameter, one where
    `verbose` has no default (or the WRONG default -- `verbose=True`), or
    one declared keyword-only (`def renderer(*, report, verbose=False):`)
    -- every real call site (`spec.renderer(report, False)`) passes both
    positionally, so a keyword-only signature would pass a name check yet
    raise `TypeError` on first real use (contract §7.1 failure #7)."""
    target = _resolve_callable(attr_name)
    sig = _safe_signature(target, attr_name)
    params = list(sig.parameters.values())
    if len(params) != 2:
        raise InvalidAnalyzerSpec(
            f"{attr_name}: renderer must accept exactly (report, verbose), "
            f"got {[p.name for p in params]!r}")
    report_param, verbose_param = params
    for param, expected_name in ((report_param, "report"), (verbose_param, "verbose")):
        if param.name != expected_name or param.kind not in _POSITIONALLY_PASSABLE:
            raise InvalidAnalyzerSpec(
                f"{attr_name}: parameter {param.name!r} must be a "
                f"positionally-passable {expected_name!r}, got kind={param.kind}")
    if not _defaults_match(verbose_param.default, _EXPECTED_RENDERER_VERBOSE_DEFAULT):
        raise InvalidAnalyzerSpec(
            f"{attr_name}: renderer's verbose parameter must default to "
            f"{_EXPECTED_RENDERER_VERBOSE_DEFAULT!r} (the contract-frozen "
            f"value), got {verbose_param.default!r}")
    try:
        sig.bind(object(), False)
    except TypeError as exc:
        raise InvalidAnalyzerSpec(
            f"{attr_name}: cannot be called as renderer(report, verbose): {exc}")
    return _late_bound(attr_name)


def _resolve_and_validate_projector(attr_name: str) -> Callable:
    """Same treatment for `record_projector` -- must accept exactly
    `(report)`, positionally, never keyword-only (contract §7.1 failure
    #7). `def projector(*, report):` would pass a name-only check yet
    raise `TypeError` the first time `spec.record_projector(report)` is
    called positionally, exactly like the renderer case above."""
    target = _resolve_callable(attr_name)
    sig = _safe_signature(target, attr_name)
    params = list(sig.parameters.values())
    if len(params) != 1 or params[0].name != "report" or params[0].kind not in _POSITIONALLY_PASSABLE:
        raise InvalidAnalyzerSpec(
            f"{attr_name}: record_projector must accept exactly a "
            f"positionally-passable (report), got {[p.name for p in params]!r}")
    try:
        sig.bind(object())
    except TypeError as exc:
        raise InvalidAnalyzerSpec(
            f"{attr_name}: cannot be called as record_projector(report): {exc}")
    return _late_bound(attr_name)


def _validate_provenance_hook_shape(hook) -> None:
    """`AnalyzerSpec.provenance_hook` gets the same resolve-then-inspect
    treatment `builder`/`renderer`/`record_projector` get above --
    `callable(...)` alone is exactly what contract §7.1 failure #7 calls
    out as insufficient for those three, and `provenance_hook` is no
    different: a zero-arg or wrong-arity hook passes `callable()` and only
    raises `TypeError` the first time some caller (#72's own
    `V2Output.set_yara_provenance()` wiring) actually invokes it against a
    real `Report` -- which can be well after a dump is open and a scan has
    run, exactly the "before any analyzer work begins" guarantee this
    section exists to provide. Unlike the other three, `provenance_hook`
    is not a dispatcher-facing name resolved via `_resolve_callable` --
    it is already a plain function/lambda object (`_yara_provenance_hook`
    below) passed directly into `AnalyzerSpec`, so this validates the
    object itself rather than resolving one off `sys.modules`."""
    if not callable(hook):
        raise InvalidAnalyzerSpec(
            f"AnalyzerSpec.provenance_hook must be None or callable, got {hook!r}")
    sig = _safe_signature(hook, "AnalyzerSpec.provenance_hook")
    params = list(sig.parameters.values())
    if len(params) != 1 or params[0].kind not in _POSITIONALLY_PASSABLE:
        raise InvalidAnalyzerSpec(
            f"AnalyzerSpec.provenance_hook must accept exactly one "
            f"positionally-passable parameter (the Report), got "
            f"{[p.name for p in params]!r}")
    try:
        sig.bind(object())
    except TypeError as exc:
        raise InvalidAnalyzerSpec(
            f"AnalyzerSpec.provenance_hook cannot be called as hook(report): {exc}")


def _register(identity: str, package: str, report_type: type, builder_attr: str,
              renderer_attr: str, projector_attr: str, option_defaults: dict,
              provenance_hook, full_scope_capable: bool,
              targeted_capability) -> AnalyzerSpec:
    return AnalyzerSpec(
        identity=identity,
        package=package,
        report_type=report_type,
        builder=_resolve_and_validate_builder(builder_attr, option_defaults),
        renderer=_resolve_and_validate_renderer(renderer_attr),
        record_projector=_resolve_and_validate_projector(projector_attr),
        option_names=frozenset(option_defaults),
        provenance_hook=provenance_hook,
        full_scope_capable=full_scope_capable,
        targeted_capability=targeted_capability,
    )


# `yara`'s own provenance hook (contract §5 field 8, §3) -- owns the
# `RulesProvenance -> dict` conversion `dumpex/hunt/__init__.py:258-259`
# performs today, so every caller always receives an already-JSON-safe
# `dict | None`, never the raw dataclass. Reads `report.coverage.rules.
# provenance` off the `Report` INSTANCE passed to it -- never
# `dumpex.hunt.yara_hunt.get_yara_provenance()`'s process-wide global (see
# tests/integration/test_yara_provenance_attribution.py).
def _yara_provenance_hook(report) -> "dict | None":
    provenance = report.coverage.rules.provenance
    return provenance.to_dict() if provenance is not None else None


def _build_registrations() -> tuple:
    return (
        _register(
            "injection", "dumpex.hunt.injection", InjectionReport,
            "_build_injection_report", "_render_injection_console",
            "_record_from_injection_report", {}, None,
            full_scope_capable=True, targeted_capability=None),
        _register(
            "hollowing", "dumpex.hunt.hollowing", HollowingReport,
            "_build_hollowing_report", "_render_hollowing_console",
            "_record_from_hollowing_report", {}, None,
            full_scope_capable=True, targeted_capability=None),
        _register(
            "stomping", "dumpex.hunt.stomping", StompingReport,
            "_build_stomping_report", "_render_stomping_console",
            "_record_from_stomping_report", {"ref_dir": None}, None,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(TargetedScanUnit.REGION, frozenset())),
        _register(
            "pipe", "dumpex.hunt.pipe", PipeReport,
            "_build_pipe_report", "_render_pipe_console",
            "_record_from_pipe_report", {}, None,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(TargetedScanUnit.REGION, frozenset())),
        _register(
            "cs-beacon", "dumpex.hunt.cs_beacon", CSBeaconReport,
            "_build_cs_beacon_report", "_render_cs_beacon_console",
            "_record_from_cs_beacon_report", {}, None,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(TargetedScanUnit.SEGMENT, frozenset())),
        _register(
            "yara", "dumpex.hunt.yara_hunt", YaraReport,
            "_build_yara_report", "_render_yara_console",
            "_record_from_yara_report", {"rules_dir": None}, _yara_provenance_hook,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(TargetedScanUnit.SEGMENT, frozenset())),
        _register(
            "obfuscation", "dumpex.hunt.encoding", EncodingReport,
            "_build_encoding_report", "_render_encoding_console",
            "_record_from_encoding_report", {}, None,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(TargetedScanUnit.REGION_LAYER, frozenset())),
    )


def _validate_registrations(specs: tuple) -> None:
    """Registry-level checks that need the full registration set, not one
    spec at a time -- duplicate/missing/reordered identity (§7.1 failures
    #1/#2/#4), wrong report type (#6), and the approved-targeted-identity
    exact-set equality (#5's second half)."""
    seen = set()
    for index, spec in enumerate(specs):
        if spec.identity in seen:
            raise InvalidAnalyzerSpec(f"duplicate analyzer identity {spec.identity!r}")
        seen.add(spec.identity)
        expected_index = HUNTERS.index(spec.identity)
        if index != expected_index:
            raise InvalidAnalyzerSpec(
                f"{spec.identity!r} registered at position {index}, expected "
                f"{expected_index} to match HUNTERS order")
        if spec.identity not in EXPECTED_REPORT_TYPES:
            raise InvalidAnalyzerSpec(f"{spec.identity}: no expected report_type on file")
        if spec.report_type is not EXPECTED_REPORT_TYPES[spec.identity]:
            raise InvalidAnalyzerSpec(f"{spec.identity}: wrong report_type")

    missing = set(HUNTERS) - seen
    if missing:
        raise InvalidAnalyzerSpec(f"missing registration(s) for {sorted(missing)}")

    targeted_identities = {spec.identity for spec in specs if spec.targeted_capability is not None}
    if targeted_identities != _APPROVED_TARGETED_IDENTITIES:
        raise InvalidAnalyzerSpec(
            f"targeted_capability identities {sorted(targeted_identities)} must "
            f"equal the approved set {sorted(_APPROVED_TARGETED_IDENTITIES)} exactly")


_REGISTRATIONS = _build_registrations()

# The module-level, import-time-constructed singleton -- the sole
# `AnalyzerRegistry` instance this process ever builds (contract §6).
# `AnalyzerRegistry.__init__` itself runs `_validate_registrations()` --
# there is no separate validation step to forget here.
REGISTRY = AnalyzerRegistry(_REGISTRATIONS)

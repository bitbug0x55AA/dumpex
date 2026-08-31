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
    must fail closed. Unreachable for the shipped registry (every
    targeted-capable spec carries a populated grant); it exists for a
    future capability declared before its grant is decided."""

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


class UnsupportedTargetedExecution(Exception):
    """Call-time failure -- ``identity``/``source``/``scopes`` is a granted
    targeted capability, but the spec carries no ``targeted_adapter`` to
    execute it. A capability declaration authorizes routing; it does not
    prove an executor exists, so a granted-but-unimplemented capability
    fails closed here rather than returning a clean empty result.
    ``scopes`` is the (possibly empty) frozenset the request carried."""

    def __init__(self, identity, source, scopes):
        self.identity = identity
        self.source = source
        self.scopes = frozenset(scopes)
        super().__init__(
            f"{identity!r}/{source!r} (scopes {sorted(self.scopes)}) has a granted "
            f"targeted capability but no registered execution adapter")


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
    (obfuscation's `encoding_scan` -> `OVERSIZE_SCAN_LAYERS`); an empty
    `scopes` means "no finer subdivision", never "unrestricted"."""
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
    (contract §1) -- a `scan_unit` tag, the closed set of grants for this
    analyzer's targetable sources, and the per-analyzer `request_ceiling`
    (the largest targeted range this analyzer may be asked for, in bytes --
    a required safety bound frozen by the capability matrix, kept ON the
    capability rather than in a second identity-keyed table). Each
    targeted-capable analyzer carries exactly the grant(s) and ceiling the
    targeted-rescan capability matrix freezes for it.

    `consumed_options` is the subset of the analyzer's own `option_names`
    that a TARGETED invocation actually reads. It is normally narrower than
    the full-scope set, because a targeted invocation runs one granted source
    rather than the analyzer's whole pipeline: `stomping` reads `ref_dir` for
    its reference-file comparison, which no targeted rescan performs, so its
    targeted set is empty; `yara` reads `rules_dir` in both modes, so its
    targeted set keeps it. This is the registry's own answer to "does this
    option influence a targeted run", which a command surface asks instead of
    keeping its own table, and which `HuntExecutionContext.observation_key()`
    reads so an option a run never consulted cannot change the observation
    identity."""
    scan_unit: TargetedScanUnit
    grants: frozenset
    request_ceiling: int = 256 * (1 << 20)
    consumed_options: frozenset = frozenset()

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
        if not isinstance(self.request_ceiling, int) or isinstance(self.request_ceiling, bool) \
                or self.request_ceiling <= 0:
            raise InvalidAnalyzerSpec(
                f"TargetedCapability.request_ceiling must be a positive int (bytes), "
                f"got {self.request_ceiling!r}")
        if not isinstance(self.consumed_options, frozenset) or not all(
                isinstance(o, str) for o in self.consumed_options):
            raise InvalidAnalyzerSpec(
                f"TargetedCapability.consumed_options must be a frozenset[str], "
                f"got {self.consumed_options!r}")


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

# Each targeted-capable analyzer's own frozen request-size ceiling in bytes
# (contract §"Range validation" 5-6) -- bound to identity here so a spec
# whose `TargetedCapability.request_ceiling` disagrees (or silently keeps
# the field default) is a construction-time failure. `TargetedCapability`
# carries the value; this table only pins which value each real identity
# must carry, exactly the way `_EXPECTED_TARGETED_SCAN_UNITS` above pins
# the scan unit.
_MIB_ = 1 << 20
_EXPECTED_TARGETED_REQUEST_CEILINGS = {
    "pipe": 256 * _MIB_,
    "stomping": 256 * _MIB_,
    "cs-beacon": 256 * _MIB_,
    "yara": 256 * _MIB_,
    "obfuscation": 32 * _MIB_,
}
_require_equal_sets(
    set(_EXPECTED_TARGETED_REQUEST_CEILINGS), _APPROVED_TARGETED_IDENTITIES,
    "_EXPECTED_TARGETED_REQUEST_CEILINGS must exactly match _APPROVED_TARGETED_IDENTITIES")

# Each targeted-capable analyzer's own frozen `consumed_options` -- the hunt
# options a TARGETED invocation of it actually reads, bound to identity here
# for the same reason the ceiling and scan unit are: a spec that silently
# keeps the empty default (or declares an option its targeted executor never
# consults) is a construction-time failure rather than a run that records an
# option it ignored.
#
# `stomping` is empty because a targeted rescan runs `ioc_string_scan` alone;
# `ref_dir` feeds the reference-file comparison, which is a source no targeted
# invocation evaluates. `yara` keeps `rules_dir` because its targeted executor
# resolves rule files through it exactly as full scope does.
_EXPECTED_TARGETED_CONSUMED_OPTIONS = {
    "pipe": frozenset(),
    "stomping": frozenset(),
    "cs-beacon": frozenset(),
    "yara": frozenset({"rules_dir"}),
    "obfuscation": frozenset(),
}
_require_equal_sets(
    set(_EXPECTED_TARGETED_CONSUMED_OPTIONS), _APPROVED_TARGETED_IDENTITIES,
    "_EXPECTED_TARGETED_CONSUMED_OPTIONS must exactly match _APPROVED_TARGETED_IDENTITIES")

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

# Each targeted-capable analyzer's own coverage sources that a targeted
# invocation of it NEVER evaluates -- declared, not derived. This is what a
# targeted record states explicitly so a completed grant cannot read as
# completed coverage for the whole analyzer.
#
# Declared rather than inferred from "which sources did a limitation happen to
# name", because that inference is exactly backwards: it marks a source absent
# when it SUCCEEDED (nothing to report) and present when it failed. YARA
# genuinely resolves and compiles its rule files and genuinely classifies each
# hit's memory context -- `yara_rules` and `yara_context` are where its verdict
# comes from -- so YARA declares nothing here, matching the targeted-rescan
# contract's own capability matrix ("Observational only: none"). CS Beacon
# likewise reads MemoryInfo and the thread contexts and feeds both into scored
# corroboration.
#
# A source listed here must be one of the identity's real published coverage
# sources and must never be its granted targeted source. A source the adapter
# merely consults -- the MemoryInfo lookup that resolves the containing
# descriptor -- is NOT listed: the rescan read it, and claiming otherwise would
# invent a gap.
_UNEVALUATED_TARGETED_SOURCES = {
    # Handle evidence is a separate scan the targeted pipe adapter never runs.
    "pipe": frozenset({"handle_data"}),
    # Module registration, PE headers, reference files, and the section
    # content diff are stomping's scored path; a targeted IOC string scan
    # touches none of them.
    "stomping": frozenset({"modules", "module_headers", "reference_files",
                            "section_content_diff"}),
    "cs-beacon": frozenset(),
    "yara": frozenset(),
    "obfuscation": frozenset(),
}
_require_equal_sets(
    set(_UNEVALUATED_TARGETED_SOURCES), _APPROVED_TARGETED_IDENTITIES,
    "_UNEVALUATED_TARGETED_SOURCES must exactly match _APPROVED_TARGETED_IDENTITIES")


def _validate_unevaluated_sources(table: dict) -> None:
    """Every declared never-evaluated source must be one of that identity's
    real published coverage sources -- a typo'd or invented name would put a
    source in a record's roster that the analyzer does not have. Extracted as
    a named function so it is directly unit-testable against a synthetic
    table, the same way `_validate_scoped_sources` is."""
    for identity, sources in table.items():
        if not isinstance(sources, frozenset) or not all(
                isinstance(name, str) and name for name in sources):
            raise InvalidAnalyzerSpec(
                f"_UNEVALUATED_TARGETED_SOURCES[{identity!r}] must be a frozenset of "
                f"non-empty str, got {sources!r}")
        published = _COVERAGE_SOURCE_NAMES_BY_IDENTITY[identity]
        unknown = sources - published
        if unknown:
            raise InvalidAnalyzerSpec(
                f"_UNEVALUATED_TARGETED_SOURCES[{identity!r}] names {sorted(unknown)}, "
                f"which are not among {identity}'s real coverage sources "
                f"{sorted(published)}")


_validate_unevaluated_sources(_UNEVALUATED_TARGETED_SOURCES)


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


# ── Public coverage-vocabulary accessors ───────────────────────────────
# The observation layer (`dumpex.hunt._observation`) validates a closure's
# `(source, scope)` against the analyzer's real published vocabulary -- the
# same per-hunter `report_facts.COVERAGE_SOURCE_NAMES` a `TargetedGrant.source`
# is checked against. It reads it through these accessors, never the private
# `_COVERAGE_SOURCE_NAMES_BY_IDENTITY` / `_SCOPED_TARGETED_SOURCES` tables, so
# a restructure here does not silently break an external consumer.

def coverage_sources_for(identity: str) -> frozenset:
    """The published coverage-source vocabulary for `identity` (the shipped
    `report_facts.COVERAGE_SOURCE_NAMES`). Empty for `injection`/`hollowing`
    (no published constant) and for an unknown identity."""
    return frozenset(_COVERAGE_SOURCE_NAMES_BY_IDENTITY.get(identity, ()))


def unevaluated_targeted_sources(identity: str) -> frozenset:
    """The coverage sources a targeted invocation of `identity` never
    evaluates -- the declared set, empty for an analyzer whose whole published
    vocabulary a targeted rescan does reach (`yara`, `cs-beacon`) and for an
    identity with no targeted capability at all.

    A targeted record reports these as absent, each with its own
    `TARGETED_SOURCE_NOT_EVALUATED`, so a complete result for the granted
    source cannot be read as complete coverage for the analyzer."""
    return frozenset(_UNEVALUATED_TARGETED_SOURCES.get(identity, ()))


def closed_scope_vocab_for(identity: str, source: str) -> "frozenset | None":
    """The CLOSED, importable sub-scope vocabulary for `(identity, source)`,
    or `None` when the source has no such vocabulary (its `scope`, if any, is
    an open budget-kind / sub-signal tag). Today only obfuscation's
    `encoding_scan` -> `OVERSIZE_SCAN_LAYERS`. A closure may legitimately name
    no scope on such a source (a layer-agnostic gap); only an invented layer
    name is rejected."""
    entry = _SCOPED_TARGETED_SOURCES.get(identity)
    if entry is not None and entry[0] == source:
        return frozenset(entry[1])
    return None


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


# A full-scope builder's first positional parameter. `"mf"` receives the
# raw dump handle (every builder today); `"context"` receives the whole
# `HuntExecutionContext`, for a builder that consumes the shared
# observation registry or budgets. `_execute_full_scope()` passes one or
# the other by this declared convention.
_BUILDER_ARGS = frozenset({"mf", "context"})


# ── AnalyzerSpec (contract §5) ─────────────────────────────────────────

@dataclass(frozen=True)
class AnalyzerSpec:
    """One analyzer's closed, immutable operational boundary -- exactly the
    fields the registry contract's own `AnalyzerSpec` list names, no more.
    Deliberately NOT reusing
    `dumpex.hunt._domain.require_recursively_immutable`: that helper's own
    leaf-type allowlist rejects any callable outright, and the
    builder/renderer/record_projector/provenance_hook/targeted_adapter/
    targeted_report_projector fields are exactly that.
    `AnalyzerSpec.__post_init__` instead validates each field's own shape
    directly.

    Deliberately not a field: execution order (a spec's position is its
    index in the registry's own registration sequence, validated against
    `HUNTERS.index(identity)` at construction -- never a second,
    independently-settable ordinal). Deliberately never a field value: a
    dump handle, a raw scan buffer, or any other mutable parser object --
    every callable field is typed as a callable that ACCEPTS a
    `Report`/`mf` argument, never an already-invoked result. This is
    enforced STRUCTURALLY, by field typing (`type`/`frozenset[str]`/`bool`/
    `TargetedCapability | None`, plus `callable(...)` for every function
    field), not by a runtime scan of a callable's own closure --
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
    targeted_adapter: "Callable | None" = None
    targeted_report_projector: "Callable | None" = None
    builder_arg: str = "mf"

    def __post_init__(self):
        if self.identity not in HUNTERS:
            raise InvalidAnalyzerSpec(
                f"AnalyzerSpec.identity must be one of {HUNTERS}, got "
                f"{self.identity!r}")
        _require_str(self.package, "AnalyzerSpec.package")
        if self.builder_arg not in _BUILDER_ARGS:
            raise InvalidAnalyzerSpec(
                f"{self.identity}: builder_arg must be one of {sorted(_BUILDER_ARGS)}, "
                f"got {self.builder_arg!r}")
        if not isinstance(self.report_type, type):
            raise InvalidAnalyzerSpec(
                f"AnalyzerSpec.report_type must be a type, got {self.report_type!r}")
        for name in ("builder", "renderer", "record_projector"):
            if not callable(getattr(self, name)):
                raise InvalidAnalyzerSpec(
                    f"AnalyzerSpec.{name} must be callable, got "
                    f"{getattr(self, name)!r}")
        _check_builder_arg_matches_signature(self.identity, self.builder, self.builder_arg)
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
        if self.targeted_adapter is not None:
            if self.targeted_capability is None:
                raise InvalidAnalyzerSpec(
                    f"{self.identity}: targeted_adapter set with no targeted_capability "
                    f"-- an executor for a capability that does not exist")
            _validate_targeted_adapter_shape(self.identity, self.targeted_adapter)
        # An executor and the projection of its result are one capability:
        # an adapter whose ObservationResult nothing can turn into a
        # HunterRecord is unreachable from a command, and a projector with no
        # executor has nothing to project.
        if (self.targeted_adapter is None) != (self.targeted_report_projector is None):
            raise InvalidAnalyzerSpec(
                f"{self.identity}: targeted_adapter and targeted_report_projector are set "
                f"together or not at all -- a targeted executor whose result cannot be "
                f"projected is unreachable from a command")
        if self.targeted_report_projector is not None:
            _validate_targeted_report_projector_shape(
                self.identity, self.targeted_report_projector)

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

        # An option a targeted invocation consumes must be one the analyzer
        # declares at all: a capability cannot widen the analyzer's own option
        # vocabulary, only narrow it for the targeted mode.
        consumed = self.targeted_capability.consumed_options
        if not consumed <= self.option_names:
            raise InvalidAnalyzerSpec(
                f"{self.identity}: targeted_capability.consumed_options "
                f"{sorted(consumed - self.option_names)} are not in this analyzer's own "
                f"option_names {sorted(self.option_names)}")
        if self.identity not in _EXPECTED_TARGETED_CONSUMED_OPTIONS:
            raise InvalidAnalyzerSpec(
                f"{self.identity}: no expected targeted consumed_options on file -- "
                f"_EXPECTED_TARGETED_CONSUMED_OPTIONS is missing an entry for this "
                f"targeted-capable identity")
        expected_consumed = _EXPECTED_TARGETED_CONSUMED_OPTIONS[self.identity]
        if consumed != expected_consumed:
            raise InvalidAnalyzerSpec(
                f"{self.identity}: targeted_capability.consumed_options must be "
                f"{sorted(expected_consumed)}, got {sorted(consumed)}")

        # One invocation runs exactly one source, and there is no public
        # source-selection flag, so a capability granting two sources is a
        # command surface with no way to choose between them. Checked here,
        # at construction, rather than at the moment a user runs the command:
        # a spec that cannot be invoked must not register, must not reach the
        # supported-set roster, and must not surface as a traceback.
        granted_sources = {grant.source for grant in self.targeted_capability.grants}
        declared_unevaluated = _UNEVALUATED_TARGETED_SOURCES.get(self.identity, frozenset())
        overlap = granted_sources & declared_unevaluated
        if overlap:
            raise InvalidAnalyzerSpec(
                f"{self.identity}: {sorted(overlap)} is both a targeted grant and declared "
                f"never-evaluated -- a targeted invocation cannot run a source it also "
                f"reports as outside its own scope")
        if len(granted_sources) > 1:
            raise InvalidAnalyzerSpec(
                f"{self.identity}: targeted_capability grants {len(granted_sources)} sources "
                f"{sorted(granted_sources)} -- one targeted invocation runs exactly one "
                f"source and there is no public source-selection flag")

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
        """Single-`(source, scope)` grant primitive: answers "is this ONE
        `source`/`scope` granted", with the symmetric-match rule (an empty
        grant `scopes` authorizes `scope=None` only; a non-empty one
        authorizes a named member only).

        This does NOT authorize a whole invocation: a `HuntRequest` carries a
        scope SET and an obfuscation invocation always attempts all three
        layers, so `HuntRequest` and `resolve_targeted_adapter` both go
        through `select_targeted_scopes()` instead. Use this only where a
        single grant genuinely is the question (grant-shape tests, a future
        single-layer capability)."""
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

    def select_targeted_scopes(self, identity: str, source: str,
                               scopes: frozenset) -> AnalyzerSpec:
        """Like `select_targeted()`, but validates the whole scope SET one
        request will attempt at once (a `HuntRequest` carries a set, not a
        single layer -- obfuscation always attempts all of its granted
        layers, and the contract has no public per-layer selection). An
        unscoped source requires an empty set; a scoped source requires
        exactly its full granted scope set. Raises the same typed
        `UnknownAnalyzerIdentity` / `UnsupportedTargetedCapability` /
        `UnpopulatedTargetedGrant` / `UnsupportedTargetedSource` /
        `UnsupportedTargetedScope` failures as `select_targeted()`, in that
        order -- identity/capability/grant/source are checked before the
        scope set, so an unknown identity is `UnknownAnalyzerIdentity`
        regardless of what `scopes` is. A non-frozenset `scopes` is a caller
        type error, not a scope failure."""
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
        if not isinstance(scopes, frozenset):
            raise TypeError(
                f"select_targeted_scopes() scopes must be a frozenset, got {scopes!r}")
        granted = self.granted_scopes(identity, source)
        if granted:
            if scopes != granted:
                raise UnsupportedTargetedScope(identity, source, tuple(sorted(scopes)))
        elif scopes:
            raise UnsupportedTargetedScope(identity, source, tuple(sorted(scopes)))
        return spec

    def granted_scopes(self, identity: str, source: str) -> frozenset:
        """The full granted scope set for `(identity, source)` -- empty for an
        unscoped source, an unknown identity/source, or an analyzer with no
        capability; obfuscation's three layers for `encoding_scan`. The one
        place a caller resolves "the granted set" instead of restating it.
        This resolves only -- authorization is `select_targeted_scopes()`'s
        job, which a caller still goes through afterwards."""
        spec = self._by_identity.get(identity)
        if spec is None or spec.targeted_capability is None:
            return frozenset()
        matching = [g for g in spec.targeted_capability.grants if g.source == source]
        return frozenset().union(*(g.scopes for g in matching)) if matching else frozenset()

    def targeted_identities(self) -> tuple:
        """Every identity a targeted (`--hunt-addr`) invocation can name, in
        `HUNTERS` order -- a declared capability, a registered executor, and a
        single resolvable source, since none of the three alone can run one.
        This is what a command surface asks instead of keeping its own
        allowlist; `"all"` is never a member (it is a selection mode, not an
        analyzer).

        The roster never advertises an analyzer an invocation would then fail
        on: a spec whose grants cannot resolve to one source is excluded here
        as well as refused by `targeted_source()`."""
        return tuple(spec.identity for spec in self._specs
                     if spec.targeted_capability is not None
                     and spec.targeted_adapter is not None
                     and len({grant.source for grant in spec.targeted_capability.grants}) == 1)

    def targeted_source(self, identity: str) -> str:
        """The single coverage source one targeted invocation of `identity`
        runs. There is no public source-selection flag, so an analyzer whose
        capability granted more than one source would leave a command surface
        guessing -- that fails closed here rather than being resolved by
        picking one. Raises the same typed identity/capability/grant failures
        `select_targeted_scopes()` does."""
        if identity not in self._by_identity:
            raise UnknownAnalyzerIdentity(identity, set(self._by_identity))
        spec = self._by_identity[identity]
        if spec.targeted_capability is None:
            raise UnsupportedTargetedCapability(identity)
        grants = spec.targeted_capability.grants
        if not grants:
            raise UnpopulatedTargetedGrant(identity)
        sources = {grant.source for grant in grants}
        if len(sources) != 1:
            # `AnalyzerSpec.__post_init__` already refuses a multi-source
            # grant, so reaching this means a registry assembled around a spec
            # that bypassed construction. Still fail closed rather than pick
            # one of the sources for the caller.
            raise InvalidAnalyzerSpec(
                f"{identity}: {len(sources)} granted targeted sources "
                f"{sorted(sources)} -- one invocation runs exactly one source and "
                f"there is no public source-selection flag")
        return sources.pop()

    def resolve_targeted_adapter(self, identity: str, source: str,
                                 scopes: frozenset = frozenset()) -> "tuple[AnalyzerSpec, Callable]":
        """The one entry point a targeted-scan executor uses. Resolves the
        grant and the scope SET exactly as `select_targeted_scopes()` does
        (raising the same typed lookup/capability/scope failures -- so the
        executor boundary and the `HuntRequest` boundary agree on what a legal
        obfuscation targeted scan is), then requires the spec to carry a
        `targeted_adapter`. A granted capability with no adapter raises
        `UnsupportedTargetedExecution`. Returns `(spec, adapter)`."""
        spec = self.select_targeted_scopes(identity, source, scopes)
        if spec.targeted_adapter is None:
            raise UnsupportedTargetedExecution(identity, source, scopes)
        return spec, spec.targeted_adapter


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
    # Marks this as the internal pass-through wrapper whose real target
    # `_resolve_and_validate_*` already signature-checked -- the one
    # callable `_check_builder_arg_matches_signature` trusts without
    # re-inspecting (its own signature is `(*args, **kwargs)` and says
    # nothing about the real builder).
    _call._dumpex_late_bound = True
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


def _check_builder_arg_matches_signature(identity: str, builder, builder_arg: str) -> None:
    """`_register()` validates the real target through
    `_resolve_and_validate_builder()`, but a direct `AnalyzerSpec(...)` can
    still declare a `builder_arg` its builder's own first parameter
    contradicts -- and passing the whole `HuntExecutionContext` to a builder
    that named its first parameter `mf` only fails later, deeper in that
    builder.

    Only the `_late_bound()` pass-through wrapper (which carries an explicit
    marker, and whose real target `_resolve_and_validate_builder()` already
    checked) is trusted without inspection. Every other callable must have an
    introspectable signature whose first parameter is a positionally-passable
    parameter named `builder_arg` -- a keyword-only first parameter, an
    `*args`/`**kwargs` catch-all, or an uninspectable callable all fail
    closed, since `_execute_full_scope()` calls `spec.builder(<mf-or-context>)`
    positionally."""
    if getattr(builder, "_dumpex_late_bound", False):
        return
    params = list(_safe_signature(builder, f"{identity} builder").parameters.values())
    if not params or params[0].name != builder_arg \
            or params[0].kind not in _POSITIONALLY_PASSABLE:
        raise InvalidAnalyzerSpec(
            f"{identity}: builder_arg={builder_arg!r} requires the builder's first "
            f"parameter to be a positionally-passable {builder_arg!r}, got "
            f"{[p.name for p in params]!r}")


def _resolve_and_validate_builder(attr_name: str, option_defaults: dict,
                                  builder_arg: str = "mf") -> Callable:
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
    if not params or params[0].name != builder_arg or params[0].kind not in _POSITIONALLY_PASSABLE:
        raise InvalidAnalyzerSpec(
            f"{attr_name}: first parameter must be a positionally-passable "
            f"{builder_arg!r}, got {[p.name for p in params]!r}")
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


def _validate_targeted_adapter_shape(identity: str, adapter) -> None:
    """`AnalyzerSpec.targeted_adapter` gets the same resolve-then-inspect
    treatment `builder`/`renderer`/`record_projector` get -- `callable(...)`
    alone accepts a zero-arg or wrong-arity adapter that only raises
    `TypeError` the first time a targeted executor calls it against a real
    `HuntExecutionContext`, which can be well after a dump is open. The one
    call shape a targeted executor uses is `adapter(context)`: exactly one
    positionally-passable parameter named `context`.

    Only the `_late_bound()` pass-through wrapper (whose real target
    `_resolve_and_validate_targeted_adapter()` already signature-checked) is
    trusted without inspection -- its own signature is `(*args, **kwargs)`, the
    same seam `_check_builder_arg_matches_signature` already exempts."""
    if not callable(adapter):
        raise InvalidAnalyzerSpec(
            f"{identity}: targeted_adapter must be None or callable, got {adapter!r}")
    if getattr(adapter, "_dumpex_late_bound", False):
        return
    sig = _safe_signature(adapter, f"{identity} targeted_adapter")
    params = list(sig.parameters.values())
    if len(params) != 1 or params[0].name != "context" \
            or params[0].kind not in _POSITIONALLY_PASSABLE:
        raise InvalidAnalyzerSpec(
            f"{identity}: targeted_adapter must accept exactly one positionally-passable "
            f"'context' parameter, got {[p.name for p in params]!r}")
    try:
        sig.bind(object())
    except TypeError as exc:
        raise InvalidAnalyzerSpec(
            f"{identity}: targeted_adapter cannot be called as adapter(context): {exc}")


def _resolve_and_validate_targeted_adapter(attr_name: str) -> Callable:
    """Resolve the real targeted-adapter target once, here, at registration
    time (facade imports are complete by the time this module's top-level code
    runs -- contract §6's import-ordering guarantee) and validate its full
    signature is exactly `adapter(context)` -- one positionally-passable
    `context` parameter, the shape `resolve_targeted_adapter()`'s executor
    boundary calls it with. `spec.targeted_adapter` itself stays late-bound
    (`_late_bound` above), so monkeypatching `dumpex.hunt.<attr_name>` after
    construction is untouched by this check having already run once."""
    target = _resolve_callable(attr_name)
    sig = _safe_signature(target, attr_name)
    params = list(sig.parameters.values())
    if len(params) != 1 or params[0].name != "context" \
            or params[0].kind not in _POSITIONALLY_PASSABLE:
        raise InvalidAnalyzerSpec(
            f"{attr_name}: targeted_adapter must accept exactly one positionally-passable "
            f"'context' parameter, got {[p.name for p in params]!r}")
    try:
        sig.bind(object())
    except TypeError as exc:
        raise InvalidAnalyzerSpec(
            f"{attr_name}: cannot be called as adapter(context): {exc}")
    return _late_bound(attr_name)


_TARGETED_REPORT_PROJECTOR_PARAMS = ("context", "result")


def _validate_targeted_report_projector_shape(identity: str, projector) -> None:
    """`AnalyzerSpec.targeted_report_projector` gets the same resolve-then-
    inspect treatment every other callable field gets. The one call shape a
    targeted executor uses is `projector(context, result)`: the invocation's
    `HuntExecutionContext` (for the dump-wide stream facts a report's own
    coverage snapshot needs) and the adapter's own `ObservationResult`.

    Only the `_late_bound()` pass-through wrapper (whose real target
    `_resolve_and_validate_targeted_report_projector()` already signature-
    checked) is trusted without inspection, exactly as for the adapter."""
    if not callable(projector):
        raise InvalidAnalyzerSpec(
            f"{identity}: targeted_report_projector must be None or callable, "
            f"got {projector!r}")
    if getattr(projector, "_dumpex_late_bound", False):
        return
    _check_targeted_report_projector_signature(
        f"{identity} targeted_report_projector", projector)


def _check_targeted_report_projector_signature(label: str, projector) -> None:
    sig = _safe_signature(projector, label)
    params = list(sig.parameters.values())
    if [p.name for p in params] != list(_TARGETED_REPORT_PROJECTOR_PARAMS) or any(
            p.kind not in _POSITIONALLY_PASSABLE for p in params):
        raise InvalidAnalyzerSpec(
            f"{label}: targeted_report_projector must accept exactly the positionally-"
            f"passable {list(_TARGETED_REPORT_PROJECTOR_PARAMS)}, got "
            f"{[p.name for p in params]!r}")
    try:
        sig.bind(object(), object())
    except TypeError as exc:
        raise InvalidAnalyzerSpec(
            f"{label}: cannot be called as projector(context, result): {exc}")


def _resolve_and_validate_targeted_report_projector(attr_name: str) -> Callable:
    """The registration-time counterpart of
    `_resolve_and_validate_targeted_adapter` for the targeted report
    projector: resolve the real target once and check its full signature,
    while `spec.targeted_report_projector` stays late-bound so a
    monkeypatched `dumpex.hunt.<attr_name>` still routes."""
    _check_targeted_report_projector_signature(attr_name, _resolve_callable(attr_name))
    return _late_bound(attr_name)


def _register(identity: str, package: str, report_type: type, builder_attr: str,
              renderer_attr: str, projector_attr: str, option_defaults: dict,
              provenance_hook, full_scope_capable: bool,
              targeted_capability, targeted_adapter_attr: "str | None" = None,
              targeted_report_projector_attr: "str | None" = None,
              builder_arg: str = "mf") -> AnalyzerSpec:
    return AnalyzerSpec(
        identity=identity,
        package=package,
        report_type=report_type,
        builder=_resolve_and_validate_builder(builder_attr, option_defaults, builder_arg),
        renderer=_resolve_and_validate_renderer(renderer_attr),
        record_projector=_resolve_and_validate_projector(projector_attr),
        option_names=frozenset(option_defaults),
        provenance_hook=provenance_hook,
        full_scope_capable=full_scope_capable,
        targeted_capability=targeted_capability,
        targeted_adapter=(None if targeted_adapter_attr is None
                          else _resolve_and_validate_targeted_adapter(targeted_adapter_attr)),
        targeted_report_projector=(
            None if targeted_report_projector_attr is None
            else _resolve_and_validate_targeted_report_projector(
                targeted_report_projector_attr)),
        builder_arg=builder_arg,
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
            targeted_capability=TargetedCapability(
                TargetedScanUnit.REGION,
                frozenset({TargetedGrant("ioc_string_scan", frozenset())}),
                _EXPECTED_TARGETED_REQUEST_CEILINGS["stomping"],
                _EXPECTED_TARGETED_CONSUMED_OPTIONS["stomping"]),
            targeted_adapter_attr="_run_targeted_stomping",
            targeted_report_projector_attr="_project_targeted_stomping"),
        _register(
            "pipe", "dumpex.hunt.pipe", PipeReport,
            "_build_pipe_report", "_render_pipe_console",
            "_record_from_pipe_report", {}, None,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(
                TargetedScanUnit.REGION,
                frozenset({TargetedGrant("pipe_name_scan", frozenset())}),
                _EXPECTED_TARGETED_REQUEST_CEILINGS["pipe"],
                _EXPECTED_TARGETED_CONSUMED_OPTIONS["pipe"]),
            targeted_adapter_attr="_run_targeted_pipe",
            targeted_report_projector_attr="_project_targeted_pipe"),
        _register(
            "cs-beacon", "dumpex.hunt.cs_beacon", CSBeaconReport,
            "_build_cs_beacon_report", "_render_cs_beacon_console",
            "_record_from_cs_beacon_report", {}, None,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(
                TargetedScanUnit.SEGMENT,
                frozenset({TargetedGrant("segment_scan", frozenset())}),
                _EXPECTED_TARGETED_REQUEST_CEILINGS["cs-beacon"],
                _EXPECTED_TARGETED_CONSUMED_OPTIONS["cs-beacon"]),
            targeted_adapter_attr="_run_targeted_cs_beacon",
            targeted_report_projector_attr="_project_targeted_cs_beacon"),
        _register(
            "yara", "dumpex.hunt.yara_hunt", YaraReport,
            "_build_yara_report", "_render_yara_console",
            "_record_from_yara_report", {"rules_dir": None}, _yara_provenance_hook,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(
                TargetedScanUnit.SEGMENT,
                frozenset({TargetedGrant("segment_scan", frozenset())}),
                _EXPECTED_TARGETED_REQUEST_CEILINGS["yara"],
                _EXPECTED_TARGETED_CONSUMED_OPTIONS["yara"]),
            targeted_adapter_attr="_run_targeted_yara",
            targeted_report_projector_attr="_project_targeted_yara"),
        _register(
            "obfuscation", "dumpex.hunt.encoding", EncodingReport,
            "_build_encoding_report", "_render_encoding_console",
            "_record_from_encoding_report", {}, None,
            full_scope_capable=True,
            targeted_capability=TargetedCapability(
                TargetedScanUnit.REGION_LAYER,
                frozenset({TargetedGrant(
                    "encoding_scan", frozenset({"sleep_mask", "entropy", "decode"}))}),
                _EXPECTED_TARGETED_REQUEST_CEILINGS["obfuscation"],
                _EXPECTED_TARGETED_CONSUMED_OPTIONS["obfuscation"]),
            targeted_adapter_attr="_run_targeted_obfuscation",
            targeted_report_projector_attr="_project_targeted_obfuscation"),
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

    # Each targeted-capable spec's request ceiling must be the exact
    # matrix-frozen value -- unconditional `[identity]` lookup (never
    # `.get(...)`), so a MISSING expected entry or a spec that silently
    # kept `TargetedCapability.request_ceiling`'s field default both fail
    # here, the same way `_EXPECTED_TARGETED_SCAN_UNITS` is enforced.
    for spec in specs:
        if spec.targeted_capability is None:
            continue
        if spec.identity not in _EXPECTED_TARGETED_REQUEST_CEILINGS:
            raise InvalidAnalyzerSpec(
                f"{spec.identity}: no expected request ceiling on file -- "
                f"_EXPECTED_TARGETED_REQUEST_CEILINGS is missing an entry for this "
                f"targeted-capable identity")
        expected_ceiling = _EXPECTED_TARGETED_REQUEST_CEILINGS[spec.identity]
        if spec.targeted_capability.request_ceiling != expected_ceiling:
            raise InvalidAnalyzerSpec(
                f"{spec.identity}: targeted_capability.request_ceiling must be "
                f"{expected_ceiling}, got {spec.targeted_capability.request_ceiling}")


_REGISTRATIONS = _build_registrations()

# The module-level, import-time-constructed singleton -- the sole
# `AnalyzerRegistry` instance this process ever builds (contract §6).
# `AnalyzerRegistry.__init__` itself runs `_validate_registrations()` --
# there is no separate validation step to forget here.
REGISTRY = AnalyzerRegistry(_REGISTRATIONS)

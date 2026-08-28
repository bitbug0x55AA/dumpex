"""Per-invocation registry of reusable expensive analyzer observations.

Some analyzer work -- hidden-PE scans, thread-context reads, PE-header
validation, range capture, identity checks -- is expensive enough that it must
run at most once per invocation even when several coverage relationships would
each ask for it. This module holds those observations for one invocation only.

Execution identity and closure attribution are two different things:

* :class:`ObservationKey` is *execution identity* -- the analyzer, whether the
  run was targeted, the exact requested range, and the configuration / rules /
  algorithm version that decide whether an earlier result is still valid. It
  carries no ``source`` and no ``scope``: an originating relationship's
  ``source``/``scope``/``cause`` is attribution, not a reason to run the same
  analyzer over the same bytes again.
* :class:`ObservationClosure` is *closure attribution* -- one independently
  validated ``(source, scope)`` coverage closure projected from an observation,
  with its own honest ``coverage_status`` / ``capture_state`` / ``read_slice`` /
  limitations. One :class:`ObservationResult` carries a tuple of them, so a
  single expensive run can expose (for example) a complete ``pipe_name``
  closure and a partial ``c2_context`` closure at the same time, and reuse of
  that one result never propagates one closure's ``complete`` to another.

:class:`ObservationRegistry` is bounded in entries and event history so an
attacker-controlled dump cannot grow it without limit. ``get_or_compute`` is
the expensive-scan boundary: it runs a producer at most once per key -- never
again after a success, a failure (tombstoned as a lightweight type/message
pair; a later request raises a fresh ``ObservationProducerFailed``), or a
saturated refusal. Saturation is never silent: ``get_or_compute`` raises
:class:`ObservationBudgetExhausted` rather than return ``None``, so a caller
cannot fall through to a clean negative. Every observation is recorded as
produced, reused, unavailable, failed, incompatible-cache, or saturated, so a
later consumer can prove which happened.
"""
from dataclasses import dataclass, field
from enum import Enum

from dumpex.core.va_range import CaptureState, ReadSlice, VirtualRange
from dumpex.hunt import _registry
from dumpex.hunt._domain import as_tuple, require_recursively_immutable
from dumpex.output.coverage import CoverageLimitation
from dumpex.output.records import HUNTERS

__all__ = [
    "ObservationOutcome",
    "ObservationKey",
    "ObservationClosure",
    "BudgetOutcome",
    "ObservationResult",
    "ObservationRegistry",
    "ObservationProducerFailed",
    "ObservationBudgetExhausted",
    "COVERAGE_STATUSES",
    "DEFAULT_MAX_ENTRIES",
]

COVERAGE_STATUSES = ("not_evaluated", "partial", "complete")

# One invocation's registry is bounded so a dump with many distinct
# regions/segments cannot drive unbounded key or event cardinality -- nor,
# via `get_or_compute()`, unbounded expensive-scan cost. Once full, a new
# key is refused before its producer runs.
DEFAULT_MAX_ENTRIES = 256


class ObservationProducerFailed(Exception):
    """Raised when :meth:`ObservationRegistry.get_or_compute` is asked again
    for a key whose producer already failed this invocation. It is a fresh,
    lightweight instance every time -- the original exception is not retained
    or re-raised, so a caller retrying in a loop cannot grow an accumulating
    traceback. It names the original failure's type and message."""

    def __init__(self, key, failure_type: str, failure_message: str):
        self.key = key
        self.failure_type = failure_type
        self.failure_message = failure_message
        super().__init__(
            f"observation {key!r} already failed this invocation "
            f"({failure_type}: {failure_message})")


class ObservationBudgetExhausted(Exception):
    """Raised by :meth:`ObservationRegistry.get_or_compute` when the
    per-invocation observation budget (``max_entries`` distinct keys) is
    spent and ``key`` is new. The producer is NOT run. A caller must treat
    this as a coverage gap -- mint a ``not_evaluated`` closure and disclose
    the budget -- never fall through to a clean negative."""

    def __init__(self, key, max_entries: int):
        self.key = key
        self.max_entries = max_entries
        super().__init__(
            f"observation budget exhausted ({max_entries} distinct keys) -- "
            f"{key!r} was not scanned")


class ObservationOutcome(str, Enum):
    """What happened to one observation request within an invocation.

    ``PRODUCED`` -- computed now and retained for reuse.
    ``REUSED`` -- served from an identical earlier key.
    ``UNAVAILABLE`` -- a prerequisite was missing, so nothing was computed.
    ``FAILED`` -- production was attempted and raised.
    ``INCOMPATIBLE_CACHE`` -- an earlier observation covers the same
    analyzer/range (the same coverage locus) but under different
    configuration, rules, or algorithm version, so it cannot be reused.
    ``SATURATED`` -- the per-invocation observation budget is spent and this
    key is new: :meth:`get_or_compute` did not run the producer at all.
    """
    PRODUCED = "produced"
    REUSED = "reused"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    INCOMPATIBLE_CACHE = "incompatible_cache"
    SATURATED = "saturated"


def _require_optional_nonempty_str(value, field_name: str) -> None:
    if value is not None and (not isinstance(value, str) or not value):
        raise ValueError(f"{field_name} must be None or a non-empty str, got {value!r}")


def _require_nonempty_str(value, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty str, got {value!r}")


# ── ObservationKey (execution identity) ────────────────────────────────

@dataclass(frozen=True)
class ObservationKey:
    """The identity of one analyzer execution, and the reuse key for its
    result -- deliberately free of ``source`` and ``scope``.

    ``is_targeted`` marks a ``--hunt-addr`` targeted invocation apart from a
    full ``--hunt`` run. ``requested_range`` is the exact
    :class:`dumpex.core.va_range.VirtualRange` this execution covered -- always
    set for a targeted observation, set for a full-scope observation that ran
    against one region/segment, and ``None`` only for a genuinely dump-wide
    aggregate. ``config_provenance`` / ``rule_provenance`` are content-identity
    tokens; ``algorithm_version`` names the algorithm whose output this is.

    Two coverage relationships that differ only in attribution
    (``SkipRelationship.source`` / ``scope`` / ``cause``) build the SAME key,
    so the expensive producer runs once and both relationships reuse it.
    """
    analyzer: str
    is_targeted: bool
    algorithm_version: str
    requested_range: "VirtualRange | None" = None
    config_provenance: "str | None" = None
    rule_provenance: "str | None" = None

    def __post_init__(self):
        if self.analyzer not in HUNTERS:
            raise ValueError(
                f"ObservationKey.analyzer must be one of {HUNTERS}, got {self.analyzer!r}")
        _require_nonempty_str(self.algorithm_version, "ObservationKey.algorithm_version")
        if not isinstance(self.is_targeted, bool):
            raise ValueError(
                f"ObservationKey.is_targeted must be a bool, got {self.is_targeted!r}")
        _require_optional_nonempty_str(self.config_provenance, "ObservationKey.config_provenance")
        _require_optional_nonempty_str(self.rule_provenance, "ObservationKey.rule_provenance")
        if self.requested_range is not None and not isinstance(self.requested_range, VirtualRange):
            raise ValueError(
                "ObservationKey.requested_range must be None or a VirtualRange, got "
                f"{self.requested_range!r}")
        if self.is_targeted and self.requested_range is None:
            raise ValueError(
                "ObservationKey: a targeted observation requires a requested_range")
        require_recursively_immutable(self, "ObservationKey")

    @property
    def coverage_locus(self) -> tuple:
        """The analyzer + scope + range this observation speaks to, apart from
        the configuration/rules/algorithm that decide whether a stored result
        is still valid for it. Two keys sharing a locus but not equal are the
        incompatible-cache case."""
        return (self.analyzer, self.is_targeted, self.requested_range)


# ── BudgetOutcome / ObservationClosure (closure attribution) ───────────

@dataclass(frozen=True)
class BudgetOutcome:
    """One budget's state as an observation left it -- keyed by the same
    ``name`` :meth:`dumpex.hunt._execution.HuntBudgetLedger.register` uses, so
    a reused observation's budget outcome resolves back to a registered
    budget. ``limit``/``consumed`` are byte/hit/second counts (or ``None`` when
    the budget does not expose one); ``exhausted`` says whether it stopped the
    work."""
    name: str
    exhausted: bool
    limit: "int | None" = None
    consumed: "int | None" = None

    def __post_init__(self):
        _require_nonempty_str(self.name, "BudgetOutcome.name")
        if not isinstance(self.exhausted, bool):
            raise ValueError(f"BudgetOutcome.exhausted must be a bool, got {self.exhausted!r}")
        for f in ("limit", "consumed"):
            v = getattr(self, f)
            if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 0):
                raise ValueError(f"BudgetOutcome.{f} must be None or a non-negative int, got {v!r}")


@dataclass(frozen=True)
class ObservationClosure:
    """One independently validated coverage closure projected from an
    observation. Its ``coverage_status`` / ``capture_state`` / ``read_slice``
    are this closure's own honest facts, never the observation's aggregate --
    reading the ``c2_context`` closure never returns the ``pipe_name``
    closure's status.

    ``limitations`` is a tuple of
    :class:`dumpex.output.coverage.CoverageLimitation` (structured, never a
    flattened string); ``budget_outcomes`` a tuple of :class:`BudgetOutcome`;
    ``diagnostics`` a tuple of non-empty strings.

    Self-contained consistency: a ``read_slice`` must match ``capture_state``,
    a short read cannot be ``complete``, and ``complete`` requires a complete
    capture. The checks that need the observation's key
    (``read_slice.requested == key.requested_range`` and "a range that ran
    carries its read_slice") live on :class:`ObservationResult`.
    """
    source: str
    coverage_status: str
    capture_state: CaptureState
    scope: "str | None" = None
    read_slice: "ReadSlice | None" = None
    limitations: tuple = ()
    budget_outcomes: tuple = ()
    diagnostics: tuple = ()

    def __post_init__(self):
        _require_nonempty_str(self.source, "ObservationClosure.source")
        _require_optional_nonempty_str(self.scope, "ObservationClosure.scope")
        if self.coverage_status not in COVERAGE_STATUSES:
            raise ValueError(
                f"ObservationClosure.coverage_status must be one of {COVERAGE_STATUSES}, "
                f"got {self.coverage_status!r}")
        if not isinstance(self.capture_state, CaptureState):
            raise ValueError(
                f"ObservationClosure.capture_state must be a CaptureState, got "
                f"{self.capture_state!r}")
        if self.read_slice is not None and not isinstance(self.read_slice, ReadSlice):
            raise ValueError(
                f"ObservationClosure.read_slice must be None or a ReadSlice, got "
                f"{self.read_slice!r}")

        object.__setattr__(self, "limitations",
                           as_tuple(self.limitations, "ObservationClosure.limitations"))
        object.__setattr__(self, "budget_outcomes",
                           as_tuple(self.budget_outcomes, "ObservationClosure.budget_outcomes"))
        object.__setattr__(self, "diagnostics",
                           as_tuple(self.diagnostics, "ObservationClosure.diagnostics"))
        for limitation in self.limitations:
            if not isinstance(limitation, CoverageLimitation):
                raise ValueError(
                    "ObservationClosure.limitations entries must be CoverageLimitation "
                    f"instances -- a string discards the source/scope/targets/budget "
                    f"facts a reuse must keep -- got {limitation!r}")
        for outcome in self.budget_outcomes:
            if not isinstance(outcome, BudgetOutcome):
                raise ValueError(
                    "ObservationClosure.budget_outcomes entries must be BudgetOutcome "
                    f"instances, got {outcome!r}")
        for note in self.diagnostics:
            if not isinstance(note, str) or not note:
                raise ValueError(
                    f"ObservationClosure.diagnostics entries must be non-empty str, got {note!r}")

        rs = self.read_slice
        if rs is not None:
            if self.capture_state != rs.capture.state:
                raise ValueError(
                    f"ObservationClosure.capture_state ({self.capture_state}) must equal "
                    f"read_slice.capture.state ({rs.capture.state})")
            if rs.is_short and self.coverage_status == "complete":
                raise ValueError(
                    "ObservationClosure.coverage_status cannot be 'complete' when the read "
                    "did not return the whole requested range")
        if self.coverage_status == "complete" and self.capture_state != CaptureState.COMPLETE:
            raise ValueError(
                f"ObservationClosure.coverage_status 'complete' requires capture_state "
                f"COMPLETE, got {self.capture_state}")

    @property
    def attribution(self) -> tuple:
        return (self.source, self.scope)


# ── ObservationResult ─────────────────────────────────────────────────

@dataclass(frozen=True)
class ObservationResult:
    """One expensive observation's frozen outcome: its execution ``key``, one
    or more :class:`ObservationClosure` projections, and an optional immutable
    ``payload``.

    Reuse returns the same instance, so a partial / failed / truncated /
    not-evaluated closure is never silently upgraded. Cross-field checks that
    need the key are enforced here: a closure's ``read_slice`` must describe
    the key's own range, a range-local observation with no captured bytes is
    ``not_evaluated``, and a range-local closure that ran carries its
    ``read_slice``.
    """
    key: ObservationKey
    closures: tuple
    payload: object = None

    def __post_init__(self):
        if not isinstance(self.key, ObservationKey):
            raise ValueError(
                f"ObservationResult.key must be an ObservationKey, got {self.key!r}")
        object.__setattr__(self, "closures",
                           as_tuple(self.closures, "ObservationResult.closures"))
        if not self.closures:
            raise ValueError("ObservationResult.closures must be non-empty")
        seen = set()
        for closure in self.closures:
            if not isinstance(closure, ObservationClosure):
                raise ValueError(
                    f"ObservationResult.closures entries must be ObservationClosure, "
                    f"got {closure!r}")
            if closure.attribution in seen:
                raise ValueError(
                    f"ObservationResult.closures has two closures for "
                    f"{closure.attribution!r} -- each (source, scope) is projected once")
            seen.add(closure.attribution)
            self._check_closure_source(closure)
            self._check_closure_against_key(closure)

        self._check_shared_capture()
        require_recursively_immutable(self, "ObservationResult")

    def _check_shared_capture(self) -> None:
        """Capture is a fact of (dump, requested_range), which every closure of
        one key shares -- the targeted contract's "captured once and shared by
        all layers". Only ``coverage_status`` / ``limitations`` /
        ``budget_outcomes`` / ``diagnostics`` (and how many of the read bytes
        each layer consumed) are legitimately per-closure. So no closure may
        contradict a sibling about how much of the range the dump backed."""
        capture_states = {c.capture_state for c in self.closures}
        if len(capture_states) > 1:
            raise ValueError(
                "ObservationResult: closures of one key disagree about capture_state "
                f"{sorted(s.value for s in capture_states)} -- the range is captured once "
                f"and shared by every closure")
        captures = {c.read_slice.capture for c in self.closures if c.read_slice is not None}
        if len(captures) > 1:
            raise ValueError(
                "ObservationResult: closures of one key carry different CapturedSlice "
                "values -- the range is captured once and shared by every closure")

    def _check_closure_source(self, closure: ObservationClosure) -> None:
        vocab = _registry.coverage_sources_for(self.key.analyzer)
        if not vocab:
            return   # injection / hollowing -- no published vocabulary constant
        if closure.source not in vocab:
            raise ValueError(
                f"ObservationResult: closure source {closure.source!r} is not one of "
                f"{self.key.analyzer}'s real coverage sources {sorted(vocab)}")
        # A source with a CLOSED layer vocabulary (obfuscation's
        # `encoding_scan` -> OVERSIZE_SCAN_LAYERS) may still carry NO scope --
        # a layer-agnostic gap (a whole-analyzer budget exhaustion, all
        # regions filtered) belongs to no single layer. Only an invented
        # layer name is rejected. Every other source's `scope` is an open
        # budget-kind / sub-signal tag with no fixed vocabulary.
        layers = _registry.closed_scope_vocab_for(self.key.analyzer, closure.source)
        if layers is not None and closure.scope is not None and closure.scope not in layers:
            raise ValueError(
                f"ObservationResult: closure scope {closure.scope!r} for "
                f"{self.key.analyzer}/{closure.source!r} must be None or one of "
                f"{sorted(layers)}")

    def _check_closure_against_key(self, closure: ObservationClosure) -> None:
        rs = closure.read_slice
        if rs is not None:
            if self.key.requested_range is None:
                raise ValueError(
                    "ObservationResult: a closure read_slice is a single-range fact -- "
                    "the key must carry the range it was read against")
            if rs.requested != self.key.requested_range:
                raise ValueError(
                    f"ObservationResult: closure read_slice.requested ({rs.requested}) must "
                    f"equal the key's requested_range ({self.key.requested_range})")
        if self.key.requested_range is not None:
            if closure.capture_state == CaptureState.NONE \
                    and closure.coverage_status != "not_evaluated":
                raise ValueError(
                    f"ObservationResult: closure {closure.attribution!r} captured no bytes "
                    f"so it is 'not_evaluated' -- no bytes reached the algorithm")
            if closure.coverage_status != "not_evaluated" and rs is None:
                raise ValueError(
                    f"ObservationResult: closure {closure.attribution!r} ran (partial or "
                    f"complete) so it carries the ReadSlice it ran against")

    def closure_for(self, source: str, scope: "str | None" = None) -> ObservationClosure:
        """The projected closure for ``(source, scope)``. Raises ``KeyError``
        for an unprojected closure -- never falls back to the observation's
        aggregate status."""
        for closure in self.closures:
            if closure.source == source and closure.scope == scope:
                return closure
        raise KeyError(
            f"observation {self.key!r} has no closure for source={source!r} scope={scope!r}")

    def has_closure(self, source: str, scope: "str | None" = None) -> bool:
        return any(c.source == source and c.scope == scope for c in self.closures)


# ── failure record ────────────────────────────────────────────────────

@dataclass(frozen=True)
class _FailureRecord:
    """The lightweight, immutable trace of one producer failure -- type name
    and message only, never the live exception object (which would keep its
    call frames and grow its traceback on every re-raise)."""
    exc_type: str
    message: str


_FALLBACK_FAILURE = _FailureRecord("<producer failure>", "<summary unavailable>")


def _describe_failure(exc: BaseException) -> _FailureRecord:
    """A best-effort summary of a producer failure. Ordinary formatting faults
    (an exception whose ``__str__`` raises an ``Exception``) become a fixed
    placeholder. A ``BaseException`` from that formatting -- a genuine
    ``KeyboardInterrupt`` / ``SystemExit`` -- is deliberately NOT caught here;
    :meth:`ObservationRegistry.get_or_compute` has already written the fallback
    tombstone before calling this, so the producer still runs at most once, and
    the interrupt is not swallowed."""
    try:
        exc_type = type(exc).__name__
        if not isinstance(exc_type, str) or not exc_type:
            exc_type = repr(type(exc))
    except Exception:
        exc_type = "<unformattable exception type>"
    try:
        message = str(exc)
        if not isinstance(message, str):
            message = "<exception message is not a string>"
    except Exception:
        message = "<exception message could not be formatted>"
    return _FailureRecord(exc_type, message)


def _require_produced_result(key: ObservationKey, result) -> None:
    """A producer must return an :class:`ObservationResult` for the exact key
    it was asked to produce. A wrong type or a mismatched key is a producer
    defect handled as a production failure by
    :meth:`ObservationRegistry.get_or_compute`."""
    if not isinstance(result, ObservationResult):
        raise TypeError(
            f"observation producer for {key!r} must return an ObservationResult, "
            f"got {type(result).__name__}")
    if result.key != key:
        raise ValueError(
            "observation producer returned a result for a different key "
            f"({result.key!r} != {key!r})")


# ── ObservationRegistry ───────────────────────────────────────────────

@dataclass
class ObservationRegistry:
    """One invocation's bounded store of :class:`ObservationResult` by
    :class:`ObservationKey`, plus the lifecycle event history.

    Not immutable: this is the single mutable per-invocation object. It never
    revises a stored result, and its private storage cannot be handed in from
    outside -- ``_entries`` / ``_events`` / ``_failures`` are all ``init=False``
    so a shared or process-wide cache is not constructible.

    ``max_entries`` bounds *how many distinct expensive observations one
    invocation may run*, not just memory: :meth:`get_or_compute` is the scan
    boundary, and once the distinct-key count (retained results plus failure
    tombstones) is full it refuses a new key *before* calling the producer
    (raising :class:`ObservationBudgetExhausted`). A dump with thousands of
    attacker-controlled regions therefore cannot drive thousands of expensive
    scans -- and a key that already succeeded, failed, or was refused is never
    scanned again. There is no eviction.
    """
    max_entries: int = DEFAULT_MAX_ENTRIES
    _entries: dict = field(default_factory=dict, init=False, repr=False)
    _failures: dict = field(default_factory=dict, init=False, repr=False)
    _events: list = field(default_factory=list, init=False, repr=False)
    _tally: dict = field(default_factory=dict, init=False, repr=False)
    _record_overflow: int = field(default=0, init=False, repr=False)
    _event_overflow: int = field(default=0, init=False, repr=False)
    _claimed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self):
        if not isinstance(self.max_entries, int) or isinstance(self.max_entries, bool) \
                or self.max_entries <= 0:
            raise ValueError(
                f"ObservationRegistry.max_entries must be a positive int, got {self.max_entries!r}")
        self._tally = {outcome: 0 for outcome in ObservationOutcome}

    def claim(self) -> None:
        """Bind this registry to one :class:`dumpex.hunt._execution.HuntExecutionContext`,
        once. A second claim -- the registry reaching a second context, hence
        a second invocation or dump -- raises. `ObservationKey` carries no
        dump identity, so a shared registry would serve one dump's result for
        another; this is the enforcement that it cannot be shared."""
        if self._claimed:
            raise ValueError(
                "ObservationRegistry is already bound to an execution context -- it is "
                "strictly per-invocation and cannot be reused across dumps")
        self._claimed = True

    def _note(self, key: ObservationKey, outcome: ObservationOutcome) -> None:
        # The per-outcome tally is exact and never truncated. The detailed
        # (key, outcome) history is bounded to the entry cap; events dropped
        # past it are counted in `event_overflow`, never silently lost.
        self._tally[outcome] += 1
        if len(self._events) < self.max_entries:
            self._events.append((key, outcome))
        else:
            self._event_overflow += 1

    def _incompatible_locus_present(self, key: ObservationKey) -> bool:
        locus = key.coverage_locus
        return any(stored.coverage_locus == locus for stored in self._entries)

    def _distinct_keys(self) -> int:
        # A retained result and a failure tombstone both occupy budget, so a
        # flood of failing keys is capped exactly like a flood of succeeding
        # ones.
        return len(self._entries) + len(self._failures)

    def lookup(self, key: ObservationKey) -> "ObservationResult | None":
        """The stored result for ``key`` (recording ``REUSED``), or ``None``.
        When no exact result exists but a stored one shares the coverage
        locus, records ``INCOMPATIBLE_CACHE``. Read-only: never runs a
        producer, never raises for saturation."""
        if not isinstance(key, ObservationKey):
            raise TypeError(f"ObservationRegistry.lookup() needs an ObservationKey, got {key!r}")
        hit = self._entries.get(key)
        if hit is not None:
            self._note(key, ObservationOutcome.REUSED)
            return hit
        if self._incompatible_locus_present(key):
            self._note(key, ObservationOutcome.INCOMPATIBLE_CACHE)
        return None

    def get_or_compute(self, key: ObservationKey, producer) -> ObservationResult:
        """The expensive-scan boundary: ``producer()`` runs **at most once**
        for ``key`` this invocation -- never after a hit, a failure, or a
        saturated refusal.

        ``producer`` is a zero-argument callable returning an
        :class:`ObservationResult` whose ``key`` equals ``key``.

        - exact hit -> the stored result, ``REUSED``;
        - ``key`` already failed this invocation -> ``FAILED`` recorded again
          and a fresh :class:`ObservationProducerFailed` raised, producer not
          called;
        - budget spent and ``key`` new -> ``SATURATED`` recorded and
          :class:`ObservationBudgetExhausted` raised, producer not called;
        - otherwise -> ``producer()`` once. A raise, or a return that is not an
          :class:`ObservationResult` for ``key``, is recorded ``FAILED``,
          tombstoned (a fixed fallback written first, before any of the
          exception's own formatting), and propagated. Success is retained and
          recorded ``PRODUCED`` (with ``INCOMPATIBLE_CACHE`` first if a stale
          variant was stored).
        """
        if not isinstance(key, ObservationKey):
            raise TypeError(
                f"ObservationRegistry.get_or_compute() needs an ObservationKey, got {key!r}")
        if not callable(producer):
            raise TypeError("ObservationRegistry.get_or_compute() needs a callable producer")
        hit = self._entries.get(key)
        if hit is not None:
            self._note(key, ObservationOutcome.REUSED)
            return hit
        tombstone = self._failures.get(key)
        if tombstone is not None:
            self._note(key, ObservationOutcome.FAILED)
            raise ObservationProducerFailed(key, tombstone.exc_type, tombstone.message)
        if self._incompatible_locus_present(key):
            self._note(key, ObservationOutcome.INCOMPATIBLE_CACHE)
        if self._distinct_keys() >= self.max_entries:
            self._note(key, ObservationOutcome.SATURATED)
            raise ObservationBudgetExhausted(key, self.max_entries)
        try:
            result = producer()
            _require_produced_result(key, result)
        except BaseException as exc:
            # The fallback tombstone and the FAILED note are written with no
            # user-controlled code in the path (a two-string _FailureRecord
            # and a dict/list mutation), BEFORE `_describe_failure` runs any
            # of `exc`'s own formatting. So a producer that raises anything --
            # Exception or BaseException -- still tombstones this key and runs
            # at most once; the exception itself is re-raised unchanged.
            self._failures[key] = _FALLBACK_FAILURE
            self._note(key, ObservationOutcome.FAILED)
            self._failures[key] = _describe_failure(exc)
            raise
        self._entries[key] = result
        self._note(key, ObservationOutcome.PRODUCED)
        return result

    def record(self, result: ObservationResult) -> ObservationResult:
        """Retain an ``ObservationResult`` computed outside the registry (a
        cheap derivation, not an expensive scan -- use :meth:`get_or_compute`
        for those). Idempotent: an identical key already present returns the
        stored instance and records ``REUSED``. Once the budget is spent and
        the key is new, the result is returned un-retained and recorded
        ``SATURATED``.

        A key already tombstoned by a :meth:`get_or_compute` failure is
        terminal: ``record`` raises rather than let a failed key be re-stored
        as a success (``_entries`` and the failure tombstones are strictly
        disjoint)."""
        if not isinstance(result, ObservationResult):
            raise TypeError(
                f"ObservationRegistry.record() needs an ObservationResult, got {result!r}")
        if result.key in self._failures:
            raise ValueError(
                f"ObservationRegistry.record(): {result.key!r} already failed this "
                f"invocation -- a failed observation is terminal and cannot be recorded "
                f"as a success")
        existing = self._entries.get(result.key)
        if existing is not None:
            self._note(result.key, ObservationOutcome.REUSED)
            return existing
        if self._distinct_keys() >= self.max_entries:
            self._record_overflow += 1
            self._note(result.key, ObservationOutcome.SATURATED)
            return result
        self._entries[result.key] = result
        self._note(result.key, ObservationOutcome.PRODUCED)
        return result

    def note_unavailable(self, key: ObservationKey) -> None:
        """Record that ``key``'s prerequisites were missing, so nothing ran.
        Instrumentation only -- leaves no tombstone."""
        if not isinstance(key, ObservationKey):
            raise TypeError("ObservationRegistry.note_unavailable() needs an ObservationKey")
        self._note(key, ObservationOutcome.UNAVAILABLE)

    def note_failed(self, key: ObservationKey) -> None:
        """Record that producing ``key``'s observation failed. Instrumentation
        only -- a caller managing its own producer; :meth:`get_or_compute`
        tombstones a key so it is not retried."""
        if not isinstance(key, ObservationKey):
            raise TypeError("ObservationRegistry.note_failed() needs an ObservationKey")
        self._note(key, ObservationOutcome.FAILED)

    def events(self) -> tuple:
        """The recorded ``(ObservationKey, ObservationOutcome)`` history,
        capped at ``max_entries``. Use :meth:`counts` for exact totals."""
        return tuple(self._events)

    def counts(self) -> dict:
        """Exact count of every :class:`ObservationOutcome` recorded this
        invocation -- a running tally, not derived from the truncatable event
        history."""
        return dict(self._tally)

    @property
    def retained(self) -> int:
        """Observations currently held for reuse."""
        return len(self._entries)

    @property
    def abandoned(self) -> int:
        """Distinct keys tombstoned by a :meth:`get_or_compute` failure -- each
        refused on any later request, never retried."""
        return len(self._failures)

    @property
    def event_overflow(self) -> int:
        """History entries dropped past ``max_entries`` (still in :meth:`counts`)."""
        return self._event_overflow

    @property
    def record_overflow(self) -> int:
        """Results passed to :meth:`record` the full store could not retain
        (also a ``SATURATED`` event). Expensive scans routed through
        :meth:`get_or_compute` never reach this -- they raise instead."""
        return self._record_overflow

"""The per-invocation hunt execution context.

A :class:`HuntExecutionContext` bundles the state one ``--hunt`` invocation
shares across analyzers and that is not static analyzer metadata: the
normalized :class:`dumpex.hunt._request.HuntRequest`, the open dump handle, the
invocation-local :class:`dumpex.hunt._observation.ObservationRegistry`, and a
budget ledger.

It also exposes the dump's captured-segment and captured-region views from
:mod:`dumpex.core.va_range`, enumerated once and memoized, so several analyzers
sharing one context do not each re-walk the segment table.

Read/runtime facades are deliberately NOT on the context. A hunter's
``read_region`` / ``get_thread_contexts`` bindings are monkeypatched per hunter
package (`dumpex.hunt.pipe.read_region`, ...), and a single shared
:class:`dumpex.hunt._runtime.HunterRuntime` snapshot cannot represent several
hunters patched differently in one ``--hunt all`` run. A context-aware builder
still builds its own :class:`~dumpex.hunt._runtime.HunterRuntime` from its own
facade globals, exactly as every builder does today.

The context is not recursively immutable: it holds the live dump handle and the
mutable observation registry by design. It is frozen only against field
reassignment; the memoized views are cached through ``object.__setattr__``.
"""
from dataclasses import dataclass, field

from dumpex.core import va_range
from dumpex.hunt import _registry
from dumpex.hunt._observation import ObservationKey, ObservationRegistry
from dumpex.hunt._request import HuntRequest

__all__ = [
    "HuntBudgetLedger",
    "HuntExecutionContext",
    "build_execution_context",
]

# A single invocation registers only a handful of budgets (the most any
# current hunter builds is two). The cap is a fail-closed guard against a
# caller looping a name, not a working limit.
DEFAULT_MAX_BUDGETS = 32


@dataclass
class HuntBudgetLedger:
    """One invocation's budgets, by name.

    Deliberately not tied to any one budget type: hunters build budgets
    differently (two ``ScanBudget`` objects for pipe, one for obfuscation,
    bespoke classes elsewhere). This is only a per-invocation namespace whose
    guarantees are that a budget is registered once and that the ledger is
    bounded. Budgets are always fresh per invocation; nothing here persists
    between commands.
    """
    max_budgets: int = DEFAULT_MAX_BUDGETS
    _budgets: dict = field(default_factory=dict, init=False, repr=False)
    _claimed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self):
        if not isinstance(self.max_budgets, int) or isinstance(self.max_budgets, bool) \
                or self.max_budgets <= 0:
            raise ValueError(
                f"HuntBudgetLedger.max_budgets must be a positive int, got {self.max_budgets!r}")

    def claim(self) -> None:
        """Bind this ledger to one :class:`HuntExecutionContext`, once. A
        second claim -- the ledger reaching a second context -- raises, so a
        ledger's budget state and names cannot bleed between invocations."""
        if self._claimed:
            raise ValueError(
                "HuntBudgetLedger is already bound to an execution context -- a ledger "
                "is per-invocation and cannot be shared")
        self._claimed = True

    def register(self, name: str, budget: object) -> object:
        """Register ``budget`` under ``name`` and return it. Re-registering a
        name, or exceeding the cap, raises -- a budget has one owner per
        invocation."""
        if not isinstance(name, str) or not name:
            raise ValueError(f"HuntBudgetLedger name must be a non-empty str, got {name!r}")
        if name in self._budgets:
            raise ValueError(f"HuntBudgetLedger: {name!r} is already registered this invocation")
        if len(self._budgets) >= self.max_budgets:
            raise ValueError(
                f"HuntBudgetLedger: refusing to register more than {self.max_budgets} budgets")
        self._budgets[name] = budget
        return budget

    def get(self, name: str) -> object:
        """The budget registered under ``name``. Raises ``KeyError`` when
        unset -- a caller must register before reading, never silently get a
        fresh one."""
        return self._budgets[name]

    def __contains__(self, name: str) -> bool:
        return name in self._budgets

    def names(self) -> tuple:
        return tuple(self._budgets)


@dataclass(frozen=True, eq=False)
class HuntExecutionContext:
    """One invocation's request, dump handle, observation registry, and
    budgets.

    Build one through :func:`build_execution_context`. The captured-view
    accessors below enumerate the dump once and memoize, so passing one
    context to several analyzers costs one segment-table and one region-list
    walk for the whole run.

    ``eq=False``: a context is an identity object (it wraps a live dump handle
    and a mutable registry), so two contexts are equal only when they are the
    same object -- never by value.

    ``observations`` and ``budgets`` are created fresh here (``init=False``) --
    they cannot be handed in -- and each is ``claim()``-ed to this context, so
    a registry or ledger reaching a second context raises rather than leak one
    dump's observations or budget state into another. ``ObservationKey``
    carries no dump identity, so cross-dump reuse of one registry would
    silently serve dump A's result for dump B; this closes that.
    """
    request: HuntRequest
    mf: object
    observations: ObservationRegistry = field(
        default_factory=ObservationRegistry, init=False, repr=False)
    budgets: HuntBudgetLedger = field(
        default_factory=HuntBudgetLedger, init=False, repr=False)
    _view_cache: dict = field(default_factory=dict, init=False, repr=False, compare=False)

    def __post_init__(self):
        if not isinstance(self.request, HuntRequest):
            raise ValueError(
                f"HuntExecutionContext.request must be a HuntRequest, got {self.request!r}")
        self.observations.claim()
        self.budgets.claim()

    def captured_segment_enumeration(self) -> va_range.CapturedEnumeration:
        """Every ``Memory64List``/``MemoryList`` segment as ascending-address
        :class:`dumpex.core.va_range.CapturedSegment` views, plus the count of
        raw descriptors the value model could not represent -- enumerated once.
        A consumer that must distinguish "no segment contains this address"
        from "a segment does, but its descriptor was dropped" reads
        ``.skipped``."""
        if "segment_enum" not in self._view_cache:
            self._view_cache["segment_enum"] = va_range.enumerate_captured_segments(self.mf)
        return self._view_cache["segment_enum"]

    def captured_segments(self) -> tuple:
        """Every ``Memory64List``/``MemoryList`` segment of the dump as
        ascending-address :class:`dumpex.core.va_range.CapturedSegment`
        views, enumerated once."""
        return self.captured_segment_enumeration().views

    def captured_region_enumeration(self) -> va_range.CapturedEnumeration:
        """Every ``MemoryInfoListStream`` region as ascending-address
        :class:`dumpex.core.va_range.CapturedRegion` views, plus the count of
        raw descriptors the value model could not represent -- enumerated once.
        A consumer that must distinguish "no region contains this address" from
        "a region does, but its descriptor was dropped" reads ``.skipped``."""
        if "region_enum" not in self._view_cache:
            self._view_cache["region_enum"] = va_range.enumerate_captured_regions(self.mf)
        return self._view_cache["region_enum"]

    def captured_regions(self) -> tuple:
        """Every ``MemoryInfoListStream`` region of the dump as ascending-
        address :class:`dumpex.core.va_range.CapturedRegion` views,
        enumerated once."""
        return self.captured_region_enumeration().views

    def capture_of(self, requested: va_range.VirtualRange) -> va_range.CapturedSlice:
        """How ``requested`` relates to the dump's captured evidence, computed
        against the memoized segment views."""
        if not isinstance(requested, va_range.VirtualRange):
            raise TypeError(
                f"HuntExecutionContext.capture_of() needs a VirtualRange, got {requested!r}")
        return va_range.slice_captured(requested, self.captured_segments())

    def observation_key(self, analyzer: str, *, algorithm_version: str,
                        requested_range: "va_range.VirtualRange | None" = None,
                        config_provenance: "str | None" = None,
                        rule_provenance: "str | None" = None) -> ObservationKey:
        """The canonical way to build an :class:`ObservationKey` during an
        invocation. ``is_targeted`` and the configuration / rule provenance
        are derived from ``self.request`` so an adapter cannot forget them.

        An analyzer whose spec declares a ``ref_dir`` / ``rules_dir`` option
        always gets a provenance token: an explicit argument, else the
        request's own option value, else the fixed ``"ref_dir:unset"`` /
        ``"rules_dir:unset"`` sentinel -- so a run with a directory and a run
        without one produce different keys rather than the factory refusing to
        exist for the common unconfigured case. An analyzer with no such
        option gets ``None`` (there is nothing to identify).
        """
        spec = _registry.REGISTRY.get(analyzer)
        if requested_range is None and self.request.is_targeted:
            requested_range = self.request.target_range

        cfg = None
        if "ref_dir" in spec.option_names:
            resolved = (config_provenance if config_provenance is not None
                        else self.request.options.ref_dir)
            cfg = resolved if resolved is not None else "ref_dir:unset"
        rules = None
        if "rules_dir" in spec.option_names:
            resolved = (rule_provenance if rule_provenance is not None
                        else self.request.options.rules_dir)
            rules = resolved if resolved is not None else "rules_dir:unset"

        return ObservationKey(
            analyzer=analyzer,
            is_targeted=self.request.is_targeted,
            algorithm_version=algorithm_version,
            requested_range=requested_range,
            config_provenance=cfg,
            rule_provenance=rules,
        )


def build_execution_context(mf, request: HuntRequest) -> HuntExecutionContext:
    """The single construction path for a :class:`HuntExecutionContext`. The
    context creates its own fresh :class:`ObservationRegistry` and
    :class:`HuntBudgetLedger` -- neither can be shared with another
    invocation."""
    if not isinstance(request, HuntRequest):
        raise TypeError(
            f"build_execution_context() needs a HuntRequest, got {request!r}")
    return HuntExecutionContext(request=request, mf=mf)

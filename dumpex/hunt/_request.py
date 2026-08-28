"""Immutable per-invocation hunt request -- normalized investigator intent.

A ``HuntRequest`` is the one value object that carries what an investigator
asked for into the analyzer registry: which analyzer (or ``"all"``), whether
the run is full-scope or targeted at one virtual-address range, and only the
approved hunt options. It owns intent, never dump handles, runtime facades,
budgets, or results -- those belong to
:class:`dumpex.hunt._execution.HuntExecutionContext`.

The request is recursively immutable: every field is a frozen value, and
construction validates the full shape so a request that reaches an executor is
already normalized. Targeted construction routes through
:meth:`dumpex.hunt._registry.AnalyzerRegistry.select_targeted_scopes`, so an
unsupported analyzer, source, or scope set fails closed here, before any dump
is opened, and the per-analyzer request-size ceiling
(``TargetedCapability.request_ceiling``) is enforced from the registry -- there
is no second identity-keyed ceiling table.
"""
from dataclasses import dataclass
from enum import Enum
import os

from dumpex.core.va_range import VirtualRange
from dumpex.hunt import _registry
from dumpex.hunt._domain import require_recursively_immutable
from dumpex.output.records import HUNTERS

__all__ = [
    "HuntScopeKind",
    "HuntOptions",
    "HuntRequest",
]

_MIB = 1 << 20

_FULL_SELECTIONS = frozenset(HUNTERS) | {"all"}


def _normalize_option(value, name: str) -> "str | None":
    """Match what every builder already does with a directory option: a
    falsy value (``None``, ``""``) is "unset" -> ``None``; an ``os.PathLike``
    is accepted and coerced to ``str``; anything else must already be a
    ``str``. This never tightens what the previous ad-hoc ``_option_view()``
    accepted."""
    if not value:
        return None
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if not isinstance(value, str):
        raise ValueError(
            f"HuntOptions.{name} must be a str, an os.PathLike, or falsy for unset, "
            f"got {value!r}")
    return value


class HuntScopeKind(str, Enum):
    """Whether a request covers the whole dump or one investigator-selected
    virtual-address range. ``str`` mix-in so the value carries through a
    structured projection unchanged."""
    FULL = "full"
    TARGETED = "targeted"


@dataclass(frozen=True)
class HuntOptions:
    """The closed set of hunt options an executor knows how to supply --
    exactly the names :data:`dumpex.hunt._registry.KNOWN_OPTION_NAMES` holds.
    A falsy value normalizes to ``None`` and an ``os.PathLike`` to its string
    form, so ``--ref-dir ""`` / ``--yara-dir ""`` (which the CLI passes
    through) behave exactly as before. ``as_option_view()`` produces the same
    mapping shape ``dumpex.hunt._execute_full_scope`` builds."""
    ref_dir: "str | None" = None
    rules_dir: "str | None" = None

    def __post_init__(self):
        object.__setattr__(self, "ref_dir", _normalize_option(self.ref_dir, "ref_dir"))
        object.__setattr__(self, "rules_dir", _normalize_option(self.rules_dir, "rules_dir"))

    def as_option_view(self) -> dict:
        return {"ref_dir": self.ref_dir, "rules_dir": self.rules_dir}


@dataclass(frozen=True)
class HuntRequest:
    """One invocation's normalized intent.

    ``selected`` is ``"all"`` or a :data:`dumpex.output.records.HUNTERS`
    member for a full-scope request, and always a single ``HUNTERS`` member
    for a targeted one. ``targeted_source`` / ``targeted_scopes`` /
    ``target_range`` are set together for a targeted request and are unset for
    a full-scope one. ``targeted_scopes`` is a ``frozenset`` -- empty for an
    unscoped source, and the full granted layer set for a scoped one
    (obfuscation always attempts all of its layers; there is no public
    per-layer selection), so one request always covers one whole invocation.

    Every constructor path is fully validated: a full-scope ``selected`` is a
    real selection, and a targeted request is resolved through the registry
    (:meth:`~dumpex.hunt._registry.AnalyzerRegistry.select_targeted_scopes`)
    and checked against that analyzer's ``request_ceiling``. An unsupported
    analyzer, source, scope set, or oversized range fails here, before any
    dump work.
    """
    scope: HuntScopeKind
    selected: str
    options: HuntOptions
    targeted_source: "str | None" = None
    targeted_scopes: frozenset = frozenset()
    target_range: "VirtualRange | None" = None

    def __post_init__(self):
        if not isinstance(self.scope, HuntScopeKind):
            raise ValueError(
                f"HuntRequest.scope must be a HuntScopeKind, got {self.scope!r}")
        if not isinstance(self.options, HuntOptions):
            raise ValueError(
                f"HuntRequest.options must be a HuntOptions, got {self.options!r}")
        if not isinstance(self.targeted_scopes, frozenset):
            raise ValueError(
                f"HuntRequest.targeted_scopes must be a frozenset, got {self.targeted_scopes!r}")

        if self.scope is HuntScopeKind.FULL:
            if self.selected not in _FULL_SELECTIONS:
                raise ValueError(
                    f"HuntRequest.selected must be 'all' or one of {HUNTERS} for a "
                    f"full-scope request, got {self.selected!r}")
            if self.targeted_source is not None or self.targeted_scopes or self.target_range is not None:
                raise ValueError(
                    "HuntRequest: a full-scope request carries no targeted "
                    "source/scopes/range")
        else:
            if not isinstance(self.targeted_source, str) or not self.targeted_source:
                raise ValueError(
                    "HuntRequest: a targeted request requires a non-empty "
                    "targeted_source")
            if not all(isinstance(s, str) and s for s in self.targeted_scopes):
                raise ValueError(
                    f"HuntRequest.targeted_scopes must contain non-empty str, "
                    f"got {self.targeted_scopes!r}")
            if not isinstance(self.target_range, VirtualRange):
                raise ValueError(
                    "HuntRequest: a targeted request requires a VirtualRange "
                    f"target_range, got {self.target_range!r}")
            # An empty scope set means "the granted set" -- resolve it from
            # the registry rather than make the caller (#64) restate
            # obfuscation's three layers. An explicit set is kept and
            # validated equal below.
            if not self.targeted_scopes:
                object.__setattr__(self, "targeted_scopes", _registry.REGISTRY.granted_scopes(
                    self.selected, self.targeted_source))
            # The grant resolves through the registry (raising its typed
            # UnknownAnalyzerIdentity / UnsupportedTargetedCapability /
            # UnpopulatedTargetedGrant / UnsupportedTargetedSource /
            # UnsupportedTargetedScope failure). REGISTRY is read lazily so a
            # test patching `_registry.REGISTRY` affects request validation
            # the same way it affects execution.
            spec = _registry.REGISTRY.select_targeted_scopes(
                self.selected, self.targeted_source, self.targeted_scopes)
            ceiling = spec.targeted_capability.request_ceiling
            if self.target_range.size > ceiling:
                raise ValueError(
                    f"HuntRequest: {self.selected!r} range size 0x{self.target_range.size:x} "
                    f"exceeds its request ceiling of {ceiling // _MIB} MiB")

        require_recursively_immutable(self, "HuntRequest")

    @classmethod
    def full(cls, selected: str, *, ref_dir=None, rules_dir=None) -> "HuntRequest":
        """A full-scope request for ``selected`` (``"all"`` or one hunter)."""
        if selected not in _FULL_SELECTIONS:
            raise ValueError(
                f"HuntRequest.full() selected must be 'all' or one of {HUNTERS}, "
                f"got {selected!r}")
        return cls(
            scope=HuntScopeKind.FULL,
            selected=selected,
            options=HuntOptions(ref_dir=ref_dir, rules_dir=rules_dir),
        )

    @classmethod
    def targeted(cls, identity: str, source: str, target_range: VirtualRange, *,
                 scopes: "frozenset | set | None" = None, ref_dir=None,
                 rules_dir=None) -> "HuntRequest":
        """A targeted request for one hunter over ``target_range``.

        Convenience only: construction validates the grant and the scope set
        through
        :meth:`dumpex.hunt._registry.AnalyzerRegistry.select_targeted_scopes`
        and the analyzer's ``request_ceiling``. ``scopes`` is empty for an
        unscoped source; for a scoped source (obfuscation) it must be the full
        granted layer set.
        """
        return cls(
            scope=HuntScopeKind.TARGETED,
            selected=identity,
            options=HuntOptions(ref_dir=ref_dir, rules_dir=rules_dir),
            targeted_source=source,
            targeted_scopes=frozenset(scopes) if scopes else frozenset(),
            target_range=target_range,
        )

    @property
    def is_targeted(self) -> bool:
        return self.scope is HuntScopeKind.TARGETED

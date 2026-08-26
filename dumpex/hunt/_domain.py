"""Shared immutable hunt-domain primitives and validators.

CheckResult keeps typed evidence separate from rendered facts and validates tag,
confidence, score contribution, and evidence caps. Recursive immutability checks
reject mutable or unrecognized payloads so reports cannot retain live parser
objects or change after scoring.
"""
import dataclasses
import enum
from types import MappingProxyType

from dumpex.hunt._finding import (
    Finding, TAG_OBSERVATION, _TAGS, _CONFIDENCES, severity_for,
    _require_nonempty_str, _require_optional_nonempty_str,
    _require_list_of_str, _require_str_list, _require_technique_ids,
)


# Containers that are mutable in place regardless of any `frozen=True` on
# whatever holds them -- `frozen` only stops attribute REASSIGNMENT, so a
# frozen dataclass field holding a list still lets a caller do
# `report.evidence.rwx.append(...)` (or keep the original list and mutate
# it after construction). Named separately from the general rejection
# below only so the error message can say what specifically went wrong;
# `types.MappingProxyType` is deliberately NOT here and is NOT a dict
# subclass -- it is the read-only mapping view
# dumpex.hunt.injection.models.Correlation already normalizes its
# per-allocation maps to.
_MUTABLE_CONTAINERS = (list, set, dict, bytearray)

# The ONLY leaf values `require_recursively_immutable` accepts. This is a
# deliberate allowlist, not a denylist of known-bad types: a denylist
# treats every unrecognized object as an immutable leaf, which is exactly
# how a `MinidumpFile`, a `read_region` resolver, or any custom class
# wrapping a mutable payload gets to sit inside a "frozen" evidence object
# and stay reachable from -- and mutable through -- a constructed Report.
# The whole point of the guardrail is that such a reference cannot be
# retained at all, so anything not proven immutable is refused.
#
# Matched by EXACT type (`type(value) in ...`), never isinstance: a
# subclass of an immutable builtin is not itself immutable. `class
# Sneaky(str)` with an instance attribute holding a list passes every
# isinstance check for `str` while carrying a mutable payload that
# survives into the Report. A value type that genuinely belongs here
# later (a date, a Decimal) is added deliberately, with the reasoning
# written down, rather than admitted by an isinstance test.
_IMMUTABLE_LEAF_TYPES = frozenset({type(None), bool, int, float, complex, str, bytes})

# Containers this module recurses into, also matched by exact type and
# for the same reason -- a tuple/frozenset SUBCLASS can carry mutable
# instance attributes that recursing over its items would never see.
_IMMUTABLE_CONTAINERS = frozenset({tuple, frozenset})

# `__slots__`/`__dict__` names that are Python's own opt-in mechanisms,
# never a place user data lives: `__dict__` appearing IN a `__slots__`
# tuple just means the class re-enables an instance dict (already handled
# by the `__dict__`-contents check below); `__weakref__` is a C-level
# descriptor enabling weak references, never a container a caller could
# stash a mutable payload in.
_NON_DATA_SLOT_NAMES = frozenset({"__weakref__", "__dict__"})


def _own_slot_names(cls) -> set:
    """Every attribute name any class in `cls`'s MRO declares via its OWN
    `__slots__` (i.e. read from that class's `__dict__`, never through
    attribute lookup/inheritance -- the MRO walk already visits every
    class, so inheritance would only add redundant re-reads of a base
    class's own entry).

    This exists because a slot-backed attribute is invisible to both
    `dataclasses.fields()` (unless it was ALSO declared as an annotated
    dataclass field) and to `vars(instance)`/`instance.__dict__` (a slot
    never populates the instance dict at all -- that is the entire point
    of using `__slots__`). A subclass that adds its own `__slots__` entry
    beyond its declared dataclass fields gets a place to hold arbitrary
    mutable state that neither of those two views would ever reveal.

    `__slots__` may be declared as a single bare string (meaning ONE slot
    with that name) or any other iterable of strings -- a bare string must
    never be iterated directly, or `__slots__ = "hidden"` would silently
    decompose into six one-character "slot names" instead of the single
    slot it actually declares.
    """
    names = set()
    for klass in cls.__mro__:
        raw = klass.__dict__.get("__slots__")
        if raw is None:
            continue
        names.update((raw,) if isinstance(raw, str) else raw)
    return names - _NON_DATA_SLOT_NAMES


def as_tuple(value, field_name: str) -> tuple:
    """Accept a list OR tuple and return a tuple -- a defensive copy, so
    mutating the caller's own list after construction can never reach
    back into the constructed value object.

    Restricted to list/tuple specifically rather than "anything iterable",
    for the same reasons dumpex.output.coverage._normalize_tuple already
    documents: a bare string would silently explode into its characters, a
    set/dict would carry hash-order-dependent (therefore run-to-run
    unstable) ordering into a field whose order is part of the output
    contract, and a generator would work exactly once and then read empty.
    """
    if not isinstance(value, (list, tuple)):
        raise TypeError(
            f"{field_name} must be a list or tuple, got {type(value).__name__}")
    return tuple(value)


def require_recursively_immutable(value, field_name: str) -> None:
    """Raise unless every value reachable from value is immutable.

    Frozen dataclasses are shallow, so fields, undeclared attributes, and slots
    across the MRO are inspected recursively. Mutable containers, mutable
    dataclasses, mapping proxies, immutable-builtin subclasses, and unrecognized
    objects are rejected to prevent reports retaining mutable parser state.

    Tuples, frozensets, exact immutable scalars, frozen dataclasses, and enums are
    accepted only after their contents and instance state pass the same checks.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        if not value.__dataclass_params__.frozen:
            raise TypeError(
                f"{field_name} must be recursively immutable, but holds a "
                f"non-frozen dataclass {type(value).__name__}: {value!r}")
        declared = {f.name for f in dataclasses.fields(value)}
        instance_state = getattr(value, "__dict__", None)
        undeclared = (set(instance_state) if instance_state is not None else set()) - declared
        undeclared |= _own_slot_names(type(value)) - declared
        if undeclared:
            raise TypeError(
                f"{field_name} holds a {type(value).__name__} with "
                f"undeclared instance attribute(s) {sorted(undeclared)} -- "
                f"only declared fields are validated for immutability, so "
                f"anything else (whether stored in __dict__ or in a "
                f"__slots__ entry the class hierarchy adds beyond its "
                f"declared dataclass fields) is unchecked instance state a "
                f"subclass or a caller could have attached")
        for f in dataclasses.fields(value):
            require_recursively_immutable(getattr(value, f.name),
                                           f"{field_name}.{f.name}")
        return
    if isinstance(value, enum.Enum):
        # Checked before the leaf test on purpose: a `str, Enum` member
        # (dumpex.output.coverage's vocabularies) would otherwise slip
        # past on its str-ness alone, without its value being looked at.
        require_recursively_immutable(value.value, f"{field_name}.value")
        for attribute, attribute_value in vars(value).items():
            # `__objclass__` is the ONE genuinely Enum-internal attribute
            # that isn't itself a plain immutable leaf (it's a reference
            # to the enum class -- a `type` object, always present, never
            # user-supplied): exempted by exact name, not by a leading-
            # underscore heuristic. `_name_`/`_value_`/`_sort_order_` are
            # ordinary str/str/int leaves and pass this same call like any
            # other attribute -- no exemption needed, and none given.
            if attribute == "__objclass__":
                continue
            require_recursively_immutable(attribute_value, f"{field_name}.{attribute}")
        return
    if type(value) in _IMMUTABLE_CONTAINERS:
        for item in value:
            require_recursively_immutable(item, f"{field_name}[]")
        return
    if type(value) in _IMMUTABLE_LEAF_TYPES:
        return
    if isinstance(value, _MUTABLE_CONTAINERS):
        raise TypeError(
            f"{field_name} must be recursively immutable, but holds a mutable "
            f"{type(value).__name__}: {value!r}")
    if isinstance(value, MappingProxyType):
        raise TypeError(
            f"{field_name} must be recursively immutable, but holds a "
            f"MappingProxyType: {value!r} -- a read-only view is not an "
            f"immutable value; whoever holds the mapping behind it can still "
            f"change what this Report reports")
    raise TypeError(
        f"{field_name} must be recursively immutable, but holds a "
        f"{type(value).__name__} that is neither an immutable leaf nor an "
        f"immutable container: {value!r} -- an unrecognized object (or a "
        f"subclass of an immutable one) cannot be assumed immutable, and a "
        f"dump/resolver/projector reference must not be reachable from the "
        f"domain model at all")


def _require_evidence_items(value, field_name: str) -> tuple:
    """Normalize to a tuple and enforce what may be an evidence ITEM.

    An item must be a frozen dataclass instance -- a typed value object
    built by the scan/correlation layer. That single rule is what keeps
    every kind of thing this migration is removing out of the model at
    once: a raw minidump Region/ThreadInfo (not a dataclass at all), a
    `dict` of hand-rolled keys, a `MinidumpFile`/resolver handle, and --
    the case worth naming explicitly -- a pre-rendered console/JSON fact
    string.

    `Finding` is rejected by name even though it IS a frozen dataclass:
    it is the compat PROJECTION of a CheckResult (already carrying
    formatted `facts`/`verbose_facts` text), so admitting one here would
    put a rendered representation back inside the canonical model and
    reopen exactly the drift this type exists to close.
    """
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        where = f"{field_name}[{index}]"
        if isinstance(item, Finding):
            raise TypeError(
                f"{where} must be a typed evidence value object, not a Finding -- "
                f"Finding is a projection OF a CheckResult (it already carries "
                f"rendered facts text) and must never be stored as its evidence")
        if not (dataclasses.is_dataclass(item) and not isinstance(item, type)):
            raise TypeError(
                f"{where} must be a frozen evidence dataclass, got "
                f"{type(item).__name__}: {item!r}")
        require_recursively_immutable(item, where)
    return items


def _require_optional_positive_int(value, field_name: str) -> None:
    # bool is a subclass of int, so it has to be excluded explicitly --
    # `evidence_limit=True` would otherwise silently mean "enumerate one
    # item".
    if value is not None and (not isinstance(value, int)
                              or isinstance(value, bool) or value <= 0):
        raise ValueError(
            f"{field_name} must be None or a positive int (not bool), got {value!r}")


@dataclasses.dataclass(frozen=True)
class CheckResult:
    """One check's outcome, as the hunter's own decision layer knows it --
    the canonical, immutable replacement for building a
    `dumpex.hunt._finding.Finding` inside aggregate.py.

    Every field except `evidence`/`evidence_limit` carries the same
    meaning it already has on `Finding` (see dumpex/hunt/_finding.py's own
    module docstring for facts/inference/confidence/rationale/limitations,
    and `Finding`'s docstring for tag/technique_ids/evidence_refs/iocs/
    rule_id/rule_version). The two that differ:

      evidence        -- the TYPED value objects this check observed
                          (dumpex.hunt.injection.models.RwxRegionEvidence,
                          HiddenPeEvidence, ...), in the order the hunter
                          observed them. This replaces `Finding.facts`/
                          `Finding.verbose_facts`, which are already-
                          rendered strings: both of those become pure
                          projections OF this tuple, so the console
                          evidence block and the JSON `facts` array can
                          never describe the same region differently.

                          Objects here are the SAME instances the Report's
                          own evidence buckets hold -- shared references
                          to immutable value objects, never a second copy
                          that could drift from the first. That is a
                          checked invariant, not a convention: the Report
                          enforces it by identity at construction (see
                          dumpex.hunt.injection.domain.InjectionReport's
                          own `_require_results_cite_this_reports_own_
                          evidence`).

                          Legitimately empty for a check whose entire
                          claim is about a coverage GAP rather than about
                          observed items (injection's
                          `rip_correlation_unavailable`): there is no
                          evidence to point at, and a projector renders
                          that check's single fact from the Report's own
                          coverage snapshot instead.

      evidence_limit  -- how many evidence items a STRUCTURED projection
                          may enumerate before summarizing the remainder
                          ("... and N more"), or None for no cap. This is
                          a per-check detection-policy budget the hunter
                          owns (different checks legitimately cap
                          differently), not a console layout decision --
                          which is why it lives here rather than in a
                          projector, and why the console's own
                          verbose/normal choice is deliberately NOT
                          represented on this type at all.

    Deliberately absent, and never to be added: `facts`/`verbose_facts`
    (rendered text), `id` (a hash OF the rendered facts -- computable only
    once a projection exists, so it belongs to `Finding`, not here), and
    anything carrying a dump handle, an address resolver, or a verbosity/
    DetailLevel flag.
    """
    check:          str
    inference:      str
    confidence:     str
    rationale:      str
    evidence:       tuple = dataclasses.field(default_factory=tuple)
    limitations:    tuple = dataclasses.field(default_factory=tuple)
    tag:            str = TAG_OBSERVATION
    technique_ids:  tuple = dataclasses.field(default_factory=tuple)
    evidence_refs:  tuple = dataclasses.field(default_factory=tuple)
    iocs:           tuple = dataclasses.field(default_factory=tuple)
    rule_id:        "str | None" = None
    rule_version:   "str | None" = None
    evidence_limit: "int | None" = None

    def __post_init__(self):
        _require_nonempty_str(self.check, "CheckResult.check")
        if self.tag not in _TAGS:
            raise ValueError(f"CheckResult.tag must be one of {_TAGS}, got {self.tag!r}")
        if self.confidence not in _CONFIDENCES:
            raise ValueError(
                f"CheckResult.confidence must be one of {_CONFIDENCES}, "
                f"got {self.confidence!r}")
        _require_nonempty_str(self.inference, "CheckResult.inference")
        _require_nonempty_str(self.rationale, "CheckResult.rationale")
        _require_list_of_str(self.limitations, "CheckResult.limitations")
        _require_technique_ids(self.technique_ids, "CheckResult.technique_ids")
        _require_str_list(self.evidence_refs, "CheckResult.evidence_refs")
        _require_str_list(self.iocs, "CheckResult.iocs")
        _require_optional_nonempty_str(self.rule_id, "CheckResult.rule_id")
        _require_optional_nonempty_str(self.rule_version, "CheckResult.rule_version")
        _require_optional_positive_int(self.evidence_limit, "CheckResult.evidence_limit")

        # object.__setattr__ is the documented way to assign inside a
        # frozen dataclass's own __post_init__. Every sequence field is
        # normalized to a tuple here -- both a defensive copy of whatever
        # the caller passed and, since tuples are immutable, a second
        # barrier independent of frozen=True (the same reasoning
        # Finding.__post_init__ already applies to its own list fields).
        object.__setattr__(self, "evidence",
                            _require_evidence_items(self.evidence, "CheckResult.evidence"))
        object.__setattr__(self, "limitations",
                            as_tuple(self.limitations, "CheckResult.limitations"))
        object.__setattr__(self, "technique_ids",
                            as_tuple(self.technique_ids, "CheckResult.technique_ids"))
        object.__setattr__(self, "evidence_refs",
                            as_tuple(self.evidence_refs, "CheckResult.evidence_refs"))
        object.__setattr__(self, "iocs", as_tuple(self.iocs, "CheckResult.iocs"))
        # Same default as Finding: `check` already IS this codebase's
        # stable detection-logic identifier, so this is a real value, not
        # a placeholder.
        object.__setattr__(self, "rule_id",
                            self.rule_id if self.rule_id is not None else self.check)

    @property
    def severity(self) -> str:
        """SIEM-facing severity, derived from (tag, confidence) through the
        ONE reducer that already owns that mapping
        (dumpex.hunt._finding.severity_for). A property rather than a
        stored field precisely because it is derived: there is no way to
        construct a CheckResult whose severity contradicts its own tag/
        confidence, and no stored copy that a later change to the mapping
        could leave stale."""
        return severity_for(self.tag, self.confidence)

"""`--profile`'s analysis-capability vocabulary: the ordered capability
registry, the limitation codes and their rendered text, and the
ProfileCapabilityEntry validated against them.

Like every --profile record (dumpex.output.records.profile), a capability
entry states what evidence exists, never a verdict.
"""
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType


class CapabilityStatus(str, Enum):
    AVAILABLE   = "available"
    LIMITED     = "limited"
    UNAVAILABLE = "unavailable"


_CAPABILITY_STATUSES = tuple(s.value for s in CapabilityStatus)


@dataclass(frozen=True)
class CapabilityDefinition:
    """One row of the closed, frozen analysis-capability registry --
    the SINGLE source of truth both `ProfileCapabilityEntry.__post_init__`
    (construction-time validation, below) and dumpex.commands.profile's
    own collector logic read from, so a typo or a future capability edit
    made in only one place now fails loudly at record-construction time
    instead of silently producing a self-consistent-but-wrong record
    (e.g. a `handle_analysis` entry built with `required_source_groups=
    (("threads",),)` -- internally consistent by every OTHER rule this
    type enforces, but factually wrong for that capability id).

    `required_source_groups` is a tuple of OR-groups (see
    docs/developer/recon_profile_contract.md §4.2): each group is one or more
    alternative source names where at least one must be usable; a
    single-member group is an ordinary hard requirement. `label` is the
    console's own display name (dumpex.commands.profile.
    render_profile_console) -- kept here, not hand-duplicated in the
    renderer, for the same anti-drift reason as everything else in this
    registry."""
    capability_id:            str
    label:                      str
    required_source_groups:      tuple   # tuple[tuple[str, ...], ...]
    optional_sources:              tuple   # tuple[str]

    @property
    def required_sources(self) -> tuple:
        """The flattened, order-preserving, deduplicated union of every
        required group's members -- the same derivation
        ProfileCapabilityEntry.required_sources is validated to equal."""
        return tuple(dict.fromkeys(
            name for group in self.required_source_groups for name in group))


# The closed, frozen analysis-capability registry -- issue #95's own six
# first-release capability ids, in this fixed order. Chosen to match
# dumpex's ACTUAL current collectors/hunters, never a claim invented for
# --profile alone:
#
#   memory_region_analysis      -- dumpex.commands.list_cmd (--list):
#                                   MemoryInfoListStream alone.
#   module_analysis               -- dumpex.commands.modules (--modules):
#                                   ModuleListStream alone.
#   injection_artifact_analysis    -- dumpex.hunt.injection: its own
#                                   evaluation gate is evaluation_sources=
#                                   ("memory_info", "thread_info")
#                                   (dumpex.hunt.injection.report_facts.
#                                   project_coverage_report) -- an
#                                   OR-group, not "both required": the
#                                   hunter still RUNS (and reports real
#                                   PE_HEADER_READ_FAILED/_SHORT_READ
#                                   per-region facts) with EITHER
#                                   MemoryInfoListStream or
#                                   ThreadInfoListStream alone, and even
#                                   with zero captured memory bytes -- a
#                                   missing memory_content is a per-region
#                                   read failure the hunter reports, not a
#                                   reason to refuse to run at all.
#                                   ModuleListStream/ThreadListStream/
#                                   memory_content are therefore optional
#                                   enrichment here, matching the hunter's
#                                   own SourceRequirement-only (never
#                                   evaluation-group) treatment of them.
#   thread_analysis                 -- dumpex.commands.threads (--threads):
#                                   its own evaluation_sources=("threads",
#                                   "thread_info") is likewise an OR-group
#                                   (collect_threads() builds real records
#                                   from ThreadInfoListStream alone when
#                                   ThreadListStream is absent, reporting a
#                                   specific field-level limitation, not
#                                   not_evaluated) -- ModuleListStream
#                                   (start-address classification) is the
#                                   only true optional enrichment.
#   handle_analysis                  -- dumpex.commands.handles (--handles,
#                                   issue #42): HandleDataStream alone.
#   injector_handle_assessment         -- the SAME HandleDataStream evidence
#                                   handle_analysis uses, answering a DIFFERENT
#                                   analytical question (discussion #94's own
#                                   "handle-based assessment of potential
#                                   injector activity") that no dumpex hunter
#                                   implements yet (see #95's own non-goals:
#                                   "no automatic hunter integration ...
#                                   shared hunter consumption is follow-on
#                                   work") -- this capability id exists so a
#                                   dump's EVIDENCE BOUNDARY for that future
#                                   work is already visible today.
#                                   ThreadListStream is optional
#                                   cross-referencing context.
CAPABILITY_REGISTRY = (
    CapabilityDefinition("memory_region_analysis", "Memory-region analysis",
                          (("memory_info",),), ()),
    CapabilityDefinition("module_analysis", "Module analysis",
                          (("modules",),), ()),
    CapabilityDefinition("injection_artifact_analysis", "Injection-artifact analysis",
                          (("memory_info", "thread_info"),),
                          ("modules", "threads", "memory_content")),
    CapabilityDefinition("thread_analysis", "Thread analysis",
                          (("threads", "thread_info"),), ("modules",)),
    CapabilityDefinition("handle_analysis", "Handle analysis",
                          (("handles",),), ()),
    CapabilityDefinition("injector_handle_assessment", "Injector-handle assessment",
                          (("handles",),), ("threads",)),
)

# The frozen, ordered set of capability ids the first release covers --
# ProfileRecord.__post_init__ requires ProfileRecord.capabilities to
# carry EXACTLY these ids, in EXACTLY this order, every time: a closed
# matrix, not an open-ended list a future caller could silently add to or
# reorder. Derived from CAPABILITY_REGISTRY rather than hand-listed a
# second time, so the id set and its order can never drift from the
# registry that also defines each id's own source rules.
CAPABILITY_IDS = tuple(d.capability_id for d in CAPABILITY_REGISTRY)

CAPABILITY_BY_ID = MappingProxyType({d.capability_id: d for d in CAPABILITY_REGISTRY})


class CapabilityLimitationCode(str, Enum):
    REQUIRED_SOURCE_ABSENT = "REQUIRED_SOURCE_ABSENT"   # a source this capability REQUIRES
                                                          # is not present in the dump at all
    REQUIRED_SOURCE_FAILED = "REQUIRED_SOURCE_FAILED"    # a required source is present and
                                                          # dumpex genuinely attempted to parse
                                                          # it, and that attempt raised
    REQUIRED_SOURCE_INDETERMINATE = "REQUIRED_SOURCE_INDETERMINATE"
    # ^ a required source's own stream type has 2+ directory entries
    # (dumpex.output.records.StreamParserState.INDETERMINATE, §2.4 of
    # docs/developer/recon_profile_contract.md) -- open_dump() keeps only ONE
    # mf.<attr>/failure pair per stream TYPE, so whether that surviving
    # state reflects a clean parse or a failure cannot be attributed to
    # any one physical entry. Deliberately NOT REQUIRED_SOURCE_FAILED:
    # that code is a positive claim ("dumpex attempted to parse this and
    # it raised"), which is not always true here -- every duplicate entry
    # may in fact have parsed cleanly. Both still make the capability
    # unavailable (the evidence cannot be trusted either way), but the
    # WORDING must not assert a parse failure that may never have
    # happened.
    OPTIONAL_SOURCE_ABSENT = "OPTIONAL_SOURCE_ABSENT"    # a source that is PURELY optional
                                                          # (never a member of any required
                                                          # OR-group) is absent -- degrades to
                                                          # limited, never erases the required
                                                          # side's own available evidence
    OPTIONAL_SOURCE_FAILED = "OPTIONAL_SOURCE_FAILED"    # same, but present and could not be
                                                          # parsed
    OPTIONAL_SOURCE_INDETERMINATE = "OPTIONAL_SOURCE_INDETERMINATE"
    # ^ REQUIRED_SOURCE_INDETERMINATE's companion for a PURELY optional source.
    REQUIRED_GROUP_MEMBER_ABSENT = "REQUIRED_GROUP_MEMBER_ABSENT"
    # ^ This source IS a member of one of the capability's own required
    # OR-groups (§4.2 of docs/developer/recon_profile_contract.md -- e.g.
    # thread_analysis's ("threads", "thread_info") group), but a
    # DIFFERENT member of that SAME group already satisfies the
    # requirement, so the group as a whole is met and this member's own
    # absence only degrades the result to `limited`. Deliberately NOT
    # OPTIONAL_SOURCE_ABSENT: that code's fixed template says "optional
    # corroborating evidence", which is false for a source the registry
    # genuinely requires (just not THIS specific one, given a sibling
    # covered it) -- publishing "optional" for a required_sources member
    # is the same class of fabricated-detail problem
    # REQUIRED_SOURCE_INDETERMINATE exists to prevent, on a different
    # axis (source-vs-code contradiction rather than parse-outcome
    # wording).
    REQUIRED_GROUP_MEMBER_FAILED = "REQUIRED_GROUP_MEMBER_FAILED"
    # ^ REQUIRED_GROUP_MEMBER_ABSENT's companion: the unsatisfied sibling
    # is present but failed to parse, rather than merely absent.
    REQUIRED_GROUP_MEMBER_INDETERMINATE = "REQUIRED_GROUP_MEMBER_INDETERMINATE"
    # ^ REQUIRED_GROUP_MEMBER_ABSENT's companion: the unsatisfied sibling
    # is ambiguous (§2.4 -- duplicate directory entries), rather than
    # absent or genuinely failed.
    REQUIRED_SOURCE_TRUNCATED = "REQUIRED_SOURCE_TRUNCATED"
    # ^ A required-group member (satisfying its own group -- whether that
    # group has one member or several) is present, unambiguous, and
    # genuinely parsed -- but the underlying stream itself declares MORE
    # items than dumpex actually read (e.g. HandleDataStream's own
    # NumberOfDescriptors exceeding len(handles): issue #86's own
    # MAX_HANDLE_DESCRIPTORS cap, a DataSize too small for every declared
    # descriptor, or the file itself ending early). The group is still
    # satisfied -- real, examinable (if incomplete) data exists, so this
    # contributes to `limited`, never `unavailable` -- but the shortfall
    # must not stay silent (the same "real numbers are kept, but the fact
    # must not be silent" reasoning PROFILE_MEMORY_CONTENT_FALLBACK
    # already applies to a fallback stream, applied here to a single
    # stream's own incomplete parse instead). Distinct from
    # REQUIRED_GROUP_MEMBER_*, which describes an UNSATISFIED sibling --
    # a truncated source is the satisfying one (or the capability's only
    # option), just incompletely so.
    OPTIONAL_SOURCE_TRUNCATED = "OPTIONAL_SOURCE_TRUNCATED"
    # ^ REQUIRED_SOURCE_TRUNCATED's companion for a PURELY optional source.


_CAPABILITY_LIMITATION_CODES = tuple(c.value for c in CapabilityLimitationCode)
_REQUIRED_LIMITATION_CODES = (CapabilityLimitationCode.REQUIRED_SOURCE_ABSENT.value,
                               CapabilityLimitationCode.REQUIRED_SOURCE_FAILED.value,
                               CapabilityLimitationCode.REQUIRED_SOURCE_INDETERMINATE.value)
_OPTIONAL_LIMITATION_CODES = (CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value,
                               CapabilityLimitationCode.OPTIONAL_SOURCE_FAILED.value,
                               CapabilityLimitationCode.OPTIONAL_SOURCE_INDETERMINATE.value)
_REQUIRED_GROUP_MEMBER_LIMITATION_CODES = (
    CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_ABSENT.value,
    CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_FAILED.value,
    CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_INDETERMINATE.value)
_TRUNCATED_LIMITATION_CODES = (CapabilityLimitationCode.REQUIRED_SOURCE_TRUNCATED.value,
                                CapabilityLimitationCode.OPTIONAL_SOURCE_TRUNCATED.value)

# The human-facing minidump stream/source name for every source id the
# capability registry can name -- used ONLY by render_capability_limitation()
# below, never by a record's own `source` field (which always keeps the
# internal key, e.g. "handles", matching the same key CoverageReport.
# sources already uses elsewhere in this codebase).
CAPABILITY_SOURCE_DISPLAY_NAMES = {
    "memory_info":     "MemoryInfoListStream",
    "modules":         "ModuleListStream",
    "threads":         "ThreadListStream",
    "thread_info":     "ThreadInfoListStream",
    "handles":         "HandleDataStream",
    "sysinfo":         "SystemInfoStream",
    "memory_content":  "captured memory content (Memory64ListStream/MemoryListStream)",
}

_CAPABILITY_LIMITATION_TEMPLATES = {
    CapabilityLimitationCode.REQUIRED_SOURCE_ABSENT.value:
        "{name} is not present in this dump",
    CapabilityLimitationCode.REQUIRED_SOURCE_FAILED.value:
        "{name} is present in this dump but could not be parsed",
    CapabilityLimitationCode.REQUIRED_SOURCE_INDETERMINATE.value:
        "{name} has duplicate directory entries; its parse outcome cannot be attributed to "
        "one entry with confidence",
    CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value:
        "{name} is not present in this dump (optional corroborating evidence)",
    CapabilityLimitationCode.OPTIONAL_SOURCE_FAILED.value:
        "{name} is present in this dump but could not be parsed (optional corroborating evidence)",
    CapabilityLimitationCode.OPTIONAL_SOURCE_INDETERMINATE.value:
        "{name} has duplicate directory entries; its parse outcome cannot be attributed to "
        "one entry with confidence (optional corroborating evidence)",
    CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_ABSENT.value:
        "{name} is not present in this dump, but a different required-group member for this "
        "capability already is -- treated as a degraded (not blocking) gap",
    CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_FAILED.value:
        "{name} is present in this dump but could not be parsed, but a different "
        "required-group member for this capability already is usable -- treated as a "
        "degraded (not blocking) gap",
    CapabilityLimitationCode.REQUIRED_GROUP_MEMBER_INDETERMINATE.value:
        "{name} has duplicate directory entries; its parse outcome cannot be attributed to "
        "one entry with confidence, but a different required-group member for this "
        "capability already is usable -- treated as a degraded (not blocking) gap",
    CapabilityLimitationCode.REQUIRED_SOURCE_TRUNCATED.value:
        "{name} is present and was parsed, but declares more items than dumpex actually "
        "read -- the shortfall was not read (and was not silently discarded)",
    CapabilityLimitationCode.OPTIONAL_SOURCE_TRUNCATED.value:
        "{name} is present and was parsed, but declares more items than dumpex actually "
        "read -- the shortfall was not read (and was not silently discarded) (optional "
        "corroborating evidence)",
}


def render_capability_limitation(code: str, source: str) -> str:
    """The ONE place a CapabilityLimitation becomes human text -- mirrors
    dumpex.output.coverage.render_limitation()'s "never composed ad hoc at
    the call site" rule, scoped to this closed, four-code vocabulary."""
    name = CAPABILITY_SOURCE_DISPLAY_NAMES.get(source, source)
    return _CAPABILITY_LIMITATION_TEMPLATES[code].format(name=name)


@dataclass(frozen=True)
class CapabilityLimitation:
    """One reason ONE capability is limited or unavailable -- never a
    command-level dumpex.output.coverage.CoverageLimitation (a different
    axis: this describes an ANALYSIS CAPABILITY's own evidence gap, not
    whether --profile itself completed). `detail` is derived, never
    caller-composed, from (code, source) via render_capability_limitation()
    -- see that function's own docstring."""
    code:   str   # CapabilityLimitationCode
    source: str   # one of the owning ProfileCapabilityEntry's own required_sources/optional_sources

    def __post_init__(self):
        if self.code not in _CAPABILITY_LIMITATION_CODES:
            raise ValueError(
                f"CapabilityLimitation.code must be one of {_CAPABILITY_LIMITATION_CODES}, "
                f"got {self.code!r}")
        if not isinstance(self.source, str) or not self.source:
            raise ValueError(f"CapabilityLimitation.source must be a non-empty string, got {self.source!r}")

    def to_dict(self) -> dict:
        return {"code": self.code, "source": self.source,
                "detail": render_capability_limitation(self.code, self.source)}


@dataclass(frozen=True)
class ProfileCapabilityEntry:
    """One row of the closed analysis-capability matrix.
    `required_source_groups`/`optional_sources` are this capability's OWN
    frozen requirement rule (mirrors the real collector/hunter that
    capability describes -- see docs/developer/recon_profile_contract.md §4.2),
    carried on the record itself so a consumer never has to re-derive
    "why" from the registry module out of band.

    `required_source_groups` is a tuple of OR-**groups**: each group is
    one or more alternative source names where at least one must be
    usable for the capability to be anything but `unavailable` (a
    single-member group is an ordinary hard requirement). This is the
    actual rule §4.3 applies -- NOT flattened away, because a group
    member that goes unsatisfied while a SIBLING in the same group
    satisfies it is a materially different fact from a source that is
    purely optional: publishing the sibling's own gap as
    OPTIONAL_SOURCE_* (this type's own EARLIER shape) asserted "optional
    corroborating evidence" for a source the registry genuinely requires,
    which is exactly the kind of fabricated-detail problem
    REQUIRED_SOURCE_INDETERMINATE already exists to prevent on a
    different axis -- REQUIRED_GROUP_MEMBER_* is the dedicated,
    accurate code for it instead (§6.2).

    `required_sources` is kept alongside as the flattened, deduplicated,
    order-preserving union of every group's members -- for a consumer
    that only wants "which sources matter at all", and validated below
    to always equal exactly that derivation, so the two can never drift.

    `status` and `limitations` are cross-validated against each other and
    against required_source_groups/optional_sources below: a caller
    cannot construct e.g. status="available" while still attaching a
    REQUIRED_SOURCE_ABSENT limitation, status="unavailable" with none at
    all, or an OPTIONAL_SOURCE_* limitation naming a source that is
    actually a required-group member -- the exact "must be technically
    enforced, not caller discipline" rule this whole record family exists
    to satisfy."""
    capability_id:            str
    status:                    str      # CapabilityStatus
    required_source_groups:    tuple    # tuple[tuple[str, ...], ...]
    required_sources:            tuple    # tuple[str] -- flattened required_source_groups
    optional_sources:              tuple    # tuple[str]
    limitations:                    tuple    # tuple[CapabilityLimitation]

    def __post_init__(self):
        if self.capability_id not in CAPABILITY_IDS:
            raise ValueError(
                f"ProfileCapabilityEntry.capability_id must be one of {CAPABILITY_IDS}, "
                f"got {self.capability_id!r}")
        if self.status not in _CAPABILITY_STATUSES:
            raise ValueError(
                f"ProfileCapabilityEntry.status must be one of {_CAPABILITY_STATUSES}, "
                f"got {self.status!r}")

        if not isinstance(self.required_source_groups, tuple) or not self.required_source_groups:
            raise ValueError(
                "ProfileCapabilityEntry.required_source_groups must be a non-empty tuple of "
                f"groups -- a capability with no required evidence at all cannot be "
                f"meaningfully gated, got {self.required_source_groups!r}")
        flattened = []
        for group in self.required_source_groups:
            if not isinstance(group, tuple) or not group or any(
                    not isinstance(v, str) or not v for v in group):
                raise ValueError(
                    "ProfileCapabilityEntry.required_source_groups entries must each be a "
                    f"non-empty tuple of non-empty strings, got {group!r}")
            if len(set(group)) != len(group):
                raise ValueError(
                    f"ProfileCapabilityEntry.required_source_groups entry has duplicate "
                    f"members: {group!r}")
            flattened.extend(group)
        if len(set(flattened)) != len(flattened):
            raise ValueError(
                "ProfileCapabilityEntry.required_source_groups' members must not repeat "
                f"across groups, got {self.required_source_groups!r}")

        if not isinstance(self.optional_sources, tuple) or any(
                not isinstance(v, str) or not v for v in self.optional_sources):
            raise ValueError(
                "ProfileCapabilityEntry.optional_sources must be a tuple of non-empty "
                f"strings, got {self.optional_sources!r}")
        if set(flattened) & set(self.optional_sources):
            raise ValueError(
                "ProfileCapabilityEntry.required_source_groups and optional_sources must "
                f"not overlap, got required members={flattened!r} "
                f"optional_sources={self.optional_sources!r}")

        expected_required_sources = tuple(dict.fromkeys(flattened))
        if self.required_sources != expected_required_sources:
            raise ValueError(
                "ProfileCapabilityEntry.required_sources must equal the flattened, "
                f"order-preserving union of required_source_groups -- expected "
                f"{expected_required_sources!r}, got {self.required_sources!r}")

        # Cross-checked against CAPABILITY_REGISTRY -- the single source
        # of truth this capability_id's own source rule is defined
        # against -- not merely internally self-consistent. Without this,
        # a `handle_analysis` entry built with required_source_groups=
        # (("threads",),) would pass every check above (it is a
        # perfectly well-formed group, disjoint from optional_sources,
        # correctly flattened) while being factually wrong for that
        # capability id -- exactly the "must be technically enforced, not
        # caller discipline" rule this whole record family exists to
        # satisfy, applied to the registry's own frozen mapping, not just
        # this one instance's internal shape.
        definition = CAPABILITY_BY_ID[self.capability_id]
        if self.required_source_groups != definition.required_source_groups:
            raise ValueError(
                f"ProfileCapabilityEntry({self.capability_id!r}).required_source_groups "
                f"must equal the frozen registry's own {definition.required_source_groups!r}, "
                f"got {self.required_source_groups!r}")
        if self.optional_sources != definition.optional_sources:
            raise ValueError(
                f"ProfileCapabilityEntry({self.capability_id!r}).optional_sources must "
                f"equal the frozen registry's own {definition.optional_sources!r}, got "
                f"{self.optional_sources!r}")

        if not isinstance(self.limitations, tuple) or any(
                type(l) is not CapabilityLimitation for l in self.limitations):
            raise TypeError("ProfileCapabilityEntry.limitations must be a tuple of CapabilityLimitation instances")

        required_gaps = tuple(l for l in self.limitations if l.code in _REQUIRED_LIMITATION_CODES)
        group_member_gaps = tuple(l for l in self.limitations
                                    if l.code in _REQUIRED_GROUP_MEMBER_LIMITATION_CODES)
        optional_gaps = tuple(l for l in self.limitations if l.code in _OPTIONAL_LIMITATION_CODES)
        truncated_gaps = tuple(l for l in self.limitations if l.code in _TRUNCATED_LIMITATION_CODES)
        if (len(required_gaps) + len(group_member_gaps) + len(optional_gaps) + len(truncated_gaps)
                != len(self.limitations)):
            raise ValueError(
                "ProfileCapabilityEntry.limitations contains a code outside the closed "
                f"REQUIRED_SOURCE_*/REQUIRED_GROUP_MEMBER_*/OPTIONAL_SOURCE_*/*_TRUNCATED "
                f"vocabulary: {self.limitations!r}")
        required_truncated = tuple(
            l for l in truncated_gaps
            if l.code == CapabilityLimitationCode.REQUIRED_SOURCE_TRUNCATED.value)
        optional_truncated = tuple(
            l for l in truncated_gaps
            if l.code == CapabilityLimitationCode.OPTIONAL_SOURCE_TRUNCATED.value)

        # No source may carry more than one limitation -- two limitations
        # for the same source would be either a duplicate (redundant) or
        # a contradiction (e.g. REQUIRED_SOURCE_ABSENT and
        # OPTIONAL_SOURCE_ABSENT both naming "threads"), neither of which
        # a well-formed record can represent.
        limitation_sources = [l.source for l in self.limitations]
        if len(set(limitation_sources)) != len(limitation_sources):
            raise ValueError(
                "ProfileCapabilityEntry.limitations names the same source more than once: "
                f"{limitation_sources!r}")

        # Each code family is matched to exactly the sources it is
        # allowed to describe -- REQUIRED_SOURCE_*/REQUIRED_GROUP_MEMBER_*/
        # REQUIRED_SOURCE_TRUNCATED only for a member of one of this
        # capability's own required groups (all three describe a
        # required-group member; which one is chosen is a fact about
        # ABSENT/FAILED/INDETERMINATE vs. an unsatisfied sibling vs. an
        # incomplete parse, not about which set the source lives in),
        # OPTIONAL_SOURCE_*/OPTIONAL_SOURCE_TRUNCATED only for a source
        # that is PURELY optional -- never for a required-group member,
        # which is exactly the "optional corroborating evidence"
        # fabrication this type's own docstring describes.
        required_set = set(flattened)
        for l in required_gaps + group_member_gaps + required_truncated:
            if l.source not in required_set:
                raise ValueError(
                    f"ProfileCapabilityEntry: a {l.code!r} limitation's source {l.source!r} "
                    f"must be a member of one of this capability's own "
                    f"required_source_groups {self.required_source_groups!r}")
        for l in optional_gaps + optional_truncated:
            if l.source not in self.optional_sources:
                raise ValueError(
                    f"ProfileCapabilityEntry: an OPTIONAL_SOURCE_*/OPTIONAL_SOURCE_TRUNCATED "
                    f"limitation's source {l.source!r} must be one of this capability's own "
                    f"optional_sources {self.optional_sources!r} -- a required-group member's "
                    f"own gap must use REQUIRED_SOURCE_*/REQUIRED_GROUP_MEMBER_*/"
                    f"REQUIRED_SOURCE_TRUNCATED instead, never OPTIONAL_SOURCE_*")

        # REQUIRED_GROUP_MEMBER_* asserts "a DIFFERENT member of this
        # SAME group already satisfies it" -- meaningless (and therefore
        # forbidden) for a single-member group, which has no sibling to
        # make that claim about.
        group_by_member = {name: group for group in self.required_source_groups for name in group}
        for l in group_member_gaps:
            group = group_by_member[l.source]
            if len(group) == 1:
                raise ValueError(
                    f"ProfileCapabilityEntry: a REQUIRED_GROUP_MEMBER_* limitation's source "
                    f"{l.source!r} belongs to the single-member group {group!r}, which has no "
                    f"sibling to have satisfied it -- use REQUIRED_SOURCE_* instead")

        # Every required group is either FULLY blocked (every one of its
        # members carries a required_gap) or FULLY unblocked (none of
        # them do) -- a group with only SOME members blocked would be an
        # incomplete/inconsistent construction (the collector's own
        # algorithm always resolves a failed group's every member at
        # once; nothing may reach this type any other way).
        required_gap_sources = {l.source for l in required_gaps}
        for group in self.required_source_groups:
            blocked_count = sum(1 for name in group if name in required_gap_sources)
            if blocked_count not in (0, len(group)):
                raise ValueError(
                    f"ProfileCapabilityEntry: required group {group!r} has only "
                    f"{blocked_count}/{len(group)} member(s) carrying a REQUIRED_SOURCE_* "
                    f"limitation -- a group must be either fully blocked or fully unblocked, "
                    f"never partially")

        if self.status == CapabilityStatus.UNAVAILABLE.value:
            if not required_gaps:
                raise ValueError(
                    "ProfileCapabilityEntry.status is 'unavailable' but carries no "
                    "REQUIRED_SOURCE_* limitation explaining why")
            if not any(all(name in required_gap_sources for name in group)
                       for group in self.required_source_groups):
                raise ValueError(
                    "ProfileCapabilityEntry.status is 'unavailable' but no required group is "
                    "fully blocked -- §4.3 makes a capability unavailable only when at least "
                    "one whole required OR-group has no usable member")
        elif self.status == CapabilityStatus.LIMITED.value:
            if required_gaps:
                raise ValueError(
                    "ProfileCapabilityEntry.status is 'limited' but carries a "
                    "REQUIRED_SOURCE_* limitation -- missing required evidence must be "
                    "'unavailable', never 'limited'")
            if not (group_member_gaps or optional_gaps or truncated_gaps):
                raise ValueError(
                    "ProfileCapabilityEntry.status is 'limited' but carries no "
                    "REQUIRED_GROUP_MEMBER_*/OPTIONAL_SOURCE_*/*_TRUNCATED limitation "
                    "explaining why")
        else:   # available
            if self.limitations:
                raise ValueError(
                    "ProfileCapabilityEntry.status is 'available' but carries limitations -- "
                    "'available' means no evidence gap at all")

    def to_dict(self) -> dict:
        return {
            "capability_id":            self.capability_id,
            "status":                   self.status,
            "required_source_groups":   [list(group) for group in self.required_source_groups],
            "required_sources":         list(self.required_sources),
            "optional_sources":         list(self.optional_sources),
            "limitations":              [l.to_dict() for l in self.limitations],
        }

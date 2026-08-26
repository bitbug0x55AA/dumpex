"""Structured findings and verdict presentation for hunt analyzers.

A Finding separates facts, inference, confidence, rationale, limitations,
provenance, and console-only verbose detail. Construction normalizes immutable
fields and derives deterministic identifiers and severity. Verdict helpers keep
detection status separate from coverage completeness.
"""
import enum
import hashlib
import json
from dataclasses import dataclass, field
from dumpex.core.mitre import is_valid_technique_id
from dumpex.ui.colors import RED, YELLOW, DIM, BOLD
from dumpex.hunt._console import resolve_width, wrap_text


class DetailLevel(enum.Enum):
    """How much of a Finding's evidence to render on console/--txt --
    replaces the old `verbose: bool` + `facts_mode: "full"/"notice"/
    "omit"` combination Finding.print() used to take. Two states because
    there are only two things a caller of print() ever needs: the
    console's own default view, or the --verbose expansion -- see
    Finding.print()'s own docstring for exactly what each level shows."""
    NORMAL  = "normal"
    VERBOSE = "verbose"

CONFIDENCE_LOW    = "low"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_HIGH   = "high"

# Tags describing what role a finding plays, independent of confidence —
# used by hunt modules to decide what may drive a score/verdict.
TAG_OBSERVATION = "observation"   # raw signal, informational only, never
                                   # scored on its own (entropy/base64/gzip,
                                   # bare string matches)
TAG_LEAD        = "lead"          # suggestive but unverified — worth an
                                   # analyst's attention, not proof
TAG_DETECTION   = "detection"     # structurally corroborated evidence

_TAGS        = (TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION)
_CONFIDENCES = (CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH)

_CONFIDENCE_COLOR = {CONFIDENCE_LOW: DIM, CONFIDENCE_MEDIUM: YELLOW, CONFIDENCE_HIGH: RED}
_CONFIDENCE_ORDER = {CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_HIGH: 2}

# SIEM-facing severity — a fifth, coarser axis alongside tag/confidence,
# derived (never independently chosen by a hunter) from the two so it can
# never drift from what tag/confidence already say about a finding.
SEVERITY_INFO     = "info"
SEVERITY_LOW      = "low"
SEVERITY_MEDIUM   = "medium"
SEVERITY_HIGH     = "high"
SEVERITY_CRITICAL = "critical"

# TAG_OBSERVATION is always "info" regardless of confidence — same rule
# review_priority()/overall_confidence() already apply: an unscored raw
# signal (entropy, a bare string match) never gets alarming severity text
# just because it happened to be read with high confidence in what it IS
# (e.g. "high confidence this is valid Base64") — confidence there
# describes the OBSERVATION, not the maliciousness. TAG_LEAD tops out at
# "medium" even at CONFIDENCE_HIGH, mirroring review_priority()'s own
# ceiling for unscored leads (PRIORITY_MEDIUM, never PRIORITY_HIGH) — a
# lead is "worth an analyst's attention", not yet proof, no matter how
# confidently it was read. Only TAG_DETECTION (the tag that actually moves
# a hunter's score) can reach "critical", and only at CONFIDENCE_HIGH.
_SEVERITY_BY_TAG_CONFIDENCE = {
    (TAG_OBSERVATION, CONFIDENCE_LOW):    SEVERITY_INFO,
    (TAG_OBSERVATION, CONFIDENCE_MEDIUM): SEVERITY_INFO,
    (TAG_OBSERVATION, CONFIDENCE_HIGH):   SEVERITY_INFO,
    (TAG_LEAD, CONFIDENCE_LOW):           SEVERITY_LOW,
    (TAG_LEAD, CONFIDENCE_MEDIUM):        SEVERITY_MEDIUM,
    (TAG_LEAD, CONFIDENCE_HIGH):          SEVERITY_MEDIUM,
    (TAG_DETECTION, CONFIDENCE_LOW):      SEVERITY_MEDIUM,
    (TAG_DETECTION, CONFIDENCE_MEDIUM):   SEVERITY_HIGH,
    (TAG_DETECTION, CONFIDENCE_HIGH):     SEVERITY_CRITICAL,
}


def severity_for(tag: str, confidence: str) -> str:
    """The single reducer from (tag, confidence) to a SIEM-facing severity
    — see _SEVERITY_BY_TAG_CONFIDENCE's own comment for the mapping
    rationale. Falls back to SEVERITY_INFO for an unrecognized (tag,
    confidence) pair rather than raising, matching this module's existing
    precedent (confidence_at_least()/_CONFIDENCE_ORDER.get() already
    default rather than raise) -- this matters only for a caller outside
    Finding itself: Finding.__post_init__ validates tag/confidence
    against _TAGS/_CONFIDENCES BEFORE ever calling this, specifically so
    a typo'd tag/confidence fails loudly at construction time instead of
    silently producing a "info"-severity Finding that may then fail
    schema validation on tag/confidence anyway."""
    return _SEVERITY_BY_TAG_CONFIDENCE.get((tag, confidence), SEVERITY_INFO)


def _require_str_list(value, field_name: str) -> None:
    # Accepts list OR tuple (never bare str/bytes -- neither isinstance
    # check below matches those) -- Finding.__post_init__ normalizes
    # every list-typed field to a tuple (see Finding's own docstring), so
    # a validator that only accepted `list` would reject the round-trip
    # dataclasses.replace(some_finding, ...) relies on: that helper
    # reconstructs a Finding by re-passing the CURRENT (already-tuple)
    # field values back through this same __init__/__post_init__.
    if not isinstance(value, (list, tuple)) or any(not isinstance(v, str) or not v for v in value):
        raise ValueError(f"{field_name} must be a list of non-empty strings, got {value!r}")


def _require_list_of_str(value, field_name: str) -> None:
    # Permissive on emptiness (unlike _require_str_list above) -- matches
    # the v2.5 schema's own facts/limitations items, which allow "" (an
    # empty fact string is odd but not itself a shape violation the wire
    # contract rejects; tightening that is a separate, schema-level
    # decision, not one this constructor should make unilaterally). Same
    # list-or-tuple acceptance as _require_str_list above, for the same
    # dataclasses.replace() round-trip reason.
    if not isinstance(value, (list, tuple)) or any(not isinstance(v, str) for v in value):
        raise ValueError(f"{field_name} must be a list of strings, got {value!r}")


def _require_technique_ids(value, field_name: str) -> None:
    _require_str_list(value, field_name)
    if len(set(value)) != len(value):
        raise ValueError(f"{field_name} must not contain duplicates, got {value!r}")
    bad = [t for t in value if not is_valid_technique_id(t)]
    if bad:
        raise ValueError(
            f"{field_name} entries must match MITRE ATT&CK technique/sub-technique id shape "
            f"(e.g. \"T1055\", \"T1559.001\"), got invalid: {bad!r}")


def _require_nonempty_str(value, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string, got {value!r}")


def _require_optional_nonempty_str(value, field_name: str) -> None:
    if value is not None and (not isinstance(value, str) or not value):
        raise ValueError(f"{field_name} must be None or a non-empty string, got {value!r}")


@dataclass(frozen=True)
class Finding:
    """Immutable structured finding.

    Sequence fields are copied to tuples so frozen construction also prevents
    in-place mutation. Wire fields are converted back to lists by to_dict;
    verbose_facts is console-only and is excluded from equality and the id.

    The deterministic id hashes material alert fields using canonical JSON.
    Set-like fields are sorted, while fact order is preserved. It is stable for
    identical content but not globally unique across evidence; cross-case
    consumers must combine it with the evidence hash.

    Severity is derived from tag and confidence. Technique ids, evidence
    references, and IOCs are explicit rather than parsed from prose. A rule
    version is used only when supplied by a real versioned source.
    """
    # facts/limitations/technique_ids/evidence_refs/iocs: accept list OR
    # tuple on construction (see _require_str_list/_require_list_of_str's
    # own comments -- this is what lets dataclasses.replace(some_finding,
    # ...) round-trip); __post_init__ always normalizes whichever was
    # passed to a tuple, and that's what a constructed instance actually
    # holds -- see this class's own docstring on why (frozen + immutable
    # storage, not just a frozen top-level attribute).
    check:       str            # short check identifier, e.g. "injection.allocation_correlation"
    facts:       list           # list[str] (tuple[str] once constructed) — objective observations
    inference:   str            # what this suggests
    confidence:  str            # CONFIDENCE_LOW / CONFIDENCE_MEDIUM / CONFIDENCE_HIGH
    rationale:   str            # why this confidence level, specifically
    limitations: list = field(default_factory=list)   # list[str] (tuple[str] once constructed)
    tag:         str  = TAG_OBSERVATION                # TAG_OBSERVATION / TAG_LEAD / TAG_DETECTION
    technique_ids:  list = field(default_factory=list)   # list[str] (tuple[str] once constructed)
    evidence_refs:  list = field(default_factory=list)   # list[str] (tuple[str] once constructed)
    iocs:           list = field(default_factory=list)   # list[str] (tuple[str] once constructed)
    rule_id:        "str | None" = None   # defaults to `check` in __post_init__ if not given
    rule_version:   "str | None" = None   # None unless a real versioned rule source set it
    # compare=False: verbose_facts is deliberately excluded from `id`'s
    # hash basis (see this class's own docstring) precisely because it
    # never carries information facts/inference don't already assert at a
    # coarser grain -- two Findings differing ONLY in verbose_facts are
    # the same finding for every purpose except console rendering, so
    # __eq__/__hash__ (like `id`) must not treat them as different.
    verbose_facts:  list = field(default_factory=list, compare=False)
                                                           # list[str] (tuple[str] once constructed)
                                                           # -- console/--txt --verbose only, see docstring
    id:             "str | None" = field(init=False, default=None)         # always computed
    severity:       "str | None" = field(init=False, default=None)         # always computed

    def __post_init__(self):
        _require_nonempty_str(self.check, "Finding.check")
        if self.tag not in _TAGS:
            raise ValueError(f"Finding.tag must be one of {_TAGS}, got {self.tag!r}")
        if self.confidence not in _CONFIDENCES:
            raise ValueError(
                f"Finding.confidence must be one of {_CONFIDENCES}, got {self.confidence!r}")
        _require_nonempty_str(self.inference, "Finding.inference")
        _require_nonempty_str(self.rationale, "Finding.rationale")
        _require_list_of_str(self.facts, "Finding.facts")
        _require_list_of_str(self.limitations, "Finding.limitations")
        _require_str_list(self.verbose_facts, "Finding.verbose_facts")
        _require_optional_nonempty_str(self.rule_id, "Finding.rule_id")
        _require_optional_nonempty_str(self.rule_version, "Finding.rule_version")
        rule_id = self.rule_id if self.rule_id is not None else self.check
        _require_technique_ids(self.technique_ids, "Finding.technique_ids")
        _require_str_list(self.evidence_refs, "Finding.evidence_refs")
        _require_str_list(self.iocs, "Finding.iocs")

        # object.__setattr__ -- the documented way to assign inside a
        # frozen dataclass's own __post_init__ (plain `self.x = ...`
        # would raise FrozenInstanceError just like it would anywhere
        # else on this instance). Every list-typed field is normalized to
        # a tuple here -- both a defensive copy of the caller's own list
        # (so mutating it after construction can't reach back into this
        # instance) and, since tuples are themselves immutable, a second
        # barrier against in-place mutation independent of frozen=True --
        # see this class's own docstring.
        object.__setattr__(self, "rule_id", rule_id)
        object.__setattr__(self, "facts", tuple(self.facts))
        object.__setattr__(self, "limitations", tuple(self.limitations))
        object.__setattr__(self, "technique_ids", tuple(self.technique_ids))
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        object.__setattr__(self, "iocs", tuple(self.iocs))
        object.__setattr__(self, "verbose_facts", tuple(self.verbose_facts))

        # Always derived -- see this class's own docstring for why
        # neither of these may be set by a caller.
        object.__setattr__(self, "severity", severity_for(self.tag, self.confidence))
        # technique_ids/evidence_refs/iocs are sorted before hashing --
        # their own order carries no meaning (technique_ids is already
        # required unique above); facts is deliberately NOT sorted, see
        # this class's own docstring on `id`.
        basis = json.dumps({
            "check":          self.check,
            "rule_id":        self.rule_id,
            "rule_version":   self.rule_version,
            "tag":            self.tag,
            "confidence":     self.confidence,
            "technique_ids":  sorted(self.technique_ids),
            "evidence_refs":  sorted(self.evidence_refs),
            "iocs":           sorted(self.iocs),
            "facts":          list(self.facts),
        }, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        object.__setattr__(
            self, "id", "finding-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32])

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "check":         self.check,
            "tag":           self.tag,
            "severity":      self.severity,
            "confidence":    self.confidence,
            "facts":         list(self.facts),
            "inference":     self.inference,
            "rationale":     self.rationale,
            "limitations":   list(self.limitations),
            "technique_ids": list(self.technique_ids),
            "evidence_refs": list(self.evidence_refs),
            "iocs":          list(self.iocs),
            "rule_id":       self.rule_id,
            "rule_version":  self.rule_version,
        }

    def print(self, indent: int = 2, level: "DetailLevel" = DetailLevel.NORMAL,
              width: "int | None" = None, title: "str | None" = None):
        """Render this finding for console output.

        Normal mode reports evidence availability without deriving a count from a
        possibly capped facts list. Verbose mode prints verbose_facts when
        present, otherwise facts, but never both. Rendering does not change the
        finding or its structured representation.

        Width controls deterministic wrapping. An optional title adds a readable
        heading while retaining the stable check id.
        """
        for line in render_finding_lines(self, level=level, indent=indent,
                                          width=width, title=title):
            print(line)


def _wrap_labeled(prefix: str, text: str, width: int) -> list:
    """`prefix` (e.g. "  Inference   : ") is prepended to the first
    wrapped line; every continuation line is indented to align under
    wherever the text after `prefix` started, via `wrap_text`'s own
    `hang_indent`. Returns at least one line (the bare prefix) even for
    empty `text`, so a caller can always join the result onto the
    previous line's prefix unconditionally."""
    hang = len(prefix)
    wrapped = wrap_text(text, width, hang_indent=hang)
    if not wrapped:
        return [prefix.rstrip()]
    first, rest = wrapped[0], wrapped[1:]
    return [prefix + first, *rest]


def render_finding_lines(finding: "Finding", *, level: "DetailLevel",
                          indent: int = 2, width: "int | None" = None,
                          title: "str | None" = None) -> list:
    """Pure function: `finding` -> the exact list of lines
    `Finding.print()` prints (one list element per line, no trailing
    newline characters) -- the ONE place that layout is decided, so
    Finding.print() itself is just `for line in render_finding_lines(...):
    print(line)`. See `Finding.print()`'s own docstring for the
    level/width/title contract this implements."""
    if not isinstance(level, DetailLevel):
        raise TypeError(f"Finding.print: level must be a DetailLevel, got {type(level).__name__}")
    w = resolve_width(width)
    pad = " " * indent
    color = _CONFIDENCE_COLOR.get(finding.confidence, DIM)
    tag_str = {"observation": "OBSERVATION", "lead": "LEAD", "detection": "DETECTION"}.get(
        finding.tag, finding.tag.upper())

    lines = []
    if title:
        lines.append(f"{pad}{BOLD(title)}  [{color(finding.confidence.upper())}]  "
                      f"{DIM(tag_str)}  {DIM('(' + finding.check + ')')}")
    else:
        lines.append(f"{pad}{BOLD(finding.check)}  [{color(finding.confidence.upper())}]  "
                      f"{DIM(tag_str)}")

    lines.extend(_wrap_labeled(f"{pad}  Inference   : ", finding.inference, w))
    lines.extend(_wrap_labeled(f"{pad}  Confidence  : ",
                                f"{finding.confidence}  —  {finding.rationale}", w))

    evidence = finding.verbose_facts or finding.facts
    if evidence:
        if level is DetailLevel.VERBOSE:
            lines.append(f"{pad}  Facts:")
            for item in evidence:
                lines.extend(_wrap_labeled(f"{pad}    - ", item, w))
        else:
            lines.append(f"{pad}  Facts: available — use --verbose to list")
    if finding.limitations:
        lines.append(f"{pad}  Limitations:")
        for l in finding.limitations:
            lines.extend(_wrap_labeled(f"{pad}    - ", l, w))
    lines.append("")
    return lines


def confidence_at_least(confidence: str, minimum: str) -> bool:
    """True if `confidence` is at or above `minimum` on the LOW<MEDIUM<HIGH order."""
    return _CONFIDENCE_ORDER.get(confidence, -1) >= _CONFIDENCE_ORDER.get(minimum, 99)


CONFIDENCE_NONE = "none"


def overall_confidence(findings: list, score: int) -> str:
    """
    Reduce a hunter's list of Finding objects (plus its own score) to a
    single top-level confidence for JSON summary consumers —
    "none"/"low"/"medium"/"high" — WITHOUT inflating it from the score
    alone (a prior pattern, `score >= max_score - 1`, silently turned a
    single medium-confidence structural lead into a "HIGH CONFIDENCE" structured-output
    row for several hunters).

    score == 0            -> "none": nothing scored, regardless of what
                              leads/observations were reported alongside.
    score  > 0             -> the highest confidence among this hunter's
                              own tag=TAG_DETECTION findings, since those
                              are what actually justified the nonzero
                              score. If a hunter incremented its score
                              without attaching a corresponding
                              TAG_DETECTION Finding (a hunter-side bug),
                              this deliberately falls back to "low" rather
                              than guessing "high" — silently overstating
                              confidence is the worse failure mode.
    """
    if score <= 0:
        return CONFIDENCE_NONE
    detections = [f for f in findings if f.tag == TAG_DETECTION]
    if not detections:
        return CONFIDENCE_LOW
    return max((f.confidence for f in detections), key=lambda c: _CONFIDENCE_ORDER.get(c, -1))


VERDICT_CLEAN         = "clean"
VERDICT_POSSIBLE      = "possible"
VERDICT_LIKELY        = "likely"
VERDICT_HIGH          = "high"
VERDICT_INCONCLUSIVE  = "inconclusive"
VERDICT_NOT_EVALUATED = "not_evaluated"

# Statuses (from hunt/_ui.py) that must NOT collapse into "clean" just
# because score <= 0 — "clean" specifically means "looked, complete
# coverage, found nothing", which is a different claim than "didn't look"
# or "looked but coverage was incomplete". Kept as string literals here
# (rather than importing hunt/_ui.py) to avoid a dependency cycle —
# hunt/_ui.py is a leaf print-helper module, but the two constants below
# are exactly the NOT_EVALUATED/INCONCLUSIVE values it defines.
_STATUS_NOT_EVALUATED = "NOT_EVALUATED"
_STATUS_INCONCLUSIVE  = "INCONCLUSIVE"


def verdict_level(score: int, level_by_score: dict, status: str = None) -> str:
    """
    Map a hunter's integer score (and its top-level scan status) to
    "clean"/"possible"/"likely"/"high"/"inconclusive"/"not_evaluated"
    using an EXPLICIT, hunter-supplied {score: level} table — never
    derived generically from score/max_score arithmetic. Different
    hunters have different max scores and different evidentiary weight
    per point (stomping's max is 2, injection's is 3; a stomping "2" and
    an injection "2" do not mean the same thing), so a single formula
    like `score >= max_score - 1` cannot represent both correctly at
    once — it previously produced console/structured-output verdict text that
    disagreed with each other for the same finding.

    Each hunter owns its own table and is the single source of truth for
    its own verdict_level; structured.py and hunt/__init__.py must read
    this field directly (`findings["verdict_level"].upper()`) rather than
    re-deriving it from score or confidence.

    `status` should be the hunter's own findings["status"] (DETECTED /
    NOT_DETECTED_IN_SCANNED_SCOPE / INCONCLUSIVE / NOT_EVALUATED). When
    it's NOT_EVALUATED or INCONCLUSIVE, that takes priority over the
    score <= 0 -> "clean" default: a hunter that never ran, or that ran
    over incomplete coverage, has not earned "clean" — printing "clean"
    there previously told an analyst a scope was verified benign when it
    was actually never (or only partly) checked. `status` is optional and
    defaults to None for callers that haven't been updated yet, in which
    case behavior is unchanged (score <= 0 -> "clean").

    Otherwise: score <= 0 maps to "clean"; score > 0 looks up the table.
    """
    if status == _STATUS_NOT_EVALUATED:
        return VERDICT_NOT_EVALUATED
    if status == _STATUS_INCONCLUSIVE:
        return VERDICT_INCONCLUSIVE
    if score <= 0:
        return VERDICT_CLEAN
    return level_by_score.get(score, VERDICT_POSSIBLE)


PRIORITY_NONE   = "none"
PRIORITY_LOW    = "low"
PRIORITY_MEDIUM = "medium"
PRIORITY_HIGH   = "high"


def lead_count(findings: list) -> int:
    """
    Count of tag=TAG_LEAD findings in a hunter's own findings_list —
    leads worth an analyst's attention that did NOT contribute to score.
    Deliberately excludes TAG_OBSERVATION (background signal, never
    actionable on its own) and TAG_DETECTION (already reflected in
    score/status, not a separate "unscored" item).
    """
    return sum(1 for f in findings if f.tag == TAG_LEAD)


def review_priority(findings: list, score: int, status: str = None) -> str:
    """
    Reduce a hunter's findings_list (+ score/status) to a single
    "none"/"low"/"medium"/"high" triage label for JSON/console summary
    consumers — independent of the verdict TEXT (which already encodes
    score/status), so a score==0 hunter that nonetheless surfaced real
    leads doesn't silently read as "nothing to do here" in a summary table.

      status == NOT_EVALUATED                     -> "none": never ran,
                                                      nothing to review.
      score > 0 (a TAG_DETECTION contributed)      -> "high": already
                                                      actionable.
      any TAG_LEAD with confidence >= MEDIUM       -> "medium": a
                                                      corroborated-enough
                                                      lead worth a closer
                                                      look even though it
                                                      didn't score (e.g.
                                                      stomping's RIP-in-
                                                      anomalous-section lead,
                                                      encoding's shellcode-
                                                      bootstrap-in-RWX lead).
      any TAG_LEAD (low confidence) or
      any TAG_OBSERVATION                          -> "low": background
                                                      signal, low urgency.
      nothing at all                               -> "none".
    """
    if status == _STATUS_NOT_EVALUATED:
        return PRIORITY_NONE
    if score > 0:
        return PRIORITY_HIGH
    leads = [f for f in findings if f.tag == TAG_LEAD]
    if any(confidence_at_least(f.confidence, CONFIDENCE_MEDIUM) for f in leads):
        return PRIORITY_MEDIUM
    if leads or any(f.tag == TAG_OBSERVATION for f in findings):
        return PRIORITY_LOW
    return PRIORITY_NONE


def leads_suffix(findings: list) -> str:
    """
    "" if no TAG_LEAD findings are present, else a short suffix to append
    to a hunter's own CLEAN/INCONCLUSIVE verdict reason text — so the ONE
    line an analyst may only glance at (or grep for) never implies
    "nothing here" when unscored leads actually were found just above it.
    Deliberately keyed only on TAG_LEAD, not TAG_OBSERVATION — background
    signal like bare entropy/Base64 presence is not something the verdict
    line itself needs to call out.
    """
    n = lead_count(findings)
    if not n:
        return ""
    return f" — {n} lead(s) found above (unscored, see findings/--verbose)"

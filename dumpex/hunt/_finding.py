"""
Shared finding schema for hunt modules (phase-two detection logic).

Every finding a hunt module reports carries five things, kept
deliberately separate so a consumer (analyst or downstream tooling) can
tell "what was observed" apart from "what we think it means":

  facts        — objective, directly-observed data: addresses, sizes,
                 hashes, protection flags, register values. No judgment
                 calls belong here.
  inference    — the human-readable claim this finding supports (e.g.
                 "thread's current RIP executes inside an allocation that
                 also carries a structurally-valid hidden PE header").
  confidence   — "low" | "medium" | "high" — how much weight the
                 inference should get. Independent of how alarming the
                 wording sounds.
  rationale    — WHY this confidence level and not another: what
                 corroborates it, or what's missing that would raise it.
  limitations  — known gaps/caveats: coverage limits, assumptions, or
                 conditions that would invalidate the inference.

Design intent (phase two): raw signals that are cheap to fake or that
occur naturally in benign memory (Shannon entropy, a Base64-looking run,
a GZIP magic byte, a bare "\\pipe\\" string) must never by themselves
produce a "malicious" verdict. They are reported as `tag="observation"`,
confidence LOW, and hunt modules must gate their scored/verdict logic on
confidence, not on presence. Only structurally corroborated findings
(matching PE headers, live register state, handle objects, cross-checked
page/section metadata) reach MEDIUM/HIGH and move a verdict.
"""
import hashlib
import json
from dataclasses import dataclass, field
from dumpex.core.mitre import is_valid_technique_id
from dumpex.ui.colors import RED, YELLOW, DIM, BOLD

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
    """Frozen (immutable) value object -- a review found that even with
    id/severity marked init=False, a plain mutable dataclass still let a
    caller mutate `tag`/`confidence`/etc. AFTER construction (invalidating
    the already-derived id/severity without either being recomputed), or
    mutate a `facts`/`limitations`/`technique_ids`/`evidence_refs`/`iocs`
    list in place after passing it in (since a dataclass field only holds
    a reference to the caller's own list, not a copy) -- either one lets
    `to_dict()` later emit a shape that no longer matches its own id/
    severity, or that no longer validates against the schema at all.
    frozen=True raises dataclasses.FrozenInstanceError on any attribute
    assignment after __init__ returns (`__post_init__` itself uses
    object.__setattr__ to set derived fields, the documented way to
    assign inside a frozen dataclass's own __post_init__). The five
    list-typed fields are additionally normalized to tuples in
    __post_init__ -- both a defensive copy (mutating the caller's
    original list after construction can no longer affect this instance)
    and, since tuples are themselves immutable, a second, independent
    barrier against exactly the in-place-mutation gap frozen=True alone
    does not close. `to_dict()` converts them back to `list` for JSON.

    See this module's own top-of-file docstring for facts/inference/
    confidence/rationale/limitations. The seven fields below extend the
    same judgment with a normalized-SIEM-alert shape (id/severity for
    triage and dedup, technique_ids/evidence_refs/iocs/rule_id/
    rule_version for correlation and provenance):

      id            — NOT settable by a caller (init=False): always
                       computed in __post_init__ from an unambiguous JSON
                       encoding of EVERY field that makes one Finding a
                       materially different alert from another --
                       check, rule_id, rule_version, tag, confidence,
                       technique_ids, evidence_refs, iocs, and facts --
                       encoded as a sort_keys=True JSON object (never a
                       "|".join() of raw strings, which lets two
                       DIFFERENT fact lists collide onto the same joined
                       text -- e.g. facts=["a|b"] vs facts=["a","b"]),
                       truncated to 128 bits (32 hex chars) of SHA-256.
                       technique_ids/evidence_refs/iocs are sorted before
                       hashing (their own order carries no meaning, and
                       two calls that build the same set in a different
                       order must still produce the same id); facts is
                       NOT sorted (its order is meaningful/deterministic
                       per hunter). Including rule_version and tag is
                       deliberate: a rules.yaml update that changes what a
                       check detects, or a hunter that later upgrades the
                       same underlying evidence from a lead to a
                       detection, must NOT collide onto the id of the
                       stale finding it superseded -- an id collision
                       there would make a SIEM silently dedup away a
                       materially different alert.
                       This id has 128-bit (SHA-256-derived) collision
                       resistance for genuinely different content, not an
                       absolute "never collides" guarantee -- collisions
                       are only expected between two Findings whose
                       hashed fields are byte-for-byte identical.
                       Stable across repeated `--hunt` runs against the
                       SAME evidence, so it is safe to use as a re-scan
                       idempotency/dedup key for THAT dump. It is NOT a
                       globally unique cross-dump/cross-host identifier:
                       two structurally identical findings from two
                       different dumps (same check, same facts -- e.g.
                       the same malware family hitting the same address
                       on two different hosts) intentionally produce the
                       SAME id, because id is a pure function of the
                       finding's own content, not of which evidence it
                       came from. A consumer that needs a globally unique
                       key (e.g. a SIEM correlating across cases) MUST
                       combine this id with the evidence identity already
                       present in the same document (`meta.evidence[].
                       sha256`) -- e.g. `sha256(evidence_sha256 + ":" +
                       finding.id)` -- rather than treating `id` alone as
                       globally unique.
      technique_ids — list[str] of MITRE ATT&CK technique/sub-technique
                       IDs (e.g. "T1055", "T1559.001" -- validated against
                       that shape, deduplicated). Empty unless the hunter
                       that built this Finding actually has a real
                       mapping to attach (e.g. dumpex.hunt.pipe's own
                       rules.yaml framework_pipes entries, which already
                       carry a `mitre` field) — never invented per check.
      severity      — NOT settable by a caller (init=False): always
                       computed from (tag, confidence) via severity_for()
                       — see that function. A caller cannot construct a
                       Finding whose severity contradicts its own tag/
                       confidence (previously this field silently
                       accepted any recognized severity string regardless
                       of tag/confidence, letting e.g. tag="observation"
                       carry severity="critical").
      evidence_refs — list[str] of structured pointers (e.g.
                       "region:0x...", "tid:1234") a consumer can use to
                       cross-reference this finding against the hunter's
                       own `details` object, distinct from `facts`
                       (free-text) and `iocs` (indicator values).
      iocs          — list[str] of indicator-of-compromise values this
                       finding's facts embed (an IP, a beacon pipe name,
                       a hash) — empty unless the hunter explicitly
                       extracted one; never parsed back out of `facts`
                       here, to avoid silently mis-extracting a false
                       positive from free text.
      rule_id       — defaults to `check` when not given: in this
                       codebase `check` already IS the stable detection-
                       logic identifier (e.g.
                       "hollowing.mem_private_at_image_base") every other
                       reducer in this module keys off of, so this is a
                       real value, not a placeholder.
      rule_version  — None unless a real versioned rule source produced
                       this finding. Where a rule DOES come from
                       rules.yaml (e.g. pipe's framework_pipes matches),
                       this must be the loaded ruleset's own CONTENT hash
                       (dumpex.rules_pkg.loader.get_rules_source_info()
                       ["sha256"]), never rules.yaml's own top-level
                       `version:` field -- that field is an explicit
                       FORMAT/schema version ("bump when schema changes",
                       per rules.yaml's own comment), not a content
                       version: editing a pipe pattern or a MITRE mapping
                       does not change it, so using it here would silently
                       report the same rule_version for materially
                       different detection content. Deliberately NOT
                       defaulted to a fabricated per-check version number
                       for hunters whose detection logic isn't externally
                       versioned at all.
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

    def print(self, indent: int = 2):
        """Console rendering — deliberately unchanged by the v2.5 SIEM-alert
        fields (id/severity/technique_ids/evidence_refs/iocs/rule_id/
        rule_version): those are a --json/--csv concern, not something an
        analyst reading the console transcript needs repeated inline.
        Every field FROM THE ORIGINAL FIVE-FIELD MODEL is still shown,
        nothing there is implied."""
        pad   = " " * indent
        color = _CONFIDENCE_COLOR.get(self.confidence, DIM)
        tag_str = {"observation": "OBSERVATION", "lead": "LEAD", "detection": "DETECTION"}.get(
            self.tag, self.tag.upper())
        print(f"{pad}{BOLD(self.check)}  [{color(self.confidence.upper())}]  {DIM(tag_str)}")
        print(f"{pad}  Inference   : {self.inference}")
        print(f"{pad}  Confidence  : {self.confidence}  —  {self.rationale}")
        if self.facts:
            print(f"{pad}  Facts:")
            for f in self.facts:
                print(f"{pad}    - {f}")
        if self.limitations:
            print(f"{pad}  Limitations:")
            for l in self.limitations:
                print(f"{pad}    - {l}")
        print()


def confidence_at_least(confidence: str, minimum: str) -> bool:
    """True if `confidence` is at or above `minimum` on the LOW<MEDIUM<HIGH order."""
    return _CONFIDENCE_ORDER.get(confidence, -1) >= _CONFIDENCE_ORDER.get(minimum, 99)


CONFIDENCE_NONE = "none"


def overall_confidence(findings: list, score: int) -> str:
    """
    Reduce a hunter's list of Finding objects (plus its own score) to a
    single top-level confidence for CSV/JSON summary consumers —
    "none"/"low"/"medium"/"high" — WITHOUT inflating it from the score
    alone (a prior pattern, `score >= max_score - 1`, silently turned a
    single medium-confidence structural lead into a "HIGH CONFIDENCE" CSV
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
    once — it previously produced console/CSV verdict text that
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
    "none"/"low"/"medium"/"high" triage label for CSV/JSON/console summary
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

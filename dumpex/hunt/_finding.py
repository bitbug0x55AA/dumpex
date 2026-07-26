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
from dataclasses import dataclass, field
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

_CONFIDENCE_COLOR = {CONFIDENCE_LOW: DIM, CONFIDENCE_MEDIUM: YELLOW, CONFIDENCE_HIGH: RED}
_CONFIDENCE_ORDER = {CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_HIGH: 2}


@dataclass
class Finding:
    check:       str            # short check identifier, e.g. "injection.allocation_correlation"
    facts:       list           # list[str] — objective observations, no judgment
    inference:   str            # what this suggests
    confidence:  str            # CONFIDENCE_LOW / CONFIDENCE_MEDIUM / CONFIDENCE_HIGH
    rationale:   str            # why this confidence level, specifically
    limitations: list = field(default_factory=list)   # list[str]
    tag:         str  = TAG_OBSERVATION                # TAG_OBSERVATION / TAG_LEAD / TAG_DETECTION

    def to_dict(self) -> dict:
        return {
            "check":       self.check,
            "tag":         self.tag,
            "confidence":  self.confidence,
            "facts":       list(self.facts),
            "inference":   self.inference,
            "rationale":   self.rationale,
            "limitations": list(self.limitations),
        }

    def print(self, indent: int = 2):
        """Console rendering — every field is shown, nothing is implied."""
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

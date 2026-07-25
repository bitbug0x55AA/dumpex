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

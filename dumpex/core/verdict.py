"""Report verdict policy: the independent indicator dimensions a report
card scores, the machine-readable verdict tiers, and the rule that maps a
set of dimensions to a tier.

The colored console wording of each tier is presentation and lives in
`dumpex.ui.memory_presentation`.
"""

INDICATOR_DIMS = {
    "unbacked_thread": "Unbacked thread execution (start addr outside all known modules)",
    "rwx_private":     "Anomalous memory protection (RWX + MEM_PRIVATE)",
    "injected_pe":     "Injected PE (valid PE header outside any loaded module, "
                       "in private or executable memory)",
    "ioc_strings":     "IOC string pattern(s) matched in region",
}

VERDICT_CLEAN                    = "CLEAN"
VERDICT_SUSPICIOUS                = "SUSPICIOUS"
VERDICT_LIKELY_MALICIOUS          = "LIKELY_MALICIOUS"
VERDICT_HIGH_CONFIDENCE_MALICIOUS = "HIGH_CONFIDENCE_MALICIOUS"


def verdict_for(dims: dict) -> str:
    """The machine-readable tier for a MECE dims dict. The colored console
    string (`dumpex.ui.memory_presentation._verdict`) is derived from this
    same tier, so the wire value (TriageCardRecord.verdict) and the console
    text are one rule, not two hand-maintained copies that could drift."""
    score = len(dims)
    if score == 0:
        return VERDICT_CLEAN
    if score == 1:
        return VERDICT_SUSPICIOUS
    if score == 2:
        return VERDICT_LIKELY_MALICIOUS
    return VERDICT_HIGH_CONFIDENCE_MALICIOUS

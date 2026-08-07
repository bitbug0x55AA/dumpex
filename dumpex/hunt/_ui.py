"""Shared print helpers for hunt modules."""
from dumpex.ui.colors import BOLD, RED, GREEN, YELLOW, DIM
from dumpex.hunt._console import classify_status_icon

def _print_hunt_header(title: str):
    print(f"\n{BOLD('══════════════════════════════════════════')}")
    print(f"{BOLD(f'  HUNT: {title}')}")
    print(f"{BOLD('══════════════════════════════════════════')}\n")


def _print_check(label: str, status: str, detail: str = ""):
    icon = classify_status_icon(status)
    print(f"  {icon} {BOLD(label)}")
    print(f"      Status : {status}")
    if detail:
        print(f"      Detail : {detail}")
    print()


# ── Scan status model ────────────────────────────────────────────────────
# A hunt module must not collapse "I looked and found nothing" and "I never
# actually looked" into the same green CLEAN/score==0 signal — that's how
# --hunt all ends up claiming "No TTP indicators" while a scanner silently
# never ran (missing dependency, missing stream, unreadable segment).
#
#   DETECTED                       — matched something in what was scanned
#   NOT_DETECTED_IN_SCANNED_SCOPE  — ran to completion, found nothing
#   NOT_EVALUATED                  — did not run at all (dependency/stream
#                                     missing, feature disabled, gated off)
#   INCONCLUSIVE                   — ran, but coverage was incomplete
#                                     (segments skipped/unreadable, partial
#                                     stream) so a negative result can't be
#                                     trusted as covering the full scope
DETECTED                      = "DETECTED"
NOT_DETECTED_IN_SCANNED_SCOPE = "NOT_DETECTED_IN_SCANNED_SCOPE"
NOT_EVALUATED                 = "NOT_EVALUATED"
INCONCLUSIVE                  = "INCONCLUSIVE"

_STATUS_COLOR = {
    DETECTED:                      RED,
    NOT_DETECTED_IN_SCANNED_SCOPE: GREEN,
    NOT_EVALUATED:                 DIM,
    INCONCLUSIVE:                  YELLOW,
}
_STATUS_LABEL = {
    DETECTED:                      "DETECTED",
    NOT_DETECTED_IN_SCANNED_SCOPE: "NOT DETECTED (in scanned scope)",
    NOT_EVALUATED:                 "NOT EVALUATED",
    INCONCLUSIVE:                  "INCONCLUSIVE",
}


def _status_text(status: str, reason: str = "") -> str:
    """Colorized one-line rendering of a scan status, for use in verdict lines."""
    color = _STATUS_COLOR.get(status, DIM)
    label = _STATUS_LABEL.get(status, status)
    return color(f"{label} — {reason}" if reason else label)


# The (evaluated, detected, complete) -> status reduction itself now lives
# in dumpex.hunt._coverage (derive_status/derive_coverage_status) — every
# phase-two hunter shares that single implementation rather than each
# re-deriving the same rule locally. This module stays focused on print
# helpers and the status/coverage string constants those functions return.


"""Shared print helpers for hunt modules."""
from dumpex.ui.colors import BOLD, RED, GREEN, YELLOW, DIM

def _print_hunt_header(title: str):
    print(f"\n{BOLD('══════════════════════════════════════════')}")
    print(f"{BOLD(f'  HUNT: {title}')}")
    print(f"{BOLD('══════════════════════════════════════════')}\n")


def _print_check(label: str, status: str, detail: str = ""):
    icon = RED("[!]") if "SUSPICIOUS" in status or "ANOMAL" in status else (
           YELLOW("[~]") if "NOTABLE" in status else GREEN("[✓]"))
    print(f"  {icon} {BOLD(label)}")
    print(f"      Status : {status}")
    if detail:
        print(f"      Detail : {detail}")
    print()


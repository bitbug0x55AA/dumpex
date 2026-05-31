"""--list command."""
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW
from dumpex.core.memory import get_memory_regions, prot_str
from dumpex.rules_pkg.loader import SUSPICIOUS_PROTS

def cmd_list(mf, filter_prot=None):
    regions = get_memory_regions(mf)
    print(f"\n{BOLD('Address'):<24} {BOLD('Size'):<14} {BOLD('State'):<14} {BOLD('Protection'):<32} {BOLD('Type')}")
    print("─" * 100)
    count = 0
    for r in regions:
        p = prot_str(r.Protect)
        if filter_prot and filter_prot.upper() not in p.upper():
            continue
        color = RED if any(s in p for s in SUSPICIOUS_PROTS) else (lambda x: x)
        print(color(f"0x{r.BaseAddress:<22x} 0x{r.RegionSize:<12x} {prot_str(r.State):<14} {p:<32} {prot_str(r.Type)}"))
        count += 1
    print(f"\n{GREEN(f'[+] {count} region(s) shown.')}")


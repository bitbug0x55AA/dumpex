"""TTP rule loader — reads rules.yaml / rules.json, falls back to built-ins."""
import re
import sys
import json
from pathlib import Path
from dumpex.ui.colors import DIM, YELLOW

SUSPICIOUS_PROTS = {"PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY"}

# ── Rule loader ───────────────────────────────────────────────────────────────
# Loads TTP detection rules from rules.yaml (preferred) or rules.json (fallback).
# If neither file is found, or if the YAML/JSON parser is unavailable, built-in
# defaults are used so the tool always runs standalone.
#
# Rule file search order:
#   1. Same directory as dumpex.py
#   2. Current working directory
#
# To add a new pipe pattern or IOC keyword, edit rules.yaml — no code changes needed.

_RULES_CACHE = None   # module-level singleton; populated on first call to get_rules()

# ── Built-in defaults (kept in sync with rules.yaml) ─────────────────────────
_DEFAULT_RULES = {
    "suspicious_protections": {"PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY"},
    "stomping_whitelist": {
        "wininet.dll", "winhttp.dll", "urlmon.dll", "mshtml.dll",
        "ieframe.dll", "cryptsp.dll", "crypt32.dll", "ncrypt.dll",
        "schannel.dll", "secur32.dll", "ws2_32.dll", "dnsapi.dll",
        "dhcpcsvc.dll", "iphlpapi.dll", "mswsock.dll", "cryptdll.dll",
        "rasapi32.dll", "rasman.dll",
    },
    "stomping_ioc_patterns": [
        r"cmd\.exe", r"powershell", r"CreateRemoteThread", r"VirtualAlloc",
        r"WriteProcessMemory", r"shellcode", r"beacon", r"cobalt",
        r"base64", r"WSASocket", r"meterpreter", r"mimikatz",
    ],
    "stomping_net_ioc_patterns": [
        r"https?://[^\s]{6,}",
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{2,5})?",
        r"InternetOpen", r"LoadLibrary[AW]?\s*\(", r"GetProcAddress",
    ],
    "pipe_c2_context_patterns": [
        r"https?://",
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{2,5})?",
        r"submit\.php", r"/ca$", r"/w2p",
    ],
    "framework_pipes": [
        {"pattern": r"postex_",           "framework": "Cobalt Strike",
         "technique": "Post-Exploitation (postex) pipe",            "mitre": "T1559.001"},
        {"pattern": r"msagent_",          "framework": "Cobalt Strike",
         "technique": "SMB Beacon peer-to-peer pipe",                "mitre": "T1090.001"},
        {"pattern": r"status_[0-9a-f]+",  "framework": "Cobalt Strike",
         "technique": "Beacon status pipe",                          "mitre": "T1559.001"},
        {"pattern": r"583da750",          "framework": "Cobalt Strike",
         "technique": "Hardcoded CS pipe name fragment",             "mitre": "T1559.001"},
        {"pattern": r"MSSE-[0-9a-f]+-server", "framework": "Metasploit",
         "technique": "Meterpreter named pipe transport",            "mitre": "T1559.001"},
        {"pattern": r"psexesvc",          "framework": "PsExec / Impacket",
         "technique": "PSExec service pipe",                         "mitre": "T1021.002"},
        {"pattern": r"paexec",            "framework": "PAExec",
         "technique": "PAExec lateral movement pipe",                "mitre": "T1021.002"},
        {"pattern": r"remcom",            "framework": "RemCom",
         "technique": "RemCom lateral movement tool pipe",           "mitre": "T1021.002"},
        {"pattern": r"svcctl",            "framework": "SCM / Lateral Movement",
         "technique": "Service Control Manager pipe",                "mitre": "T1021.002"},
        {"pattern": r"DserNamePipe",      "framework": "Various",
         "technique": "PrintNightmare / Spooler exploit pipe",       "mitre": "T1068"},
        {"pattern": r"mojo\.\d+\.\d+", "framework": "Chrome / Chromium IPC (possible abuse)",
         "technique": "Mojo IPC pipe — legitimate but abused",       "mitre": "T1559.001"},
    ],
}


def _compile_rules(raw: dict) -> dict:
    """
    Post-process a loaded rule dict: compile regex strings into re.Pattern objects,
    convert lists to sets where membership testing is the primary operation.
    """
    r = {}

    r["suspicious_protections"] = set(raw.get("suspicious_protections",
                                              list(_DEFAULT_RULES["suspicious_protections"])))

    r["stomping_whitelist"] = set(raw.get("stomping_whitelist",
                                          list(_DEFAULT_RULES["stomping_whitelist"])))

    for key in ("stomping_ioc_patterns", "stomping_net_ioc_patterns", "pipe_c2_context_patterns"):
        patterns = raw.get(key, _DEFAULT_RULES[key])
        combined = "|".join(f"(?:{p})" for p in patterns)
        r[key] = re.compile(combined, re.IGNORECASE)

    pipes = raw.get("framework_pipes", _DEFAULT_RULES["framework_pipes"])
    r["framework_pipes"] = [
        (re.compile(entry["pattern"], re.IGNORECASE),
         entry.get("framework", ""),
         entry.get("technique", ""),
         entry.get("mitre", ""))
        for entry in pipes
    ]

    return r


def _find_rules_file() -> Path | None:
    """
    Search for the TTP rules file.

    Search order (first match wins):
      <script_dir>/rules/rules.yaml   <- canonical new layout
      <cwd>/rules/rules.yaml
      <script_dir>/rules.yaml         <- legacy flat layout (backwards compat)
      <cwd>/rules.yaml
      (same pattern for .yml and .json variants)
    """
    script_dir = Path(sys.argv[0]).resolve().parent
    cwd        = Path.cwd()
    for base in (script_dir, cwd):
        for name in ("rules.yaml", "rules.yml", "rules.json"):
            for p in (base / "rules" / name, base / name):
                if p.is_file():
                    return p
    return None


def _load_rules() -> dict:
    """
    Load and compile TTP detection rules.

    Priority:
      1. rules.yaml / rules.yml  (requires pyyaml)
      2. rules.json              (stdlib json)
      3. Built-in defaults       (always available)

    Errors (missing file, parse failure, schema mismatch) are printed as
    warnings and cause automatic fallback to the next source.
    """
    path = _find_rules_file()

    if path is not None:
        try:
            if path.suffix in (".yaml", ".yml"):
                try:
                    import yaml
                    with open(path, "r", encoding="utf-8") as fh:
                        raw = yaml.safe_load(fh)
                except ImportError:
                    print(DIM(f"  [~] pyyaml not installed — cannot read {path.name}; "
                              f"install with: pip install pyyaml"))
                    raw = None
            else:
                import json
                with open(path, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)

            if raw is not None:
                version = raw.get("version", 1)
                if version != 1:
                    print(YELLOW(f"  [~] {path.name}: unknown schema version {version}, "
                                 f"proceeding anyway"))
                rules = _compile_rules(raw)
                print(DIM(f"  [·] Rules loaded from {path}"))
                return rules

        except Exception as e:
            print(YELLOW(f"  [~] Could not load {path}: {e} — using built-in defaults"))

    return _compile_rules({k: list(v) if isinstance(v, set) else v
                           for k, v in _DEFAULT_RULES.items()})


def get_rules() -> dict:
    """Return the compiled rule set, loading it on first call."""
    global _RULES_CACHE, SUSPICIOUS_PROTS
    if _RULES_CACHE is None:
        _RULES_CACHE = _load_rules()
        # Keep module-level SUSPICIOUS_PROTS in sync with the loaded rules
        # so all call-sites that reference it directly stay correct.
        SUSPICIOUS_PROTS = _RULES_CACHE["suspicious_protections"]
    return _RULES_CACHE

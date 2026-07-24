"""TTP rule loader — reads rules.yaml / rules.json, falls back to built-ins."""
import re
import sys
import json
import importlib.resources
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


_RULE_FILE_NAMES = (("rules.yaml", ".yaml"), ("rules.yml", ".yml"), ("rules.json", ".json"))


class _RuleSource:
    """
    Uniform handle for a candidate rules file, whether it lives at a plain
    filesystem path or inside the installed package via importlib.resources
    (which is not necessarily a real filesystem path — e.g. a zip-safe
    install — so callers must go through read_text() rather than open()).
    """
    __slots__ = ("display", "suffix", "_read_text")

    def __init__(self, display: str, suffix: str, read_text):
        self.display = display
        self.suffix  = suffix
        self._read_text = read_text

    def read_text(self) -> str:
        return self._read_text()


def _fs_source(directory: Path) -> "_RuleSource | None":
    """Look for rules.yaml/.yml/.json directly inside `directory` on a real filesystem path."""
    for name, suffix in _RULE_FILE_NAMES:
        candidate = directory / name
        if candidate.is_file():
            return _RuleSource(str(candidate), suffix,
                                lambda c=candidate: c.read_text(encoding="utf-8"))
    return None


def _packaged_source() -> "_RuleSource | None":
    """
    Locate rules.yaml/.yml/.json bundled inside dumpex.rules_pkg/data — the
    single copy shipped in the wheel (see pyproject.toml package-data) —
    via importlib.resources rather than a __file__-relative path. This is
    what actually makes `pip install dumpex` work standalone with no
    rules/ directory anywhere near the invoking script, and it keeps
    working even for a zip-safe/zipapp install where __file__ isn't a real
    filesystem path at all (a plain `Path(__file__).parent` lookup would
    silently find nothing there).
    """
    try:
        data_dir = importlib.resources.files("dumpex.rules_pkg").joinpath("data")
    except (ModuleNotFoundError, FileNotFoundError, NotADirectoryError):
        return None
    for name, suffix in _RULE_FILE_NAMES:
        candidate = data_dir.joinpath(name)
        try:
            if candidate.is_file():
                return _RuleSource(f"<dumpex.rules_pkg>/data/{name}", suffix,
                                    lambda c=candidate: c.read_text(encoding="utf-8"))
        except Exception:
            continue
    return None


def _find_rules_source() -> "_RuleSource | None":
    """
    Search for the TTP rules file. First match wins.

      1. <_MEIPASS>/rules/rules.yaml        PyInstaller onefile: --add-data
                                             extracts to sys._MEIPASS, not
                                             next to the exe (sys.argv[0]).
      2. dumpex.rules_pkg/data/rules.yaml   Bundled inside the installed
                                             package itself — see
                                             _packaged_source(). This is the
                                             single canonical copy of the
                                             default ruleset; it is NOT
                                             duplicated anywhere else in
                                             the repo, so there is nothing
                                             else to drift out of sync
                                             with it.
      3. <script_dir>/rules/rules.yaml,     Explicit user override: drop a
         <cwd>/rules/rules.yaml             custom rules.yaml next to the
                                             dumpex binary or in the
                                             working directory to change
                                             TTP rules without touching the
                                             installed package.
      4. <script_dir>/rules.yaml,           Legacy flat layout (back-compat).
         <cwd>/rules.yaml

    (.yml and .json are also tried at each filesystem location, in that order.)
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        src = _fs_source(Path(meipass) / "rules")
        if src is not None:
            return src

    src = _packaged_source()
    if src is not None:
        return src

    script_dir = Path(sys.argv[0]).resolve().parent
    cwd        = Path.cwd()
    for base in (script_dir, cwd):
        src = _fs_source(base / "rules")
        if src is not None:
            return src
    for base in (script_dir, cwd):
        src = _fs_source(base)
        if src is not None:
            return src
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
    source = _find_rules_source()

    if source is not None:
        try:
            if source.suffix in (".yaml", ".yml"):
                try:
                    import yaml
                    raw = yaml.safe_load(source.read_text())
                except ImportError:
                    print(DIM(f"  [~] pyyaml not installed — cannot read {source.display}; "
                              f"install with: pip install pyyaml"))
                    raw = None
            else:
                raw = json.loads(source.read_text())

            if raw is not None:
                version = raw.get("version", 1)
                if version != 1:
                    print(YELLOW(f"  [~] {source.display}: unknown schema version {version}, "
                                 f"proceeding anyway"))
                rules = _compile_rules(raw)
                print(DIM(f"  [·] Rules loaded from {source.display}"))
                return rules

        except Exception as e:
            print(YELLOW(f"  [~] Could not load {source.display}: {e} — using built-in defaults"))

    return _compile_rules({k: list(v) if isinstance(v, set) else v
                           for k, v in _DEFAULT_RULES.items()})


def get_rules() -> dict:
    """
    Return the compiled rule set, loading it on first call.

    Callers must read rule values from this dict (e.g.
    get_rules()["suspicious_protections"]) rather than importing a
    module-level name — `from module import NAME` binds a snapshot at
    import time, so any name reassigned later (e.g. after loading a
    custom rules.yaml) would silently stay stale in the importing module.
    """
    global _RULES_CACHE
    if _RULES_CACHE is None:
        _RULES_CACHE = _load_rules()
    return _RULES_CACHE

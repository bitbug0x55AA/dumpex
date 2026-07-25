"""TTP rule loader — reads rules.yaml / rules.json, falls back to built-ins."""
import re
import sys
import json
import hashlib
import importlib.resources
from pathlib import Path
from dumpex.ui.colors import DIM, YELLOW, RED, GREEN

SUSPICIOUS_PROTS = {"PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY"}

# ── Rule loader ───────────────────────────────────────────────────────────────
# Loads TTP detection rules from rules.yaml (preferred) or rules.json (fallback).
# If neither file is found, or if the YAML/JSON parser is unavailable, built-in
# defaults are used so the tool always runs standalone.
#
# Source priority: explicit --rules-file  >  packaged defaults (bundled in
# the wheel). There is deliberately no automatic cwd/script-dir scan — see
# configure_rules_source() and _find_rules_source() below. A DFIR working
# directory routinely contains untrusted case files; silently picking up a
# rules.yaml that happens to be sitting there (which is also what made the
# override path unreachable in practice, since the packaged copy was
# checked first and always exists) is neither safe nor useful. Use
# --rules-file to opt in explicitly.
#
# To add a new pipe pattern or IOC keyword, edit rules.yaml — no code changes needed.

_RULES_CACHE = None   # module-level singleton; populated on first call to get_rules()
_EXPLICIT_RULES_PATH = None   # set via configure_rules_source() / --rules-file
_LAST_SOURCE_INFO = None      # set by _load_rules(); see get_rules_source_info()


def configure_rules_source(explicit_path) -> None:
    """
    Set an explicit rules.yaml/.yml/.json path (--rules-file) to use ahead
    of the packaged defaults. Must be called before the first get_rules()
    call actually loads anything — get_rules() caches its result on first
    use, so this clears that cache to force a reload if one already
    happened. Passing None clears any previously configured override.

    Once set, this path is the ONLY source that will ever be used for
    this run — see _load_explicit_rules(): a missing, unreadable,
    unparseable, or schema-invalid file at this path is a hard exit, not
    a fallback to packaged/built-in rules. A caller who explicitly asked
    for a specific ruleset must never silently get a verdict produced by
    a different one.
    """
    global _EXPLICIT_RULES_PATH, _RULES_CACHE, _LAST_SOURCE_INFO
    _EXPLICIT_RULES_PATH = Path(explicit_path) if explicit_path else None
    _RULES_CACHE = None
    _LAST_SOURCE_INFO = None


def get_rules_source_info() -> "dict | None":
    """
    Metadata describing the rules source actually used by the most recent
    get_rules() call: {"path": str|None, "sha256": str|None, "explicit":
    bool, "version": int}. `path`/`sha256` are None only for the built-in
    defaults (no file was loaded at all). None overall if get_rules()
    hasn't been called yet in this process.

    Callers (structured JSON/TXT output) use this to record provenance —
    which ruleset, and its exact content hash, actually produced a given
    verdict — so a finding can be reproduced later even if rules.yaml
    changes.
    """
    return _LAST_SOURCE_INFO

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
    Search for the PACKAGED/AUTOMATIC TTP rules file — not consulted at
    all when --rules-file is set (see _load_rules/_load_explicit_rules,
    which is a separate, fail-closed path). First match wins.

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

    There is deliberately no automatic cwd/script-dir scan (see module
    docstring): that path used to sit AFTER the packaged-defaults check,
    which always succeeds now that rules.yaml is bundled in the wheel —
    making it dead code that could never actually run. Reordering it ahead
    of the packaged check instead would mean silently trusting whatever
    rules.yaml happens to be sitting in a DFIR analyst's case working
    directory. --rules-file is the explicit, auditable replacement.
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        src = _fs_source(Path(meipass) / "rules")
        if src is not None:
            return src

    return _packaged_source()


def _load_explicit_rules() -> dict:
    """
    Load rules from the user-specified --rules-file, with NO fallback to
    packaged/built-in rules on any failure: a missing file, unreadable
    content, YAML/JSON parse failure, non-mapping/unexpected schema, or a
    rule pattern that fails to compile is a hard, non-zero exit. Silently
    falling back here (as a prior version did) meant an automated caller
    who asked for a specific ruleset could get a verdict produced by a
    DIFFERENT ruleset without any indication that its request wasn't
    honored — for a DFIR tool, that's a worse failure mode than just
    stopping.
    """
    global _LAST_SOURCE_INFO
    path = _EXPLICIT_RULES_PATH

    if not path.is_file():
        print(RED(f"[!] --rules-file {path} not found."))
        sys.exit(1)

    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        print(RED(f"[!] --rules-file {path} could not be read: {e}"))
        sys.exit(1)

    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            raw = json.loads(text)
        else:
            # .yaml/.yml, or an unrecognized extension — YAML is a
            # superset of JSON for our purposes, so this also handles a
            # JSON-formatted file with an unexpected extension.
            import yaml
            raw = yaml.safe_load(text)
    except ImportError:
        print(RED(f"[!] --rules-file {path}: pyyaml not installed, cannot parse. "
                  f"Install with: pip install pyyaml"))
        sys.exit(1)
    except Exception as e:
        print(RED(f"[!] --rules-file {path}: parse error: {e}"))
        sys.exit(1)

    if not isinstance(raw, dict):
        print(RED(f"[!] --rules-file {path}: expected a YAML/JSON mapping at the top "
                  f"level, got {type(raw).__name__}."))
        sys.exit(1)

    version = raw.get("version", 1)
    if version != 1:
        print(RED(f"[!] --rules-file {path}: unknown schema version {version}."))
        sys.exit(1)

    try:
        rules = _compile_rules(raw)
    except Exception as e:
        print(RED(f"[!] --rules-file {path}: failed to compile rules: {e}"))
        sys.exit(1)

    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    _LAST_SOURCE_INFO = {"path": str(path), "sha256": digest, "explicit": True, "version": version}
    print(GREEN(f"  [·] Rules loaded from --rules-file {path}  (sha256={digest[:16]}…)"))
    return rules


def _load_rules() -> dict:
    """
    Load and compile TTP detection rules.

    If --rules-file was set (configure_rules_source()), it is the ONLY
    source consulted — see _load_explicit_rules(), which fails closed
    (non-zero exit) on any problem rather than falling back. Otherwise:
      1. Packaged defaults (rules.yaml bundled in the wheel — see
         _find_rules_source)
      2. Built-in defaults (always available)

    Errors loading the packaged copy (parse failure, schema mismatch) are
    printed as warnings and cause automatic fallback to built-in defaults
    — that path is NOT user-requested, so silent fallback there is the
    right behavior (it's what keeps the tool runnable standalone).
    """
    global _LAST_SOURCE_INFO

    if _EXPLICIT_RULES_PATH is not None:
        return _load_explicit_rules()

    source = _find_rules_source()

    if source is not None:
        try:
            text = source.read_text()
            if source.suffix in (".yaml", ".yml"):
                try:
                    import yaml
                    raw = yaml.safe_load(text)
                except ImportError:
                    print(DIM(f"  [~] pyyaml not installed — cannot read {source.display}; "
                              f"install with: pip install pyyaml"))
                    raw = None
            else:
                raw = json.loads(text)

            if raw is not None:
                version = raw.get("version", 1)
                if version != 1:
                    print(YELLOW(f"  [~] {source.display}: unknown schema version {version}, "
                                 f"proceeding anyway"))
                rules = _compile_rules(raw)
                digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
                _LAST_SOURCE_INFO = {"path": source.display, "sha256": digest,
                                      "explicit": False, "version": version}
                print(DIM(f"  [·] Rules loaded from {source.display}  (sha256={digest[:16]}…)"))
                return rules

        except Exception as e:
            print(YELLOW(f"  [~] Could not load {source.display}: {e} — using built-in defaults"))

    _LAST_SOURCE_INFO = {"path": None, "sha256": None, "explicit": False, "version": 1}
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

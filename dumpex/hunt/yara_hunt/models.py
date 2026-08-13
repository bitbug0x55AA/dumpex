"""Frozen leaf evidence types for the YARA scan/aggregate pipeline -- the
recursively immutable replacement for this module's pre-migration mutable
`RuleBundle`/`ScanOutcome`/`RuleGroup` DTOs (dicts/lists/sets). Not the
public JSON shape -- `report_legacy.py`/`report_record.py` project these
into the `findings` dict / `HunterRecord`, unchanged in shape from before
this migration (see issue #11's "Compatibility" section).

Every type here is validated by `__post_init__` and swept by
`dumpex.hunt._domain.require_recursively_immutable` -- nothing reachable
from a constructed instance can be a live list/dict/set, a raw minidump
object, or a resolver/dump handle (see that function's own docstring).
"""
from dataclasses import dataclass, field

from dumpex.hunt._domain import as_tuple, require_recursively_immutable


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a bool, got {type(value).__name__}: {value!r}")


def _require_int(value, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be an int, got {type(value).__name__}: {value!r}")


def _require_nonneg_int(value, field_name: str) -> None:
    _require_int(value, field_name)
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0, got {value}")


def _require_str(value, field_name: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a str, got {type(value).__name__}: {value!r}")


def _require_optional_str(value, field_name: str) -> None:
    if value is not None:
        _require_str(value, field_name)


def _require_bytes(value, field_name: str) -> None:
    if type(value) is not bytes:
        raise TypeError(f"{field_name} must be bytes, got {type(value).__name__}: {value!r}")


def _require_str_tuple(value, field_name: str) -> tuple:
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        _require_str(item, f"{field_name}[{index}]")
    return items


# yara-python's own `Match.meta` values are always str/int/bool -- the same
# three leaf types `dumpex.hunt._domain.require_recursively_immutable`
# already accepts, so a meta ITEM needs no separate immutability sweep.
_META_VALUE_TYPES = (str, int, bool)


def _require_meta_items(value, field_name: str) -> tuple:
    """Normalize a rule's full `meta:` block to a tuple of `(key, value)`
    pairs, sorted by key. A rule's meta block may declare ANY key (the
    packaged rules alone use description/author/reference/mitre/
    dumpex_scope -- a future rule file could add any other), and the
    legacy/typed-record `matches[*].meta` output must reproduce the whole
    block, not a fixed subset -- so this is NOT reduced to a handful of
    named fields the way `RuleMatchEvidence`'s other fields are."""
    items = as_tuple(value, field_name)
    for index, item in enumerate(items):
        if not (isinstance(item, tuple) and len(item) == 2):
            raise TypeError(
                f"{field_name}[{index}] must be a (key, value) pair, got {item!r}")
        key, val = item
        if type(key) is not str:
            raise TypeError(f"{field_name}[{index}][0] must be a str, got {type(key).__name__}")
        if not isinstance(val, _META_VALUE_TYPES):
            raise TypeError(
                f"{field_name}[{index}][1] must be a str, int, or bool, got "
                f"{type(val).__name__}: {val!r}")
    keys = [k for k, _ in items]
    if keys != sorted(keys):
        raise ValueError(f"{field_name} must be sorted by key")
    return items


@dataclass(frozen=True)
class RuleFileDiagnostic:
    """One candidate .yar/.yara file's own compile outcome and content hash
    -- one entry per file considered, regardless of whether it compiled.
    Replaces the pre-migration `provenance["files"]` dict entries; also the
    ONE place a compile failure's reproducible detail is retained now that
    `rules.load_and_compile()` no longer prints it (issue #11's confirmed
    gap: "prints rule compilation failures from the rule loader while the
    builder claims to be silent" -- report_console.py renders this fact
    from the Report instead)."""
    name:      str
    sha256:    "str | None"
    compiled:  bool
    error:     "str | None"

    def __post_init__(self):
        _require_str(self.name, "RuleFileDiagnostic.name")
        _require_optional_str(self.sha256, "RuleFileDiagnostic.sha256")
        _require_bool(self.compiled, "RuleFileDiagnostic.compiled")
        _require_optional_str(self.error, "RuleFileDiagnostic.error")
        if self.compiled and self.error is not None:
            raise ValueError(
                "RuleFileDiagnostic.error must be None when compiled is True")
        if not self.compiled and self.error is None:
            raise ValueError(
                "RuleFileDiagnostic.error must be set when compiled is False")


@dataclass(frozen=True)
class RulesProvenance:
    """Reproducible content provenance for every .yar/.yara file considered
    in one `rules.load_and_compile()` call -- the frozen replacement for
    the pre-migration provenance dict returned alongside `RuleBundle`.
    `get_yara_provenance()` (dumpex/hunt/yara_hunt/__init__.py) is the ONE
    compatibility adapter rendering this back to that dict shape; nothing
    else may reconstruct that shape independently."""
    rules_dir:          str
    files:               tuple = field(default_factory=tuple)   # tuple[RuleFileDiagnostic], sorted by name
    aggregate_sha256:    str = ""
    compiled_ok:         int = 0
    compile_failed:      int = 0

    def __post_init__(self):
        _require_str(self.rules_dir, "RulesProvenance.rules_dir")
        items = as_tuple(self.files, "RulesProvenance.files")
        for index, item in enumerate(items):
            if not isinstance(item, RuleFileDiagnostic):
                raise TypeError(
                    f"RulesProvenance.files[{index}] must be a RuleFileDiagnostic, got "
                    f"{type(item).__name__}: {item!r}")
        sorted_names = [f.name for f in items]
        if sorted_names != sorted(sorted_names):
            raise ValueError("RulesProvenance.files must be sorted by name")
        object.__setattr__(self, "files", items)
        _require_str(self.aggregate_sha256, "RulesProvenance.aggregate_sha256")
        _require_nonneg_int(self.compiled_ok, "RulesProvenance.compiled_ok")
        _require_nonneg_int(self.compile_failed, "RulesProvenance.compile_failed")
        compiled = sum(1 for f in items if f.compiled)
        failed = len(items) - compiled
        if compiled != self.compiled_ok:
            raise ValueError(
                f"RulesProvenance.compiled_ok ({self.compiled_ok}) must equal the number of "
                f"compiled files in `files` ({compiled})")
        if failed != self.compile_failed:
            raise ValueError(
                f"RulesProvenance.compile_failed ({self.compile_failed}) must equal the number "
                f"of failed files in `files` ({failed})")
        require_recursively_immutable(self, "RulesProvenance")

    def to_dict(self) -> dict:
        """The exact pre-migration provenance dict shape -- the ONE place
        this Report-internal type is rendered back to that shape (see
        `get_yara_provenance()`'s own docstring)."""
        return {
            "rules_dir": self.rules_dir,
            "files": [{"name": f.name, "sha256": f.sha256, "compiled": f.compiled,
                       "error": f.error} for f in self.files],
            "aggregate_sha256": self.aggregate_sha256,
            "compiled_ok": self.compiled_ok,
            "compile_failed": self.compile_failed,
        }


@dataclass(frozen=True)
class StringEvidence:
    """One matched string instance, VA/file-offset already resolved --
    replaces the pre-migration `annotated_strings` dict entries
    (`{"var","offset","va","fo","data"}`)."""
    var:     str
    offset:  int
    va:      int
    fo:      int
    data:    bytes

    def __post_init__(self):
        _require_str(self.var, "StringEvidence.var")
        _require_nonneg_int(self.offset, "StringEvidence.offset")
        _require_nonneg_int(self.va, "StringEvidence.va")
        _require_nonneg_int(self.fo, "StringEvidence.fo")
        _require_bytes(self.data, "StringEvidence.data")
        require_recursively_immutable(self, "StringEvidence")


@dataclass(frozen=True)
class RuleMatchEvidence:
    """One individual (segment, rule_file) match -- one entry PER match
    event, never collapsed with another: two different rule FILES (or
    namespaces) defining a same-named rule that both match the same
    region are two distinct pieces of evidence (different `file`/
    `namespace`, different provenance) and both survive into the Report
    (see scanner.py's own docstring on why this must not be deduplicated
    by `(rule, seg_va)` at the evidence layer -- a console projector may
    still GROUP same-named-rule entries for DISPLAY, but that is a
    presentation choice made from the full, undiscarded set).

    `backing_module`/`memory_context`/`context_unverified` are resolved
    ONCE, at scan time (dumpex.hunt.yara_hunt.context's classifiers),
    instead of retained as a raw `modules` list on the Report and
    re-resolved by the console at render time -- issue #11's confirmed
    gap: "retains raw module objects in Report.modules".
    """
    rule:                str
    file:                str
    namespace:            str = "default"
    tags:                 tuple = field(default_factory=tuple)     # tuple[str]
    meta:                  tuple = field(default_factory=tuple)     # tuple[(str, str|int|bool)], sorted by key
    seg_va:                int = 0
    seg_fo:                int = 0
    seg_size:              int = 0
    strings:               tuple = field(default_factory=tuple)    # tuple[StringEvidence], capped at
                                                                     # config.max_strings_per_match
    string_count:           int = 0    # TOTAL string instances this match actually had,
                                        # possibly > len(strings) -- see strings_truncated
    backing_module:        "str | None" = None
    memory_context:        "str | None" = None
    context_unverified:    bool = False

    def __post_init__(self):
        _require_str(self.rule, "RuleMatchEvidence.rule")
        _require_str(self.file, "RuleMatchEvidence.file")
        _require_str(self.namespace, "RuleMatchEvidence.namespace")
        object.__setattr__(self, "tags",
                            _require_str_tuple(self.tags, "RuleMatchEvidence.tags"))
        object.__setattr__(self, "meta",
                            _require_meta_items(self.meta, "RuleMatchEvidence.meta"))
        _require_nonneg_int(self.seg_va, "RuleMatchEvidence.seg_va")
        _require_nonneg_int(self.seg_fo, "RuleMatchEvidence.seg_fo")
        _require_nonneg_int(self.seg_size, "RuleMatchEvidence.seg_size")
        strings = as_tuple(self.strings, "RuleMatchEvidence.strings")
        for index, item in enumerate(strings):
            if not isinstance(item, StringEvidence):
                raise TypeError(
                    f"RuleMatchEvidence.strings[{index}] must be a StringEvidence, got "
                    f"{type(item).__name__}: {item!r}")
        object.__setattr__(self, "strings", strings)
        _require_nonneg_int(self.string_count, "RuleMatchEvidence.string_count")
        if self.string_count < len(strings):
            raise ValueError(
                f"RuleMatchEvidence.string_count ({self.string_count}) cannot be less than "
                f"len(strings) ({len(strings)}) -- it counts every instance this match had, "
                f"capped or not")
        _require_optional_str(self.backing_module, "RuleMatchEvidence.backing_module")
        _require_optional_str(self.memory_context, "RuleMatchEvidence.memory_context")
        _require_bool(self.context_unverified, "RuleMatchEvidence.context_unverified")
        require_recursively_immutable(self, "RuleMatchEvidence")

    @property
    def strings_truncated(self) -> bool:
        """True iff `string_count` exceeded the per-match cap this hunter
        applied (`config.max_strings_per_match`) -- derived, never stored
        redundantly, so it can never disagree with `string_count`/
        `len(strings)`. Issue #11's confirmed gap: string-evidence
        truncation was previously invisible to both console and callers."""
        return self.string_count > len(self.strings)

    def meta_get(self, key: str, default=None):
        return next((value for k, value in self.meta if k == key), default)

    def meta_dict(self) -> dict:
        """The full `meta:` block, reconstructed -- the ONE place this
        frozen tuple representation is turned back into a plain dict, for
        `report_legacy.py`/`report_record.py`'s own `matches[*].meta`
        projection."""
        return dict(self.meta)

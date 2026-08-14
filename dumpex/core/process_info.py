"""
Shared, side-effect-free process-metadata layer -- issue #37's frozen
contract (docs/recon_process_sysinfo_handles_contract.md), §3.2/§3.3/§3.4/
§4.2/§4.4, built by issue #38 so `--process` and `--sysinfo` (issues
#40/#41) can both consume it without composing each other's command
collectors or duplicating PEB/MiscInfo policy.

Every function here is pure: no console output, no mutation of `mf` or of
any list/object passed in, and no raw minidump parser object is ever
retained past this module's own boundary -- only frozen dataclasses of
plain scalars/`None`/nested frozen dataclasses are handed back. This is
true even for module resolution: resolve_module_by_base() (an internal
primitive whose exact signature and "return the module itself" semantics
are frozen verbatim by §3.3.3, for composing INSIDE this module) is never
handed to a caller directly by build_process_identity_snapshot() --
_module_reference() converts its result into a ModuleReference (three
scalars) before it ever leaves this file.

Three families live here:

  - normalize_*() / format_process_create_time_utc(): raw
    MINIDUMP_MISC_INFO/PEB field -> a validated scalar or None. Coverage
    is always derived from these normalized results, never from raw
    truthiness (§3.2) -- a truthy-but-invalid raw value (PID 0, an
    unaligned image base, a ProcessCreateTime past UINT32 range) must not
    count as evaluated identity evidence.
  - resolve_module_by_base() / walk_environment_block() /
    parse_environment_entries(): read or normalize evidence not exposed
    anywhere else today -- an exact-base module match, an independent,
    bounded re-walk of the PEB's environment block that never depends on
    (or can be defeated by) the library's own PEB.from_minidump() build,
    and the `=`-prefixed-entry-aware name/value reconstruction over that
    walk's raw strings.
  - build_process_identity_snapshot() and the frozen dataclasses it
    returns (MiscInfoClaim, PebClaim, ModuleClaim, ModuleReference,
    ProcessDiagnostic, ProcessIdentitySnapshot): the shared boundary
    itself -- one function that applies the §3.3 source-precedence rules
    across MiscInfo/PEB/ModuleList, keeps every source's claim
    independently attributable (a fallback never overwrites or erases a
    preferred source's own claim -- §3.3.4), and represents PEB/module
    base or name disagreement as typed, non-coverage-affecting
    diagnostics (§3.4.4/§6.2) rather than silently picking one side.
"""
import ntpath
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType

from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE
from minidump.structures.peb import PEB_OFFSETS

from dumpex.core.memory import read_region, stream_failure, va_range_captured_bytes
from dumpex.core.pe_utils import parse_pe_header
from dumpex.output.coverage import SourceState

# ── §3.2 normalization ──────────────────────────────────────────────────

_UINT32_MAX = 0xFFFFFFFF
_UINT64_MAX = 0xFFFFFFFFFFFFFFFF
_IMAGE_BASE_ALIGNMENT = 0x1000


def normalize_pid(raw) -> "int | None":
    """MINIDUMP_MISC_INFO.ProcessId -> int | None. 0 is the library's
    unset value (not a dumpable process); anything outside UINT32 range
    cannot be a real PID either. `bool` is excluded even though it is a
    subclass of `int` -- a stray `True`/`False` must never normalize to
    1/0."""
    if not isinstance(raw, int) or isinstance(raw, bool):
        return None
    if not (1 <= raw <= _UINT32_MAX):
        return None
    return raw


def classify_process_create_time(raw) -> str:
    """-> 'ok' | 'unset' | 'invalid'. Range-checked BEFORE any datetime
    conversion: datetime.fromtimestamp() is platform-dependent and
    happily converts values a UINT32 field could never actually hold."""
    if not isinstance(raw, int) or isinstance(raw, bool):
        return "invalid"
    if raw == 0:
        return "unset"
    if not (0 <= raw <= _UINT32_MAX):
        return "invalid"
    return "ok"


def format_process_create_time_utc(raw) -> "str | None":
    """MINIDUMP_MISC_INFO.ProcessCreateTime -> the contract's UTC string
    ("%Y-%m-%d %H:%M:%S UTC", §1.3), or None when
    classify_process_create_time(raw) is not "ok" -- 'unset'/'invalid'
    both normalize to unavailable evidence here; the raw value itself
    (0, negative, out-of-range, non-int) is preserved separately by the
    caller (misc_info_claim.raw_process_create_time, §3.2), never
    reconstructed from this function's None. Uses an explicit UTC
    timezone rather than the platform-local one datetime.fromtimestamp()
    would otherwise apply, so the same raw value renders identically on
    every analysis host."""
    if classify_process_create_time(raw) != "ok":
        return None
    return datetime.fromtimestamp(raw, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _safe_str(raw) -> str:
    """str(raw), with a pathological `__str__` (one that itself raises)
    caught rather than propagated -- this function's only job is to
    produce SOME JSON-safe scalar to preserve a rejected raw value as,
    never to validate or interpret it."""
    try:
        return str(raw)
    except Exception:
        return f"<unrepresentable {type(raw).__name__}>"


def _raw_int_or_str(raw):
    """A rejected raw value bound for an integer-typed field (pid,
    process_create_time) -> None (raw itself was never seen), a plain
    int (raw genuinely was one, just out of the accepted range), or a
    string (raw wasn't an int at all) -- §3.2's exact "integer, or a
    string when the raw value was not an integer at all" rule. Never the
    object itself: a caller passing a live parser/mock object as `raw`
    must not get it echoed back out through this boundary."""
    if raw is None:
        return None
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    return _safe_str(raw)


def _raw_address_hex_or_str(raw):
    """A rejected raw value bound for an address-typed field (image
    base) -> None, a fixed-width hex string when raw is a plain int in
    uint64 range (§3.2's rule, even when normalize_image_base() itself
    rejected it for being unaligned/zero -- alignment doesn't disqualify
    a value from being renderable as an address), or a string
    otherwise."""
    if raw is None:
        return None
    if isinstance(raw, int) and not isinstance(raw, bool) and 0 <= raw <= _UINT64_MAX:
        return f"0x{raw:016x}"
    return _safe_str(raw)


def _raw_str(raw):
    """A rejected raw value bound for a string-typed field (path,
    command line) -> None, the string itself if raw already was one, or
    its str() representation otherwise (§3.2's "string" rule, defensive
    against a caller handing this a non-string object)."""
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    return _safe_str(raw)


def normalize_windows_path(raw) -> "str | None":
    """PEB/module path string -> str | None. Strips trailing NULs and
    surrounding whitespace; '' and whitespace-only become None (the
    codebase's existing `... or None` convention -- see
    dumpex.core.memory.module_name_only's own docstring). Never
    truncates, never rewrites separators, never lowercases: the stored
    value is evidence, not a normalized comparison key."""
    if not isinstance(raw, str):
        return None
    stripped = raw.rstrip("\x00").strip()
    return stripped or None


def normalize_command_line(raw) -> "str | None":
    """Same rules as normalize_windows_path() -- a command line has no
    path structure to interpret, but an empty/whitespace-only/NUL-padded
    value is genuinely absent evidence on exactly the same terms."""
    if not isinstance(raw, str):
        return None
    stripped = raw.rstrip("\x00").strip()
    return stripped or None


def normalize_image_base(raw) -> "int | None":
    """peb.image_base_address -> int | None. Requires a plain int (not
    bool), 0 < raw <= UINT64_MAX, and 0x1000 alignment -- an unaligned or
    zero value is a read artifact, not a plausible mapped image base."""
    if not isinstance(raw, int) or isinstance(raw, bool):
        return None
    if not (0 < raw <= _UINT64_MAX):
        return None
    if raw % _IMAGE_BASE_ALIGNMENT != 0:
        return None
    return raw


# ── §3.3.3 module resolution by exact base ──────────────────────────────

def resolve_module_by_base(base_address: "int | None", modules: list):
    """The module whose .baseaddress == base_address EXACTLY, or None.
    Its signature and "return the module itself" behavior are frozen
    verbatim by §3.3.3 -- this is a low-level, internal-composition
    primitive, not the shared boundary itself: build_process_identity_
    snapshot() below is the only place production code should call it,
    and it converts the result into a ModuleReference (scalars only)
    before returning anything to ITS OWN caller. A raw module reference
    never escapes this module.

    Deliberately NOT dumpex.core.memory.addr_to_module(), whose
    containment test (baseaddress <= addr < endaddress) would match the
    main image for ANY address inside it -- here the question is "is a
    module REGISTERED at exactly this base", and containment answers a
    different, weaker question. Returns None immediately for a
    `base_address` that isn't a real int (e.g. the caller passed through
    an un-normalized value by mistake) rather than raising."""
    if not isinstance(base_address, int) or isinstance(base_address, bool):
        return None
    for m in modules:
        if getattr(m, "baseaddress", None) == base_address:
            return m
    return None


def _windows_basename(path: "str | None") -> "str | None":
    """ntpath.basename(), never os.path.basename() -- minidump paths are
    always Windows paths regardless of the analysis host (matches
    dumpex.core.memory.module_name_only()'s own reasoning). Preserves
    case: the stored value is evidence, not a comparison key (§3.2's
    "never lowercases" rule applies here too) -- callers that need a
    case-insensitive comparison do it themselves, at the comparison
    site, without touching the stored string."""
    if not path:
        return None
    base = ntpath.basename(path)
    return base or None


def _module_reference(m) -> "ModuleReference | None":
    """A raw minidump module -> a frozen, scalar-only ModuleReference, or
    None when the module's own base address isn't a plain int (a
    malformed ModuleListStream entry dumpex will not certify as a
    reference). The ONE place a raw module object is read past this
    module's boundary -- every caller gets this back, never `m` itself."""
    base = getattr(m, "baseaddress", None)
    if not isinstance(base, int) or isinstance(base, bool):
        return None
    path = normalize_windows_path(getattr(m, "name", None))
    return ModuleReference(base_address=base, name=_windows_basename(path), path=path)


def _hex_or_none(n) -> "str | None":
    """dumpex's fixed-width (16 hex digit, zero-padded, lowercase) address
    convention, duplicated here (rather than imported from
    dumpex.output.records/dumpex.output.coverage) because the dependency
    direction is core/domain model -> output adapter, never backwards --
    dumpex.output.coverage._hex_address keeps the identical one-line
    duplicate for the same reason."""
    return None if n is None else f"0x{n:016x}"


# ── §3.4 claims, diagnostics, and the shared process-identity snapshot ──

@dataclass(frozen=True)
class ModuleReference:
    """One module's own identity, reduced to three scalars -- used both
    for module_claim's own resolved values and for name_matched_candidate
    (§3.4.3). Never wraps a raw parser object."""
    base_address: int
    name: "str | None"
    path: "str | None"


@dataclass(frozen=True)
class MiscInfoClaim:
    """§3.4.1. `pid`/`process_create_time_utc`/both raw_* fields are None
    when misc_info is absent/failed; a structurally-present-but-rejected
    raw value is always preserved (as a JSON-safe scalar, never the raw
    object -- see _raw_int_or_str()) in raw_pid/raw_process_create_time
    even when the corresponding normalized field is None (§3.2's
    "nothing is discarded by a normalizer" rule).

    `source_state` (a dumpex.output.coverage.SourceState value: ABSENT/
    PRESENT/FAILED) and `failure_detail` keep "never present in this
    dump" and "present, but parsing it raised" distinct -- both collapse
    identically to pid/process_create_time_utc being None otherwise, and
    an analyst deciding between "re-collect" and "investigate dump
    integrity" needs to tell them apart (issue #38's own "keep source
    state, absence, failure, and conflict distinct" requirement)."""
    pid: "int | None"
    process_create_time_utc: "str | None"
    raw_pid: object
    raw_process_create_time: object
    source_state: str
    failure_detail: "str | None"


@dataclass(frozen=True)
class PebClaim:
    """§3.4.2. `name` is the basename of `image_path` (via
    _windows_basename(), i.e. ntpath.basename() -- never split with
    os.path.basename() on a POSIX analysis host), independent of
    whichever path selected_process_path ultimately came from.
    `source_state` is ABSENT or PRESENT only -- the PEB source never
    becomes FAILED in v2.13 (issue #37 §2.4: PEB.from_minidump()
    exceptions already leave mf.peb as None, i.e. ABSENT, not a distinct
    failure state)."""
    image_base_address: "int | None"
    image_path: "str | None"
    name: "str | None"
    command_line: "str | None"
    raw_image_base_address: object
    raw_image_path: object
    raw_command_line: object
    source_state: str


@dataclass(frozen=True)
class ModuleClaim:
    """§3.4.3. `match_state` is one of "resolved" | "unregistered" |
    "unavailable" -- see build_process_identity_snapshot()'s own
    docstring for exactly when each fires. `name_matched_candidate` is
    populated only for "unregistered", found by a single deterministic
    pass in `modules`' own source order (never re-sorted); when more than
    one module shares that basename, only the first is kept and
    `name_matched_candidate_ambiguous` says so rather than silently
    picking one.

    `modules_source_state`/`modules_failure_detail` mirror MiscInfoClaim's
    own ABSENT/PRESENT/FAILED distinction for ModuleListStream -- an
    absent stream and a stream that raised while parsing both drive
    `match_state` to "unavailable" identically (neither leaves anything
    to resolve against), but they are different facts an analyst needs
    to tell apart, so both survive here even though match_state itself
    can't carry the distinction."""
    match_state: str
    base_address: "int | None"
    name: "str | None"
    path: "str | None"
    name_matched_candidate: "ModuleReference | None"
    name_matched_candidate_ambiguous: bool
    modules_source_state: str
    modules_failure_detail: "str | None"


@dataclass(frozen=True)
class MainImagePeClaim:
    """§3.4.4's main_image_pe: whether the PE header at the PEB-reported
    (never the module-fallback) image base was read and structurally
    validated. `checked` is False (with `valid`/`reason` both None) when
    there was no normalized image base to check at all, or nothing could
    be read there -- a read failure is "never checked", not a failed
    check. `reason` is dumpex.core.pe_utils.parse_pe_header()'s own
    `reason` string, copied verbatim, never composed here."""
    checked: bool
    valid: "bool | None"
    reason: "str | None"


@dataclass(frozen=True)
class ProcessDiagnostic:
    """§3.4.4/§6.2. A disagreement between two pieces of captured
    evidence -- never a verdict, never able to change coverage status.
    `code` is one of the five identity-family §6.2 codes this module can
    fire (PROCESS_MODULE_BASE_UNMATCHED/_CONFLICT/_NAME_AMBIGUOUS/
    _IDENTITY_MISMATCH/_PATH_SOURCE_FALLBACK); `severity` is "info" or
    "warning", fixed per code; `details` is an immutable mapping (never a
    plain dict a caller could mutate after construction). `affected_count`
    is §3.4.4's own field -- None for every one-shot diagnostic this
    module fires (all five identity-family codes are one-shot; §6.2's
    only aggregating example, IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS, is
    outside this module's scope) -- kept here, validated, so the shape
    matches the frozen contract even though this module's own
    constructors never populate it."""
    code: str
    severity: str
    message: str
    details: MappingProxyType = field(default_factory=lambda: MappingProxyType({}))
    affected_count: "int | None" = None

    def __post_init__(self):
        if self.affected_count is not None and (
                not isinstance(self.affected_count, int) or isinstance(self.affected_count, bool)
                or self.affected_count <= 0):
            raise ValueError(
                f"ProcessDiagnostic.affected_count must be None or a positive int, "
                f"got {self.affected_count!r}")


@dataclass(frozen=True)
class ProcessIdentitySnapshot:
    """The shared process-identity result: PEB, MiscInfo, ModuleList, and
    main-image-PE claims kept independently attributable (§3.3.4 -- a
    fallback never overwrites or erases a preferred source's own claim),
    plus the already-resolved path/name precedence winner and every
    diagnostic §3.4.4 licenses. This is the reusable boundary
    --process/--sysinfo (and later Recon/Hunt consumers) build their own
    field/record/JSON shapes from, without importing each other's
    command collectors, re-deriving precedence/diagnostic logic
    independently, or re-reading the main image's PE header a second
    time for the same invocation."""
    misc_info_claim: MiscInfoClaim
    peb_claim: PebClaim
    module_claim: ModuleClaim
    main_image_pe: MainImagePeClaim
    selected_path_source: "str | None"      # "peb" | "module" | None
    selected_process_path: "str | None"
    selected_process_name: "str | None"
    diagnostics: tuple

    @property
    def pid(self) -> "int | None":
        return self.misc_info_claim.pid

    @property
    def process_start_utc(self) -> "str | None":
        return self.misc_info_claim.process_create_time_utc

    @property
    def image_base_address(self) -> "int | None":
        # §3.3.4: image_base_address is a PEB claim ONLY -- the module
        # list's own base for a name-matched candidate is never promoted
        # into it, regardless of module_claim's own state.
        return self.peb_claim.image_base_address

    @property
    def command_line(self) -> "str | None":
        return self.peb_claim.command_line


def _stream_source_state(mf, attr_name: str, stream_type) -> "tuple[str, str | None]":
    """(source_state, failure_detail) for one of mf's stream-backed
    attributes, reusing dumpex.core.memory.stream_failure() -- the single
    place any code asks "did this stream fail to parse?" -- so ABSENT and
    FAILED are never independently re-derived (and never conflated) here.
    An mf that never went through open_dump() (a test fixture missing
    _dumpex_stream_failures) is treated as "no failures", matching
    stream_failure()'s own documented contract."""
    detail = stream_failure(mf, stream_type)
    if detail is not None:
        return (SourceState.FAILED, detail)
    if getattr(mf, attr_name, None) is None:
        return (SourceState.ABSENT, None)
    return (SourceState.PRESENT, None)


def _build_misc_info_claim(mf) -> MiscInfoClaim:
    """§3.2's raw-preservation rule, applied precisely: a raw_* field is
    non-None if and only if something was structurally present AND its
    normalizer rejected it -- never an echo of a value that normalized
    successfully, and never a fabricated `"None"` for a source that was
    absent to begin with. "field is null and raw_field is not null" must
    stay the ONLY way to detect a rejection; echoing the raw value
    alongside a successful normalization would make that detection
    ambiguous. A rejected raw value is preserved as a JSON-safe scalar
    (see _raw_int_or_str()), never the raw object itself -- absence and
    failure (mf.misc_info is None vs. MiscInfoStream present but failed
    to parse) are kept distinct via `source_state`/`failure_detail`."""
    source_state, failure_detail = _stream_source_state(
        mf, "misc_info", MINIDUMP_STREAM_TYPE.MiscInfoStream)
    misc_info = getattr(mf, "misc_info", None)
    raw_pid = getattr(misc_info, "ProcessId", None) if misc_info is not None else None
    raw_time = getattr(misc_info, "ProcessCreateTime", None) if misc_info is not None else None
    pid = normalize_pid(raw_pid)
    time_utc = format_process_create_time_utc(raw_time)
    return MiscInfoClaim(
        pid=pid,
        process_create_time_utc=time_utc,
        raw_pid=None if pid is not None else _raw_int_or_str(raw_pid),
        raw_process_create_time=None if time_utc is not None else _raw_int_or_str(raw_time),
        source_state=source_state,
        failure_detail=failure_detail,
    )


def _build_peb_claim(mf) -> PebClaim:
    """Same raw-preservation rule as _build_misc_info_claim() -- see its
    docstring. `source_state` is ABSENT/PRESENT only (see PebClaim's own
    docstring for why PEB never reaches FAILED)."""
    peb = getattr(mf, "peb", None)
    source_state = SourceState.PRESENT if peb is not None else SourceState.ABSENT
    raw_base = getattr(peb, "image_base_address", None) if peb is not None else None
    raw_path = getattr(peb, "image_path", None) if peb is not None else None
    raw_cmd = getattr(peb, "command_line", None) if peb is not None else None
    image_base = normalize_image_base(raw_base)
    image_path = normalize_windows_path(raw_path)
    command_line = normalize_command_line(raw_cmd)
    return PebClaim(
        image_base_address=image_base,
        image_path=image_path,
        name=_windows_basename(image_path),
        command_line=command_line,
        raw_image_base_address=None if image_base is not None else _raw_address_hex_or_str(raw_base),
        raw_image_path=None if image_path is not None else _raw_str(raw_path),
        raw_command_line=None if command_line is not None else _raw_str(raw_cmd),
        source_state=source_state,
    )


def _build_module_claim(mf, peb_claim: PebClaim):
    """-> (ModuleClaim, name_matched_candidate_count). The count is
    needed only to render PROCESS_MODULE_NAME_AMBIGUOUS's `count` detail
    and is not part of the frozen ModuleClaim shape itself (§3.4.3 has no
    such field -- only the boolean). `modules_source_state`/
    `modules_failure_detail` are attached to every returned ModuleClaim
    regardless of match_state, so an absent and a failed ModuleListStream
    both surface as match_state == "unavailable" yet remain
    distinguishable through those two fields."""
    modules_source_state, modules_failure_detail = _stream_source_state(
        mf, "modules", MINIDUMP_STREAM_TYPE.ModuleListStream)
    modules_stream = getattr(mf, "modules", None)
    modules_available = modules_stream is not None
    modules = list(getattr(modules_stream, "modules", None) or [])

    def _claim(**kwargs):
        return ModuleClaim(modules_source_state=modules_source_state,
                            modules_failure_detail=modules_failure_detail, **kwargs)

    base = peb_claim.image_base_address
    if base is None or not modules_available:
        return (_claim(match_state="unavailable", base_address=None, name=None, path=None,
                        name_matched_candidate=None, name_matched_candidate_ambiguous=False),
                0)

    resolved = resolve_module_by_base(base, modules)
    if resolved is not None:
        ref = _module_reference(resolved)
        if ref is not None:
            return (_claim(match_state="resolved", base_address=ref.base_address,
                            name=ref.name, path=ref.path, name_matched_candidate=None,
                            name_matched_candidate_ambiguous=False),
                    0)
        # A module IS registered at this exact base, but its own base
        # address is malformed enough that _module_reference() refused
        # it -- treat identically to "no module registered here" rather
        # than fabricate a claim from data dumpex will not certify.

    target = peb_claim.name.lower() if peb_claim.name else None
    candidates = []
    if target:
        for m in modules:
            ref = _module_reference(m)
            if ref is not None and ref.name is not None and ref.name.lower() == target:
                candidates.append(ref)

    return (_claim(match_state="unregistered", base_address=None, name=None, path=None,
                    name_matched_candidate=candidates[0] if candidates else None,
                    name_matched_candidate_ambiguous=len(candidates) > 1),
            len(candidates))


MAIN_IMAGE_PE_READ_MAX = 4096   # bytes read at the normalized image base for
                                 # structural PE validation -- matches
                                 # dumpex.hunt.stomping.config.PE_VALIDATE_READ_MAX,
                                 # the codebase's existing module-header read
                                 # size convention.


def _build_main_image_pe_claim(mf, image_base: "int | None") -> MainImagePeClaim:
    """§3.4.4's main_image_pe, built once here so --process/--sysinfo and
    any later Recon/Hunt consumer never each re-read and re-validate the
    same main-image PE header for one invocation. `image_base` is always
    peb_claim.image_base_address (§3.3.4 -- never a module-fallback
    base). Uses va_range_captured_bytes() first, rather than requesting
    the full MAIN_IMAGE_PE_READ_MAX outright, so a main image whose
    capture is shorter than that (but still non-empty) is still checked
    against however many bytes really are there, instead of failing the
    read entirely over a boundary read_region() would otherwise raise
    on."""
    if image_base is None:
        return MainImagePeClaim(checked=False, valid=None, reason=None)
    captured = va_range_captured_bytes(mf, image_base, MAIN_IMAGE_PE_READ_MAX)
    if not captured:
        return MainImagePeClaim(checked=False, valid=None, reason=None)
    try:
        data = read_region(mf, image_base, captured)
    except Exception:
        return MainImagePeClaim(checked=False, valid=None, reason=None)
    if not data:
        return MainImagePeClaim(checked=False, valid=None, reason=None)
    result = parse_pe_header(data)
    return MainImagePeClaim(checked=True, valid=result["valid"], reason=result["reason"] or None)


def build_process_identity_snapshot(mf) -> ProcessIdentitySnapshot:
    """The single, shared reduction of MiscInfo + PEB + ModuleList into
    one immutable process-identity result (§3.3/§3.4). Pure and silent:
    reads mf.misc_info/mf.peb/mf.modules, never mutates them, never
    prints, and never hands a raw parser object back to the caller.

    Path/name precedence (§3.3.1/§3.3.3): peb_claim.image_path wins when
    present; otherwise, when module_claim resolves (which requires a
    normalized PEB image base AND ModuleListStream present -- §3.3.3),
    the resolved module's own path/name are used instead, and a
    PROCESS_PATH_SOURCE_FALLBACK diagnostic records that the fallback
    fired. Neither source's own claim is ever overwritten by the other
    (§3.3.4) -- peb_claim/module_claim always stay independently
    readable in the returned snapshot regardless of which one "won".

    module_claim itself is computed whenever the PEB image base
    normalized and ModuleListStream is present, REGARDLESS of whether
    the PEB already supplied a path -- so a PEB with its own valid path
    can still surface a PROCESS_MODULE_BASE_CONFLICT/_UNMATCHED
    diagnostic about a disagreeing ModuleListStream, without that
    disagreement ever touching image_base_address or the selected path.

    Diagnostics fire in §6.2's declaration order: PROCESS_MODULE_BASE_
    UNMATCHED or _CONFLICT (mutually exclusive, only for match_state ==
    "unregistered"), then _NAME_AMBIGUOUS alongside either, then
    _IDENTITY_MISMATCH (only for match_state == "resolved", when the
    resolved module's own name disagrees with peb_claim.name), then
    _PATH_SOURCE_FALLBACK (only when the module claim was actually used
    as the path source)."""
    misc_info_claim = _build_misc_info_claim(mf)
    peb_claim = _build_peb_claim(mf)
    module_claim, ambiguous_count = _build_module_claim(mf, peb_claim)
    main_image_pe = _build_main_image_pe_claim(mf, peb_claim.image_base_address)

    if peb_claim.image_path is not None:
        selected_path_source = "peb"
        selected_process_path = peb_claim.image_path
        selected_process_name = peb_claim.name
    elif module_claim.match_state == "resolved":
        selected_path_source = "module"
        selected_process_path = module_claim.path
        selected_process_name = module_claim.name
    else:
        selected_path_source = None
        selected_process_path = None
        selected_process_name = None

    diagnostics = []

    if module_claim.match_state == "unregistered":
        if module_claim.name_matched_candidate is not None:
            c = module_claim.name_matched_candidate
            diagnostics.append(ProcessDiagnostic(
                code="PROCESS_MODULE_BASE_CONFLICT", severity="warning",
                message=(f"a module named {c.name} is loaded at {_hex_or_none(c.base_address)}, "
                         f"not the PEB-reported image base {_hex_or_none(peb_claim.image_base_address)}"),
                details=MappingProxyType({
                    "name": c.name, "module_base": _hex_or_none(c.base_address),
                    "peb_base": _hex_or_none(peb_claim.image_base_address)})))
        else:
            diagnostics.append(ProcessDiagnostic(
                code="PROCESS_MODULE_BASE_UNMATCHED", severity="info",
                message=("no module in ModuleListStream is registered at the PEB-reported "
                         f"image base {_hex_or_none(peb_claim.image_base_address)}"),
                details=MappingProxyType({"peb_base": _hex_or_none(peb_claim.image_base_address)})))
        if module_claim.name_matched_candidate_ambiguous:
            c = module_claim.name_matched_candidate
            diagnostics.append(ProcessDiagnostic(
                code="PROCESS_MODULE_NAME_AMBIGUOUS", severity="info",
                message=f"{ambiguous_count} modules share the name {c.name}; only the first is reported",
                details=MappingProxyType({"name": c.name, "count": ambiguous_count})))

    if (module_claim.match_state == "resolved" and peb_claim.name is not None
            and module_claim.name is not None and peb_claim.name.lower() != module_claim.name.lower()):
        diagnostics.append(ProcessDiagnostic(
            code="PROCESS_MODULE_IDENTITY_MISMATCH", severity="warning",
            message=(f"PEB image path basename ({peb_claim.name}) disagrees with the matched "
                     f"module's own name ({module_claim.name})"),
            details=MappingProxyType({"peb_name": peb_claim.name, "module_name": module_claim.name})))

    if selected_path_source == "module":
        diagnostics.append(ProcessDiagnostic(
            code="PROCESS_PATH_SOURCE_FALLBACK", severity="info",
            message=(f"process path was taken from ModuleListStream ({module_claim.path}); "
                     f"the PEB supplied none"),
            details=MappingProxyType({"module_path": module_claim.path})))

    return ProcessIdentitySnapshot(
        misc_info_claim=misc_info_claim, peb_claim=peb_claim, module_claim=module_claim,
        main_image_pe=main_image_pe,
        selected_path_source=selected_path_source, selected_process_path=selected_process_path,
        selected_process_name=selected_process_name, diagnostics=tuple(diagnostics))


# ── §4.2 independent, bounded environment-block walk ────────────────────

MAX_ENV_BYTES   = 65536   # cumulative bytes read across the environment walk
MAX_ENV_ENTRIES = 2048    # entries kept from the environment block

_ENV_READ_CHUNK = 4096   # always even, and every request below is forced
                          # even too -- every read position stays an even
                          # offset from the block's own start, so a UTF-16
                          # code unit can never straddle a chunk boundary


def _env_read_capture(reader, max_bytes: int) -> bytes:
    """Read up to `max_bytes` from `reader`'s current position, in
    bounded, always-even-length chunks, stopping (WITHOUT raising) the
    moment the current memory segment has nothing left to give. Never
    raises: a `move()`/`read()` failure mid-walk just ends the capture
    with whatever was already read, exactly like reaching a genuine
    segment boundary -- the caller distinguishes "why" only through what
    ended up in the returned bytes versus how many were asked for."""
    data = bytearray()
    remaining = max_bytes
    while remaining > 0:
        try:
            segment_left = reader.current_segment.remaining_len(reader.current_position)
        except Exception:
            break
        if not segment_left:
            break
        want = min(_ENV_READ_CHUNK, remaining, segment_left)
        want -= want % 2
        if want <= 0:
            break
        try:
            chunk = reader.read(want)
        except Exception:
            break
        if not chunk:
            break
        data.extend(chunk)
        remaining -= len(chunk)
    return bytes(data)


def _classify_environment_capture(data: bytes, *, max_bytes: int, max_entries: int):
    """The pure, testable half of walk_environment_block(): turn already-
    captured bytes into (state, entries, detail). See that function's
    own docstring for the seven-state contract this implements.

    A verified-empty block is a SPECIAL case, checked before the general
    per-entry walk: it requires FOUR captured, confirmed-zero bytes (a
    zero-length first "entry" immediately followed by the block's own
    extra terminating NUL code unit), not merely the first two -- a
    capture that stops after only two zero bytes cannot prove there
    wasn't more block left to read, so it is `unparseable`, never
    promoted into "the process had no environment" (issue #37 §4.3.2).
    """
    if len(data) >= 4 and data[:4] == b"\x00\x00\x00\x00":
        return ("present_empty", [], None)

    n = len(data)
    entries = []
    pos = 0
    terminator_confirmed = False
    stop_reason = None   # one of the ENVIRONMENT_BLOCK_TRUNCATED §4.3.3 scope tokens

    while True:
        if len(entries) >= max_entries:
            stop_reason = "environment_entries"
            break

        entry_start = pos
        raw = bytearray()
        found_terminator = False
        while pos + 2 <= n:
            code_unit = data[pos:pos + 2]
            pos += 2
            if code_unit == b"\x00\x00":
                found_terminator = True
                break
            raw += code_unit

        if not found_terminator:
            pos = entry_start
            stop_reason = "environment_bytes" if n >= max_bytes else "captured_segment"
            break

        if not raw:
            if not entries:
                # A zero-length FIRST "entry" without the special 4-byte
                # confirmation above (which already ran and failed) is not
                # trustworthy on its own -- a single captured NUL code
                # unit at the very start cannot prove there wasn't more
                # block left to read. Falls through as an unconfirmed
                # stop with zero entries, i.e. unparseable, matching "only
                # two captured zero bytes" in the #37 contract.
                break
            terminator_confirmed = True
            break

        try:
            entries.append(bytes(raw).decode("utf-16-le"))
        except UnicodeDecodeError:
            pos = entry_start
            stop_reason = "undecodable_entry"
            break

    if terminator_confirmed:
        return ("present", entries, None)
    if entries:
        return ("partial", entries, stop_reason)
    return ("unparseable", None, stop_reason)


def walk_environment_block(mf, max_bytes: int = MAX_ENV_BYTES, max_entries: int = MAX_ENV_ENTRIES):
    """-> (state, entries, detail). Never raises.

    Independently re-derives every pointer (TEB -> PEB -> ProcessParameters
    -> Environment) itself, using the SAME offset table the library reads
    (minidump.structures.peb.PEB_OFFSETS -- not a second, hand-copied
    table) -- it works even when PEB.from_minidump() itself failed and
    left mf.peb as None, and it never reads mf.peb.

    `state` is one of a closed set of seven:
      "unsupported"             -- sysinfo/threads absent -- no TEB to
                                    start from (the same precondition the
                                    library's own PEB build needs)
      "architecture_unsupported"-- sysinfo present but ProcessorArchitecture
                                    is neither AMD64 nor INTEL (e.g. ARM64,
                                    which the library silently mis-offsets
                                    as x64 rather than refusing)
      "pointer_unreadable"      -- one of the three pointer reads failed,
                                    short-read, or was null
      "present_empty"           -- a verified, fully-captured empty block
      "present"                 -- >=1 entries and a confirmed block terminator
      "partial"                 -- >=1 entries, terminator never confirmed
                                    (budget, captured-segment end, or an
                                    undecodable entry stopped the walk)
      "unparseable"             -- 0 entries and no confirmed terminator

    `entries` is a list of raw `"name=value"` strings (never split here --
    see dumpex's #37 §4.4 for the `=`-prefixed reconstruction rule, which
    belongs to the command layer, not this walk) for "present"/"partial",
    `[]` for "present_empty", `None` otherwise.

    `detail` is one of the ENVIRONMENT_BLOCK_TRUNCATED scope tokens
    ("environment_bytes" | "environment_entries" | "captured_segment" |
    "undecodable_entry") for "partial"/"unparseable" whenever a stop
    reason is known; a short free-text string naming which pointer step
    failed for "pointer_unreadable"; None otherwise.
    """
    sysinfo = getattr(mf, "sysinfo", None)
    threads = getattr(mf, "threads", None)
    if not (sysinfo and threads and getattr(threads, "threads", None)):
        return ("unsupported", None, None)

    arch = getattr(sysinfo, "ProcessorArchitecture", None)
    if arch == PROCESSOR_ARCHITECTURE.AMD64:
        offset_index = 1
    elif arch == PROCESSOR_ARCHITECTURE.INTEL:
        offset_index = 0
    else:
        return ("architecture_unsupported", None, None)

    offsets = PEB_OFFSETS[offset_index]
    ptr_size = 8 if offset_index == 1 else 4
    reader = mf.get_reader().get_buffered_reader()

    def read_pointer(addr, step):
        try:
            reader.move(addr)
            raw = reader.read(ptr_size)
        except Exception as e:
            return None, f"{step} unreadable: {e}"
        if raw is None or len(raw) < ptr_size:
            return None, f"{step} unreadable: short read"
        value = int.from_bytes(raw, "little")
        if value == 0:
            return None, f"{step} is a null pointer"
        return value, None

    teb_va = threads.threads[0].Teb
    peb_va, detail = read_pointer(teb_va + offsets["peb"], "TEB->PEB pointer")
    if peb_va is None:
        return ("pointer_unreadable", None, detail)

    pp_va, detail = read_pointer(peb_va + offsets["process_parameters"],
                                  "PEB->ProcessParameters pointer")
    if pp_va is None:
        return ("pointer_unreadable", None, detail)

    env_va, detail = read_pointer(pp_va + offsets["environment_variables"],
                                   "ProcessParameters->Environment pointer")
    if env_va is None:
        return ("pointer_unreadable", None, detail)

    try:
        reader.move(env_va)
    except Exception as e:
        return ("pointer_unreadable", None, f"Environment block base unreadable: {e}")

    data = _env_read_capture(reader, max_bytes)
    return _classify_environment_capture(data, max_bytes=max_bytes, max_entries=max_entries)


# ── §4.4 special `=`-prefixed entry reconstruction ───────────────────────

@dataclass(frozen=True)
class EnvironmentEntry:
    """One normalized `name=value` pair from walk_environment_block()'s
    raw entries. A plain (name, value) pair, not a mapping -- see
    parse_environment_entries()'s own docstring for why duplicates and
    order must survive."""
    name: str
    value: str


def _split_environment_string(raw: str) -> EnvironmentEntry:
    """§4.4's `=`-prefix reconstruction for ONE raw `"name=value"` string.

    Windows records per-drive working directories as entries whose name
    itself begins with `=` (e.g. `=C:=C:\\Work`). A naive `split("=", 1)`
    yields `name=""`, `value="C:=C:\\Work"` -- losing the real name. Each
    raw string is therefore processed as:

      1. Split once on the first `=`.
      2. If the resulting name is empty AND the value itself contains an
         `=`, re-split the value on ITS first `=` and reconstruct
         `name = "=" + left`, `value = right`.
      3. An entry with no `=` at all keeps the whole string as `name` and
         `""` as `value` -- a genuinely nameless/valueless block entry is
         preserved, not dropped."""
    name, sep, value = raw.partition("=")
    if not sep:
        return EnvironmentEntry(name=raw, value="")
    if name == "" and "=" in value:
        left, _, right = value.partition("=")
        return EnvironmentEntry(name="=" + left, value=right)
    return EnvironmentEntry(name=name, value=value)


def parse_environment_entries(raw_entries) -> tuple:
    """Normalize a heterogeneous list of environment entries -> a tuple
    of EnvironmentEntry. Returns `()` for `None` or an empty list --
    callers distinguish "no entries" from "walk didn't run" via
    walk_environment_block()'s own `state`, not via this function's
    return value.

    Three input shapes are accepted, per entry (a single `raw_entries`
    list may freely mix them):

      - `str`: walk_environment_block()'s own raw `"name=value"` output
        -- goes through _split_environment_string()'s §4.4 reconstruction.
      - a mapping with a `"name"` key (`{"name": ..., "value": ...}`,
        `"value"` optional) -- the shape the installed `minidump`
        library's OWN `PEB.from_minidump()` already produces for
        `peb.environment_variables`, so a caller consuming that directly
        (rather than walk_environment_block()'s independent re-walk)
        normalizes through the same function; or a single-key mapping
        (`{"A": "1"}`), read as one (name, value) pair.
      - a 2-item tuple/list (`("A", "1")` or `["A", "1"]`) -- already-
        split name/value pairs from any other source.

    Every already-split name/value (from a mapping or tuple/list -- NOT
    a raw string, which still gets §4.4's reconstruction) is copied
    through str() immediately, so neither a later mutation of the
    caller's own input container nor a non-string name/value (e.g. a
    stray int) can leave anything but a plain, frozen string in the
    result -- consistent with the rest of this module never retaining a
    live reference into caller-owned data.

    Anything else raises TypeError immediately (a caller passing an
    unrecognized shape deserves a clear, immediate error, not a silently
    wrong EnvironmentEntry).

    Result stays a tuple of records, never a dict/mapping: duplicate
    names, `=`-prefixed names, and source order are all real forensic
    evidence a dict would silently destroy (last-write-wins on a
    duplicate key, and no stable iteration order guarantee across
    entries with the same name)."""
    if not raw_entries:
        return ()

    entries = []
    for raw in raw_entries:
        if isinstance(raw, str):
            entries.append(_split_environment_string(raw))
        elif isinstance(raw, Mapping):
            if "name" in raw:
                entries.append(EnvironmentEntry(name=_safe_str(raw["name"]),
                                                 value=_safe_str(raw.get("value", ""))))
            elif len(raw) == 1:
                (key, value), = raw.items()
                entries.append(EnvironmentEntry(name=_safe_str(key), value=_safe_str(value)))
            else:
                raise TypeError(
                    f"parse_environment_entries(): a mapping entry must have a 'name' key "
                    f"or exactly one key/value pair, got keys {list(raw.keys())!r}")
        elif isinstance(raw, (tuple, list)) and len(raw) == 2:
            name, value = raw
            entries.append(EnvironmentEntry(name=_safe_str(name), value=_safe_str(value)))
        else:
            raise TypeError(
                f"parse_environment_entries(): unsupported entry shape {type(raw).__name__!r} "
                f"(expected str, a name/value mapping, or a 2-item tuple/list)")
    return tuple(entries)

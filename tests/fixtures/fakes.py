"""
Lightweight fakes for exercising dumpex.hunt.* modules without a real
.dmp file. Plain classes, no framework dependency of their own — matches
this project's own dependency-light philosophy (dumpex's own runtime
deps are just minidump/colorama/pyyaml, with yara-python optional).

Every class here mirrors just the attributes the hunt modules actually
read off the real `minidump` library objects (MinidumpMemoryInfo,
MinidumpModule, MINIDUMP_THREAD, MinidumpThreadInfo,
MinidumpHandleDescriptor) — see dumpex/core/memory.py for the real
counterparts.
"""
import struct

from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE
from minidump.structures.peb import PEB_OFFSETS


class Prot:
    """Stand-in for a minidump enum value (has a `.name` attribute)."""
    def __init__(self, name):
        self.name = name


class Region:
    """Stand-in for MinidumpMemoryInfo."""
    def __init__(self, base, alloc, size, state, protect, mtype):
        self.BaseAddress    = base
        self.AllocationBase = alloc
        self.RegionSize     = size
        self.State          = Prot(state)
        self.Protect        = Prot(protect)
        self.Type           = Prot(mtype)


class Module:
    """Stand-in for MinidumpModule."""
    def __init__(self, base, size, name):
        self.baseaddress = base
        self.endaddress   = base + size
        self.size         = size
        self.name         = name


class ThreadInfo:
    """Stand-in for MinidumpThreadInfo (ThreadInfoListStream entry).
    CreateTime/ExitTime/KernelTime/UserTime/ExitStatus/DumpFlags are all
    optional (default None, matching "not read off this fixture at all"
    via dumpex.commands.threads' getattr(..., default) calls) -- pass
    create_time explicitly to build a "real" entry with actual timing
    data, e.g. for a mixed real+placeholder ThreadRecord test."""
    def __init__(self, tid, start_address, *, create_time=None, exit_time=None,
                 kernel_time=None, user_time=None, exit_status=None, dump_flags=None):
        self.ThreadId     = tid
        self.StartAddress = start_address
        self.CreateTime   = create_time
        self.ExitTime     = exit_time
        self.KernelTime   = kernel_time
        self.UserTime     = user_time
        self.ExitStatus   = exit_status
        self.DumpFlags    = dump_flags


class Ctx:
    """Stand-in for a parsed x64 CONTEXT (only the field hunt modules read)."""
    def __init__(self, rip):
        self.Rip = rip


class Thread:
    """Stand-in for MINIDUMP_THREAD (ThreadListStream entry) with a context already attached."""
    def __init__(self, tid, ctx):
        self.ThreadId     = tid
        self.ContextObject = ctx


class Handle:
    """Stand-in for MinidumpHandleDescriptor (HandleDataStream entry)."""
    def __init__(self, handle, typename, objname, access=0x12019f):
        self.Handle         = handle
        self.TypeName       = typename
        self.ObjectName     = objname
        self.GrantedAccess  = access
        self.HandleCount    = 1
        self.PointerCount   = 1


class FakeStream:
    """Stand-in for a MinidumpXxxList wrapper object (`.infos`, `.modules`, `.threads`, `.handles`)."""
    def __init__(self, items, attr):
        setattr(self, attr, items)


class Segment:
    """Stand-in for a Memory64ListStream entry (dumpex.hunt.cs_beacon walks
    these; dumpex.core.memory.va_to_file_offset()/va_range_captured_bytes()
    read the real minidump library's own segment objects the same way)."""
    def __init__(self, start_virtual_address, start_file_address, size):
        self.start_virtual_address = start_virtual_address
        self.start_file_address    = start_file_address
        self.size                  = size
        self.end_virtual_address   = start_virtual_address + size


class FakeReader:
    """
    Stand-in for MinidumpFile.get_reader()'s return value — cs_beacon/scanner.py
    calls reader.read(va, size) directly (unlike the rest of the hunt
    modules, which go through core.memory.read_region).
    """
    def __init__(self, read_map):
        self._read_map = read_map

    def read(self, addr, size):
        for base, data in self._read_map.items():
            if base <= addr < base + len(data):
                off = addr - base
                return data[off:off + size]
        return b''


class Peb:
    """Stand-in for MinidumpFile.peb. Started as hunt/hollowing.py's
    minimal (image_base_address, image_path) subset; extended with the
    remaining fields dumpex.commands.peb/sysinfo read (address,
    being_debugged, command_line, window_title, dll_path,
    current_directory, standard_input/output/error,
    environment_variables) -- all optional, defaulting to None/empty so
    existing two-positional-arg callers are unaffected."""
    def __init__(self, image_base_address, image_path, *, address=0,
                 being_debugged=False, command_line=None, window_title=None,
                 dll_path=None, current_directory=None,
                 standard_input=None, standard_output=None, standard_error=None,
                 environment_variables=None):
        self.address                = address
        self.image_base_address     = image_base_address
        self.image_path             = image_path
        self.being_debugged         = being_debugged
        self.command_line           = command_line
        self.window_title           = window_title
        self.dll_path               = dll_path
        self.current_directory      = current_directory
        self.standard_input         = standard_input
        self.standard_output        = standard_output
        self.standard_error         = standard_error
        self.environment_variables  = environment_variables


class EnumVal:
    """Alias of Prot -- stand-in for a minidump enum value (has .name).
    Named separately so sysinfo-related fakes read clearly (ProductType/
    ProcessorArchitecture are conceptually enums, not protection flags)."""
    def __init__(self, name):
        self.name = name


class SysInfo:
    """Stand-in for MinidumpFile.sysinfo (SystemInfoStream). `processor_
    architecture` defaults to the REAL minidump.streams.SystemInfoStream.
    PROCESSOR_ARCHITECTURE.AMD64 enum member (not a generic EnumVal
    string stand-in like ProductType below) -- dumpex.core.process_info.
    walk_environment_block() compares mf.sysinfo.ProcessorArchitecture
    against that real enum with `==`, and a bare object with only a
    matching `.name` never compares equal to it. Passing a plain string
    still works (wrapped in EnumVal, `.name` only) for a caller that
    deliberately wants an architecture walk_environment_block() cannot
    recognize."""
    def __init__(self, *, major_version=10, minor_version=0, build_number=19041,
                 operating_system="Windows 10", csd_version=None,
                 processor_architecture=PROCESSOR_ARCHITECTURE.AMD64,
                 product_type="VER_NT_WORKSTATION", number_of_processors=4,
                 vendor_id=b"GenuineIntel"):
        self.MajorVersion           = major_version
        self.MinorVersion           = minor_version
        self.BuildNumber            = build_number
        self.OperatingSystem        = operating_system
        self.CSDVersion             = csd_version
        if processor_architecture is None:
            self.ProcessorArchitecture = None
        elif isinstance(processor_architecture, str):
            self.ProcessorArchitecture = EnumVal(processor_architecture)
        else:
            self.ProcessorArchitecture = processor_architecture
        self.ProductType            = EnumVal(product_type) if product_type else None
        self.NumberOfProcessors     = number_of_processors
        self.VendorId               = vendor_id


class MiscInfo:
    """Stand-in for MinidumpFile.misc_info (MINIDUMP_MISC_INFO)."""
    def __init__(self, *, process_id=None, process_create_time=None,
                 process_user_time=None, process_kernel_time=None,
                 processor_current_mhz=None, processor_max_mhz=None):
        self.ProcessId            = process_id
        self.ProcessCreateTime    = process_create_time
        self.ProcessUserTime      = process_user_time
        self.ProcessKernelTime    = process_kernel_time
        self.ProcessorCurrentMhz  = processor_current_mhz
        self.ProcessorMaxMhz      = processor_max_mhz


class ExceptionStream:
    """Stand-in for MinidumpFile.exception (ExceptionStream) -- only the
    field dumpex.commands.sysinfo.collect_pid reads as a last-resort TID."""
    def __init__(self, thread_id):
        self.ThreadId = thread_id


class FakeMF:
    """
    Stand-in MinidumpFile. Every stream defaults to None (== "not present
    in this dump", matching a real MinidumpFile whose stream attributes
    are all None until MinidumpFile.parse() populates the ones the dump
    actually contains) — tests opt in to whichever streams they need.
    """
    memory_info         = None
    modules              = None
    thread_info           = None
    threads               = None
    handles                = None
    memory_segments_64      = None
    memory_segments          = None
    peb                       = None
    sysinfo                   = None
    misc_info                  = None
    exception                   = None
    filename                     = "test.dmp"
    _reader                   = None

    def get_reader(self):
        return self._reader


# ── environment-block walk fake ───────────────────────────────────────────
# A minimal stand-in for MinidumpBufferedReader (minidump.minidumpreader),
# just enough of .move()/.read()/.current_segment/.current_position to
# exercise dumpex.core.process_info.walk_environment_block()'s real
# pointer-chasing and read logic without a real .dmp file. FakeMF.get_reader()
# returns self._reader directly (no get_buffered_reader() layer of its own),
# so wire_environment_walk() below wraps the buffered reader in EnvReader to
# supply that layer, matching what walk_environment_block() actually calls
# (mf.get_reader().get_buffered_reader()).

class EnvSegment:
    def __init__(self, start, data):
        self.start_address = start
        self.data = data
        self.end_address = start + len(data)

    def remaining_len(self, position):
        if not (self.start_address <= position < self.end_address):
            return None
        return self.end_address - position


class _RemainingLenFaultSegment(EnvSegment):
    """EnvSegment whose remaining_len() raises once `position` reaches
    `fault_at` -- see EnvBufferedReader's own docstring for why."""
    def __init__(self, start, data, fault_at):
        super().__init__(start, data)
        self._fault_at = fault_at

    def remaining_len(self, position):
        if self._fault_at is not None and position >= self._fault_at:
            raise Exception("Injected remaining_len() failure")
        return super().remaining_len(position)


class EnvBufferedReader:
    """`fault_at`/`fault_kind` (issue #41 P3 -- see
    dumpex.core.process_info._env_read_capture()'s own docstring: "Never
    raises: a move()/read() failure mid-walk just ends the capture with
    whatever was already read") let a test inject exactly one of that
    function's three defensive branches once `current_position` reaches
    `fault_at`, WITHOUT the fault ever hitting the plain segment-boundary
    path _env_read_capture() already exercises unassisted:

      "remaining_len_raises" -- current_segment.remaining_len() raises
      "read_raises"          -- read() raises
      "read_empty"           -- read() returns b"" without raising

    Real bytes are still served for every read that completes BEFORE
    `fault_at`, so a caller can prove entries captured earlier in the
    walk survive the fault, not just that no exception escapes."""
    def __init__(self, segments: dict, *, fault_at: "int | None" = None,
                 fault_kind: "str | None" = None):
        self._fault_at = fault_at
        self._fault_kind = fault_kind
        if fault_kind == "remaining_len_raises":
            self._segments = [_RemainingLenFaultSegment(start, data, fault_at)
                               for start, data in segments.items()]
        else:
            self._segments = [EnvSegment(start, data) for start, data in segments.items()]
        self.current_segment = None
        self.current_position = None

    def move(self, address):
        for seg in self._segments:
            if seg.start_address <= address < seg.end_address:
                self.current_segment = seg
                self.current_position = address
                return
        raise Exception('Memory address 0x%08x is not in process memory space' % address)

    def read(self, size):
        if self._fault_kind == "read_raises" and self.current_position >= self._fault_at:
            raise Exception("Injected read() failure")
        if self._fault_kind == "read_empty" and self.current_position >= self._fault_at:
            return b""
        end = self.current_position + size
        if end > self.current_segment.end_address:
            raise Exception('Would read over segment boundaries!')
        off = self.current_position - self.current_segment.start_address
        data = self.current_segment.data[off:off + size]
        self.current_position = end
        return data


class EnvReader:
    def __init__(self, buffered):
        self._buffered = buffered

    def get_buffered_reader(self):
        return self._buffered


class UnconstructibleEnvReader:
    """Models minidump.minidumpreader.MinidumpFileReader.__init__'s own
    FIRST statement (`self.modules = minidumpfile.modules.modules`),
    unguarded in the real library -- so a scenario whose ModuleListStream
    is absent fails through mf.get_reader() the exact way a real
    open_dump() output would (AttributeError: 'NoneType' object has no
    attribute 'modules'), rather than a FakeMF-specific message a real
    dump would never produce."""
    def __init__(self, modules):
        self._modules = modules

    def get_buffered_reader(self):
        return self._modules.modules


ENV_WALK_TEB_VA            = 0x7FF000000000
ENV_WALK_PEB_VA            = 0x7FF000001000
ENV_WALK_PROCESS_PARAMS_VA = 0x7FF000002000
ENV_WALK_ENV_VA            = 0x7FF000003000


def wire_environment_walk(mf, env_segment_data: bytes, *,
                           teb=ENV_WALK_TEB_VA, peb=ENV_WALK_PEB_VA,
                           process_params=ENV_WALK_PROCESS_PARAMS_VA,
                           env_va=ENV_WALK_ENV_VA, wire_teb_pointer=True,
                           fault_at: "int | None" = None, fault_kind: "str | None" = None):
    """Wires a real x64 TEB->PEB->ProcessParameters->Environment pointer
    chain onto `mf` (whose .sysinfo/.threads are already set, with a real
    minidump.streams.SystemInfoStream.PROCESSOR_ARCHITECTURE.AMD64/INTEL
    value on .sysinfo.ProcessorArchitecture -- see SysInfo's own default
    above) so dumpex.core.process_info.walk_environment_block(mf) actually
    walks `env_segment_data` instead of short-circuiting on precondition/
    architecture checks. `wire_teb_pointer=False` omits the very first
    pointer's own backing segment, to exercise the pointer_unreadable
    branch instead. Sets mf.threads.threads[0].Teb to `teb` as a side
    effect -- `mf.threads` must already be populated with at least one
    thread before calling this. `fault_at`/`fault_kind` (an absolute VA
    within `env_segment_data`'s own segment, and one of EnvBufferedReader's
    three fault kinds) inject a bounded-read failure partway through the
    capture -- see that class's own docstring."""
    segments = {}
    if wire_teb_pointer:
        segments[teb + PEB_OFFSETS[1]["peb"]] = peb.to_bytes(8, "little")
    segments[peb + PEB_OFFSETS[1]["process_parameters"]] = process_params.to_bytes(8, "little")
    segments[process_params + PEB_OFFSETS[1]["environment_variables"]] = env_va.to_bytes(8, "little")
    segments[env_va] = env_segment_data
    mf._reader = EnvReader(EnvBufferedReader(segments, fault_at=fault_at, fault_kind=fault_kind))
    mf.threads.threads[0].Teb = teb


def build_pe_header(sections, machine=0x8664, timestamp=0x12345678,
                     size_of_image=0x5000, image_base=0x140000000,
                     entry_point=0x1000, trailing_padding=0x200):
    """
    Build a minimal, structurally-valid PE32+ header + section table as
    raw bytes — enough for dumpex.core.pe_utils.parse_pe_header() to
    accept it. `sections` is a list of dicts:
      {"name": bytes, "vaddr": int, "vsize": int, "rawptr": int,
       "rawsize": int, "chars": int}
    """
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, e_lfanew)
    buf = bytearray(dos) + b'PE\x00\x00'
    opt_hdr_size = 224
    buf += struct.pack('<HHIIIHH', machine, len(sections), timestamp, 0, 0, opt_hdr_size, 0x0102)
    opt = bytearray(opt_hdr_size)
    struct.pack_into('<H', opt, 0, 0x20b)              # PE32+ magic
    struct.pack_into('<I', opt, 16, entry_point)
    struct.pack_into('<Q', opt, 24, image_base)
    struct.pack_into('<I', opt, 56, size_of_image)
    buf += opt
    for s in sections:
        rec = bytearray(40)
        rec[0:8] = s["name"][:8].ljust(8, b'\x00')
        struct.pack_into('<IIII', rec, 8, s["vsize"], s["vaddr"], s["rawsize"], s["rawptr"])
        struct.pack_into('<I', rec, 36, s["chars"])
        buf += rec
    return bytes(buf) + b'\x00' * trailing_padding


# PE section Characteristics flags (see dumpex.core.pe_utils)
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ    = 0x40000000
IMAGE_SCN_MEM_WRITE   = 0x80000000

TEXT_SECTION_RX  = {"name": b".text", "vaddr": 0x1000, "vsize": 0x2000,
                     "rawptr": 0x400, "rawsize": 0x2000,
                     "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}


def mem_reader(read_map):
    """Build a read_region(mf, addr, size) fake backed by {base: bytes} entries."""
    def _read(mf, addr, size):
        for base, data in read_map.items():
            if base <= addr < base + len(data):
                off = addr - base
                return data[off:off + size]
        return b'\x00' * size
    return _read


def matching_module_and_ref(module_base=0x7ff600000000, timestamp=0x11111111,
                             text_bytes=None):
    """
    Build a (header_bytes, mem_text_bytes, ref_file_bytes, section) tuple
    for a single-.text-section module where the in-memory content and the
    on-disk reference content are IDENTICAL (and loaded at the same
    address as the preferred ImageBase, so the relocation delta is 0) —
    the baseline "nothing changed" fixture several stomping tests build
    on.
    """
    section = dict(TEXT_SECTION_RX)
    header = build_pe_header([section], timestamp=timestamp, size_of_image=0x5000,
                              image_base=module_base)   # loaded at its preferred base
    text_bytes = text_bytes or bytes((i * 7) % 251 for i in range(section["vsize"]))
    ref_file = bytearray(header)
    ref_file += b'\x00' * (section["rawptr"] - len(ref_file))
    ref_file += text_bytes
    return header, text_bytes, bytes(ref_file), section


def cs_beacon_config_bytes(xor_key: int = 0x69) -> bytes:
    """
    Build a minimal, XOR-encoded CS beacon config TLV blob that passes
    dumpex.hunt.cs_beacon.scanner's _cs_scan_segment and
    dumpex.hunt.cs_beacon.parser's _cs_decode_and_parse_tlv/_cs_sanity_check:
      - field 0x0001 (BeaconType) = 0 ("HTTP", a recognized value)
      - field 0x0007 (PublicKey) raw bytes forming a minimally-valid X.509
        SubjectPublicKeyInfo DER structure: an outer SEQUENCE whose
        declared length fits the buffer, containing an AlgorithmIdentifier
        SEQUENCE carrying the rsaEncryption OID (1.2.840.113549.1.1.1) —
        satisfies dumpex.hunt.cs_beacon.der's _cs_validate_public_key_der(),
        not just a "308" hex prefix (see that module for why the stricter
        check exists)
      - a trailing fid=0 terminator record, required for `complete=True`
        (a TLV blob with no terminator is truncated, not a legitimate
        config, however "clean" its fields otherwise look)
    The plaintext's first 6 bytes are exactly CS_BEACON_SIGNATURE by
    construction (field_id=1, type=1, length=2), so XOR-encoding the
    whole blob with `xor_key` embeds the corresponding pre-XOR marker
    (CS_SIG_XOR69/CS_SIG_XOR2E) at its start.
    """
    def _tlv(fid, ftype, raw):
        return struct.pack('>HHH', fid, ftype, len(raw)) + raw

    beacon_type_field = _tlv(0x0001, 1, struct.pack('>H', 0))

    rsa_encryption_oid = bytes.fromhex('06092a864886f70d010101')   # tag+len+OID value
    der_null            = bytes.fromhex('0500')
    algorithm_id        = bytes([0x30, len(rsa_encryption_oid) + len(der_null)]) \
                           + rsa_encryption_oid + der_null
    bit_string           = bytes([0x03, 0x03, 0x00, 0x30, 0x00])   # unused-bits=0 + DER SEQUENCE (RSAPublicKey)
    pubkey_content        = algorithm_id + bit_string
    pubkey_raw            = bytes([0x30, len(pubkey_content)]) + pubkey_content
    pubkey_field = _tlv(0x0007, 3, pubkey_raw)
    terminator = struct.pack('>H', 0)   # fid=0, no type/length follows
    plaintext = beacon_type_field + pubkey_field + terminator
    return bytes(b ^ (xor_key & 0xff) for b in plaintext)

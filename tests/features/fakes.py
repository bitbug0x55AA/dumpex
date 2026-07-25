"""
Lightweight fakes for exercising dumpex.hunt.* modules without a real
.dmp file. Plain classes, no framework dependency of their own — matches
this project's own dependency-light philosophy (dumpex's own runtime
deps are just minidump/colorama, with pyyaml/yara-python optional).

Every class here mirrors just the attributes the hunt modules actually
read off the real `minidump` library objects (MinidumpMemoryInfo,
MinidumpModule, MINIDUMP_THREAD, MinidumpThreadInfo,
MinidumpHandleDescriptor) — see dumpex/core/memory.py for the real
counterparts.
"""
import struct


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
    """Stand-in for MinidumpThreadInfo (ThreadInfoListStream entry)."""
    def __init__(self, tid, start_address):
        self.ThreadId     = tid
        self.StartAddress = start_address


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

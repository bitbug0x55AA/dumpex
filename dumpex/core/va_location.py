"""Resolve one virtual address to the module, section, and captured
region that describe it.

This is the structural join the report's PE, instruction, and IAT
correlation walk repeatedly: given a branch target, a live thunk target,
or an anchor address, say which loaded module owns it, which section of
that module's image it falls in, and what the region table records for
the page. It reads only value views the caller already has -- the raw
module list, the neutral :class:`~dumpex.core.va_range.CapturedRegion`
enumeration, and an optional :class:`~dumpex.core.pe_profile.PeImageProfile`
for the owning module -- and resolves no bytes of its own.

A ``None`` field is "this evidence does not describe the address", never
a claim the address is invalid. Section fields are ``None`` unless the
caller supplies the profile for the module the address lands in.
"""
from dataclasses import dataclass

from dumpex.core.memory import addr_to_module
from dumpex.core.pe_correlation import section_interval
from dumpex.core.va_range import region_containing

__all__ = ["VaLocation", "resolve_va_location"]

REGISTRATION_REGISTERED = "registered"       # a loaded module's range holds the address
REGISTRATION_UNREGISTERED = "unregistered"   # a module list was available and none holds it
REGISTRATION_UNAVAILABLE = "unavailable"     # no module list to resolve registration against


@dataclass(frozen=True)
class VaLocation:
    """Where one virtual address lives, as three independent evidence
    sources describe it.

    ``registration`` distinguishes an address inside a loaded module from
    one that is merely inside a committed private region from one that
    cannot be placed at all -- the middle case is an investigation lead,
    not a defect. ``module_rva`` is ``va - module_base`` when a module
    owns the address. The ``section_*`` fields are populated only when the
    caller supplied the owning module's profile.
    """
    va: int
    registration: str
    module_name: "str | None" = None
    module_base: "int | None" = None
    module_end: "int | None" = None
    module_rva: "int | None" = None
    section_index: "int | None" = None
    section_name: "str | None" = None
    section_characteristics: "int | None" = None
    section_executable: "bool | None" = None
    section_writable: "bool | None" = None
    section_readable: "bool | None" = None
    region_base: "int | None" = None
    region_size: "int | None" = None
    region_state: "str | None" = None
    region_type: "str | None" = None
    region_protection: "str | None" = None
    region_allocation_base: "int | None" = None

    @property
    def in_region(self) -> bool:
        return self.region_base is not None

    @property
    def in_module(self) -> bool:
        return self.module_base is not None


def resolve_va_location(va: int, *, modules=(), region_views=(),
                        module_profile=None) -> VaLocation:
    """Resolve ``va`` against ``modules`` (raw minidump module objects),
    ``region_views`` (an iterable of
    :class:`~dumpex.core.va_range.CapturedRegion`), and an optional
    ``module_profile`` for the module that owns ``va``.

    ``module_profile`` is only consulted when its ``actual_base`` matches
    the module resolved for ``va``: a profile for a different image tells
    this address nothing, and pairing them would report a foreign section
    layout.
    """
    module = addr_to_module(va, modules) if modules else None
    if module is not None:
        registration = REGISTRATION_REGISTERED
    elif modules:
        registration = REGISTRATION_UNREGISTERED
    else:
        registration = REGISTRATION_UNAVAILABLE

    module_name = module_base = module_end = module_rva = None
    if module is not None:
        module_name = getattr(module, "name", None)
        module_base = getattr(module, "baseaddress", None)
        module_end = getattr(module, "endaddress", None)
        if isinstance(module_base, int):
            module_rva = va - module_base

    section_index = section_name = section_characteristics = None
    section_executable = section_writable = section_readable = None
    if (module_profile is not None and module_rva is not None
            and getattr(module_profile, "actual_base", None) == module_base):
        for section in module_profile.sections:
            interval = section_interval(section)
            if interval is not None and interval[0] <= module_rva < interval[1]:
                section_index = section.section_index
                section_name = section.name
                section_characteristics = section.characteristics
                section_executable = section.is_executable
                section_writable = section.is_writable
                section_readable = section.is_readable
                break

    region = region_containing(va, region_views) if region_views else None
    region_base = region_size = region_state = region_type = None
    region_protection = region_allocation_base = None
    if region is not None:
        region_base = region.base_address
        region_size = region.size
        region_state = region.state
        region_type = region.type
        region_protection = region.protection
        region_allocation_base = region.allocation_base

    return VaLocation(
        va=va, registration=registration,
        module_name=module_name, module_base=module_base, module_end=module_end,
        module_rva=module_rva,
        section_index=section_index, section_name=section_name,
        section_characteristics=section_characteristics,
        section_executable=section_executable, section_writable=section_writable,
        section_readable=section_readable,
        region_base=region_base, region_size=region_size, region_state=region_state,
        region_type=region_type, region_protection=region_protection,
        region_allocation_base=region_allocation_base)

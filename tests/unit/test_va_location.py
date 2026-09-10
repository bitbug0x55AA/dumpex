"""The structural VA -> (module, section, region) join."""
import types

from dumpex.core.pe_profile import SectionDescriptor
from dumpex.core.va_location import (
    REGISTRATION_REGISTERED, REGISTRATION_UNAVAILABLE, REGISTRATION_UNREGISTERED,
    resolve_va_location,
)
from dumpex.core.va_range import CapturedRegion, VirtualRange

from tests.fixtures.fakes import Module

IMAGE_BASE = 0x140000000


def _section(index, name, vaddr, vsize, *, x=False, w=False, r=True):
    return SectionDescriptor(
        section_index=index, name=name, virtual_size=vsize, virtual_address=vaddr,
        size_of_raw_data=vsize, pointer_to_raw_data=0, pointer_to_relocations=0,
        pointer_to_linenumbers=0, number_of_relocations=0, number_of_linenumbers=0,
        characteristics=0x60000020 if x else 0x40000040,
        is_executable=x, is_writable=w, is_readable=r)


def _profile(base, sections):
    return types.SimpleNamespace(actual_base=base, sections=tuple(sections))


def _region(base, size, *, alloc=None, prot="PAGE_READWRITE", mtype="MEM_PRIVATE"):
    return CapturedRegion(range=VirtualRange(base, size),
                          allocation_base=alloc if alloc is not None else base,
                          state="MEM_COMMIT", type=mtype, protection=prot)


def test_address_in_a_module_is_registered_with_rva():
    modules = [Module(IMAGE_BASE, 0x5000, "app.exe")]
    loc = resolve_va_location(IMAGE_BASE + 0x1234, modules=modules)
    assert loc.registration == REGISTRATION_REGISTERED
    assert loc.module_name == "app.exe"
    assert loc.module_base == IMAGE_BASE
    assert loc.module_rva == 0x1234


def test_section_resolves_only_with_the_owning_module_profile():
    modules = [Module(IMAGE_BASE, 0x5000, "app.exe")]
    profile = _profile(IMAGE_BASE, [
        _section(0, ".text", 0x1000, 0x2000, x=True),
        _section(1, ".data", 0x3000, 0x1000, w=True)])
    loc = resolve_va_location(IMAGE_BASE + 0x1500, modules=modules,
                              module_profile=profile)
    assert loc.section_index == 0
    assert loc.section_name == ".text"
    assert loc.section_executable is True


def test_a_profile_for_a_different_base_is_ignored():
    modules = [Module(IMAGE_BASE, 0x5000, "app.exe")]
    foreign = _profile(0x180000000, [_section(0, ".text", 0x1000, 0x2000, x=True)])
    loc = resolve_va_location(IMAGE_BASE + 0x1500, modules=modules,
                              module_profile=foreign)
    assert loc.section_index is None


def test_address_in_a_private_region_but_no_module_is_unregistered():
    modules = [Module(IMAGE_BASE, 0x5000, "app.exe")]
    views = [_region(0x2000000, 0x4000, prot="PAGE_EXECUTE_READWRITE")]
    loc = resolve_va_location(0x2000800, modules=modules, region_views=views)
    assert loc.registration == REGISTRATION_UNREGISTERED
    assert loc.region_base == 0x2000000
    assert loc.region_protection == "PAGE_EXECUTE_READWRITE"
    assert loc.module_base is None


def test_no_module_list_leaves_registration_unavailable():
    loc = resolve_va_location(0x2000800, modules=(),
                              region_views=[_region(0x2000000, 0x4000)])
    assert loc.registration == REGISTRATION_UNAVAILABLE
    assert loc.in_region


def test_address_outside_every_region_and_module():
    loc = resolve_va_location(0xdead0000, modules=[Module(IMAGE_BASE, 0x1000, "a")],
                              region_views=[_region(0x2000000, 0x1000)])
    assert loc.registration == REGISTRATION_UNREGISTERED
    assert loc.region_base is None

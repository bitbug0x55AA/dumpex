/*
  Suspicious memory layout indicators
  These rules fire on patterns that are unusual in legitimate processes
  and commonly associated with injection/reflective loading.
*/

rule PE_In_Private_Memory {
    meta:
        description = "MZ/PE header found — useful when applied to MEM_PRIVATE regions outside module list"
        mitre       = "T1055"
    strings:
        $mz = { 4D 5A }          // MZ
        $pe = { 50 45 00 00 }    // PE\0\0
    condition:
        $mz at 0 and $pe
}

rule Reflective_Loader_Signature {
    meta:
        description = "ReflectiveDLLInjection loader hash constant (public research, Stephen Fewer)"
        reference   = "https://github.com/stephenfewer/ReflectiveDLLInjection"
        mitre       = "T1055.001"
    strings:
        // Hash of 'LoadLibraryA' used by reflective loader
        $rfl_hash = { EC 0E E0 4E }
        // Hash of 'GetProcAddress'
        $rfl_hash2 = { 78 97 B8 7C }
    condition:
        all of them
}

rule Shellcode_Bootstrap_x64 {
    meta:
        description = "Common x64 shellcode PIC bootstrap: call/pop RIP technique"
        mitre       = "T1059.003"
    strings:
        // call $+5 / pop rcx  — position-independent code bootstrap
        $bootstrap = { E8 00 00 00 00 59 }
        // GetEIP via call/pop in 32-bit
        $bootstrap32 = { E8 00 00 00 00 5B }
    condition:
        any of them
}

rule Win32_API_Hashing {
    meta:
        description = "Stack-based API hashing stubs commonly found in shellcode/loaders"
        mitre       = "T1027.007"
    strings:
        // ror edi, 0x0d  — standard ROR-13 API hashing constant
        $ror13 = { C1 CF 0D }
        // add edi, eax
        $add_edi = { 03 F8 }
    condition:
        $ror13 and $add_edi
}

rule Suspicious_VirtualAlloc_Sequence {
    meta:
        description = "VirtualAlloc + WriteProcessMemory string pair — common in injectors"
        mitre       = "T1055"
    strings:
        $va  = "VirtualAllocEx" nocase wide ascii
        $wpm = "WriteProcessMemory" nocase wide ascii
        $crt = "CreateRemoteThread" nocase wide ascii
    condition:
        2 of them
}

/*
  Cobalt Strike beacon indicators
  Sources:
    - 1768.py by Didier Stevens (public domain) — beacon config XOR signatures
    - NVISO Labs "Cobalt Strike: Memory Dumps" blog series (public)
*/

rule CS_Beacon_Config_XOR69 {
    meta:
        description = "Cobalt Strike beacon configuration block encoded with XOR key 0x69 (CS3-era)"
        author      = "Dumpex / Didier Stevens"
        reference   = "https://blog.didierstevens.com/programs/cobalt-strike-tools/"
        mitre       = "T1027"
    strings:
        // START_CONFIG bytes { 00 01 00 01 00 02 } XOR 0x69
        $sig = { 69 68 69 68 69 6B }
    condition:
        $sig
}

rule CS_Beacon_Config_XOR2E {
    meta:
        description = "Cobalt Strike beacon configuration block encoded with XOR key 0x2E (CS4-era)"
        author      = "Dumpex / Didier Stevens"
        reference   = "https://blog.didierstevens.com/programs/cobalt-strike-tools/"
        mitre       = "T1027"
    strings:
        // START_CONFIG bytes { 00 01 00 01 00 02 } XOR 0x2e
        $sig = { 2E 2F 2E 2F 2E 2C }
    condition:
        $sig
}

rule CS_Beacon_PublicKey_Header {
    meta:
        description = "Cobalt Strike beacon RSA public key ASN.1 header (plaintext)"
        author      = "Dumpex"
        reference   = "https://blog.didierstevens.com/programs/cobalt-strike-tools/"
        mitre       = "T1573.002"
    strings:
        // SEQUENCE { SEQUENCE { OID rsaEncryption } BIT STRING }
        $pubkey_hdr = { 30 81 9F 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 81 8D 00 30 81 89 02 81 }
    condition:
        $pubkey_hdr
}

rule CS_Default_PipeName_PostEx {
    meta:
        description = "Cobalt Strike default post-exploitation pipe name pattern"
        mitre       = "T1559.001"
    strings:
        $p1 = "postex_" nocase
        $p2 = "msagent_" nocase
        $p3 = /status_[0-9a-f]{6,}/ nocase
    condition:
        any of them
}

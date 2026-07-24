/*
  Lateral movement and credential access tool indicators
  Based on publicly documented tool signatures.
*/

rule PSExec_Strings {
    meta:
        description = "PsExec / PAExec service executable strings"
        mitre       = "T1021.002"
    strings:
        $s1 = "PSEXESVC" wide ascii nocase
        $s2 = "paexec" wide ascii nocase
        $s3 = "RemComSvc" wide ascii nocase
        $s4 = "\\psexec" wide ascii nocase
    condition:
        any of them
}

rule Mimikatz_Strings {
    meta:
        description = "Mimikatz credential dumping tool string indicators"
        reference   = "https://github.com/gentilkiwi/mimikatz"
        mitre       = "T1003.001"
    strings:
        $s1 = "mimikatz" nocase wide ascii
        $s2 = "sekurlsa::" nocase wide ascii
        $s3 = "kerberos::" nocase wide ascii
        $s4 = "lsadump::" nocase wide ascii
        $s5 = "gentilkiwi" nocase wide ascii
    condition:
        any of them
}

rule Impacket_Strings {
    meta:
        description = "Impacket toolkit Python string indicators"
        reference   = "https://github.com/fortra/impacket"
        mitre       = "T1021.002"
    strings:
        $s1 = "impacket" nocase wide ascii
        $s2 = "smbclient.py" nocase wide ascii
        $s3 = "secretsdump" nocase wide ascii
    condition:
        any of them
}

rule LSASS_Dump_Keywords {
    meta:
        description = "LSASS process dump attempt string indicators"
        mitre       = "T1003.001"
    strings:
        $s1 = "lsass.exe" nocase wide ascii
        $s2 = "MiniDumpWriteDump" wide ascii
        $s3 = "procdump" nocase wide ascii
        $s4 = "comsvcs.dll" nocase wide ascii
    condition:
        2 of them
}

rule Scheduled_Task_Lateral {
    meta:
        description = "Scheduled task / AT command lateral movement indicators"
        mitre       = "T1053.005"
    strings:
        $s1 = "schtasks" nocase wide ascii
        $s2 = "/create" nocase wide ascii
        $s3 = "cmd.exe /c" nocase wide ascii
    condition:
        all of them
}

rule WMI_Lateral_Movement {
    meta:
        description = "WMI-based lateral movement string pattern"
        mitre       = "T1047"
    strings:
        $s1 = "Win32_Process" wide ascii
        $s2 = "Create" wide ascii
        $s3 = "wmic" nocase wide ascii
    condition:
        ($s1 and $s2) or $s3
}

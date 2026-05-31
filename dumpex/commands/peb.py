"""--peb command."""
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW

def cmd_peb(mf: MinidumpFile):
    peb = mf.peb
    if not peb:
        print("[!] PEB could not be parsed (missing sysinfo or thread list in dump)")
        return

    print(f"\n{BOLD('═══ PEB ═══')}")
    print(f"  {'PEB Address':<24} 0x{peb.address:x}")
    print(f"  {'BeingDebugged':<24} {peb.being_debugged}")
    print(f"  {'ImageBaseAddress':<24} 0x{peb.image_base_address:x}")
    print(f"  {'ImagePath':<24} {peb.image_path or '(none)'}")
    print(f"  {'CommandLine':<24} {peb.command_line or '(none)'}")
    print(f"  {'WindowTitle':<24} {peb.window_title or '(none)'}")
    print(f"  {'DllPath':<24} {peb.dll_path or '(none)'}")
    print(f"  {'CurrentDirectory':<24} {peb.current_directory or '(none)'}")
    print(f"  {'StandardInput':<24} {peb.standard_input}")
    print(f"  {'StandardOutput':<24} {peb.standard_output}")
    print(f"  {'StandardError':<24} {peb.standard_error}")

    if peb.environment_variables:
        print(f"\n  {BOLD('Environment Variables:')}")
        for env in peb.environment_variables:
            k = env.get("name", "") if isinstance(env, dict) else env[0]
            v = env.get("value", "") if isinstance(env, dict) else env[1]
            print(f"    {k}={v}")


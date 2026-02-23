import pefile
from typing import Dict, Any, List

# Common hypervisor/sandbox indicators found in strings or device names
ANTI_VM_STRINGS = [
    b"VBox", b"VMWare", b"VirtualBox", b"vboxguest", b"XenVmm", b"qemu",
    b"vboxhook.dll", b"vmtoolsd.exe", b"vmacthlp.exe", b"vboxservice.exe"
]

# Common APIs used to check if the process is being debugged
ANTI_DEBUG_APIS = [
    b"IsDebuggerPresent",
    b"CheckRemoteDebuggerPresent",
    b"OutputDebugStringA",
    b"OutputDebugStringW",
    b"NtQueryInformationProcess",
    b"FindWindowA", # Often looking for "OLLYDBG" or "x64dbg"
    b"FindWindowW"
]

# Hardware instruction bytes (e.g. RDTSC - 0F 31)
# Note: Full byte-pattern matching for obfuscation is complex, just checking strings/imports for MVP.

# Standard widely-used PE Section names
STANDARD_SECTIONS = [
    b".text", b".bss", b".rdata", b".data", b".rsrc", b".edata",
    b".idata", b".pdata", b".debug", b".reloc", b".tls"
]

def detect_evasion(file_path: str, pe: pefile.PE = None) -> Dict[str, Any]:
    """Analyzes a binary for techniques used to evade VMs or debuggers."""
    results = {
        "anti_vm": [],
        "anti_debug": [],
        "suspicious_sections": []
    }
    
    if not pe:
        try:
            pe = pefile.PE(file_path)
        except Exception:
            return results # Not a PE file, skip

    try:
        # 1. Anti-VM Strings
        with open(file_path, "rb") as f:
            raw_data = f.read()
            raw_data_lower = raw_data.lower()
            
            for avm in ANTI_VM_STRINGS:
                avm_lower = avm.lower()
                # Create UTF-16LE equivalent (e.g. b'v\x00m\x00w\x00a\x00r\x00e\x00')
                avm_wide = b"".join([bytes([b, 0]) for b in avm_lower])
                
                if avm_lower in raw_data_lower or avm_wide in raw_data_lower:
                    results["anti_vm"].append(avm.decode('utf-8', errors='ignore'))
                        
        # 2. Anti-Debug Imports 
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        for api in ANTI_DEBUG_APIS:
                            if api in imp.name:
                                results["anti_debug"].append(api.decode('utf-8'))
                                
        # 3. Suspicious Sections (Packers/Obfuscators)
        for section in pe.sections:
            sec_name = section.Name.rstrip(b'\x00')
            if sec_name not in STANDARD_SECTIONS:
                # Common ones like .UPX0 will get flagged here, as well as random junk
                results["suspicious_sections"].append(sec_name.decode('utf-8', errors='ignore'))
                
    except Exception as e:
        results["error"] = str(e)
        
    # Deduplicate lists
    results["anti_vm"] = list(set(results["anti_vm"]))
    results["anti_debug"] = list(set(results["anti_debug"]))
    results["suspicious_sections"] = list(set(results["suspicious_sections"]))

    return results

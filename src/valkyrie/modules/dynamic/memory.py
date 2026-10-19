import os
import re
from typing import Dict, Any, List

# Basic signatures for common shellcode/stagers
SHELLCODE_SIGS = {
    "NOP_SLED_16": b"\x90" * 16,
    "MSF_REVERSE_TCP_X86": b"\xfc\xe8\x82\x00\x00\x00\x60", # Standard Metasploit payload header
    "MSF_REVERSE_TCP_X64": b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00",
    "SHIKATA_GA_NAI_DECODER": b"\xd9\xeb\x9b\xd9\x74\x24\xf4", # Common shikata_ga_nai x86 decoder stub
}

def analyze_memory(maps_log_path: str, mem_dump_path: str) -> Dict[str, Any]:
    """Scans extracted live process memory for RWX allocations and shellcode."""
    results = {
        "rwx_regions": [],
        "shellcode_matches": [],
        "error": None
    }
    
    # 1. Parse maps for RWX allocated regions
    if maps_log_path and os.path.exists(maps_log_path):
        try:
            with open(maps_log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # typical map line: 08048000-080b0000 r-xp 00000000 08:01 1049909 /bin/cat
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        perms = parts[1]
                        if "rwx" in perms:
                            region = parts[0]
                            mapping = parts[-1] if len(parts) >= 6 else "[anonymous]"
                            results["rwx_regions"].append({
                                "region": region,
                                "permissions": perms,
                                "mapping": mapping
                            })
        except Exception as e:
            results["error"] = f"Failed to parse maps: {e}"
            
    # 2. Scan core memory dump for shellcode signatures
    if mem_dump_path and os.path.exists(mem_dump_path):
        try:
            # We use a memory mapped file or chunked read since dumps can be large
            with open(mem_dump_path, "rb") as f:
                # Basic chunking scan for MVP
                chunk_size = 1024 * 1024 * 10 # 10MB chunks
                overlap = 256
                buffer = b""
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                        
                    scan_buffer = buffer + chunk
                    
                    for sig_name, sig_bytes in SHELLCODE_SIGS.items():
                        if sig_bytes in scan_buffer:
                            # Avoid duplicates
                            if sig_name not in results["shellcode_matches"]:
                                results["shellcode_matches"].append(sig_name)
                                
                    # Keep tail for overlap
                    buffer = chunk[-overlap:]
                    
        except Exception as e:
            results["error"] = f"Failed to scan mem_dump: {e}"
            
    return results

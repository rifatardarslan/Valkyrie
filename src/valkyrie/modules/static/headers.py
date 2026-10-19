import pefile
from typing import Dict, Any, List

def analyze_headers(file_path: str) -> Dict[str, Any]:
    """Extracts interesting data from PE headers."""
    result = {
        "is_pe": False,
        "imports": [],
        "exports": [],
        "sections": [],
        "suspicious_indicators": [],
        "error": None
    }
    
    try:
        pe = pefile.PE(file_path)
        result["is_pe"] = True
        
        # Sections
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            sec_info = {
                "name": sec_name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": hex(section.Misc_VirtualSize),
                "raw_size": section.SizeOfRawData,
                "entropy": section.get_entropy()
            }
            
            # Check for suspicious section characteristics
            # Executable and Writable is highly suspicious (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)
            if (section.Characteristics & 0x20000000) and (section.Characteristics & 0x80000000):
                result["suspicious_indicators"].append(f"Section {sec_name} is EXECUTABLE and WRITABLE.")
                sec_info["suspicious"] = True
            else:
                sec_info["suspicious"] = False
                
            if sec_info["entropy"] > 7.0:
                result["suspicious_indicators"].append(f"Section {sec_name} has high entropy ({round(sec_info['entropy'], 2)}).")
                sec_info["suspicious"] = True
                
            result["sections"].append(sec_info)
            
        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode('utf-8', errors='ignore'))
                    else:
                        functions.append(f"Ordinal({imp.ordinal})")
                
                result["imports"].append({
                    "dll": dll_name,
                    "functions": functions
                })
                
        # Exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result["exports"].append(exp.name.decode('utf-8', errors='ignore'))
                    
    except pefile.PEFormatError:
        result["error"] = "Not a valid PE file or corrupted."
    except Exception as e:
        result["error"] = str(e)
        
    return result

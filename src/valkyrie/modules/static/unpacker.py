import os
import subprocess
import shutil
from typing import Dict, Any

def unpack_upx(file_path: str) -> Dict[str, Any]:
    """
    Attempts to unpack a UPX packed executable.
    Assumes 'upx' is installed and available in the system PATH.
    """
    result = {
        "unpacked": False,
        "unpacked_file_path": None,
        "message": ""
    }
    
    # Verify upx is available
    if not shutil.which("upx"):
        result["message"] = "UPX executable not found in PATH."
        return result
        
    # Check if 'UPX' string exists in the file (Very basic check, a better one involves pefile sections)
    has_upx_magic = False
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            if b"UPX0" in content or b"UPX1" in content or b"UPX!" in content:
                has_upx_magic = True
    except Exception:
        pass
        
    if not has_upx_magic:
        result["message"] = "No obvious UPX magic bytes found."
        return result
        
    # Attempt unpacking
    unpacked_path = f"{file_path}.unpacked"
    try:
        # Copy the original file to safely unpack it
        shutil.copy2(file_path, unpacked_path)
        
        # Run upx -d
        process = subprocess.run(
            ["upx", "-d", unpacked_path],
            capture_output=True,
            text=True
        )
        
        if process.returncode == 0:
            result["unpacked"] = True
            result["unpacked_file_path"] = unpacked_path
            result["message"] = "Successfully unpacked using UPX."
        else:
            result["message"] = f"UPX unpacking failed: {process.stderr.strip()}"
            if os.path.exists(unpacked_path):
                os.remove(unpacked_path)
    except Exception as e:
        result["message"] = str(e)
        if os.path.exists(unpacked_path):
            os.remove(unpacked_path)
            
    return result

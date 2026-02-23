import hashlib
from typing import Dict, Any

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False


def calculate_hashes(file_path: str) -> Dict[str, Any]:
    """Calculates cryptographic and fuzzy hashes for a file."""
    hashes = {}
    
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            # Read in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                
        hashes["md5"] = md5_hash.hexdigest()
        hashes["sha1"] = sha1_hash.hexdigest()
        hashes["sha256"] = sha256_hash.hexdigest()
        
        # Fuzzy hashing
        if SSDEEP_AVAILABLE:
            hashes["ssdeep"] = ssdeep.hash_from_file(file_path)
        else:
            hashes["ssdeep"] = "Not available (ssdeep not installed)"
            
    except Exception as e:
        hashes["error"] = str(e)
        
    return hashes

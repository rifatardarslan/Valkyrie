import requests
from typing import Dict, Any, Optional

def check_circl_whitelist(sha256_hash: str) -> Optional[Dict[str, Any]]:
    """
    Checks the CIRCL Hash Lookup API to see if the hash belongs to a known safe file.
    This database includes the NIST NSRL dataset.
    Returns the metadata dictionary if found (whitelisted), otherwise None.
    """
    if not sha256_hash:
        return None
        
    url = f"https://hashlookup.circl.lu/lookup/sha256/{sha256_hash}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            # If it's in the DB, it's generally considered known (often safe NSRL)
            return data
    except requests.RequestException:
        pass
        
    return None

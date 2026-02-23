import re
from typing import Dict, List, Any

# Pattern library for sensitive artifacts
ARTIFACT_PATTERNS = {
    # Match standard IPv4 addresses (excluding local/private for brevity, though here we match all valid)
    "ipv4_port": rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d{1,5}\b',
    # Match Bitcoin addresses (P2PKH and P2SH starting with 1 or 3, Bech32 starting with bc1)
    "bitcoin_wallet": rb'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qzpry9x8gf2tvdw0s3jn54khce6mua7l]{39,59})\b',
    # Identify explicit URL payloads or C2 domains
    "url": rb'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(?::\d{1,5})?(?:/[^\s]*)?',
    # AWS Access Key ID
    "aws_key": rb'\bAKIA[0-9A-Z]{16}\b',
    # Hardware/Software Mutex naming conventions (Global\..., UUIDs, etc.)
    "mutex": rb'(?i)(?:Global\\[a-zA-Z0-9_.-]{4,100}|[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})',
    # Windows Registry Paths
    "registry_key": rb'(?i)(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|Software)\\[a-zA-Z0-9_\.\-\\]{5,150}'
}

def extract_artifacts(file_path: str) -> Dict[str, List[str]]:
    """Scans raw binary for highly sensitive actionable intelligence artifacts using Regex."""
    results = {
        "ipv4_port": [],
        "bitcoin_wallet": [],
        "url": [],
        "aws_key": [],
        "mutex": [],
        "registry_key": [],
        "error": None
    }
    
    try:
        with open(file_path, "rb") as f:
            raw_data = f.read()
            
            for artifact_type, pattern in ARTIFACT_PATTERNS.items():
                matches = re.findall(pattern, raw_data)
                if matches:
                    for m in matches:
                        try:
                            dec = m.decode('ascii', errors='ignore')
                            if dec not in results[artifact_type]:
                                results[artifact_type].append(dec)
                        except Exception:
                            pass
                            
    except Exception as e:
        results["error"] = str(e)
        
    return results

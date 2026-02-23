import math
from typing import Dict, Any

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    
    # Calculate frequency of each byte
    counts = [0] * 256
    for b in data:
        counts[b] += 1
        
    # Calculate entropy
    for count in counts:
        if count == 0:
            continue
        p = float(count) / length
        entropy -= p * math.log2(p)
        
    return entropy

def analyze_entropy(file_path: str) -> Dict[str, Any]:
    """Analyzes the overall file entropy."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            
        overall_entropy = calculate_shannon_entropy(data)
        
        # Generally, entropy > 7.0 is considered highly packed or encrypted
        is_packed = overall_entropy > 7.0
        
        return {
            "overall_entropy": round(overall_entropy, 4),
            "is_packed": is_packed
        }
    except Exception as e:
        return {"error": str(e)}

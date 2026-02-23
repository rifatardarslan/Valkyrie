import re
import base64
import binascii
from typing import List, Dict, Any

# Minimum length to reduce false positives for Base64 and Hex
MIN_B64_LEN = 16
MIN_HEX_LEN = 16

def is_printable_ascii(s: bytes) -> bool:
    """Check if decoded bytes are predominantly printable ASCII."""
    if not s:
        return False
    printable = sum(1 for b in s if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(s)) > 0.8  # 80% threshold

def extract_and_decode(file_path: str) -> Dict[str, List[str]]:
    """Scans binary string fragments for obfuscation patterns and decodes them."""
    results = {
        "base64_decoded": [],
        "hex_decoded": [],
        "xor_decoded": []
    }
    
    try:
        with open(file_path, "rb") as f:
            raw_data = f.read()
            
        # 1. Base64 Decoding
        # Regex targets standard base64 alphabet, capturing potential padding
        b64_pattern = re.compile(b'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        for match in b64_pattern.findall(raw_data):
            try:
                decoded = base64.b64decode(match)
                if len(decoded) > 5 and is_printable_ascii(decoded):
                    dec_str = decoded.decode('ascii', errors='ignore')
                    if dec_str not in results["base64_decoded"]:
                        results["base64_decoded"].append(f"{match.decode('ascii')} -> {dec_str}")
            except Exception:
                pass
                
        # 2. Hex Decoding
        # Regex targets long continuous hex sequences (often used for payload drops)
        hex_pattern = re.compile(b'(?:[0-9a-fA-F]{2}){8,}')
        for match in hex_pattern.findall(raw_data):
            try:
                decoded = binascii.unhexlify(match)
                if len(decoded) > 5 and is_printable_ascii(decoded):
                    dec_str = decoded.decode('ascii', errors='ignore')
                    if dec_str not in results["hex_decoded"]:
                        results["hex_decoded"].append(f"{match.decode('ascii')} -> {dec_str}")
            except Exception:
                pass

        # 3. Simple single-byte XOR Brute Force (MVP)
        # We extract all standard printable strings, but also look for non-printable buffers
        # For MVP, we will only XOR brute force short suspicious buffers that might be URLs
        # (A full XOR brute force on the entire file is too slow for static analysis)
        # We'll check for the "http" pattern encoded via single-byte XOR.
        # 'h' = 0x68, 't' = 0x74, 'p' = 0x70
        url_pattern = b"http"
        for i in range(len(raw_data) - 4):
            # Check if block XORs out to "http"
            # key = cipher_byte ^ plain_byte
            k1 = raw_data[i] ^ url_pattern[0]
            k2 = raw_data[i+1] ^ url_pattern[1]
            k3 = raw_data[i+2] ^ url_pattern[2]
            k4 = raw_data[i+3] ^ url_pattern[3]
            
            if k1 == k2 == k3 == k4 and k1 != 0:
                # Potential XOR key found! Let's decode until null byte or non-printable
                key = k1
                decoded_url = ""
                for j in range(i, len(raw_data)):
                    dec_b = raw_data[j] ^ key
                    if dec_b == 0 or not (32 <= dec_b <= 126):
                        break
                    decoded_url += chr(dec_b)
                
                if len(decoded_url) > 8:
                    entry = f"Key: 0x{key:02X} -> {decoded_url}"
                    if entry not in results["xor_decoded"]:
                        results["xor_decoded"].append(entry)
                        
    except Exception as e:
        results["error"] = str(e)
        
    return results

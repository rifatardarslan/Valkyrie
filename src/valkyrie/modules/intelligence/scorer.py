from typing import Dict, Any

def calculate_threat_score(aggregated_results: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluates all analysis modules to produce a final 0-100 Threat Score."""
    score = 0
    reasons = []

    # 1. Static Analysis Weights
    static = aggregated_results.get("static", {})
    
    # Pack/Entropy
    if static.get("entropy", {}).get("is_packed", False):
        score += 15
        reasons.append("High entropy detected (Likely Packed) [+15]")
        
    if static.get("unpack_info", {}).get("unpacked", False):
        score += 10
        reasons.append("Automated unpacking succeeded [+10]")

    # YARA
    yara = static.get("yara", [])
    if yara and "error" not in yara[0]:
        score += 30
        reasons.append(f"YARA Rule Matches ({len(yara)}) [+30]")

    # Evasion
    evasion = static.get("evasion", {})
    if evasion:
        avm = len(evasion.get("anti_vm", []))
        adbg = len(evasion.get("anti_debug", []))
        ssec = len(evasion.get("suspicious_sections", []))
        
        if avm > 0:
            score += 25
            reasons.append(f"Anti-VM Strings Detected ({avm}) [+25]")
        if adbg > 0:
            score += 25
            reasons.append(f"Anti-Debug APIs Detected ({adbg}) [+25]")
        if ssec > 0:
            score += 15
            reasons.append(f"Suspicious/Obfuscated Sections ({ssec}) [+15]")

    # 2. Dynamic Analysis Weights
    dynamic = aggregated_results.get("dynamic", {})
    strace = dynamic.get("strace", {})
    
    if strace:
        file_mods = len(strace.get("file_operations", []))
        proc_mods = len(strace.get("process_operations", []))
        net_calls = len(strace.get("network_calls", []))
        
        if file_mods > 0:
            val = min(file_mods * 2, 10) # 2 pts per file max 10
            score += val
            reasons.append(f"File Operations ({file_mods}) [+{val}]")
            
        if proc_mods > 0:
            val = min(proc_mods * 5, 20) # 5 pts per proc max 20
            score += val
            reasons.append(f"Process Injections/Executions ({proc_mods}) [+{val}]")
            
        if net_calls > 0:
            score += 20
            reasons.append(f"Network Connectivity Observed ({net_calls}) [+20]")

    # 3. Intelligence Weights
    intel = aggregated_results.get("intelligence", {})
    
    # Whitelist (Immunity)
    if "whitelist" in intel:
        # Known safe file drops score significantly or entirely
        reasons.append("NSRL Whitelist Match [-100]")
        score = 0
            
    # MITRE ATT&CK
    mitre = intel.get("mitre", [])
    if mitre:
        val = min(len(mitre) * 10, 30)
        score += val
        reasons.append(f"MITRE ATT&CK Tactics Mapped ({len(mitre)}) [+{val}]")

    # OSINT (VirusTotal / MalwareBazaar)
    osint = intel.get("osint", {})
    if osint:
        vt = osint.get("virustotal", {})
        mb = osint.get("malwarebazaar", {})
        
        mal_count = vt.get("malicious", 0)
        if mal_count > 0:
            val = min(mal_count * 5, 40) # Massive red flag
            score += val
            reasons.append(f"VirusTotal Detections ({mal_count}) [+{val}]")
            
        if mb.get("signature") and mb.get("signature") != "Unknown":
            score += 30
            reasons.append(f"MalwareBazaar Signature ({mb['signature']}) [+30]")

    # Final Boundary Enforcement (0 - 100)
    final_score = min(max(score, 0), 100)
    
    label = "Safe"
    if final_score >= 90:
        label = "Critical"
    elif final_score >= 60:
        label = "Malicious"
    elif final_score >= 20:
        label = "Suspicious"

    return {
        "score": final_score,
        "label": label,
        "reasons": reasons
    }

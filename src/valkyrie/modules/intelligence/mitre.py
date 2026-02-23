import json
from typing import Dict, Any, List

# Basic mapping rules (Behavior string subset -> MITRE Technique)
MITRE_RULES = [
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "keywords": ["cmd.exe", "powershell.exe", "bash", "sh", "execve(\"/bin/"]
    },
    {
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "keywords": ["High Entropy?", "'is_packed': True", "UPX"]
    },
    {
        "technique_id": "T1106",
        "technique_name": "Native API",
        "tactic": "Execution",
        "keywords": ["OpenProcess", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]
    },
    {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "keywords": ["Network call (connect)", "Network call (sendto)", "socket(", "urllib"]
    },
    {
        "technique_id": "T1562",
        "technique_name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "keywords": ["Suspicious Indicators", "EXECUTABLE and WRITABLE"]
    }
]

def map_mitre(aggregated_results: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Applies basic rule-matching against the aggregated results string representation 
    to map behaviors to MITRE ATT&CK techniques.
    """
    matches = []
    
    # Convert results to a searchable string (hacky but effective for this scale)
    results_str = json.dumps(aggregated_results, default=str)
    
    for rule in MITRE_RULES:
        for keyword in rule["keywords"]:
            if keyword in results_str or keyword.lower() in results_str.lower():
                matches.append({
                    "id": rule["technique_id"],
                    "name": rule["technique_name"],
                    "tactic": rule["tactic"],
                    "trigger": keyword
                })
                break # Avoid duplicate hits on the same rule
                
    return matches

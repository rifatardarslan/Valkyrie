import os
import json
from typing import Dict, Any, List

def load_capability_rules() -> Dict[str, Any]:
    rules_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "rules", "capabilities.json")
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def assess_capabilities(aggregated_results: Dict[str, Any], raw_strings: List[str] = None) -> List[Dict[str, str]]:
    """Evaluates the static extraction results against the predefined intelligence logic rules."""
    rules = load_capability_rules()
    discovered_capabilities = []
    
    if not rules:
        return [{"error": "Capabilities rule file not found."}]
        
    static = aggregated_results.get("static", {})
    headers = static.get("headers", {})
    imports = headers.get("imports", {})
    
    # Flatten imports to search easily
    flat_imports = []
    if isinstance(imports, dict):
        for dll, funcs in imports.items():
            flat_imports.append(dll.lower())
            flat_imports.extend([f.lower() for f in funcs])
            
    # Also grab evasion strings if they exist
    threat_strings = []
    evasion = static.get("evasion", {})
    if evasion:
        threat_strings.extend(evasion.get("anti_vm", []))
        
    # We can pass raw_strings or XOR decoded domains in here too
    if raw_strings:
        threat_strings.extend(raw_strings)
        
    flat_strings_lower = [s.lower() for s in threat_strings]
            
    for cap_name, rule_def in rules.items():
        matched = False
        
        # Check Imports logic (OR matches for now, Capa uses complex AND/OR trees)
        rule_imports = rule_def.get("imports", [])
        if rule_imports:
            for imp in rule_imports:
                if imp.lower() in flat_imports:
                    matched = True
                    break
                    
        # Check Strings logic
        if not matched:
            rule_strings = rule_def.get("strings", [])
            if rule_strings:
                for s in rule_strings:
                    if s.lower() in flat_strings_lower:
                        matched = True
                        break
                        
        if matched:
            discovered_capabilities.append({
                "tag": cap_name,
                "description": rule_def.get("description", "")
            })
            
    return discovered_capabilities

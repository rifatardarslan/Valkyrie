import os
try:
    import yara
except ImportError:
    yara = None

from typing import Dict, Any, List

def compile_rules(rules_dir: str):
    """Compiles all YARA rules found in the rules directory."""
    filepaths = {}
    if not os.path.exists(rules_dir):
        return None
        
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith((".yar", ".yara")):
                path = os.path.join(root, file)
                filepaths[file] = path
                
    if not filepaths:
        return None
        
    try:
        if yara is None: return None
        return yara.compile(filepaths=filepaths)
    except Exception as e:
        print(f"Error compiling YARA rules: {e}")
        return None

def scan_file(file_path: str, rules_dir: str = "rules") -> List[Dict[str, Any]]:
    """Scans a file against compiled YARA rules."""
    rules = compile_rules(rules_dir)
    if not rules:
        return []
        
    try:
        matches = rules.match(file_path)
        
        results = []
        for match in matches:
            results.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": match.meta,
                # "strings": match.strings  # Often too verbose for standard output
            })
            
        return results
    except Exception as e:
        return [{"error": str(e)}]

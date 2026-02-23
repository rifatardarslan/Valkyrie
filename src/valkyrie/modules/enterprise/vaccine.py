import os
from typing import Dict, Any, List

class VaccineGenerator:
    """Generates a prophylactic Python script to pre-occupy malware Mutexes and Registry Keys."""
    
    def __init__(self, out_dir: str = "reports"):
        self.out_dir = out_dir
        if not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)
            
    def generate(self, aggregated_results: Dict[str, Any]) -> str:
        """
        Extracts discovered Mutexes and RegKeys from the intelligence results
        and dynamically generates a 'vaccine.py' script.
        """
        intel = aggregated_results.get("intelligence", {})
        artifacts = intel.get("artifacts", {})
        
        mutexes = artifacts.get("mutex", [])
        reg_keys = artifacts.get("registry_key", [])
        
        # We also might have dynamic strace findings
        dynamic = aggregated_results.get("dynamic", {})
        timeline = dynamic.get("strace", {}).get("timeline", [])
        
        # Scrape timeline for dynamic mutex creations or registry creations
        for event in timeline:
            action = event.get("action", "")
            if "Mutex" in action or "Registry" in action:
                # Basic extraction from the descriptive action string
                # E.g., "Created Mutex: Global\\BazarLoader"
                if "Mutex: " in action:
                    m = action.split("Mutex: ")[-1].strip()
                    if m not in mutexes: mutexes.append(m)
                elif "Registry: " in action:
                    r = action.split("Registry: ")[-1].strip()
                    if r not in reg_keys: reg_keys.append(r)
        
        # Deduplicate
        mutexes = list(set(mutexes))
        reg_keys = list(set(reg_keys))
        
        if not mutexes and not reg_keys:
            return None # Nothing to vaccinate against
            
        script_content = self._build_script(mutexes, reg_keys)
        
        out_path = os.path.join(self.out_dir, "vaccine.py")
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(script_content)
            return out_path
        except Exception as e:
            print(f"[-] Failed to write vaccine script: {e}")
            return None
            
    def _build_script(self, mutexes: List[str], reg_keys: List[str]) -> str:
        """Template for the generated Python prophylactic script."""
        
        template = f'''"""
Valkyrie Vaccine - Proactive Defense Script
Auto-Generated based on sandbox analysis.
"""
import sys
import time

{ "import winreg" if reg_keys else "" }
{ "import ctypes" if mutexes else "" }

def deploy_vaccine():
    print("[*] Deploying Valkyrie Vaccine...")
    
    # 1. Pre-occupy Mutexes
    mutants = []
'''
        for m in mutexes:
            # Escape backslashes for python strings
            safe_m = m.replace("\\", "\\\\")
            template += f'    mutex_name = "{safe_m}"\n'
            template += f'    mutant = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)\n'
            template += f'    if mutant:\n'
            template += f'        mutants.append(mutant)\n'
            template += f'        print(f"[+] Held Mutex: {{mutex_name}}")\n'
            template += f'    else:\n'
            template += f'        print(f"[-] Failed to hold Mutex: {{mutex_name}}")\n\n'
            
        template += '''
    # 2. Pre-create Registry Keys (requires privileges)
'''
        for r in reg_keys:
            safe_r = r.replace("\\", "\\\\")
            template += f'    reg_path = "{safe_r}"\n'
            template += f'    print(f"[*] Simulating creation of Registry Key: {{reg_path}}")\n'
            template += f'    # Implement winreg.CreateKeyEx here if safe to do so automatically.\n\n'
            
        template += '''
    print("[*] Vaccine deployed successfully. Keeping host safe...")
    print("[*] Press Ctrl+C to stop the vaccine (release handles).")
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\\n[*] Releasing vaccine handles...")
        # Mutexes are automatically released by Windows when process dies/handles close.

if __name__ == "__main__":
    if sys.platform != "win32":
        print("[-] This vaccine targets Windows threats. Cannot deploy on Linux/Mac.")
        sys.exit(1)
    deploy_vaccine()
'''
        return template

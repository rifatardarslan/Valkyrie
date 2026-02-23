import os
import json
from typing import Dict, Any

try:
    from stix2 import Indicator, Malware, File, Bundle, Relationship
except ImportError:
    Indicator = Malware = File = Bundle = Relationship = None

class StixExporter:
    """Exports Valkyrie Findings to STIX 2.1 Standard Format."""
    
    def __init__(self, out_dir: str = "reports"):
        self.out_dir = out_dir
        if not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)
            
    def export(self, aggregated_results: Dict[str, Any]) -> str:
        """Converts extracted IOCs into a STIX Bundle and writes to JSON."""
        if not Bundle:
            print("[-] stix2 library not installed. Skipping STIX export.")
            return None
            
        static = aggregated_results.get("static", {})
        intelligence = aggregated_results.get("intelligence", {})
        dynamic = aggregated_results.get("dynamic", {})
        
        objects = []
        relationships = []
        
        # 1. Create the base Malware Object
        file_name = static.get("target_file", "Unknown Target")
        malware = Malware(
            name=f"Valkyrie Analyzed Sample: {os.path.basename(file_name)}",
            is_family=False,
            description="Analyzed by Valkyrie Automated Sandbox"
        )
        objects.append(malware)
        
        # 2. Extract Hashes into a File Object
        hashes = static.get("hashes", {})
        if hashes:
            stix_hashes = {}
            if "md5" in hashes: stix_hashes["MD5"] = hashes["md5"]
            if "sha256" in hashes: stix_hashes["SHA-256"] = hashes["sha256"]
            
            if stix_hashes:
                file_obj = File(
                    name=os.path.basename(file_name),
                    hashes=stix_hashes
                )
                objects.append(file_obj)
                # Link File to Malware
                rel = Relationship(source_ref=malware.id, target_ref=file_obj.id, relationship_type="drops")
                relationships.append(rel)
                
                # Create Indicator for the File Hash
                if "sha256" in hashes:
                    ind = Indicator(
                        name="Malicious File Hash",
                        pattern=f"[file:hashes.'SHA-256' = '{hashes['sha256']}']",
                        pattern_type="stix",
                        valid_from="2020-01-01T00:00:00Z"
                    )
                    objects.append(ind)
                    relationships.append(Relationship(source_ref=ind.id, target_ref=malware.id, relationship_type="indicates"))

        # 3. Extract Network Indicators (IPv4) from Regex or OSINT
        network_iocs = set()
        
        # From OSINT/Network Rep
        net_rep = intelligence.get("osint", {}).get("network_reputation", {})
        for ip in net_rep.keys():
            network_iocs.add(ip)
            
        # From Dynamic PCAP/Strace (simplified extraction for demo)
        strace_ops = dynamic.get("strace", {})
        if "network_calls" in strace_ops:
            import re
            for call in strace_ops["network_calls"]:
                ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', call)
                for ip in ips: network_iocs.add(ip)
                
        for ip in network_iocs:
            ind = Indicator(
                name="Malicious C2 IP Address",
                pattern=f"[ipv4-addr:value = '{ip}']",
                pattern_type="stix",
                valid_from="2020-01-01T00:00:00Z"
            )
            objects.append(ind)
            relationships.append(Relationship(source_ref=ind.id, target_ref=malware.id, relationship_type="indicates"))

        # 4. Generate Bundle
        if not objects:
            return None
            
        bundle = Bundle(objects=objects + relationships)
        
        out_path = os.path.join(self.out_dir, "valkyrie_stix.json")
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(bundle.serialize(pretty=True))
            return out_path
        except Exception as e:
            print(f"[-] STIX export failed: {e}")
            return None

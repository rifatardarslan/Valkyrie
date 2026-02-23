import os
import json
from typing import Dict, Any

def export_json(results: Dict[str, Any], out_dir: str):
    """Exports the complete analysis dictionary as JSON."""
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "valkyrie_report.json")
    
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, default=str)
        return out_path
    except Exception as e:
        print(f"Error saving JSON report: {e}")
        return None

def export_md(results: Dict[str, Any], out_dir: str):
    """Generates a readable Markdown report."""
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "valkyrie_report.md")
    
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("# Valkyrie Malware Analysis Report\n\n")
            
            f.write("## Executive Summary (AI Generated)\n")
            f.write(f"{results.get('intelligence', {}).get('ai_summary', 'Not available.')}\n\n")
            
            f.write("## MITRE ATT&CK Mappings\n")
            mitre = results.get("intelligence", {}).get("mitre", [])
            for m in mitre:
                f.write(f"- **{m['id']}** - {m['name']} ({m['tactic']})\n")
            f.write("\n")
            
            f.write("## File Identifiers\n")
            static = results.get("static", {})
            f.write(f"- Target: `{static.get('target_file')}`\n")
            hashes = static.get("hashes", {})
            f.write(f"- MD5: `{hashes.get('md5')}`\n")
            f.write(f"- SHA256: `{hashes.get('sha256')}`\n\n")
            
            intelligence = results.get("intelligence", {})
            if "whitelist" in intelligence:
                wl = intelligence["whitelist"]
                f.write("## Whitelist (NSRL) Match\n")
                f.write(f"**This file is known-good.**\n- Product: {wl.get('ProductName', 'Unknown')}\n- OS: {wl.get('OSCode', 'Unknown')}\n\n")

            if "osint" in intelligence:
                osint = intelligence["osint"]
                f.write("## Global Threat Intelligence (OSINT)\n")
                
                vt = osint.get("virustotal", {})
                if "malicious" in vt:
                    total_vt = vt['malicious'] + vt['undetected'] + vt['suspicious']
                    f.write(f"- **VirusTotal:** {vt['malicious']} / {total_vt} malicious (Label: {vt.get('suggested_threat_label')})\n")
                
                mb = osint.get("malwarebazaar", {})
                if "signature" in mb:
                    f.write(f"- **MalwareBazaar:** Identified as `{mb['signature']}`\n")
                    
                net_rep = osint.get("network_reputation", {})
                if net_rep:
                    f.write("\n### Network IOC Reputation\n")
                    f.write("| IP Address | Abuse Score | Country | Usage |\n")
                    f.write("|---|---|---|---|\n")
                    for ip, rep in net_rep.items():
                        if "error" not in rep and "status" not in rep:
                            f.write(f"| {ip} | {rep.get('abuse_confidence_score', 0)}% | {rep.get('country', '')} | {rep.get('usage_type', '')} |\n")
                f.write("\n")
                
            # --- Advanced Intelligence (Capa-like) ---
            capabilities = intelligence.get("capabilities", [])
            if capabilities and not "error" in capabilities[0]:
                f.write("## Discovered Capabilities\n")
                f.write("| Capability | Description |\n")
                f.write("|---|---|\n")
                for cap in capabilities:
                    f.write(f"| **{cap.get('tag')}** | {cap.get('description')} |\n")
                f.write("\n")
                
            artifacts = intelligence.get("artifacts", {})
            has_artifacts = any(v for k, v in artifacts.items() if k != "error" and v)
            if has_artifacts:
                f.write("## Sensitive Regex Artifacts\n")
                f.write("| Type | Value |\n")
                f.write("|---|---|\n")
                for k, v in artifacts.items():
                    if k != "error" and v:
                        for val in v[:10]:
                            f.write(f"| {k.upper()} | `{val}` |\n")
                f.write("\n")
                
            deobf = intelligence.get("deobfuscation", {})
            has_deobf = any(v for k, v in deobf.items() if k != "error" and v)
            if has_deobf:
                f.write("## De-obfuscated Payloads\n")
                f.write("| Method | Decoding Preview |\n")
                f.write("|---|---|\n")
                for k, v in deobf.items():
                    if k != "error" and v:
                        for val in v[:10]:
                            preview = val[:100] + "..." if len(val) > 100 else val
                            f.write(f"| {k.replace('_decoded', '').upper()} | `{preview.replace('|', '/')}` |\n")
                f.write("\n")
            
            f.write("---\n")
            
            # --- Threat Score ---
            threat_score = intelligence.get("threat_score")
            if threat_score:
                f.write("## Valkyrie Threat Score\n")
                color_icon = "🟢"
                if threat_score['score'] >= 90: color_icon = "🔴"
                elif threat_score['score'] >= 60: color_icon = "🟠"
                elif threat_score['score'] >= 20: color_icon = "🟡"
                
                f.write(f"### {color_icon} Score: {threat_score['score']} / 100 ({threat_score['label']})\n\n")
                if threat_score.get("reasons"):
                    f.write("**Contributing Factors:**\n")
                    for r in threat_score["reasons"]:
                        f.write(f"- {r}\n")
                f.write("\n")
                
            # --- Memory Forensics ---
            mem = results.get("dynamic", {}).get("memory", {})
            if mem.get("rwx_regions") or mem.get("shellcode_matches"):
                f.write("## Process Memory Forensics (Live)\n")
                f.write("| Finding Type | Details |\n")
                f.write("|---|---|\n")
                for rwx in mem.get("rwx_regions", []):
                    f.write(f"| RWX Mapping | `{rwx['region']}` [{rwx['mapping']}] |\n")
                for shell in mem.get("shellcode_matches", []):
                    f.write(f"| Shellcode Pattern | {shell} |\n")
                f.write("\n")
                
            # --- Behavioral Timeline ---
            timeline = results.get("dynamic", {}).get("strace", {}).get("timeline", [])
            if timeline:
                f.write("## Behavioral Timeline (Strace)\n")
                f.write("| Tick | Action | Raw Syscall |\n")
                f.write("|---|---|---|\n")
                for ts in timeline:
                    f.write(f"| T+{ts['tick']} | {ts['action']} | `{ts['raw']}` |\n")
                f.write("\n")
                
            f.write("---\n")
            f.write("*Full details are available in the accompanying JSON report.*\n")
            
        return out_path
    except Exception as e:
        print(f"Error saving MD report: {e}")
        return None

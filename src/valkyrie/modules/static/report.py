from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import box

console = Console()

def render_static_report(results: Dict[str, Any]):
    """Renders a beautiful CLI report using rich."""
    
    console.print(Panel.fit("[bold cyan]Valkyrie Static Analysis Report[/bold cyan]", border_style="cyan"))
    
    # 1. File Info & Hashes
    hash_table = Table(title="File Identification", box=box.ROUNDED)
    hash_table.add_column("Property", style="cyan")
    hash_table.add_column("Value", style="green")
    
    hash_table.add_row("Target File", results.get("target_file", "Unknown"))
    
    hashes = results.get("hashes", {})
    if "error" in hashes:
        hash_table.add_row("Hashes Error", hashes["error"])
    else:
        hash_table.add_row("MD5", hashes.get("md5", ""))
        hash_table.add_row("SHA-256", hashes.get("sha256", ""))
        hash_table.add_row("SSDEEP", str(hashes.get("ssdeep", "")))
        
    console.print(hash_table)
    
    # 2. Entropy and Packing
    entropy_info = results.get("entropy", {})
    upx_info = results.get("unpack_info", {})
    
    packing_table = Table(title="Packing & Entropy", box=box.ROUNDED)
    packing_table.add_column("Check", style="cyan")
    packing_table.add_column("Result", style="yellow")
    
    entropy_val = entropy_info.get("overall_entropy", 0.0)
    ent_style = "bold red" if entropy_val > 7.0 else "green"
    packing_table.add_row("Overall Entropy", f"[{ent_style}]{entropy_val}[/{ent_style}]")
    packing_table.add_row("High Entropy?", "Yes" if entropy_info.get("is_packed") else "No")
    
    if upx_info.get("unpacked"):
        packing_table.add_row("Automated Unpacking", f"[bold green]Success: {upx_info.get('message')}[/bold green]")
    else:
        packing_table.add_row("Automated Unpacking", upx_info.get("message", "N/A"))
        
    console.print(packing_table)
    
    # 3. Headers (PE specific)
    headers = results.get("headers", {})
    if headers.get("is_pe"):
        # Sections
        sections = headers.get("sections", [])
        if sections:
            sec_table = Table(title="PE Sections", box=box.MINIMAL_HEAVY_HEAD)
            sec_table.add_column("Name")
            sec_table.add_column("V.Address")
            sec_table.add_column("V.Size")
            sec_table.add_column("Entropy")
            
            for sec in sections:
                style = "bold red" if sec.get("suspicious") else "none"
                sec_table.add_row(
                    f"[{style}]{sec['name']}[/{style}]",
                    sec['virtual_address'],
                    sec['virtual_size'],
                    f"[{style}]{round(sec['entropy'], 2)}[/{style}]"
                )
            console.print(sec_table)
            
        # Suspicious Indicators
        susp_inds = headers.get("suspicious_indicators", [])
        if susp_inds:
            console.print("[bold red]Suspicious Indicators Detected![/bold red]")
            for ind in susp_inds:
                console.print(f" - [red]{ind}[/red]")
            console.print()
            
        # Imports (Top 5 DLLs)
        imports = headers.get("imports", [])
        if imports:
            imp_table = Table(title="Top Imports", box=box.SIMPLE)
            imp_table.add_column("DLL", style="magenta")
            imp_table.add_column("Functions", style="white")
            for imp in imports[:5]:
                dll = imp.get("dll", "")
                funcs = ", ".join(imp.get("functions", [])[:5]) # Show first 5 func
                if len(imp.get("functions", [])) > 5:
                    funcs += "..."
                imp_table.add_row(dll, funcs)
            console.print(imp_table)
            
    # 4. YARA Matches
    yara_matches = results.get("yara", [])
    if yara_matches and "error" not in yara_matches[0]:
        yara_table = Table(title="YARA Matches", box=box.ROUNDED)
        yara_table.add_column("Rule", style="bold red")
        yara_table.add_column("Namespace")
        for match in yara_matches:
            yara_table.add_row(match.get("rule", ""), match.get("namespace", ""))
        console.print(yara_table)
    elif yara_matches and "error" in yara_matches[0]:
        console.print(f"[bold red]YARA scanning error:[/bold red] {yara_matches[0]['error']}")

    # 5. Evasion Indicators
    evasion = results.get("evasion", {})
    if evasion:
        avm = evasion.get("anti_vm", [])
        adbg = evasion.get("anti_debug", [])
        ssec = evasion.get("suspicious_sections", [])
        
        if avm or adbg or ssec:
            evase_table = Table(title="Evasion Indicators", box=box.HEAVY_EDGE, style="red")
            evase_table.add_column("Technique", style="yellow bold")
            evase_table.add_column("Evidence", style="white")
            
            if avm:
                evase_table.add_row("Anti-VM Strings", ", ".join(avm))
            if adbg:
                evase_table.add_row("Anti-Debug APIs", ", ".join(adbg))
            if ssec:
                evase_table.add_row("Obfuscated Sections", ", ".join(ssec))
                
            console.print(evase_table)

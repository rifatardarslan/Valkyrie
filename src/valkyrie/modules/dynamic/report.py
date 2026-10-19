from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import box

console = Console()

def render_dynamic_report(results: Dict[str, Any]):
    """Renders a beautiful CLI report for Dynamic Analysis using rich."""
    
    console.print(Panel.fit("[bold magenta]Valkyrie Dynamic Sandbox Report[/bold magenta]", border_style="magenta"))
    
    sandbox = results.get("sandbox", {})
    if not sandbox.get("success"):
        console.print(f"[bold red]Sandbox Execution Failed:[/bold red] {sandbox.get('error')}")
        return
        
    # Execution Overview
    exec_table = Table(title="Execution Overview", box=box.ROUNDED)
    exec_table.add_column("Property", style="magenta")
    exec_table.add_column("Status", style="green")
    
    exec_table.add_row("Target File", results.get("target_file", "Unknown"))
    exec_table.add_row("Artifacts Saved To", sandbox.get("host_artifacts_dir", "Unknown"))
    exec_table.add_row("Strace Log Captured", "Yes" if sandbox.get("strace_log") else "No")
    exec_table.add_row("PCAP Captured", "Yes" if sandbox.get("pcap_file") else "No")
    
    console.print(exec_table)
    
    # Behavior Parsing
    strace = results.get("strace", {})
    if strace.get("error"):
        console.print(f"[bold yellow]Strace Parser Error:[/bold yellow] {strace['error']}")
        return
        
    # File Operations
    file_ops = strace.get("file_operations", [])
    if file_ops:
        file_table = Table(title="File System Activity", box=box.SIMPLE)
        file_table.add_column("Operation", style="yellow")
        for op in file_ops[:20]: # Limit output
            file_table.add_row(op)
        if len(file_ops) > 20:
             file_table.add_row(f"... and {len(file_ops)-20} more.")
        console.print(file_table)
        
    # Executions
    exec_ops = strace.get("execution_operations", [])
    if exec_ops:
        ex_table = Table(title="Process Execution", box=box.SIMPLE)
        ex_table.add_column("Command", style="red")
        for op in exec_ops[:10]:
            ex_table.add_row(op)
        if len(exec_ops) > 10:
             ex_table.add_row(f"... and {len(exec_ops)-10} more.")
        console.print(ex_table)
        
    # Network Activity
    net_ops = strace.get("network_operations", [])
    if net_ops:
        net_table = Table(title="Network Calls (Strace Hook)", box=box.SIMPLE)
        net_table.add_column("Socket Activity", style="cyan")
        for op in net_ops[:10]:
            net_table.add_row(op)
        if len(net_ops) > 10:
             net_table.add_row(f"... and {len(net_ops)-10} more.")
        console.print(net_table)
        
    # General Syscall Stats
    raw_calls = strace.get("raw_syscalls_count", {})
    if raw_calls:
        top_calls = sorted(raw_calls.items(), key=lambda x: x[1], reverse=True)[:5]
        call_table = Table(title="Top 5 Syscalls", box=box.SIMPLE)
        call_table.add_column("Syscall")
        call_table.add_column("Count")
        for call, count in top_calls:
             call_table.add_row(call, str(count))
        console.print(call_table)
        
    # Memory Forensics
    mem = results.get("memory", {})
    if mem.get("rwx_regions") or mem.get("shellcode_matches"):
        mem_table = Table(title="Process Memory Forensics (Live)", box=box.HEAVY_EDGE, style="red")
        mem_table.add_column("Finding Type", style="bold red")
        mem_table.add_column("Details", style="white")
        
        for rwx in mem.get("rwx_regions", []):
            mem_table.add_row("RWX Mapping", f"{rwx['region']} [{rwx['mapping']}]")
            
        for shell in mem.get("shellcode_matches", []):
            mem_table.add_row("Shellcode Pattern", shell)
            
        console.print(mem_table)

import os
import click
import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from valkyrie.modules.static.analyzer import StaticAnalyzer
from valkyrie.modules.dynamic.analyzer import DynamicAnalyzer
from valkyrie.modules.intelligence.mitre import map_mitre
from valkyrie.modules.intelligence.ai_summary import generate_ai_summary
from valkyrie.modules.intelligence.whitelist import check_circl_whitelist
from valkyrie.modules.intelligence.osint import run_osint_enrichment
from valkyrie.core.exporter import export_json, export_md
from valkyrie.modules.intelligence.scorer import calculate_threat_score
from valkyrie.modules.intelligence.deobfuscator import extract_and_decode
from valkyrie.modules.intelligence.extractor import extract_artifacts
from valkyrie.modules.intelligence.capability import assess_capabilities
from dotenv import load_dotenv

def render_threat_score(score_data: dict):
    from rich.align import Align
    score = score_data.get("score", 0)
    label = score_data.get("label", "Unknown")
    
    color = "green"
    if score >= 90: color = "bold red"
    elif score >= 60: color = "red"
    elif score >= 20: color = "yellow"
    
    panel_content = f"[{color}][font=block] {score} / 100 [/font][/{color}]\n\n[bold white]Severity:[/bold white] [{color}]{label}[/{color}]\n"
    
    if score_data.get("reasons"):
        panel_content += "\n[bold]Contributing Factors:[/bold]\n"
        for r in score_data["reasons"]:
            panel_content += f" - {r}\n"
            
    console.print(Panel(Align.center(panel_content), title="[bold white]Valkyrie Threat Score[/bold white]", border_style=color))


load_dotenv()

console = Console()

VERSION = "1.0.0"


def print_banner():
    fig = pyfiglet.figlet_format("VALKYRIE", font="slant")
    console.print(Text(fig, style="bold red"))

    subtitle = Text()
    subtitle.append("  Professional Malware Analysis Pipeline  ", style="bold white")
    subtitle.append(f"v{VERSION}", style="bold red")
    console.print(subtitle)
    console.print()


def print_menu():
    menu = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    menu.add_column(style="bold cyan", no_wrap=True)
    menu.add_column(style="white")
    menu.add_row("analyze", "Analyze a suspect file (static / dynamic / full)")
    menu.add_row("vaccine", "Generate a proactive defense vaccine from a report")
    console.print(Panel(menu, title="[bold red]Commands[/bold red]", border_style="red", box=box.ROUNDED))

    console.print("\n  [dim]Run[/dim]  [bold]valkyrie analyze -f <file> -m full[/bold]")
    console.print("  [dim]Help[/dim] [bold]valkyrie <command> --help[/bold]\n")


@click.group(invoke_without_command=True)
@click.version_option(VERSION, "-v", "--version", message="Valkyrie v%(version)s")
@click.pass_context
def cli(ctx):
    """Valkyrie: Professional-grade CLI Malware Analyzer."""
    if ctx.invoked_subcommand is None:
        print_banner()
        print_menu()

@cli.command()
@click.option('--file', '-f', required=True, type=click.Path(exists=True), help='Path to the suspect file (PE/ELF).')
@click.option('--mode', '-m', type=click.Choice(['static', 'dynamic', 'full'], case_sensitive=False), default='static', help='Analysis mode.')
@click.option('--timeout', '-t', type=int, default=15, help='Dynamic Sandbox execution timeout (seconds).')
@click.option('--outdir', '-o', type=click.Path(), default='reports', help='Output directory for JSON/MD reports.')
def analyze(file: str, mode: str, timeout: int, outdir: str):
    """Analyze a suspect file."""
    console.print(f"[bold green]Starting {mode} analysis[/bold green] on [bold cyan]{file}[/bold cyan]...")
    
    aggregated_results = {
        "static": {},
        "dynamic": {},
        "intelligence": {}
    }
    
    # 1. Static Analysis
    if mode in ['static', 'full']:
        static_analyzer = StaticAnalyzer()
        with console.status(f"[bold green]Running Static Analysis on {file}...") as status:
            aggregated_results["static"] = static_analyzer.analyze(file)
        static_analyzer.report()
        
        # Whitelist Check
        if "hashes" in aggregated_results["static"] and "sha256" in aggregated_results["static"]["hashes"]:
            sha256 = aggregated_results["static"]["hashes"]["sha256"]
            with console.status(f"[bold blue]Checking CIRCL Whitelist (NSRL) for {sha256}...") as status:
                wl_result = check_circl_whitelist(sha256)
                if wl_result:
                    aggregated_results["intelligence"]["whitelist"] = wl_result
                    console.print(Panel(
                        f"[bold green]Verified Safe File[/bold green]\n"
                        f"This file's hash is present in the CIRCL known-good database.\n"
                        f"Product: {wl_result.get('ProductName', 'Unknown')}",
                        border_style="green"
                    ))
        
    # 2. Dynamic Analysis
    if mode in ['dynamic', 'full']:
        try:
            from docker.errors import DockerException
            dynamic_analyzer = DynamicAnalyzer(timeout_seconds=timeout)
            console.print(f"[bold magenta]Entering Dynamic Sandbox...[/bold magenta]")
            with console.status(f"[bold magenta]Running Isolated Execution in Docker for {timeout}s... This takes time and requires Docker daemon.") as status:
                aggregated_results["dynamic"] = dynamic_analyzer.analyze(file)
            dynamic_analyzer.report()
        except DockerException as e:
            console.print(f"[bold red]Dynamic Analysis Failed:[/bold red] Error connecting to Docker Daemon. Is Docker Desktop running? Details: {str(e)}")
        except Exception as e:
            console.print(f"[bold red]Dynamic Analysis Error:[/bold red] {str(e)}")
            
    # 3. Intelligence Layer (Runs automatically on 'full')
    if mode == 'full':
        console.print(Panel.fit("[bold blue]Valkyrie Intelligence Layer[/bold blue]", border_style="blue"))
        
        with console.status("[bold blue]Mapping behaviors to MITRE ATT&CK...") as status:
            mitre_matches = map_mitre(aggregated_results)
            aggregated_results["intelligence"]["mitre"] = mitre_matches
            
        with console.status("[bold blue]Generating AI Executive Summary (requires OPENAI_API_KEY)...") as status:
            ai_summary = generate_ai_summary(aggregated_results)
            aggregated_results["intelligence"]["ai_summary"] = ai_summary
            
        with console.status("[bold blue]Querying Global Threat Intelligence (OSINT)...") as status:
            sha256 = aggregated_results.get("static", {}).get("hashes", {}).get("sha256", "")
            network_ioc_list = []
            strace_ops = aggregated_results.get("dynamic", {}).get("strace", {})
            if "network_calls" in strace_ops:
                import re
                for call in strace_ops["network_calls"]:
                    ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', call)
                    network_ioc_list.extend(ips)
            network_ioc_list = list(set(network_ioc_list))
            
            osint_data = run_osint_enrichment(sha256, network_ioc_list)
            aggregated_results["intelligence"]["osint"] = osint_data
            
        # Display Intelligence
        if mitre_matches:
            mitre_table = Table(title="MITRE ATT&CK Mappings", box=box.ROUNDED)
            mitre_table.add_column("TID", style="red bold")
            mitre_table.add_column("Tactic", style="cyan")
            mitre_table.add_column("Technique")
            mitre_table.add_column("Trigger Data", style="yellow")
            
            for m in mitre_matches:
                mitre_table.add_row(m["id"], m["tactic"], m["name"], m.get("trigger", ""))
            console.print(mitre_table)
            
        if "osint" in aggregated_results["intelligence"]:
            osint = aggregated_results["intelligence"]["osint"]
            vt = osint.get("virustotal", {})
            if "malicious" in vt:
                total_vt = vt['malicious'] + vt['undetected'] + vt['suspicious']
                color = "red" if vt['malicious'] > 0 else "green"
                console.print(f"\n[bold {color}]VirusTotal Detection:[/bold {color}] {vt['malicious']} / {total_vt} (Label: {vt.get('suggested_threat_label')})")
            
            mb = osint.get("malwarebazaar", {})
            if "signature" in mb:
                console.print(f"[bold red]MalwareBazaar Signature:[/bold red] {mb['signature']}")
                
            net_rep = osint.get("network_reputation", {})
            if net_rep:
                rep_tbl = Table(title="Network Intelligence (AbuseIPDB)", box=box.ROUNDED)
                rep_tbl.add_column("IP")
                rep_tbl.add_column("Abuse Score", style="red")
                rep_tbl.add_column("Country")
                rep_tbl.add_column("Usage")
                
                rows_added = 0
                for ip, rep in net_rep.items():
                    if "error" not in rep and "status" not in rep:
                        rep_tbl.add_row(ip, str(rep.get("abuse_confidence_score", 0)), rep.get("country", ""), rep.get("usage_type", ""))
                        rows_added += 1
                if rows_added > 0:
                    console.print(rep_tbl)
            
        console.print(Panel(ai_summary, title="AI Executive Summary", border_style="blue"))
        
        # --- Advanced Intelligence Layer (Capa-like) ---
        with console.status("[bold blue]Running Advanced De-obfuscation and Artifact Extraction...") as status:
            deobf_results = extract_and_decode(file)
            aggregated_results["intelligence"]["deobfuscation"] = deobf_results
            
            regex_results = extract_artifacts(file)
            aggregated_results["intelligence"]["artifacts"] = regex_results
            
            capabilities = assess_capabilities(aggregated_results, deobf_results.get("xor_decoded", []))
            aggregated_results["intelligence"]["capabilities"] = capabilities
            
        # Display Capabilities
        if capabilities and not "error" in capabilities[0]:
            cap_tbl = Table(title="Discovered Capabilities", box=box.HEAVY_EDGE, style="red")
            cap_tbl.add_column("Capability", style="bold red")
            cap_tbl.add_column("Description", style="white")
            for cap in capabilities:
                cap_tbl.add_row(cap['tag'], cap['description'])
            console.print(cap_tbl)
            
        # Display Sensitive Artifacts (Regex)
        found_artifacts = False
        art_tbl = Table(title="Sensitive Regex Artifacts", box=box.ROUNDED, style="yellow")
        art_tbl.add_column("Artifact Type", style="cyan")
        art_tbl.add_column("Value", style="red")
        
        for k, v in regex_results.items():
            if k != "error" and v:
                found_artifacts = True
                for val in v[:5]:  # Limit output
                    art_tbl.add_row(k.upper(), val)
                if len(v) > 5:
                    art_tbl.add_row(k.upper(), f"... and {len(v)-5} more.")
        if found_artifacts:
            console.print(art_tbl)
            
        # Display De-obfuscated Strings
        found_deobf = False
        deobf_tbl = Table(title="De-Obfuscated Payloads", box=box.ROUNDED, style="magenta")
        deobf_tbl.add_column("Method", style="cyan")
        deobf_tbl.add_column("Decoded Value (Preview)", style="white")
        
        for k, v in deobf_results.items():
            if k != "error" and v:
                found_deobf = True
                for val in v[:5]:
                    preview = val[:80] + "..." if len(val) > 80 else val
                    deobf_tbl.add_row(k.replace("_decoded", "").upper(), preview)
        if found_deobf:
            console.print(deobf_tbl)
        
        # Threat Score
        with console.status("[bold blue]Calculating Heuristic Threat Score...") as status:
            threat_score = calculate_threat_score(aggregated_results)
            aggregated_results["intelligence"]["threat_score"] = threat_score
            
        render_threat_score(threat_score)
        
        # Behavioral Timeline
        timeline = aggregated_results.get("dynamic", {}).get("strace", {}).get("timeline", [])
        if timeline:
            tl_table = Table(title="Behavioral Execution Timeline", box=box.SIMPLE_HEAD)
            tl_table.add_column("Tick", style="cyan", justify="right")
            tl_table.add_column("Action", style="white")
            tl_table.add_column("Syscall", style="dim")
            for ts in timeline:
                tl_table.add_row(f"T+{ts['tick']}", ts['action'], ts['raw'])
            console.print(tl_table)
        
        # 4. Export logic
        with console.status("[bold yellow]Exporting Final Reports...") as status:
            json_path = export_json(aggregated_results, outdir)
            md_path = export_md(aggregated_results, outdir)
            
            # Enterprise Integration
            from valkyrie.modules.enterprise.reporter import EnterpriseReporter
            from valkyrie.modules.enterprise.stix_export import StixExporter
            from valkyrie.modules.enterprise.webhook import WebhookAlerter
            from valkyrie.modules.intelligence.vaccine_engine import VaccineEngine
            
            html_path = os.path.join(outdir, "valkyrie_report.html")
            pdf_path = os.path.join(outdir, "valkyrie_report.pdf")
            
            reporter = EnterpriseReporter()
            if reporter.generate_html(aggregated_results, html_path):
                pass
            
            # Use native PDF generation
            reporter.generate_pdf(aggregated_results, pdf_path)
                
            stix_exporter = StixExporter(out_dir=outdir)
            stix_path = stix_exporter.export(aggregated_results)
            
            webhook = WebhookAlerter()
            webhook.send_alert(aggregated_results)
            
            vaccine_gen = VaccineEngine()
            vaccine_content = vaccine_gen.generate_vaccine_script(aggregated_results)
            vaccine_path = os.path.join(outdir, "vaccine.py")
            if vaccine_content and ("mutex_name =" in vaccine_content or "reg_path =" in vaccine_content):
                with open(vaccine_path, "w", encoding="utf-8") as f:
                    f.write(vaccine_content)
            else:
                vaccine_path = None
            
        console.print(f"[bold green]Reports generated successfully in {outdir}/[/bold green]")
        if json_path: console.print(f" - [cyan]JSON Report:[/cyan] {json_path}")
        if md_path: console.print(f" - [cyan]Markdown Report:[/cyan] {md_path}")
        if os.path.exists(html_path): console.print(f" - [cyan]HTML Report:[/cyan] {html_path}")
        if os.path.exists(pdf_path): console.print(f" - [cyan]PDF Report:[/cyan] {pdf_path}")
        if stix_path: console.print(f" - [cyan]STIX 2.1 Intel:[/cyan] {stix_path}")
        if vaccine_path: console.print(f" - [bold magenta]Valkyrie Vaccine Script:[/bold magenta] {vaccine_path}")
            
    console.print("[green]Analysis complete.[/green]")

@cli.command("vaccine")
@click.option("--report", "-r", type=click.Path(exists=False), help="Path to the analysis report JSON.")
@click.option("--output", "-o", default="vaccine_script.py", help="Output filename for the Python vaccine script.")
def generate_vaccine(report, output):
    """Generates a Proactive Defense Vaccine based on analysis indicators."""
    import json
    from valkyrie.modules.intelligence.vaccine_engine import VaccineEngine
    
    if not report:
        report = "reports/valkyrie_report.json"
        
    if not os.path.exists(report):
        console.print(f"[bold red][-] Report file not found at {report}. Please provide a valid report using --report or run an analysis first.[/bold red]")
        return
        
    try:
        with open(report, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[bold red][-] Failed to read report: {e}[/bold red]")
        return
        
    engine = VaccineEngine()
    script = engine.generate_vaccine_script(data)
    
    # Check if the generated script actually contains indicators
    if not script or ("CreateMutexW" not in script and "Simulating creation of Registry Key" not in script):
        console.print("[yellow][!] No usable indicators (Mutexes or Registry Keys) found in the report to generate a vaccine.[/yellow]")
        return
        
    try:
        with open(output, "w", encoding="utf-8") as f:
            f.write(script)
        console.print(f"[bold green][+] Valkyrie Vaccine successfully generated at:[/bold green] {output}")
        console.print("[cyan][*] You can deploy this proactive defense script on target Windows endpoints.[/cyan]")
    except Exception as e:
        console.print(f"[bold red][-] Failed to write vaccine script: {e}[/bold red]")


if __name__ == '__main__':
    cli()

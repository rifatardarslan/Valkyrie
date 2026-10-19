import os
import getpass
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader
try:
    import pdfkit
except ImportError:
    pdfkit = None

class EnterpriseReporter:
    """Renders HTML and PDF reports using Jinja2 and PDFKit."""
    
    def __init__(self, template_dir: str = "templates"):
        # Absolute path to template dir
        # __file__ is src/valkyrie/modules/enterprise/reporter.py
        # root is ../../../../
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        if not base_dir.endswith("Valkyrie"):
            # Fallback if execution path differs
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
            
        full_template_dir = os.path.join(base_dir, template_dir)
        
        if not os.path.exists(full_template_dir):
            os.makedirs(full_template_dir, exist_ok=True)
            
        self.env = Environment(loader=FileSystemLoader(full_template_dir))
        
    def generate_html(self, results: Dict[str, Any], out_path: str) -> bool:
        """Renders the aggregated results dictionary into an HTML file."""
        try:
            template = self.env.get_template("report.html")
            
            # Extract main pillars
            static = results.get("static", {})
            dynamic = results.get("dynamic", {})
            intelligence = results.get("intelligence", {})
            
            html_content = template.render(
                static=static,
                dynamic=dynamic,
                intelligence=intelligence,
                author=getpass.getuser()
            )
            
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(html_content)
                
            return True
        except Exception as e:
            print(f"[-] Failed to generate HTML report: {e}")
            return False
            
    def generate_pdf(self, results: Dict[str, Any], out_path: str) -> bool:
        """Generates a PDF report using fpdf2."""
        try:
            from fpdf import FPDF
            
            pdf = FPDF()
            pdf.add_page()
            
            # Colors and Fonts
            pdf.set_fill_color(30, 41, 59) # Dark background typical
            pdf.set_text_color(248, 250, 252) # White text
            pdf.set_font("helvetica", "B", 24)
            
            # Header
            pdf.rect(0, 0, 210, 297, 'F') # Fill page
            pdf.cell(0, 20, "Valkyrie Executive Report", align="C", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(10)
            
            # Content setup
            pdf.set_font("helvetica", "", 12)
            
            # Threat Score
            score_data = results.get("intelligence", {}).get("threat_score", {})
            score = score_data.get("score", 0)
            label = score_data.get("label", "Safe")
            
            pdf.set_font("helvetica", "B", 16)
            pdf.set_text_color(59, 130, 246) # Blue
            pdf.cell(0, 10, "Heuristic Threat Score", new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_font("helvetica", "B", 20)
            if score >= 90: pdf.set_text_color(239, 68, 68) # Red
            elif score >= 50: pdf.set_text_color(245, 158, 11) # Yellow
            else: pdf.set_text_color(16, 185, 129) # Green
            
            pdf.cell(0, 10, f"{score} / 100 ({label})", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(5)
            
            # File Identification
            static = results.get("static", {})
            pdf.set_text_color(59, 130, 246) # Blue
            pdf.set_font("helvetica", "B", 16)
            pdf.cell(0, 10, "File Identification", new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_font("helvetica", "", 10)
            pdf.set_text_color(248, 250, 252)
            pdf.cell(40, 8, "Target File:")
            pdf.cell(0, 8, f"{static.get('target_file', 'Unknown')}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(40, 8, "SHA-256:")
            pdf.cell(0, 8, f"{static.get('hashes', {}).get('sha256', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(10)
            
            # AI Summary
            ai_sum = results.get("intelligence", {}).get("ai_summary", "")
            if ai_sum:
                ai_sum = ai_sum.replace("⚠️", "Warning:")
                pdf.set_font("helvetica", "B", 16)
                pdf.set_text_color(59, 130, 246)
                pdf.cell(0, 10, "AI Behavioral Summary", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("helvetica", "", 10)
                pdf.set_text_color(248, 250, 252)
                pdf.multi_cell(0, 6, ai_sum)
                pdf.ln(10)
            
            pdf.output(out_path)
            return True
        except Exception as e:
            print(f"[-] Failed to generate PDF report: {e}")
            return False

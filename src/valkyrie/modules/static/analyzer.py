from typing import Dict, Any
from valkyrie.core.analyzer import AbstractAnalyzer
from valkyrie.modules.static.entropy import analyze_entropy
from valkyrie.modules.static.hashing import calculate_hashes
from valkyrie.modules.static.headers import analyze_headers
from valkyrie.modules.static.yara_scanner import scan_file
from valkyrie.modules.static.unpacker import unpack_upx
from valkyrie.modules.static.report import render_static_report

class StaticAnalyzer(AbstractAnalyzer):
    def __init__(self):
        self.results = {}

    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Runs the complete static analysis pipeline."""
        
        # 1. Unpacking Attempt (Optional)
        upx_res = unpack_upx(file_path)
        
        # If we successfully unpacked it, analyze the unpacked file instead
        target_file = upx_res["unpacked_file_path"] if upx_res["unpacked"] else file_path
        
        # 2. Extract Data
        self.results = {
            "target_file": target_file,
            "original_file": file_path,
            "unpack_info": upx_res,
            "hashes": calculate_hashes(target_file),
            "entropy": analyze_entropy(target_file),
            "headers": analyze_headers(target_file),
            "yara": scan_file(target_file)
        }
        
        return self.results

    def report(self) -> str:
        """Renders the results to the terminal using rich."""
        if not self.results:
            return "No analysis results available."
            
        render_static_report(self.results)
        return ""

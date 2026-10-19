from typing import Dict, Any
from valkyrie.core.analyzer import AbstractAnalyzer
from valkyrie.modules.dynamic.sandbox import DockerSandbox
from valkyrie.modules.dynamic.parser import parse_strace
from valkyrie.modules.dynamic.report import render_dynamic_report
from valkyrie.modules.dynamic.memory import analyze_memory

class DynamicAnalyzer(AbstractAnalyzer):
    def __init__(self, timeout_seconds=15):
        self.sandbox = DockerSandbox(timeout_seconds=timeout_seconds)
        self.results = {}

    def analyze(self, file_path: str) -> Dict[str, Any]:
        """Runs the complete dynamic analysis pipeline in Docker."""
        
        # 1. Orchestrate Container Execution
        sandbox_result = self.sandbox.execute(file_path)
        
        # 2. Parse Results
        parsed_strace = {}
        memory_forensics = {}
        if sandbox_result.get("success"):
            if sandbox_result.get("strace_log"):
                parsed_strace = parse_strace(sandbox_result["strace_log"])
                
            maps_log = sandbox_result.get("maps_log")
            mem_dump = sandbox_result.get("mem_dump")
            if maps_log or mem_dump:
                memory_forensics = analyze_memory(maps_log, mem_dump)
            
        self.results = {
            "target_file": file_path,
            "sandbox": sandbox_result,
            "strace": parsed_strace,
            "memory": memory_forensics
        }
        
        return self.results

    def report(self) -> str:
        """Renders the results to the terminal using rich."""
        if not self.results:
            return "No analysis results available."
            
        render_dynamic_report(self.results)
        return ""

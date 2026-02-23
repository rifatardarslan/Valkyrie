import os
import json
from typing import Dict, Any
from openai import OpenAI

def generate_ai_summary(aggregated_results: Dict[str, Any]) -> str:
    """
    Sends the aggregated JSON findings to an LLM to generate an Executive Summary.
    Requires OPENAI_API_KEY environment variable.
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return (
            "⚠️ AI Summary Unavailable: OPENAI_API_KEY environment variable is not set. "
            "Set the key to enable LLM-powered executive summaries."
        )
        
    try:
        client = OpenAI(api_key=api_key)
        
        # Strip out noisy/large data to reduce token count
        clean_results = _prepare_for_llm(aggregated_results)
        json_payload = json.dumps(clean_results, indent=2, default=str)
        
        prompt = (
            "You are an elite Malware Analyst. Review the following automated static and dynamic analysis JSON report. "
            "Provide a concise, professional Executive Summary detailing the file's primary intent, capabilities, and threat level. "
            "Do not just restate the JSON; provide an expert synthesis. Keep it to 1-2 paragraphs.\n\n"
            f"Report Data:\n{json_payload}"
        )
        
        response = client.chat.completions.create(
            model="gpt-3.5-turbo", # or gpt-4 if preferred
            messages=[
                {"role": "system", "content": "You are a senior malware analyst providing succinct executive summaries."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=300,
            temperature=0.3
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        return f"⚠️ AI Summary Generation Failed: {str(e)}"

def _prepare_for_llm(results: Dict[str, Any]) -> Dict[str, Any]:
    """Prunes massive arrays (like top imports) to avoid token limit errors."""
    import copy
    clean = copy.deepcopy(results)
    
    if "static" in clean and "headers" in clean["static"]:
        if "imports" in clean["static"]["headers"]:
            clean["static"]["headers"]["imports"] = clean["static"]["headers"]["imports"][:3]
    
    if "dynamic" in clean and "strace" in clean["dynamic"]:
        # Only send counts, not full file ops string lists which could be megabytes
        if "file_operations" in clean["dynamic"]["strace"]:
            clean["dynamic"]["strace"]["file_ops_count"] = len(clean["dynamic"]["strace"]["file_operations"])
            del clean["dynamic"]["strace"]["file_operations"]
            
    return clean

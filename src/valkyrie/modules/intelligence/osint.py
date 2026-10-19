import os
import requests
from typing import Dict, Any, List

def query_virustotal(sha256_hash: str) -> Dict[str, Any]:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not set"}
        
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "suggested_threat_label": data.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown")
            }
        elif response.status_code == 404:
            return {"status": "Not found in VirusTotal"}
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def query_malwarebazaar(sha256_hash: str) -> Dict[str, Any]:
    api_key = os.environ.get("MALWAREBAZAAR_API_KEY")
    # MalwareBazaar allows hash lookups without an API key sometimes, but good to pass if we have it
    headers = {"API-KEY": api_key} if api_key else {}
    data = {"query": "get_info", "hash": sha256_hash}
    
    try:
        response = requests.post("https://mb-api.abuse.ch/api/v1/", data=data, headers=headers, timeout=10)
        res = response.json()
        if res.get("query_status") == "ok":
            info = res.get("data", [{}])[0]
            return {
                "signature": info.get("signature", "Unknown"),
                "tags": info.get("tags", []),
                "first_seen": info.get("first_seen", "Unknown")
            }
        else:
            return {"status": "Not found in MalwareBazaar"}
    except Exception as e:
        return {"error": str(e)}

def query_abuseipdb(ip_address: str) -> Dict[str, Any]:
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY not set"}
        
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "Unknown"),
                "usage_type": data.get("usageType", "Unknown"),
                "domain": data.get("domain", "Unknown")
            }
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def run_osint_enrichment(sha256_hash: str, network_ioc_list: List[str]) -> Dict[str, Any]:
    """Runs all available OSINT checks and returns aggregated findings."""
    results = {
        "virustotal": {},
        "malwarebazaar": {},
        "network_reputation": {}
    }
    
    if sha256_hash:
        results["virustotal"] = query_virustotal(sha256_hash)
        results["malwarebazaar"] = query_malwarebazaar(sha256_hash)
        
    if network_ioc_list:
        for ioc in network_ioc_list:
            # simple check: if it looks like an IP (roughly) vs a domain.
            # AbuseIPDB is best for IPs. We'll attempt lookup for all for simplicity in MVP.
            if ioc.count('.') == 3 and all(p.isdigit() for p in ioc.split('.')):
                results["network_reputation"][ioc] = query_abuseipdb(ioc)
            else:
                results["network_reputation"][ioc] = {"status": "Not an IPv4 address"}
                
    return results

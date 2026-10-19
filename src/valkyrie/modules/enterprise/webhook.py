import os
import json
import requests
from typing import Dict, Any

class WebhookAlerter:
    """Sends Critical Alerts to Enterprise Webhooks (Slack/Discord/Teams)."""
    
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url or os.environ.get("WEBHOOK_URL")
        
    def send_alert(self, aggregated_results: Dict[str, Any]) -> bool:
        """Evaluates the threat score and sends an alert if critical."""
        if not self.webhook_url:
            return False
            
        intelligence = aggregated_results.get("intelligence", {})
        score_data = intelligence.get("threat_score", {})
        score = score_data.get("score", 0)
        
        # Only alert on high severity
        if score < 75:
            return False
            
        static = aggregated_results.get("static", {})
        target = static.get("target_file", "Unknown Target")
        sha256 = static.get("hashes", {}).get("sha256", "Unknown Hash")
        label = score_data.get("label", "CRITICAL")
        
        reasons = score_data.get("reasons", [])
        reasons_text = "\n".join([f"- {r}" for r in reasons[:5]])
        
        # Discord/Slack compatible structured JSON payload
        payload = {
            "username": "Valkyrie Analyzer",
            "avatar_url": "https://i.imgur.com/4M34hiw.png",
            "embeds": [
                {
                    "title": f"🚨 HIGH THREAT ALERT: {target}",
                    "color": 16711680, # Red
                    "description": f"Valkyrie detected a highly malicious file scoring **{score}/100** ({label}).",
                    "fields": [
                        {
                            "name": "SHA-256 Hash",
                            "value": f"`{sha256}`",
                            "inline": False
                        },
                        {
                            "name": "Key Contributing Risk Factors",
                            "value": reasons_text if reasons_text else "No specific reasons provided.",
                            "inline": False
                        }
                    ],
                    "footer": {
                        "text": "Valkyrie Automated Defense Grid"
                    }
                }
            ]
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            return response.status_code in [200, 204]
        except Exception as e:
            print(f"[-] Webhook failed to send: {e}")
            return False
